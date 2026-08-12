use sqlx::{
    Connection, Row, SqliteConnection,
    migrate::{Migrate, Migrator},
    sqlite::SqliteConnectOptions,
};

use provider_storage::SqliteAccountRepository;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
const RELEASED_INITIAL_CHECKSUM: [u8; 48] = [
    0x3b, 0x9e, 0xff, 0x02, 0x5c, 0xfd, 0x5c, 0x4a, 0xad, 0x75, 0x17, 0x1b, 0xdb, 0xd8, 0x94, 0xf4,
    0xee, 0x48, 0x1b, 0x04, 0xd9, 0xf4, 0x48, 0x7a, 0xd1, 0x58, 0xa5, 0x59, 0x5f, 0xec, 0xe6, 0x23,
    0x5d, 0x49, 0xa5, 0xe1, 0x40, 0x75, 0x9f, 0x17, 0x3e, 0x8f, 0x96, 0xab, 0x7f, 0xc2, 0x8c, 0x9a,
];

#[test]
fn released_initial_migration_is_immutable() {
    assert_eq!(
        MIGRATOR.migrations[0].checksum.as_ref(),
        RELEASED_INITIAL_CHECKSUM
    );
}

#[tokio::test]
async fn upgrades_a_database_created_by_the_released_initial_migration() {
    let mut connection = SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true),
    )
    .await
    .expect("open SQLite database");

    connection
        .ensure_migrations_table("_sqlx_migrations")
        .await
        .expect("create SQLx migration metadata table");
    connection
        .apply("_sqlx_migrations", &MIGRATOR.migrations[0])
        .await
        .expect("apply released initial migration");

    sqlx::query(
        r#"
        INSERT INTO users (id, username, password_hash, role, created_at, updated_at)
        VALUES ('user-1', 'migration-user', 'hash', 'user', 1, 1)
        "#,
    )
    .execute(&mut connection)
    .await
    .expect("insert data into the released schema");

    sqlx::query(
        r#"
        INSERT INTO provider_accounts
            (id, owner_user_id, provider, label, group_label, created_at, updated_at)
        VALUES ('account-1', 'user-1', 'grok', 'Legacy account', 'default', 1, 1)
        "#,
    )
    .execute(&mut connection)
    .await
    .expect("insert legacy provider account");

    sqlx::query(
        r#"
        INSERT INTO provider_models
            (account_id, upstream_model, metadata_json, created_at, updated_at)
        VALUES ('account-1', 'legacy-model', '{}', 1, 1)
        "#,
    )
    .execute(&mut connection)
    .await
    .expect("insert legacy provider model");

    MIGRATOR
        .run(&mut connection)
        .await
        .expect("upgrade released schema to current schema");

    let account = sqlx::query("SELECT priority FROM provider_accounts WHERE id = 'account-1'")
        .fetch_one(&mut connection)
        .await
        .expect("load upgraded provider account");
    assert_eq!(account.get::<i64, _>("priority"), 0);

    let model = sqlx::query(
        r#"
        SELECT input_modalities_json, input_modalities_source
        FROM provider_models
        WHERE account_id = 'account-1' AND upstream_model = 'legacy-model'
        "#,
    )
    .fetch_one(&mut connection)
    .await
    .expect("load upgraded provider model");
    assert_eq!(
        model.get::<Option<String>, _>("input_modalities_json"),
        None
    );
    assert_eq!(
        model.get::<String, _>("input_modalities_source"),
        "discovery"
    );

    let quota_columns = sqlx::query("PRAGMA table_info(api_key_quota_ledger)")
        .fetch_all(&mut connection)
        .await
        .expect("load upgraded quota ledger columns")
        .into_iter()
        .map(|row| row.get::<String, _>("name"))
        .collect::<Vec<_>>();
    assert!(quota_columns.iter().any(|name| name == "dispatched_at_ms"));

    let versions = sqlx::query("SELECT version FROM _sqlx_migrations ORDER BY version")
        .fetch_all(&mut connection)
        .await
        .expect("load applied migration versions")
        .into_iter()
        .map(|row| row.get::<i64, _>("version"))
        .collect::<Vec<_>>();
    assert_eq!(versions, vec![1, 2, 3, 4]);
}

#[tokio::test]
async fn upgrades_the_bundled_pre_release_migration_history() {
    let path = std::env::temp_dir().join(format!(
        "provider-core-migration-upgrade-{}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let mut connection = SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .foreign_keys(true),
    )
    .await
    .expect("open SQLite database");
    MIGRATOR
        .run(&mut connection)
        .await
        .expect("create current schema");

    let bundled_checksum = [
        0xba, 0x82, 0xe6, 0x2c, 0xfc, 0x60, 0xb6, 0xd2, 0x95, 0x53, 0xbe, 0xb5, 0x2c, 0x4f, 0x47,
        0x05, 0x7c, 0x95, 0xa1, 0x4a, 0x96, 0x9d, 0x49, 0x14, 0x0d, 0x8a, 0x0c, 0xa5, 0x17, 0xad,
        0x3a, 0x98, 0x10, 0x11, 0x95, 0x7d, 0xa0, 0x2c, 0x63, 0x15, 0x5c, 0x1d, 0xec, 0x54, 0xe7,
        0xcd, 0x96, 0xc2,
    ];
    sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = 1")
        .bind(bundled_checksum.as_slice())
        .execute(&mut connection)
        .await
        .expect("restore bundled migration checksum");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version IN (2, 3, 4)")
        .execute(&mut connection)
        .await
        .expect("restore bundled migration versions");
    sqlx::query("ALTER TABLE api_key_quota_ledger DROP COLUMN dispatched_at_ms")
        .execute(&mut connection)
        .await
        .expect("restore bundled quota ledger schema");
    drop(connection);

    SqliteAccountRepository::connect(&path, [0x5a; 32])
        .await
        .expect("normalize and upgrade bundled migration history");

    let mut connection = SqliteConnection::connect(&format!("sqlite:{}", path.display()))
        .await
        .expect("reopen upgraded database");
    let versions = sqlx::query("SELECT version FROM _sqlx_migrations ORDER BY version")
        .fetch_all(&mut connection)
        .await
        .expect("load normalized versions")
        .into_iter()
        .map(|row| row.get::<i64, _>("version"))
        .collect::<Vec<_>>();
    assert_eq!(versions, vec![1, 2, 3, 4]);
    drop(connection);
    let _ = std::fs::remove_file(path);
}
