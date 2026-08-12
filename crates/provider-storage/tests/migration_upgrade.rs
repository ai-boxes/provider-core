use sqlx::{
    Connection, Row, SqliteConnection,
    migrate::{Migrate, Migrator},
    sqlite::SqliteConnectOptions,
};

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
