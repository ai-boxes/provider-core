use sqlx::{
    Connection, SqliteConnection,
    migrate::{Migrate, Migrator},
};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[tokio::test]
async fn observation_upgrade_preserves_history_and_accepts_same_second_changes() {
    let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    connection
        .ensure_migrations_table("_sqlx_migrations")
        .await
        .unwrap();
    for migration in MIGRATOR.iter().filter(|migration| migration.version <= 11) {
        connection
            .apply("_sqlx_migrations", migration)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO provider_accounts (id, provider, label, group_label, config_json, priority) VALUES ('account-1', 'codex', 'Codex', 'codex', '{}', 0)")
        .execute(&mut connection).await.unwrap();
    sqlx::query("INSERT INTO provider_quota_window_observations (account_id, credential_revision, credential_identity_revision, observed_at_ms, group_key, metric_key, metric_position, used_hundredths, period_kind, starts_at_ms, ends_at_ms, duration_seconds) VALUES ('account-1', 1, 0, 200000, 'codex', 'primary', 0, 5000, 'rolling', 100000, 300000, 200)")
        .execute(&mut connection).await.unwrap();
    let before: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT rowid, observed_at_ms, used_hundredths, ends_at_ms FROM provider_quota_window_observations",
    ).fetch_one(&mut connection).await.unwrap();
    MIGRATOR.run(&mut connection).await.unwrap();
    let after: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT observation_sequence, observed_at_ms, used_hundredths, ends_at_ms FROM provider_quota_window_observations",
    ).fetch_one(&mut connection).await.unwrap();
    assert_eq!(before, after);
    sqlx::query("INSERT INTO provider_quota_window_observations (account_id, credential_revision, credential_identity_revision, observed_at_ms, group_key, metric_key, metric_position, used_hundredths, period_kind, starts_at_ms, ends_at_ms, duration_seconds) SELECT account_id, credential_revision, credential_identity_revision, observed_at_ms, group_key, metric_key, metric_position, 0, period_kind, starts_at_ms, ends_at_ms, duration_seconds FROM provider_quota_window_observations")
        .execute(&mut connection).await.unwrap();
    let sequence: i64 = sqlx::query_scalar(
        "SELECT MAX(observation_sequence) FROM provider_quota_window_observations",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert!(sequence > before.0);
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(integrity, "ok");
}
