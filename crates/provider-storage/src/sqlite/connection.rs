use super::*;

// A short-lived pre-release image bundled the changes now represented by
// migrations 2 and 3 into migration 1. Normalize only that exact checksum and
// only after verifying the resulting schema, so unknown migration histories
// still fail closed in SQLx.
const BUNDLED_V1_CHECKSUM: [u8; 48] = [
    0xba, 0x82, 0xe6, 0x2c, 0xfc, 0x60, 0xb6, 0xd2, 0x95, 0x53, 0xbe, 0xb5, 0x2c, 0x4f, 0x47, 0x05,
    0x7c, 0x95, 0xa1, 0x4a, 0x96, 0x9d, 0x49, 0x14, 0x0d, 0x8a, 0x0c, 0xa5, 0x17, 0xad, 0x3a, 0x98,
    0x10, 0x11, 0x95, 0x7d, 0xa0, 0x2c, 0x63, 0x15, 0x5c, 0x1d, 0xec, 0x54, 0xe7, 0xcd, 0x96, 0xc2,
];

impl SqliteAccountRepository {
    pub async fn connect(
        path: impl AsRef<Path>,
        credential_key: [u8; 32],
    ) -> Result<Self, AccountRepositoryError> {
        let path = path.as_ref();
        prepare_data_directory(path)?;

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5))
            .disable_statement_logging();
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|error| repository_error("failed to open SQLite database", error))?;

        normalize_bundled_v1_migration_history(&pool)
            .await
            .map_err(|error| repository_error("failed to normalize SQLite migrations", error))?;

        MIGRATOR
            .run(&pool)
            .await
            .map_err(|error| repository_error("failed to run SQLite migrations", error))?;
        restrict_sqlite_permissions(path)?;

        Ok(Self {
            pool,
            credential_cipher: CredentialCipher::new(credential_key),
        })
    }

    #[cfg(any(test, feature = "test-util"))]
    #[doc(hidden)]
    pub async fn in_memory() -> Result<Self, AccountRepositoryError> {
        // `foreign_keys` must match `connect`: cascade deletes are part of the
        // schema's meaning, so a test database without them would not be
        // exercising the real one.
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|error| repository_error("failed to open test SQLite database", error))?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|error| repository_error("failed to run test SQLite migrations", error))?;
        Ok(Self {
            pool,
            credential_cipher: CredentialCipher::new([0x5a; 32]),
        })
    }

    /// Observed usage facts live in the same database, so they share this pool
    /// rather than opening a second one.
    #[must_use]
    pub fn usage_repository(&self) -> crate::SqliteUsageRepository {
        crate::usage::SqliteUsageRepository::new(self.pool.clone())
    }
}

async fn normalize_bundled_v1_migration_history(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let checksum: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT checksum FROM _sqlx_migrations WHERE version = 1 AND success = 1",
    )
    .fetch_optional(pool)
    .await
    .or_else(|error| {
        if matches!(&error, sqlx::Error::Database(database) if database.message().contains("no such table")) {
            Ok(None)
        } else {
            Err(error)
        }
    })?;
    if checksum.as_deref() != Some(BUNDLED_V1_CHECKSUM.as_slice()) {
        return Ok(());
    }

    for (table, column) in [
        ("provider_accounts", "priority"),
        ("provider_models", "input_modalities_json"),
        ("provider_models", "input_modalities_source"),
    ] {
        let present: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?")
                .bind(table)
                .bind(column)
                .fetch_one(pool)
                .await?;
        if present != 1 {
            return Err(sqlx::Error::Protocol(format!(
                "bundled migration history is missing {table}.{column}"
            )));
        }
    }

    let migration_1 = &MIGRATOR.migrations[0];
    let migration_3 = &MIGRATOR.migrations[2];
    let mut connection = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *connection)
        .await?;
    let result = async {
        sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = 1")
            .bind(migration_1.checksum.as_ref())
            .execute(&mut *connection)
            .await?;
        sqlx::query(
            r#"
            INSERT INTO _sqlx_migrations (
                version, description, success, checksum, execution_time
            ) VALUES (?, ?, 1, ?, 0)
            ON CONFLICT (version) DO NOTHING
            "#,
        )
        .bind(migration_3.version)
        .bind(migration_3.description.as_ref())
        .bind(migration_3.checksum.as_ref())
        .execute(&mut *connection)
        .await?;
        Ok::<(), sqlx::Error>(())
    }
    .await;
    match result {
        Ok(()) => sqlx::query("COMMIT")
            .execute(&mut *connection)
            .await
            .map(|_| ()),
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
            Err(error)
        }
    }
}

fn prepare_data_directory(path: &Path) -> Result<(), AccountRepositoryError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    std::fs::create_dir_all(parent)
        .map_err(|error| repository_error("failed to create SQLite data directory", error))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| repository_error("failed to restrict SQLite data directory", error))?;
    }
    Ok(())
}

fn restrict_sqlite_permissions(path: &Path) -> Result<(), AccountRepositoryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        for file in sqlite_files(path) {
            match std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(repository_error(
                        "failed to restrict SQLite database files",
                        error,
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn sqlite_files(path: &Path) -> [std::path::PathBuf; 3] {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let mut shared_memory = path.as_os_str().to_owned();
    shared_memory.push("-shm");
    [path.to_path_buf(), wal.into(), shared_memory.into()]
}
