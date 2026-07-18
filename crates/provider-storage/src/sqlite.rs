use std::{path::Path, str::FromStr, time::Duration};

use async_trait::async_trait;
use provider_core::{
    AccountAuthState, AccountId, AccountRepository, AccountRepositoryError, CredentialUpdate,
    CredentialWriteOutcome, StoredCredential, StoredProviderAccount,
};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{
    ConnectOptions, Row, SqlitePool,
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow},
};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct SqliteAccountRepository {
    pool: SqlitePool,
}

impl SqliteAccountRepository {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, AccountRepositoryError> {
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

        MIGRATOR
            .run(&pool)
            .await
            .map_err(|error| repository_error("failed to run SQLite migrations", error))?;
        restrict_sqlite_permissions(path)?;

        Ok(Self { pool })
    }

    #[cfg(test)]
    async fn in_memory() -> Result<Self, AccountRepositoryError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|error| repository_error("failed to open test SQLite database", error))?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|error| repository_error("failed to run test SQLite migrations", error))?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl AccountRepository for SqliteAccountRepository {
    async fn load_enabled_accounts(
        &self,
    ) -> Result<Vec<StoredProviderAccount>, AccountRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                a.id,
                a.provider,
                a.label,
                a.enabled,
                a.auth_state,
                a.safe_error_code,
                a.created_at,
                a.updated_at,
                c.revision,
                c.format_version,
                c.credential_json,
                c.expires_at,
                c.last_refreshed_at,
                c.updated_at AS credential_updated_at
            FROM provider_accounts AS a
            LEFT JOIN provider_credentials AS c ON c.account_id = a.id
            WHERE a.enabled = 1
            ORDER BY a.created_at, a.id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| repository_error("failed to load provider accounts", error))?;

        rows.into_iter().map(stored_account).collect()
    }

    async fn compare_and_swap_credential(
        &self,
        account_id: &AccountId,
        update: CredentialUpdate,
    ) -> Result<CredentialWriteOutcome, AccountRepositoryError> {
        let expected_revision = database_integer(update.expected_revision, "credential revision")?;
        let next_revision = update
            .expected_revision
            .checked_add(1)
            .ok_or_else(|| AccountRepositoryError::new("credential revision overflow"))?;
        database_integer(next_revision, "credential revision")?;
        let format_version = i64::from(update.format_version);

        let mut transaction =
            self.pool.begin().await.map_err(|error| {
                repository_error("failed to start credential transaction", error)
            })?;
        let result = sqlx::query(
            r#"
            UPDATE provider_credentials
            SET
                revision = revision + 1,
                format_version = ?,
                credential_json = ?,
                expires_at = ?,
                last_refreshed_at = ?,
                updated_at = ?
            WHERE account_id = ? AND revision = ?
            "#,
        )
        .bind(format_version)
        .bind(update.credential_json.expose_secret())
        .bind(update.expires_at)
        .bind(update.last_refreshed_at)
        .bind(update.updated_at)
        .bind(account_id.as_str())
        .bind(expected_revision)
        .execute(&mut *transaction)
        .await
        .map_err(|error| repository_error("failed to update provider credential", error))?;

        if result.rows_affected() == 0 {
            transaction.rollback().await.map_err(|error| {
                repository_error("failed to roll back credential conflict", error)
            })?;
            return Ok(CredentialWriteOutcome::Conflict);
        }

        sqlx::query(
            r#"
            UPDATE provider_accounts
            SET auth_state = 'active', safe_error_code = NULL, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(update.updated_at)
        .bind(account_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| repository_error("failed to update provider account state", error))?;

        transaction
            .commit()
            .await
            .map_err(|error| repository_error("failed to commit credential update", error))?;

        Ok(CredentialWriteOutcome::Updated {
            revision: next_revision,
        })
    }

    async fn update_auth_state(
        &self,
        account_id: &AccountId,
        state: AccountAuthState,
        safe_error_code: Option<&str>,
        updated_at: i64,
    ) -> Result<(), AccountRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE provider_accounts
            SET auth_state = ?, safe_error_code = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(state.as_str())
        .bind(safe_error_code)
        .bind(updated_at)
        .bind(account_id.as_str())
        .execute(&self.pool)
        .await
        .map_err(|error| repository_error("failed to update provider account auth state", error))?;

        if result.rows_affected() == 0 {
            return Err(AccountRepositoryError::new(
                "provider account was not found while updating auth state",
            ));
        }
        Ok(())
    }
}

fn stored_account(row: SqliteRow) -> Result<StoredProviderAccount, AccountRepositoryError> {
    let id = row_value::<String>(&row, "id")?;
    let id = AccountId::new(id).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account ID: {error}"))
    })?;
    let auth_state = row_value::<String>(&row, "auth_state")?;
    let auth_state = AccountAuthState::from_str(&auth_state).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account auth state: {error}"))
    })?;
    let revision = required_joined_value::<i64>(&row, "revision", &id)?;
    let format_version = required_joined_value::<i64>(&row, "format_version", &id)?;
    let credential_json = required_joined_value::<String>(&row, "credential_json", &id)?;
    let credential_updated_at = required_joined_value::<i64>(&row, "credential_updated_at", &id)?;

    Ok(StoredProviderAccount {
        id,
        provider: row_value(&row, "provider")?,
        label: row_value(&row, "label")?,
        enabled: row_value::<i64>(&row, "enabled")? != 0,
        auth_state,
        safe_error_code: row_value(&row, "safe_error_code")?,
        created_at: row_value(&row, "created_at")?,
        updated_at: row_value(&row, "updated_at")?,
        credential: StoredCredential {
            revision: non_negative_u64(revision, "credential revision")?,
            format_version: positive_u32(format_version, "credential format version")?,
            credential_json: SecretString::from(credential_json),
            expires_at: row_value(&row, "expires_at")?,
            last_refreshed_at: row_value(&row, "last_refreshed_at")?,
            updated_at: credential_updated_at,
        },
    })
}

fn row_value<T>(row: &SqliteRow, column: &str) -> Result<T, AccountRepositoryError>
where
    for<'row> T: sqlx::Decode<'row, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row.try_get(column)
        .map_err(|error| repository_error("failed to decode provider account row", error))
}

fn required_joined_value<T>(
    row: &SqliteRow,
    column: &str,
    account_id: &AccountId,
) -> Result<T, AccountRepositoryError>
where
    for<'row> T: sqlx::Decode<'row, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row_value::<Option<T>>(row, column)?.ok_or_else(|| {
        AccountRepositoryError::new(format!(
            "enabled provider account {account_id} is missing credentials"
        ))
    })
}

fn non_negative_u64(value: i64, field: &str) -> Result<u64, AccountRepositoryError> {
    u64::try_from(value)
        .map_err(|_| AccountRepositoryError::new(format!("{field} must not be negative")))
}

fn positive_u32(value: i64, field: &str) -> Result<u32, AccountRepositoryError> {
    let value = u32::try_from(value)
        .map_err(|_| AccountRepositoryError::new(format!("{field} is out of range")))?;
    if value == 0 {
        return Err(AccountRepositoryError::new(format!(
            "{field} must be positive"
        )));
    }
    Ok(value)
}

fn database_integer(value: u64, field: &str) -> Result<i64, AccountRepositoryError> {
    i64::try_from(value)
        .map_err(|_| AccountRepositoryError::new(format!("{field} is out of range")))
}

fn repository_error(operation: &str, error: impl std::fmt::Display) -> AccountRepositoryError {
    AccountRepositoryError::new(format!("{operation}: {error}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrates_and_compare_and_swaps_credentials() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        sqlx::query(
            r#"
            INSERT INTO provider_accounts
                (id, provider, label, enabled, auth_state)
            VALUES ('grok-main', 'grok', 'Main', 1, 'active')
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("insert account");
        sqlx::query(
            r#"
            INSERT INTO provider_credentials
                (account_id, revision, format_version, credential_json, expires_at)
            VALUES ('grok-main', 0, 1, '{"access_token":"old"}', 100)
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("insert credential");

        let accounts = repository
            .load_enabled_accounts()
            .await
            .expect("load accounts");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id.as_str(), "grok-main");
        assert_eq!(accounts[0].credential.revision, 0);
        assert!(accounts[0].created_at > 0);
        assert!(accounts[0].updated_at > 0);
        assert!(accounts[0].credential.updated_at > 0);

        let update = CredentialUpdate {
            expected_revision: 0,
            format_version: 1,
            credential_json: SecretString::from(r#"{"access_token":"new"}"#.to_owned()),
            expires_at: Some(200),
            last_refreshed_at: Some(10),
            updated_at: 10,
        };
        let outcome = repository
            .compare_and_swap_credential(&accounts[0].id, update.clone())
            .await
            .expect("credential update");
        assert_eq!(outcome, CredentialWriteOutcome::Updated { revision: 1 });

        let conflict = repository
            .compare_and_swap_credential(&accounts[0].id, update)
            .await
            .expect("stale credential update");
        assert_eq!(conflict, CredentialWriteOutcome::Conflict);

        let reloaded = repository
            .load_enabled_accounts()
            .await
            .expect("reload accounts");
        assert_eq!(reloaded[0].credential.revision, 1);
        assert_eq!(
            reloaded[0].credential.credential_json.expose_secret(),
            r#"{"access_token":"new"}"#
        );
    }
}
