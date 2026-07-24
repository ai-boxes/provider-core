use std::{path::Path, str::FromStr, time::Duration};

use async_trait::async_trait;
use provider_auth::{
    ApiKeyId, AuthRepository, AuthRepositoryError, InitialUserCreateOutcome, NewApiKey, NewSession,
    NewUser, RefreshSessionOutcome, SessionId, StoredApiKey, StoredSession, StoredUser, UserId,
    UserRole, UserSummary,
};
use provider_core::{
    AccountAuthState, AccountId, AccountRepository, AccountRepositoryError, CredentialKind,
    CredentialUpdate, CredentialWriteOutcome, DiscoveredProviderModel, NewProviderAccount,
    ProviderAccountCreateOutcome, ProviderAccountSummary, ProviderAccountUpdate, ProviderKind,
    ProviderManagementRepository, ProviderModelOverride, ProviderVisibility, StoredCredential,
    StoredProviderAccount, StoredProviderModel,
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

    #[cfg(any(test, feature = "test-util"))]
    #[doc(hidden)]
    pub async fn in_memory() -> Result<Self, AccountRepositoryError> {
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
                a.owner_user_id,
                a.visibility,
                a.provider,
                a.label,
                a.config_json,
                a.enabled,
                a.auth_state,
                a.safe_error_code,
                a.created_at,
                a.updated_at,
                c.revision,
                c.credential_kind,
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
                credential_kind = ?,
                format_version = ?,
                credential_json = ?,
                expires_at = ?,
                last_refreshed_at = ?,
                updated_at = ?
            WHERE account_id = ? AND revision = ?
            "#,
        )
        .bind(update.kind.as_str())
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

#[async_trait]
impl ProviderManagementRepository for SqliteAccountRepository {
    async fn list_provider_accounts(
        &self,
        actor_user_id: &str,
    ) -> Result<Vec<ProviderAccountSummary>, AccountRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                a.id,
                a.owner_user_id,
                a.visibility,
                a.provider,
                a.label,
                a.config_json,
                a.enabled,
                a.auth_state,
                a.safe_error_code,
                a.created_at,
                a.updated_at,
                c.revision,
                c.credential_kind
            FROM provider_accounts AS a
            INNER JOIN provider_credentials AS c ON c.account_id = a.id
            WHERE a.owner_user_id IS NOT NULL
              AND (a.owner_user_id = ? OR a.visibility = 'shared')
            ORDER BY a.created_at, a.id
            "#,
        )
        .bind(actor_user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| repository_error("failed to list provider accounts", error))?;

        rows.into_iter().map(account_summary).collect()
    }

    async fn load_provider_account(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<StoredProviderAccount>, AccountRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                a.id,
                a.owner_user_id,
                a.visibility,
                a.provider,
                a.label,
                a.config_json,
                a.enabled,
                a.auth_state,
                a.safe_error_code,
                a.created_at,
                a.updated_at,
                c.revision,
                c.credential_kind,
                c.format_version,
                c.credential_json,
                c.expires_at,
                c.last_refreshed_at,
                c.updated_at AS credential_updated_at
            FROM provider_accounts AS a
            LEFT JOIN provider_credentials AS c ON c.account_id = a.id
            WHERE a.id = ?
            "#,
        )
        .bind(account_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| repository_error("failed to load provider account", error))?;

        row.map(stored_account).transpose()
    }

    async fn create_provider_account(
        &self,
        account: NewProviderAccount,
        owner_user_id: &str,
        visibility: ProviderVisibility,
    ) -> Result<ProviderAccountCreateOutcome, AccountRepositoryError> {
        let format_version = i64::from(account.credential.format_version);
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| repository_error("failed to start account transaction", error))?;
        let inserted = sqlx::query(
            r#"
            INSERT INTO provider_accounts
                (id, owner_user_id, visibility, provider, label, config_json, enabled, auth_state)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
            ON CONFLICT(id) DO NOTHING
            "#,
        )
        .bind(account.id.as_str())
        .bind(owner_user_id)
        .bind(visibility.as_str())
        .bind(account.provider.as_str())
        .bind(account.label)
        .bind(account.config_json)
        .bind(database_bool(account.enabled))
        .execute(&mut *transaction)
        .await
        .map_err(|error| repository_error("failed to create provider account", error))?;

        if inserted.rows_affected() == 0 {
            transaction.rollback().await.map_err(|error| {
                repository_error("failed to roll back duplicate account", error)
            })?;
            return Ok(ProviderAccountCreateOutcome::Conflict);
        }

        sqlx::query(
            r#"
            INSERT INTO provider_credentials
                (account_id, credential_kind, revision, format_version, credential_json,
                 expires_at, last_refreshed_at)
            VALUES (?, ?, 0, ?, ?, ?, ?)
            "#,
        )
        .bind(account.id.as_str())
        .bind(account.credential.kind.as_str())
        .bind(format_version)
        .bind(account.credential.credential_json.expose_secret())
        .bind(account.credential.expires_at)
        .bind(account.credential.last_refreshed_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| repository_error("failed to create provider credential", error))?;

        transaction
            .commit()
            .await
            .map_err(|error| repository_error("failed to commit provider account", error))?;
        Ok(ProviderAccountCreateOutcome::Created)
    }

    async fn update_provider_account(
        &self,
        account_id: &AccountId,
        update: ProviderAccountUpdate,
    ) -> Result<bool, AccountRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE provider_accounts
            SET label = ?, config_json = ?, visibility = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(update.label)
        .bind(update.config_json)
        .bind(update.visibility.as_str())
        .bind(update.updated_at)
        .bind(account_id.as_str())
        .execute(&self.pool)
        .await
        .map_err(|error| repository_error("failed to update provider account", error))?;
        Ok(result.rows_affected() > 0)
    }

    async fn set_provider_account_enabled(
        &self,
        account_id: &AccountId,
        enabled: bool,
        updated_at: i64,
    ) -> Result<bool, AccountRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE provider_accounts
            SET enabled = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(database_bool(enabled))
        .bind(updated_at)
        .bind(account_id.as_str())
        .execute(&self.pool)
        .await
        .map_err(|error| repository_error("failed to update provider account status", error))?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_provider_account(
        &self,
        account_id: &AccountId,
    ) -> Result<bool, AccountRepositoryError> {
        let result = sqlx::query("DELETE FROM provider_accounts WHERE id = ?")
            .bind(account_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|error| repository_error("failed to delete provider account", error))?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_provider_models(
        &self,
        account_id: Option<&AccountId>,
    ) -> Result<Vec<StoredProviderModel>, AccountRepositoryError> {
        let rows = if let Some(account_id) = account_id {
            sqlx::query(
                r#"
                SELECT account_id, upstream_model, alias, enabled, available, routable, metadata_json,
                       last_seen_at, created_at, updated_at
                FROM provider_models
                WHERE account_id = ?
                ORDER BY upstream_model
                "#,
            )
            .bind(account_id.as_str())
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                r#"
                SELECT account_id, upstream_model, alias, enabled, available, routable, metadata_json,
                       last_seen_at, created_at, updated_at
                FROM provider_models
                ORDER BY account_id, upstream_model
                "#,
            )
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|error| repository_error("failed to list provider models", error))?;

        rows.into_iter().map(stored_model).collect()
    }

    async fn synchronize_provider_models(
        &self,
        account_id: &AccountId,
        models: Vec<DiscoveredProviderModel>,
        synced_at: i64,
    ) -> Result<Vec<StoredProviderModel>, AccountRepositoryError> {
        if models
            .iter()
            .any(|model| model.upstream_model.trim().is_empty())
        {
            return Err(AccountRepositoryError::new(
                "discovered provider model must not be empty",
            ));
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| repository_error("failed to start model transaction", error))?;
        let account_exists = sqlx::query("SELECT 1 FROM provider_accounts WHERE id = ?")
            .bind(account_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| repository_error("failed to verify provider account", error))?
            .is_some();
        if !account_exists {
            transaction.rollback().await.map_err(|error| {
                repository_error("failed to roll back missing account model sync", error)
            })?;
            return Err(AccountRepositoryError::new(
                "provider account was not found while synchronizing models",
            ));
        }

        sqlx::query(
            "UPDATE provider_models SET available = 0, updated_at = ? WHERE account_id = ?",
        )
        .bind(synced_at)
        .bind(account_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| repository_error("failed to mark provider models unavailable", error))?;

        for model in models {
            let upstream_model = model.upstream_model.trim();
            sqlx::query(
                r#"
                INSERT INTO provider_models
                    (account_id, upstream_model, enabled, available, routable, metadata_json,
                     last_seen_at, updated_at)
                VALUES (?, ?, 1, 1, ?, ?, ?, ?)
                ON CONFLICT(account_id, upstream_model) DO UPDATE SET
                    available = 1,
                    routable = excluded.routable,
                    metadata_json = excluded.metadata_json,
                    last_seen_at = excluded.last_seen_at,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(account_id.as_str())
            .bind(upstream_model)
            .bind(database_bool(model.routable))
            .bind(model.metadata_json)
            .bind(synced_at)
            .bind(synced_at)
            .execute(&mut *transaction)
            .await
            .map_err(|error| repository_error("failed to synchronize provider model", error))?;
        }

        transaction
            .commit()
            .await
            .map_err(|error| repository_error("failed to commit provider models", error))?;
        self.list_provider_models(Some(account_id)).await
    }

    async fn update_provider_model(
        &self,
        account_id: &AccountId,
        upstream_model: &str,
        update: ProviderModelOverride,
    ) -> Result<bool, AccountRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE provider_models
            SET alias = ?, enabled = ?, updated_at = ?
            WHERE account_id = ? AND upstream_model = ?
            "#,
        )
        .bind(update.alias)
        .bind(database_bool(update.enabled))
        .bind(update.updated_at)
        .bind(account_id.as_str())
        .bind(upstream_model)
        .execute(&self.pool)
        .await
        .map_err(|error| repository_error("failed to update provider model", error))?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl AuthRepository for SqliteAccountRepository {
    async fn setup_required(&self) -> Result<bool, AuthRepositoryError> {
        let row = sqlx::query("SELECT initial_user_id FROM auth_setup WHERE singleton = 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|error| auth_repository_error("failed to load setup state", error))?;
        Ok(auth_row_value::<Option<String>>(&row, "initial_user_id")?.is_none())
    }

    async fn create_initial_user(
        &self,
        user: NewUser,
        session: NewSession,
    ) -> Result<InitialUserCreateOutcome, AuthRepositoryError> {
        if session.user_id != user.id {
            return Err(AuthRepositoryError::new(
                "initial session must belong to the initial user",
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(|error| {
            auth_repository_error("failed to start initial user transaction", error)
        })?;
        let inserted = sqlx::query(
            r#"
            INSERT INTO users
                (id, username, password_hash, role, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(user.id.as_str())
        .bind(user.username)
        .bind(user.password_hash)
        .bind(user.role.as_str())
        .bind(database_bool(user.enabled))
        .bind(user.created_at)
        .bind(user.created_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| auth_repository_error("failed to create initial user", error))?;
        if inserted.rows_affected() == 0 {
            transaction.rollback().await.map_err(|error| {
                auth_repository_error("failed to roll back initial user conflict", error)
            })?;
            return Ok(InitialUserCreateOutcome::AlreadyConfigured);
        }

        let claimed = sqlx::query(
            r#"
            UPDATE auth_setup
            SET initial_user_id = ?
            WHERE singleton = 1 AND initial_user_id IS NULL
            "#,
        )
        .bind(user.id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| auth_repository_error("failed to claim initial setup", error))?;
        if claimed.rows_affected() == 0 {
            transaction.rollback().await.map_err(|error| {
                auth_repository_error("failed to roll back completed setup", error)
            })?;
            return Ok(InitialUserCreateOutcome::AlreadyConfigured);
        }

        sqlx::query(
            r#"
            UPDATE provider_accounts
            SET owner_user_id = ?, visibility = 'private'
            WHERE owner_user_id IS NULL
            "#,
        )
        .bind(user.id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            auth_repository_error("failed to assign existing providers to initial user", error)
        })?;

        sqlx::query(
            r#"
            INSERT INTO user_sessions
                (id, user_id, access_token_hash, refresh_token_hash, access_expires_at,
                 refresh_expires_at, absolute_expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(session.id.as_str())
        .bind(session.user_id.as_str())
        .bind(session.access_token_hash.as_slice())
        .bind(session.refresh_token_hash.as_slice())
        .bind(session.access_expires_at)
        .bind(session.refresh_expires_at)
        .bind(session.absolute_expires_at)
        .bind(session.created_at)
        .bind(session.created_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| auth_repository_error("failed to create initial session", error))?;

        transaction
            .commit()
            .await
            .map_err(|error| auth_repository_error("failed to commit initial user", error))?;
        Ok(InitialUserCreateOutcome::Created)
    }

    async fn load_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<StoredUser>, AuthRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT id, username, password_hash, role, enabled, created_at, updated_at
            FROM users
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to load user by username", error))?;
        row.map(stored_user).transpose()
    }

    async fn load_user(&self, user_id: &UserId) -> Result<Option<StoredUser>, AuthRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT id, username, password_hash, role, enabled, created_at, updated_at
            FROM users
            WHERE id = ?
            "#,
        )
        .bind(user_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to load user", error))?;
        row.map(stored_user).transpose()
    }

    async fn list_users(&self) -> Result<Vec<UserSummary>, AuthRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, username, role, enabled, created_at, updated_at
            FROM users
            ORDER BY created_at, id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to list users", error))?;
        rows.into_iter().map(user_summary).collect()
    }

    async fn create_user(&self, user: NewUser) -> Result<bool, AuthRepositoryError> {
        let result = sqlx::query(
            r#"
            INSERT INTO users
                (id, username, password_hash, role, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(user.id.as_str())
        .bind(user.username)
        .bind(user.password_hash)
        .bind(user.role.as_str())
        .bind(database_bool(user.enabled))
        .bind(user.created_at)
        .bind(user.created_at)
        .execute(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to create user", error))?;
        Ok(result.rows_affected() > 0)
    }

    async fn set_user_enabled(
        &self,
        user_id: &UserId,
        enabled: bool,
        updated_at: i64,
    ) -> Result<bool, AuthRepositoryError> {
        let result = sqlx::query("UPDATE users SET enabled = ?, updated_at = ? WHERE id = ?")
            .bind(database_bool(enabled))
            .bind(updated_at)
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|error| auth_repository_error("failed to update user status", error))?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_user_password(
        &self,
        user_id: &UserId,
        password_hash: String,
        updated_at: i64,
    ) -> Result<bool, AuthRepositoryError> {
        let result = sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(password_hash)
            .bind(updated_at)
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|error| auth_repository_error("failed to update user password", error))?;
        Ok(result.rows_affected() > 0)
    }

    async fn create_session(&self, session: NewSession) -> Result<(), AuthRepositoryError> {
        sqlx::query(
            r#"
            INSERT INTO user_sessions
                (id, user_id, access_token_hash, refresh_token_hash, access_expires_at,
                 refresh_expires_at, absolute_expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(session.id.as_str())
        .bind(session.user_id.as_str())
        .bind(session.access_token_hash.as_slice())
        .bind(session.refresh_token_hash.as_slice())
        .bind(session.access_expires_at)
        .bind(session.refresh_expires_at)
        .bind(session.absolute_expires_at)
        .bind(session.created_at)
        .bind(session.created_at)
        .execute(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to create user session", error))?;
        Ok(())
    }

    async fn load_session_by_access_hash(
        &self,
        access_token_hash: &[u8; 32],
    ) -> Result<Option<StoredSession>, AuthRepositoryError> {
        load_session(&self.pool, SESSION_BY_ACCESS_SQL, access_token_hash).await
    }

    async fn load_session_by_refresh_hash(
        &self,
        refresh_token_hash: &[u8; 32],
    ) -> Result<Option<StoredSession>, AuthRepositoryError> {
        load_session(&self.pool, SESSION_BY_REFRESH_SQL, refresh_token_hash).await
    }

    async fn rotate_session(
        &self,
        refresh_token_hash: &[u8; 32],
        new_access_token_hash: [u8; 32],
        new_refresh_token_hash: [u8; 32],
        access_expires_at: i64,
        refresh_expires_at: i64,
        updated_at: i64,
    ) -> Result<RefreshSessionOutcome, AuthRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE user_sessions
            SET access_token_hash = ?, refresh_token_hash = ?, access_expires_at = ?,
                refresh_expires_at = ?, updated_at = ?
            WHERE refresh_token_hash = ?
              AND revoked_at IS NULL
              AND refresh_expires_at > ?
              AND absolute_expires_at > ?
            "#,
        )
        .bind(new_access_token_hash.as_slice())
        .bind(new_refresh_token_hash.as_slice())
        .bind(access_expires_at)
        .bind(refresh_expires_at)
        .bind(updated_at)
        .bind(refresh_token_hash.as_slice())
        .bind(updated_at)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to rotate user session", error))?;
        Ok(if result.rows_affected() > 0 {
            RefreshSessionOutcome::Updated
        } else {
            RefreshSessionOutcome::Invalid
        })
    }

    async fn revoke_session(
        &self,
        session_id: &SessionId,
        revoked_at: i64,
    ) -> Result<bool, AuthRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE user_sessions
            SET revoked_at = ?, updated_at = ?
            WHERE id = ? AND revoked_at IS NULL
            "#,
        )
        .bind(revoked_at)
        .bind(revoked_at)
        .bind(session_id.as_str())
        .execute(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to revoke user session", error))?;
        Ok(result.rows_affected() > 0)
    }

    async fn revoke_user_sessions(
        &self,
        user_id: &UserId,
        revoked_at: i64,
    ) -> Result<u64, AuthRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE user_sessions
            SET revoked_at = ?, updated_at = ?
            WHERE user_id = ? AND revoked_at IS NULL
            "#,
        )
        .bind(revoked_at)
        .bind(revoked_at)
        .bind(user_id.as_str())
        .execute(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to revoke user sessions", error))?;
        Ok(result.rows_affected())
    }

    async fn create_api_key(&self, key: NewApiKey) -> Result<bool, AuthRepositoryError> {
        let result = sqlx::query(
            r#"
            INSERT INTO api_keys
                (id, owner_user_id, label, key, enabled, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(key.id.as_str())
        .bind(key.owner_user_id.as_str())
        .bind(key.label)
        .bind(key.key.expose_secret())
        .bind(database_bool(key.enabled))
        .bind(key.expires_at)
        .bind(key.created_at)
        .bind(key.created_at)
        .execute(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to create API key", error))?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_api_keys(
        &self,
        owner_user_id: &UserId,
    ) -> Result<Vec<StoredApiKey>, AuthRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, owner_user_id, label, key, enabled, expires_at, last_used_at,
                   created_at, updated_at
            FROM api_keys
            WHERE owner_user_id = ?
            ORDER BY created_at, id
            "#,
        )
        .bind(owner_user_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to list API keys", error))?;
        rows.into_iter().map(stored_api_key).collect()
    }

    async fn load_api_key(
        &self,
        owner_user_id: &UserId,
        key_id: &ApiKeyId,
    ) -> Result<Option<StoredApiKey>, AuthRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT id, owner_user_id, label, key, enabled, expires_at, last_used_at,
                   created_at, updated_at
            FROM api_keys
            WHERE id = ? AND owner_user_id = ?
            "#,
        )
        .bind(key_id.as_str())
        .bind(owner_user_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to load API key", error))?;
        row.map(stored_api_key).transpose()
    }

    async fn update_api_key(
        &self,
        owner_user_id: &UserId,
        key_id: &ApiKeyId,
        enabled: bool,
        expires_at: Option<i64>,
        updated_at: i64,
    ) -> Result<Option<StoredApiKey>, AuthRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE api_keys
            SET enabled = ?, expires_at = ?, updated_at = ?
            WHERE id = ? AND owner_user_id = ?
            RETURNING id, owner_user_id, label, key, enabled, expires_at,
                      last_used_at, created_at, updated_at
            "#,
        )
        .bind(database_bool(enabled))
        .bind(expires_at)
        .bind(updated_at)
        .bind(key_id.as_str())
        .bind(owner_user_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to update API key", error))?;
        row.map(stored_api_key).transpose()
    }

    async fn delete_api_key(
        &self,
        owner_user_id: &UserId,
        key_id: &ApiKeyId,
    ) -> Result<bool, AuthRepositoryError> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = ? AND owner_user_id = ?")
            .bind(key_id.as_str())
            .bind(owner_user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|error| auth_repository_error("failed to delete API key", error))?;
        Ok(result.rows_affected() > 0)
    }

    async fn load_active_api_keys(&self) -> Result<Vec<StoredApiKey>, AuthRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT k.id, k.owner_user_id, k.label, k.key, k.enabled, k.expires_at,
                   k.last_used_at, k.created_at, k.updated_at
            FROM api_keys AS k
            INNER JOIN users AS u ON u.id = k.owner_user_id
            WHERE k.enabled = 1 AND u.enabled = 1
            ORDER BY k.created_at, k.id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to load active API keys", error))?;
        rows.into_iter().map(stored_api_key).collect()
    }
}

async fn load_session(
    pool: &SqlitePool,
    query: &'static str,
    token_hash: &[u8; 32],
) -> Result<Option<StoredSession>, AuthRepositoryError> {
    let row = sqlx::query(query)
        .bind(token_hash.as_slice())
        .fetch_optional(pool)
        .await
        .map_err(|error| auth_repository_error("failed to load user session", error))?;
    row.map(stored_session).transpose()
}

const SESSION_BY_ACCESS_SQL: &str = r#"
    SELECT
        s.id,
        s.access_token_hash,
        s.refresh_token_hash,
        s.access_expires_at,
        s.refresh_expires_at,
        s.absolute_expires_at,
        s.revoked_at,
        s.created_at,
        s.updated_at,
        u.id AS user_id,
        u.username,
        u.role,
        u.enabled,
        u.created_at AS user_created_at,
        u.updated_at AS user_updated_at
    FROM user_sessions AS s
    INNER JOIN users AS u ON u.id = s.user_id
    WHERE s.access_token_hash = ?
    "#;

const SESSION_BY_REFRESH_SQL: &str = r#"
    SELECT
        s.id,
        s.access_token_hash,
        s.refresh_token_hash,
        s.access_expires_at,
        s.refresh_expires_at,
        s.absolute_expires_at,
        s.revoked_at,
        s.created_at,
        s.updated_at,
        u.id AS user_id,
        u.username,
        u.role,
        u.enabled,
        u.created_at AS user_created_at,
        u.updated_at AS user_updated_at
    FROM user_sessions AS s
    INNER JOIN users AS u ON u.id = s.user_id
    WHERE s.refresh_token_hash = ?
    "#;

fn stored_account(row: SqliteRow) -> Result<StoredProviderAccount, AccountRepositoryError> {
    let id = row_value::<String>(&row, "id")?;
    let id = AccountId::new(id).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account ID: {error}"))
    })?;
    let auth_state = row_value::<String>(&row, "auth_state")?;
    let auth_state = AccountAuthState::from_str(&auth_state).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account auth state: {error}"))
    })?;
    let provider = row_value::<String>(&row, "provider")?;
    let provider = ProviderKind::from_str(&provider).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account type: {error}"))
    })?;
    let credential_kind = required_joined_value::<String>(&row, "credential_kind", &id)?;
    let credential_kind = CredentialKind::from_str(&credential_kind).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider credential type: {error}"))
    })?;
    let revision = required_joined_value::<i64>(&row, "revision", &id)?;
    let format_version = required_joined_value::<i64>(&row, "format_version", &id)?;
    let credential_json = required_joined_value::<String>(&row, "credential_json", &id)?;
    let credential_updated_at = required_joined_value::<i64>(&row, "credential_updated_at", &id)?;

    Ok(StoredProviderAccount {
        id,
        owner_user_id: row_value(&row, "owner_user_id")?,
        visibility: provider_visibility(&row)?,
        provider,
        label: row_value(&row, "label")?,
        config_json: row_value(&row, "config_json")?,
        enabled: row_value::<i64>(&row, "enabled")? != 0,
        auth_state,
        safe_error_code: row_value(&row, "safe_error_code")?,
        created_at: row_value(&row, "created_at")?,
        updated_at: row_value(&row, "updated_at")?,
        credential: StoredCredential {
            kind: credential_kind,
            revision: non_negative_u64(revision, "credential revision")?,
            format_version: positive_u32(format_version, "credential format version")?,
            credential_json: SecretString::from(credential_json),
            expires_at: row_value(&row, "expires_at")?,
            last_refreshed_at: row_value(&row, "last_refreshed_at")?,
            updated_at: credential_updated_at,
        },
    })
}

fn account_summary(row: SqliteRow) -> Result<ProviderAccountSummary, AccountRepositoryError> {
    let id = row_value::<String>(&row, "id")?;
    let id = AccountId::new(id).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account ID: {error}"))
    })?;
    let provider = row_value::<String>(&row, "provider")?;
    let provider = ProviderKind::from_str(&provider).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account type: {error}"))
    })?;
    let credential_kind = row_value::<String>(&row, "credential_kind")?;
    let credential_kind = CredentialKind::from_str(&credential_kind).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider credential type: {error}"))
    })?;
    let auth_state = row_value::<String>(&row, "auth_state")?;
    let auth_state = AccountAuthState::from_str(&auth_state).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account auth state: {error}"))
    })?;

    Ok(ProviderAccountSummary {
        id,
        owner_user_id: row_value(&row, "owner_user_id")?,
        visibility: provider_visibility(&row)?,
        provider,
        label: row_value(&row, "label")?,
        config_json: row_value(&row, "config_json")?,
        credential_kind,
        credential_revision: row_value::<i64>(&row, "revision")?
            .try_into()
            .map_err(|_| AccountRepositoryError::new("invalid provider credential revision"))?,
        enabled: row_value::<i64>(&row, "enabled")? != 0,
        auth_state,
        safe_error_code: row_value(&row, "safe_error_code")?,
        created_at: row_value(&row, "created_at")?,
        updated_at: row_value(&row, "updated_at")?,
    })
}

fn stored_model(row: SqliteRow) -> Result<StoredProviderModel, AccountRepositoryError> {
    let account_id = row_value::<String>(&row, "account_id")?;
    let account_id = AccountId::new(account_id).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account ID: {error}"))
    })?;
    Ok(StoredProviderModel {
        account_id,
        upstream_model: row_value(&row, "upstream_model")?,
        alias: row_value(&row, "alias")?,
        enabled: row_value::<i64>(&row, "enabled")? != 0,
        available: row_value::<i64>(&row, "available")? != 0,
        routable: row_value::<i64>(&row, "routable")? != 0,
        metadata_json: row_value(&row, "metadata_json")?,
        last_seen_at: row_value(&row, "last_seen_at")?,
        created_at: row_value(&row, "created_at")?,
        updated_at: row_value(&row, "updated_at")?,
    })
}

fn provider_visibility(row: &SqliteRow) -> Result<ProviderVisibility, AccountRepositoryError> {
    ProviderVisibility::from_str(&row_value::<String>(row, "visibility")?).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider visibility: {error}"))
    })
}

fn stored_user(row: SqliteRow) -> Result<StoredUser, AuthRepositoryError> {
    Ok(StoredUser {
        id: auth_user_id(&row, "id")?,
        username: auth_row_value(&row, "username")?,
        password_hash: auth_row_value(&row, "password_hash")?,
        role: auth_user_role(&row, "role")?,
        enabled: auth_row_value::<i64>(&row, "enabled")? != 0,
        created_at: auth_row_value(&row, "created_at")?,
        updated_at: auth_row_value(&row, "updated_at")?,
    })
}

fn user_summary(row: SqliteRow) -> Result<UserSummary, AuthRepositoryError> {
    Ok(UserSummary {
        id: auth_user_id(&row, "id")?,
        username: auth_row_value(&row, "username")?,
        role: auth_user_role(&row, "role")?,
        enabled: auth_row_value::<i64>(&row, "enabled")? != 0,
        created_at: auth_row_value(&row, "created_at")?,
        updated_at: auth_row_value(&row, "updated_at")?,
    })
}

fn stored_session(row: SqliteRow) -> Result<StoredSession, AuthRepositoryError> {
    Ok(StoredSession {
        id: auth_session_id(&row, "id")?,
        user: UserSummary {
            id: auth_user_id(&row, "user_id")?,
            username: auth_row_value(&row, "username")?,
            role: auth_user_role(&row, "role")?,
            enabled: auth_row_value::<i64>(&row, "enabled")? != 0,
            created_at: auth_row_value(&row, "user_created_at")?,
            updated_at: auth_row_value(&row, "user_updated_at")?,
        },
        access_token_hash: auth_hash(&row, "access_token_hash")?,
        refresh_token_hash: auth_hash(&row, "refresh_token_hash")?,
        access_expires_at: auth_row_value(&row, "access_expires_at")?,
        refresh_expires_at: auth_row_value(&row, "refresh_expires_at")?,
        absolute_expires_at: auth_row_value(&row, "absolute_expires_at")?,
        revoked_at: auth_row_value(&row, "revoked_at")?,
        created_at: auth_row_value(&row, "created_at")?,
        updated_at: auth_row_value(&row, "updated_at")?,
    })
}

fn stored_api_key(row: SqliteRow) -> Result<StoredApiKey, AuthRepositoryError> {
    Ok(StoredApiKey {
        id: auth_api_key_id(&row, "id")?,
        owner_user_id: auth_user_id(&row, "owner_user_id")?,
        label: auth_row_value(&row, "label")?,
        key: SecretString::from(auth_row_value::<String>(&row, "key")?),
        enabled: auth_row_value::<i64>(&row, "enabled")? != 0,
        expires_at: auth_row_value(&row, "expires_at")?,
        last_used_at: auth_row_value(&row, "last_used_at")?,
        created_at: auth_row_value(&row, "created_at")?,
        updated_at: auth_row_value(&row, "updated_at")?,
    })
}

fn auth_user_id(row: &SqliteRow, column: &str) -> Result<UserId, AuthRepositoryError> {
    UserId::new(auth_row_value::<String>(row, column)?)
        .map_err(|error| AuthRepositoryError::new(format!("invalid user ID: {error}")))
}

fn auth_session_id(row: &SqliteRow, column: &str) -> Result<SessionId, AuthRepositoryError> {
    SessionId::new(auth_row_value::<String>(row, column)?)
        .map_err(|error| AuthRepositoryError::new(format!("invalid session ID: {error}")))
}

fn auth_api_key_id(row: &SqliteRow, column: &str) -> Result<ApiKeyId, AuthRepositoryError> {
    ApiKeyId::new(auth_row_value::<String>(row, column)?)
        .map_err(|error| AuthRepositoryError::new(format!("invalid API key ID: {error}")))
}

fn auth_user_role(row: &SqliteRow, column: &str) -> Result<UserRole, AuthRepositoryError> {
    UserRole::from_str(&auth_row_value::<String>(row, column)?)
        .map_err(|error| AuthRepositoryError::new(format!("invalid user role: {error}")))
}

fn auth_hash(row: &SqliteRow, column: &str) -> Result<[u8; 32], AuthRepositoryError> {
    auth_row_value::<Vec<u8>>(row, column)?
        .try_into()
        .map_err(|_| AuthRepositoryError::new(format!("{column} must contain exactly 32 bytes")))
}

fn auth_row_value<T>(row: &SqliteRow, column: &str) -> Result<T, AuthRepositoryError>
where
    for<'row> T: sqlx::Decode<'row, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row.try_get(column)
        .map_err(|error| auth_repository_error("failed to decode authentication row", error))
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

const fn database_bool(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn repository_error(operation: &str, error: impl std::fmt::Display) -> AccountRepositoryError {
    AccountRepositoryError::new(format!("{operation}: {error}"))
}

fn auth_repository_error(operation: &str, error: impl std::fmt::Display) -> AuthRepositoryError {
    AuthRepositoryError::new(format!("{operation}: {error}"))
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
        assert_eq!(accounts[0].provider, ProviderKind::Grok);
        assert_eq!(accounts[0].credential.kind, CredentialKind::Oauth);
        assert_eq!(accounts[0].credential.revision, 0);
        assert!(accounts[0].created_at > 0);
        assert!(accounts[0].updated_at > 0);
        assert!(accounts[0].credential.updated_at > 0);

        let update = CredentialUpdate {
            expected_revision: 0,
            kind: CredentialKind::Oauth,
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

    #[tokio::test]
    async fn round_trips_codex_provider_accounts() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        let owner = NewUser {
            id: UserId::new("codex-owner").expect("user ID"),
            username: "codex-owner".to_owned(),
            password_hash: "password-hash".to_owned(),
            role: UserRole::SuperAdmin,
            enabled: true,
            created_at: 1,
        };
        repository
            .create_initial_user(owner.clone(), test_session("codex-session", owner.id, 7, 8))
            .await
            .expect("create Codex owner");
        let account_id = AccountId::new("codex-main").expect("account ID");
        let credential_json = SecretString::from(
            r#"{"type":"codex","auth_kind":"oauth","access_token":"secret","refresh_token":"refresh","id_token":"header.payload.signature","last_refreshed_at":10}"#
                .to_owned(),
        );
        let account = NewProviderAccount {
            id: account_id.clone(),
            provider: ProviderKind::Codex,
            label: "Codex Main".to_owned(),
            config_json: "{}".to_owned(),
            enabled: true,
            credential: provider_core::NewCredential {
                kind: CredentialKind::Oauth,
                format_version: 1,
                credential_json: credential_json.clone(),
                expires_at: Some(100),
                last_refreshed_at: Some(10),
            },
        };

        assert_eq!(
            repository
                .create_provider_account(account, "codex-owner", ProviderVisibility::Shared)
                .await
                .expect("create Codex account"),
            ProviderAccountCreateOutcome::Created
        );
        let stored = repository
            .load_provider_account(&account_id)
            .await
            .expect("load Codex account")
            .expect("stored Codex account");

        assert_eq!(stored.provider, ProviderKind::Codex);
        assert_eq!(stored.visibility, ProviderVisibility::Shared);
        assert_eq!(stored.credential.kind, CredentialKind::Oauth);
        assert_eq!(stored.credential.expires_at, Some(100));
        assert_eq!(stored.credential.last_refreshed_at, Some(10));
        assert_eq!(
            stored.credential.credential_json.expose_secret(),
            credential_json.expose_secret()
        );
    }

    #[tokio::test]
    async fn creates_accounts_and_preserves_model_overrides_during_sync() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        let owner_user_id = UserId::new("model-owner").expect("user ID");
        repository
            .create_initial_user(
                NewUser {
                    id: owner_user_id.clone(),
                    username: "model-owner".to_owned(),
                    password_hash: "password-hash".to_owned(),
                    role: UserRole::SuperAdmin,
                    enabled: true,
                    created_at: 1,
                },
                test_session("model-owner-session", owner_user_id, 20, 21),
            )
            .await
            .expect("create model owner");
        let account_id = AccountId::new("grok-models").expect("account ID");
        let account = NewProviderAccount {
            id: account_id.clone(),
            provider: ProviderKind::Grok,
            label: "Grok Models".to_owned(),
            config_json: "{}".to_owned(),
            enabled: true,
            credential: provider_core::NewCredential {
                kind: CredentialKind::Oauth,
                format_version: 1,
                credential_json: SecretString::from(
                    r#"{"type":"xai","auth_kind":"oauth","access_token":"secret"}"#.to_owned(),
                ),
                expires_at: None,
                last_refreshed_at: None,
            },
        };
        assert_eq!(
            repository
                .create_provider_account(
                    account.clone(),
                    "model-owner",
                    ProviderVisibility::Private,
                )
                .await
                .expect("create account"),
            ProviderAccountCreateOutcome::Created
        );
        assert_eq!(
            repository
                .create_provider_account(account, "model-owner", ProviderVisibility::Private)
                .await
                .expect("duplicate account"),
            ProviderAccountCreateOutcome::Conflict
        );

        repository
            .synchronize_provider_models(
                &account_id,
                vec![
                    DiscoveredProviderModel {
                        upstream_model: "grok-a".to_owned(),
                        metadata_json: r#"{"version":1}"#.to_owned(),
                        routable: true,
                    },
                    DiscoveredProviderModel {
                        upstream_model: "grok-b".to_owned(),
                        metadata_json: "{}".to_owned(),
                        routable: true,
                    },
                ],
                10,
            )
            .await
            .expect("initial model sync");
        assert!(
            repository
                .update_provider_model(
                    &account_id,
                    "grok-a",
                    ProviderModelOverride {
                        alias: Some("grok-latest".to_owned()),
                        enabled: false,
                        updated_at: 11,
                    },
                )
                .await
                .expect("model override")
        );

        let models = repository
            .synchronize_provider_models(
                &account_id,
                vec![
                    DiscoveredProviderModel {
                        upstream_model: "grok-a".to_owned(),
                        metadata_json: r#"{"version":2}"#.to_owned(),
                        routable: true,
                    },
                    DiscoveredProviderModel {
                        upstream_model: "grok-c".to_owned(),
                        metadata_json: "{}".to_owned(),
                        routable: true,
                    },
                ],
                20,
            )
            .await
            .expect("second model sync");

        let model_a = models
            .iter()
            .find(|model| model.upstream_model == "grok-a")
            .expect("grok-a");
        assert_eq!(model_a.alias.as_deref(), Some("grok-latest"));
        assert!(!model_a.enabled);
        assert!(model_a.available);
        assert_eq!(model_a.metadata_json, r#"{"version":2}"#);
        assert!(
            !models
                .iter()
                .find(|model| model.upstream_model == "grok-b")
                .expect("grok-b")
                .available
        );
        assert!(
            models
                .iter()
                .find(|model| model.upstream_model == "grok-c")
                .expect("grok-c")
                .available
        );
    }

    #[tokio::test]
    async fn initial_setup_is_single_use_and_claims_existing_providers() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        sqlx::query(
            r#"
            INSERT INTO provider_accounts
                (id, provider, label, enabled, auth_state)
            VALUES ('existing-grok', 'grok', 'Existing Grok', 1, 'active')
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("insert existing provider");

        let initial_user = NewUser {
            id: UserId::new("user-initial").expect("user ID"),
            username: "admin".to_owned(),
            password_hash: "password-hash".to_owned(),
            role: UserRole::SuperAdmin,
            enabled: true,
            created_at: 100,
        };
        assert_eq!(
            repository
                .create_initial_user(
                    initial_user.clone(),
                    test_session("initial-session", initial_user.id.clone(), 10, 11),
                )
                .await
                .expect("create initial user"),
            InitialUserCreateOutcome::Created
        );
        let second_user = NewUser {
            id: UserId::new("user-second").expect("user ID"),
            username: "second".to_owned(),
            ..initial_user
        };
        assert_eq!(
            repository
                .create_initial_user(
                    second_user.clone(),
                    test_session("second-session", second_user.id, 12, 13),
                )
                .await
                .expect("reject second initial user"),
            InitialUserCreateOutcome::AlreadyConfigured
        );

        let row = sqlx::query(
            "SELECT owner_user_id, visibility FROM provider_accounts WHERE id = 'existing-grok'",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("load claimed provider");
        assert_eq!(
            row.try_get::<String, _>("owner_user_id")
                .expect("provider owner"),
            "user-initial"
        );
        assert_eq!(
            row.try_get::<String, _>("visibility")
                .expect("provider visibility"),
            "private"
        );
        assert!(
            repository
                .load_user_by_username("second")
                .await
                .expect("load user")
                .is_none()
        );
        assert!(
            repository
                .load_session_by_access_hash(&[10; 32])
                .await
                .expect("load initial session")
                .is_some()
        );
    }

    #[tokio::test]
    async fn refresh_rotation_consumes_the_previous_token_once() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        let user_id = UserId::new("user-session").expect("user ID");
        assert_eq!(
            repository
                .create_initial_user(
                    NewUser {
                        id: user_id.clone(),
                        username: "admin".to_owned(),
                        password_hash: "password-hash".to_owned(),
                        role: UserRole::SuperAdmin,
                        enabled: true,
                        created_at: 100,
                    },
                    test_session("initial-session", user_id.clone(), 10, 11),
                )
                .await
                .expect("create initial user"),
            InitialUserCreateOutcome::Created
        );
        repository
            .create_session(NewSession {
                id: SessionId::new("session-one").expect("session ID"),
                user_id,
                access_token_hash: [1; 32],
                refresh_token_hash: [2; 32],
                access_expires_at: 200,
                refresh_expires_at: 300,
                absolute_expires_at: 400,
                created_at: 100,
            })
            .await
            .expect("create session");

        assert_eq!(
            repository
                .rotate_session(&[2; 32], [3; 32], [4; 32], 250, 350, 150)
                .await
                .expect("rotate session"),
            RefreshSessionOutcome::Updated
        );
        assert_eq!(
            repository
                .rotate_session(&[2; 32], [5; 32], [6; 32], 260, 360, 160)
                .await
                .expect("reject reused refresh token"),
            RefreshSessionOutcome::Invalid
        );

        let session = repository
            .load_session_by_refresh_hash(&[4; 32])
            .await
            .expect("load rotated session")
            .expect("rotated session");
        assert_eq!(session.access_token_hash, [3; 32]);
        assert_eq!(session.refresh_expires_at, 350);
        assert_eq!(session.absolute_expires_at, 400);
    }

    fn test_session(id: &str, user_id: UserId, access_hash: u8, refresh_hash: u8) -> NewSession {
        NewSession {
            id: SessionId::new(id).expect("session ID"),
            user_id,
            access_token_hash: [access_hash; 32],
            refresh_token_hash: [refresh_hash; 32],
            access_expires_at: 200,
            refresh_expires_at: 300,
            absolute_expires_at: 400,
            created_at: 100,
        }
    }
}
