use std::{path::Path, str::FromStr, time::Duration};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use provider_auth::{
    ApiKeyId, AuthRepository, AuthRepositoryError, InitialUserCreateOutcome, NewApiKey,
    NewRegistrationCode, NewSession, NewUser, QuotaAdmissionOutcome, RegisterUserOutcome,
    SessionId, StoredApiKey, StoredApiKeyUpdate, StoredSession, StoredUser, UserId, UserRole,
    UserSummary, atoms_ge,
};
#[cfg(test)]
use provider_core::ProviderModelPricingTier;
use provider_core::{
    AccountAuthState, AccountId, AccountRepository, AccountRepositoryError, CredentialKind,
    CredentialUpdate, CredentialWriteOutcome, DiscoveredProviderModel, NewProviderAccount,
    ProviderAccountCreateOutcome, ProviderAccountSummary, ProviderAccountUpdate, ProviderKind,
    ProviderManagementRepository, ProviderModelOverride, ProviderModelPricing,
    ProviderModelPricingRecord, ProviderModelPricingSource, ProviderSnapshot,
    ProviderSnapshotWriteOutcome, ProviderVisibility, StoredCredential, StoredProviderAccount,
    StoredProviderModel,
};
use provider_usage::{component_prices_from_model_pricing, context_price_tiers_from_model_pricing};
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
    credential_cipher: CredentialCipher,
}

#[derive(Clone)]
struct CredentialCipher {
    cipher: XChaCha20Poly1305,
}

const CREDENTIAL_CIPHERTEXT_VERSION: &str = "v1";
const CREDENTIAL_NONCE_BYTES: usize = 24;

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
                a.group_label,
                a.priority,
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
            ORDER BY a.priority, a.created_at, a.id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| repository_error("failed to load provider accounts", error))?;

        rows.into_iter()
            .map(|row| stored_account(row, &self.credential_cipher))
            .collect()
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
        .bind(
            self.credential_cipher
                .encrypt(account_id, &update.credential_json)?,
        )
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
                a.group_label,
                a.priority,
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
            ORDER BY a.priority, a.created_at, a.id
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
                a.group_label,
                a.priority,
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

        row.map(|row| stored_account(row, &self.credential_cipher))
            .transpose()
    }

    async fn commit_provider_snapshot(
        &self,
        snapshot: ProviderSnapshot,
        create: bool,
        expected_credential_revision: Option<u64>,
    ) -> Result<ProviderSnapshotWriteOutcome, AccountRepositoryError> {
        let account = snapshot.account;
        let credential_ciphertext = self
            .credential_cipher
            .encrypt(&account.id, &account.credential.credential_json)?;
        let revision = database_integer(account.credential.revision, "credential revision")?;
        let format_version = i64::from(account.credential.format_version);
        let mut transaction = self.pool.begin().await.map_err(|error| {
            repository_error("failed to start provider snapshot transaction", error)
        })?;

        if create {
            let inserted = sqlx::query(
                r#"
                INSERT INTO provider_accounts
                    (id, owner_user_id, visibility, provider, label, group_label, config_json,
                     priority, enabled, auth_state, safe_error_code, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO NOTHING
                "#,
            )
            .bind(account.id.as_str())
            .bind(account.owner_user_id.as_deref())
            .bind(account.visibility.as_str())
            .bind(account.provider.as_str())
            .bind(&account.label)
            .bind(&account.group_label)
            .bind(&account.config_json)
            .bind(i64::from(account.priority))
            .bind(database_bool(account.enabled))
            .bind(account.auth_state.as_str())
            .bind(account.safe_error_code.as_deref())
            .bind(account.created_at)
            .bind(account.updated_at)
            .execute(&mut *transaction)
            .await
            .map_err(|error| repository_error("failed to create provider snapshot", error))?;
            if inserted.rows_affected() == 0 {
                transaction.rollback().await.map_err(|error| {
                    repository_error("failed to roll back provider snapshot conflict", error)
                })?;
                return Ok(ProviderSnapshotWriteOutcome::Conflict);
            }
            sqlx::query(
                r#"
                INSERT INTO provider_credentials
                    (account_id, credential_kind, revision, format_version, credential_json,
                     expires_at, last_refreshed_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(account.id.as_str())
            .bind(account.credential.kind.as_str())
            .bind(revision)
            .bind(format_version)
            .bind(&credential_ciphertext)
            .bind(account.credential.expires_at)
            .bind(account.credential.last_refreshed_at)
            .bind(account.credential.updated_at)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                repository_error("failed to create provider credential snapshot", error)
            })?;
        } else {
            let Some(expected_revision) = expected_credential_revision else {
                return Err(AccountRepositoryError::new(
                    "provider snapshot update requires an expected credential revision",
                ));
            };
            let write_auth_state = account.credential.revision > expected_revision;
            let expected_revision = database_integer(expected_revision, "credential revision")?;
            let updated = if write_auth_state {
                sqlx::query(
                    r#"
                    UPDATE provider_accounts
                    SET owner_user_id = ?, visibility = ?, label = ?, group_label = ?, priority = ?, config_json = ?,
                        enabled = ?, auth_state = ?, safe_error_code = ?, updated_at = ?
                    WHERE id = ?
                    "#,
                )
                .bind(account.owner_user_id.as_deref())
                .bind(account.visibility.as_str())
                .bind(&account.label)
                .bind(&account.group_label)
                .bind(i64::from(account.priority))
                .bind(&account.config_json)
                .bind(database_bool(account.enabled))
                .bind(account.auth_state.as_str())
                .bind(account.safe_error_code.as_deref())
                .bind(account.updated_at)
                .bind(account.id.as_str())
                .execute(&mut *transaction)
                .await
            } else {
                sqlx::query(
                    r#"
                    UPDATE provider_accounts
                    SET owner_user_id = ?, visibility = ?, label = ?, group_label = ?, priority = ?, config_json = ?,
                        enabled = ?, updated_at = ?
                    WHERE id = ?
                    "#,
                )
                .bind(account.owner_user_id.as_deref())
                .bind(account.visibility.as_str())
                .bind(&account.label)
                .bind(&account.group_label)
                .bind(i64::from(account.priority))
                .bind(&account.config_json)
                .bind(database_bool(account.enabled))
                .bind(account.updated_at)
                .bind(account.id.as_str())
                .execute(&mut *transaction)
                .await
            }
            .map_err(|error| repository_error("failed to update provider snapshot", error))?;
            if updated.rows_affected() == 0 {
                transaction.rollback().await.map_err(|error| {
                    repository_error("failed to roll back missing provider snapshot", error)
                })?;
                return Ok(ProviderSnapshotWriteOutcome::NotFound);
            }
            let credential = sqlx::query(
                r#"
                UPDATE provider_credentials
                SET revision = ?, credential_kind = ?, format_version = ?, credential_json = ?,
                    expires_at = ?, last_refreshed_at = ?, updated_at = ?
                WHERE account_id = ? AND revision = ?
                "#,
            )
            .bind(revision)
            .bind(account.credential.kind.as_str())
            .bind(format_version)
            .bind(&credential_ciphertext)
            .bind(account.credential.expires_at)
            .bind(account.credential.last_refreshed_at)
            .bind(account.credential.updated_at)
            .bind(account.id.as_str())
            .bind(expected_revision)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                repository_error("failed to update provider credential snapshot", error)
            })?;
            if credential.rows_affected() == 0 {
                transaction.rollback().await.map_err(|error| {
                    repository_error("failed to roll back provider snapshot conflict", error)
                })?;
                return Ok(ProviderSnapshotWriteOutcome::Conflict);
            }
        }

        if snapshot.write_models && snapshot.reset_models {
            sqlx::query("DELETE FROM provider_models WHERE account_id = ?")
                .bind(account.id.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(|error| {
                    repository_error("failed to reset provider model snapshot", error)
                })?;
        } else if snapshot.write_models {
            sqlx::query(
                "UPDATE provider_models SET available = 0, updated_at = ? WHERE account_id = ?",
            )
            .bind(account.updated_at)
            .bind(account.id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                repository_error("failed to invalidate provider model snapshot", error)
            })?;
        }
        for model in snapshot.models {
            let (pricing_source, pricing_json) = encode_model_pricing(model.pricing.as_ref())?;
            let input_modalities_json = encode_input_modalities(model.input_modalities.as_deref())?;
            sqlx::query(
                r#"
                INSERT INTO provider_models
                    (account_id, upstream_model, enabled, available, routable,
                     input_modalities_json, input_modalities_source, metadata_json,
                     pricing_source, pricing_json, last_seen_at, created_at, updated_at)
                VALUES (?, ?, 1, 1, ?, ?, 'discovery', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(account_id, upstream_model) DO UPDATE SET
                    available = 1,
                    routable = excluded.routable,
                    input_modalities_json = CASE
                        WHEN provider_models.input_modalities_source = 'manual'
                            THEN provider_models.input_modalities_json
                        ELSE excluded.input_modalities_json
                    END,
                    input_modalities_source = CASE
                        WHEN provider_models.input_modalities_source = 'manual'
                            THEN provider_models.input_modalities_source
                        ELSE excluded.input_modalities_source
                    END,
                    metadata_json = excluded.metadata_json,
                    pricing_source = CASE
                        WHEN provider_models.pricing_source = 'manual' THEN provider_models.pricing_source
                        ELSE excluded.pricing_source
                    END,
                    pricing_json = CASE
                        WHEN provider_models.pricing_source = 'manual' THEN provider_models.pricing_json
                        ELSE excluded.pricing_json
                    END,
                    last_seen_at = excluded.last_seen_at,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(account.id.as_str())
            .bind(model.upstream_model)
            .bind(database_bool(model.routable))
            .bind(input_modalities_json)
            .bind(model.metadata_json)
            .bind(pricing_source)
            .bind(pricing_json)
            .bind(account.updated_at)
            .bind(account.updated_at)
            .bind(account.updated_at)
            .execute(&mut *transaction)
            .await
            .map_err(|error| repository_error("failed to write provider model snapshot", error))?;
        }
        let rows = sqlx::query(
            r#"
            SELECT account_id, upstream_model, alias, enabled, available, routable,
                   input_modalities_json, metadata_json,
                   pricing_source, pricing_json, last_seen_at, created_at, updated_at
            FROM provider_models
            WHERE account_id = ?
            ORDER BY upstream_model
            "#,
        )
        .bind(account.id.as_str())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| repository_error("failed to read committed provider models", error))?;
        let models = rows
            .into_iter()
            .map(stored_model)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await.map_err(|error| {
            repository_error("failed to commit provider snapshot transaction", error)
        })?;
        Ok(ProviderSnapshotWriteOutcome::Committed { models })
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
                (id, owner_user_id, visibility, provider, label, group_label, priority, config_json, enabled, auth_state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            ON CONFLICT(id) DO NOTHING
            "#,
        )
        .bind(account.id.as_str())
        .bind(owner_user_id)
        .bind(visibility.as_str())
        .bind(account.provider.as_str())
        .bind(account.label)
        .bind(account.group_label)
        .bind(i64::from(account.priority))
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
        .bind(
            self.credential_cipher
                .encrypt(&account.id, &account.credential.credential_json)?,
        )
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
            SET label = ?, group_label = ?, priority = ?, config_json = ?, visibility = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(update.label)
        .bind(update.group_label)
        .bind(i64::from(update.priority))
        .bind(update.config_json)
        .bind(update.visibility.as_str())
        .bind(update.updated_at)
        .bind(account_id.as_str())
        .execute(&self.pool)
        .await
        .map_err(|error| repository_error("failed to update provider account", error))?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_provider_account_and_credential(
        &self,
        account_id: &AccountId,
        account: ProviderAccountUpdate,
        credential: CredentialUpdate,
    ) -> Result<Option<CredentialWriteOutcome>, AccountRepositoryError> {
        let expected_revision =
            database_integer(credential.expected_revision, "credential revision")?;
        let next_revision = credential
            .expected_revision
            .checked_add(1)
            .ok_or_else(|| AccountRepositoryError::new("credential revision overflow"))?;
        database_integer(next_revision, "credential revision")?;
        let format_version = i64::from(credential.format_version);

        let mut transaction = self.pool.begin().await.map_err(|error| {
            repository_error("failed to start provider update transaction", error)
        })?;
        let account_result = sqlx::query(
            r#"
            UPDATE provider_accounts
            SET label = ?, group_label = ?, priority = ?, config_json = ?, visibility = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(account.label)
        .bind(account.group_label)
        .bind(i64::from(account.priority))
        .bind(account.config_json)
        .bind(account.visibility.as_str())
        .bind(account.updated_at)
        .bind(account_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| repository_error("failed to update provider account", error))?;
        if account_result.rows_affected() == 0 {
            transaction.rollback().await.map_err(|error| {
                repository_error("failed to roll back missing provider update", error)
            })?;
            return Ok(None);
        }

        let credential_result = sqlx::query(
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
        .bind(credential.kind.as_str())
        .bind(format_version)
        .bind(
            self.credential_cipher
                .encrypt(account_id, &credential.credential_json)?,
        )
        .bind(credential.expires_at)
        .bind(credential.last_refreshed_at)
        .bind(credential.updated_at)
        .bind(account_id.as_str())
        .bind(expected_revision)
        .execute(&mut *transaction)
        .await
        .map_err(|error| repository_error("failed to update provider credential", error))?;
        if credential_result.rows_affected() == 0 {
            transaction.rollback().await.map_err(|error| {
                repository_error("failed to roll back credential conflict", error)
            })?;
            return Ok(Some(CredentialWriteOutcome::Conflict));
        }

        sqlx::query(
            r#"
            UPDATE provider_accounts
            SET auth_state = 'active', safe_error_code = NULL, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(credential.updated_at)
        .bind(account_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| repository_error("failed to update provider account state", error))?;

        transaction
            .commit()
            .await
            .map_err(|error| repository_error("failed to commit provider update", error))?;
        Ok(Some(CredentialWriteOutcome::Updated {
            revision: next_revision,
        }))
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
                SELECT account_id, upstream_model, alias, enabled, available, routable,
                       input_modalities_json, metadata_json,
                       pricing_source, pricing_json, last_seen_at, created_at, updated_at
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
                SELECT account_id, upstream_model, alias, enabled, available, routable,
                       input_modalities_json, metadata_json,
                       pricing_source, pricing_json, last_seen_at, created_at, updated_at
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
            let upstream_model = model.upstream_model.as_str();
            if upstream_model.is_empty() || upstream_model.trim() != upstream_model {
                return Err(AccountRepositoryError::new(
                    "discovered provider model must not be empty or contain surrounding whitespace",
                ));
            }
            let (pricing_source, pricing_json) = encode_model_pricing(model.pricing.as_ref())?;
            let input_modalities_json = encode_input_modalities(model.input_modalities.as_deref())?;
            sqlx::query(
                r#"
                INSERT INTO provider_models
                    (account_id, upstream_model, enabled, available, routable,
                     input_modalities_json, input_modalities_source, metadata_json,
                     pricing_source, pricing_json, last_seen_at, updated_at)
                VALUES (?, ?, 1, 1, ?, ?, 'discovery', ?, ?, ?, ?, ?)
                ON CONFLICT(account_id, upstream_model) DO UPDATE SET
                    available = 1,
                    routable = excluded.routable,
                    input_modalities_json = CASE
                        WHEN provider_models.input_modalities_source = 'manual'
                            THEN provider_models.input_modalities_json
                        ELSE excluded.input_modalities_json
                    END,
                    input_modalities_source = CASE
                        WHEN provider_models.input_modalities_source = 'manual'
                            THEN provider_models.input_modalities_source
                        ELSE excluded.input_modalities_source
                    END,
                    metadata_json = excluded.metadata_json,
                    pricing_source = CASE
                        WHEN provider_models.pricing_source = 'manual' THEN provider_models.pricing_source
                        ELSE excluded.pricing_source
                    END,
                    pricing_json = CASE
                        WHEN provider_models.pricing_source = 'manual' THEN provider_models.pricing_json
                        ELSE excluded.pricing_json
                    END,
                    last_seen_at = excluded.last_seen_at,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(account_id.as_str())
            .bind(upstream_model)
            .bind(database_bool(model.routable))
            .bind(input_modalities_json)
            .bind(model.metadata_json)
            .bind(pricing_source)
            .bind(pricing_json)
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
        let (update_pricing, pricing_json) = match update.pricing {
            None => (false, None),
            Some(None) => (true, None),
            Some(Some(pricing)) => (
                true,
                Some(serde_json::to_string(&pricing).map_err(|error| {
                    repository_error("failed to encode provider model pricing", error)
                })?),
            ),
        };
        let input_modalities_json = encode_input_modalities(update.input_modalities.as_deref())?;
        let result = sqlx::query(
            r#"
            UPDATE provider_models
            SET alias = ?,
                enabled = ?,
                input_modalities_source = CASE
                    WHEN input_modalities_json IS NOT ? THEN 'manual'
                    ELSE input_modalities_source
                END,
                input_modalities_json = ?,
                pricing_source = CASE
                    WHEN ? = 0 THEN pricing_source
                    WHEN ? IS NULL THEN NULL
                    ELSE 'manual'
                END,
                pricing_json = CASE WHEN ? = 0 THEN pricing_json ELSE ? END,
                updated_at = ?
            WHERE account_id = ? AND upstream_model = ?
            "#,
        )
        .bind(update.alias)
        .bind(database_bool(update.enabled))
        .bind(input_modalities_json.as_deref())
        .bind(input_modalities_json)
        .bind(database_bool(update_pricing))
        .bind(pricing_json.as_deref())
        .bind(database_bool(update_pricing))
        .bind(pricing_json)
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
                (id, user_id, token_hash, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(session.id.as_str())
        .bind(session.user_id.as_str())
        .bind(session.token_hash.as_slice())
        .bind(session.expires_at)
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

    async fn create_registration_code(
        &self,
        code: NewRegistrationCode,
    ) -> Result<(), AuthRepositoryError> {
        sqlx::query(
            r#"
            INSERT INTO registration_codes
                (code_hash, expires_at)
            VALUES (?, ?)
            "#,
        )
        .bind(code.code_hash.as_slice())
        .bind(code.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to create registration code", error))?;
        Ok(())
    }

    async fn registration_code_valid(
        &self,
        code_hash: &[u8; 32],
        now: i64,
    ) -> Result<bool, AuthRepositoryError> {
        let exists = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM registration_codes
                WHERE code_hash = ? AND expires_at > ?
            )
            "#,
        )
        .bind(code_hash.as_slice())
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to validate registration code", error))?;
        Ok(exists != 0)
    }

    async fn register_user(
        &self,
        code_hash: &[u8; 32],
        user: NewUser,
        session: NewSession,
        now: i64,
    ) -> Result<RegisterUserOutcome, AuthRepositoryError> {
        if session.user_id != user.id {
            return Err(AuthRepositoryError::new(
                "registration session must belong to the registered user",
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(|error| {
            auth_repository_error("failed to start user registration transaction", error)
        })?;
        let consumed =
            sqlx::query("DELETE FROM registration_codes WHERE code_hash = ? AND expires_at > ?")
                .bind(code_hash.as_slice())
                .bind(now)
                .execute(&mut *transaction)
                .await
                .map_err(|error| {
                    auth_repository_error("failed to consume registration code", error)
                })?;
        if consumed.rows_affected() == 0 {
            transaction.rollback().await.map_err(|error| {
                auth_repository_error("failed to roll back invalid registration code", error)
            })?;
            return Ok(RegisterUserOutcome::InvalidCode);
        }
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
        .map_err(|error| auth_repository_error("failed to register user", error))?;
        if inserted.rows_affected() == 0 {
            transaction.rollback().await.map_err(|error| {
                auth_repository_error("failed to roll back registration conflict", error)
            })?;
            return Ok(RegisterUserOutcome::Conflict);
        }
        sqlx::query(
            r#"
            INSERT INTO user_sessions
                (id, user_id, token_hash, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(session.id.as_str())
        .bind(session.user_id.as_str())
        .bind(session.token_hash.as_slice())
        .bind(session.expires_at)
        .bind(session.created_at)
        .bind(session.created_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| auth_repository_error("failed to create registration session", error))?;
        transaction
            .commit()
            .await
            .map_err(|error| auth_repository_error("failed to commit user registration", error))?;
        Ok(RegisterUserOutcome::Created)
    }

    async fn set_user_enabled(
        &self,
        user_id: &UserId,
        enabled: bool,
        updated_at: i64,
    ) -> Result<bool, AuthRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(|error| {
            auth_repository_error("failed to start user status transaction", error)
        })?;
        let result = sqlx::query("UPDATE users SET enabled = ?, updated_at = ? WHERE id = ?")
            .bind(database_bool(enabled))
            .bind(updated_at)
            .bind(user_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|error| auth_repository_error("failed to update user status", error))?;
        if result.rows_affected() > 0 && !enabled {
            sqlx::query(
                "UPDATE user_sessions SET revoked_at = ?, updated_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            )
            .bind(updated_at)
            .bind(updated_at)
            .bind(user_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|error| auth_repository_error("failed to revoke disabled user sessions", error))?;
            sqlx::query(
                "UPDATE api_keys SET enabled = 0, updated_at = ? WHERE owner_user_id = ? AND enabled = 1",
            )
            .bind(updated_at)
            .bind(user_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|error| auth_repository_error("failed to disable user API keys", error))?;
        }
        transaction.commit().await.map_err(|error| {
            auth_repository_error("failed to commit user status transaction", error)
        })?;
        Ok(result.rows_affected() > 0)
    }

    async fn reset_user_password(
        &self,
        user_id: &UserId,
        password_hash: String,
        updated_at: i64,
    ) -> Result<bool, AuthRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(|error| {
            auth_repository_error("failed to start password reset transaction", error)
        })?;
        let result = sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(password_hash)
            .bind(updated_at)
            .bind(user_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|error| auth_repository_error("failed to update user password", error))?;
        if result.rows_affected() > 0 {
            sqlx::query(
                "UPDATE user_sessions SET revoked_at = ?, updated_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            )
            .bind(updated_at)
            .bind(updated_at)
            .bind(user_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|error| auth_repository_error("failed to revoke password-reset sessions", error))?;
        }
        transaction.commit().await.map_err(|error| {
            auth_repository_error("failed to commit password reset transaction", error)
        })?;
        Ok(result.rows_affected() > 0)
    }

    async fn create_session(&self, session: NewSession) -> Result<(), AuthRepositoryError> {
        sqlx::query(
            r#"
            INSERT INTO user_sessions
                (id, user_id, token_hash, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(session.id.as_str())
        .bind(session.user_id.as_str())
        .bind(session.token_hash.as_slice())
        .bind(session.expires_at)
        .bind(session.created_at)
        .bind(session.created_at)
        .execute(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to create user session", error))?;
        Ok(())
    }

    async fn load_session_by_token_hash(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<StoredSession>, AuthRepositoryError> {
        load_session(&self.pool, SESSION_BY_TOKEN_SQL, token_hash).await
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

    async fn create_api_key(&self, key: NewApiKey) -> Result<bool, AuthRepositoryError> {
        let result = sqlx::query(
            r#"
            INSERT INTO api_keys
                (id, owner_user_id, group_label, label, key, enabled, expires_at,
                 quota_limit_atoms, spent_atoms, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, '0', ?, ?)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(key.id.as_str())
        .bind(key.owner_user_id.as_str())
        .bind(&key.group_label)
        .bind(key.label)
        .bind(key.key.expose_secret())
        .bind(database_bool(key.enabled))
        .bind(key.expires_at)
        .bind(key.quota_limit_atoms.as_deref())
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
            SELECT id, owner_user_id, group_label, label, key, enabled, expires_at,
                   quota_limit_atoms, spent_atoms, last_used_at, created_at, updated_at
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
            SELECT id, owner_user_id, group_label, label, key, enabled, expires_at,
                   quota_limit_atoms, spent_atoms, last_used_at, created_at, updated_at
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
        update: StoredApiKeyUpdate,
    ) -> Result<Option<StoredApiKey>, AuthRepositoryError> {
        let StoredApiKeyUpdate {
            group_label,
            label,
            enabled,
            expires_at,
            quota_limit_atoms,
            updated_at,
        } = update;
        let row = if let Some(limit) = quota_limit_atoms {
            sqlx::query(
                r#"
                UPDATE api_keys
                SET group_label = ?, label = ?, enabled = ?, expires_at = ?,
                    quota_limit_atoms = ?, updated_at = ?
                WHERE id = ? AND owner_user_id = ?
                RETURNING id, owner_user_id, group_label, label, key, enabled, expires_at,
                          quota_limit_atoms, spent_atoms, last_used_at, created_at, updated_at
                "#,
            )
            .bind(&group_label)
            .bind(&label)
            .bind(database_bool(enabled))
            .bind(expires_at)
            .bind(limit.as_deref())
            .bind(updated_at)
            .bind(key_id.as_str())
            .bind(owner_user_id.as_str())
            .fetch_optional(&self.pool)
            .await
        } else {
            sqlx::query(
                r#"
                UPDATE api_keys
                SET group_label = ?, label = ?, enabled = ?, expires_at = ?, updated_at = ?
                WHERE id = ? AND owner_user_id = ?
                RETURNING id, owner_user_id, group_label, label, key, enabled, expires_at,
                          quota_limit_atoms, spent_atoms, last_used_at, created_at, updated_at
                "#,
            )
            .bind(&group_label)
            .bind(&label)
            .bind(database_bool(enabled))
            .bind(expires_at)
            .bind(updated_at)
            .bind(key_id.as_str())
            .bind(owner_user_id.as_str())
            .fetch_optional(&self.pool)
            .await
        }
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
            SELECT k.id, k.owner_user_id, k.group_label, k.label, k.key, k.enabled, k.expires_at,
                   k.quota_limit_atoms, k.spent_atoms, k.last_used_at, k.created_at, k.updated_at
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

    async fn list_visible_account_ids_by_group_label(
        &self,
        actor_user_id: &UserId,
        group_label: &str,
    ) -> Result<Vec<String>, AuthRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id
            FROM provider_accounts
            WHERE group_label = ?
              AND enabled = 1
              AND owner_user_id IS NOT NULL
              AND (owner_user_id = ? OR visibility = 'shared')
            ORDER BY created_at, id
            "#,
        )
        .bind(group_label)
        .bind(actor_user_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to list accounts by group label", error))?;
        let mut account_ids = Vec::with_capacity(rows.len());
        for row in rows {
            account_ids.push(
                row_value::<String>(&row, "id")
                    .map_err(|error| AuthRepositoryError::new(error.to_string()))?,
            );
        }
        Ok(account_ids)
    }

    async fn admit_api_key_quota(
        &self,
        api_key_id: &ApiKeyId,
    ) -> Result<QuotaAdmissionOutcome, AuthRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT quota_limit_atoms, spent_atoms
            FROM api_keys
            WHERE id = ?
            "#,
        )
        .bind(api_key_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| auth_repository_error("failed to load API key quota", error))?
        .ok_or_else(|| AuthRepositoryError::new("API key quota is unavailable"))?;
        let limit = auth_row_value::<Option<String>>(&row, "quota_limit_atoms")?;
        let Some(limit) = limit else {
            return Ok(QuotaAdmissionOutcome::Unlimited);
        };
        let spent = auth_row_value::<String>(&row, "spent_atoms")?;
        // Reject only after lifetime spent reaches the configured limit.
        if atoms_ge(&spent, &limit)
            .map_err(|_| AuthRepositoryError::new("invalid quota admission value"))?
        {
            return Ok(QuotaAdmissionOutcome::Exceeded);
        }
        Ok(QuotaAdmissionOutcome::Admitted)
    }

    async fn quota_ledger_ready(&self) -> Result<(), AuthRepositoryError> {
        let mut connection = self.pool.acquire().await.map_err(|error| {
            auth_repository_error("failed to acquire quota ledger connection", error)
        })?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(|error| auth_repository_error("failed to begin quota ledger probe", error))?;
        let probe = sqlx::query_scalar::<_, i64>("SELECT 1 FROM api_key_quota_ledger LIMIT 1")
            .fetch_optional(&mut *connection)
            .await;
        let rollback = sqlx::query("ROLLBACK").execute(&mut *connection).await;
        probe
            .map_err(|error| auth_repository_error("failed to probe quota ledger table", error))?;
        rollback.map_err(|error| {
            auth_repository_error("failed to roll back quota ledger probe", error)
        })?;
        Ok(())
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

const SESSION_BY_TOKEN_SQL: &str = r#"
    SELECT
        s.id,
        s.token_hash,
        s.expires_at,
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
    WHERE s.token_hash = ?
    "#;

impl CredentialCipher {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new((&key).into()),
        }
    }

    fn encrypt(
        &self,
        account_id: &AccountId,
        plaintext: &SecretString,
    ) -> Result<String, AccountRepositoryError> {
        let mut nonce = [0_u8; CREDENTIAL_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|error| {
            repository_error("failed to generate provider credential nonce", error)
        })?;
        let nonce_value = XNonce::from(nonce);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: plaintext.expose_secret().as_bytes(),
                    aad: account_id.as_str().as_bytes(),
                },
            )
            .map_err(|_| AccountRepositoryError::new("failed to encrypt provider credential"))?;
        let mut encoded = Vec::with_capacity(nonce.len() + ciphertext.len());
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        Ok(format!(
            "{CREDENTIAL_CIPHERTEXT_VERSION}:{}",
            STANDARD_NO_PAD.encode(encoded)
        ))
    }

    fn decrypt(
        &self,
        account_id: &AccountId,
        encoded: &str,
    ) -> Result<SecretString, AccountRepositoryError> {
        let payload = encoded.strip_prefix("v1:").ok_or_else(|| {
            AccountRepositoryError::new("unsupported provider credential ciphertext version")
        })?;
        let payload = STANDARD_NO_PAD.decode(payload).map_err(|_| {
            AccountRepositoryError::new("provider credential ciphertext is not valid base64")
        })?;
        if payload.len() <= CREDENTIAL_NONCE_BYTES {
            return Err(AccountRepositoryError::new(
                "provider credential ciphertext is truncated",
            ));
        }
        let (nonce, ciphertext) = payload.split_at(CREDENTIAL_NONCE_BYTES);
        let nonce: [u8; CREDENTIAL_NONCE_BYTES] = nonce
            .try_into()
            .map_err(|_| AccountRepositoryError::new("provider credential nonce is invalid"))?;
        let nonce = XNonce::from(nonce);
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: account_id.as_str().as_bytes(),
                },
            )
            .map_err(|_| AccountRepositoryError::new("failed to decrypt provider credential"))?;
        String::from_utf8(plaintext)
            .map(SecretString::from)
            .map_err(|_| AccountRepositoryError::new("provider credential plaintext is not UTF-8"))
    }
}

fn stored_account(
    row: SqliteRow,
    credential_cipher: &CredentialCipher,
) -> Result<StoredProviderAccount, AccountRepositoryError> {
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
    let credential_json = credential_cipher.decrypt(&id, &credential_json)?;
    let credential_updated_at = required_joined_value::<i64>(&row, "credential_updated_at", &id)?;

    Ok(StoredProviderAccount {
        id,
        owner_user_id: row_value(&row, "owner_user_id")?,
        visibility: provider_visibility(&row)?,
        provider,
        label: row_value(&row, "label")?,
        group_label: row_value(&row, "group_label")?,
        priority: non_negative_u32(row_value(&row, "priority")?, "provider account priority")?,
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
            credential_json,
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
        group_label: row_value(&row, "group_label")?,
        priority: non_negative_u32(row_value(&row, "priority")?, "provider account priority")?,
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
    let pricing = decode_model_pricing(
        row_value(&row, "pricing_source")?,
        row_value(&row, "pricing_json")?,
    )?;
    Ok(StoredProviderModel {
        account_id,
        upstream_model: row_value(&row, "upstream_model")?,
        alias: row_value(&row, "alias")?,
        enabled: row_value::<i64>(&row, "enabled")? != 0,
        available: row_value::<i64>(&row, "available")? != 0,
        routable: row_value::<i64>(&row, "routable")? != 0,
        input_modalities: decode_input_modalities(row_value(&row, "input_modalities_json")?)?,
        metadata_json: row_value(&row, "metadata_json")?,
        pricing,
        last_seen_at: row_value(&row, "last_seen_at")?,
        created_at: row_value(&row, "created_at")?,
        updated_at: row_value(&row, "updated_at")?,
    })
}

fn encode_input_modalities(
    input_modalities: Option<&[provider_core::ProviderModelInputModality]>,
) -> Result<Option<String>, AccountRepositoryError> {
    provider_core::validate_input_modalities(input_modalities)
        .map_err(AccountRepositoryError::new)?;
    input_modalities
        .map(|modalities| {
            serde_json::to_string(modalities).map_err(|error| {
                repository_error("failed to encode provider model input modalities", error)
            })
        })
        .transpose()
}

fn decode_input_modalities(
    json: Option<String>,
) -> Result<Option<Vec<provider_core::ProviderModelInputModality>>, AccountRepositoryError> {
    let Some(json) = json else {
        return Ok(None);
    };
    let modalities = serde_json::from_str::<Vec<provider_core::ProviderModelInputModality>>(&json)
        .map_err(|error| {
            repository_error("failed to decode provider model input modalities", error)
        })?;
    provider_core::validate_input_modalities(Some(&modalities))
        .map_err(AccountRepositoryError::new)?;
    Ok(Some(modalities))
}

fn encode_model_pricing(
    record: Option<&ProviderModelPricingRecord>,
) -> Result<(Option<&'static str>, Option<String>), AccountRepositoryError> {
    let Some(record) = record else {
        return Ok((None, None));
    };
    let json = serde_json::to_string(&record.pricing)
        .map_err(|error| repository_error("failed to encode provider model pricing", error))?;
    Ok((Some(record.source.as_str()), Some(json)))
}

fn decode_model_pricing(
    source: Option<String>,
    json: Option<String>,
) -> Result<Option<ProviderModelPricingRecord>, AccountRepositoryError> {
    match (source.as_deref(), json) {
        (None, None) => Ok(None),
        (Some(source), Some(json)) => {
            let source = match source {
                "catalog" => ProviderModelPricingSource::Catalog,
                "manual" => ProviderModelPricingSource::Manual,
                _ => {
                    return Err(AccountRepositoryError::new(
                        "unknown provider model pricing source",
                    ));
                }
            };
            let pricing = serde_json::from_str::<ProviderModelPricing>(&json).map_err(|error| {
                repository_error("failed to decode provider model pricing", error)
            })?;
            if component_prices_from_model_pricing(&pricing).is_none()
                || context_price_tiers_from_model_pricing(&pricing).is_none()
            {
                return Err(AccountRepositoryError::new(
                    "stored provider model pricing is invalid",
                ));
            }
            Ok(Some(ProviderModelPricingRecord { source, pricing }))
        }
        _ => Err(AccountRepositoryError::new(
            "provider model pricing source and json must be set together",
        )),
    }
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
        token_hash: auth_hash(&row, "token_hash")?,
        expires_at: auth_row_value(&row, "expires_at")?,
        revoked_at: auth_row_value(&row, "revoked_at")?,
        created_at: auth_row_value(&row, "created_at")?,
        updated_at: auth_row_value(&row, "updated_at")?,
    })
}

fn stored_api_key(row: SqliteRow) -> Result<StoredApiKey, AuthRepositoryError> {
    let group_label = auth_row_value::<String>(&row, "group_label")?;
    let quota_limit_atoms = auth_row_value::<Option<String>>(&row, "quota_limit_atoms")?;
    let spent_atoms = auth_row_value::<String>(&row, "spent_atoms")?;
    if quota_limit_atoms
        .as_deref()
        .is_some_and(|value| provider_auth::format_usd_atoms(value).is_err())
        || provider_auth::format_usd_atoms(&spent_atoms).is_err()
    {
        return Err(AuthRepositoryError::new(
            "invalid API key quota ledger value",
        ));
    }
    Ok(StoredApiKey {
        id: auth_api_key_id(&row, "id")?,
        owner_user_id: auth_user_id(&row, "owner_user_id")?,
        group_label,
        label: auth_row_value(&row, "label")?,
        key: SecretString::from(auth_row_value::<String>(&row, "key")?),
        enabled: auth_row_value::<i64>(&row, "enabled")? != 0,
        expires_at: auth_row_value(&row, "expires_at")?,
        quota_limit_atoms,
        spent_atoms,
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

fn non_negative_u32(value: i64, field: &str) -> Result<u32, AccountRepositoryError> {
    value
        .try_into()
        .map_err(|_| AccountRepositoryError::new(format!("invalid {field}")))
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
    async fn snapshot_update_preserves_auth_state_until_credential_revision_advances() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        let account_id = AccountId::new("snapshot-auth-state").expect("account ID");
        let mut account = StoredProviderAccount {
            id: account_id.clone(),
            owner_user_id: None,
            visibility: ProviderVisibility::Private,
            provider: ProviderKind::OpenAiCompatible,
            label: "Original".to_owned(),
            group_label: "default".to_owned(),
            priority: 0,
            config_json: r#"{"base_url":"https://example.com"}"#.to_owned(),
            enabled: true,
            auth_state: AccountAuthState::Active,
            safe_error_code: None,
            created_at: 1,
            updated_at: 1,
            credential: StoredCredential {
                kind: CredentialKind::ApiKey,
                revision: 0,
                format_version: 1,
                credential_json: SecretString::from("secret"),
                expires_at: None,
                last_refreshed_at: None,
                updated_at: 1,
            },
        };
        repository
            .commit_provider_snapshot(
                ProviderSnapshot {
                    account: account.clone(),
                    models: Vec::new(),
                    write_models: false,
                    reset_models: false,
                },
                true,
                None,
            )
            .await
            .expect("create snapshot");
        repository
            .update_auth_state(
                &account_id,
                AccountAuthState::ReauthRequired,
                Some("credential_expired"),
                2,
            )
            .await
            .expect("mark reauth required");

        account.label = "Refreshed models".to_owned();
        account.updated_at = 3;
        repository
            .commit_provider_snapshot(
                ProviderSnapshot {
                    account: account.clone(),
                    models: Vec::new(),
                    write_models: true,
                    reset_models: false,
                },
                false,
                Some(0),
            )
            .await
            .expect("refresh snapshot");
        let preserved = repository
            .load_provider_account(&account_id)
            .await
            .expect("load preserved account")
            .expect("preserved account");
        assert_eq!(preserved.auth_state, AccountAuthState::ReauthRequired);
        assert_eq!(
            preserved.safe_error_code.as_deref(),
            Some("credential_expired")
        );

        account.credential.revision = 1;
        account.auth_state = AccountAuthState::Active;
        account.safe_error_code = None;
        account.updated_at = 4;
        repository
            .commit_provider_snapshot(
                ProviderSnapshot {
                    account,
                    models: Vec::new(),
                    write_models: false,
                    reset_models: false,
                },
                false,
                Some(0),
            )
            .await
            .expect("replace credential snapshot");
        let restored = repository
            .load_provider_account(&account_id)
            .await
            .expect("load restored account")
            .expect("restored account");
        assert_eq!(restored.auth_state, AccountAuthState::Active);
        assert_eq!(restored.safe_error_code, None);
        assert_eq!(restored.credential.revision, 1);
    }

    #[tokio::test]
    async fn quota_ledger_readiness_probe_is_non_mutating() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        let before = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_key_quota_ledger")
            .fetch_one(&repository.pool)
            .await
            .expect("count ledger before probe");

        repository
            .quota_ledger_ready()
            .await
            .expect("quota ledger readiness");

        let after = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_key_quota_ledger")
            .fetch_one(&repository.pool)
            .await
            .expect("count ledger after probe");
        assert_eq!(after, before);
    }

    #[tokio::test]
    async fn password_reset_rolls_back_when_session_revocation_fails() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        let user = NewUser {
            id: UserId::new("atomic-reset-user").expect("user ID"),
            username: "atomic-reset".to_owned(),
            password_hash: "old-hash".to_owned(),
            role: UserRole::SuperAdmin,
            enabled: true,
            created_at: 100,
        };
        repository
            .create_initial_user(
                user.clone(),
                test_session("atomic-reset-session", user.id.clone(), 30),
            )
            .await
            .expect("create initial user");
        sqlx::query(
            r#"
            CREATE TRIGGER reject_session_revoke
            BEFORE UPDATE OF revoked_at ON user_sessions
            BEGIN
                SELECT RAISE(ABORT, 'session revoke failed');
            END
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("install failure trigger");

        assert!(
            repository
                .reset_user_password(&user.id, "new-hash".to_owned(), 150)
                .await
                .is_err()
        );
        assert_eq!(
            repository
                .load_user(&user.id)
                .await
                .expect("load user")
                .expect("stored user")
                .password_hash,
            "old-hash"
        );
    }

    #[tokio::test]
    async fn provider_model_modality_check_accepts_only_unique_supported_strings() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        sqlx::query(
            r#"
            INSERT INTO provider_accounts (id, provider, label, group_label)
            VALUES ('modality-check', 'openai_compatible', 'Modality Check', 'default')
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("insert provider account");

        for (model, modalities) in [
            ("all", r#"["video","text","audio","image","pdf"]"#),
            ("subset", r#"["audio"]"#),
        ] {
            sqlx::query(
                r#"
                INSERT INTO provider_models
                    (account_id, upstream_model, input_modalities_json)
                VALUES ('modality-check', ?, ?)
                "#,
            )
            .bind(model)
            .bind(modalities)
            .execute(&repository.pool)
            .await
            .expect("valid modality array");
        }

        for (model, modalities) in [
            ("unknown", r#"["future"]"#),
            ("duplicate", r#"["text","text"]"#),
            ("non-string", "[1]"),
            ("empty", "[]"),
        ] {
            assert!(
                sqlx::query(
                    r#"
                    INSERT INTO provider_models
                        (account_id, upstream_model, input_modalities_json)
                    VALUES ('modality-check', ?, ?)
                    "#,
                )
                .bind(model)
                .bind(modalities)
                .execute(&repository.pool)
                .await
                .is_err(),
                "invalid modalities {modalities} must be rejected by SQLite"
            );
        }
    }

    #[test]
    fn stored_model_pricing_rejects_invalid_price_semantics() {
        let decode =
            |json: &str| decode_model_pricing(Some("catalog".to_owned()), Some(json.to_owned()));

        assert!(decode(
            r#"{"input":"1","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[]}"#
        )
        .is_ok());
        assert!(decode(
            r#"{"input":"1e3","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[]}"#
        )
        .is_err());
        assert!(decode(
            r#"{"input":null,"output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[]}"#
        )
        .is_err());
        assert!(decode(
            r#"{"input":"1","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[{"threshold_tokens":200000,"input":null,"output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null}]}"#
        )
        .is_err());
        assert!(decode(
            r#"{"input":"1","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[{"threshold_tokens":200000,"input":"2","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null},{"threshold_tokens":200000,"input":"3","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null}]}"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn migrates_and_compare_and_swaps_credentials() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        sqlx::query(
            r#"
            INSERT INTO provider_accounts
                (id, provider, label, group_label, enabled, auth_state)
            VALUES ('grok-main', 'grok', 'Main', 'legacy', 1, 'active')
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("insert account");
        let account_id = AccountId::new("grok-main").expect("account ID");
        let encrypted = repository
            .credential_cipher
            .encrypt(
                &account_id,
                &SecretString::from(r#"{"access_token":"old"}"#.to_owned()),
            )
            .expect("encrypt credential");
        sqlx::query(
            r#"
            INSERT INTO provider_credentials
                (account_id, credential_kind, revision, format_version, credential_json, expires_at)
            VALUES ('grok-main', 'oauth', 0, 1, ?, 100)
            "#,
        )
        .bind(encrypted)
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
            .create_initial_user(owner.clone(), test_session("codex-session", owner.id, 7))
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
            group_label: "default".to_owned(),
            priority: 0,
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
                test_session("model-owner-session", owner_user_id, 20),
            )
            .await
            .expect("create model owner");
        let account_id = AccountId::new("grok-models").expect("account ID");
        let account = NewProviderAccount {
            id: account_id.clone(),
            provider: ProviderKind::Grok,
            label: "Grok Models".to_owned(),
            group_label: "default".to_owned(),
            priority: 0,
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
                        input_modalities: None,
                        metadata_json: r#"{"version":1}"#.to_owned(),
                        routable: true,
                        pricing: Some(ProviderModelPricingRecord {
                            source: ProviderModelPricingSource::Catalog,
                            pricing: ProviderModelPricing {
                                input: Some("1".to_owned()),
                                output: Some("2".to_owned()),
                                cache_read: None,
                                cache_write: None,
                                reasoning: None,
                                input_audio: None,
                                output_audio: None,
                                tiers: vec![ProviderModelPricingTier {
                                    threshold_tokens: 200_000,
                                    input: Some("2".to_owned()),
                                    output: Some("4".to_owned()),
                                    cache_read: None,
                                    cache_write: None,
                                    reasoning: None,
                                    input_audio: None,
                                    output_audio: None,
                                }],
                            },
                        }),
                    },
                    DiscoveredProviderModel {
                        upstream_model: "grok-b".to_owned(),
                        input_modalities: Some(vec![
                            provider_core::ProviderModelInputModality::Video,
                            provider_core::ProviderModelInputModality::Image,
                        ]),
                        metadata_json: "{}".to_owned(),
                        routable: true,
                        pricing: None,
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
                        input_modalities: Some(vec![
                            provider_core::ProviderModelInputModality::Text,
                        ]),
                        pricing: None,
                        updated_at: 11,
                    },
                )
                .await
                .expect("model override without pricing")
        );
        assert!(
            repository
                .update_provider_model(
                    &account_id,
                    "grok-b",
                    ProviderModelOverride {
                        alias: Some("grok-b-latest".to_owned()),
                        enabled: true,
                        input_modalities: Some(vec![
                            provider_core::ProviderModelInputModality::Video,
                            provider_core::ProviderModelInputModality::Image,
                        ]),
                        pricing: None,
                        updated_at: 11,
                    },
                )
                .await
                .expect("alias-only model override")
        );
        let catalog_model = repository
            .list_provider_models(Some(&account_id))
            .await
            .expect("catalog model after override")
            .into_iter()
            .find(|model| model.upstream_model == "grok-a")
            .expect("grok-a after override");
        assert_eq!(
            catalog_model
                .pricing
                .expect("catalog pricing remains")
                .pricing
                .tiers
                .len(),
            1,
            "an alias/status-only edit must preserve catalog tiers"
        );

        let repriced_models = repository
            .synchronize_provider_models(
                &account_id,
                vec![
                    DiscoveredProviderModel {
                        upstream_model: "grok-a".to_owned(),
                        input_modalities: None,
                        metadata_json: r#"{"version":1}"#.to_owned(),
                        routable: true,
                        pricing: Some(ProviderModelPricingRecord {
                            source: ProviderModelPricingSource::Catalog,
                            pricing: ProviderModelPricing {
                                input: Some("5".to_owned()),
                                output: Some("6".to_owned()),
                                cache_read: None,
                                cache_write: None,
                                reasoning: None,
                                input_audio: None,
                                output_audio: None,
                                tiers: vec![ProviderModelPricingTier {
                                    threshold_tokens: 200_000,
                                    input: Some("7".to_owned()),
                                    output: Some("8".to_owned()),
                                    cache_read: None,
                                    cache_write: None,
                                    reasoning: None,
                                    input_audio: None,
                                    output_audio: None,
                                }],
                            },
                        }),
                    },
                    DiscoveredProviderModel {
                        upstream_model: "grok-b".to_owned(),
                        input_modalities: Some(vec![
                            provider_core::ProviderModelInputModality::Audio,
                            provider_core::ProviderModelInputModality::Pdf,
                        ]),
                        metadata_json: "{}".to_owned(),
                        routable: true,
                        pricing: None,
                    },
                ],
                12,
            )
            .await
            .expect("catalog repricing sync");
        let repriced = repriced_models
            .iter()
            .find(|model| model.upstream_model == "grok-a")
            .expect("repriced grok-a")
            .pricing
            .as_ref()
            .expect("repriced catalog value");
        assert_eq!(repriced.source, ProviderModelPricingSource::Catalog);
        assert_eq!(repriced.pricing.input.as_deref(), Some("5"));
        assert_eq!(repriced.pricing.tiers[0].output.as_deref(), Some("8"));
        assert_eq!(
            repriced_models
                .iter()
                .find(|model| model.upstream_model == "grok-b")
                .expect("refreshed grok-b")
                .input_modalities,
            Some(vec![
                provider_core::ProviderModelInputModality::Audio,
                provider_core::ProviderModelInputModality::Pdf,
            ]),
            "editing only the alias must not freeze discovered input modalities"
        );

        assert!(
            repository
                .update_provider_model(
                    &account_id,
                    "grok-a",
                    ProviderModelOverride {
                        alias: Some("grok-latest".to_owned()),
                        enabled: false,
                        input_modalities: Some(vec![
                            provider_core::ProviderModelInputModality::Text,
                        ]),
                        pricing: Some(Some(ProviderModelPricing {
                            input: Some("3".to_owned()),
                            output: Some("4".to_owned()),
                            cache_read: None,
                            cache_write: None,
                            reasoning: None,
                            input_audio: None,
                            output_audio: None,
                            tiers: Vec::new(),
                        })),
                        updated_at: 12,
                    },
                )
                .await
                .expect("model override and manual pricing")
        );

        let models = repository
            .synchronize_provider_models(
                &account_id,
                vec![
                    DiscoveredProviderModel {
                        upstream_model: "grok-a".to_owned(),
                        input_modalities: Some(vec![
                            provider_core::ProviderModelInputModality::Text,
                            provider_core::ProviderModelInputModality::Image,
                        ]),
                        metadata_json: r#"{"version":2}"#.to_owned(),
                        routable: true,
                        pricing: Some(ProviderModelPricingRecord {
                            source: ProviderModelPricingSource::Catalog,
                            pricing: ProviderModelPricing {
                                input: Some("10".to_owned()),
                                output: Some("20".to_owned()),
                                cache_read: None,
                                cache_write: None,
                                reasoning: None,
                                input_audio: None,
                                output_audio: None,
                                tiers: Vec::new(),
                            },
                        }),
                    },
                    DiscoveredProviderModel {
                        upstream_model: "grok-c".to_owned(),
                        input_modalities: None,
                        metadata_json: "{}".to_owned(),
                        routable: true,
                        pricing: None,
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
        assert_eq!(
            model_a.input_modalities,
            Some(vec![provider_core::ProviderModelInputModality::Text]),
            "model synchronization must preserve manually configured input modalities"
        );
        assert_eq!(
            model_a.pricing,
            Some(ProviderModelPricingRecord {
                source: ProviderModelPricingSource::Manual,
                pricing: ProviderModelPricing {
                    input: Some("3".to_owned()),
                    output: Some("4".to_owned()),
                    cache_read: None,
                    cache_write: None,
                    reasoning: None,
                    input_audio: None,
                    output_audio: None,
                    tiers: Vec::new(),
                },
            }),
            "model synchronization must preserve manual pricing"
        );
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
        assert!(
            repository
                .update_provider_model(
                    &account_id,
                    "grok-a",
                    ProviderModelOverride {
                        alias: None,
                        enabled: true,
                        input_modalities: None,
                        pricing: Some(None),
                        updated_at: 21,
                    },
                )
                .await
                .expect("clear model pricing")
        );
        assert_eq!(
            repository
                .list_provider_models(Some(&account_id))
                .await
                .expect("models after clearing pricing")
                .into_iter()
                .find(|model| model.upstream_model == "grok-a")
                .expect("grok-a after clearing pricing")
                .pricing,
            None
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
                (id, provider, label, group_label, enabled, auth_state)
            VALUES ('existing-grok', 'grok', 'Existing Grok', 'legacy', 1, 'active')
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
                    test_session("initial-session", initial_user.id.clone(), 10),
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
                    test_session("second-session", second_user.id, 12),
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
                .load_session_by_token_hash(&[10; 32])
                .await
                .expect("load initial session")
                .is_some()
        );
    }

    #[tokio::test]
    async fn opaque_session_can_be_loaded_and_revoked() {
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
                    test_session("initial-session", user_id.clone(), 10),
                )
                .await
                .expect("create initial user"),
            InitialUserCreateOutcome::Created
        );
        repository
            .create_session(NewSession {
                id: SessionId::new("session-one").expect("session ID"),
                user_id,
                token_hash: [1; 32],
                expires_at: 300,
                created_at: 100,
            })
            .await
            .expect("create session");
        let session = repository
            .load_session_by_token_hash(&[1; 32])
            .await
            .expect("load session")
            .expect("session");
        assert_eq!(session.token_hash, [1; 32]);
        assert_eq!(session.expires_at, 300);
        assert!(
            repository
                .revoke_session(&session.id, 150)
                .await
                .expect("revoke")
        );
        assert_eq!(
            repository
                .load_session_by_token_hash(&[1; 32])
                .await
                .expect("load revoked session")
                .expect("revoked session")
                .revoked_at,
            Some(150)
        );
    }

    #[tokio::test]
    async fn disabling_user_atomically_revokes_sessions_and_permanently_disables_keys() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        let user_id = UserId::new("disabled-user").expect("user ID");
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
                test_session("disabled-user-session", user_id.clone(), 9),
            )
            .await
            .expect("create initial user");
        sqlx::query(
            r#"
            INSERT INTO api_keys
                (id, owner_user_id, group_label, label, key,
                 enabled, spent_atoms, created_at, updated_at)
            VALUES ('disabled-user-key', ?, 'group', 'key', 'pode-disabled-user-key',
                    1, '0', 100, 100)
            "#,
        )
        .bind(user_id.as_str())
        .execute(&repository.pool)
        .await
        .expect("create API key");

        assert!(
            repository
                .set_user_enabled(&user_id, false, 200)
                .await
                .expect("disable user")
        );
        let state = sqlx::query(
            r#"
            SELECT u.enabled, s.revoked_at, k.enabled AS key_enabled
            FROM users AS u
            INNER JOIN user_sessions AS s ON s.user_id = u.id
            INNER JOIN api_keys AS k ON k.owner_user_id = u.id
            WHERE u.id = ?
            "#,
        )
        .bind(user_id.as_str())
        .fetch_one(&repository.pool)
        .await
        .expect("load disabled state");
        assert_eq!(state.try_get::<i64, _>("enabled").expect("user enabled"), 0);
        assert_eq!(
            state.try_get::<i64, _>("revoked_at").expect("revoked at"),
            200
        );
        assert_eq!(
            state.try_get::<i64, _>("key_enabled").expect("key enabled"),
            0
        );

        assert!(
            repository
                .set_user_enabled(&user_id, true, 300)
                .await
                .expect("re-enable user")
        );
        let key_enabled = sqlx::query_scalar::<_, i64>(
            "SELECT enabled FROM api_keys WHERE id = 'disabled-user-key'",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("load API key state");
        assert_eq!(key_enabled, 0);
    }

    #[tokio::test]
    async fn quota_admission_allows_remaining_spend_and_rejects_exhausted_keys() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        let user_id = UserId::new("quota-user").expect("user ID");
        repository
            .create_initial_user(
                NewUser {
                    id: user_id.clone(),
                    username: "quota-admin".to_owned(),
                    password_hash: "password-hash".to_owned(),
                    role: UserRole::SuperAdmin,
                    enabled: true,
                    created_at: 1,
                },
                test_session("quota-session", user_id.clone(), 1),
            )
            .await
            .expect("create quota user");
        let key_id = ApiKeyId::new("quota-key").expect("API key ID");
        sqlx::query(
            r#"
            INSERT INTO api_keys (
                id, owner_user_id, group_label, label, key,
                enabled, quota_limit_atoms, spent_atoms, created_at, updated_at
            )
            VALUES (?, ?, 'group', 'quota', 'pode-quota-key', 1, '100', '0', 1, 1)
            "#,
        )
        .bind(key_id.as_str())
        .bind(user_id.as_str())
        .execute(&repository.pool)
        .await
        .expect("create quota key");

        let (left, right) = tokio::join!(
            repository.admit_api_key_quota(&key_id),
            repository.admit_api_key_quota(&key_id),
        );
        assert_eq!(
            left.expect("left admission"),
            QuotaAdmissionOutcome::Admitted
        );
        assert_eq!(
            right.expect("right admission"),
            QuotaAdmissionOutcome::Admitted
        );

        sqlx::query("UPDATE api_keys SET spent_atoms = '99' WHERE id = ?")
            .bind(key_id.as_str())
            .execute(&repository.pool)
            .await
            .expect("set remaining spend");
        assert_eq!(
            repository
                .admit_api_key_quota(&key_id)
                .await
                .expect("boundary admission"),
            QuotaAdmissionOutcome::Admitted
        );

        sqlx::query("UPDATE api_keys SET spent_atoms = '100' WHERE id = ?")
            .bind(key_id.as_str())
            .execute(&repository.pool)
            .await
            .expect("exhaust quota");
        assert_eq!(
            repository
                .admit_api_key_quota(&key_id)
                .await
                .expect("exhausted admission"),
            QuotaAdmissionOutcome::Exceeded
        );

        sqlx::query("UPDATE api_keys SET spent_atoms = '150' WHERE id = ?")
            .bind(key_id.as_str())
            .execute(&repository.pool)
            .await
            .expect("overshoot spend");
        assert_eq!(
            repository
                .admit_api_key_quota(&key_id)
                .await
                .expect("overspent admission"),
            QuotaAdmissionOutcome::Exceeded
        );

        sqlx::query("UPDATE api_keys SET quota_limit_atoms = NULL, spent_atoms = '0' WHERE id = ?")
            .bind(key_id.as_str())
            .execute(&repository.pool)
            .await
            .expect("clear quota limit");
        assert_eq!(
            repository
                .admit_api_key_quota(&key_id)
                .await
                .expect("unlimited admission"),
            QuotaAdmissionOutcome::Unlimited
        );
    }

    #[tokio::test]
    async fn registration_codes_are_one_time_and_survive_username_conflicts() {
        let repository = SqliteAccountRepository::in_memory()
            .await
            .expect("in-memory repository");
        let admin = NewUser {
            id: UserId::new("registration-admin").expect("admin ID"),
            username: "admin".to_owned(),
            password_hash: "admin-password-hash".to_owned(),
            role: UserRole::SuperAdmin,
            enabled: true,
            created_at: 100,
        };
        assert_eq!(
            repository
                .create_initial_user(
                    admin.clone(),
                    test_session("registration-admin-session", admin.id.clone(), 10),
                )
                .await
                .expect("create admin"),
            InitialUserCreateOutcome::Created
        );
        repository
            .create_registration_code(NewRegistrationCode {
                code_hash: [20; 32],
                expires_at: 200,
            })
            .await
            .expect("create registration code");
        assert!(
            repository
                .registration_code_valid(&[20; 32], 199)
                .await
                .expect("validate unexpired registration code")
        );
        assert!(
            !repository
                .registration_code_valid(&[20; 32], 200)
                .await
                .expect("reject registration code at expiry")
        );

        let conflict = NewUser {
            id: UserId::new("conflicting-registration").expect("user ID"),
            username: "ADMIN".to_owned(),
            password_hash: "password-hash".to_owned(),
            role: UserRole::User,
            enabled: true,
            created_at: 120,
        };
        assert_eq!(
            repository
                .register_user(
                    &[20; 32],
                    conflict.clone(),
                    test_session("conflicting-registration-session", conflict.id, 20),
                    120,
                )
                .await
                .expect("reject username conflict"),
            RegisterUserOutcome::Conflict
        );

        let member = NewUser {
            id: UserId::new("registered-member").expect("user ID"),
            username: "member".to_owned(),
            password_hash: "password-hash".to_owned(),
            role: UserRole::User,
            enabled: true,
            created_at: 121,
        };
        assert_eq!(
            repository
                .register_user(
                    &[20; 32],
                    member.clone(),
                    test_session("registered-member-session", member.id.clone(), 22),
                    121,
                )
                .await
                .expect("register member"),
            RegisterUserOutcome::Created
        );
        assert!(
            repository
                .load_user(&member.id)
                .await
                .expect("load registered member")
                .is_some()
        );
        assert_eq!(
            repository
                .register_user(
                    &[20; 32],
                    NewUser {
                        id: UserId::new("reused-registration").expect("user ID"),
                        username: "other".to_owned(),
                        password_hash: "password-hash".to_owned(),
                        role: UserRole::User,
                        enabled: true,
                        created_at: 122,
                    },
                    test_session(
                        "reused-registration-session",
                        UserId::new("reused-registration").expect("user ID"),
                        24,
                    ),
                    122,
                )
                .await
                .expect("reject reused code"),
            RegisterUserOutcome::InvalidCode
        );
    }

    fn test_session(id: &str, user_id: UserId, token_hash: u8) -> NewSession {
        NewSession {
            id: SessionId::new(id).expect("session ID"),
            user_id,
            token_hash: [token_hash; 32],
            expires_at: 300,
            created_at: 100,
        }
    }
}
