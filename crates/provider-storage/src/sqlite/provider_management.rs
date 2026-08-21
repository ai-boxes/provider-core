use super::*;

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

    async fn list_all_provider_accounts(
        &self,
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
            ORDER BY a.priority, a.created_at, a.id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| repository_error("failed to list all provider accounts", error))?;

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
        let expected_revision = if create {
            None
        } else {
            Some(expected_credential_revision.ok_or_else(|| {
                AccountRepositoryError::new(
                    "provider snapshot update requires an expected credential revision",
                )
            })?)
        };
        let mut transaction = self.write.begin().await.map_err(|error| {
            repository_error("failed to start provider snapshot transaction", error)
        })?;
        let result = async {
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
                let expected_revision = expected_revision.ok_or_else(|| {
                    AccountRepositoryError::new(
                        "provider snapshot update requires an expected credential revision",
                    )
                })?;
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
                let (pricing_source, pricing_json) =
                    encode_model_pricing(model.pricing.as_ref())?;
                let input_modalities_json =
                    encode_input_modalities(model.input_modalities.as_deref())?;
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
                .map_err(|error| {
                    repository_error("failed to write provider model snapshot", error)
                })?;
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
            .map_err(|error| {
                repository_error("failed to read committed provider models", error)
            })?;
            let models = rows
                .into_iter()
                .map(stored_model)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ProviderSnapshotWriteOutcome::Committed { models })
        }
        .await;
        match result {
            Ok(outcome @ ProviderSnapshotWriteOutcome::Committed { .. }) => {
                transaction.commit().await.map_err(|error| {
                    repository_error("failed to commit provider snapshot transaction", error)
                })?;
                Ok(outcome)
            }
            Ok(outcome) => {
                let _ = transaction.rollback().await;
                Ok(outcome)
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                Err(error)
            }
        }
    }

    async fn create_provider_account(
        &self,
        account: NewProviderAccount,
        owner_user_id: &str,
        visibility: ProviderVisibility,
    ) -> Result<ProviderAccountCreateOutcome, AccountRepositoryError> {
        let format_version = i64::from(account.credential.format_version);
        let ciphertext = self
            .credential_cipher
            .encrypt(&account.id, &account.credential.credential_json)?;
        let mut transaction = self
            .write
            .begin()
            .await
            .map_err(|error| repository_error("failed to start account transaction", error))?;
        let result = async {
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
            .bind(&ciphertext)
            .bind(account.credential.expires_at)
            .bind(account.credential.last_refreshed_at)
            .execute(&mut *transaction)
            .await
            .map_err(|error| repository_error("failed to create provider credential", error))?;

            Ok(ProviderAccountCreateOutcome::Created)
        }
        .await;
        match result {
            Ok(ProviderAccountCreateOutcome::Created) => {
                transaction.commit().await.map_err(|error| {
                    repository_error("failed to commit provider account", error)
                })?;
                Ok(ProviderAccountCreateOutcome::Created)
            }
            Ok(outcome) => {
                let _ = transaction.rollback().await;
                Ok(outcome)
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                Err(error)
            }
        }
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
        .execute(&mut *self.write.lock().await)
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
        let ciphertext = self
            .credential_cipher
            .encrypt(account_id, &credential.credential_json)?;

        let mut transaction = self.write.begin().await.map_err(|error| {
            repository_error("failed to start provider update transaction", error)
        })?;
        let result = async {
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
            .bind(&ciphertext)
            .bind(credential.expires_at)
            .bind(credential.last_refreshed_at)
            .bind(credential.updated_at)
            .bind(account_id.as_str())
            .bind(expected_revision)
            .execute(&mut *transaction)
            .await
            .map_err(|error| repository_error("failed to update provider credential", error))?;
            if credential_result.rows_affected() == 0 {
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

            Ok(Some(CredentialWriteOutcome::Updated {
                revision: next_revision,
            }))
        }
        .await;
        match result {
            Ok(Some(outcome @ CredentialWriteOutcome::Updated { .. })) => {
                transaction
                    .commit()
                    .await
                    .map_err(|error| repository_error("failed to commit provider update", error))?;
                Ok(Some(outcome))
            }
            Ok(outcome) => {
                let _ = transaction.rollback().await;
                Ok(outcome)
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                Err(error)
            }
        }
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
        .execute(&mut *self.write.lock().await)
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
            .execute(&mut *self.write.lock().await)
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
        if models.iter().any(|model| {
            let upstream_model = model.upstream_model.as_str();
            upstream_model.is_empty() || upstream_model.trim() != upstream_model
        }) {
            return Err(AccountRepositoryError::new(
                "discovered provider model must not be empty or contain surrounding whitespace",
            ));
        }
        let mut transaction = self
            .write
            .begin()
            .await
            .map_err(|error| repository_error("failed to start model transaction", error))?;
        let result = async {
            let account_exists = sqlx::query("SELECT 1 FROM provider_accounts WHERE id = ?")
                .bind(account_id.as_str())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|error| repository_error("failed to verify provider account", error))?
                .is_some();
            if !account_exists {
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
            .map_err(|error| {
                repository_error("failed to mark provider models unavailable", error)
            })?;

            for model in models {
                let upstream_model = model.upstream_model.as_str();
                let (pricing_source, pricing_json) =
                    encode_model_pricing(model.pricing.as_ref())?;
                let input_modalities_json =
                    encode_input_modalities(model.input_modalities.as_deref())?;
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
                .map_err(|error| {
                    repository_error("failed to synchronize provider model", error)
                })?;
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                transaction
                    .commit()
                    .await
                    .map_err(|error| repository_error("failed to commit provider models", error))?;
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                return Err(error);
            }
        }
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
        .execute(&mut *self.write.lock().await)
        .await
        .map_err(|error| repository_error("failed to update provider model", error))?;
        Ok(result.rows_affected() > 0)
    }
}
