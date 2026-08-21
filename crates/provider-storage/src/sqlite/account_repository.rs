use super::*;

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
        let ciphertext = self
            .credential_cipher
            .encrypt(account_id, &update.credential_json)?;

        let mut transaction =
            self.write.begin().await.map_err(|error| {
                repository_error("failed to start credential transaction", error)
            })?;
        let result = async {
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
            .bind(&ciphertext)
            .bind(update.expires_at)
            .bind(update.last_refreshed_at)
            .bind(update.updated_at)
            .bind(account_id.as_str())
            .bind(expected_revision)
            .execute(&mut *transaction)
            .await
            .map_err(|error| repository_error("failed to update provider credential", error))?;

            if result.rows_affected() == 0 {
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

            Ok(CredentialWriteOutcome::Updated {
                revision: next_revision,
            })
        }
        .await;
        match result {
            Ok(outcome @ CredentialWriteOutcome::Updated { .. }) => {
                transaction.commit().await.map_err(|error| {
                    repository_error("failed to commit credential update", error)
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
        .execute(&mut *self.write.lock().await)
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
