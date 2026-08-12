use super::*;

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
    ) -> Result<UserUpdateOutcome, AuthRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(|error| {
            auth_repository_error("failed to start user status transaction", error)
        })?;
        let result = sqlx::query(
            r#"
            UPDATE users
            SET enabled = ?, updated_at = ?
            WHERE id = ?
              AND (
                  ? = 1
                  OR role != 'super_admin'
                  OR enabled = 0
                  OR EXISTS (
                      SELECT 1
                      FROM users AS other
                      WHERE other.id != users.id
                        AND other.role = 'super_admin'
                        AND other.enabled = 1
                  )
              )
            "#,
        )
        .bind(database_bool(enabled))
        .bind(updated_at)
        .bind(user_id.as_str())
        .bind(database_bool(enabled))
        .execute(&mut *transaction)
        .await
        .map_err(|error| auth_repository_error("failed to update user status", error))?;
        if result.rows_affected() == 0 {
            let exists =
                sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)")
                    .bind(user_id.as_str())
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(|error| {
                        auth_repository_error("failed to check user status target", error)
                    })?;
            transaction.rollback().await.map_err(|error| {
                auth_repository_error("failed to roll back rejected user status update", error)
            })?;
            return Ok(if exists == 0 {
                UserUpdateOutcome::NotFound
            } else {
                UserUpdateOutcome::LastEnabledSuperAdmin
            });
        }
        if !enabled {
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
        Ok(UserUpdateOutcome::Updated)
    }

    async fn set_user_role(
        &self,
        user_id: &UserId,
        role: UserRole,
        updated_at: i64,
    ) -> Result<UserUpdateOutcome, AuthRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(|error| {
            auth_repository_error("failed to start user role transaction", error)
        })?;
        let result = sqlx::query(
            r#"
            UPDATE users
            SET role = ?, updated_at = ?
            WHERE id = ?
              AND role != ?
              AND (
                  role != 'super_admin'
                  OR enabled = 0
                  OR ? = 'super_admin'
                  OR EXISTS (
                      SELECT 1
                      FROM users AS other
                      WHERE other.id != users.id
                        AND other.role = 'super_admin'
                        AND other.enabled = 1
                  )
              )
            "#,
        )
        .bind(role.as_str())
        .bind(updated_at)
        .bind(user_id.as_str())
        .bind(role.as_str())
        .bind(role.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| auth_repository_error("failed to update user role", error))?;
        if result.rows_affected() == 0 {
            let current_role =
                sqlx::query_scalar::<_, String>("SELECT role FROM users WHERE id = ?")
                    .bind(user_id.as_str())
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(|error| {
                        auth_repository_error("failed to check user role target", error)
                    })?;
            transaction.rollback().await.map_err(|error| {
                auth_repository_error("failed to roll back rejected user role update", error)
            })?;
            return Ok(match current_role.as_deref() {
                None => UserUpdateOutcome::NotFound,
                Some(current) if current == role.as_str() => UserUpdateOutcome::Updated,
                Some(_) => UserUpdateOutcome::LastEnabledSuperAdmin,
            });
        }
        sqlx::query(
            "UPDATE user_sessions SET revoked_at = ?, updated_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        )
        .bind(updated_at)
        .bind(updated_at)
        .bind(user_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| auth_repository_error("failed to revoke role-updated sessions", error))?;
        transaction.commit().await.map_err(|error| {
            auth_repository_error("failed to commit user role transaction", error)
        })?;
        Ok(UserUpdateOutcome::Updated)
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
