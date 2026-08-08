use async_trait::async_trait;
use thiserror::Error;

use crate::{
    ApiKeyId, NewApiKey, NewRegistrationCode, NewSession, NewUser, SessionId, StoredApiKey,
    StoredSession, StoredUser, UserId, UserSummary,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialUserCreateOutcome {
    Created,
    AlreadyConfigured,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshSessionOutcome {
    Updated,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterUserOutcome {
    Created,
    InvalidCode,
    Conflict,
}

#[async_trait]
pub trait AuthRepository: Send + Sync {
    async fn setup_required(&self) -> Result<bool, AuthRepositoryError>;

    async fn create_initial_user(
        &self,
        user: NewUser,
        session: NewSession,
    ) -> Result<InitialUserCreateOutcome, AuthRepositoryError>;

    async fn load_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<StoredUser>, AuthRepositoryError>;

    async fn load_user(&self, user_id: &UserId) -> Result<Option<StoredUser>, AuthRepositoryError>;

    async fn list_users(&self) -> Result<Vec<UserSummary>, AuthRepositoryError>;

    async fn create_user(&self, user: NewUser) -> Result<bool, AuthRepositoryError>;

    async fn create_registration_code(
        &self,
        code: NewRegistrationCode,
    ) -> Result<(), AuthRepositoryError>;

    async fn registration_code_valid(
        &self,
        code_hash: &[u8; 32],
        now: i64,
    ) -> Result<bool, AuthRepositoryError>;

    async fn register_user(
        &self,
        code_hash: &[u8; 32],
        user: NewUser,
        session: NewSession,
        now: i64,
    ) -> Result<RegisterUserOutcome, AuthRepositoryError>;

    async fn set_user_enabled(
        &self,
        user_id: &UserId,
        enabled: bool,
        updated_at: i64,
    ) -> Result<bool, AuthRepositoryError>;

    async fn reset_user_password(
        &self,
        user_id: &UserId,
        password_hash: String,
        updated_at: i64,
    ) -> Result<bool, AuthRepositoryError>;

    async fn create_session(&self, session: NewSession) -> Result<(), AuthRepositoryError>;

    async fn load_session_by_access_hash(
        &self,
        access_token_hash: &[u8; 32],
    ) -> Result<Option<StoredSession>, AuthRepositoryError>;

    async fn load_session_by_refresh_hash(
        &self,
        refresh_token_hash: &[u8; 32],
    ) -> Result<Option<StoredSession>, AuthRepositoryError>;

    async fn rotate_session(
        &self,
        refresh_token_hash: &[u8; 32],
        new_access_token_hash: [u8; 32],
        new_refresh_token_hash: [u8; 32],
        access_expires_at: i64,
        refresh_expires_at: i64,
        updated_at: i64,
    ) -> Result<RefreshSessionOutcome, AuthRepositoryError>;

    async fn revoke_session(
        &self,
        session_id: &SessionId,
        revoked_at: i64,
    ) -> Result<bool, AuthRepositoryError>;

    async fn create_api_key(&self, key: NewApiKey) -> Result<bool, AuthRepositoryError>;

    async fn list_api_keys(
        &self,
        owner_user_id: &UserId,
    ) -> Result<Vec<StoredApiKey>, AuthRepositoryError>;

    async fn load_api_key(
        &self,
        owner_user_id: &UserId,
        key_id: &ApiKeyId,
    ) -> Result<Option<StoredApiKey>, AuthRepositoryError>;

    async fn update_api_key(
        &self,
        owner_user_id: &UserId,
        key_id: &ApiKeyId,
        group_label: &str,
        label: &str,
        enabled: bool,
        expires_at: Option<i64>,
        quota_limit_atoms: Option<Option<String>>,
        updated_at: i64,
    ) -> Result<Option<StoredApiKey>, AuthRepositoryError>;

    async fn delete_api_key(
        &self,
        owner_user_id: &UserId,
        key_id: &ApiKeyId,
    ) -> Result<bool, AuthRepositoryError>;

    async fn load_active_api_keys(&self) -> Result<Vec<StoredApiKey>, AuthRepositoryError>;

    /// Account IDs visible to `actor_user_id` that carry the given group label.
    async fn list_visible_account_ids_by_group_label(
        &self,
        actor_user_id: &UserId,
        group_label: &str,
    ) -> Result<Vec<String>, AuthRepositoryError>;

    /// Current cumulative known spend for a key, in USD atoms.
    async fn load_api_key_spent_atoms(
        &self,
        api_key_id: &ApiKeyId,
    ) -> Result<Option<(String, bool)>, AuthRepositoryError>;

    async fn quota_ledger_ready(&self) -> Result<(), AuthRepositoryError>;
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct AuthRepositoryError {
    message: String,
}

impl AuthRepositoryError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
