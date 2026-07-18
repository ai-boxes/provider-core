use std::{fmt, str::FromStr};

use async_trait::async_trait;
use secrecy::SecretString;
use thiserror::Error;

use crate::Provider;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, AccountIdError> {
        let value = value.into().trim().to_owned();
        if value.is_empty() {
            return Err(AccountIdError);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for AccountId {
    type Err = AccountIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("account ID must not be empty")]
pub struct AccountIdError;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AccountAuthState {
    #[default]
    Active,
    ReauthRequired,
}

impl AccountAuthState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ReauthRequired => "reauth_required",
        }
    }
}

impl FromStr for AccountAuthState {
    type Err = AccountAuthStateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "active" => Ok(Self::Active),
            "reauth_required" => Ok(Self::ReauthRequired),
            _ => Err(AccountAuthStateError),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("unsupported account auth state")]
pub struct AccountAuthStateError;

#[derive(Clone, Debug)]
pub struct StoredCredential {
    pub revision: u64,
    pub format_version: u32,
    pub credential_json: SecretString,
    pub expires_at: Option<i64>,
    pub last_refreshed_at: Option<i64>,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct StoredProviderAccount {
    pub id: AccountId,
    pub provider: String,
    pub label: String,
    pub enabled: bool,
    pub auth_state: AccountAuthState,
    pub safe_error_code: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub credential: StoredCredential,
}

#[derive(Clone, Debug)]
pub struct CredentialUpdate {
    pub expected_revision: u64,
    pub format_version: u32,
    pub credential_json: SecretString,
    pub expires_at: Option<i64>,
    pub last_refreshed_at: Option<i64>,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialWriteOutcome {
    Updated { revision: u64 },
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshTrigger {
    Scheduled,
    Unauthorized,
    Manual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshErrorKind {
    ReauthRequired,
    Transient,
    Internal,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct RefreshError {
    kind: RefreshErrorKind,
    message: String,
}

impl RefreshError {
    #[must_use]
    pub fn new(kind: RefreshErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> RefreshErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountRuntimeState {
    pub generation: u64,
    pub next_refresh_at: Option<i64>,
    pub auth_state: AccountAuthState,
    pub persistence_pending: bool,
}

impl AccountRuntimeState {
    #[must_use]
    pub const fn available_for_requests(self) -> bool {
        matches!(self.auth_state, AccountAuthState::Active)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshOutcome {
    pub state: AccountRuntimeState,
}

#[async_trait]
pub trait ProviderAccount: Provider {
    fn account_id(&self) -> &AccountId;

    fn runtime_state(&self) -> AccountRuntimeState;

    async fn refresh_credentials(
        &self,
        trigger: RefreshTrigger,
    ) -> Result<RefreshOutcome, RefreshError>;
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct AccountRepositoryError {
    message: String,
}

impl AccountRepositoryError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait AccountRepository: Send + Sync {
    async fn load_enabled_accounts(
        &self,
    ) -> Result<Vec<StoredProviderAccount>, AccountRepositoryError>;

    async fn compare_and_swap_credential(
        &self,
        account_id: &AccountId,
        update: CredentialUpdate,
    ) -> Result<CredentialWriteOutcome, AccountRepositoryError>;

    async fn update_auth_state(
        &self,
        account_id: &AccountId,
        state: AccountAuthState,
        safe_error_code: Option<&str>,
        updated_at: i64,
    ) -> Result<(), AccountRepositoryError>;
}
