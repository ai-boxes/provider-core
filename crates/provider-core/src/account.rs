use std::{fmt, str::FromStr};

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DiscoveredProviderModel, ProviderError, ProviderErrorKind, ProviderModel,
    ProviderQuotaObservation, ProviderQuotaSource, ProviderRequest, ProviderStream,
};

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Grok,
    Codex,
    #[serde(rename = "openai_compatible")]
    OpenAiCompatible,
    AnthropicCompatible,
}

impl ProviderKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grok => "grok",
            Self::Codex => "codex",
            Self::OpenAiCompatible => "openai_compatible",
            Self::AnthropicCompatible => "anthropic_compatible",
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ProviderKind {
    type Err = ProviderKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "grok" => Ok(Self::Grok),
            "codex" => Ok(Self::Codex),
            "openai_compatible" => Ok(Self::OpenAiCompatible),
            "anthropic_compatible" => Ok(Self::AnthropicCompatible),
            _ => Err(ProviderKindError),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("unsupported provider type")]
pub struct ProviderKindError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Oauth,
    ApiKey,
}

impl CredentialKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oauth => "oauth",
            Self::ApiKey => "api_key",
        }
    }
}

impl FromStr for CredentialKind {
    type Err = CredentialKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "oauth" => Ok(Self::Oauth),
            "api_key" => Ok(Self::ApiKey),
            _ => Err(CredentialKindError),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("unsupported credential type")]
pub struct CredentialKindError;

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

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderVisibility {
    #[default]
    Private,
    Shared,
}

impl ProviderVisibility {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Shared => "shared",
        }
    }
}

impl FromStr for ProviderVisibility {
    type Err = ProviderVisibilityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "private" => Ok(Self::Private),
            "shared" => Ok(Self::Shared),
            _ => Err(ProviderVisibilityError),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("unsupported provider visibility")]
pub struct ProviderVisibilityError;

#[derive(Clone, Debug)]
pub struct StoredCredential {
    pub kind: CredentialKind,
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
    pub owner_user_id: Option<String>,
    pub visibility: ProviderVisibility,
    pub provider: ProviderKind,
    pub label: String,
    pub group_label: String,
    pub config_json: String,
    pub enabled: bool,
    pub auth_state: AccountAuthState,
    pub safe_error_code: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub credential: StoredCredential,
}

impl StoredProviderAccount {
    #[must_use]
    pub fn access(&self) -> ProviderAccountAccess {
        ProviderAccountAccess {
            owner_user_id: self.owner_user_id.clone(),
            visibility: self.visibility,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAccountAccess {
    pub owner_user_id: Option<String>,
    pub visibility: ProviderVisibility,
}

impl ProviderAccountAccess {
    #[must_use]
    pub fn allows(&self, user_id: &str) -> bool {
        self.owner_user_id.as_deref().is_some_and(|owner_user_id| {
            owner_user_id == user_id || self.visibility == ProviderVisibility::Shared
        })
    }
}

#[derive(Clone, Debug)]
pub struct NewCredential {
    pub kind: CredentialKind,
    pub format_version: u32,
    pub credential_json: SecretString,
    pub expires_at: Option<i64>,
    pub last_refreshed_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct NewProviderAccount {
    pub id: AccountId,
    pub provider: ProviderKind,
    pub label: String,
    pub group_label: String,
    pub config_json: String,
    pub enabled: bool,
    pub credential: NewCredential,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAccountSummary {
    pub id: AccountId,
    pub owner_user_id: Option<String>,
    pub visibility: ProviderVisibility,
    pub provider: ProviderKind,
    pub label: String,
    pub group_label: String,
    pub config_json: String,
    pub credential_kind: CredentialKind,
    pub credential_revision: u64,
    pub enabled: bool,
    pub auth_state: AccountAuthState,
    pub safe_error_code: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct ProviderAccountUpdate {
    pub label: String,
    pub group_label: String,
    pub config_json: String,
    pub visibility: ProviderVisibility,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderAccountCreateOutcome {
    Created,
    Conflict,
}

#[derive(Clone, Debug)]
pub struct CredentialUpdate {
    pub expected_revision: u64,
    pub kind: CredentialKind,
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

#[derive(Clone, Debug)]
pub struct ProviderSnapshot {
    pub account: StoredProviderAccount,
    pub models: Vec<crate::DiscoveredProviderModel>,
    pub write_models: bool,
    pub reset_models: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderSnapshotWriteOutcome {
    Committed {
        models: Vec<crate::StoredProviderModel>,
    },
    Conflict,
    NotFound,
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
pub trait ProviderAccount: Send + Sync {
    fn provider_name(&self) -> &'static str;

    fn account_id(&self) -> &AccountId;

    fn runtime_state(&self) -> AccountRuntimeState;

    fn credential_revision(&self) -> u64;

    fn quota_source(&self) -> Option<&dyn ProviderQuotaSource> {
        None
    }

    fn quota_observation(&self) -> Option<ProviderQuotaObservation> {
        None
    }

    /// How this provider's responses report usage.
    ///
    /// `None` means the wire contract has not been established from real
    /// responses yet, so usage is not tracked for it. Guessing a contract would
    /// produce confident numbers with no evidence behind them.
    fn usage_profile(&self) -> Option<crate::usage::ProviderUsageProfile> {
        None
    }

    async fn execute_stream(
        &self,
        request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError>;

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError>;

    async fn discover_models(&self) -> Result<Vec<DiscoveredProviderModel>, ProviderError> {
        Err(ProviderError::new(
            ProviderErrorKind::Upstream,
            "provider model discovery is not available",
        ))
    }

    fn fallback_models(&self) -> &[ProviderModel] {
        &[]
    }

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

#[async_trait]
pub trait ProviderManagementRepository: AccountRepository + Send + Sync {
    async fn list_provider_accounts(
        &self,
        actor_user_id: &str,
    ) -> Result<Vec<ProviderAccountSummary>, AccountRepositoryError>;

    async fn load_provider_account(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<StoredProviderAccount>, AccountRepositoryError>;

    /// Persist account metadata, credentials and the discovered model snapshot in one transaction.
    /// Updates with an unchanged credential revision preserve the current authentication state;
    /// advancing the revision owns the transition to the candidate authentication state.
    async fn commit_provider_snapshot(
        &self,
        snapshot: ProviderSnapshot,
        create: bool,
        expected_credential_revision: Option<u64>,
    ) -> Result<ProviderSnapshotWriteOutcome, AccountRepositoryError>;

    async fn create_provider_account(
        &self,
        account: NewProviderAccount,
        owner_user_id: &str,
        visibility: ProviderVisibility,
    ) -> Result<ProviderAccountCreateOutcome, AccountRepositoryError>;

    async fn update_provider_account(
        &self,
        account_id: &AccountId,
        update: ProviderAccountUpdate,
    ) -> Result<bool, AccountRepositoryError>;

    /// Update account metadata and its credential in one database transaction.
    async fn update_provider_account_and_credential(
        &self,
        account_id: &AccountId,
        account: ProviderAccountUpdate,
        credential: CredentialUpdate,
    ) -> Result<Option<CredentialWriteOutcome>, AccountRepositoryError>;

    async fn set_provider_account_enabled(
        &self,
        account_id: &AccountId,
        enabled: bool,
        updated_at: i64,
    ) -> Result<bool, AccountRepositoryError>;

    async fn delete_provider_account(
        &self,
        account_id: &AccountId,
    ) -> Result<bool, AccountRepositoryError>;

    async fn list_provider_models(
        &self,
        account_id: Option<&AccountId>,
    ) -> Result<Vec<crate::StoredProviderModel>, AccountRepositoryError>;

    async fn synchronize_provider_models(
        &self,
        account_id: &AccountId,
        models: Vec<crate::DiscoveredProviderModel>,
        synced_at: i64,
    ) -> Result<Vec<crate::StoredProviderModel>, AccountRepositoryError>;

    async fn update_provider_model(
        &self,
        account_id: &AccountId,
        upstream_model: &str,
        update: crate::ProviderModelOverride,
    ) -> Result<bool, AccountRepositoryError>;
}
