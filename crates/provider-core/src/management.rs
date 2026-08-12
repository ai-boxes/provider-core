use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use thiserror::Error;

use crate::{
    AccountId, AccountRepository, NewProviderAccount, ProviderAccount, ProviderAccountAccess,
    ProviderAccountUpdate, ProviderDriver, ProviderKind, ProviderQuotaControl,
    StoredProviderAccount, StoredProviderModel,
};

#[derive(Clone, Debug)]
pub enum AccountProvisioningInput {
    CredentialJson {
        id: AccountId,
        label: String,
        group_label: String,
        credential_json: SecretString,
    },
    Direct {
        id: AccountId,
        label: String,
        group_label: String,
        config_json: String,
        api_key: SecretString,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderOAuthChallenge {
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub user_code: String,
    pub expires_at: i64,
    pub interval_seconds: u64,
}

pub struct StartedProviderOAuth {
    pub challenge: ProviderOAuthChallenge,
    pub pending: Box<dyn PendingProviderOAuth>,
}

#[async_trait]
pub trait PendingProviderOAuth: Send {
    async fn complete(self: Box<Self>) -> Result<SecretString, ProviderConfigurationError>;
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct ProviderConfigurationError {
    message: String,
}

impl ProviderConfigurationError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[async_trait]
pub trait ManagedProviderDriver: ProviderDriver {
    fn kind(&self) -> ProviderKind;

    fn supports_quota(&self) -> bool {
        false
    }

    fn prepare_account(
        &self,
        input: AccountProvisioningInput,
    ) -> Result<NewProviderAccount, ProviderConfigurationError>;

    fn prepare_account_update(
        &self,
        update: ProviderAccountUpdate,
    ) -> Result<ProviderAccountUpdate, ProviderConfigurationError>;

    async fn start_oauth(&self) -> Result<StartedProviderOAuth, ProviderConfigurationError> {
        Err(ProviderConfigurationError::new(
            "provider does not support OAuth onboarding",
        ))
    }

    fn build_account(
        self: Arc<Self>,
        account: StoredProviderAccount,
        repository: Arc<dyn AccountRepository>,
    ) -> Result<Arc<dyn ProviderAccount>, ProviderConfigurationError>;
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct ProviderControlError {
    message: String,
}

impl ProviderControlError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait ProviderControl: ProviderQuotaControl + Send + Sync {
    fn prepare_account(
        &self,
        kind: ProviderKind,
        input: AccountProvisioningInput,
    ) -> Result<NewProviderAccount, ProviderControlError>;

    fn prepare_account_update(
        &self,
        kind: ProviderKind,
        update: ProviderAccountUpdate,
    ) -> Result<ProviderAccountUpdate, ProviderControlError>;

    fn build_account(
        &self,
        account: StoredProviderAccount,
    ) -> Result<Arc<dyn ProviderAccount>, ProviderControlError>;

    async fn start_oauth(
        &self,
        kind: ProviderKind,
    ) -> Result<StartedProviderOAuth, ProviderControlError>;

    async fn install_account(
        &self,
        kind: ProviderKind,
        account: Arc<dyn ProviderAccount>,
        models: Vec<StoredProviderModel>,
        access: ProviderAccountAccess,
        priority: u32,
    );

    fn update_account_access(&self, account_id: &AccountId, access: ProviderAccountAccess) -> bool;

    fn update_account_models(
        &self,
        account_id: &AccountId,
        models: Vec<StoredProviderModel>,
    ) -> bool;

    fn claim_unowned_account_access(&self, owner_user_id: &str);

    async fn remove_account(&self, account_id: &AccountId) -> bool;
}
