//! Provider contracts and proxy orchestration.

#![forbid(unsafe_code)]

pub mod account;
pub mod model;
pub mod protocol;
pub mod provider;
pub mod proxy;
pub mod token_count;

pub use account::{
    AccountAuthState, AccountAuthStateError, AccountId, AccountIdError, AccountRepository,
    AccountRepositoryError, AccountRuntimeState, CredentialUpdate, CredentialWriteOutcome,
    ProviderAccount, RefreshError, RefreshErrorKind, RefreshOutcome, RefreshTrigger,
    StoredCredential, StoredProviderAccount,
};
pub use model::ProviderModel;
pub use protocol::{PreparedProviderRequest, ProtocolBridge, ResponseTranslator, WireFormat};
pub use provider::{Provider, ProviderDriver, ProviderError, ProviderErrorKind, ProviderStream};
pub use proxy::{ProviderRequest, ProxyRequest, ProxyRequestError, ProxyService, RequestMetadata};
pub use token_count::{TokenCountError, TokenCounter};
