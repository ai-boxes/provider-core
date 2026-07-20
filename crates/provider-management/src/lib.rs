//! Provider account onboarding and model catalog use cases.

#![forbid(unsafe_code)]

mod manager;
mod model_catalog;

pub use manager::{
    CreatedProviderAccount, DirectProviderAccountInput, OAuthSessionSnapshot, OAuthSessionStatus,
    ProviderCredentialReplacement, ProviderManager, ProviderManagerError,
};
pub use model_catalog::{
    ModelCatalogError, ModelCatalogService, ModelCatalogSnapshot, ModelCatalogSource,
};
