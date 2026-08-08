use std::sync::Arc;

use provider_core::{
    AccountRepositoryError, DiscoveredProviderModel, ProviderAccount, ProviderError,
    ProviderManagementRepository, ProviderModelPricingCatalog, ProviderModelPricingRecord,
    ProviderModelPricingSource, StoredProviderModel,
};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ModelCatalogSnapshot {
    pub models: Vec<StoredProviderModel>,
}

#[derive(Clone)]
pub struct ModelCatalogService {
    repository: Arc<dyn ProviderManagementRepository>,
    pricing: Option<Arc<dyn ProviderModelPricingCatalog>>,
}

impl ModelCatalogService {
    #[must_use]
    pub fn new(repository: Arc<dyn ProviderManagementRepository>) -> Self {
        Self {
            repository,
            pricing: None,
        }
    }

    #[must_use]
    pub fn with_pricing(
        repository: Arc<dyn ProviderManagementRepository>,
        pricing: Arc<dyn ProviderModelPricingCatalog>,
    ) -> Self {
        Self {
            repository,
            pricing: Some(pricing),
        }
    }

    pub async fn refresh(
        &self,
        account: &dyn ProviderAccount,
        synced_at: i64,
    ) -> Result<ModelCatalogSnapshot, ModelCatalogError> {
        let mut models = account.discover_models().await?;
        self.attach_pricing(&mut models);
        let models = self
            .repository
            .synchronize_provider_models(account.account_id(), models, synced_at)
            .await?;
        Ok(ModelCatalogSnapshot { models })
    }

    fn attach_pricing(&self, models: &mut [DiscoveredProviderModel]) {
        let Some(catalog) = self.pricing.as_ref() else {
            return;
        };
        for model in models {
            model.pricing = catalog.exact_pricing(&model.upstream_model).map(|pricing| {
                ProviderModelPricingRecord {
                    source: ProviderModelPricingSource::Catalog,
                    pricing,
                }
            });
        }
    }
}

#[derive(Debug, Error)]
pub enum ModelCatalogError {
    #[error("provider model discovery failed: {0}")]
    Discovery(#[from] ProviderError),
    #[error("model catalog repository operation failed: {0}")]
    Repository(#[from] AccountRepositoryError),
}
