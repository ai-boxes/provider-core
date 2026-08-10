use std::sync::Arc;

use provider_core::{
    DiscoveredProviderModel, ProviderAccount, ProviderError, ProviderModelPricingCatalog,
    ProviderModelPricingRecord, ProviderModelPricingSource, StoredProviderModel,
};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ModelCatalogSnapshot {
    pub models: Vec<StoredProviderModel>,
}

#[derive(Clone)]
pub struct ModelCatalogService {
    pricing: Option<Arc<dyn ProviderModelPricingCatalog>>,
}

impl Default for ModelCatalogService {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelCatalogService {
    #[must_use]
    pub fn new() -> Self {
        Self { pricing: None }
    }

    #[must_use]
    pub fn with_pricing(pricing: Arc<dyn ProviderModelPricingCatalog>) -> Self {
        Self {
            pricing: Some(pricing),
        }
    }

    pub async fn discover(
        &self,
        account: &dyn ProviderAccount,
    ) -> Result<Vec<DiscoveredProviderModel>, ModelCatalogError> {
        let mut models = account.discover_models().await?;
        self.attach_pricing(&mut models);
        Ok(models)
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
}
