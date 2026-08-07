use std::sync::Arc;

use provider_core::{
    AccountRepositoryError, DiscoveredProviderModel, ProviderAccount, ProviderManagementRepository,
    ProviderModelPricingCatalog, ProviderModelPricingRecord, ProviderModelPricingSource,
    StoredProviderModel,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCatalogSource {
    Remote,
    Cached,
    BuiltIn,
    Empty,
}

#[derive(Clone, Debug)]
pub struct ModelCatalogSnapshot {
    pub source: ModelCatalogSource,
    pub models: Vec<StoredProviderModel>,
    pub warning: Option<String>,
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
        match account.discover_models().await {
            Ok(mut models) => {
                self.attach_pricing(&mut models);
                let models = self
                    .repository
                    .synchronize_provider_models(account.account_id(), models, synced_at)
                    .await?;
                Ok(ModelCatalogSnapshot {
                    source: ModelCatalogSource::Remote,
                    models,
                    warning: None,
                })
            }
            Err(discovery_error) => {
                let cached = self
                    .repository
                    .list_provider_models(Some(account.account_id()))
                    .await?;
                let cached: Vec<_> = cached.into_iter().filter(|model| model.available).collect();
                if !cached.is_empty() {
                    return Ok(ModelCatalogSnapshot {
                        source: ModelCatalogSource::Cached,
                        models: cached,
                        warning: Some(discovery_error.message().to_owned()),
                    });
                }

                let mut fallback = account
                    .fallback_models()
                    .iter()
                    .map(|model| {
                        Ok(DiscoveredProviderModel {
                            upstream_model: model.id.clone(),
                            metadata_json: serde_json::to_string(model)?,
                            routable: true,
                            pricing: None,
                        })
                    })
                    .collect::<Result<Vec<_>, serde_json::Error>>()?;
                self.attach_pricing(&mut fallback);
                if fallback.is_empty() {
                    return Ok(ModelCatalogSnapshot {
                        source: ModelCatalogSource::Empty,
                        models: Vec::new(),
                        warning: Some(discovery_error.message().to_owned()),
                    });
                }
                let models = self
                    .repository
                    .synchronize_provider_models(account.account_id(), fallback, synced_at)
                    .await?;
                Ok(ModelCatalogSnapshot {
                    source: ModelCatalogSource::BuiltIn,
                    models,
                    warning: Some(discovery_error.message().to_owned()),
                })
            }
        }
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
    #[error("model catalog repository operation failed: {0}")]
    Repository(#[from] AccountRepositoryError),
    #[error("failed to serialize fallback model metadata")]
    Serialize(#[from] serde_json::Error),
}
