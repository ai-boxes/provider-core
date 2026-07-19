use std::sync::Arc;

use provider_core::{
    AccountRepositoryError, DiscoveredProviderModel, ProviderAccount, ProviderManagementRepository,
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
}

impl ModelCatalogService {
    #[must_use]
    pub fn new(repository: Arc<dyn ProviderManagementRepository>) -> Self {
        Self { repository }
    }

    pub async fn refresh(
        &self,
        account: &dyn ProviderAccount,
        synced_at: i64,
    ) -> Result<ModelCatalogSnapshot, ModelCatalogError> {
        match account.discover_models().await {
            Ok(models) => {
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

                let fallback = account
                    .fallback_models()
                    .iter()
                    .map(|model| {
                        Ok(DiscoveredProviderModel {
                            upstream_model: model.id.clone(),
                            metadata_json: serde_json::to_string(model)?,
                            routable: true,
                        })
                    })
                    .collect::<Result<Vec<_>, serde_json::Error>>()?;
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
}

#[derive(Debug, Error)]
pub enum ModelCatalogError {
    #[error("model catalog repository operation failed: {0}")]
    Repository(#[from] AccountRepositoryError),
    #[error("failed to serialize fallback model metadata")]
    Serialize(#[from] serde_json::Error),
}
