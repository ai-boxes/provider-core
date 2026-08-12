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
        self.attach_catalog(&mut models);
        Ok(models)
    }

    fn attach_catalog(&self, models: &mut [DiscoveredProviderModel]) {
        let Some(catalog) = self.pricing.as_ref() else {
            return;
        };
        for model in models {
            model.input_modalities = catalog.exact_input_modalities(&model.upstream_model);
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

#[cfg(test)]
mod tests {
    use super::*;
    use provider_core::{
        ProviderModelInputModality, ProviderModelPricing, ProviderModelPricingCatalog,
    };

    struct Catalog;

    impl ProviderModelPricingCatalog for Catalog {
        fn exact_pricing(&self, _upstream_model: &str) -> Option<ProviderModelPricing> {
            None
        }

        fn exact_input_modalities(
            &self,
            upstream_model: &str,
        ) -> Option<Vec<ProviderModelInputModality>> {
            (upstream_model == "catalog-model").then_some(vec![
                ProviderModelInputModality::Audio,
                ProviderModelInputModality::Video,
            ])
        }
    }

    #[test]
    fn catalog_modalities_are_authoritative_over_upstream_discovery() {
        let service = ModelCatalogService::with_pricing(Arc::new(Catalog));
        let mut models = vec![
            DiscoveredProviderModel {
                upstream_model: "catalog-model".to_owned(),
                input_modalities: Some(vec![
                    ProviderModelInputModality::Text,
                    ProviderModelInputModality::Image,
                ]),
                metadata_json: "{}".to_owned(),
                routable: true,
                pricing: None,
            },
            DiscoveredProviderModel {
                upstream_model: "missing-model".to_owned(),
                input_modalities: Some(vec![
                    ProviderModelInputModality::Text,
                    ProviderModelInputModality::Image,
                ]),
                metadata_json: "{}".to_owned(),
                routable: true,
                pricing: None,
            },
        ];

        service.attach_catalog(&mut models);

        assert_eq!(
            models[0].input_modalities,
            Some(vec![
                ProviderModelInputModality::Audio,
                ProviderModelInputModality::Video,
            ])
        );
        assert_eq!(models[1].input_modalities, None);
    }
}
