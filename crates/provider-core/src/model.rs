use crate::AccountId;
use serde::{Deserialize, Serialize};

/// Model metadata exposed by a provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderModel {
    pub id: String,
    pub object: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<u64>,
    pub owned_by: String,
}

impl ProviderModel {
    #[must_use]
    pub fn new(id: impl Into<String>, owned_by: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            object: "model".to_owned(),
            created: None,
            owned_by: owned_by.into(),
        }
    }

    #[must_use]
    pub const fn with_created(mut self, created: u64) -> Self {
        self.created = Some(created);
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderModelPricingSource {
    Catalog,
    Manual,
}

impl ProviderModelPricingSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Catalog => "catalog",
            Self::Manual => "manual",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderModelPricing {
    pub input: Option<String>,
    pub output: Option<String>,
    pub cache_read: Option<String>,
    pub cache_write: Option<String>,
    pub reasoning: Option<String>,
    pub input_audio: Option<String>,
    pub output_audio: Option<String>,
    pub tiers: Vec<ProviderModelPricingTier>,
}

impl ProviderModelPricing {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.input.is_none()
            && self.output.is_none()
            && self.cache_read.is_none()
            && self.cache_write.is_none()
            && self.reasoning.is_none()
            && self.input_audio.is_none()
            && self.output_audio.is_none()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderModelPricingTier {
    pub threshold_tokens: u64,
    pub input: Option<String>,
    pub output: Option<String>,
    pub cache_read: Option<String>,
    pub cache_write: Option<String>,
    pub reasoning: Option<String>,
    pub input_audio: Option<String>,
    pub output_audio: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderModelPricingRecord {
    pub source: ProviderModelPricingSource,
    pub pricing: ProviderModelPricing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredProviderModel {
    pub upstream_model: String,
    pub metadata_json: String,
    pub routable: bool,
    pub pricing: Option<ProviderModelPricingRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredProviderModel {
    pub account_id: AccountId,
    pub upstream_model: String,
    pub alias: Option<String>,
    pub enabled: bool,
    pub available: bool,
    pub routable: bool,
    pub metadata_json: String,
    pub pricing: Option<ProviderModelPricingRecord>,
    pub last_seen_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl StoredProviderModel {
    #[must_use]
    pub fn effective_model(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.upstream_model)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderModelOverride {
    pub alias: Option<String>,
    pub enabled: bool,
    pub pricing: Option<Option<ProviderModelPricing>>,
    pub updated_at: i64,
}

pub trait ProviderModelPricingCatalog: Send + Sync {
    fn exact_pricing(&self, upstream_model: &str) -> Option<ProviderModelPricing>;
}
