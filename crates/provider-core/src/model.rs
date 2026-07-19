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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredProviderModel {
    pub upstream_model: String,
    pub metadata_json: String,
    pub routable: bool,
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
    pub updated_at: i64,
}
