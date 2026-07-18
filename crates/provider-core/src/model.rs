use serde::Serialize;

/// Model metadata exposed by a provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
