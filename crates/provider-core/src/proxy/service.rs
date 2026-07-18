use std::sync::Arc;

use crate::{Provider, ProviderError, ProviderModel, ProviderStream, ProxyRequest};

/// Application service that delegates proxy operations to the active provider.
#[derive(Clone)]
pub struct ProxyService {
    provider: Arc<dyn Provider>,
}

impl ProxyService {
    #[must_use]
    pub fn new(provider: Arc<dyn Provider>) -> Self {
        Self { provider }
    }

    #[must_use]
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    #[must_use]
    pub fn models(&self) -> &[ProviderModel] {
        self.provider.models()
    }

    pub async fn execute_stream(
        &self,
        request: ProxyRequest,
    ) -> Result<ProviderStream, ProviderError> {
        self.provider.execute_stream(request).await
    }

    pub async fn count_tokens(&self, request: ProxyRequest) -> Result<u64, ProviderError> {
        self.provider.count_tokens(request).await
    }
}
