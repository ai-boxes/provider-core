use std::sync::Arc;

use crate::{ProtocolBridge, Provider, ProviderError, ProviderModel, ProviderStream, ProxyRequest};

/// Application service that delegates proxy operations to the active provider.
#[derive(Clone)]
pub struct ProxyService {
    provider: Arc<dyn Provider>,
    protocol: Arc<dyn ProtocolBridge>,
}

impl ProxyService {
    #[must_use]
    pub fn new(provider: Arc<dyn Provider>, protocol: Arc<dyn ProtocolBridge>) -> Self {
        Self { provider, protocol }
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
        let prepared = self
            .protocol
            .prepare(request, self.provider.native_format())?;
        let (request, response) = prepared.into_parts();
        let stream = self.provider.execute_stream(request).await?;
        Ok(response.translate_stream(stream))
    }

    pub async fn count_tokens(&self, request: ProxyRequest) -> Result<u64, ProviderError> {
        let prepared = self
            .protocol
            .prepare(request, self.provider.native_format())?;
        let (request, _) = prepared.into_parts();
        self.provider.count_tokens(request).await
    }
}
