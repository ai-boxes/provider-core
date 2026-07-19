use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    ProtocolBridge, Provider, ProviderError, ProviderErrorKind, ProviderModel, ProviderRequest,
    ProviderRoute, ProviderRouteCandidate, ProviderRouter, ProviderStream, ProxyRequest,
    WireFormat,
};

/// Application service that delegates proxy operations to the active provider.
#[derive(Clone)]
pub struct ProxyService {
    router: Arc<dyn ProviderRouter>,
    protocol: Arc<dyn ProtocolBridge>,
}

impl ProxyService {
    #[must_use]
    pub fn new(provider: Arc<dyn Provider>, protocol: Arc<dyn ProtocolBridge>) -> Self {
        Self::with_router(Arc::new(SingleProviderRouter::new(provider)), protocol)
    }

    #[must_use]
    pub fn with_router(router: Arc<dyn ProviderRouter>, protocol: Arc<dyn ProtocolBridge>) -> Self {
        Self { router, protocol }
    }

    #[must_use]
    pub fn models(&self) -> Vec<ProviderModel> {
        self.router.models()
    }

    pub async fn execute_stream(
        &self,
        request: ProxyRequest,
    ) -> Result<ProviderStream, ProviderError> {
        let route = self.resolve_route(&request)?;
        let mut request = request;
        request.model = route.upstream_model;
        let prepared = self
            .protocol
            .prepare(request, route.route.native_format())?;
        let (request, response) = prepared.into_parts();
        let stream = route.route.execute_stream(request).await?;
        Ok(response.translate_stream(stream))
    }

    pub async fn count_tokens(&self, request: ProxyRequest) -> Result<u64, ProviderError> {
        let route = self.resolve_route(&request)?;
        let mut request = request;
        request.model = route.upstream_model;
        let prepared = self
            .protocol
            .prepare(request, route.route.native_format())?;
        let (request, _) = prepared.into_parts();
        route.route.count_tokens(request).await
    }

    fn resolve_route(
        &self,
        request: &ProxyRequest,
    ) -> Result<ProviderRouteCandidate, ProviderError> {
        self.router
            .routes(&request.model)
            .into_iter()
            .find(|candidate| {
                self.protocol
                    .supports(request.format, candidate.route.native_format())
            })
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::InvalidRequest,
                    "no available provider supports the requested model and protocol",
                )
            })
    }
}

struct SingleProviderRouter {
    provider: Arc<dyn Provider>,
    route: Arc<dyn ProviderRoute>,
}

impl SingleProviderRouter {
    fn new(provider: Arc<dyn Provider>) -> Self {
        let route: Arc<dyn ProviderRoute> = Arc::new(SingleProviderRoute {
            provider: provider.clone(),
        });
        Self { provider, route }
    }
}

impl ProviderRouter for SingleProviderRouter {
    fn models(&self) -> Vec<ProviderModel> {
        self.provider.models().to_vec()
    }

    fn routes(&self, model: &str) -> Vec<ProviderRouteCandidate> {
        vec![ProviderRouteCandidate {
            upstream_model: model.to_owned(),
            route: self.route.clone(),
        }]
    }
}

struct SingleProviderRoute {
    provider: Arc<dyn Provider>,
}

#[async_trait]
impl ProviderRoute for SingleProviderRoute {
    fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    fn native_format(&self) -> WireFormat {
        self.provider.native_format()
    }

    async fn execute_stream(
        &self,
        request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError> {
        self.provider.execute_stream(request).await
    }

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError> {
        self.provider.count_tokens(request).await
    }
}
