use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;

use crate::{
    AccountId, ProtocolBridge, Provider, ProviderAccountAccess, ProviderError, ProviderErrorKind,
    ProviderModel, ProviderModelPricingRecord, ProviderRequest, ProviderRoute,
    ProviderRouteCandidate, ProviderRouter, ProviderStream, ProxyRequest, ResponseTranslator,
    RoutableProviderModel, WireFormat, usage::ProviderUsageProfile,
};

/// Application service that delegates proxy operations to the active provider.
#[derive(Clone)]
pub struct ProxyService {
    router: Arc<dyn ProviderRouter>,
    protocol: Arc<dyn ProtocolBridge>,
}

impl ProxyService {
    #[must_use]
    pub fn new(
        provider: Arc<dyn Provider>,
        protocol: Arc<dyn ProtocolBridge>,
        access: ProviderAccountAccess,
    ) -> Self {
        Self::with_router(
            Arc::new(SingleProviderRouter::new(provider, access)),
            protocol,
        )
    }

    #[must_use]
    pub fn with_router(router: Arc<dyn ProviderRouter>, protocol: Arc<dyn ProtocolBridge>) -> Self {
        Self { router, protocol }
    }

    #[must_use]
    pub fn models(
        &self,
        user_id: &str,
        source_format: WireFormat,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Vec<ProviderModel> {
        self.router
            .models(user_id, account_ids)
            .into_iter()
            .filter(|model| {
                model
                    .native_formats
                    .iter()
                    .any(|target| self.protocol.supports(source_format, *target))
            })
            .map(|model| model.model)
            .collect()
    }

    pub async fn execute_stream(
        &self,
        user_id: &str,
        request: ProxyRequest,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Result<ProviderStream, ProviderError> {
        self.execute_tracked_stream(user_id, request, None, account_ids)
            .await
    }

    /// Execute a request, reporting usage facts through `tracking`.
    ///
    /// Tracking is passed straight down to the route: the attempt boundary is
    /// decided where upstream calls are actually made, not here.
    pub async fn execute_tracked_stream(
        &self,
        user_id: &str,
        request: ProxyRequest,
        tracking: Option<&Arc<dyn crate::usage::RequestTracking>>,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Result<ProviderStream, ProviderError> {
        self.prepare_stream(user_id, request, account_ids)?
            .execute_stream(tracking)
            .await
    }

    pub async fn count_tokens(
        &self,
        user_id: &str,
        request: ProxyRequest,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Result<u64, ProviderError> {
        let mut prepared = self.prepare_stream(user_id, request, account_ids)?;
        prepared.count_input_tokens().await
    }

    pub fn prepare_stream(
        &self,
        user_id: &str,
        request: ProxyRequest,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Result<PreparedProxyExecution, ProviderError> {
        let route = self.resolve_route(user_id, &request, account_ids)?;
        let mut request = request;
        request.model = route.upstream_model.clone();
        request.metadata.responses_lite = route.responses_lite;
        let prepared = self.protocol.prepare(
            request,
            route.route.native_format(),
            route.input_modalities.as_deref(),
        )?;
        let (request, response) = prepared.into_parts();
        Ok(PreparedProxyExecution {
            route,
            request,
            response,
        })
    }

    fn resolve_route(
        &self,
        user_id: &str,
        request: &ProxyRequest,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Result<ProviderRouteCandidate, ProviderError> {
        let native_formats = [
            WireFormat::OpenAiResponses,
            WireFormat::OpenAiChatCompletions,
            WireFormat::ClaudeMessages,
        ]
        .into_iter()
        .filter(|target| self.protocol.supports(request.format, *target))
        .collect::<Vec<_>>();
        self.router
            .routes(
                user_id,
                &request.model,
                &native_formats,
                request.metadata.session_id.as_deref(),
                account_ids,
            )
            .into_iter()
            .next()
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::InvalidRequest,
                    "no available provider supports the requested model and protocol",
                )
            })
    }
}

pub struct PreparedProxyExecution {
    route: ProviderRouteCandidate,
    request: ProviderRequest,
    response: Box<dyn ResponseTranslator>,
}

impl PreparedProxyExecution {
    #[must_use]
    pub fn pricing(&self) -> Option<&ProviderModelPricingRecord> {
        self.route.pricing.as_ref()
    }

    #[must_use]
    pub fn usage_profile(&self) -> Option<ProviderUsageProfile> {
        self.route.route.usage_profile()
    }

    #[must_use]
    pub fn maximum_attempts(&self) -> u32 {
        self.route.route.maximum_attempts()
    }

    pub async fn count_input_tokens(&mut self) -> Result<u64, ProviderError> {
        self.route.route.count_tokens(self.request.clone()).await
    }

    pub async fn execute_stream(
        self,
        tracking: Option<&Arc<dyn crate::usage::RequestTracking>>,
    ) -> Result<ProviderStream, ProviderError> {
        let stream = self
            .route
            .route
            .execute_stream(self.request, self.route.pricing.as_ref(), tracking)
            .await?;
        Ok(self.response.translate_stream(stream))
    }
}

struct SingleProviderRouter {
    provider: Arc<dyn Provider>,
    route: Arc<dyn ProviderRoute>,
    access: ProviderAccountAccess,
}

impl SingleProviderRouter {
    fn new(provider: Arc<dyn Provider>, access: ProviderAccountAccess) -> Self {
        let route: Arc<dyn ProviderRoute> = Arc::new(SingleProviderRoute {
            provider: provider.clone(),
        });
        Self {
            provider,
            route,
            access,
        }
    }
}

impl ProviderRouter for SingleProviderRouter {
    fn models(
        &self,
        user_id: &str,
        _account_ids: Option<&HashSet<AccountId>>,
    ) -> Vec<RoutableProviderModel> {
        if self.access.allows(user_id) {
            self.provider
                .models()
                .iter()
                .cloned()
                .map(|model| RoutableProviderModel {
                    model,
                    native_formats: vec![self.provider.native_format()],
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    fn routes(
        &self,
        user_id: &str,
        model: &str,
        native_formats: &[WireFormat],
        _session_id: Option<&str>,
        _account_ids: Option<&HashSet<AccountId>>,
    ) -> Vec<ProviderRouteCandidate> {
        if !self.access.allows(user_id) || !native_formats.contains(&self.provider.native_format())
        {
            return Vec::new();
        }
        vec![ProviderRouteCandidate {
            upstream_model: model.to_owned(),
            input_modalities: self
                .provider
                .models()
                .iter()
                .find(|candidate| candidate.id == model)
                .and_then(|candidate| candidate.input_modalities.clone()),
            responses_lite: false,
            pricing: None,
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
        _pricing: Option<&crate::ProviderModelPricingRecord>,
        // A bare `Provider` has no account or established usage contract, so
        // there is nothing to attribute an attempt to.
        _tracking: Option<&Arc<dyn crate::usage::RequestTracking>>,
    ) -> Result<ProviderStream, ProviderError> {
        self.provider.execute_stream(request).await
    }

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError> {
        self.provider.count_tokens(request).await
    }
}
