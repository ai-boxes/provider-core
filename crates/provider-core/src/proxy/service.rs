use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{StreamExt, stream};

use crate::{
    AccountId, ProtocolBridge, Provider, ProviderAccountAccess, ProviderError, ProviderErrorKind,
    ProviderModel, ProviderModelPricingRecord, ProviderRequest, ProviderRoute,
    ProviderRouteCandidate, ProviderRouter, ProviderStream, ProxyRequest, ResponseTranslator,
    RoutableProviderModel, WireFormat, usage::ProviderUsageProfile,
};

const MAX_ROUTE_CANDIDATES: usize = 3;

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
        mut request: ProxyRequest,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Result<PreparedProxyExecution, ProviderError> {
        request
            .metadata
            .routing_scope
            .get_or_insert_with(|| user_id.to_owned());
        let routes = self.resolve_routes(user_id, &request, account_ids)?;
        Ok(PreparedProxyExecution {
            router: self.router.clone(),
            protocol: self.protocol.clone(),
            request,
            routes,
        })
    }

    fn resolve_routes(
        &self,
        user_id: &str,
        request: &ProxyRequest,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Result<Vec<ProviderRouteCandidate>, ProviderError> {
        let native_formats = [
            WireFormat::OpenAiResponses,
            WireFormat::OpenAiChatCompletions,
            WireFormat::ClaudeMessages,
        ]
        .into_iter()
        .filter(|target| self.protocol.supports(request.format, *target))
        .collect::<Vec<_>>();
        let routing_scope = request.metadata.routing_scope.as_deref().unwrap_or(user_id);
        let routes = self
            .router
            .routes(
                user_id,
                routing_scope,
                &request.model,
                &native_formats,
                request.metadata.session_id.as_deref(),
                request.metadata.previous_response_id.as_deref(),
                account_ids,
            )
            .into_iter()
            .take(MAX_ROUTE_CANDIDATES)
            .collect::<Vec<_>>();
        if routes.is_empty() {
            Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "no available provider supports the requested model and protocol",
            ))
        } else {
            Ok(routes)
        }
    }
}

pub struct PreparedProxyExecution {
    router: Arc<dyn ProviderRouter>,
    protocol: Arc<dyn ProtocolBridge>,
    request: ProxyRequest,
    routes: Vec<ProviderRouteCandidate>,
}

impl PreparedProxyExecution {
    #[must_use]
    pub fn pricing(&self) -> Option<&ProviderModelPricingRecord> {
        self.routes.first().and_then(|route| route.pricing.as_ref())
    }

    #[must_use]
    pub fn usage_profile(&self) -> Option<ProviderUsageProfile> {
        self.routes
            .first()
            .and_then(|route| route.route.usage_profile())
    }

    #[must_use]
    pub fn maximum_attempts(&self) -> u32 {
        self.routes
            .iter()
            .map(|route| route.route.maximum_attempts())
            .sum()
    }

    pub async fn count_input_tokens(&mut self) -> Result<u64, ProviderError> {
        let (route, request, _) = self.prepare_candidate(0)?;
        route.route.count_tokens(request).await
    }

    pub async fn execute_stream(
        self,
        tracking: Option<&Arc<dyn crate::usage::RequestTracking>>,
    ) -> Result<ProviderStream, ProviderError> {
        let model = self.request.model.clone();
        let session_id = self.request.metadata.session_id.clone();
        let routing_scope = self
            .request
            .metadata
            .routing_scope
            .clone()
            .unwrap_or_default();
        let mut last_error = None;
        for index in 0..self.routes.len() {
            let (route, request, response) = self.prepare_candidate(index)?;
            match route
                .route
                .execute_stream(request, route.pricing.as_ref(), tracking)
                .await
            {
                Ok(stream) => {
                    if let Some(account_id) = route.account_id.as_ref() {
                        self.router.record_route_success(account_id, &model);
                        self.router.commit_session_affinity(
                            &routing_scope,
                            &model,
                            session_id.as_deref(),
                            account_id,
                        );
                    }
                    let stream = response.translate_stream(stream);
                    return Ok(match route.account_id.clone() {
                        Some(account_id) if route.route.supports_previous_response_id() => {
                            observe_response_id(
                                stream,
                                self.router.clone(),
                                routing_scope.clone(),
                                account_id,
                            )
                        }
                        _ => stream,
                    });
                }
                Err(error) => {
                    let Some(reason) = error.failover_reason() else {
                        return Err(error);
                    };
                    if self.request.metadata.previous_response_id.is_some() {
                        return Err(error);
                    }
                    if let Some(account_id) = route.account_id.as_ref() {
                        self.router.record_route_failure(account_id, &model, reason);
                    }
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.expect("a non-empty route plan must either succeed or fail"))
    }

    fn prepare_candidate(
        &self,
        index: usize,
    ) -> Result<
        (
            &ProviderRouteCandidate,
            ProviderRequest,
            Box<dyn ResponseTranslator>,
        ),
        ProviderError,
    > {
        let route = &self.routes[index];
        let mut request = self.request.clone();
        request.model = route.upstream_model.clone();
        request.metadata.responses_lite = route.responses_lite;
        let prepared = self.protocol.prepare(
            request,
            route.route.native_format(),
            route.input_modalities.as_deref(),
        )?;
        let (request, response) = prepared.into_parts();
        Ok((route, request, response))
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
        _routing_scope: &str,
        model: &str,
        native_formats: &[WireFormat],
        _session_id: Option<&str>,
        _previous_response_id: Option<&str>,
        _account_ids: Option<&HashSet<AccountId>>,
    ) -> Vec<ProviderRouteCandidate> {
        if !self.access.allows(user_id) || !native_formats.contains(&self.provider.native_format())
        {
            return Vec::new();
        }
        vec![ProviderRouteCandidate {
            account_id: None,
            priority: 0,
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

fn observe_response_id(
    inner: ProviderStream,
    router: Arc<dyn ProviderRouter>,
    routing_scope: String,
    account_id: AccountId,
) -> ProviderStream {
    struct State {
        inner: ProviderStream,
        router: Arc<dyn ProviderRouter>,
        routing_scope: String,
        account_id: AccountId,
        pending: BytesMut,
        bound: bool,
    }

    Box::pin(stream::unfold(
        State {
            inner,
            router,
            routing_scope,
            account_id,
            pending: BytesMut::new(),
            bound: false,
        },
        |mut state| async move {
            let item = state.inner.next().await?;
            if let Ok(chunk) = &item
                && !state.bound
            {
                state.pending.extend_from_slice(chunk);
                if let Some(response_id) = take_response_id(&mut state.pending) {
                    state.router.bind_response_id(
                        &state.routing_scope,
                        &response_id,
                        &state.account_id,
                    );
                    state.bound = true;
                    state.pending.clear();
                } else if state.pending.len() > 64 * 1024 {
                    state.bound = true;
                    state.pending.clear();
                }
            }
            Some((item, state))
        },
    ))
}

fn take_response_id(pending: &mut BytesMut) -> Option<String> {
    for frame in pending.as_ref().split(|byte| *byte == b'\n') {
        let data = frame
            .strip_prefix(b"data: ")
            .or_else(|| frame.strip_prefix(b"data:"));
        let Some(data) = data else { continue };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
            continue;
        };
        if value.get("type").and_then(serde_json::Value::as_str) != Some("response.created") {
            continue;
        }
        if let Some(id) = value
            .get("response")
            .and_then(|response| response.get("id"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
        {
            return Some(id.to_owned());
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use futures_util::{StreamExt, stream};

    use super::*;
    use crate::{PreparedProviderRequest, RequestMetadata};

    #[derive(Clone, Copy)]
    enum RouteResult {
        HeaderError(Option<crate::ProviderFailoverReason>),
        StreamError,
        Success,
    }

    struct TestRoute {
        calls: Arc<Mutex<Vec<String>>>,
        account: String,
        result: RouteResult,
    }

    #[async_trait]
    impl ProviderRoute for TestRoute {
        fn provider_name(&self) -> &'static str {
            "test"
        }

        fn native_format(&self) -> WireFormat {
            WireFormat::OpenAiResponses
        }

        async fn execute_stream(
            &self,
            _request: ProviderRequest,
            _pricing: Option<&ProviderModelPricingRecord>,
            _tracking: Option<&Arc<dyn crate::usage::RequestTracking>>,
        ) -> Result<ProviderStream, ProviderError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(self.account.clone());
            match self.result {
                RouteResult::HeaderError(reason) => {
                    let error = ProviderError::new(ProviderErrorKind::Upstream, "failed")
                        .with_upstream_status(500);
                    Err(match reason {
                        Some(reason) => error.with_failover_reason(reason),
                        None => error,
                    })
                }
                RouteResult::StreamError => Ok(Box::pin(stream::once(async {
                    Err(
                        ProviderError::new(ProviderErrorKind::Upstream, "stream failed")
                            .with_failover_reason(crate::ProviderFailoverReason::RateLimited),
                    )
                }))),
                RouteResult::Success => Ok(Box::pin(stream::once(async {
                    Ok(Bytes::from_static(b"ok"))
                }))),
            }
        }

        async fn count_tokens(&self, _request: ProviderRequest) -> Result<u64, ProviderError> {
            Ok(0)
        }
    }

    struct TestRouter {
        routes: Vec<ProviderRouteCandidate>,
        committed: Arc<Mutex<Vec<String>>>,
    }

    impl ProviderRouter for TestRouter {
        fn models(
            &self,
            _user_id: &str,
            _account_ids: Option<&HashSet<AccountId>>,
        ) -> Vec<RoutableProviderModel> {
            Vec::new()
        }

        fn routes(
            &self,
            _user_id: &str,
            _routing_scope: &str,
            _model: &str,
            _native_formats: &[WireFormat],
            _session_id: Option<&str>,
            _previous_response_id: Option<&str>,
            _account_ids: Option<&HashSet<AccountId>>,
        ) -> Vec<ProviderRouteCandidate> {
            self.routes.clone()
        }

        fn commit_session_affinity(
            &self,
            _routing_scope: &str,
            _model: &str,
            _session_id: Option<&str>,
            account_id: &AccountId,
        ) {
            self.committed
                .lock()
                .expect("commit lock")
                .push(account_id.to_string());
        }
    }

    struct TestProtocol {
        prepares: Arc<Mutex<u32>>,
    }

    impl ProtocolBridge for TestProtocol {
        fn supports(&self, _source: WireFormat, _target: WireFormat) -> bool {
            true
        }

        fn prepare(
            &self,
            request: ProxyRequest,
            target: WireFormat,
            _input_modalities: Option<&[crate::ProviderModelInputModality]>,
        ) -> Result<PreparedProviderRequest, ProviderError> {
            *self.prepares.lock().expect("prepare lock") += 1;
            Ok(PreparedProviderRequest::new(
                ProviderRequest::from_proxy(request, target),
                Box::new(IdentityTranslator),
            ))
        }
    }

    struct IdentityTranslator;

    impl ResponseTranslator for IdentityTranslator {
        fn translate_stream(self: Box<Self>, stream: ProviderStream) -> ProviderStream {
            stream
        }
    }

    fn candidate(
        account: &str,
        result: RouteResult,
        calls: &Arc<Mutex<Vec<String>>>,
    ) -> ProviderRouteCandidate {
        ProviderRouteCandidate {
            account_id: Some(AccountId::new(account).expect("account ID")),
            priority: 0,
            upstream_model: account.to_owned(),
            input_modalities: None,
            responses_lite: false,
            pricing: None,
            route: Arc::new(TestRoute {
                calls: calls.clone(),
                account: account.to_owned(),
                result,
            }),
        }
    }

    fn request() -> ProxyRequest {
        ProxyRequest::new(
            WireFormat::OpenAiResponses,
            "shared",
            Bytes::from_static(br#"{"model":"shared"}"#),
        )
        .expect("request")
        .with_metadata(RequestMetadata {
            session_id: Some("session".to_owned()),
            ..RequestMetadata::default()
        })
    }

    fn service(
        results: &[(&str, RouteResult)],
    ) -> (
        ProxyService,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<u32>>,
        Arc<Mutex<Vec<String>>>,
    ) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let prepares = Arc::new(Mutex::new(0));
        let committed = Arc::new(Mutex::new(Vec::new()));
        let routes = results
            .iter()
            .map(|(account, result)| candidate(account, *result, &calls))
            .collect();
        (
            ProxyService::with_router(
                Arc::new(TestRouter {
                    routes,
                    committed: committed.clone(),
                }),
                Arc::new(TestProtocol {
                    prepares: prepares.clone(),
                }),
            ),
            calls,
            prepares,
            committed,
        )
    }

    #[tokio::test]
    async fn explicit_failover_prepares_each_candidate_and_commits_the_success() {
        let (service, calls, prepares, committed) = service(&[
            (
                "account-a",
                RouteResult::HeaderError(Some(crate::ProviderFailoverReason::RateLimited)),
            ),
            ("account-b", RouteResult::Success),
        ]);
        let mut stream = service
            .execute_stream("owner", request(), None)
            .await
            .expect("fallback stream");
        assert_eq!(stream.next().await.expect("item").expect("chunk"), "ok");
        assert_eq!(*calls.lock().expect("calls"), ["account-a", "account-b"]);
        assert_eq!(*prepares.lock().expect("prepares"), 2);
        assert_eq!(*committed.lock().expect("committed"), ["account-b"]);
    }

    #[tokio::test]
    async fn unknown_header_error_never_replays_another_provider() {
        let (service, calls, _, _) = service(&[
            ("account-a", RouteResult::HeaderError(None)),
            ("account-b", RouteResult::Success),
        ]);
        assert!(
            service
                .execute_stream("owner", request(), None)
                .await
                .is_err()
        );
        assert_eq!(*calls.lock().expect("calls"), ["account-a"]);
    }

    #[tokio::test]
    async fn stream_error_never_reenters_failover() {
        let (service, calls, _, _) = service(&[
            ("account-a", RouteResult::StreamError),
            ("account-b", RouteResult::Success),
        ]);
        let mut stream = service
            .execute_stream("owner", request(), None)
            .await
            .expect("opened stream");
        assert!(stream.next().await.expect("item").is_err());
        assert_eq!(*calls.lock().expect("calls"), ["account-a"]);
    }

    #[tokio::test]
    async fn route_plan_is_capped_at_three_candidates() {
        let failure =
            RouteResult::HeaderError(Some(crate::ProviderFailoverReason::PreconnectFailure));
        let (service, calls, _, _) = service(&[
            ("account-a", failure),
            ("account-b", failure),
            ("account-c", failure),
            ("account-d", RouteResult::Success),
        ]);
        assert!(
            service
                .execute_stream("owner", request(), None)
                .await
                .is_err()
        );
        assert_eq!(
            *calls.lock().expect("calls"),
            ["account-a", "account-b", "account-c"]
        );
    }

    #[test]
    fn response_created_id_is_parsed_across_chunks() {
        let mut pending = BytesMut::from(&b"data: {\"type\":\"response.cre"[..]);
        assert_eq!(take_response_id(&mut pending), None);
        pending.extend_from_slice(b"ated\",\"response\":{\"id\":\"resp-1\"}}\n\n");
        assert_eq!(take_response_id(&mut pending).as_deref(), Some("resp-1"));
    }
}
