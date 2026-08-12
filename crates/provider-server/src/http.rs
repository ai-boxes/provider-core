use std::collections::HashSet;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{StreamExt, stream};
use provider_auth::{ApiKeyAuthenticator, AuthError, AuthService, AuthenticatedApiKey};
#[cfg(test)]
use provider_auth::{ApiKeyPatch, CreateApiKeyInput};
use provider_core::{
    AccountId, ProviderError, ProviderErrorKind, ProviderStream, ProxyRequest, ProxyRequestError,
    ProxyService, RequestMetadata, WireFormat,
};
use provider_management::ProviderManager;
use provider_usage::{
    DeliveryOutcome, ExecutionOutcome, LogicalRequestStart, LogicalTracker, UsageTracking,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::{ServiceExt, service_fn, util::BoxCloneSyncService};
use tower_http::services::{ServeDir, ServeFile};

const CLAUDE_MODEL_PREFIX: &str = "claude-fable-5-dd-";
const CLAUDE_CODE_SESSION_HEADER: &str = "x-claude-code-session-id";
const PUBLIC_DIR: &str = "/app/public";
pub(crate) const MAX_PROXY_BODY_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_MANAGEMENT_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct AppState {
    service: ProxyService,
    api_keys: ApiKeyAuthenticator,
    /// `None` disables usage tracking entirely, which is how every path stays
    /// working when there is no database to record into.
    usage: Option<Arc<UsageTracking>>,
    proxy_readiness: ProxyReadiness,
}

#[derive(Clone)]
pub struct ProxyReadiness(Arc<AtomicBool>);

pub(crate) struct ManagementRouterConfig {
    pub(crate) usage: Option<crate::usage_http::UsageServices>,
    pub(crate) trusted_proxy_ip: Option<std::net::IpAddr>,
    pub(crate) proxy_readiness: ProxyReadiness,
}

impl ProxyReadiness {
    pub fn new(ready: bool) -> Self {
        Self(Arc::new(AtomicBool::new(ready)))
    }

    pub(crate) fn signal(&self) -> Arc<AtomicBool> {
        self.0.clone()
    }

    fn get(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub fn router(service: ProxyService, api_keys: ApiKeyAuthenticator) -> Router {
    router_with_usage(service, api_keys, None)
}

pub fn router_with_usage(
    service: ProxyService,
    api_keys: ApiKeyAuthenticator,
    usage: Option<Arc<UsageTracking>>,
) -> Router {
    router_with_usage_and_readiness(service, api_keys, usage, ProxyReadiness::new(true))
}

fn router_with_usage_and_readiness(
    service: ProxyService,
    api_keys: ApiKeyAuthenticator,
    usage: Option<Arc<UsageTracking>>,
    proxy_readiness: ProxyReadiness,
) -> Router {
    Router::new()
        .route("/healthz", get(liveness))
        .route("/livez", get(liveness))
        .route("/readyz", get(readiness))
        .route("/v1/models", get(models))
        .route("/v1/responses", post(responses))
        .route("/v1/messages", post(messages))
        .route("/v1/messages/count_tokens", post(count_tokens))
        .layer(DefaultBodyLimit::max(MAX_PROXY_BODY_BYTES))
        .layer(middleware::from_fn(reject_compressed_request))
        .with_state(AppState {
            service,
            api_keys,
            usage,
            proxy_readiness,
        })
        .fallback_service(ui_service(PUBLIC_DIR))
}

pub fn router_with_management(
    service: ProxyService,
    manager: ProviderManager,
    auth: AuthService,
    api_keys: ApiKeyAuthenticator,
) -> Router {
    router_with_management_and_usage(service, manager, auth, api_keys, None, None)
}

pub fn router_with_management_and_usage(
    service: ProxyService,
    manager: ProviderManager,
    auth: AuthService,
    api_keys: ApiKeyAuthenticator,
    usage: Option<crate::usage_http::UsageServices>,
    trusted_proxy_ip: Option<std::net::IpAddr>,
) -> Router {
    router_with_management_usage_and_readiness(
        service,
        manager,
        auth,
        api_keys,
        ManagementRouterConfig {
            usage,
            trusted_proxy_ip,
            proxy_readiness: ProxyReadiness::new(true),
        },
    )
}

pub(crate) fn router_with_management_usage_and_readiness(
    service: ProxyService,
    manager: ProviderManager,
    auth: AuthService,
    api_keys: ApiKeyAuthenticator,
    config: ManagementRouterConfig,
) -> Router {
    let ManagementRouterConfig {
        usage,
        trusted_proxy_ip,
        proxy_readiness,
    } = config;
    let auth_state = crate::auth_http::AuthHttpState::new(
        auth.clone(),
        api_keys.clone(),
        manager.clone(),
        trusted_proxy_ip,
    );
    let mut management = crate::management_http::router(manager, usage.clone());
    if let Some(usage) = &usage {
        // Behind the same session guard as the rest of management: usage is read
        // by a logged-in person, never with a proxy API key.
        management = management.merge(crate::usage_http::router(usage.clone()));
    }
    let management = crate::auth_http::protect(management, auth)
        .layer(DefaultBodyLimit::max(MAX_MANAGEMENT_BODY_BYTES))
        .layer(middleware::from_fn(reject_compressed_request));
    router_with_usage_and_readiness(
        service,
        api_keys,
        usage.map(|usage| usage.tracking),
        proxy_readiness,
    )
    .merge(crate::auth_http::router(auth_state))
    .merge(management)
}

pub(crate) async fn reject_compressed_request(request: Request, next: Next) -> Response {
    let compressed = request
        .headers()
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|value| {
            value.to_str().map_or(true, |value| {
                value
                    .split(',')
                    .map(str::trim)
                    .any(|encoding| !encoding.eq_ignore_ascii_case("identity"))
            })
        });
    if compressed {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(json!({
                "error": {
                    "type": "invalid_request_error",
                    "message": "compressed request bodies are not supported"
                }
            })),
        )
            .into_response();
    }
    next.run(request).await
}

async fn liveness() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Serve compiled UI assets and fall back to `index.html` for browser routes.
fn ui_service(
    public_dir: impl AsRef<Path>,
) -> BoxCloneSyncService<Request<Body>, Response, Infallible> {
    let public_dir = public_dir.as_ref();
    let files = ServeDir::new(public_dir);
    let index = public_dir.join("index.html");
    BoxCloneSyncService::new(service_fn(move |request| {
        serve_ui(request, files.clone(), index.clone())
    }))
}

async fn serve_ui(
    request: Request<Body>,
    files: ServeDir,
    index: PathBuf,
) -> Result<Response, Infallible> {
    if !matches!(*request.method(), Method::GET | Method::HEAD)
        || is_backend_path(request.uri().path())
    {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    let accepts_html = accepts_html(request.headers());
    let method = request.method().clone();
    let response = into_axum_response(files.oneshot(request).await);
    if response.status() != StatusCode::NOT_FOUND || !accepts_html {
        return Ok(response);
    }

    let request = Request::builder()
        .method(method)
        .uri("/")
        .body(Body::empty())
        .expect("static fallback request is valid");
    Ok(into_axum_response(
        ServeFile::new(index).oneshot(request).await,
    ))
}

fn into_axum_response<T>(response: Result<T, Infallible>) -> Response
where
    T: IntoResponse,
{
    response
        .map(IntoResponse::into_response)
        .unwrap_or_else(|never| match never {})
}

fn is_backend_path(path: &str) -> bool {
    ["/api", "/v1", "/healthz", "/livez", "/readyz"]
        .iter()
        .any(|prefix| {
            path == *prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
}

fn accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .filter_map(|media_type| media_type.split(';').next())
                .any(|media_type| media_type.trim().eq_ignore_ascii_case("text/html"))
        })
}

async fn readiness(State(state): State<AppState>) -> Response {
    let database_ready = state.api_keys.quota_ledger_ready().await.is_ok();
    let writer_ready = state
        .usage
        .as_ref()
        .is_none_or(|usage| usage.quota_ledger_ready());
    let providers_ready = state.proxy_readiness.get();
    let ready = database_ready && writer_ready && providers_ready;
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({
            "status": if ready { "ready" } else { "not_ready" },
            "database": database_ready,
            "quota_ledger": writer_ready,
            "providers": providers_ready
        })),
    )
        .into_response()
}

async fn models(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, HttpError> {
    let protocol = models_protocol(&headers);
    ensure_proxy_ready(&state, protocol)?;
    let key = authenticate_api_key(&state.api_keys, &headers, protocol)?;
    let account_ids = load_key_account_filter(&state.api_keys, &key, protocol).await?;
    let models = state
        .service
        .models(key.owner_user_id.as_str(), protocol, Some(&account_ids));
    Ok(Json(match protocol {
        WireFormat::ClaudeMessages => claude_models_response(models),
        WireFormat::OpenAiResponses | WireFormat::OpenAiChatCompletions => json!({
            "object": "list",
            "data": models
        }),
    }))
}

fn models_protocol(headers: &HeaderMap) -> WireFormat {
    if headers
        .get("anthropic-version")
        .is_some_and(|value| !value.is_empty())
        || headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("claude-cli"))
    {
        WireFormat::ClaudeMessages
    } else {
        WireFormat::OpenAiResponses
    }
}

fn claude_models_response(models: Vec<provider_core::ProviderModel>) -> Value {
    let data = models
        .into_iter()
        .map(|model| {
            let id = ensure_claude_model_id(&model.id);
            let mut value = json!({
                "id": id,
                "type": "model",
                "display_name": model.id,
            });
            if let Some(created_at) = model.created.and_then(format_timestamp) {
                value["created_at"] = Value::String(created_at);
            }
            value
        })
        .collect::<Vec<_>>();
    let first_id = data
        .first()
        .and_then(|model| model.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let last_id = data
        .last()
        .and_then(|model| model.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    json!({
        "data": data,
        "has_more": false,
        "first_id": first_id,
        "last_id": last_id,
    })
}

fn format_timestamp(timestamp: u64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(i64::try_from(timestamp).ok()?)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn ensure_claude_model_id(id: &str) -> String {
    if id.starts_with("claude-") {
        id.to_owned()
    } else {
        format!(
            "{CLAUDE_MODEL_PREFIX}{}",
            id.chars().rev().collect::<String>()
        )
    }
}

fn resolve_claude_model_id(id: &str) -> String {
    id.strip_prefix(CLAUDE_MODEL_PREFIX)
        .map_or_else(|| id.to_owned(), |encoded| encoded.chars().rev().collect())
}

async fn responses(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, HttpError> {
    ensure_proxy_ready(&state, WireFormat::OpenAiResponses)?;
    let key = authenticate_api_key(&state.api_keys, &headers, WireFormat::OpenAiResponses)?;
    let (payload, logical) =
        parse_tracked_payload(&state, &key, WireFormat::OpenAiResponses, &body).await?;
    let request = match proxy_request_for_key_from_payload(
        WireFormat::OpenAiResponses,
        &headers,
        body,
        payload,
        &key,
    ) {
        Ok(request) => request,
        Err(error) => {
            finish_before_bytes(logical.as_ref(), ExecutionOutcome::StableFailure).await;
            return Err(error);
        }
    };
    proxy_prepared_stream(&state, &key, request, logical).await
}

async fn messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, HttpError> {
    ensure_proxy_ready(&state, WireFormat::ClaudeMessages)?;
    let key = authenticate_api_key(&state.api_keys, &headers, WireFormat::ClaudeMessages)?;
    let (payload, logical) =
        parse_tracked_payload(&state, &key, WireFormat::ClaudeMessages, &body).await?;
    let request = match proxy_request_for_key_from_payload(
        WireFormat::ClaudeMessages,
        &headers,
        body,
        payload,
        &key,
    ) {
        Ok(request) => request,
        Err(error) => {
            finish_before_bytes(logical.as_ref(), ExecutionOutcome::StableFailure).await;
            return Err(error);
        }
    };
    proxy_prepared_stream(&state, &key, request, logical).await
}

async fn count_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, HttpError> {
    ensure_proxy_ready(&state, WireFormat::ClaudeMessages)?;
    let key = authenticate_api_key(&state.api_keys, &headers, WireFormat::ClaudeMessages)?;
    let request = proxy_request_for_key(WireFormat::ClaudeMessages, &headers, body, &key)?;
    let account_ids =
        load_key_account_filter(&state.api_keys, &key, WireFormat::ClaudeMessages).await?;
    let count = state
        .service
        .count_tokens(key.owner_user_id.as_str(), request, Some(&account_ids))
        .await
        .map_err(|error| HttpError::from_provider(WireFormat::ClaudeMessages, error))?;

    Ok(Json(json!({ "input_tokens": count })))
}

fn ensure_proxy_ready(state: &AppState, protocol: WireFormat) -> Result<(), HttpError> {
    if state.proxy_readiness.get() {
        Ok(())
    } else {
        Err(HttpError::new(
            protocol,
            StatusCode::SERVICE_UNAVAILABLE,
            "api_error",
            "provider runtime recovery is incomplete",
        ))
    }
}

async fn proxy_prepared_stream(
    state: &AppState,
    key: &AuthenticatedApiKey,
    request: ProxyRequest,
    logical: Option<Arc<LogicalTracker>>,
) -> Result<Response, HttpError> {
    let protocol = request.format;
    if key.quota_limit_atoms.is_some() {
        // Finite keys charge from observed usage. Without tracking there is no
        // durable spend path, so admission must fail closed.
        if logical.is_none() || state.usage.is_none() {
            return Err(HttpError::service_unavailable(
                protocol,
                "quota accounting is unavailable",
            ));
        }
        match state.api_keys.admit_quota(key).await {
            Ok(()) => {}
            Err(AuthError::QuotaExceeded) => {
                finish_before_bytes(logical.as_ref(), ExecutionOutcome::StableFailure).await;
                return Err(HttpError::rate_limited(
                    protocol,
                    "API key USD quota has been exhausted",
                ));
            }
            Err(_) => {
                finish_before_bytes(logical.as_ref(), ExecutionOutcome::StableFailure).await;
                return Err(HttpError::service_unavailable(
                    protocol,
                    "quota accounting is unavailable",
                ));
            }
        }
    }
    let account_ids = match load_key_account_filter(&state.api_keys, key, protocol).await {
        Ok(account_ids) => account_ids,
        Err(error) => {
            finish_before_bytes(logical.as_ref(), ExecutionOutcome::StableFailure).await;
            return Err(error);
        }
    };
    let prepared =
        match state
            .service
            .prepare_stream(key.owner_user_id.as_str(), request, Some(&account_ids))
        {
            Ok(prepared) => prepared,
            Err(error) => {
                finish_before_bytes(logical.as_ref(), ExecutionOutcome::StableFailure).await;
                return Err(HttpError::from_provider(protocol, error));
            }
        };

    let tracking = logical.as_ref().map(LogicalTracker::request_tracking);

    if key.quota_limit_atoms.is_some() {
        let tracker = logical
            .as_ref()
            .expect("finite quota requests require a logical tracker");
        if tracker.mark_quota_dispatched().await.is_err() {
            finish_before_bytes(logical.as_ref(), ExecutionOutcome::StableFailure).await;
            return Err(HttpError::service_unavailable(
                protocol,
                "quota accounting is unavailable",
            ));
        }
    }

    let stream = match prepared.execute_stream(tracking.as_ref()).await {
        Ok(stream) => stream,
        Err(error) => {
            finish_before_bytes(logical.as_ref(), ExecutionOutcome::StableFailure).await;
            return Err(HttpError::from_provider(protocol, error));
        }
    };

    let body = Body::from_stream(observe_delivery(stream, logical));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(body)
        .map_err(|_| HttpError::internal(protocol))
}

/// Parse the JSON envelope after authentication and create the logical request
/// regardless of whether parsing succeeded. Authentication is the tracking
/// boundary: a malformed request from a known key is still one user request.
async fn parse_tracked_payload(
    state: &AppState,
    key: &AuthenticatedApiKey,
    protocol: WireFormat,
    body: &Bytes,
) -> Result<(Value, Option<Arc<LogicalTracker>>), HttpError> {
    match parse_payload(protocol, body) {
        Ok(payload) => {
            let client_model_raw = payload
                .as_object()
                .and_then(|payload| payload.get("model"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let routing_model = client_model_raw.as_deref().map(|model| {
                if protocol == WireFormat::ClaudeMessages {
                    resolve_claude_model_id(model)
                } else {
                    model.to_owned()
                }
            });
            let reasoning_effort = request_reasoning_effort(&payload);
            let logical = begin_tracking(
                state,
                key,
                protocol,
                client_model_raw,
                routing_model,
                reasoning_effort,
            )
            .await?;
            Ok((payload, logical))
        }
        Err(error) => {
            let logical = begin_tracking(state, key, protocol, None, None, None).await?;
            finish_before_bytes(logical.as_ref(), ExecutionOutcome::StableFailure).await;
            Err(error)
        }
    }
}

async fn finish_before_bytes(logical: Option<&Arc<LogicalTracker>>, execution: ExecutionOutcome) {
    if let Some(logical) = logical {
        logical.record_execution(execution);
        logical.record_delivery(DeliveryOutcome::ErrorBeforeBytes);
        if let Some(receipt) = logical.finish() {
            let _ = receipt.persisted().await;
        }
    }
}

/// Record the start of a logical request, if usage is being tracked.
///
/// Ordinary usage statistics remain fail-open. Finite-quota requests instead
/// create their durable accounting claim here and fail closed before dispatch
/// when accounting is unavailable.
async fn begin_tracking(
    state: &AppState,
    key: &AuthenticatedApiKey,
    protocol: WireFormat,
    client_model_raw: Option<String>,
    routing_model: Option<String>,
    reasoning_effort: Option<String>,
) -> Result<Option<Arc<LogicalTracker>>, HttpError> {
    let Some(usage) = state.usage.as_ref() else {
        if key.quota_limit_atoms.is_some() {
            return Err(HttpError::service_unavailable(
                protocol,
                "quota accounting is unavailable",
            ));
        }
        return Ok(None);
    };
    let start = LogicalRequestStart {
        request_id: uuid::Uuid::new_v4().to_string(),
        owner_user_id: key.owner_user_id.to_string(),
        api_key_id: Some(key.key_id.to_string()),
        api_key_label: Some(key.label.clone()),
        api_key_group_label: Some(key.group_label.clone()),
        client_model_raw,
        routing_model,
        reasoning_effort,
        started_at_ms: provider_usage::system_clock_ms(),
    };
    if key.quota_limit_atoms.is_some() {
        return usage
            .begin_quota_request(start)
            .await
            .map(Some)
            .map_err(|_| {
                HttpError::service_unavailable(protocol, "quota accounting is unavailable")
            });
    }
    Ok(Some(usage.begin_request(start).await))
}

/// Capture the client-declared reasoning level without interpreting provider
/// output tokens as a request setting. Responses uses `reasoning.effort`, while
/// Chat Completions clients commonly use the flat `reasoning_effort` spelling.
fn request_reasoning_effort(payload: &Value) -> Option<String> {
    let value = payload
        .get("reasoning")
        .and_then(Value::as_object)
        .and_then(|reasoning| reasoning.get("effort"))
        .or_else(|| payload.get("reasoning_effort"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 32)?;
    Some(value.to_owned())
}

/// Wrap the response body so the logical request learns how delivery ended.
///
/// This is the only place that can tell a clean end from a client that hung up,
/// because both happen after the handler has already returned the response.
fn observe_delivery(
    stream: ProviderStream,
    logical: Option<Arc<LogicalTracker>>,
) -> ProviderStream {
    struct Delivery {
        inner: Option<ProviderStream>,
        logical: Option<Arc<LogicalTracker>>,
        sent_bytes: bool,
    }

    impl Drop for Delivery {
        fn drop(&mut self) {
            // Closing the inner observer first lets it commit the attempt and
            // final_attempt_id before the logical terminal snapshots them.
            drop(self.inner.take());
            if let Some(logical) = self.logical.as_ref() {
                logical.record_delivery(DeliveryOutcome::ClientDrop);
                logical.finish();
            }
        }
    }

    Box::pin(stream::unfold(
        Delivery {
            inner: Some(stream),
            logical,
            sent_bytes: false,
        },
        |mut state| async move {
            let item = match state.inner.as_mut() {
                Some(inner) => inner.next().await,
                None => return None,
            };
            match item {
                Some(Ok(chunk)) => {
                    state.sent_bytes = true;
                    Some((Ok(chunk), state))
                }
                Some(Err(error)) => {
                    // The body error is terminal to the downstream. Drop the
                    // usage observer now so the attempt closes before logical.
                    drop(state.inner.take());
                    let receipt = if let Some(logical) = state.logical.as_ref() {
                        logical.record_execution(ExecutionOutcome::TranslatorOrStreamError);
                        logical.record_delivery(if state.sent_bytes {
                            DeliveryOutcome::ErrorAfterBytes
                        } else {
                            DeliveryOutcome::ErrorBeforeBytes
                        });
                        logical.finish()
                    } else {
                        None
                    };
                    if let Some(receipt) = receipt {
                        let _ = receipt.persisted().await;
                    }
                    Some((Err(error), state))
                }
                None => {
                    drop(state.inner.take());
                    let receipt = if let Some(logical) = state.logical.as_ref() {
                        logical.record_delivery(DeliveryOutcome::CleanEof);
                        logical.finish()
                    } else {
                        None
                    };
                    if let Some(receipt) = receipt
                        && !receipt.persisted().await
                    {
                        return Some((
                            Err(ProviderError::new(
                                ProviderErrorKind::Internal,
                                "quota ledger stopped before persisting request",
                            )),
                            state,
                        ));
                    }
                    None
                }
            }
        },
    ))
}

#[cfg(test)]
fn proxy_request(
    protocol: WireFormat,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<ProxyRequest, HttpError> {
    let payload = parse_payload(protocol, &body)?;
    proxy_request_from_payload(protocol, headers, body, payload)
}

fn parse_payload(protocol: WireFormat, body: &[u8]) -> Result<Value, HttpError> {
    serde_json::from_slice(body)
        .map_err(|_| HttpError::invalid_request(protocol, "request body must be valid JSON"))
}

fn proxy_request_from_payload(
    protocol: WireFormat,
    headers: &HeaderMap,
    body: Bytes,
    mut payload: Value,
) -> Result<ProxyRequest, HttpError> {
    let model = payload
        .as_object()
        .and_then(|payload| payload.get("model"))
        .and_then(Value::as_str)
        .ok_or_else(|| HttpError::invalid_request(protocol, "model must be a non-empty string"))?
        .to_owned();

    let model = if protocol == WireFormat::ClaudeMessages {
        resolve_claude_model_id(&model)
    } else {
        model
    };
    let body = if payload["model"].as_str() == Some(model.as_str()) {
        body
    } else {
        payload["model"] = Value::String(model.clone());
        Bytes::from(serde_json::to_vec(&payload).map_err(|_| HttpError::internal(protocol))?)
    };

    let request = ProxyRequest::new(protocol, model, body)
        .map_err(|error| HttpError::from_proxy_request(protocol, error))?;
    Ok(request.with_metadata(request_metadata(headers, protocol)?))
}

fn proxy_request_for_key(
    protocol: WireFormat,
    headers: &HeaderMap,
    body: Bytes,
    key: &AuthenticatedApiKey,
) -> Result<ProxyRequest, HttpError> {
    let payload = parse_payload(protocol, &body)?;
    proxy_request_for_key_from_payload(protocol, headers, body, payload, key)
}

fn proxy_request_for_key_from_payload(
    protocol: WireFormat,
    headers: &HeaderMap,
    body: Bytes,
    payload: Value,
    key: &AuthenticatedApiKey,
) -> Result<ProxyRequest, HttpError> {
    let mut request = proxy_request_from_payload(protocol, headers, body, payload)?;
    request.metadata.routing_scope = Some(key.key_id.to_string());
    request.metadata.previous_response_id = serde_json::from_slice::<Value>(&request.payload)
        .ok()
        .and_then(|payload| {
            payload
                .get("previous_response_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    if protocol == WireFormat::ClaudeMessages {
        let mut payload: Value = serde_json::from_slice(&request.payload)
            .map_err(|_| HttpError::invalid_request(protocol, "request body must be valid JSON"))?;
        let Some(root) = payload.as_object_mut() else {
            return Err(HttpError::invalid_request(
                protocol,
                "request body must be a JSON object",
            ));
        };
        if let Some(session_id) = claude_code_session_id(headers, root, protocol)? {
            request.metadata.session_id =
                Some(claude_code_cache_key(key, &request.model, &session_id));
        }
        root.remove("metadata");
        request.payload = serde_json::to_vec(&payload)
            .map(Bytes::from)
            .map_err(|_| HttpError::internal(protocol))?;
    }
    Ok(request)
}

fn request_metadata(
    headers: &HeaderMap,
    protocol: WireFormat,
) -> Result<RequestMetadata, HttpError> {
    let mut metadata = RequestMetadata::default();
    metadata.session_id = metadata_header(headers, "session-id", protocol)?;
    metadata.thread_id = metadata_header(headers, "thread-id", protocol)?;
    metadata.client_request_id = metadata_header(headers, "x-client-request-id", protocol)?;
    Ok(metadata)
}

fn claude_code_session_id(
    headers: &HeaderMap,
    body: &Map<String, Value>,
    protocol: WireFormat,
) -> Result<Option<String>, HttpError> {
    if let Some(session_id) = metadata_header(headers, CLAUDE_CODE_SESSION_HEADER, protocol)? {
        return Ok(Some(session_id));
    }
    if let Some(user_id) = body
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("user_id"))
        .and_then(Value::as_str)
        && let Ok(metadata) = serde_json::from_str::<Value>(user_id)
        && let Some(session_id) = metadata.get("session_id").and_then(Value::as_str)
    {
        return validated_session_id(session_id, protocol);
    }
    metadata_header(headers, "session-id", protocol)
}

fn validated_session_id(value: &str, protocol: WireFormat) -> Result<Option<String>, HttpError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if !valid_metadata_value(value) {
        return Err(HttpError::invalid_request(
            protocol,
            "request metadata header is invalid",
        ));
    }
    Ok(Some(value.to_owned()))
}

fn claude_code_cache_key(key: &AuthenticatedApiKey, model: &str, session_id: &str) -> String {
    let mut digest = Sha256::new();
    for value in [
        "claude-code-cache-v1",
        key.key_id.as_str(),
        key.owner_user_id.as_str(),
        model,
        session_id,
    ] {
        digest.update(
            u64::try_from(value.len())
                .expect("request metadata length must fit u64")
                .to_be_bytes(),
        );
        digest.update(value.as_bytes());
    }
    let digest = digest.finalize();
    let mut encoded = String::with_capacity(35);
    encoded.push_str("cc_");
    for byte in digest.iter().take(16) {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn metadata_header(
    headers: &HeaderMap,
    name: &'static str,
    protocol: WireFormat,
) -> Result<Option<String>, HttpError> {
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| HttpError::invalid_request(protocol, "request metadata header is invalid"))?
        .trim();
    if value.is_empty() {
        return Ok(None);
    }
    if !valid_metadata_value(value) {
        return Err(HttpError::invalid_request(
            protocol,
            "request metadata header is invalid",
        ));
    }
    Ok(Some(value.to_owned()))
}

fn valid_metadata_value(value: &str) -> bool {
    value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}

async fn load_key_account_filter(
    api_keys: &ApiKeyAuthenticator,
    key: &AuthenticatedApiKey,
    protocol: WireFormat,
) -> Result<HashSet<AccountId>, HttpError> {
    let account_ids = api_keys
        .account_ids_for_key(&key.owner_user_id, &key.group_label)
        .await
        .map_err(|_| HttpError::internal(protocol))?;
    let mut set = HashSet::new();
    for account_id in account_ids {
        let id = AccountId::new(account_id).map_err(|_| HttpError::internal(protocol))?;
        set.insert(id);
    }
    Ok(set)
}

fn authenticate_api_key(
    authenticator: &ApiKeyAuthenticator,
    headers: &HeaderMap,
    protocol: WireFormat,
) -> Result<AuthenticatedApiKey, HttpError> {
    let key = downstream_api_key(headers).ok_or_else(|| HttpError::authentication(protocol))?;
    authenticator
        .authenticate(key, unix_timestamp())
        .map_err(|_| HttpError::authentication(protocol))
}

fn downstream_api_key(headers: &HeaderMap) -> Option<&str> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_value);
    let x_api_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty());
    match (bearer, x_api_key) {
        (Some(bearer), Some(x_api_key)) if bearer != x_api_key => None,
        (Some(bearer), _) => Some(bearer),
        (None, Some(x_api_key)) => Some(x_api_key),
        (None, None) => None,
    }
}

fn bearer_value(value: &str) -> Option<&str> {
    let mut parts = value.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && parts.next().is_none() {
        Some(token)
    } else {
        None
    }
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after unix epoch")
        .as_secs()
        .try_into()
        .expect("unix timestamp must fit i64")
}

struct HttpError {
    status: StatusCode,
    body: Value,
}

impl HttpError {
    fn authentication(protocol: WireFormat) -> Self {
        Self::new(
            protocol,
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "invalid API key",
        )
    }

    fn invalid_request(protocol: WireFormat, message: &'static str) -> Self {
        Self::new(
            protocol,
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            message,
        )
    }

    fn service_unavailable(protocol: WireFormat, message: &'static str) -> Self {
        Self::new(
            protocol,
            StatusCode::SERVICE_UNAVAILABLE,
            "api_error",
            message,
        )
    }

    fn internal(protocol: WireFormat) -> Self {
        Self::new(
            protocol,
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "internal server error",
        )
    }

    fn rate_limited(protocol: WireFormat, message: &str) -> Self {
        Self::new(
            protocol,
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            message,
        )
    }

    fn from_proxy_request(protocol: WireFormat, error: ProxyRequestError) -> Self {
        Self::invalid_request(
            protocol,
            match error {
                ProxyRequestError::EmptyModel => "model must be a non-empty string",
            },
        )
    }

    fn from_provider(protocol: WireFormat, error: ProviderError) -> Self {
        let (status, error_type) = match error.kind() {
            ProviderErrorKind::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request_error"),
            ProviderErrorKind::Authentication => (StatusCode::UNAUTHORIZED, "authentication_error"),
            ProviderErrorKind::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limit_error"),
            ProviderErrorKind::Upstream => (StatusCode::BAD_GATEWAY, "api_error"),
            ProviderErrorKind::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "api_error"),
        };
        Self::new(protocol, status, error_type, error.message())
    }

    fn new(protocol: WireFormat, status: StatusCode, error_type: &str, message: &str) -> Self {
        let body = match protocol {
            WireFormat::OpenAiResponses | WireFormat::OpenAiChatCompletions => json!({
                "error": { "type": error_type, "message": message }
            }),
            WireFormat::ClaudeMessages => json!({
                "type": "error",
                "error": { "type": error_type, "message": message }
            }),
        };
        Self { status, body }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::body::to_bytes;
    use futures_util::stream;
    use provider_auth::{ApiKeyId, AuthService, UserId};
    use provider_core::{
        AccountId, CredentialKind, NewCredential, NewProviderAccount, Provider, ProviderKind,
        ProviderManagementRepository, ProviderModel, ProviderRequest, ProviderStream,
        ProviderVisibility, RequestMetadata,
    };
    use provider_protocol::DefaultProtocolBridge;
    use provider_storage::SqliteAccountRepository;
    use secrecy::{ExposeSecret, SecretString};
    use tokio::net::TcpListener;

    use super::*;

    struct TestPublicDir(PathBuf);

    impl TestPublicDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("provider-core-ui-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).expect("create UI test directory");
            fs::write(path.join("index.html"), "<main>provider ui</main>").expect("write UI index");
            fs::write(path.join("app.js"), "console.log('provider ui')").expect("write UI asset");
            Self(path)
        }
    }

    impl Drop for TestPublicDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn response_text(response: Response) -> String {
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        String::from_utf8(body.to_vec()).expect("response UTF-8")
    }

    #[tokio::test]
    async fn serves_ui_assets_and_browser_routes() {
        let public = TestPublicDir::new();
        let service = ui_service(&public.0);

        let asset = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/app.js")
                    .body(Body::empty())
                    .expect("asset request"),
            )
            .await
            .expect("infallible asset response");
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(response_text(asset).await, "console.log('provider ui')");

        let browser_route = service
            .oneshot(
                Request::builder()
                    .uri("/providers/account-1")
                    .header(header::ACCEPT, "text/html,application/xhtml+xml")
                    .body(Body::empty())
                    .expect("browser route request"),
            )
            .await
            .expect("infallible browser route response");
        assert_eq!(browser_route.status(), StatusCode::OK);
        assert_eq!(
            response_text(browser_route).await,
            "<main>provider ui</main>"
        );
    }

    #[tokio::test]
    async fn keeps_backend_and_non_browser_misses_as_not_found() {
        let public = TestPublicDir::new();
        let service = ui_service(&public.0);

        for uri in ["/api/v1/missing", "/v1/missing", "/readyz/missing"] {
            let response = service
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header(header::ACCEPT, "text/html")
                        .body(Body::empty())
                        .expect("backend request"),
                )
                .await
                .expect("infallible backend response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }

        let response = service
            .oneshot(
                Request::builder()
                    .uri("/missing.json")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("non-browser request"),
            )
            .await
            .expect("infallible non-browser response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_ui_directory_stays_not_found() {
        let missing =
            std::env::temp_dir().join(format!("provider-core-missing-ui-{}", uuid::Uuid::new_v4()));
        let response = ui_service(missing)
            .oneshot(
                Request::builder()
                    .uri("/providers")
                    .header(header::ACCEPT, "text/html; charset=utf-8")
                    .body(Body::empty())
                    .expect("browser request"),
            )
            .await
            .expect("infallible missing UI response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    async fn seed_group_label(
        repository: Arc<SqliteAccountRepository>,
        owner: &UserId,
        account_id: &str,
        group_label: &str,
    ) {
        repository
            .create_provider_account(
                NewProviderAccount {
                    id: AccountId::new(account_id).expect("account ID"),
                    provider: ProviderKind::OpenAiCompatible,
                    label: "seed".to_owned(),
                    group_label: group_label.to_owned(),
                    priority: 0,
                    config_json: "{}".to_owned(),
                    enabled: true,
                    credential: NewCredential {
                        kind: CredentialKind::ApiKey,
                        format_version: 1,
                        credential_json: SecretString::from("seed-secret".to_owned()),
                        expires_at: None,
                        last_refreshed_at: None,
                    },
                },
                owner.as_str(),
                ProviderVisibility::Private,
            )
            .await
            .expect("seed provider account");
    }

    async fn response_json(response: reqwest::Response) -> Value {
        let body = response.bytes().await.expect("response body");
        serde_json::from_slice(&body).expect("response JSON")
    }

    fn padded_json(prefix: &str, suffix: &str, size: usize) -> String {
        let padding = size
            .checked_sub(prefix.len() + suffix.len())
            .expect("requested JSON size");
        let mut body = String::with_capacity(size);
        body.push_str(prefix);
        body.extend(std::iter::repeat_n('a', padding));
        body.push_str(suffix);
        assert_eq!(body.len(), size);
        body
    }

    struct TestProvider {
        models: Vec<ProviderModel>,
        metadata: Arc<Mutex<Vec<RequestMetadata>>>,
    }

    #[async_trait]
    impl Provider for TestProvider {
        fn name(&self) -> &'static str {
            "test"
        }

        fn native_format(&self) -> WireFormat {
            WireFormat::OpenAiResponses
        }

        fn models(&self) -> &[ProviderModel] {
            &self.models
        }

        async fn execute_stream(
            &self,
            request: ProviderRequest,
        ) -> Result<ProviderStream, ProviderError> {
            self.metadata
                .lock()
                .expect("metadata capture lock")
                .push(request.metadata);
            let event = Bytes::from_static(
                b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{}}\n\n",
            );
            Ok(Box::pin(stream::once(async move { Ok(event) })))
        }

        async fn count_tokens(&self, _request: ProviderRequest) -> Result<u64, ProviderError> {
            Ok(42)
        }
    }

    #[tokio::test]
    async fn requires_api_keys_and_supports_openai_and_anthropic_headers() {
        let repository = Arc::new(
            SqliteAccountRepository::in_memory()
                .await
                .expect("repository"),
        );
        let auth = AuthService::new(repository.clone());
        let grant = auth
            .setup(
                "admin".to_owned(),
                SecretString::from("secret".to_owned()),
                unix_timestamp(),
            )
            .await
            .expect("initial setup");
        let now = unix_timestamp();
        seed_group_label(repository.clone(), &grant.user.id, "acct-http-1", "default").await;
        let api_keys = ApiKeyAuthenticator::load(repository)
            .await
            .expect("API key index");
        let created_key = api_keys
            .create(CreateApiKeyInput {
                owner_user_id: &grant.user.id,
                secret: SecretString::from("test-api-key"),
                group_label: "default".to_owned(),
                label: "test".to_owned(),
                expires_at: None,
                quota_limit_usd: None,
                now,
            })
            .await
            .expect("create API key");
        let api_key = created_key.key.expose_secret().to_owned();
        let captured_metadata = Arc::new(Mutex::new(Vec::new()));
        let service = ProxyService::new(
            Arc::new(TestProvider {
                models: vec![
                    ProviderModel::new("grok-4.5", "xai").with_input_modalities(Some(vec![
                        provider_core::ProviderModelInputModality::Text,
                        provider_core::ProviderModelInputModality::Image,
                    ])),
                ],
                metadata: captured_metadata.clone(),
            }),
            Arc::new(DefaultProtocolBridge),
            provider_core::ProviderAccountAccess {
                owner_user_id: Some(grant.user.id.as_str().to_owned()),
                visibility: provider_core::ProviderVisibility::Private,
            },
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let server =
            tokio::spawn(axum::serve(listener, router(service, api_keys.clone())).into_future());
        let client = reqwest::Client::new();
        let base_url = format!("http://{address}");

        let health = client
            .get(format!("{base_url}/healthz"))
            .send()
            .await
            .expect("health response");
        assert_eq!(health.status(), StatusCode::OK);

        let missing_key = client
            .get(format!("{base_url}/v1/models"))
            .send()
            .await
            .expect("missing API key response");
        assert_eq!(missing_key.status(), StatusCode::UNAUTHORIZED);

        let models = response_json(
            client
                .get(format!("{base_url}/v1/models"))
                .bearer_auth(&api_key)
                .send()
                .await
                .expect("models response"),
        )
        .await;
        assert_eq!(models["data"][0]["id"], "grok-4.5");
        assert_eq!(
            models["data"][0]["input_modalities"],
            json!(["text", "image"])
        );
        assert_eq!(models["data"][0]["supports_image_detail_original"], true);
        assert_eq!(models["object"], "list");

        let claude_models = response_json(
            client
                .get(format!("{base_url}/v1/models"))
                .header("x-api-key", &api_key)
                .header("anthropic-version", "2023-06-01")
                .send()
                .await
                .expect("Claude models response"),
        )
        .await;
        assert!(claude_models.get("object").is_none());
        assert_eq!(claude_models["has_more"], false);
        assert_eq!(claude_models["data"][0]["id"], "claude-fable-5-dd-5.4-korg");
        assert_eq!(claude_models["data"][0]["type"], "model");
        assert_eq!(claude_models["data"][0]["display_name"], "grok-4.5");
        assert_eq!(claude_models["first_id"], claude_models["data"][0]["id"]);
        assert_eq!(claude_models["last_id"], claude_models["data"][0]["id"]);

        for path in ["/v1/responses", "/v1/messages"] {
            let mut request = client
                .post(format!("{base_url}{path}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(json!({ "model": "grok-4.5", "input": "hello", "messages": [] }).to_string());
            request = if path == "/v1/messages" {
                request.header("x-api-key", &api_key)
            } else {
                request
                    .bearer_auth(&api_key)
                    .header("session-id", "session-1")
                    .header("thread-id", "thread:1")
                    .header("x-client-request-id", "request_1")
            };
            let response = request.send().await.expect("stream response");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("text/event-stream")
            );
        }
        let mut expected_metadata = RequestMetadata::default();
        expected_metadata.session_id = Some("session-1".to_owned());
        expected_metadata.thread_id = Some("thread:1".to_owned());
        expected_metadata.client_request_id = Some("request_1".to_owned());
        expected_metadata.routing_scope = Some(created_key.summary.id.to_string());
        let mut anthropic_metadata = RequestMetadata::default();
        anthropic_metadata.routing_scope = Some(created_key.summary.id.to_string());
        assert_eq!(
            captured_metadata
                .lock()
                .expect("metadata capture lock")
                .as_slice(),
            [expected_metadata, anthropic_metadata]
        );

        let invalid_metadata = client
            .post(format!("{base_url}/v1/responses"))
            .bearer_auth(&api_key)
            .header("session-id", "invalid value")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json!({ "model": "grok-4.5", "input": "hello" }).to_string())
            .send()
            .await
            .expect("invalid metadata response");
        assert_eq!(invalid_metadata.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            captured_metadata
                .lock()
                .expect("metadata capture lock")
                .len(),
            2
        );

        let count = response_json(
            client
                .post(format!("{base_url}/v1/messages/count_tokens"))
                .header("x-api-key", &api_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(json!({ "model": "grok-4.5", "messages": [] }).to_string())
                .send()
                .await
                .expect("count response"),
        )
        .await;
        assert_eq!(count["input_tokens"], 42);

        let compressed = client
            .post(format!("{base_url}/v1/responses"))
            .bearer_auth(&api_key)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_ENCODING, "gzip")
            .body(r#"{"model":"grok-4.5","input":"hello"}"#)
            .send()
            .await
            .expect("compressed proxy request");
        assert_eq!(compressed.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let exact_body = padded_json(
            r#"{"model":"grok-4.5","input":""#,
            r#""}"#,
            MAX_PROXY_BODY_BYTES,
        );
        let exact_limit = client
            .post(format!("{base_url}/v1/responses"))
            .bearer_auth(&api_key)
            .header(header::CONTENT_TYPE, "application/json")
            .body(exact_body)
            .send()
            .await
            .expect("proxy request at body limit");
        assert_eq!(exact_limit.status(), StatusCode::OK);

        let oversized_body = padded_json(
            r#"{"model":"grok-4.5","input":""#,
            r#""}"#,
            MAX_PROXY_BODY_BYTES + 1,
        );
        let oversized = client
            .post(format!("{base_url}/v1/responses"))
            .bearer_auth(&api_key)
            .header(header::CONTENT_TYPE, "application/json")
            .body(oversized_body)
            .send()
            .await
            .expect("oversized proxy request");
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

        api_keys
            .update(
                &grant.user.id,
                &created_key.summary.id,
                ApiKeyPatch {
                    label: None,
                    group_label: None,
                    enabled: Some(false),
                    expires_at: None,
                    quota_limit_usd: None,
                    updated_at: unix_timestamp(),
                },
            )
            .await
            .expect("disable API key");
        let disabled_key = client
            .get(format!("{base_url}/v1/models"))
            .bearer_auth(&api_key)
            .send()
            .await
            .expect("disabled API key response");
        assert_eq!(disabled_key.status(), StatusCode::UNAUTHORIZED);

        server.abort();
    }

    #[test]
    fn derives_isolated_claude_code_cache_keys() {
        let first_key = AuthenticatedApiKey {
            key_id: ApiKeyId::new("key-a").expect("API key ID"),
            owner_user_id: UserId::new("user-a").expect("user ID"),
            label: "first".to_owned(),
            group_label: "default".to_owned(),
            quota_limit_atoms: None,
        };
        let second_key = AuthenticatedApiKey {
            key_id: ApiKeyId::new("key-b").expect("API key ID"),
            owner_user_id: UserId::new("user-a").expect("user ID"),
            label: "second".to_owned(),
            group_label: "default".to_owned(),
            quota_limit_atoms: None,
        };
        let first = claude_code_cache_key(&first_key, "grok-4.5", "session-1");

        assert_eq!(
            first,
            claude_code_cache_key(&first_key, "grok-4.5", "session-1")
        );
        assert_ne!(
            first,
            claude_code_cache_key(&first_key, "grok-4.5", "session-2")
        );
        assert_ne!(
            first,
            claude_code_cache_key(&first_key, "grok-4.6", "session-1")
        );
        assert_ne!(
            first,
            claude_code_cache_key(&second_key, "grok-4.5", "session-1")
        );
        assert!(first.starts_with("cc_"));
        assert!(!first.contains("session-1"));
    }

    #[test]
    fn extracts_claude_code_session_with_expected_precedence() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "session-id",
            "fallback-session".parse().expect("fallback header"),
        );
        let payload: Value = serde_json::from_slice(
            br#"{
            "metadata":{"user_id":"{\"device_id\":\"device-a\",\"session_id\":\"payload-session\"}"}
        }"#,
        )
        .expect("payload JSON");
        let body = payload.as_object().expect("payload object");
        let payload_session =
            match claude_code_session_id(&headers, body, WireFormat::ClaudeMessages) {
                Ok(value) => value,
                Err(_) => panic!("payload session should be valid"),
            };
        assert_eq!(payload_session.as_deref(), Some("payload-session"));

        headers.insert(
            CLAUDE_CODE_SESSION_HEADER,
            "header-session".parse().expect("Claude session header"),
        );
        let header_session =
            match claude_code_session_id(&headers, body, WireFormat::ClaudeMessages) {
                Ok(value) => value,
                Err(_) => panic!("header session should be valid"),
            };
        assert_eq!(header_session.as_deref(), Some("header-session"));
    }

    #[test]
    fn ignores_unstructured_claude_user_ids() {
        let headers = HeaderMap::new();
        let prefixed: Value = serde_json::from_slice(
            br#"{"metadata":{"user_id":"user_account_session_123e4567-e89b-12d3-a456-426614174000"}}"#,
        )
        .expect("prefixed JSON");
        let prefixed_session = match claude_code_session_id(
            &headers,
            prefixed.as_object().expect("prefixed object"),
            WireFormat::ClaudeMessages,
        ) {
            Ok(value) => value,
            Err(_) => panic!("prefixed user ID should be ignored"),
        };
        assert_eq!(prefixed_session, None);
        let bare: Value =
            serde_json::from_slice(br#"{"metadata":{"user_id":"same-user-across-chats"}}"#)
                .expect("bare JSON");
        let bare_session = match claude_code_session_id(
            &headers,
            bare.as_object().expect("bare object"),
            WireFormat::ClaudeMessages,
        ) {
            Ok(value) => value,
            Err(_) => panic!("bare user ID should be ignored"),
        };
        assert_eq!(bare_session, None);
    }

    #[test]
    fn detects_claude_model_catalog_requests() {
        let mut headers = HeaderMap::new();
        assert_eq!(models_protocol(&headers), WireFormat::OpenAiResponses);

        headers.insert(
            header::USER_AGENT,
            "claude-cli/2.1.0".parse().expect("header"),
        );
        assert_eq!(models_protocol(&headers), WireFormat::ClaudeMessages);

        headers.remove(header::USER_AGENT);
        headers.insert("anthropic-version", "2023-06-01".parse().expect("header"));
        assert_eq!(models_protocol(&headers), WireFormat::ClaudeMessages);
    }

    #[test]
    fn resolves_claude_catalog_model_ids_in_request_body() {
        let request = match proxy_request(
            WireFormat::ClaudeMessages,
            &HeaderMap::new(),
            Bytes::from_static(br#"{"model":"claude-fable-5-dd-5.4-korg","messages":[]}"#),
        ) {
            Ok(request) => request,
            Err(_) => panic!("proxy request should be valid"),
        };

        assert_eq!(request.model, "grok-4.5");
        let payload: Value = serde_json::from_slice(&request.payload).expect("request payload");
        assert_eq!(payload["model"], "grok-4.5");
    }
}
