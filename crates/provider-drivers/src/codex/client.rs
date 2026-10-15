use std::time::Duration;

use futures_util::TryStreamExt;
use provider_core::{
    BoundedBodyError, ProviderError, ProviderErrorKind, ProviderStream, collect_bounded_body,
    parse_provider_retry_after,
};
use reqwest::StatusCode;
use secrecy::ExposeSecret;
use serde_json::Value;

use super::{
    credentials::CodexCredentials,
    identity::{DEFAULT_BACKEND_ROOT, responses_headers},
    quota::normalize_headers,
    request::PreparedCodexRequest,
};

const MAX_ERROR_RESPONSE_SIZE: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_HEADERS_TIMEOUT: Duration = Duration::from_secs(600);

pub(crate) struct CodexStreamResponse {
    pub(crate) stream: ProviderStream,
    pub(crate) observed_groups: Vec<provider_core::QuotaGroup>,
}

pub(crate) struct CodexClientFailure {
    pub(crate) error: ProviderError,
    pub(crate) observed_groups: Vec<provider_core::QuotaGroup>,
}

#[derive(Clone)]
pub(crate) struct CodexClient {
    http: reqwest::Client,
    backend_root: String,
}

impl CodexClient {
    pub(crate) fn new() -> Self {
        Self::with_backend_root(DEFAULT_BACKEND_ROOT)
    }

    pub(crate) fn with_backend_root(backend_root: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            backend_root: backend_root.trim_end_matches('/').to_owned(),
        }
    }

    pub(crate) async fn execute_stream(
        &self,
        credentials: &CodexCredentials,
        request: PreparedCodexRequest,
    ) -> Result<CodexStreamResponse, CodexClientFailure> {
        let responses_lite = request.metadata.responses_lite;
        let mut upstream = self
            .http
            .post(format!("{}/codex/responses", self.backend_root))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .body(request.payload);
        upstream =
            responses_headers(upstream, credentials).map_err(|error| CodexClientFailure {
                error,
                observed_groups: Vec::new(),
            })?;
        upstream = optional_header(
            upstream,
            "session-id",
            request.metadata.session_id.as_deref(),
        )
        .map_err(empty_failure)?;
        upstream = optional_header(upstream, "thread-id", request.metadata.thread_id.as_deref())
            .map_err(empty_failure)?;
        if request.metadata.responses_lite {
            upstream = upstream.header("x-openai-internal-codex-responses-lite", "true");
        }
        let client_request_id = request
            .metadata
            .client_request_id
            .as_deref()
            .or(request.metadata.thread_id.as_deref());
        upstream = optional_header(upstream, "x-client-request-id", client_request_id)
            .map_err(empty_failure)?;
        let response = tokio::time::timeout(RESPONSE_HEADERS_TIMEOUT, upstream.send())
            .await
            .map_err(|_| CodexClientFailure {
                error: ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "Codex upstream response headers timed out",
                ),
                observed_groups: Vec::new(),
            })?
            .map_err(|error| CodexClientFailure {
                error: if error.is_connect() {
                    ProviderError::new(ProviderErrorKind::Upstream, "Codex upstream request failed")
                        .with_failover_reason(
                            provider_core::ProviderFailoverReason::PreconnectFailure,
                        )
                } else {
                    ProviderError::new(ProviderErrorKind::Upstream, "Codex upstream request failed")
                },
                observed_groups: Vec::new(),
            })?;
        let status = response.status();
        let observed_groups = if status.is_success() || status == StatusCode::TOO_MANY_REQUESTS {
            normalize_headers(response.headers())
        } else {
            Vec::new()
        };
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_provider_retry_after);
            let error = status_error(response, status, responses_lite).await;
            let error = crate::upstream_error::redact_credentials(
                error,
                &[
                    credentials.access_token().expose_secret(),
                    credentials.refresh_token().expose_secret(),
                ],
            );
            let error = match retry_after {
                Some(value) => error.with_retry_after(value),
                None => error,
            };
            return Err(CodexClientFailure {
                error,
                observed_groups,
            });
        }
        let stream = response.bytes_stream().map_err(|_| {
            ProviderError::new(ProviderErrorKind::Upstream, "Codex upstream stream failed")
        });
        Ok(CodexStreamResponse {
            stream: Box::pin(stream),
            observed_groups,
        })
    }
}

fn optional_header(
    request: reqwest::RequestBuilder,
    name: &'static str,
    value: Option<&str>,
) -> Result<reqwest::RequestBuilder, ProviderError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(request);
    };
    let value = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            format!("invalid Codex {name} header value"),
        )
    })?;
    Ok(request.header(name, value))
}

fn empty_failure(error: ProviderError) -> CodexClientFailure {
    CodexClientFailure {
        error,
        observed_groups: Vec::new(),
    }
}

async fn status_error(
    response: reqwest::Response,
    status: StatusCode,
    responses_lite: bool,
) -> ProviderError {
    let upstream_request_id = reviewed_token_header(response.headers(), "x-request-id", 128);
    let (summary, body_issue) = match read_error_body(response).await {
        Ok(body) => {
            let mut summary = reviewed_error_summary(&body);
            summary.message = Some(crate::upstream_error::render_detail(&body));
            (summary, None)
        }
        Err(issue) => (ReviewedErrorSummary::default(), Some(issue)),
    };
    tracing::warn!(
        target: "provider.codex.upstream",
        upstream_status = status.as_u16(),
        responses_lite,
        has_upstream_request_id = upstream_request_id.is_some(),
        has_error_code = summary.code.is_some(),
        has_error_type = summary.error_type.is_some(),
        has_error_param = summary.param.is_some(),
        error_body_issue = body_issue.map_or("none", ErrorBodyIssue::as_str),
        "Codex upstream rejected request"
    );
    let error_token = summary.code.as_ref().or(summary.error_type.as_ref());
    let quota_token = error_token.is_some_and(|token| is_quota_exhaustion_token(token));
    let quota_exhausted = is_quota_exhaustion_status(status, quota_token);
    let kind = if quota_exhausted || status == StatusCode::TOO_MANY_REQUESTS {
        ProviderErrorKind::RateLimited
    } else {
        match status {
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
                ProviderErrorKind::InvalidRequest
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => ProviderErrorKind::Authentication,
            _ => ProviderErrorKind::Upstream,
        }
    };
    let message = match body_issue {
        None => format!("Codex upstream returned HTTP {status}"),
        Some(ErrorBodyIssue::ReadFailed) => {
            format!("Codex upstream returned HTTP {status} with an unreadable error response")
        }
        Some(ErrorBodyIssue::TooLarge) => {
            format!("Codex upstream returned HTTP {status} with an oversized error response")
        }
        Some(ErrorBodyIssue::TimedOut) => {
            format!("Codex upstream returned HTTP {status}; error body read timed out")
        }
    };
    let message = if body_issue.is_none() {
        let mut details = Vec::new();
        if let Some(detail) = summary.message.as_deref() {
            details.push(format!("message={detail}"));
        }
        if let Some(request_id) = upstream_request_id.as_deref() {
            details.push(format!("upstream_request_id={request_id}"));
        }
        if details.is_empty() {
            message
        } else {
            format!("{message}: {}", details.join(", "))
        }
    } else {
        message
    };
    let error = ProviderError::new(kind, message).with_upstream_status(status.as_u16());
    if status == StatusCode::TOO_MANY_REQUESTS {
        error.with_failover_reason(provider_core::ProviderFailoverReason::RateLimited)
    } else if quota_exhausted {
        error.with_failover_reason(provider_core::ProviderFailoverReason::QuotaExhausted)
    } else {
        error
    }
}

fn is_quota_exhaustion_token(token: &str) -> bool {
    matches!(
        token,
        "usage_limit_reached"
            | "credits_depleted"
            | "workspace_member_credits_depleted"
            | "insufficient_quota"
            | "quota_exhausted"
    )
}

fn is_quota_exhaustion_status(status: StatusCode, quota_token: bool) -> bool {
    status == StatusCode::PAYMENT_REQUIRED
        || (matches!(status, StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN) && quota_token)
}

#[derive(Clone, Copy)]
enum ErrorBodyIssue {
    ReadFailed,
    TooLarge,
    TimedOut,
}

impl ErrorBodyIssue {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ReadFailed => "read_failed",
            Self::TooLarge => "too_large",
            Self::TimedOut => "timed_out",
        }
    }
}

async fn read_error_body(response: reqwest::Response) -> Result<Vec<u8>, ErrorBodyIssue> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ERROR_RESPONSE_SIZE as u64)
    {
        return Err(ErrorBodyIssue::TooLarge);
    }
    tokio::time::timeout(
        Duration::from_secs(10),
        collect_bounded_body(response.bytes_stream(), MAX_ERROR_RESPONSE_SIZE),
    )
    .await
    .map_err(|_| ErrorBodyIssue::TimedOut)?
    .map(|body| body.to_vec())
    .map_err(|error| match error {
        BoundedBodyError::Read(_) => ErrorBodyIssue::ReadFailed,
        BoundedBodyError::TooLarge => ErrorBodyIssue::TooLarge,
    })
}

#[derive(Default)]
struct ReviewedErrorSummary {
    code: Option<String>,
    error_type: Option<String>,
    param: Option<String>,
    message: Option<String>,
}

fn reviewed_error_summary(body: &[u8]) -> ReviewedErrorSummary {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return ReviewedErrorSummary::default();
    };
    ReviewedErrorSummary {
        code: reviewed_json_token(
            value.pointer("/error/code").or_else(|| value.get("code")),
            64,
            "_-.",
        ),
        error_type: reviewed_json_token(
            value
                .pointer("/error/type")
                .or_else(|| value.get("error_type")),
            64,
            "_-.",
        ),
        param: reviewed_json_token(
            value.pointer("/error/param").or_else(|| value.get("param")),
            128,
            "_-.$[]",
        ),
        message: None,
    }
}

fn reviewed_json_token(value: Option<&Value>, max_len: usize, punctuation: &str) -> Option<String> {
    let token = value?.as_str()?.trim().to_ascii_lowercase();
    (!token.is_empty()
        && token.len() <= max_len
        && token
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || punctuation.contains(character)))
    .then_some(token)
}

fn reviewed_token_header(
    headers: &reqwest::header::HeaderMap,
    name: &'static str,
    max_len: usize,
) -> Option<String> {
    let token = headers.get(name)?.to_str().ok()?.trim();
    (!token.is_empty()
        && token.len() <= max_len
        && token
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-.:".contains(character)))
    .then(|| token.to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Router,
        body::{Body, Bytes, to_bytes},
        extract::{Request, State},
        http::Response,
        routing::post,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use futures_util::TryStreamExt;
    use provider_core::{ProviderRequest, RequestMetadata, WireFormat};
    use tokio::{net::TcpListener, task::JoinHandle};

    use super::*;
    use crate::codex::request::{PreparedCodexRequest, prepare_request};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<(reqwest::header::HeaderMap, Bytes)>>>);

    async fn success_handler(State(capture): State<Capture>, request: Request) -> Response<Body> {
        let headers = request.headers().clone();
        let body = to_bytes(request.into_body(), 1024 * 1024)
            .await
            .expect("request body");
        capture
            .0
            .lock()
            .expect("capture lock")
            .push((headers, body));
        Response::builder()
            .status(StatusCode::OK)
            .header(reqwest::header::CONTENT_TYPE, "text/event-stream")
            .header("x-codex-primary-used-percent", "25")
            .header("x-codex-primary-window-minutes", "300")
            .header("x-codex-primary-reset-at", "1234")
            .body(Body::from(Bytes::from_static(
                b"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n",
            )))
            .expect("success response")
    }

    async fn rate_limited_handler() -> Response<Body> {
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(reqwest::header::RETRY_AFTER, "20")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("x-codex-primary-used-percent", "100")
            .header("x-codex-primary-window-minutes", "300")
            .header("x-codex-primary-reset-at", "5678")
            .body(Body::from(Bytes::from_static(
                br#"{"error":{"code":"usage_limit_reached","message":"monthly usage limit reached; access-token"},"debug":{"authorization":"Bearer access-token"}}"#,
            )))
            .expect("rate limited response")
    }

    #[tokio::test]
    async fn sends_truthful_identity_and_streams_with_header_observation() {
        let capture = Capture::default();
        let router = Router::new()
            .route("/codex/responses", post(success_handler))
            .with_state(capture.clone());
        let (backend_root, server) = spawn_server(router).await;
        let client = CodexClient::with_backend_root(&backend_root);
        let credentials = credentials("workspace-1", true, "access-token");
        let mut metadata = RequestMetadata::default();
        metadata.session_id = Some("session-1".to_owned());
        metadata.thread_id = Some("thread-1".to_owned());
        let prepared = prepare_request(ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.5".to_owned(),
            payload: Bytes::from_static(br#"{"model":"caller-model","stream":false}"#),
            metadata,
        })
        .expect("prepared request");

        let response = client.execute_stream(&credentials, prepared).await;
        let response = match response {
            Ok(response) => response,
            Err(_) => panic!("stream response must succeed"),
        };
        let chunks = response
            .stream
            .try_collect::<Vec<_>>()
            .await
            .expect("stream chunks");
        server.abort();

        assert_eq!(chunks.len(), 1);
        assert_eq!(response.observed_groups.len(), 1);
        assert_eq!(response.observed_groups[0].key, "codex");
        let captured = capture.0.lock().expect("capture lock").clone();
        let (headers, captured_body) = &captured[0];
        assert_eq!(
            header(headers, reqwest::header::AUTHORIZATION.as_str()),
            "Bearer access-token"
        );
        assert_eq!(header(headers, "chatgpt-account-id"), "workspace-1");
        assert_eq!(header(headers, "x-openai-fedramp"), "true");
        assert_eq!(header(headers, "originator"), "codex_cli_rs");
        assert!(headers.get("version").is_none());
        assert!(
            header(headers, reqwest::header::USER_AGENT.as_str())
                .starts_with("codex_cli_rs/0.162.1 (")
        );
        let session_id = header(headers, "session-id");
        assert_eq!(session_id, "session-1");
        assert_eq!(header(headers, "thread-id"), "thread-1");
        assert_eq!(header(headers, "x-client-request-id"), "thread-1");
        assert!(!headers.contains_key("x-codex-installation-id"));
        assert!(!headers.contains_key("x-codex-window-id"));
        assert!(!headers.contains_key("x-codex-turn-metadata"));
        let captured_body: Value =
            serde_json::from_slice(captured_body).expect("captured request JSON");
        assert_eq!(captured_body["model"], "gpt-5.5");
        assert_eq!(captured_body["stream"], true);
        assert_eq!(captured_body["prompt_cache_key"], session_id);
    }

    #[tokio::test]
    async fn sends_responses_lite_transport_header() {
        let capture = Capture::default();
        let router = Router::new()
            .route("/codex/responses", post(success_handler))
            .with_state(capture.clone());
        let (backend_root, server) = spawn_server(router).await;
        let client = CodexClient::with_backend_root(&backend_root);
        let mut metadata = RequestMetadata::default();
        metadata.responses_lite = true;
        let prepared = prepare_request(ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.6-sol".to_owned(),
            payload: Bytes::from_static(br#"{"input":"review this"}"#),
            metadata,
        })
        .expect("prepared Responses Lite request");

        let response = match client
            .execute_stream(&credentials("workspace-1", false, "access-token"), prepared)
            .await
        {
            Ok(response) => response,
            Err(_) => panic!("Responses Lite stream must succeed"),
        };
        response
            .stream
            .try_collect::<Vec<_>>()
            .await
            .expect("stream chunks");
        server.abort();

        let captured = capture.0.lock().expect("capture lock");
        assert_eq!(
            header(&captured[0].0, "x-openai-internal-codex-responses-lite"),
            "true"
        );
    }

    #[tokio::test]
    async fn maps_429_and_preserves_rate_limit_observation() {
        let router = Router::new().route("/codex/responses", post(rate_limited_handler));
        let (backend_root, server) = spawn_server(router).await;
        let client = CodexClient::with_backend_root(&backend_root);
        let result = client
            .execute_stream(
                &credentials("workspace-1", false, "access-token"),
                PreparedCodexRequest {
                    payload: Bytes::from_static(br#"{"model":"gpt-5.5"}"#),
                    metadata: RequestMetadata::default(),
                },
            )
            .await;
        server.abort();

        let failure = match result {
            Ok(_) => panic!("429 must fail"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error.kind(), ProviderErrorKind::RateLimited);
        assert_eq!(failure.error.upstream_status(), Some(429));
        assert_eq!(
            failure.error.failover_reason(),
            Some(provider_core::ProviderFailoverReason::RateLimited)
        );
        assert_eq!(failure.error.retry_after(), Some(Duration::from_secs(20)));
        assert!(!failure.error.message().contains("access-token"));
        assert!(failure.error.message().contains("[REDACTED]"));
        assert!(
            failure
                .error
                .message()
                .contains("monthly usage limit reached")
        );
        assert_eq!(failure.observed_groups.len(), 1);
        assert_eq!(failure.observed_groups[0].key, "codex");
    }

    #[test]
    fn invalid_retry_after_values_are_rejected() {
        assert_eq!(parse_provider_retry_after("86401"), None);
        assert_eq!(
            parse_provider_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"),
            None
        );
    }

    #[test]
    fn quota_failover_tokens_use_an_exact_allowlist() {
        for token in [
            "usage_limit_reached",
            "credits_depleted",
            "workspace_member_credits_depleted",
            "insufficient_quota",
            "quota_exhausted",
        ] {
            assert!(is_quota_exhaustion_token(token));
        }
        for token in [
            "quota_parameter_invalid",
            "rate_limit_configuration_error",
            "usage_limit_unknown",
            "credits_depleted_later",
        ] {
            assert!(!is_quota_exhaustion_token(token));
        }
    }

    #[test]
    fn quota_tokens_never_override_ambiguous_or_server_statuses() {
        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(!is_quota_exhaustion_status(status, true));
        }
        assert!(is_quota_exhaustion_status(
            StatusCode::PAYMENT_REQUIRED,
            false
        ));
        assert!(is_quota_exhaustion_status(StatusCode::BAD_REQUEST, true));
        assert!(is_quota_exhaustion_status(StatusCode::FORBIDDEN, true));
        assert!(!is_quota_exhaustion_status(StatusCode::UNAUTHORIZED, true));
        assert!(!is_quota_exhaustion_status(StatusCode::NOT_FOUND, true));
    }

    #[test]
    fn error_summary_keeps_only_bounded_structural_tokens() {
        let summary = reviewed_error_summary(
            br#"{"error":{"code":"invalid_request_error","type":"bad_request","param":"input[12].id","message":"secret prompt"}}"#,
        );
        assert_eq!(summary.code.as_deref(), Some("invalid_request_error"));
        assert_eq!(summary.error_type.as_deref(), Some("bad_request"));
        assert_eq!(summary.param.as_deref(), Some("input[12].id"));

        let summary = reviewed_error_summary(
            br#"{"error":{"code":"invalid request with spaces","param":"secret/value"}}"#,
        );
        assert_eq!(summary.code, None);
        assert_eq!(summary.param, None);
    }

    fn credentials(account_id: &str, is_fedramp: bool, access_token: &str) -> CodexCredentials {
        CodexCredentials::from_tokens(
            access_token.to_owned(),
            "refresh-token".to_owned(),
            jwt(serde_json::json!({
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": account_id,
                    "chatgpt_account_is_fedramp": is_fedramp,
                    "chatgpt_plan_type": "plus"
                }
            })),
            1,
        )
        .expect("credentials")
    }

    fn jwt(payload: Value) -> String {
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("encode JWT payload"));
        format!("e30.{payload}.sig")
    }

    fn header(headers: &reqwest::header::HeaderMap, name: &str) -> String {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }

    async fn spawn_server(router: Router) -> (String, JoinHandle<std::io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock upstream");
        let address = listener.local_addr().expect("mock upstream address");
        let handle = tokio::spawn(async move { axum::serve(listener, router).await });
        (format!("http://{address}"), handle)
    }
}
