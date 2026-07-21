use std::time::Duration;

use futures_util::{StreamExt, TryStreamExt};
use provider_core::{ProviderError, ProviderErrorKind, ProviderStream};
use reqwest::StatusCode;
use serde_json::Value;

use super::{
    credentials::CodexCredentials,
    identity::{DEFAULT_BACKEND_ROOT, responses_headers},
    quota::normalize_headers,
    request::PreparedCodexRequest,
};

const MAX_ERROR_RESPONSE_SIZE: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_HEADERS_TIMEOUT: Duration = Duration::from_secs(30);

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
            .map_err(|_| CodexClientFailure {
                error: ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "Codex upstream request failed",
                ),
                observed_groups: Vec::new(),
            })?;
        let status = response.status();
        let observed_groups = if status.is_success() || status == StatusCode::TOO_MANY_REQUESTS {
            normalize_headers(response.headers())
        } else {
            Vec::new()
        };
        if !status.is_success() {
            let error = status_error(response, status).await;
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

async fn status_error(response: reqwest::Response, status: StatusCode) -> ProviderError {
    let error_token = read_error_body(response)
        .await
        .and_then(|body| reviewed_error_token(&body));
    let rate_limited = error_token.as_deref().is_some_and(|token| {
        token.contains("rate_limit")
            || token.contains("usage_limit")
            || token.contains("credits_depleted")
            || token.contains("quota")
    });
    let kind = if rate_limited || status == StatusCode::TOO_MANY_REQUESTS {
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
    ProviderError::new(kind, format!("Codex upstream returned HTTP {status}"))
        .with_upstream_status(status.as_u16())
}

async fn read_error_body(response: reqwest::Response) -> Option<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ERROR_RESPONSE_SIZE as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if body.len().saturating_add(chunk.len()) > MAX_ERROR_RESPONSE_SIZE {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

fn reviewed_error_token(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let token = value
        .pointer("/error/code")
        .or_else(|| value.pointer("/error/type"))
        .or_else(|| value.get("code"))
        .or_else(|| value.get("error_type"))?
        .as_str()?
        .trim()
        .to_ascii_lowercase();
    (!token.is_empty()
        && token.len() <= 64
        && token
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-.".contains(character)))
    .then_some(token)
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
    use provider_core::RequestMetadata;
    use tokio::{net::TcpListener, task::JoinHandle};

    use super::*;
    use crate::codex::request::PreparedCodexRequest;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Option<(reqwest::header::HeaderMap, Bytes)>>>);

    async fn success_handler(State(capture): State<Capture>, request: Request) -> Response<Body> {
        let headers = request.headers().clone();
        let body = to_bytes(request.into_body(), 1024 * 1024)
            .await
            .expect("request body");
        *capture.0.lock().expect("capture lock") = Some((headers, body));
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
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("x-codex-primary-used-percent", "100")
            .header("x-codex-primary-window-minutes", "300")
            .header("x-codex-primary-reset-at", "5678")
            .body(Body::from(Bytes::from_static(
                br#"{"error":{"code":"usage_limit_reached"}}"#,
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
        let payload = Bytes::from_static(br#"{"model":"gpt-5.5","stream":true}"#);

        let response = client
            .execute_stream(
                &credentials,
                PreparedCodexRequest {
                    payload: payload.clone(),
                    metadata,
                },
            )
            .await;
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
        let (headers, captured_body) = capture
            .0
            .lock()
            .expect("capture lock")
            .clone()
            .expect("captured request");
        assert_eq!(
            header(&headers, reqwest::header::AUTHORIZATION.as_str()),
            "Bearer access-token"
        );
        assert_eq!(header(&headers, "chatgpt-account-id"), "workspace-1");
        assert_eq!(header(&headers, "x-openai-fedramp"), "true");
        assert_eq!(header(&headers, "originator"), "codex_cli_rs");
        assert!(headers.get("version").is_none());
        assert!(
            header(&headers, reqwest::header::USER_AGENT.as_str())
                .starts_with("codex_cli_rs/0.144.5 (")
        );
        assert_eq!(header(&headers, "session-id"), "session-1");
        assert_eq!(header(&headers, "thread-id"), "thread-1");
        assert_eq!(header(&headers, "x-client-request-id"), "thread-1");
        assert_eq!(captured_body, payload);
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
        assert_eq!(failure.observed_groups.len(), 1);
        assert_eq!(failure.observed_groups[0].key, "codex");
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
