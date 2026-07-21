use std::sync::Arc;

use futures_util::TryStreamExt;
use provider_core::{ProviderError, ProviderErrorKind, ProviderStream, RequestMetadata};
use reqwest::StatusCode;
use secrecy::ExposeSecret;

use super::{
    credentials::GrokCredentials,
    identity::{DEFAULT_PROXY_BASE_URL, inference_headers},
};

const CONVERSATION_ID_HEADER: &str = "x-grok-conv-id";

/// HTTP client for the Grok CLI Responses upstream.
#[derive(Clone)]
pub struct GrokClient {
    http: reqwest::Client,
    base_url: String,
    agent_id: Arc<str>,
}

impl Default for GrokClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GrokClient {
    #[must_use]
    pub fn new() -> Self {
        Self::with_base_url(DEFAULT_PROXY_BASE_URL)
    }

    pub async fn execute_stream(
        &self,
        credentials: &GrokCredentials,
        payload: bytes::Bytes,
        model: &str,
        metadata: &RequestMetadata,
    ) -> Result<ProviderStream, ProviderError> {
        let user_id = credentials.upstream_user_id().ok_or_else(|| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "Grok credential is missing upstream user ID",
            )
        })?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let generated_session_id = uuid::Uuid::new_v4().to_string();
        let session_id = metadata
            .session_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&generated_session_id);
        let request = inference_headers(
            self.http
                .post(format!("{}/responses", self.base_url))
                .bearer_auth(credentials.access_token().expose_secret())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::ACCEPT, "text/event-stream"),
        )
        .header("x-grok-user-id", user_id)
        .header(CONVERSATION_ID_HEADER, session_id)
        .header("x-grok-req-id", request_id)
        .header("x-grok-model-override", model)
        .header("x-grok-session-id", session_id)
        .header("x-grok-agent-id", self.agent_id.as_ref())
        .body(payload);

        let response = request.send().await.map_err(|error| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                format!("Grok upstream request failed: {error}"),
            )
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(status_error(status));
        }

        let stream = response.bytes_stream().map_err(|error| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                format!("Grok upstream stream failed: {error}"),
            )
        });

        Ok(Box::pin(stream))
    }

    pub(crate) fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            agent_id: Arc::from(uuid::Uuid::new_v4().to_string()),
        }
    }
}

fn status_error(status: StatusCode) -> ProviderError {
    let kind = match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            ProviderErrorKind::InvalidRequest
        }
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => ProviderErrorKind::Authentication,
        StatusCode::TOO_MANY_REQUESTS => ProviderErrorKind::RateLimited,
        _ => ProviderErrorKind::Upstream,
    };

    ProviderError::new(kind, format!("Grok upstream returned HTTP {status}"))
        .with_upstream_status(status.as_u16())
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
    use futures_util::{StreamExt, stream};
    use tokio::{net::TcpListener, task::JoinHandle};

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct CapturedRequest {
        authorization: String,
        token_auth: String,
        client_version: String,
        user_agent: String,
        conversation_id: String,
        authenticate_response: String,
        client_mode: String,
        client_identifier: String,
        user_id: String,
        request_id: String,
        model_override: String,
        session_id: String,
        agent_id: String,
        connection: String,
        body: Bytes,
    }

    type Capture = Arc<Mutex<Option<CapturedRequest>>>;

    async fn streaming_handler(State(capture): State<Capture>, request: Request) -> Response<Body> {
        let headers = request.headers().clone();
        let body = to_bytes(request.into_body(), usize::MAX)
            .await
            .expect("request body");

        *capture.lock().expect("capture lock") = Some(CapturedRequest {
            authorization: header(&headers, reqwest::header::AUTHORIZATION.as_str()),
            token_auth: header(&headers, "x-xai-token-auth"),
            client_version: header(&headers, "x-grok-client-version"),
            user_agent: header(&headers, reqwest::header::USER_AGENT.as_str()),
            conversation_id: header(&headers, CONVERSATION_ID_HEADER),
            authenticate_response: header(&headers, "x-authenticateresponse"),
            client_mode: header(&headers, "x-grok-client-mode"),
            client_identifier: header(&headers, "x-grok-client-identifier"),
            user_id: header(&headers, "x-grok-user-id"),
            request_id: header(&headers, "x-grok-req-id"),
            model_override: header(&headers, "x-grok-model-override"),
            session_id: header(&headers, "x-grok-session-id"),
            agent_id: header(&headers, "x-grok-agent-id"),
            connection: header(&headers, reqwest::header::CONNECTION.as_str()),
            body,
        });

        let chunks = stream::iter([
            Ok::<_, std::convert::Infallible>(Bytes::from_static(
                b"event: response.created\ndata: {}\n\n",
            )),
            Ok(Bytes::from_static(
                b"event: response.completed\ndata: {}\n\n",
            )),
        ]);

        Response::builder()
            .header(reqwest::header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(chunks))
            .expect("streaming response")
    }

    async fn unauthorized_handler() -> StatusCode {
        StatusCode::UNAUTHORIZED
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

        (format!("http://{address}/v1"), handle)
    }

    #[tokio::test]
    async fn sends_required_headers_and_streams_chunks() {
        let capture = Capture::default();
        let router = Router::new()
            .route("/v1/responses", post(streaming_handler))
            .with_state(capture.clone());
        let (base_url, server) = spawn_server(router).await;
        let client = GrokClient::with_base_url(base_url);
        let credentials = GrokCredentials::from_access_token("upstream-token");
        let payload = Bytes::from_static(br#"{"model":"grok-4.5","stream":true}"#);
        let mut metadata = RequestMetadata::default();
        metadata.session_id = Some("session-1".to_owned());

        let chunks = client
            .execute_stream(&credentials, payload.clone(), "grok-4.5", &metadata)
            .await
            .expect("stream response")
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("stream chunks");

        server.abort();

        let captured = capture
            .lock()
            .expect("capture lock")
            .clone()
            .expect("captured request");
        assert_eq!(captured.authorization, "Bearer upstream-token");
        assert_eq!(captured.token_auth, "xai-grok-cli");
        assert_eq!(captured.client_version, "0.2.105");
        assert!(captured.user_agent.starts_with("grok-shell/0.2.105 ("));
        assert_eq!(captured.conversation_id, "session-1");
        assert_eq!(captured.authenticate_response, "authenticate-response");
        assert_eq!(captured.client_mode, "headless");
        assert_eq!(captured.client_identifier, "grok-shell");
        assert_eq!(captured.user_id, "test-user");
        assert!(!captured.request_id.is_empty());
        assert_eq!(captured.model_override, "grok-4.5");
        assert_eq!(captured.session_id, "session-1");
        assert!(!captured.agent_id.is_empty());
        assert!(captured.connection.is_empty());
        assert_eq!(captured.body, payload);
        assert_eq!(chunks.len(), 2);
    }

    #[tokio::test]
    async fn maps_unauthorized_status_without_response_body() {
        let router = Router::new().route("/v1/responses", post(unauthorized_handler));
        let (base_url, server) = spawn_server(router).await;
        let client = GrokClient::with_base_url(base_url);
        let credentials = GrokCredentials::from_access_token("upstream-token");

        let error = match client
            .execute_stream(
                &credentials,
                Bytes::from_static(b"{}"),
                "grok-4.5",
                &RequestMetadata::default(),
            )
            .await
        {
            Ok(_) => panic!("expected unauthorized response"),
            Err(error) => error,
        };

        server.abort();

        assert_eq!(error.kind(), ProviderErrorKind::Authentication);
        assert_eq!(
            error.message(),
            "Grok upstream returned HTTP 401 Unauthorized"
        );
        assert!(!error.message().contains("upstream-token"));
    }
}
