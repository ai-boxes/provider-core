use futures_util::TryStreamExt;
use provider_core::{ProviderError, ProviderErrorKind, ProviderStream, RequestMetadata};
use reqwest::StatusCode;
use secrecy::ExposeSecret;

use crate::GrokCredentials;

const DEFAULT_BASE_URL: &str = "https://cli-chat-proxy.grok.com/v1";
const CLIENT_VERSION: &str = "0.2.93";
const TOKEN_AUTH_HEADER: &str = "X-XAI-Token-Auth";
const TOKEN_AUTH_VALUE: &str = "xai-grok-cli";
const CLIENT_VERSION_HEADER: &str = "x-grok-client-version";
const CONVERSATION_ID_HEADER: &str = "x-grok-conv-id";

/// HTTP client for the Grok CLI Responses upstream.
#[derive(Clone)]
pub struct GrokClient {
    credentials: GrokCredentials,
    http: reqwest::Client,
    base_url: String,
}

impl GrokClient {
    #[must_use]
    pub fn new(credentials: GrokCredentials) -> Self {
        Self::with_base_url(credentials, DEFAULT_BASE_URL)
    }

    pub async fn execute_stream(
        &self,
        payload: bytes::Bytes,
        metadata: &RequestMetadata,
    ) -> Result<ProviderStream, ProviderError> {
        let mut request = self
            .http
            .post(format!("{}/responses", self.base_url))
            .bearer_auth(self.credentials.access_token().expose_secret())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .header(reqwest::header::CONNECTION, "Keep-Alive")
            .header(TOKEN_AUTH_HEADER, TOKEN_AUTH_VALUE)
            .header(CLIENT_VERSION_HEADER, CLIENT_VERSION)
            .header(
                reqwest::header::USER_AGENT,
                format!("xai-grok-workspace/{CLIENT_VERSION}"),
            )
            .body(payload);

        if let Some(session_id) = metadata
            .session_id
            .as_deref()
            .map(str::trim)
            .filter(|session_id| !session_id.is_empty())
        {
            request = request.header(CONVERSATION_ID_HEADER, session_id);
        }

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

    pub(crate) fn with_base_url(credentials: GrokCredentials, base_url: impl Into<String>) -> Self {
        Self {
            credentials,
            http: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        }
    }
}

fn status_error(status: StatusCode) -> ProviderError {
    let kind = match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            ProviderErrorKind::InvalidRequest
        }
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => ProviderErrorKind::Authentication,
        _ => ProviderErrorKind::Upstream,
    };

    ProviderError::new(kind, format!("Grok upstream returned HTTP {status}"))
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
            token_auth: header(&headers, TOKEN_AUTH_HEADER),
            client_version: header(&headers, CLIENT_VERSION_HEADER),
            user_agent: header(&headers, reqwest::header::USER_AGENT.as_str()),
            conversation_id: header(&headers, CONVERSATION_ID_HEADER),
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
        let client = GrokClient::with_base_url(
            GrokCredentials::from_access_token("upstream-token"),
            base_url,
        );
        let payload = Bytes::from_static(br#"{"model":"grok-4.5","stream":true}"#);
        let mut metadata = RequestMetadata::default();
        metadata.session_id = Some("session-1".to_owned());

        let chunks = client
            .execute_stream(payload.clone(), &metadata)
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
        assert_eq!(captured.token_auth, TOKEN_AUTH_VALUE);
        assert_eq!(captured.client_version, CLIENT_VERSION);
        assert_eq!(
            captured.user_agent,
            format!("xai-grok-workspace/{CLIENT_VERSION}")
        );
        assert_eq!(captured.conversation_id, "session-1");
        assert_eq!(captured.body, payload);
        assert_eq!(chunks.len(), 2);
    }

    #[tokio::test]
    async fn maps_unauthorized_status_without_response_body() {
        let router = Router::new().route("/v1/responses", post(unauthorized_handler));
        let (base_url, server) = spawn_server(router).await;
        let client = GrokClient::with_base_url(
            GrokCredentials::from_access_token("upstream-token"),
            base_url,
        );

        let error = match client
            .execute_stream(Bytes::from_static(b"{}"), &RequestMetadata::default())
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
