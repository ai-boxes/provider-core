use std::time::Duration;

use futures_util::StreamExt;
use provider_core::{RefreshError, RefreshErrorKind};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::Value;

use super::{
    credentials::CodexCredentials,
    identity::{CLIENT_ID, DEFAULT_AUTH_ISSUER, oauth_headers, secret},
};

const MAX_RESPONSE_SIZE: usize = 64 * 1024;
const REFRESH_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub(crate) struct CodexRefreshClient {
    http: reqwest::Client,
    token_endpoint: String,
}

#[derive(Clone)]
pub(crate) struct RefreshedCodexTokens {
    pub(crate) access_token: Option<SecretString>,
    pub(crate) refresh_token: Option<SecretString>,
    pub(crate) id_token: Option<SecretString>,
}

impl CodexRefreshClient {
    pub(crate) fn new() -> Self {
        Self::with_issuer(DEFAULT_AUTH_ISSUER)
    }

    pub(crate) fn with_issuer(issuer: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            token_endpoint: format!("{}/oauth/token", issuer.trim_end_matches('/')),
        }
    }

    pub(crate) async fn refresh(
        &self,
        credentials: &CodexCredentials,
    ) -> Result<RefreshedCodexTokens, RefreshError> {
        let body = serde_json::to_vec(&serde_json::json!({
            "client_id": CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": credentials.refresh_token().expose_secret(),
        }))
        .map_err(|_| {
            RefreshError::new(
                RefreshErrorKind::Internal,
                "failed to encode Codex refresh request",
            )
        })?;
        let response = oauth_headers(
            self.http
                .post(&self.token_endpoint)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .timeout(REFRESH_TIMEOUT)
                .body(body),
        )
        .send()
        .await
        .map_err(|_| {
            RefreshError::new(
                RefreshErrorKind::Transient,
                "Codex token refresh request failed",
            )
        })?;
        let status = response.status();
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| {
                RefreshError::new(
                    RefreshErrorKind::Transient,
                    "failed to read Codex token refresh response",
                )
            })?;
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_SIZE {
                return Err(RefreshError::new(
                    RefreshErrorKind::Transient,
                    "Codex token refresh response was too large",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let code = reviewed_error_code(&body);
            let kind = if status == reqwest::StatusCode::UNAUTHORIZED
                || matches!(
                    code.as_deref(),
                    Some(
                        "refresh_token_expired"
                            | "refresh_token_reused"
                            | "refresh_token_invalidated"
                    )
                ) {
                RefreshErrorKind::ReauthRequired
            } else {
                RefreshErrorKind::Transient
            };
            return Err(RefreshError::new(
                kind,
                format!("Codex token refresh returned HTTP {status}"),
            ));
        }
        let response: TokenResponse = serde_json::from_slice(&body).map_err(|_| {
            RefreshError::new(
                RefreshErrorKind::Transient,
                "Codex token refresh returned invalid JSON",
            )
        })?;
        Ok(RefreshedCodexTokens {
            access_token: response.access_token.and_then(secret),
            refresh_token: response.refresh_token.and_then(secret),
            id_token: response.id_token.and_then(secret),
        })
    }
}

fn reviewed_error_code(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value
        .get("error")
        .and_then(|error| match error {
            Value::String(code) => Some(code.as_str()),
            Value::Object(error) => error.get("code").and_then(Value::as_str),
            _ => None,
        })
        .or_else(|| value.get("code").and_then(Value::as_str))
        .map(str::to_owned)
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
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
    use tokio::{net::TcpListener, task::JoinHandle};

    use super::*;

    #[derive(Clone)]
    struct RefreshState {
        status: reqwest::StatusCode,
        response: String,
        capture: Arc<Mutex<Option<(reqwest::header::HeaderMap, Bytes)>>>,
    }

    async fn refresh_handler(
        State(state): State<RefreshState>,
        request: Request,
    ) -> Response<Body> {
        let headers = request.headers().clone();
        let body = to_bytes(request.into_body(), MAX_RESPONSE_SIZE)
            .await
            .expect("refresh request body");
        *state.capture.lock().expect("capture lock") = Some((headers, body));
        Response::builder()
            .status(state.status)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(Body::from(state.response))
            .expect("refresh response")
    }

    #[tokio::test]
    async fn sends_json_refresh_contract_with_truthful_headers() {
        let state = RefreshState {
            status: reqwest::StatusCode::OK,
            response: serde_json::json!({
                "access_token": "new-access-token",
                "refresh_token": "new-refresh-token"
            })
            .to_string(),
            capture: Arc::new(Mutex::new(None)),
        };
        let (issuer, server) = spawn_server(state.clone()).await;
        let tokens = CodexRefreshClient::with_issuer(&issuer)
            .refresh(&credentials())
            .await
            .expect("refresh tokens");
        server.abort();

        assert_eq!(
            tokens
                .access_token
                .as_ref()
                .map(|token| token.expose_secret()),
            Some("new-access-token")
        );
        assert_eq!(
            tokens
                .refresh_token
                .as_ref()
                .map(|token| token.expose_secret()),
            Some("new-refresh-token")
        );
        let (headers, body) = state
            .capture
            .lock()
            .expect("capture lock")
            .clone()
            .expect("captured refresh request");
        assert_eq!(header(&headers, "originator"), "codex_cli_rs");
        assert!(
            header(&headers, reqwest::header::USER_AGENT.as_str())
                .starts_with("codex_cli_rs/0.144.5 (")
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("refresh request JSON");
        assert_eq!(
            body,
            serde_json::json!({
                "client_id": CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": "refresh-token"
            })
        );
    }

    #[tokio::test]
    async fn classifies_known_refresh_failures_as_reauth_and_unknown_4xx_as_transient() {
        let permanent = RefreshState {
            status: reqwest::StatusCode::BAD_REQUEST,
            response: serde_json::json!({
                "error": {"code": "refresh_token_reused"}
            })
            .to_string(),
            capture: Arc::new(Mutex::new(None)),
        };
        let (issuer, server) = spawn_server(permanent).await;
        let error = match CodexRefreshClient::with_issuer(&issuer)
            .refresh(&credentials())
            .await
        {
            Ok(_) => panic!("reused token must require reauthorization"),
            Err(error) => error,
        };
        server.abort();
        assert_eq!(error.kind(), RefreshErrorKind::ReauthRequired);

        let transient = RefreshState {
            status: reqwest::StatusCode::BAD_REQUEST,
            response: serde_json::json!({"error": "temporarily_unavailable"}).to_string(),
            capture: Arc::new(Mutex::new(None)),
        };
        let (issuer, server) = spawn_server(transient).await;
        let error = match CodexRefreshClient::with_issuer(&issuer)
            .refresh(&credentials())
            .await
        {
            Ok(_) => panic!("unknown 4xx must remain retryable"),
            Err(error) => error,
        };
        server.abort();
        assert_eq!(error.kind(), RefreshErrorKind::Transient);
    }

    fn credentials() -> CodexCredentials {
        CodexCredentials::from_tokens(
            "access-token".to_owned(),
            "refresh-token".to_owned(),
            jwt(serde_json::json!({
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "workspace-1"
                }
            })),
            1,
        )
        .expect("credentials")
    }

    fn jwt(payload: serde_json::Value) -> String {
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

    async fn spawn_server(state: RefreshState) -> (String, JoinHandle<std::io::Result<()>>) {
        let router = Router::new()
            .route("/oauth/token", post(refresh_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind refresh mock");
        let address = listener.local_addr().expect("refresh mock address");
        let handle = tokio::spawn(async move { axum::serve(listener, router).await });
        (format!("http://{address}"), handle)
    }
}
