use provider_core::{RefreshError, RefreshErrorKind};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::GrokCredentials;

const XAI_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
const MAX_TOKEN_RESPONSE_SIZE: usize = 64 * 1024;

#[derive(Clone)]
pub(crate) struct GrokRefreshClient {
    http: reqwest::Client,
    allow_insecure_endpoint: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct RefreshedGrokTokens {
    pub(crate) access_token: SecretString,
    pub(crate) refresh_token: Option<SecretString>,
    pub(crate) id_token: Option<SecretString>,
    pub(crate) token_type: Option<String>,
    pub(crate) expires_in: u32,
}

impl GrokRefreshClient {
    pub(crate) fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            allow_insecure_endpoint: false,
        }
    }

    pub(crate) async fn refresh(
        &self,
        credentials: &GrokCredentials,
    ) -> Result<RefreshedGrokTokens, RefreshError> {
        let refresh_token = credentials.refresh_token().ok_or_else(|| {
            RefreshError::new(
                RefreshErrorKind::ReauthRequired,
                "Grok credential is missing refresh_token",
            )
        })?;
        let token_endpoint = credentials.token_endpoint().ok_or_else(|| {
            RefreshError::new(
                RefreshErrorKind::ReauthRequired,
                "Grok credential is missing token_endpoint",
            )
        })?;
        validate_token_endpoint(token_endpoint, self.allow_insecure_endpoint)?;

        let response = self
            .http
            .post(token_endpoint)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", XAI_CLIENT_ID),
                ("refresh_token", refresh_token.expose_secret()),
            ])
            .send()
            .await
            .map_err(|_| {
                RefreshError::new(
                    RefreshErrorKind::Transient,
                    "Grok token refresh request failed",
                )
            })?;
        let status = response.status();
        let body = response.bytes().await.map_err(|_| {
            RefreshError::new(
                RefreshErrorKind::Transient,
                "failed to read Grok token refresh response",
            )
        })?;
        if body.len() > MAX_TOKEN_RESPONSE_SIZE {
            return Err(RefreshError::new(
                RefreshErrorKind::Transient,
                "Grok token refresh response was too large",
            ));
        }

        if !status.is_success() {
            let error_code = serde_json::from_slice::<OAuthErrorResponse>(&body)
                .ok()
                .and_then(|response| response.error);
            let kind = match error_code.as_deref() {
                Some("invalid_grant" | "invalid_token") => RefreshErrorKind::ReauthRequired,
                _ if status.as_u16() == 401 => RefreshErrorKind::ReauthRequired,
                _ if status.as_u16() == 429 || status.is_server_error() => {
                    RefreshErrorKind::Transient
                }
                _ => RefreshErrorKind::Internal,
            };
            return Err(RefreshError::new(
                kind,
                format!("Grok token refresh returned HTTP {status}"),
            ));
        }

        let response: TokenResponse = serde_json::from_slice(&body).map_err(|_| {
            RefreshError::new(
                RefreshErrorKind::Transient,
                "Grok token refresh returned invalid JSON",
            )
        })?;
        let access_token = non_empty_secret(response.access_token).ok_or_else(|| {
            RefreshError::new(
                RefreshErrorKind::Transient,
                "Grok token refresh response is missing access_token",
            )
        })?;
        let expires_in = u32::try_from(response.expires_in)
            .ok()
            .filter(|expires_in| *expires_in > 0)
            .ok_or_else(|| {
                RefreshError::new(
                    RefreshErrorKind::Transient,
                    "Grok token refresh response has invalid expires_in",
                )
            })?;

        Ok(RefreshedGrokTokens {
            access_token,
            refresh_token: non_empty_secret(response.refresh_token),
            id_token: non_empty_secret(response.id_token),
            token_type: non_empty_string(response.token_type),
            expires_in,
        })
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            http: reqwest::Client::new(),
            allow_insecure_endpoint: true,
        }
    }
}

fn validate_token_endpoint(endpoint: &str, allow_insecure: bool) -> Result<(), RefreshError> {
    let endpoint = reqwest::Url::parse(endpoint).map_err(|_| {
        RefreshError::new(RefreshErrorKind::Internal, "Grok token_endpoint is invalid")
    })?;
    let host = endpoint.host_str().unwrap_or_default().to_ascii_lowercase();
    let secure_xai = endpoint.scheme() == "https" && (host == "x.ai" || host.ends_with(".x.ai"));
    let local_test = allow_insecure
        && endpoint.scheme() == "http"
        && matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1");
    if !secure_xai && !local_test {
        return Err(RefreshError::new(
            RefreshErrorKind::Internal,
            "Grok token_endpoint must use HTTPS on an x.ai host",
        ));
    }
    Ok(())
}

fn non_empty_secret(value: Option<String>) -> Option<SecretString> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(SecretString::from)
}

fn non_empty_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: Option<String>,
    #[serde(default)]
    expires_in: i64,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{Router, extract::State, http::StatusCode, routing::post};
    use secrecy::ExposeSecret;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn sends_refresh_form_and_returns_rotated_tokens() {
        let captured = Arc::new(Mutex::new(String::new()));
        let app = Router::new()
            .route(
                "/token",
                post(
                    |State(captured): State<Arc<Mutex<String>>>, body: String| async move {
                        *captured.lock().expect("capture lock") = body;
                        r#"{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}"#
                    },
                ),
            )
            .with_state(captured.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock token endpoint");
        let address = listener.local_addr().expect("mock token address");
        let server = tokio::spawn(axum::serve(listener, app).into_future());
        let credentials = GrokCredentials::from_json(&SecretString::from(format!(
            r#"{{"type":"xai","auth_kind":"oauth","access_token":"old-access","refresh_token":"old refresh","token_endpoint":"http://{address}/token"}}"#
        )))
        .expect("credentials");

        let refreshed = GrokRefreshClient::for_test()
            .refresh(&credentials)
            .await
            .expect("refreshed tokens");
        server.abort();

        assert_eq!(refreshed.access_token.expose_secret(), "new-access");
        assert_eq!(
            refreshed
                .refresh_token
                .as_ref()
                .expect("rotated refresh token")
                .expose_secret(),
            "new-refresh"
        );
        let body = captured.lock().expect("captured form");
        assert!(body.contains("grant_type=refresh_token"));
        assert!(body.contains("client_id="));
        assert!(body.contains("refresh_token=old+refresh"));
    }

    #[tokio::test]
    async fn refresh_error_does_not_echo_response_body() {
        let app = Router::new().route(
            "/token",
            post(|| async {
                (
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"invalid_grant","error_description":"do-not-log"}"#,
                )
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock token endpoint");
        let address = listener.local_addr().expect("mock token address");
        let server = tokio::spawn(axum::serve(listener, app).into_future());
        let credentials = GrokCredentials::from_json(&SecretString::from(format!(
            r#"{{"type":"xai","auth_kind":"oauth","access_token":"old-access","refresh_token":"old-refresh","token_endpoint":"http://{address}/token"}}"#
        )))
        .expect("credentials");

        let error = GrokRefreshClient::for_test()
            .refresh(&credentials)
            .await
            .expect_err("invalid refresh token");
        server.abort();

        assert_eq!(error.kind(), RefreshErrorKind::ReauthRequired);
        assert!(!error.message().contains("do-not-log"));
        assert!(!error.message().contains("old-refresh"));
    }
}
