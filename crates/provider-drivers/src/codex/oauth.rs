use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

use async_trait::async_trait;
use provider_core::{
    BoundedBodyError, PendingProviderOAuth, ProviderConfigurationError, ProviderOAuthChallenge,
    StartedProviderOAuth, collect_bounded_body,
};
use secrecy::SecretString;
use serde::Deserialize;

use super::{
    credentials::CodexCredentials,
    identity::{CLIENT_ID, DEFAULT_AUTH_ISSUER, oauth_headers},
};

const DEVICE_TIMEOUT_SECONDS: i64 = 15 * 60;
const DEFAULT_POLL_INTERVAL_SECONDS: u64 = 5;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_SIZE: usize = 64 * 1024;

#[derive(Clone)]
pub(crate) struct CodexOAuthClient {
    http: reqwest::Client,
    issuer: String,
}

impl CodexOAuthClient {
    pub(crate) fn new() -> Self {
        Self::with_issuer(DEFAULT_AUTH_ISSUER)
    }

    pub(crate) fn with_issuer(issuer: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            issuer: issuer.trim_end_matches('/').to_owned(),
        }
    }

    pub(crate) async fn start(&self) -> Result<StartedProviderOAuth, ProviderConfigurationError> {
        let body =
            serde_json::to_vec(&serde_json::json!({ "client_id": CLIENT_ID })).map_err(|_| {
                ProviderConfigurationError::new(
                    "failed to encode Codex device authorization request",
                )
            })?;
        let response = oauth_headers(
            self.http
                .post(format!("{}/api/accounts/deviceauth/usercode", self.issuer))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .timeout(REQUEST_TIMEOUT)
                .body(body),
        )
        .send()
        .await
        .map_err(|_| {
            ProviderConfigurationError::new("Codex device authorization request failed")
        })?;
        let response: UserCodeResponse =
            response_json(response, "Codex device authorization").await?;
        let user_code = required(response.user_code, "user_code")?;
        let device_auth_id = required(response.device_auth_id, "device_auth_id")?;
        let interval_seconds = response
            .interval
            .and_then(parse_interval)
            .filter(|interval| *interval > 0)
            .unwrap_or(DEFAULT_POLL_INTERVAL_SECONDS);
        let expires_at = unix_timestamp()
            .checked_add(DEVICE_TIMEOUT_SECONDS)
            .ok_or_else(|| {
                ProviderConfigurationError::new("Codex device authorization expiry is too large")
            })?;
        let deadline = Instant::now() + Duration::from_secs(DEVICE_TIMEOUT_SECONDS as u64);
        let verification_uri = format!("{}/codex/device", self.issuer);

        Ok(StartedProviderOAuth {
            challenge: ProviderOAuthChallenge {
                verification_uri,
                verification_uri_complete: None,
                user_code: user_code.clone(),
                expires_at,
                interval_seconds,
            },
            pending: Box::new(CodexPendingOAuth {
                http: self.http.clone(),
                issuer: self.issuer.clone(),
                user_code,
                device_auth_id,
                deadline,
                interval_seconds,
            }),
        })
    }
}

struct CodexPendingOAuth {
    http: reqwest::Client,
    issuer: String,
    user_code: String,
    device_auth_id: String,
    deadline: Instant,
    interval_seconds: u64,
}

#[async_trait]
impl PendingProviderOAuth for CodexPendingOAuth {
    async fn complete(self: Box<Self>) -> Result<SecretString, ProviderConfigurationError> {
        let code: CodeResponse = loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProviderConfigurationError::new(
                    "Codex device authorization expired",
                ));
            }
            let request_timeout = REQUEST_TIMEOUT.min(remaining);
            let body = serde_json::to_vec(&serde_json::json!({
                "device_auth_id": self.device_auth_id,
                "user_code": self.user_code,
            }))
            .map_err(|_| {
                ProviderConfigurationError::new("failed to encode Codex device token request")
            })?;
            let response = oauth_headers(
                self.http
                    .post(format!("{}/api/accounts/deviceauth/token", self.issuer))
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .timeout(request_timeout)
                    .body(body),
            )
            .send()
            .await
            .map_err(|_| ProviderConfigurationError::new("Codex device token request failed"))?;
            if response.status().is_success() {
                break response_json(response, "Codex device token").await?;
            }
            if matches!(
                response.status(),
                reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::NOT_FOUND
            ) {
                let remaining = self.deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(ProviderConfigurationError::new(
                        "Codex device authorization expired",
                    ));
                }
                tokio::time::sleep(Duration::from_secs(self.interval_seconds).min(remaining)).await;
                continue;
            }
            return Err(ProviderConfigurationError::new(format!(
                "Codex device token request returned HTTP {}",
                response.status()
            )));
        };

        let authorization_code = required(code.authorization_code, "authorization_code")?;
        let code_verifier = required(code.code_verifier, "code_verifier")?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ProviderConfigurationError::new(
                "Codex device authorization expired",
            ));
        }
        let redirect_uri = format!("{}/deviceauth/callback", self.issuer);
        let response = oauth_headers(
            self.http
                .post(format!("{}/oauth/token", self.issuer))
                .timeout(REQUEST_TIMEOUT.min(remaining))
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", authorization_code.as_str()),
                    ("redirect_uri", redirect_uri.as_str()),
                    ("client_id", CLIENT_ID),
                    ("code_verifier", code_verifier.as_str()),
                ]),
        )
        .send()
        .await
        .map_err(|_| ProviderConfigurationError::new("Codex OAuth token exchange failed"))?;
        let tokens: TokenResponse = response_json(response, "Codex OAuth token exchange").await?;
        let refreshed_at = unix_timestamp();
        CodexCredentials::from_tokens(
            required(tokens.access_token, "access_token")?,
            required(tokens.refresh_token, "refresh_token")?,
            required(tokens.id_token, "id_token")?,
            refreshed_at,
        )
        .and_then(|credentials| credentials.to_json())
        .map_err(|error| ProviderConfigurationError::new(error.to_string()))
    }
}

async fn response_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    operation: &str,
) -> Result<T, ProviderConfigurationError> {
    let status = response.status();
    let body = collect_bounded_body(response.bytes_stream(), MAX_RESPONSE_SIZE)
        .await
        .map_err(|error| match error {
            BoundedBodyError::Read(_) => {
                ProviderConfigurationError::new(format!("failed to read {operation} response"))
            }
            BoundedBodyError::TooLarge => {
                ProviderConfigurationError::new(format!("{operation} response was too large"))
            }
        })?;
    if !status.is_success() {
        return Err(ProviderConfigurationError::new(format!(
            "{operation} returned HTTP {status}"
        )));
    }
    serde_json::from_slice(&body)
        .map_err(|_| ProviderConfigurationError::new(format!("{operation} returned invalid JSON")))
}

fn required(value: Option<String>, field: &str) -> Result<String, ProviderConfigurationError> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ProviderConfigurationError::new(format!("Codex OAuth response is missing {field}"))
        })
}

fn parse_interval(value: serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::String(value) => value.trim().parse().ok(),
        serde_json::Value::Number(value) => value.as_u64(),
        _ => None,
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct UserCodeResponse {
    device_auth_id: Option<String>,
    #[serde(alias = "usercode")]
    user_code: Option<String>,
    interval: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct CodeResponse {
    authorization_code: Option<String>,
    code_verifier: Option<String>,
    #[serde(default)]
    _code_challenge: Option<String>,
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
    use secrecy::ExposeSecret;
    use tokio::{net::TcpListener, task::JoinHandle};

    use super::*;

    #[derive(Clone)]
    struct OAuthState {
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        id_token: String,
    }

    #[derive(Clone)]
    struct CapturedRequest {
        path: String,
        headers: reqwest::header::HeaderMap,
        body: Bytes,
    }

    async fn oauth_handler(State(state): State<OAuthState>, request: Request) -> Response<Body> {
        let path = request.uri().path().to_owned();
        let headers = request.headers().clone();
        let body = to_bytes(request.into_body(), MAX_RESPONSE_SIZE)
            .await
            .expect("request body");
        state
            .requests
            .lock()
            .expect("request capture lock")
            .push(CapturedRequest {
                path: path.clone(),
                headers,
                body,
            });
        let body = match path.as_str() {
            "/api/accounts/deviceauth/usercode" => serde_json::json!({
                "device_auth_id": "device-1",
                "user_code": "CODE-1",
                "interval": "1"
            }),
            "/api/accounts/deviceauth/token" => serde_json::json!({
                "authorization_code": "auth-code",
                "code_challenge": "challenge",
                "code_verifier": "verifier"
            }),
            "/oauth/token" => serde_json::json!({
                "access_token": "opaque-access-token",
                "refresh_token": "refresh-token",
                "id_token": state.id_token
            }),
            _ => {
                return Response::builder()
                    .status(404)
                    .body(Body::empty())
                    .expect("404");
            }
        };
        Response::builder()
            .status(200)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("OAuth response")
    }

    #[tokio::test]
    async fn completes_official_device_flow_with_truthful_headers() {
        let state = OAuthState {
            requests: Arc::new(Mutex::new(Vec::new())),
            id_token: jwt(serde_json::json!({
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "workspace-1",
                    "chatgpt_account_is_fedramp": false,
                    "chatgpt_plan_type": "plus"
                }
            })),
        };
        let router = Router::new()
            .route("/api/accounts/deviceauth/usercode", post(oauth_handler))
            .route("/api/accounts/deviceauth/token", post(oauth_handler))
            .route("/oauth/token", post(oauth_handler))
            .with_state(state.clone());
        let (issuer, server) = spawn_server(router).await;
        let started = CodexOAuthClient::with_issuer(&issuer)
            .start()
            .await
            .expect("start device OAuth");

        assert_eq!(
            started.challenge.verification_uri,
            format!("{issuer}/codex/device")
        );
        assert_eq!(started.challenge.user_code, "CODE-1");
        assert_eq!(started.challenge.interval_seconds, 1);
        let credential_json = started
            .pending
            .complete()
            .await
            .expect("complete device OAuth");
        server.abort();

        let credential: serde_json::Value =
            serde_json::from_str(credential_json.expose_secret()).expect("credential JSON");
        assert_eq!(credential["type"], "codex");
        assert_eq!(credential["auth_kind"], "oauth");
        assert_eq!(credential["account_id"], "workspace-1");

        let requests = state.requests.lock().expect("request capture lock");
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].path, "/api/accounts/deviceauth/usercode");
        assert_eq!(requests[1].path, "/api/accounts/deviceauth/token");
        assert_eq!(requests[2].path, "/oauth/token");
        for request in requests.iter() {
            assert_eq!(header(&request.headers, "originator"), "codex_cli_rs");
            assert!(
                header(&request.headers, reqwest::header::USER_AGENT.as_str())
                    .starts_with("codex_cli_rs/0.144.5 (")
            );
        }
        let user_code: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("user-code request JSON");
        assert_eq!(user_code, serde_json::json!({ "client_id": CLIENT_ID }));
        let poll: serde_json::Value =
            serde_json::from_slice(&requests[1].body).expect("poll request JSON");
        assert_eq!(
            poll,
            serde_json::json!({
                "device_auth_id": "device-1",
                "user_code": "CODE-1"
            })
        );
        let exchange = String::from_utf8(requests[2].body.to_vec()).expect("exchange form");
        assert!(exchange.contains("grant_type=authorization_code"));
        assert!(exchange.contains("code=auth-code"));
        assert!(exchange.contains("client_id=app_EMoamEEZ73f0CkXaXp7hrann"));
        assert!(exchange.contains("code_verifier=verifier"));
        assert!(exchange.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A"));
        assert!(exchange.contains("%2Fdeviceauth%2Fcallback"));
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

    async fn spawn_server(router: Router) -> (String, JoinHandle<std::io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind OAuth mock");
        let address = listener.local_addr().expect("OAuth mock address");
        let handle = tokio::spawn(async move { axum::serve(listener, router).await });
        (format!("http://{address}"), handle)
    }
}
