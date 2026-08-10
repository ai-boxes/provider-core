use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use provider_core::{
    BoundedBodyError, PendingProviderOAuth, ProviderConfigurationError, ProviderOAuthChallenge,
    StartedProviderOAuth, collect_bounded_body,
};
use secrecy::SecretString;
use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::quota::GrokQuotaClient;
use super::refresh::validate_oauth_endpoint;

const DISCOVERY_URL: &str = "https://auth.x.ai/.well-known/openid-configuration";
const CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
const SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_API_BASE_URL: &str = "https://api.x.ai/v1";
const DEFAULT_POLL_INTERVAL_SECONDS: u64 = 5;
const MAX_RESPONSE_SIZE: usize = 64 * 1024;

#[derive(Clone)]
pub(crate) struct GrokOAuthClient {
    http: reqwest::Client,
    discovery_url: String,
    quota_client: GrokQuotaClient,
    allow_insecure_endpoint: bool,
}

impl GrokOAuthClient {
    pub(crate) fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            discovery_url: DISCOVERY_URL.to_owned(),
            quota_client: GrokQuotaClient::new(),
            allow_insecure_endpoint: false,
        }
    }

    pub(crate) async fn start(&self) -> Result<StartedProviderOAuth, ProviderConfigurationError> {
        let discovery: DiscoveryResponse = self
            .get_json(&self.discovery_url, "Grok OAuth discovery")
            .await?;
        validate_oauth_endpoint(
            &discovery.device_authorization_endpoint,
            "device_authorization_endpoint",
            self.allow_insecure_endpoint,
        )
        .map_err(|error| ProviderConfigurationError::new(error.message()))?;
        validate_oauth_endpoint(
            &discovery.token_endpoint,
            "token_endpoint",
            self.allow_insecure_endpoint,
        )
        .map_err(|error| ProviderConfigurationError::new(error.message()))?;

        let response = self
            .http
            .post(&discovery.device_authorization_endpoint)
            .form(&[("client_id", CLIENT_ID), ("scope", SCOPE)])
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| {
                ProviderConfigurationError::new("Grok device authorization request failed")
            })?;
        let response: DeviceCodeResponse =
            response_json(response, "Grok device authorization").await?;
        let device_code = required(response.device_code, "device_code")?;
        let user_code = required(response.user_code, "user_code")?;
        let verification_uri = response
            .verification_uri
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .or_else(|| {
                response
                    .verification_uri_complete
                    .as_deref()
                    .and_then(verification_base_uri)
            })
            .ok_or_else(|| {
                ProviderConfigurationError::new(
                    "Grok device authorization response is missing verification_uri",
                )
            })?;
        let verification_uri_complete = response
            .verification_uri_complete
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let expires_in = u64::try_from(response.expires_in)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                ProviderConfigurationError::new(
                    "Grok device authorization response has invalid expires_in",
                )
            })?;
        let interval_seconds = u64::try_from(response.interval)
            .ok()
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_POLL_INTERVAL_SECONDS)
            .max(DEFAULT_POLL_INTERVAL_SECONDS);
        let expires_at = unix_timestamp()
            .checked_add(i64::try_from(expires_in).map_err(|_| {
                ProviderConfigurationError::new("Grok device authorization expiry is too large")
            })?)
            .ok_or_else(|| {
                ProviderConfigurationError::new("Grok device authorization expiry is too large")
            })?;

        Ok(StartedProviderOAuth {
            challenge: ProviderOAuthChallenge {
                verification_uri,
                verification_uri_complete,
                user_code,
                expires_at,
                interval_seconds,
            },
            pending: Box::new(GrokPendingOAuth {
                http: self.http.clone(),
                token_endpoint: discovery.token_endpoint,
                quota_client: self.quota_client.clone(),
                device_code,
                interval_seconds,
                expires_at,
            }),
        })
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        operation: &str,
    ) -> Result<T, ProviderConfigurationError> {
        let response = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| ProviderConfigurationError::new(format!("{operation} request failed")))?;
        response_json(response, operation).await
    }

    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn for_test(
        discovery_url: impl Into<String>,
        proxy_base_url: impl Into<String>,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            discovery_url: discovery_url.into(),
            quota_client: GrokQuotaClient::with_base_url(proxy_base_url),
            allow_insecure_endpoint: true,
        }
    }
}

struct GrokPendingOAuth {
    http: reqwest::Client,
    token_endpoint: String,
    quota_client: GrokQuotaClient,
    device_code: String,
    interval_seconds: u64,
    expires_at: i64,
}

#[async_trait]
impl PendingProviderOAuth for GrokPendingOAuth {
    async fn complete(self: Box<Self>) -> Result<SecretString, ProviderConfigurationError> {
        let mut interval = self.interval_seconds;
        let mut first_attempt = true;
        loop {
            if unix_timestamp() >= self.expires_at {
                return Err(ProviderConfigurationError::new(
                    "Grok device authorization expired",
                ));
            }
            if !first_attempt {
                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
            first_attempt = false;

            let response = self
                .http
                .post(&self.token_endpoint)
                .form(&[
                    ("grant_type", DEVICE_GRANT_TYPE),
                    ("device_code", self.device_code.as_str()),
                    ("client_id", CLIENT_ID),
                ])
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|_| ProviderConfigurationError::new("Grok device token request failed"))?;
            let status = response.status();
            let body = collect_bounded_body(response.bytes_stream(), MAX_RESPONSE_SIZE)
                .await
                .map_err(|error| match error {
                    BoundedBodyError::Read(_) => {
                        ProviderConfigurationError::new("failed to read Grok device token response")
                    }
                    BoundedBodyError::TooLarge => {
                        ProviderConfigurationError::new("Grok device token response was too large")
                    }
                })?;
            let token: DeviceTokenResponse = serde_json::from_slice(&body).map_err(|_| {
                ProviderConfigurationError::new("Grok device token response was invalid JSON")
            })?;
            if let Some(error) = token.error.as_deref() {
                match error {
                    "authorization_pending" => continue,
                    "slow_down" => {
                        interval = interval.saturating_add(DEFAULT_POLL_INTERVAL_SECONDS);
                        continue;
                    }
                    "expired_token" => {
                        return Err(ProviderConfigurationError::new(
                            "Grok device authorization expired",
                        ));
                    }
                    "access_denied" => {
                        return Err(ProviderConfigurationError::new(
                            "Grok device authorization was denied",
                        ));
                    }
                    _ => {
                        return Err(ProviderConfigurationError::new(format!(
                            "Grok device token request failed with OAuth error {error}"
                        )));
                    }
                }
            }
            if !status.is_success() {
                return Err(ProviderConfigurationError::new(format!(
                    "Grok device token request returned HTTP {status}"
                )));
            }

            let access_token = required(token.access_token, "access_token")?;
            let refresh_token = required(token.refresh_token, "refresh_token")?;
            let upstream_user_id = self
                .quota_client
                .fetch_user_id_with_access_token(&access_token)
                .await
                .ok();
            let refreshed_at = unix_timestamp();
            let expires_in = u64::try_from(token.expires_in)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    ProviderConfigurationError::new(
                        "Grok device token response has invalid expires_in",
                    )
                })?;
            let expired_at = refreshed_at
                .checked_add(i64::try_from(expires_in).map_err(|_| {
                    ProviderConfigurationError::new("Grok token expiry is too large")
                })?)
                .ok_or_else(|| ProviderConfigurationError::new("Grok token expiry is too large"))?;
            let document = serde_json::json!({
                "type": "xai",
                "auth_kind": "oauth",
                "access_token": access_token,
                "refresh_token": refresh_token,
                "upstream_user_id": upstream_user_id,
                "id_token": token.id_token.filter(|value| !value.trim().is_empty()),
                "token_type": token.token_type.filter(|value| !value.trim().is_empty()),
                "expires_in": expires_in,
                "expired": timestamp_rfc3339(expired_at)?,
                "last_refresh": timestamp_rfc3339(refreshed_at)?,
                "base_url": DEFAULT_API_BASE_URL,
                "token_endpoint": self.token_endpoint,
                "disabled": false
            });
            return serde_json::to_string(&document)
                .map(SecretString::from)
                .map_err(|_| {
                    ProviderConfigurationError::new("failed to serialize Grok OAuth credential")
                });
        }
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
            ProviderConfigurationError::new(format!("Grok OAuth response is missing {field}"))
        })
}

fn verification_base_uri(value: &str) -> Option<String> {
    let mut url = reqwest::Url::parse(value.trim()).ok()?;
    url.set_query(None);
    Some(url.to_string())
}

fn timestamp_rfc3339(timestamp: i64) -> Result<String, ProviderConfigurationError> {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| ProviderConfigurationError::new("Grok OAuth timestamp is out of range"))?
        .format(&Rfc3339)
        .map_err(|_| ProviderConfigurationError::new("Grok OAuth timestamp is out of range"))
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct DiscoveryResponse {
    device_authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    verification_uri_complete: Option<String>,
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    interval: i64,
}

#[derive(Deserialize)]
struct DeviceTokenResponse {
    error: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: Option<String>,
    #[serde(default)]
    expires_in: i64,
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        routing::{get, post},
    };
    use secrecy::ExposeSecret;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn completes_device_flow_into_importable_grok_credential() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind OAuth endpoint");
        let address = listener.local_addr().expect("OAuth endpoint address");
        let base_url = format!("http://{address}");
        let discovery_body = json_string(serde_json::json!({
            "device_authorization_endpoint": format!("{base_url}/device"),
            "token_endpoint": format!("{base_url}/token")
        }));
        let app = Router::new()
            .route(
                "/discovery",
                get(move || {
                    let body = discovery_body.clone();
                    async move { body }
                }),
            )
            .route(
                "/device",
                post(|| async {
                    r#"{"device_code":"device-1","user_code":"CODE-1","verification_uri":"https://accounts.x.ai/device","verification_uri_complete":"https://accounts.x.ai/device?user_code=CODE-1","expires_in":600,"interval":1}"#
                }),
            )
            .route(
                "/token",
                post(|| async {
                    r#"{"access_token":"access-secret","refresh_token":"refresh-secret","id_token":"id-secret","token_type":"Bearer","expires_in":3600}"#
                }),
            )
            .route(
                "/user",
                get(|| async { r#"{"userId":"oauth-user"}"# }),
            );
        let server = tokio::spawn(axum::serve(listener, app).into_future());

        let started = GrokOAuthClient::for_test(format!("{base_url}/discovery"), base_url.clone())
            .start()
            .await
            .expect("start OAuth");
        assert_eq!(started.challenge.user_code, "CODE-1");
        assert_eq!(started.challenge.interval_seconds, 5);

        let credential = started.pending.complete().await.expect("complete OAuth");
        server.abort();
        let document: serde_json::Value =
            serde_json::from_str(credential.expose_secret()).expect("credential document");
        assert_eq!(document["type"], "xai");
        assert_eq!(document["auth_kind"], "oauth");
        assert_eq!(document["access_token"], "access-secret");
        assert_eq!(document["refresh_token"], "refresh-secret");
        assert_eq!(document["upstream_user_id"], "oauth-user");
        assert_eq!(document["base_url"], DEFAULT_API_BASE_URL);
        assert_eq!(document["token_endpoint"], format!("{base_url}/token"));
    }

    fn json_string(value: serde_json::Value) -> String {
        value.to_string()
    }
}
