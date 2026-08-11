use std::{collections::BTreeMap, sync::LazyLock, time::Duration};

use provider_core::{
    BoundedBodyError, DiscoveredProviderModel, ProviderError, ProviderErrorKind, ProviderModel,
    collect_bounded_body,
};
use secrecy::ExposeSecret;
use serde::Deserialize;

use super::credentials::GrokCredentials;

const DEFAULT_MODEL_BASE_URL: &str = "https://api.x.ai/v1";
const MAX_MODELS_RESPONSE_SIZE: usize = 2 * 1024 * 1024;

struct ModelDefinition {
    id: &'static str,
    created: u64,
}

const MODEL_DEFINITIONS: &[ModelDefinition] = &[
    ModelDefinition {
        id: "grok-build-0.1",
        created: 1_779_321_600,
    },
    ModelDefinition {
        id: "grok-4.5",
        created: 1_783_526_400,
    },
    ModelDefinition {
        id: "grok-4.3",
        created: 1_775_606_400,
    },
    ModelDefinition {
        id: "grok-4.20-0309-reasoning",
        created: 1_773_014_400,
    },
    ModelDefinition {
        id: "grok-4.20-0309-non-reasoning",
        created: 1_773_014_400,
    },
    ModelDefinition {
        id: "grok-4.20-multi-agent-0309",
        created: 1_773_014_400,
    },
    ModelDefinition {
        id: "grok-3-mini",
        created: 1_740_960_000,
    },
    ModelDefinition {
        id: "grok-3-mini-fast",
        created: 1_740_960_000,
    },
    ModelDefinition {
        id: "grok-composer-2.5-fast",
        created: 1_740_960_000,
    },
];

static MODELS: LazyLock<Vec<ProviderModel>> = LazyLock::new(|| {
    MODEL_DEFINITIONS
        .iter()
        .map(|definition| ProviderModel::new(definition.id, "xai").with_created(definition.created))
        .collect()
});

#[must_use]
pub fn grok_models() -> &'static [ProviderModel] {
    &MODELS
}

#[derive(Clone)]
pub(crate) struct GrokModelClient {
    http: reqwest::Client,
    allow_insecure_endpoint: bool,
}

impl GrokModelClient {
    pub(crate) fn new() -> Self {
        Self {
            http: model_http_client(),
            allow_insecure_endpoint: false,
        }
    }

    pub(crate) async fn discover(
        &self,
        credentials: &GrokCredentials,
    ) -> Result<Vec<DiscoveredProviderModel>, ProviderError> {
        let base_url = credentials.base_url().unwrap_or(DEFAULT_MODEL_BASE_URL);
        validate_model_base_url(base_url, self.allow_insecure_endpoint)?;
        let response = self
            .http
            .get(format!("{}/models", base_url.trim_end_matches('/')))
            .bearer_auth(credentials.access_token().expose_secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| {
                ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "Grok model discovery request failed",
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            let kind = match status.as_u16() {
                401 | 403 => ProviderErrorKind::Authentication,
                429 => ProviderErrorKind::RateLimited,
                _ => ProviderErrorKind::Upstream,
            };
            return Err(ProviderError::new(
                kind,
                format!("Grok model discovery returned HTTP {status}"),
            )
            .with_upstream_status(status.as_u16()));
        }
        let body = collect_bounded_body(response.bytes_stream(), MAX_MODELS_RESPONSE_SIZE)
            .await
            .map_err(|error| match error {
                BoundedBodyError::Read(_) => ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "failed to read Grok model discovery response",
                ),
                BoundedBodyError::TooLarge => ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "Grok model discovery response was too large",
                ),
            })?;
        let response: ModelsResponse = serde_json::from_slice(&body).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                "Grok model discovery returned invalid JSON",
            )
        })?;
        let mut models = BTreeMap::new();
        for model in response.data {
            let id = model.id.trim();
            if id.is_empty() {
                continue;
            }
            let mut provider_model = ProviderModel::new(
                id,
                model
                    .owned_by
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or("xai"),
            );
            if let Some(created) = model.created {
                provider_model = provider_model.with_created(created);
            }
            let metadata_json = serde_json::to_string(&provider_model).map_err(|_| {
                ProviderError::new(
                    ProviderErrorKind::Internal,
                    "failed to normalize Grok model metadata",
                )
            })?;
            models.insert(
                id.to_owned(),
                DiscoveredProviderModel {
                    upstream_model: id.to_owned(),
                    metadata_json,
                    routable: !id.starts_with("grok-imagine-"),
                    pricing: None,
                },
            );
        }
        Ok(models.into_values().collect())
    }

    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn for_test() -> Self {
        Self {
            http: model_http_client(),
            allow_insecure_endpoint: true,
        }
    }
}

fn model_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn validate_model_base_url(base_url: &str, allow_insecure: bool) -> Result<(), ProviderError> {
    let endpoint = reqwest::Url::parse(base_url).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok model base_url is invalid",
        )
    })?;
    let host = endpoint.host_str().unwrap_or_default().to_ascii_lowercase();
    let secure_xai = endpoint.scheme() == "https" && (host == "x.ai" || host.ends_with(".x.ai"));
    let local_test = allow_insecure
        && endpoint.scheme() == "http"
        && matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1");
    if !secure_xai && !local_test {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok model base_url must use HTTPS on an x.ai host",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct ModelsResponse {
    #[serde(default)]
    data: Vec<ModelResponse>,
}

#[derive(Deserialize)]
struct ModelResponse {
    id: String,
    created: Option<u64>,
    owned_by: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::get,
    };
    use secrecy::SecretString;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn maps_rate_limited_model_discovery() {
        let app = Router::new().route(
            "/v1/models",
            get(|| async { StatusCode::TOO_MANY_REQUESTS }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind model endpoint");
        let address = listener.local_addr().expect("model endpoint address");
        let server = tokio::spawn(axum::serve(listener, app).into_future());
        let credentials = GrokCredentials::from_json(&SecretString::from(format!(
            r#"{{"type":"xai","auth_kind":"oauth","access_token":"model-token","base_url":"http://{address}/v1"}}"#
        )))
        .expect("credentials");

        let error = match GrokModelClient::for_test().discover(&credentials).await {
            Ok(_) => panic!("429 model discovery must fail"),
            Err(error) => error,
        };
        server.abort();

        assert_eq!(error.kind(), ProviderErrorKind::RateLimited);
        assert_eq!(error.upstream_status(), Some(429));
    }

    #[tokio::test]
    async fn discovers_and_normalizes_remote_models() {
        let authorization = Arc::new(Mutex::new(String::new()));
        let app = Router::new()
            .route(
                "/v1/models",
                get(
                    |State(authorization): State<Arc<Mutex<String>>>, headers: HeaderMap| async move {
                        *authorization.lock().expect("authorization lock") = headers
                            .get(reqwest::header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        r#"{"data":[{"id":"grok-new","created":42,"owned_by":"xai"},{"id":"grok-new"},{"id":"  "}]}"#
                    },
                ),
            )
            .with_state(authorization.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind model endpoint");
        let address = listener.local_addr().expect("model endpoint address");
        let server = tokio::spawn(axum::serve(listener, app).into_future());
        let credentials = GrokCredentials::from_json(&SecretString::from(format!(
            r#"{{"type":"xai","auth_kind":"oauth","access_token":"model-token","base_url":"http://{address}/v1"}}"#
        )))
        .expect("credentials");

        let models = GrokModelClient::for_test()
            .discover(&credentials)
            .await
            .expect("models");
        server.abort();

        assert_eq!(models.len(), 1);
        assert_eq!(models[0].upstream_model, "grok-new");
        assert_eq!(
            authorization.lock().expect("authorization lock").as_str(),
            "Bearer model-token"
        );
    }
}
