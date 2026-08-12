use std::{collections::BTreeMap, sync::LazyLock, time::Duration};

use provider_core::{
    BoundedBodyError, DiscoveredProviderModel, ProviderError, ProviderErrorKind, ProviderModel,
    collect_bounded_body,
};
use secrecy::ExposeSecret;
use serde::Deserialize;

use super::{
    credentials::GrokCredentials,
    identity::{DEFAULT_PROXY_BASE_URL, session_headers},
};

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
    base_url: String,
}

impl GrokModelClient {
    pub(crate) fn new() -> Self {
        Self {
            http: model_http_client(),
            base_url: DEFAULT_PROXY_BASE_URL.to_owned(),
        }
    }

    pub(crate) async fn discover(
        &self,
        credentials: &GrokCredentials,
        user_id: &str,
    ) -> Result<Vec<DiscoveredProviderModel>, ProviderError> {
        let response = session_headers(
            self.http
                .get(format!("{}/models", self.base_url))
                .bearer_auth(credentials.access_token().expose_secret())
                .header(reqwest::header::ACCEPT, "application/json"),
        )
        .header("x-userid", user_id)
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
                    input_modalities: None,
                    metadata_json,
                    routable: !id.starts_with("grok-imagine-"),
                    pricing: None,
                },
            );
        }
        Ok(models.into_values().collect())
    }

    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn for_test(base_url: impl Into<String>) -> Self {
        Self {
            http: model_http_client(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        }
    }
}

fn model_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
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
        let credentials = GrokCredentials::from_access_token("model-token");

        let error = match GrokModelClient::for_test(format!("http://{address}/v1"))
            .discover(&credentials, "model-user")
            .await
        {
            Ok(_) => panic!("429 model discovery must fail"),
            Err(error) => error,
        };
        server.abort();

        assert_eq!(error.kind(), ProviderErrorKind::RateLimited);
        assert_eq!(error.upstream_status(), Some(429));
    }

    #[tokio::test]
    async fn discovers_and_normalizes_remote_models() {
        let headers = Arc::new(Mutex::new(HeaderMap::new()));
        let app = Router::new()
            .route(
                "/v1/models",
                get(
                    |State(captured): State<Arc<Mutex<HeaderMap>>>, headers: HeaderMap| async move {
                        *captured.lock().expect("headers lock") = headers;
                        r#"{"data":[{"id":"grok-new","created":42,"owned_by":"xai"},{"id":"grok-new"},{"id":"  "}]}"#
                    },
                ),
            )
            .with_state(headers.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind model endpoint");
        let address = listener.local_addr().expect("model endpoint address");
        let server = tokio::spawn(axum::serve(listener, app).into_future());
        let credentials = GrokCredentials::from_access_token("model-token");

        let models = GrokModelClient::for_test(format!("http://{address}/v1"))
            .discover(&credentials, "model-user")
            .await
            .expect("models");
        server.abort();

        assert_eq!(models.len(), 1);
        assert_eq!(models[0].upstream_model, "grok-new");
        let headers = headers.lock().expect("headers lock");
        assert_eq!(
            header(&headers, reqwest::header::AUTHORIZATION.as_str()),
            "Bearer model-token"
        );
        assert_eq!(header(&headers, "x-userid"), "model-user");
        assert_eq!(header(&headers, "x-xai-token-auth"), "xai-grok-cli");
        assert_eq!(header(&headers, "x-grok-client-version"), "1.0.0");
    }

    fn header(headers: &HeaderMap, name: &str) -> String {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }
}
