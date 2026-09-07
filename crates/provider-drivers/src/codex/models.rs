use std::{collections::BTreeMap, sync::LazyLock, time::Duration};

use provider_core::{
    BoundedBodyError, DiscoveredProviderModel, ProviderError, ProviderErrorKind, ProviderModel,
    collect_bounded_body,
};
use serde::Deserialize;
use serde_json::Value;

use super::{
    contract::{BASELINE, RESPONSES, RESPONSES_LITE},
    credentials::CodexCredentials,
    identity::{DEFAULT_BACKEND_ROOT, responses_headers},
};

const MAX_MODELS_RESPONSE_SIZE: usize = 2 * 1024 * 1024;
const MODELS_TIMEOUT: Duration = Duration::from_secs(10);

static COMPATIBILITY_VERSION: LazyLock<ClientVersion> = LazyLock::new(|| {
    ClientVersion::parse(BASELINE.simulated_client_version)
        .expect("Codex CLI version must be semantic")
});
static MODELS: LazyLock<Vec<ProviderModel>> = LazyLock::new(|| {
    ["gpt-5.5", "gpt-5.2"]
        .into_iter()
        .map(|id| ProviderModel::new(id, "openai"))
        .collect()
});

#[must_use]
pub(crate) fn codex_models() -> &'static [ProviderModel] {
    &MODELS
}

#[derive(Clone)]
pub(crate) struct CodexModelClient {
    http: reqwest::Client,
    backend_root: String,
}

impl CodexModelClient {
    pub(crate) fn new() -> Self {
        Self::with_backend_root(DEFAULT_BACKEND_ROOT)
    }

    pub(crate) fn with_backend_root(backend_root: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(MODELS_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            backend_root: backend_root.trim_end_matches('/').to_owned(),
        }
    }

    pub(crate) async fn discover(
        &self,
        credentials: &CodexCredentials,
    ) -> Result<Vec<DiscoveredProviderModel>, ProviderError> {
        let request = self.http.get(format!(
            "{}/codex/models?client_version={}",
            self.backend_root, BASELINE.simulated_client_version
        ));
        let response = responses_headers(request, credentials)?
            .send()
            .await
            .map_err(|_| {
                ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "Codex model discovery request failed",
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error("Codex model discovery", status));
        }
        let body =
            read_limited(response, MAX_MODELS_RESPONSE_SIZE, "Codex model discovery").await?;
        let response: ModelsResponse = serde_json::from_slice(&body).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                "Codex model discovery returned invalid JSON",
            )
        })?;
        normalize_models(response)
    }
}

fn normalize_models(
    response: ModelsResponse,
) -> Result<Vec<DiscoveredProviderModel>, ProviderError> {
    let mut normalized = BTreeMap::new();
    match response {
        ModelsResponse::Codex { models } => {
            for model in models {
                let id = model.slug.trim();
                if id.is_empty() {
                    continue;
                }
                let compatible = model.minimal_client_version.as_ref().is_none_or(|version| {
                    version
                        .parsed()
                        .is_some_and(|minimum| minimum <= *COMPATIBILITY_VERSION)
                });
                let inference_contract = if model.use_responses_lite {
                    RESPONSES_LITE
                } else {
                    RESPONSES
                };
                let routable = matches!(model.visibility.as_deref(), Some("list" | "hide"))
                    && model.supported_in_api
                    && compatible
                    && inference_contract.status.allows_production_routing();
                let metadata = serde_json::json!({
                    "id": id,
                    "object": "model",
                    "owned_by": "openai",
                    "display_name": model.display_name,
                    "context_window": model.context_window,
                    "supported_reasoning_levels": model.supported_reasoning_levels,
                    "visibility": model.visibility,
                    "supported_in_api": model.supported_in_api,
                    "minimal_client_version": model.minimal_client_version,
                    "use_responses_lite": model.use_responses_lite,
                    "prefer_websockets": model.prefer_websockets,
                    "official_client_contract": {
                        "endpoint": inference_contract.id,
                        "status": inference_contract.status,
                    },
                });
                let metadata_json = serde_json::to_string(&metadata).map_err(|_| {
                    ProviderError::new(
                        ProviderErrorKind::Internal,
                        "failed to normalize Codex model metadata",
                    )
                })?;
                normalized.insert(
                    id.to_owned(),
                    DiscoveredProviderModel {
                        upstream_model: id.to_owned(),
                        input_modalities: None,
                        metadata_json,
                        routable,
                        pricing: None,
                    },
                );
            }
        }
        ModelsResponse::OpenAi { data } => {
            for model in data {
                let id = model.id.trim();
                if id.is_empty() {
                    continue;
                }
                let metadata = serde_json::json!({
                    "id": id,
                    "object": "model",
                    "owned_by": "openai",
                });
                let metadata_json = serde_json::to_string(&metadata).map_err(|_| {
                    ProviderError::new(
                        ProviderErrorKind::Internal,
                        "failed to normalize Codex model metadata",
                    )
                })?;
                normalized.insert(
                    id.to_owned(),
                    DiscoveredProviderModel {
                        upstream_model: id.to_owned(),
                        input_modalities: None,
                        metadata_json,
                        routable: true,
                        pricing: None,
                    },
                );
            }
        }
    }
    Ok(normalized.into_values().collect())
}

async fn read_limited(
    response: reqwest::Response,
    limit: usize,
    operation: &str,
) -> Result<Vec<u8>, ProviderError> {
    collect_bounded_body(response.bytes_stream(), limit)
        .await
        .map(|body| body.to_vec())
        .map_err(|error| match error {
            BoundedBodyError::Read(_) => ProviderError::new(
                ProviderErrorKind::Upstream,
                format!("failed to read {operation} response"),
            ),
            BoundedBodyError::TooLarge => ProviderError::new(
                ProviderErrorKind::Upstream,
                format!("{operation} response was too large"),
            ),
        })
}

fn status_error(operation: &str, status: reqwest::StatusCode) -> ProviderError {
    let kind = match status.as_u16() {
        400 | 422 => ProviderErrorKind::InvalidRequest,
        401 | 403 => ProviderErrorKind::Authentication,
        429 => ProviderErrorKind::RateLimited,
        _ => ProviderErrorKind::Upstream,
    };
    ProviderError::new(kind, format!("{operation} returned HTTP {status}"))
        .with_upstream_status(status.as_u16())
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ModelsResponse {
    Codex { models: Vec<CodexModel> },
    OpenAi { data: Vec<OpenAiModel> },
}

#[derive(Deserialize)]
struct OpenAiModel {
    id: String,
}

#[derive(Deserialize)]
struct CodexModel {
    slug: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    context_window: Option<i64>,
    #[serde(default)]
    supported_reasoning_levels: Value,
    #[serde(default)]
    visibility: Option<String>,
    #[serde(default)]
    supported_in_api: bool,
    #[serde(default)]
    minimal_client_version: Option<VersionValue>,
    #[serde(default)]
    use_responses_lite: bool,
    #[serde(default)]
    prefer_websockets: bool,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(untagged)]
enum VersionValue {
    String(String),
    Tuple([i64; 3]),
}

impl VersionValue {
    fn parsed(&self) -> Option<ClientVersion> {
        match self {
            Self::String(value) => ClientVersion::parse(value),
            Self::Tuple([major, minor, patch]) => Some(ClientVersion(*major, *minor, *patch)),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
struct ClientVersion(i64, i64, i64);

impl ClientVersion {
    fn parse(value: &str) -> Option<Self> {
        let mut parts = value.trim().split('.');
        let version = Self(
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        );
        parts.next().is_none().then_some(version)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{Router, extract::Request, extract::State, routing::get};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Option<(String, reqwest::header::HeaderMap)>>>);

    async fn models_handler(State(capture): State<Capture>, request: Request) -> axum::Json<Value> {
        *capture.0.lock().expect("capture lock") =
            Some((request.uri().to_string(), request.headers().clone()));
        axum::Json(json!({"models": []}))
    }

    #[tokio::test]
    async fn sends_official_models_request_contract() {
        let capture = Capture::default();
        let router = Router::new()
            .route("/backend-api/codex/models", get(models_handler))
            .with_state(capture.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind models mock");
        let address = listener.local_addr().expect("models mock address");
        let server = tokio::spawn(axum::serve(listener, router).into_future());

        let credentials = CodexCredentials::from_tokens(
            "access-token".to_owned(),
            "refresh-token".to_owned(),
            jwt(json!({
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "workspace-1",
                    "chatgpt_account_is_fedramp": true
                }
            })),
            1,
        )
        .expect("credentials");
        let client = CodexModelClient::with_backend_root(&format!("http://{address}/backend-api"));

        client
            .discover(&credentials)
            .await
            .expect("models response");
        server.abort();

        let (uri, headers) = capture
            .0
            .lock()
            .expect("capture lock")
            .clone()
            .expect("captured models request");
        assert_eq!(uri, "/backend-api/codex/models?client_version=0.153.4");
        assert_eq!(header(&headers, "authorization"), "Bearer access-token");
        assert_eq!(header(&headers, "chatgpt-account-id"), "workspace-1");
        assert_eq!(header(&headers, "x-openai-fedramp"), "true");
        assert_eq!(header(&headers, "originator"), "codex_cli_rs");
        assert!(header(&headers, "user-agent").starts_with("codex_cli_rs/0.153.4 ("));
        assert!(headers.get("version").is_none());
    }

    #[test]
    fn filters_codex_models_by_visibility_api_and_compatibility() {
        let response: ModelsResponse = serde_json::from_value(serde_json::json!({
            "models": [
                {
                    "slug": "gpt-5.5",
                    "display_name": "GPT-5.5",
                    "visibility": "list",
                    "supported_in_api": true,
                    "minimal_client_version": "0.124.0",
                    "use_responses_lite": false
                },
                {
                    "slug": "gpt-5.3-codex-spark",
                    "visibility": "list",
                    "supported_in_api": true,
                    "use_responses_lite": false
                },
                {
                    "slug": "lite-only",
                    "visibility": "list",
                    "supported_in_api": true,
                    "minimal_client_version": [0, 1, 0],
                    "use_responses_lite": true
                },
                {
                    "slug": "gpt-6-astra",
                    "visibility": "list",
                    "supported_in_api": true,
                    "minimal_client_version": "0.153.0",
                    "use_responses_lite": true
                },
                {
                    "slug": "future",
                    "visibility": "list",
                    "supported_in_api": true,
                    "minimal_client_version": "0.154.0"
                },
                {
                    "slug": "invalid-version",
                    "visibility": "list",
                    "supported_in_api": true,
                    "minimal_client_version": "not-semver"
                },
                {
                    "slug": "hidden",
                    "visibility": "none",
                    "supported_in_api": true
                },
                {
                    "slug": "codex-auto-review",
                    "visibility": "hide",
                    "supported_in_api": true,
                    "minimal_client_version": "0.98.0",
                    "use_responses_lite": true
                },
                {
                    "slug": "gpt-reserve",
                    "visibility": "hide",
                    "supported_in_api": true,
                    "minimal_client_version": "0.153.0",
                    "use_responses_lite": true
                }
            ]
        }))
        .expect("models response");

        let models = normalize_models(response).expect("normalized models");
        assert!(model(&models, "gpt-5.5").routable);
        let astra = model(&models, "gpt-6-astra");
        assert!(astra.routable);
        let astra_metadata: Value =
            serde_json::from_str(&astra.metadata_json).expect("astra metadata");
        assert_eq!(
            astra_metadata["official_client_contract"],
            serde_json::json!({
                "endpoint": "responses_lite",
                "status": "verified"
            })
        );
        let spark = model(&models, "gpt-5.3-codex-spark");
        assert_eq!(spark.input_modalities, None);
        let spark_metadata: Value =
            serde_json::from_str(&spark.metadata_json).expect("spark metadata");
        assert!(spark_metadata.get("input_modalities").is_none());
        assert_eq!(
            spark_metadata["official_client_contract"],
            serde_json::json!({
                "endpoint": "responses_http",
                "status": "verified"
            })
        );
        let lite = model(&models, "lite-only");
        assert!(lite.routable);
        let lite_metadata: Value =
            serde_json::from_str(&lite.metadata_json).expect("Lite metadata");
        assert_eq!(
            lite_metadata["official_client_contract"],
            serde_json::json!({
                "endpoint": "responses_lite",
                "status": "verified"
            })
        );
        assert!(!model(&models, "future").routable);
        assert!(!model(&models, "invalid-version").routable);
        assert!(!model(&models, "hidden").routable);
        assert!(model(&models, "codex-auto-review").routable);
        assert!(model(&models, "gpt-reserve").routable);
    }

    #[test]
    fn accepts_standard_openai_model_shape_and_keeps_small_fallback() {
        let response: ModelsResponse = serde_json::from_value(serde_json::json!({
            "data": [{"id": "gpt-openai"}]
        }))
        .expect("OpenAI models response");
        let models = normalize_models(response).expect("normalized models");

        assert!(model(&models, "gpt-openai").routable);
        assert_eq!(model(&models, "gpt-openai").input_modalities, None);
        let metadata: Value = serde_json::from_str(&model(&models, "gpt-openai").metadata_json)
            .expect("model metadata");
        assert!(metadata.get("input_modalities").is_none());
        assert_eq!(
            codex_models()
                .iter()
                .map(|model| model.id.as_str())
                .collect::<Vec<_>>(),
            ["gpt-5.5", "gpt-5.2"]
        );
    }

    fn model<'a>(models: &'a [DiscoveredProviderModel], id: &str) -> &'a DiscoveredProviderModel {
        models
            .iter()
            .find(|model| model.upstream_model == id)
            .expect("model")
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
}
