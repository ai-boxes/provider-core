use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use futures_util::TryStreamExt;
use provider_core::{
    AccountAuthState, AccountId, AccountProvisioningInput, AccountRepository, AccountRuntimeState,
    BoundedBodyError, DiscoveredProviderModel, ManagedProviderDriver, NewCredential,
    NewProviderAccount, ProviderAccount, ProviderAccountUpdate, ProviderConfigurationError,
    ProviderDriver, ProviderError, ProviderErrorKind, ProviderKind, ProviderModel, ProviderRequest,
    ProviderStream, RefreshError, RefreshOutcome, RefreshTrigger, StoredProviderAccount,
    TokenCounter, WireFormat, collect_bounded_body, usage::ProviderUsageProfile,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    compatibility::{CompatibleConfig, CompatibleCredentials, normalize_label},
    token_count::Cl100kTokenCounter,
};

const CREDENTIAL_FORMAT_VERSION: u32 = 1;
const MAX_MODELS_RESPONSE_SIZE: usize = 2 * 1024 * 1024;
const MAX_ERROR_RESPONSE_SIZE: usize = 16 * 1024;
const MAX_ERROR_DETAIL_CHARS: usize = 512;

pub struct OpenAiCompatibleDriver {
    token_counter: Cl100kTokenCounter,
    #[cfg(feature = "test-util")]
    test_http: Option<reqwest::Client>,
}

struct OpenAiCompatibleAccount {
    driver: Arc<OpenAiCompatibleDriver>,
    account_id: AccountId,
    credential_revision: u64,
    config: CompatibleConfig,
    credentials: CompatibleCredentials,
    auth_state: AccountAuthState,
    http: tokio::sync::OnceCell<reqwest::Client>,
}

impl Default for OpenAiCompatibleDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenAiCompatibleDriver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            token_counter: Cl100kTokenCounter,
            #[cfg(feature = "test-util")]
            test_http: None,
        }
    }

    #[cfg(feature = "test-util")]
    #[must_use]
    pub fn for_test(http: reqwest::Client) -> Arc<Self> {
        Arc::new(Self {
            token_counter: Cl100kTokenCounter,
            test_http: Some(http),
        })
    }
}

impl ProviderDriver for OpenAiCompatibleDriver {
    fn name(&self) -> &'static str {
        "openai_compatible"
    }

    fn native_format(&self) -> WireFormat {
        WireFormat::OpenAiChatCompletions
    }

    fn models(&self) -> &[ProviderModel] {
        &[]
    }
}

impl ManagedProviderDriver for OpenAiCompatibleDriver {
    fn kind(&self) -> ProviderKind {
        ProviderKind::OpenAiCompatible
    }

    fn prepare_account(
        &self,
        input: AccountProvisioningInput,
    ) -> Result<NewProviderAccount, ProviderConfigurationError> {
        let AccountProvisioningInput::Direct {
            id,
            label,
            group_label,
            config_json,
            api_key,
        } = input
        else {
            return Err(ProviderConfigurationError::new(
                "OpenAI-compatible accounts require direct configuration",
            ));
        };
        let label = normalize_label("OpenAI-compatible", &label)?;
        let config = CompatibleConfig::parse("OpenAI-compatible", &config_json)?;
        let (kind, credential_json) = CompatibleCredentials::from_input(api_key)?;
        Ok(NewProviderAccount {
            id,
            provider: ProviderKind::OpenAiCompatible,
            label,
            group_label,
            config_json: config.to_json()?,
            enabled: true,
            credential: NewCredential {
                kind,
                format_version: CREDENTIAL_FORMAT_VERSION,
                credential_json,
                expires_at: None,
                last_refreshed_at: None,
            },
        })
    }

    fn build_account(
        self: Arc<Self>,
        account: StoredProviderAccount,
        _repository: Arc<dyn AccountRepository>,
    ) -> Result<Arc<dyn ProviderAccount>, ProviderConfigurationError> {
        if account.provider != ProviderKind::OpenAiCompatible {
            return Err(ProviderConfigurationError::new(
                "stored account is not OpenAI-compatible",
            ));
        }
        if account.credential.format_version != CREDENTIAL_FORMAT_VERSION {
            return Err(ProviderConfigurationError::new(
                "unsupported OpenAI-compatible credential format",
            ));
        }
        let config = CompatibleConfig::parse("OpenAI-compatible", &account.config_json)?;
        let credentials = CompatibleCredentials::parse(
            "OpenAI-compatible",
            account.credential.kind,
            &account.credential.credential_json,
        )?;
        Ok(Arc::new(OpenAiCompatibleAccount {
            driver: self,
            account_id: account.id,
            credential_revision: account.credential.revision,
            config,
            credentials,
            auth_state: account.auth_state,
            http: tokio::sync::OnceCell::new(),
        }))
    }

    fn prepare_account_update(
        &self,
        mut update: ProviderAccountUpdate,
    ) -> Result<ProviderAccountUpdate, ProviderConfigurationError> {
        update.label = normalize_label("OpenAI-compatible", &update.label)?;
        update.config_json =
            CompatibleConfig::parse("OpenAI-compatible", &update.config_json)?.to_json()?;
        Ok(update)
    }
}

#[async_trait]
impl ProviderAccount for OpenAiCompatibleAccount {
    fn provider_name(&self) -> &'static str {
        "openai_compatible"
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn usage_profile(&self) -> Option<ProviderUsageProfile> {
        Some(ProviderUsageProfile {
            provider: ProviderKind::OpenAiCompatible,
            contract: super::usage::openai_compatible_usage_contract(),
        })
    }

    fn runtime_state(&self) -> AccountRuntimeState {
        AccountRuntimeState {
            generation: 0,
            next_refresh_at: None,
            auth_state: self.auth_state,
            persistence_pending: false,
        }
    }

    fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    async fn execute_stream(
        &self,
        request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError> {
        if request.format != WireFormat::OpenAiChatCompletions {
            return Err(ProviderError::new(
                ProviderErrorKind::Internal,
                "OpenAI-compatible account received an unsupported native format",
            ));
        }
        let upstream = self
            .http_client()
            .await?
            .post(format!("{}/chat/completions", self.config.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .body(request.payload)
            .bearer_auth(self.credentials.api_key.expose_secret());
        let response = upstream.send().await.map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                "OpenAI-compatible upstream request failed",
            )
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error("OpenAI-compatible upstream", response).await);
        }
        let stream = response.bytes_stream().map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                "OpenAI-compatible upstream stream failed",
            )
        });
        Ok(Box::pin(stream))
    }

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError> {
        let input = std::str::from_utf8(&request.payload).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "OpenAI-compatible request was not valid UTF-8",
            )
        })?;
        self.driver.token_counter.count(input).map_err(|error| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                format!("failed to count OpenAI-compatible request tokens: {error}"),
            )
        })
    }

    async fn discover_models(&self) -> Result<Vec<DiscoveredProviderModel>, ProviderError> {
        let request = self
            .http_client()
            .await?
            .get(format!("{}/models", self.config.base_url))
            .timeout(Duration::from_secs(10))
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(self.credentials.api_key.expose_secret());
        let response = request.send().await.map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                "OpenAI-compatible model discovery request failed",
            )
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error("OpenAI-compatible model discovery", response).await);
        }
        let body = collect_bounded_body(response.bytes_stream(), MAX_MODELS_RESPONSE_SIZE)
            .await
            .map_err(|error| match error {
                BoundedBodyError::Read(_) => ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "failed to read OpenAI-compatible model response",
                ),
                BoundedBodyError::TooLarge => ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "OpenAI-compatible model response was too large",
                ),
            })?;
        let response: ModelsResponse = serde_json::from_slice(&body).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                "OpenAI-compatible model discovery returned invalid JSON",
            )
        })?;
        normalize_models(response.data, "openai_compatible")
    }

    async fn refresh_credentials(
        &self,
        _trigger: RefreshTrigger,
    ) -> Result<RefreshOutcome, RefreshError> {
        Ok(RefreshOutcome {
            state: self.runtime_state(),
        })
    }
}

impl OpenAiCompatibleAccount {
    async fn http_client(&self) -> Result<&reqwest::Client, ProviderError> {
        #[cfg(feature = "test-util")]
        if let Some(http) = &self.driver.test_http {
            return Ok(http);
        }
        self.http
            .get_or_try_init(|| async { self.config.build_client() })
            .await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorBodyIssue {
    ReadFailed,
    TooLarge,
}

async fn status_error(operation: &str, response: reqwest::Response) -> ProviderError {
    let status = response.status();
    let kind = match status.as_u16() {
        400 | 422 => ProviderErrorKind::InvalidRequest,
        401 | 403 => ProviderErrorKind::Authentication,
        429 => ProviderErrorKind::RateLimited,
        _ => ProviderErrorKind::Upstream,
    };
    let message = match read_error_detail(response).await {
        Ok(Some(detail)) => format!("{operation} returned HTTP {status}: {detail}"),
        Ok(None) => format!("{operation} returned HTTP {status}"),
        Err(ErrorBodyIssue::ReadFailed) => {
            format!("{operation} returned HTTP {status} with an unreadable error response")
        }
        Err(ErrorBodyIssue::TooLarge) => {
            format!("{operation} returned HTTP {status} with an oversized error response")
        }
    };
    ProviderError::new(kind, message).with_upstream_status(status.as_u16())
}

async fn read_error_detail(response: reqwest::Response) -> Result<Option<String>, ErrorBodyIssue> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ERROR_RESPONSE_SIZE as u64)
    {
        return Err(ErrorBodyIssue::TooLarge);
    }
    let body = collect_bounded_body(response.bytes_stream(), MAX_ERROR_RESPONSE_SIZE)
        .await
        .map_err(|error| match error {
            BoundedBodyError::Read(_) => ErrorBodyIssue::ReadFailed,
            BoundedBodyError::TooLarge => ErrorBodyIssue::TooLarge,
        })?;
    Ok(sanitize_error_detail(&body))
}

fn sanitize_error_detail(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    if let Ok(value) = serde_json::from_slice::<Value>(body)
        && let Some(message) = extract_json_error_message(&value)
    {
        return Some(truncate_error_detail(&message));
    }
    let text = std::str::from_utf8(body).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    Some(truncate_error_detail(text))
}

fn extract_json_error_message(value: &Value) -> Option<String> {
    let candidates = [
        value.pointer("/error/message"),
        value.pointer("/error/msg"),
        value.get("message"),
        value.get("error"),
    ];
    for candidate in candidates {
        match candidate {
            Some(Value::String(message)) => {
                let message = message.trim();
                if !message.is_empty() {
                    return Some(message.to_owned());
                }
            }
            Some(Value::Object(object)) => {
                if let Some(Value::String(message)) = object.get("message") {
                    let message = message.trim();
                    if !message.is_empty() {
                        return Some(message.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn truncate_error_detail(text: &str) -> String {
    let cleaned = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() <= MAX_ERROR_DETAIL_CHARS {
        cleaned
    } else {
        let mut truncated = cleaned
            .chars()
            .take(MAX_ERROR_DETAIL_CHARS)
            .collect::<String>();
        truncated.push_str("...");
        truncated
    }
}

fn normalize_models(
    models: Vec<ModelResponse>,
    default_owner: &str,
) -> Result<Vec<DiscoveredProviderModel>, ProviderError> {
    let mut normalized = std::collections::BTreeMap::new();
    for model in models {
        let id = model.id.trim();
        if id.is_empty() {
            continue;
        }
        provider_core::validate_input_modalities(model.input_modalities.as_deref()).map_err(
            |_| {
                ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "OpenAI-compatible model returned invalid input_modalities",
                )
            },
        )?;
        let mut provider_model = ProviderModel::new(
            id,
            model
                .owned_by
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(default_owner),
        )
        .with_input_modalities(model.input_modalities);
        if let Some(created) = model.created {
            provider_model = provider_model.with_created(created);
        }
        let metadata_json = serde_json::to_string(&provider_model).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "failed to normalize OpenAI-compatible model metadata",
            )
        })?;
        normalized.insert(
            id.to_owned(),
            DiscoveredProviderModel {
                upstream_model: id.to_owned(),
                input_modalities: provider_model.input_modalities.clone(),
                metadata_json,
                routable: true,
                pricing: None,
            },
        );
    }
    Ok(normalized.into_values().collect())
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
    input_modalities: Option<Vec<provider_core::ProviderModelInputModality>>,
}

#[cfg(test)]
mod tests {
    use super::{
        ModelResponse, extract_json_error_message, normalize_models, sanitize_error_detail,
        truncate_error_detail,
    };
    use provider_core::ProviderModelInputModality;
    use serde_json::json;

    #[test]
    fn openai_error_objects_surface_their_message() {
        let body = serde_json::to_vec(&json!({
            "error": { "message": "model not found", "type": "invalid_request_error" }
        }))
        .expect("json");
        assert_eq!(
            sanitize_error_detail(&body).as_deref(),
            Some("model not found")
        );
    }

    #[test]
    fn nested_and_flat_error_shapes_are_accepted() {
        assert_eq!(
            extract_json_error_message(&json!({ "message": "flat failure" })).as_deref(),
            Some("flat failure")
        );
        assert_eq!(
            extract_json_error_message(&json!({ "error": "string failure" })).as_deref(),
            Some("string failure")
        );
    }

    #[test]
    fn error_detail_is_trimmed_and_length_limited() {
        let long = "x".repeat(600);
        let truncated = truncate_error_detail(&long);
        assert!(truncated.ends_with("..."));
        assert_eq!(truncated.chars().count(), 515);
        assert_eq!(
            sanitize_error_detail(b"  hello\nworld  ").as_deref(),
            Some("hello world")
        );
    }

    #[test]
    fn discovered_input_modalities_are_explicit_and_validated() {
        let models = normalize_models(
            vec![ModelResponse {
                id: "vision".to_owned(),
                created: None,
                owned_by: None,
                input_modalities: Some(vec![
                    ProviderModelInputModality::Audio,
                    ProviderModelInputModality::Pdf,
                ]),
            }],
            "openai_compatible",
        )
        .expect("valid modalities");
        assert_eq!(
            models[0].input_modalities,
            Some(vec![
                ProviderModelInputModality::Audio,
                ProviderModelInputModality::Pdf,
            ])
        );

        assert!(
            normalize_models(
                vec![ModelResponse {
                    id: "invalid".to_owned(),
                    created: None,
                    owned_by: None,
                    input_modalities: Some(vec![
                        ProviderModelInputModality::Video,
                        ProviderModelInputModality::Video,
                    ]),
                }],
                "openai_compatible",
            )
            .is_err()
        );
    }
}
