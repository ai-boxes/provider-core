use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use futures_util::TryStreamExt;
use provider_core::{
    AccountAuthState, AccountId, AccountProvisioningInput, AccountRepository, AccountRuntimeState,
    BoundedBodyError, DiscoveredProviderModel, ManagedProviderDriver, NewCredential,
    NewProviderAccount, ProviderAccount, ProviderAccountUpdate, ProviderConfigurationError,
    ProviderDriver, ProviderError, ProviderErrorKind, ProviderKind, ProviderModel, ProviderRequest,
    ProviderStream, RefreshError, RefreshOutcome, RefreshTrigger, StoredProviderAccount,
    TokenCounter, WireFormat, collect_bounded_body,
};
use secrecy::ExposeSecret;
use serde::Deserialize;

use crate::{
    compatibility::{CompatibleConfig, CompatibleCredentials, normalize_label},
    token_count::Cl100kTokenCounter,
};

const CREDENTIAL_FORMAT_VERSION: u32 = 1;
const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_MODELS_RESPONSE_SIZE: usize = 2 * 1024 * 1024;

pub struct AnthropicCompatibleDriver {
    token_counter: Cl100kTokenCounter,
}

struct AnthropicCompatibleAccount {
    driver: Arc<AnthropicCompatibleDriver>,
    account_id: AccountId,
    credential_revision: u64,
    config: CompatibleConfig,
    credentials: CompatibleCredentials,
    auth_state: AccountAuthState,
    http: tokio::sync::OnceCell<reqwest::Client>,
}

impl Default for AnthropicCompatibleDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl AnthropicCompatibleDriver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            token_counter: Cl100kTokenCounter,
        }
    }
}

impl ProviderDriver for AnthropicCompatibleDriver {
    fn name(&self) -> &'static str {
        "anthropic_compatible"
    }

    fn native_format(&self) -> WireFormat {
        WireFormat::ClaudeMessages
    }

    fn models(&self) -> &[ProviderModel] {
        &[]
    }
}

impl ManagedProviderDriver for AnthropicCompatibleDriver {
    fn kind(&self) -> ProviderKind {
        ProviderKind::AnthropicCompatible
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
                "Anthropic-compatible accounts require direct configuration",
            ));
        };
        let label = normalize_label("Anthropic-compatible", &label)?;
        let config = CompatibleConfig::parse("Anthropic-compatible", &config_json)?;
        let (kind, credential_json) = CompatibleCredentials::from_input(api_key)?;
        Ok(NewProviderAccount {
            id,
            provider: ProviderKind::AnthropicCompatible,
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
        if account.provider != ProviderKind::AnthropicCompatible {
            return Err(ProviderConfigurationError::new(
                "stored account is not Anthropic-compatible",
            ));
        }
        if account.credential.format_version != CREDENTIAL_FORMAT_VERSION {
            return Err(ProviderConfigurationError::new(
                "unsupported Anthropic-compatible credential format",
            ));
        }
        let config = CompatibleConfig::parse("Anthropic-compatible", &account.config_json)?;
        let credentials = CompatibleCredentials::parse(
            "Anthropic-compatible",
            account.credential.kind,
            &account.credential.credential_json,
        )?;
        Ok(Arc::new(AnthropicCompatibleAccount {
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
        update.label = normalize_label("Anthropic-compatible", &update.label)?;
        update.config_json =
            CompatibleConfig::parse("Anthropic-compatible", &update.config_json)?.to_json()?;
        Ok(update)
    }
}

#[async_trait]
impl ProviderAccount for AnthropicCompatibleAccount {
    fn provider_name(&self) -> &'static str {
        "anthropic_compatible"
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
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
        if request.format != WireFormat::ClaudeMessages {
            return Err(ProviderError::new(
                ProviderErrorKind::Internal,
                "Anthropic-compatible account received an unsupported native format",
            ));
        }
        let upstream = self
            .http_client()
            .await?
            .post(format!("{}/messages", self.config.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("x-api-key", self.credentials.api_key.expose_secret())
            .body(request.payload);
        let response = upstream.send().await.map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                "Anthropic-compatible upstream request failed",
            )
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error("Anthropic-compatible upstream", status));
        }
        let stream = response.bytes_stream().map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                "Anthropic-compatible upstream stream failed",
            )
        });
        Ok(Box::pin(stream))
    }

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError> {
        let input = std::str::from_utf8(&request.payload).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "Anthropic-compatible request was not valid UTF-8",
            )
        })?;
        self.driver.token_counter.count(input).map_err(|error| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                format!("failed to count Anthropic-compatible request tokens: {error}"),
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
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("x-api-key", self.credentials.api_key.expose_secret());
        let response = request.send().await.map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                "Anthropic-compatible model discovery request failed",
            )
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error("Anthropic-compatible model discovery", status));
        }
        let body = collect_bounded_body(response.bytes_stream(), MAX_MODELS_RESPONSE_SIZE)
            .await
            .map_err(|error| match error {
                BoundedBodyError::Read(_) => ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "failed to read Anthropic-compatible model response",
                ),
                BoundedBodyError::TooLarge => ProviderError::new(
                    ProviderErrorKind::Upstream,
                    "Anthropic-compatible model response was too large",
                ),
            })?;
        let response: ModelsResponse = serde_json::from_slice(&body).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Upstream,
                "Anthropic-compatible model discovery returned invalid JSON",
            )
        })?;
        normalize_models(response.data)
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

impl AnthropicCompatibleAccount {
    async fn http_client(&self) -> Result<&reqwest::Client, ProviderError> {
        self.http
            .get_or_try_init(|| async { self.config.build_client() })
            .await
    }
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

fn normalize_models(
    models: Vec<ModelResponse>,
) -> Result<Vec<DiscoveredProviderModel>, ProviderError> {
    let mut normalized = std::collections::BTreeMap::new();
    for model in models {
        let id = model.id.trim();
        if id.is_empty() {
            continue;
        }
        let provider_model = ProviderModel::new(id, "anthropic");
        let metadata_json = serde_json::to_string(&provider_model).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "failed to normalize Anthropic-compatible model metadata",
            )
        })?;
        normalized.insert(
            id.to_owned(),
            DiscoveredProviderModel {
                upstream_model: id.to_owned(),
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
}
