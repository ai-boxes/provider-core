use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use provider_core::{
    AccountAuthState, AccountId, AccountProvisioningInput, AccountRepository, AccountRuntimeState,
    CredentialKind, CredentialUpdate, CredentialWriteOutcome, ManagedProviderDriver, NewCredential,
    NewProviderAccount, ProviderAccount, ProviderAccountUpdate, ProviderConfigurationError,
    ProviderDriver, ProviderError, ProviderErrorKind, ProviderKind, ProviderModel,
    ProviderQuotaError, ProviderQuotaFetch, ProviderQuotaObservation, ProviderQuotaSource,
    ProviderRequest, ProviderStream, RefreshError, RefreshErrorKind, RefreshOutcome,
    RefreshTrigger, StartedProviderOAuth, StoredProviderAccount, TokenCounter, WireFormat,
    usage::{CacheEligibility, PricingMode, ProviderUsageProfile},
};

use super::{
    client::{CodexClient, CodexClientFailure, CodexStreamResponse},
    credentials::{CodexAuthError, CodexCredentials},
    models::{CodexModelClient, codex_models},
    oauth::CodexOAuthClient,
    quota::CodexQuotaClient,
    refresh::CodexRefreshClient,
    request::prepare_request,
};
use crate::token_count::Cl100kTokenCounter;

const CREDENTIAL_FORMAT_VERSION: u32 = 1;
const REFRESH_LEAD_SECONDS: i64 = 5 * 60;
const LAST_REFRESH_FALLBACK_SECONDS: i64 = 8 * 24 * 60 * 60;
const PERSISTENCE_RETRY_SECONDS: i64 = 30;

pub struct CodexDriver {
    client: CodexClient,
    refresh_client: CodexRefreshClient,
    model_client: CodexModelClient,
    oauth_client: CodexOAuthClient,
    quota_client: CodexQuotaClient,
    token_counter: Cl100kTokenCounter,
}

struct CodexAccount {
    driver: Arc<CodexDriver>,
    account_id: AccountId,
    repository: Option<Arc<dyn AccountRepository>>,
    state: RwLock<CodexState>,
}

#[derive(Clone)]
struct CodexState {
    credentials: CodexCredentials,
    revision: u64,
    generation: u64,
    next_refresh_at: Option<i64>,
    auth_state: AccountAuthState,
    pending_update: Option<CredentialUpdate>,
    observation_generation: u64,
    observation: Option<ProviderQuotaObservation>,
}

impl Default for CodexDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl CodexDriver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: CodexClient::new(),
            refresh_client: CodexRefreshClient::new(),
            model_client: CodexModelClient::new(),
            oauth_client: CodexOAuthClient::new(),
            quota_client: CodexQuotaClient::new(),
            token_counter: Cl100kTokenCounter,
        }
    }

    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    #[must_use]
    pub fn for_test(backend_root: &str, auth_issuer: &str) -> Arc<Self> {
        Arc::new(Self {
            client: CodexClient::with_backend_root(backend_root),
            refresh_client: CodexRefreshClient::with_issuer(auth_issuer),
            model_client: CodexModelClient::with_backend_root(backend_root),
            oauth_client: CodexOAuthClient::with_issuer(auth_issuer),
            quota_client: CodexQuotaClient::with_backend_root(backend_root),
            token_counter: Cl100kTokenCounter,
        })
    }
}

impl ProviderDriver for CodexDriver {
    fn name(&self) -> &'static str {
        "codex"
    }

    fn native_format(&self) -> WireFormat {
        WireFormat::OpenAiResponses
    }

    fn models(&self) -> &[ProviderModel] {
        codex_models()
    }
}

#[async_trait]
impl ManagedProviderDriver for CodexDriver {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Codex
    }

    fn supports_quota(&self) -> bool {
        true
    }

    fn prepare_account(
        &self,
        input: AccountProvisioningInput,
    ) -> Result<NewProviderAccount, ProviderConfigurationError> {
        let AccountProvisioningInput::CredentialJson {
            id,
            label,
            credential_json,
        } = input
        else {
            return Err(ProviderConfigurationError::new(
                "Codex accounts require OAuth credential JSON",
            ));
        };
        let label = normalized_label(&label)?;
        let credentials = CodexCredentials::from_json(&credential_json)
            .map_err(|error| ProviderConfigurationError::new(error.to_string()))?;
        let credential_json = credentials
            .to_json()
            .map_err(|error| ProviderConfigurationError::new(error.to_string()))?;
        Ok(NewProviderAccount {
            id,
            provider: ProviderKind::Codex,
            label,
            config_json: "{}".to_owned(),
            enabled: true,
            credential: NewCredential {
                kind: CredentialKind::Oauth,
                format_version: CREDENTIAL_FORMAT_VERSION,
                credential_json,
                expires_at: credentials.expires_at(),
                last_refreshed_at: Some(credentials.last_refreshed_at()),
            },
        })
    }

    fn prepare_account_update(
        &self,
        mut update: ProviderAccountUpdate,
    ) -> Result<ProviderAccountUpdate, ProviderConfigurationError> {
        update.label = normalized_label(&update.label)?;
        validate_empty_config(&update.config_json)?;
        update.config_json = "{}".to_owned();
        Ok(update)
    }

    async fn start_oauth(&self) -> Result<StartedProviderOAuth, ProviderConfigurationError> {
        self.oauth_client.start().await
    }

    fn build_account(
        self: Arc<Self>,
        account: StoredProviderAccount,
        repository: Arc<dyn AccountRepository>,
    ) -> Result<Arc<dyn ProviderAccount>, ProviderConfigurationError> {
        CodexAccount::from_stored(self, account, repository)
            .map(|account| Arc::new(account) as Arc<dyn ProviderAccount>)
            .map_err(|error| ProviderConfigurationError::new(error.to_string()))
    }
}

impl CodexAccount {
    fn from_stored(
        driver: Arc<CodexDriver>,
        account: StoredProviderAccount,
        repository: Arc<dyn AccountRepository>,
    ) -> Result<Self, CodexAuthError> {
        if account.provider != ProviderKind::Codex {
            return Err(CodexAuthError::InvalidStoredProvider);
        }
        if account.credential.kind != CredentialKind::Oauth {
            return Err(CodexAuthError::InvalidCredentialKind);
        }
        if account.credential.format_version != CREDENTIAL_FORMAT_VERSION {
            return Err(CodexAuthError::UnsupportedCredentialFormat(
                account.credential.format_version,
            ));
        }
        let credentials = CodexCredentials::from_json(&account.credential.credential_json)?;
        let state = CodexState {
            next_refresh_at: (account.auth_state == AccountAuthState::Active)
                .then(|| refresh_at(&credentials, &account.id))
                .flatten(),
            credentials,
            revision: account.credential.revision,
            generation: 0,
            auth_state: account.auth_state,
            pending_update: None,
            observation_generation: 0,
            observation: None,
        };
        Ok(Self {
            driver,
            account_id: account.id,
            repository: Some(repository),
            state: RwLock::new(state),
        })
    }

    fn state(&self) -> RwLockReadGuard<'_, CodexState> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn state_mut(&self) -> RwLockWriteGuard<'_, CodexState> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn snapshot(&self) -> CodexState {
        self.state().clone()
    }

    fn publish_observation(
        &self,
        expected_revision: u64,
        expected_generation: u64,
        groups: Vec<provider_core::QuotaGroup>,
    ) {
        if groups.is_empty() {
            return;
        }
        let mut state = self.state_mut();
        if state.revision != expected_revision || state.generation != expected_generation {
            return;
        }
        state.observation_generation = state.observation_generation.saturating_add(1);
        state.observation = Some(ProviderQuotaObservation {
            credential_revision: state.revision,
            generation: state.observation_generation,
            observed_at: unix_timestamp(),
            groups,
        });
    }

    async fn persist_pending(
        &self,
        repository: &Arc<dyn AccountRepository>,
        pending: CredentialUpdate,
    ) -> Result<RefreshOutcome, RefreshError> {
        match repository
            .compare_and_swap_credential(&self.account_id, pending.clone())
            .await
        {
            Ok(CredentialWriteOutcome::Updated { revision }) => {
                let mut state = self.state_mut();
                state.revision = revision;
                state.pending_update = None;
                state.next_refresh_at = refresh_at(&state.credentials, &self.account_id);
                state.observation = None;
                Ok(RefreshOutcome {
                    state: runtime_state(&state),
                })
            }
            Ok(CredentialWriteOutcome::Conflict) => Err(RefreshError::new(
                RefreshErrorKind::Internal,
                "Codex credential revision conflict",
            )),
            Err(_) => {
                let mut state = self.state_mut();
                state.next_refresh_at = unix_timestamp().checked_add(PERSISTENCE_RETRY_SECONDS);
                Ok(RefreshOutcome {
                    state: runtime_state(&state),
                })
            }
        }
    }

    async fn mark_reauth_required(&self, repository: &Arc<dyn AccountRepository>) {
        let now = unix_timestamp();
        let _ = repository
            .update_auth_state(
                &self.account_id,
                AccountAuthState::ReauthRequired,
                Some("refresh_reauth_required"),
                now,
            )
            .await;
        let mut state = self.state_mut();
        state.auth_state = AccountAuthState::ReauthRequired;
        state.next_refresh_at = None;
        state.observation = None;
    }
}

#[async_trait]
impl ProviderAccount for CodexAccount {
    fn provider_name(&self) -> &'static str {
        "codex"
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn usage_profile(&self) -> Option<ProviderUsageProfile> {
        // Codex is the one provider whose Responses usage shape has been pinned
        // against real `response.completed` events, so it is the only one that
        // reports a contract. Cache eligibility is fixed here because Codex
        // always caches its prompt prefix; per-request eligibility arrives with
        // the providers that let a request opt out.
        Some(ProviderUsageProfile {
            provider: ProviderKind::Codex,
            contract: super::codex_usage_contract(CacheEligibility::Eligible, PricingMode::Default),
        })
    }

    fn runtime_state(&self) -> AccountRuntimeState {
        runtime_state(&self.state())
    }

    fn credential_revision(&self) -> u64 {
        self.state().revision
    }

    fn quota_source(&self) -> Option<&dyn ProviderQuotaSource> {
        Some(self)
    }

    fn quota_observation(&self) -> Option<ProviderQuotaObservation> {
        let state = self.state();
        state
            .observation
            .as_ref()
            .filter(|observation| observation.credential_revision == state.revision)
            .cloned()
    }

    async fn execute_stream(
        &self,
        request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError> {
        let state = self.snapshot();
        let prepared = prepare_request(request)?;
        match self
            .driver
            .client
            .execute_stream(&state.credentials, prepared)
            .await
        {
            Ok(CodexStreamResponse {
                stream,
                observed_groups,
            }) => {
                self.publish_observation(state.revision, state.generation, observed_groups);
                Ok(stream)
            }
            Err(CodexClientFailure {
                error,
                observed_groups,
            }) => {
                self.publish_observation(state.revision, state.generation, observed_groups);
                Err(error)
            }
        }
    }

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError> {
        let prepared = prepare_request(request)?;
        let input = std::str::from_utf8(&prepared.payload).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "normalized Codex request was not valid UTF-8",
            )
        })?;
        self.driver.token_counter.count(input).map_err(|error| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                format!("failed to count Codex request tokens: {error}"),
            )
        })
    }

    async fn discover_models(
        &self,
    ) -> Result<Vec<provider_core::DiscoveredProviderModel>, ProviderError> {
        let credentials = self.state().credentials.clone();
        self.driver.model_client.discover(&credentials).await
    }

    fn fallback_models(&self) -> &[ProviderModel] {
        self.driver.models()
    }

    async fn refresh_credentials(
        &self,
        _trigger: RefreshTrigger,
    ) -> Result<RefreshOutcome, RefreshError> {
        let repository = self.repository.as_ref().ok_or_else(|| {
            RefreshError::new(
                RefreshErrorKind::Internal,
                "Codex account has no credential repository",
            )
        })?;
        let pending_update = self.state().pending_update.clone();
        if let Some(pending) = pending_update {
            return self.persist_pending(repository, pending).await;
        }
        let current = self.snapshot();
        if current.auth_state == AccountAuthState::ReauthRequired {
            return Err(RefreshError::new(
                RefreshErrorKind::ReauthRequired,
                "Codex account requires authorization",
            ));
        }
        let tokens = match self
            .driver
            .refresh_client
            .refresh(&current.credentials)
            .await
        {
            Ok(tokens) => tokens,
            Err(error) if error.kind() == RefreshErrorKind::ReauthRequired => {
                self.mark_reauth_required(repository).await;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let refreshed_at = unix_timestamp();
        let credentials = match current.credentials.refreshed(tokens, refreshed_at) {
            Ok(credentials) => credentials,
            Err(error) => {
                let error = codex_refresh_error(error);
                if error.kind() == RefreshErrorKind::ReauthRequired {
                    self.mark_reauth_required(repository).await;
                }
                return Err(error);
            }
        };
        let credential_json = credentials.to_json().map_err(|error| {
            RefreshError::new(
                RefreshErrorKind::Internal,
                format!("failed to serialize Codex credential: {error}"),
            )
        })?;
        let update = CredentialUpdate {
            expected_revision: current.revision,
            kind: CredentialKind::Oauth,
            format_version: CREDENTIAL_FORMAT_VERSION,
            credential_json,
            expires_at: credentials.expires_at(),
            last_refreshed_at: Some(credentials.last_refreshed_at()),
            updated_at: refreshed_at,
        };
        match repository
            .compare_and_swap_credential(&self.account_id, update.clone())
            .await
        {
            Ok(CredentialWriteOutcome::Updated { revision }) => {
                let mut state = self.state_mut();
                state.credentials = credentials;
                state.revision = revision;
                state.generation = state.generation.saturating_add(1);
                state.next_refresh_at = refresh_at(&state.credentials, &self.account_id);
                state.auth_state = AccountAuthState::Active;
                state.pending_update = None;
                state.observation = None;
                Ok(RefreshOutcome {
                    state: runtime_state(&state),
                })
            }
            Ok(CredentialWriteOutcome::Conflict) => Err(RefreshError::new(
                RefreshErrorKind::Internal,
                "Codex credential revision conflict",
            )),
            Err(_) => {
                let mut state = self.state_mut();
                state.credentials = credentials;
                state.generation = state.generation.saturating_add(1);
                state.next_refresh_at = refreshed_at.checked_add(PERSISTENCE_RETRY_SECONDS);
                state.auth_state = AccountAuthState::Active;
                state.pending_update = Some(update);
                state.observation = None;
                Ok(RefreshOutcome {
                    state: runtime_state(&state),
                })
            }
        }
    }
}

#[async_trait]
impl ProviderQuotaSource for CodexAccount {
    async fn fetch_quota(&self) -> Result<ProviderQuotaFetch, ProviderQuotaError> {
        let state = self.snapshot();
        let snapshot = self
            .driver
            .quota_client
            .fetch(self.account_id.as_str(), &state.credentials)
            .await?;
        Ok(ProviderQuotaFetch {
            snapshot,
            credential_revision: state.revision,
        })
    }
}

fn normalized_label(label: &str) -> Result<String, ProviderConfigurationError> {
    let label = label.trim().to_owned();
    if label.is_empty() {
        return Err(ProviderConfigurationError::new(
            "Codex account label must not be empty",
        ));
    }
    Ok(label)
}

fn validate_empty_config(config_json: &str) -> Result<(), ProviderConfigurationError> {
    let value: serde_json::Value = serde_json::from_str(config_json).map_err(|_| {
        ProviderConfigurationError::new("Codex configuration must be a JSON object")
    })?;
    if !value.as_object().is_some_and(serde_json::Map::is_empty) {
        return Err(ProviderConfigurationError::new(
            "Codex upstream URL is managed by the driver",
        ));
    }
    Ok(())
}

fn codex_refresh_error(error: CodexAuthError) -> RefreshError {
    let kind = match error {
        CodexAuthError::ClaimMismatch("account_id") => RefreshErrorKind::ReauthRequired,
        _ => RefreshErrorKind::Transient,
    };
    RefreshError::new(kind, format!("failed to update Codex credential: {error}"))
}

fn runtime_state(state: &CodexState) -> AccountRuntimeState {
    AccountRuntimeState {
        generation: state.generation,
        next_refresh_at: state.next_refresh_at,
        auth_state: state.auth_state,
        persistence_pending: state.pending_update.is_some(),
    }
}

fn refresh_at(credentials: &CodexCredentials, account_id: &AccountId) -> Option<i64> {
    if let Some(expires_at) = credentials.expires_at() {
        let mut hasher = DefaultHasher::new();
        account_id.hash(&mut hasher);
        let jitter = i64::try_from(hasher.finish() % 31).unwrap_or_default();
        return expires_at.checked_sub(REFRESH_LEAD_SECONDS + jitter);
    }
    credentials
        .last_refreshed_at()
        .checked_add(LAST_REFRESH_FALLBACK_SECONDS)
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}
