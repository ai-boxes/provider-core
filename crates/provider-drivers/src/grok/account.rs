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
    ProviderQuotaError, ProviderQuotaErrorKind, ProviderQuotaSnapshot, ProviderQuotaSource,
    ProviderRequest, ProviderStream, RefreshError, RefreshErrorKind, RefreshOutcome,
    RefreshTrigger, StartedProviderOAuth, StoredProviderAccount, TokenCounter, WireFormat,
};

use super::{
    client::GrokClient,
    credentials::{GrokAuthError, GrokCredentials},
    models::{GrokModelClient, grok_models},
    oauth::GrokOAuthClient,
    quota::GrokQuotaClient,
    refresh::{GrokRefreshClient, validate_token_endpoint},
    request::prepare_request,
};
use crate::token_count::Cl100kTokenCounter;

const GROK_CREDENTIAL_FORMAT_VERSION: u32 = 1;
const REFRESH_LEAD_SECONDS: i64 = 5 * 60;
const PERSISTENCE_RETRY_SECONDS: i64 = 30;

/// Shared xAI implementation used by all Grok accounts.
pub struct GrokDriver {
    client: GrokClient,
    refresh_client: GrokRefreshClient,
    model_client: GrokModelClient,
    oauth_client: GrokOAuthClient,
    quota_client: GrokQuotaClient,
    token_counter: Cl100kTokenCounter,
}

/// Credential and persistence state for one Grok account.
struct GrokAccount {
    driver: Arc<GrokDriver>,
    account_id: AccountId,
    repository: Option<Arc<dyn AccountRepository>>,
    state: RwLock<GrokState>,
}

#[derive(Clone)]
struct GrokState {
    credentials: GrokCredentials,
    revision: u64,
    generation: u64,
    format_version: u32,
    expires_at: Option<i64>,
    next_refresh_at: Option<i64>,
    auth_state: AccountAuthState,
    pending_update: Option<CredentialUpdate>,
}

impl Default for GrokDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl GrokDriver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: GrokClient::new(),
            refresh_client: GrokRefreshClient::new(),
            model_client: GrokModelClient::new(),
            oauth_client: GrokOAuthClient::new(),
            quota_client: GrokQuotaClient::new(),
            token_counter: Cl100kTokenCounter,
        }
    }

    pub fn load_account(
        self: &Arc<Self>,
        account: StoredProviderAccount,
        repository: Arc<dyn AccountRepository>,
    ) -> Result<Arc<dyn ProviderAccount>, GrokAuthError> {
        GrokAccount::from_stored(self.clone(), account, repository)
            .map(|account| Arc::new(account) as Arc<dyn ProviderAccount>)
    }

    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    #[must_use]
    pub fn for_test(base_url: impl Into<String>) -> Arc<Self> {
        let base_url = base_url.into();
        Arc::new(Self {
            client: GrokClient::with_base_url(base_url.clone()),
            refresh_client: GrokRefreshClient::new(),
            model_client: GrokModelClient::for_test(),
            oauth_client: GrokOAuthClient::for_test("http://127.0.0.1/unused", base_url.clone()),
            quota_client: GrokQuotaClient::with_base_url(base_url),
            token_counter: Cl100kTokenCounter,
        })
    }

    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    #[must_use]
    pub fn for_test_with_oauth(
        base_url: impl Into<String>,
        discovery_url: impl Into<String>,
    ) -> Arc<Self> {
        let base_url = base_url.into();
        Arc::new(Self {
            client: GrokClient::with_base_url(base_url.clone()),
            refresh_client: GrokRefreshClient::new(),
            model_client: GrokModelClient::for_test(),
            oauth_client: GrokOAuthClient::for_test(discovery_url, base_url.clone()),
            quota_client: GrokQuotaClient::with_base_url(base_url),
            token_counter: Cl100kTokenCounter,
        })
    }

    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    #[must_use]
    pub fn test_account(
        self: &Arc<Self>,
        access_token: impl Into<String>,
    ) -> Arc<dyn ProviderAccount> {
        Arc::new(GrokAccount::for_test(self.clone(), access_token))
    }

    async fn execute_stream(
        &self,
        credentials: &GrokCredentials,
        request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError> {
        let prepared = prepare_request(request)?;
        self.client
            .execute_stream(
                credentials,
                prepared.payload,
                &prepared.model,
                &prepared.metadata,
            )
            .await
    }

    fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError> {
        let prepared = prepare_request(request)?;
        let input = std::str::from_utf8(&prepared.payload).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "normalized Grok request was not valid UTF-8",
            )
        })?;

        self.token_counter.count(input).map_err(|error| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                format!("failed to count Grok request tokens: {error}"),
            )
        })
    }
}

impl ProviderDriver for GrokDriver {
    fn name(&self) -> &'static str {
        "grok"
    }

    fn native_format(&self) -> WireFormat {
        WireFormat::OpenAiResponses
    }

    fn models(&self) -> &[ProviderModel] {
        grok_models()
    }
}

#[async_trait]
impl ManagedProviderDriver for GrokDriver {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Grok
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
                "Grok accounts require OAuth credential JSON",
            ));
        };
        let label = label.trim().to_owned();
        if label.is_empty() {
            return Err(ProviderConfigurationError::new(
                "Grok account label must not be empty",
            ));
        }
        let credentials = GrokCredentials::from_json(&credential_json)
            .map_err(|error| ProviderConfigurationError::new(error.to_string()))?;
        if credentials.refresh_token().is_none() {
            return Err(ProviderConfigurationError::new(
                "Grok credential is missing refresh_token",
            ));
        }
        let token_endpoint = credentials.token_endpoint().ok_or_else(|| {
            ProviderConfigurationError::new("Grok credential is missing token_endpoint")
        })?;
        validate_token_endpoint(token_endpoint, false)
            .map_err(|error| ProviderConfigurationError::new(error.message()))?;
        let expires_at = credentials
            .expires_at()
            .map_err(|error| ProviderConfigurationError::new(error.to_string()))?;
        let last_refreshed_at = credentials
            .last_refreshed_at()
            .map_err(|error| ProviderConfigurationError::new(error.to_string()))?;

        Ok(NewProviderAccount {
            id,
            provider: ProviderKind::Grok,
            label,
            config_json: "{}".to_owned(),
            enabled: true,
            credential: NewCredential {
                kind: CredentialKind::Oauth,
                format_version: GROK_CREDENTIAL_FORMAT_VERSION,
                credential_json,
                expires_at,
                last_refreshed_at,
            },
        })
    }

    fn build_account(
        self: Arc<Self>,
        account: StoredProviderAccount,
        repository: Arc<dyn AccountRepository>,
    ) -> Result<Arc<dyn ProviderAccount>, ProviderConfigurationError> {
        GrokAccount::from_stored(self, account, repository)
            .map(|account| Arc::new(account) as Arc<dyn ProviderAccount>)
            .map_err(|error| ProviderConfigurationError::new(error.to_string()))
    }

    fn prepare_account_update(
        &self,
        mut update: ProviderAccountUpdate,
    ) -> Result<ProviderAccountUpdate, ProviderConfigurationError> {
        update.label = update.label.trim().to_owned();
        if update.label.is_empty() {
            return Err(ProviderConfigurationError::new(
                "Grok account label must not be empty",
            ));
        }
        if serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&update.config_json)
            .is_err()
        {
            return Err(ProviderConfigurationError::new(
                "Grok configuration must be a JSON object",
            ));
        }
        Ok(update)
    }

    async fn start_oauth(&self) -> Result<StartedProviderOAuth, ProviderConfigurationError> {
        self.oauth_client.start().await
    }
}

impl GrokAccount {
    fn from_stored(
        driver: Arc<GrokDriver>,
        account: StoredProviderAccount,
        repository: Arc<dyn AccountRepository>,
    ) -> Result<Self, GrokAuthError> {
        if account.provider != ProviderKind::Grok {
            return Err(GrokAuthError::InvalidStoredProvider);
        }
        if account.credential.format_version != GROK_CREDENTIAL_FORMAT_VERSION {
            return Err(GrokAuthError::UnsupportedCredentialFormat(
                account.credential.format_version,
            ));
        }
        let credentials = GrokCredentials::from_json(&account.credential.credential_json)?;
        let account_id = account.id;
        let state = GrokState {
            credentials,
            revision: account.credential.revision,
            generation: 0,
            format_version: account.credential.format_version,
            expires_at: account.credential.expires_at,
            next_refresh_at: (account.auth_state == AccountAuthState::Active)
                .then(|| refresh_at(account.credential.expires_at, &account_id))
                .flatten(),
            auth_state: account.auth_state,
            pending_update: None,
        };
        Ok(Self::build(driver, account_id, state, Some(repository)))
    }

    #[cfg(feature = "test-util")]
    fn for_test(driver: Arc<GrokDriver>, access_token: impl Into<String>) -> Self {
        let account_id = static_account_id("test-grok");
        Self::build(
            driver,
            account_id,
            GrokState {
                credentials: GrokCredentials::from_access_token(access_token),
                revision: 0,
                generation: 0,
                format_version: GROK_CREDENTIAL_FORMAT_VERSION,
                expires_at: None,
                next_refresh_at: None,
                auth_state: AccountAuthState::Active,
                pending_update: None,
            },
            None,
        )
    }

    fn build(
        driver: Arc<GrokDriver>,
        account_id: AccountId,
        state: GrokState,
        repository: Option<Arc<dyn AccountRepository>>,
    ) -> Self {
        Self {
            driver,
            account_id,
            repository,
            state: RwLock::new(state),
        }
    }

    fn state(&self) -> RwLockReadGuard<'_, GrokState> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn state_mut(&self) -> RwLockWriteGuard<'_, GrokState> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn snapshot(&self) -> GrokCredentials {
        self.state().credentials.clone()
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
                state.next_refresh_at = refresh_at(state.expires_at, &self.account_id);
                Ok(RefreshOutcome {
                    state: runtime_state(&state),
                })
            }
            Ok(CredentialWriteOutcome::Conflict) => Err(RefreshError::new(
                RefreshErrorKind::Internal,
                "Grok credential revision conflict",
            )),
            Err(_) => {
                eprintln!(
                    "failed to persist refreshed Grok credential for account {}",
                    self.account_id
                );
                let mut state = self.state_mut();
                state.next_refresh_at = unix_timestamp().checked_add(PERSISTENCE_RETRY_SECONDS);
                Ok(RefreshOutcome {
                    state: runtime_state(&state),
                })
            }
        }
    }

    async fn credentials_with_upstream_user_id(
        &self,
    ) -> Result<GrokCredentials, ProviderQuotaError> {
        let current = self.state().clone();
        if current.credentials.upstream_user_id().is_some() {
            return Ok(current.credentials);
        }
        let user_id = self
            .driver
            .quota_client
            .fetch_user_id(&current.credentials)
            .await?;
        let credentials = current
            .credentials
            .with_upstream_user_id(&user_id)
            .map_err(|_| {
                ProviderQuotaError::new(
                    ProviderQuotaErrorKind::Internal,
                    "failed to update Grok upstream user ID",
                )
            })?;
        let credential_json = credentials.to_json().map_err(|_| {
            ProviderQuotaError::new(
                ProviderQuotaErrorKind::Internal,
                "failed to serialize Grok credential",
            )
        })?;

        {
            let mut state = self.state_mut();
            if state.revision == current.revision && state.pending_update.is_some() {
                state.credentials = credentials.clone();
                if let Some(pending) = state.pending_update.as_mut() {
                    pending.credential_json = credential_json;
                }
                return Ok(credentials);
            }
        }

        let Some(repository) = self.repository.as_ref() else {
            return Ok(credentials);
        };
        let last_refreshed_at = current.credentials.last_refreshed_at().map_err(|_| {
            ProviderQuotaError::new(
                ProviderQuotaErrorKind::Internal,
                "Grok credential has an invalid refresh timestamp",
            )
        })?;
        let update = CredentialUpdate {
            expected_revision: current.revision,
            kind: CredentialKind::Oauth,
            format_version: current.format_version,
            credential_json,
            expires_at: current.expires_at,
            last_refreshed_at,
            updated_at: unix_timestamp(),
        };
        match repository
            .compare_and_swap_credential(&self.account_id, update)
            .await
        {
            Ok(CredentialWriteOutcome::Updated { revision }) => {
                let mut state = self.state_mut();
                if state.revision == current.revision {
                    state.credentials = credentials.clone();
                    state.revision = revision;
                }
            }
            Ok(CredentialWriteOutcome::Conflict) => {}
            Err(_) => {
                eprintln!(
                    "failed to persist Grok upstream user ID for account {}",
                    self.account_id
                );
            }
        }
        Ok(credentials)
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
    }
}

#[async_trait]
impl ProviderAccount for GrokAccount {
    fn provider_name(&self) -> &'static str {
        "grok"
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn runtime_state(&self) -> AccountRuntimeState {
        runtime_state(&self.state())
    }

    fn credential_revision(&self) -> u64 {
        self.state().revision
    }

    async fn execute_stream(
        &self,
        request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError> {
        let credentials = self
            .credentials_with_upstream_user_id()
            .await
            .map_err(quota_provider_error)?;
        self.driver.execute_stream(&credentials, request).await
    }

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError> {
        self.driver.count_tokens(request)
    }

    async fn discover_models(
        &self,
    ) -> Result<Vec<provider_core::DiscoveredProviderModel>, ProviderError> {
        let credentials = self.snapshot();
        self.driver.model_client.discover(&credentials).await
    }

    fn fallback_models(&self) -> &[ProviderModel] {
        self.driver.models()
    }

    fn quota_source(&self) -> Option<&dyn ProviderQuotaSource> {
        Some(self)
    }

    async fn refresh_credentials(
        &self,
        _trigger: RefreshTrigger,
    ) -> Result<RefreshOutcome, RefreshError> {
        let repository = self.repository.as_ref().ok_or_else(|| {
            RefreshError::new(
                RefreshErrorKind::Internal,
                "Grok account has no credential repository",
            )
        })?;
        let pending = { self.state().pending_update.clone() };
        if let Some(pending) = pending {
            return self.persist_pending(repository, pending).await;
        }

        let current = self.state().clone();
        if current.auth_state == AccountAuthState::ReauthRequired {
            return Err(RefreshError::new(
                RefreshErrorKind::ReauthRequired,
                "Grok account requires authorization",
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
        let (credentials, expires_at) = current
            .credentials
            .refreshed(&tokens, refreshed_at)
            .map_err(|error| {
                RefreshError::new(
                    RefreshErrorKind::Internal,
                    format!("failed to update Grok credential: {error}"),
                )
            })?;
        let credential_json = credentials.to_json().map_err(|error| {
            RefreshError::new(
                RefreshErrorKind::Internal,
                format!("failed to serialize Grok credential: {error}"),
            )
        })?;
        let update = CredentialUpdate {
            expected_revision: current.revision,
            kind: CredentialKind::Oauth,
            format_version: current.format_version,
            credential_json,
            expires_at: Some(expires_at),
            last_refreshed_at: Some(refreshed_at),
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
                state.expires_at = Some(expires_at);
                state.next_refresh_at = refresh_at(Some(expires_at), &self.account_id);
                state.auth_state = AccountAuthState::Active;
                state.pending_update = None;
                Ok(RefreshOutcome {
                    state: runtime_state(&state),
                })
            }
            Ok(CredentialWriteOutcome::Conflict) => Err(RefreshError::new(
                RefreshErrorKind::Internal,
                "Grok credential revision conflict",
            )),
            Err(_) => {
                eprintln!(
                    "failed to persist refreshed Grok credential for account {}",
                    self.account_id
                );
                let mut state = self.state_mut();
                state.credentials = credentials;
                state.generation = state.generation.saturating_add(1);
                state.expires_at = Some(expires_at);
                state.next_refresh_at = refreshed_at.checked_add(PERSISTENCE_RETRY_SECONDS);
                state.auth_state = AccountAuthState::Active;
                state.pending_update = Some(update);
                Ok(RefreshOutcome {
                    state: runtime_state(&state),
                })
            }
        }
    }
}

#[async_trait]
impl ProviderQuotaSource for GrokAccount {
    async fn fetch_quota(&self) -> Result<ProviderQuotaSnapshot, ProviderQuotaError> {
        let credentials = self.credentials_with_upstream_user_id().await?;
        let user_id = credentials.upstream_user_id().ok_or_else(|| {
            ProviderQuotaError::new(
                ProviderQuotaErrorKind::Internal,
                "Grok credential is missing upstream user ID",
            )
        })?;
        self.driver
            .quota_client
            .fetch_quota(self.account_id.as_str(), &credentials, user_id)
            .await
    }
}

fn quota_provider_error(error: ProviderQuotaError) -> ProviderError {
    let kind = match error.kind() {
        ProviderQuotaErrorKind::Authentication => ProviderErrorKind::Authentication,
        ProviderQuotaErrorKind::Unsupported
        | ProviderQuotaErrorKind::RateLimited
        | ProviderQuotaErrorKind::Upstream
        | ProviderQuotaErrorKind::InvalidResponse => ProviderErrorKind::Upstream,
        ProviderQuotaErrorKind::Internal => ProviderErrorKind::Internal,
    };
    let mut provider_error = ProviderError::new(kind, error.message());
    if let Some(status) = error.upstream_status() {
        provider_error = provider_error.with_upstream_status(status);
    }
    provider_error
}

fn runtime_state(state: &GrokState) -> AccountRuntimeState {
    AccountRuntimeState {
        generation: state.generation,
        next_refresh_at: state.next_refresh_at,
        auth_state: state.auth_state,
        persistence_pending: state.pending_update.is_some(),
    }
}

fn refresh_at(expires_at: Option<i64>, account_id: &AccountId) -> Option<i64> {
    let expires_at = expires_at?;
    let mut hasher = DefaultHasher::new();
    account_id.hash(&mut hasher);
    let jitter = i64::try_from(hasher.finish() % 31).unwrap_or_default();
    expires_at.checked_sub(REFRESH_LEAD_SECONDS + jitter)
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

#[cfg(feature = "test-util")]
fn static_account_id(value: &str) -> AccountId {
    match AccountId::new(value) {
        Ok(account_id) => account_id,
        Err(_) => unreachable!("static account ID must be valid"),
    }
}
