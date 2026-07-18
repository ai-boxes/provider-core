use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use provider_core::{
    AccountAuthState, AccountId, AccountRepository, AccountRuntimeState, CredentialUpdate,
    CredentialWriteOutcome, Protocol, Provider, ProviderAccount, ProviderError, ProviderErrorKind,
    ProviderModel, ProviderStream, ProxyRequest, RefreshError, RefreshErrorKind, RefreshOutcome,
    RefreshTrigger, StoredProviderAccount, TokenCounter,
};

use crate::{
    Cl100kTokenCounter, GrokAuthError, GrokClient, GrokCredentials, grok_models,
    refresh::GrokRefreshClient,
    request::{prepare_claude_request, prepare_codex_request},
    response::adapt_grok_stream_to_claude,
};

const GROK_CREDENTIAL_FORMAT_VERSION: u32 = 1;
const REFRESH_LEAD_SECONDS: i64 = 5 * 60;
const PERSISTENCE_RETRY_SECONDS: i64 = 30;

/// Grok adapter and credential state for one provider account.
#[derive(Clone)]
pub struct GrokProvider {
    account_id: AccountId,
    repository: Option<Arc<dyn AccountRepository>>,
    state: Arc<RwLock<GrokState>>,
    client: GrokClient,
    refresh_client: GrokRefreshClient,
    token_counter: Cl100kTokenCounter,
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

impl GrokProvider {
    pub fn from_stored(
        account: StoredProviderAccount,
        repository: Arc<dyn AccountRepository>,
    ) -> Result<Self, GrokAuthError> {
        if account.provider.trim() != "grok" {
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
        Ok(Self::build(
            account_id,
            state,
            Some(repository),
            GrokClient::new(),
        ))
    }

    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    pub fn for_test(access_token: impl Into<String>, base_url: impl Into<String>) -> Self {
        let account_id = static_account_id("test-grok");
        Self::build(
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
            GrokClient::with_base_url(base_url),
        )
    }

    fn build(
        account_id: AccountId,
        state: GrokState,
        repository: Option<Arc<dyn AccountRepository>>,
        client: GrokClient,
    ) -> Self {
        Self {
            account_id,
            repository,
            state: Arc::new(RwLock::new(state)),
            client,
            refresh_client: GrokRefreshClient::new(),
            token_counter: Cl100kTokenCounter,
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
impl Provider for GrokProvider {
    fn name(&self) -> &'static str {
        "grok"
    }

    fn models(&self) -> &[ProviderModel] {
        grok_models()
    }

    async fn execute_stream(&self, request: ProxyRequest) -> Result<ProviderStream, ProviderError> {
        let credentials = self.snapshot();
        match request.protocol {
            Protocol::CodexResponses => {
                let prepared = prepare_codex_request(request)?;
                self.client
                    .execute_stream(&credentials, prepared.payload, &prepared.metadata)
                    .await
            }
            Protocol::ClaudeMessages => {
                let prepared = prepare_claude_request(request)?;
                let stream = self
                    .client
                    .execute_stream(
                        &credentials,
                        prepared.upstream.payload,
                        &prepared.upstream.metadata,
                    )
                    .await?;
                Ok(adapt_grok_stream_to_claude(stream, prepared.response))
            }
        }
    }

    async fn count_tokens(&self, request: ProxyRequest) -> Result<u64, ProviderError> {
        let prepared = match request.protocol {
            Protocol::CodexResponses => prepare_codex_request(request)?,
            Protocol::ClaudeMessages => prepare_claude_request(request)?.upstream,
        };
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

#[async_trait]
impl ProviderAccount for GrokProvider {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn runtime_state(&self) -> AccountRuntimeState {
        runtime_state(&self.state())
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
        let tokens = match self.refresh_client.refresh(&current.credentials).await {
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
