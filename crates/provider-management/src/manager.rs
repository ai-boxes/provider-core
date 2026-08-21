use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex as StdMutex, PoisonError, Weak},
    time::{SystemTime, UNIX_EPOCH},
};

use provider_core::{
    AccountAuthState, AccountId, AccountProvisioningInput, CredentialKind, ProviderAccountSummary,
    ProviderAccountUpdate, ProviderControl, ProviderControlError, ProviderKind,
    ProviderManagementRepository, ProviderModelOverride, ProviderModelPricingCatalog,
    ProviderOAuthChallenge, ProviderQuotaErrorKind, ProviderQuotaFreshness,
    ProviderQuotaObservation, ProviderQuotaSupport, ProviderQuotaView, ProviderSnapshot,
    ProviderSnapshotWriteOutcome, ProviderVisibility, QuotaGroupAudience, StoredCredential,
    StoredProviderAccount, StoredProviderModel, merge_quota_groups,
};
use secrecy::SecretString;
use thiserror::Error;
use tokio::{sync::Mutex as AsyncMutex, task::AbortHandle};
use uuid::Uuid;

use crate::{ModelCatalogError, ModelCatalogService, ModelCatalogSnapshot};

const QUOTA_FRESH_SECONDS: i64 = 30;
const QUOTA_RETRY_SECONDS: i64 = 30;
const QUOTA_STALE_SECONDS: i64 = 15 * 60;

pub struct CreatedProviderAccount {
    pub account: ProviderAccountSummary,
    pub models: ModelCatalogSnapshot,
}

pub struct DirectProviderAccountInput {
    pub kind: ProviderKind,
    pub label: String,
    pub group_label: String,
    pub priority: u32,
    pub config_json: String,
    pub api_key: SecretString,
    pub visibility: ProviderVisibility,
}

pub struct CredentialProviderAccountInput {
    pub kind: ProviderKind,
    pub label: String,
    pub group_label: String,
    pub priority: u32,
    pub credential_json: SecretString,
    pub visibility: ProviderVisibility,
}

pub struct ProviderCredentialReplacement {
    pub kind: CredentialKind,
    pub format_version: u32,
    pub credential_json: SecretString,
    pub expires_at: Option<i64>,
    pub last_refreshed_at: Option<i64>,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthSessionStatus {
    Pending,
    Provisioning,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug)]
pub struct OAuthSessionSnapshot {
    pub id: String,
    pub owner_user_id: String,
    pub visibility: ProviderVisibility,
    pub provider: ProviderKind,
    pub account_id: AccountId,
    pub label: String,
    pub group_label: String,
    pub priority: u32,
    pub status: OAuthSessionStatus,
    pub challenge: ProviderOAuthChallenge,
    pub error: Option<String>,
}

struct OAuthSessionEntry {
    snapshot: OAuthSessionSnapshot,
    abort: Option<AbortHandle>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OAuthSessionTarget {
    Create,
    Reauthenticate,
}

struct OAuthSessionStart {
    owner_user_id: String,
    kind: ProviderKind,
    label: String,
    group_label: String,
    priority: u32,
    visibility: ProviderVisibility,
    account_id: AccountId,
    target: OAuthSessionTarget,
}

#[derive(Clone)]
struct QuotaCacheEntry {
    credential_revision: u64,
    snapshot: Option<provider_core::ProviderQuotaSnapshot>,
    last_full_fetch_at: Option<i64>,
    last_observation_generation: u64,
    last_error: Option<ProviderQuotaErrorKind>,
    last_attempt_at: i64,
    attempt: u64,
}

#[derive(Default)]
struct QuotaState {
    entries: StdMutex<BTreeMap<AccountId, QuotaCacheEntry>>,
    gates: StdMutex<BTreeMap<AccountId, Weak<AsyncMutex<()>>>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum QuotaFetchMode {
    Automatic,
    Force,
}

#[derive(Clone)]
pub struct ProviderManager {
    repository: Arc<dyn ProviderManagementRepository>,
    control: Arc<dyn ProviderControl>,
    models: ModelCatalogService,
    oauth_sessions: Arc<StdMutex<BTreeMap<String, OAuthSessionEntry>>>,
    quota: Arc<QuotaState>,
}

impl ProviderManager {
    #[must_use]
    pub fn new(
        repository: Arc<dyn ProviderManagementRepository>,
        control: Arc<dyn ProviderControl>,
    ) -> Self {
        Self {
            models: ModelCatalogService::new(),
            repository,
            control,
            oauth_sessions: Arc::new(StdMutex::new(BTreeMap::new())),
            quota: Arc::new(QuotaState::default()),
        }
    }

    #[must_use]
    pub fn with_model_pricing_catalog(
        repository: Arc<dyn ProviderManagementRepository>,
        control: Arc<dyn ProviderControl>,
        pricing: Arc<dyn ProviderModelPricingCatalog>,
    ) -> Self {
        Self {
            models: ModelCatalogService::with_pricing(pricing),
            repository,
            control,
            oauth_sessions: Arc::new(StdMutex::new(BTreeMap::new())),
            quota: Arc::new(QuotaState::default()),
        }
    }

    pub async fn create_direct_account(
        &self,
        owner_user_id: &str,
        input: DirectProviderAccountInput,
        now: i64,
    ) -> Result<CreatedProviderAccount, ProviderManagerError> {
        let id = generated_account_id();
        let group_label = normalize_group_label(input.group_label)?;
        self.create_account(
            owner_user_id,
            input.kind,
            AccountProvisioningInput::Direct {
                id,
                label: input.label,
                group_label,
                config_json: input.config_json,
                api_key: input.api_key,
            },
            input.priority,
            input.visibility,
            now,
        )
        .await
    }

    pub async fn create_credential_account(
        &self,
        owner_user_id: &str,
        input: CredentialProviderAccountInput,
        now: i64,
    ) -> Result<CreatedProviderAccount, ProviderManagerError> {
        let id = generated_account_id();
        let group_label = normalize_group_label(input.group_label)?;
        self.create_account(
            owner_user_id,
            input.kind,
            AccountProvisioningInput::CredentialJson {
                id,
                label: input.label,
                group_label,
                credential_json: input.credential_json,
            },
            input.priority,
            input.visibility,
            now,
        )
        .await
    }

    pub async fn start_oauth_session(
        &self,
        owner_user_id: &str,
        kind: ProviderKind,
        label: String,
        group_label: String,
        priority: u32,
        visibility: ProviderVisibility,
    ) -> Result<OAuthSessionSnapshot, ProviderManagerError> {
        self.start_oauth_session_for_target(OAuthSessionStart {
            owner_user_id: owner_user_id.to_owned(),
            kind,
            label,
            group_label,
            priority,
            visibility,
            account_id: generated_account_id(),
            target: OAuthSessionTarget::Create,
        })
        .await
    }

    pub async fn start_oauth_reauth_session(
        &self,
        owner_user_id: &str,
        account_id: &AccountId,
    ) -> Result<OAuthSessionSnapshot, ProviderManagerError> {
        let current = self.load_owned_account(owner_user_id, account_id).await?;
        if current.credential.kind != CredentialKind::Oauth
            || !matches!(current.provider, ProviderKind::Grok | ProviderKind::Codex)
        {
            return Err(ProviderManagerError::InvalidInput(
                "provider account does not support OAuth reauthorization",
            ));
        }

        self.start_oauth_session_for_target(OAuthSessionStart {
            owner_user_id: owner_user_id.to_owned(),
            kind: current.provider,
            label: current.label,
            group_label: current.group_label,
            priority: current.priority,
            visibility: current.visibility,
            account_id: account_id.clone(),
            target: OAuthSessionTarget::Reauthenticate,
        })
        .await
    }

    async fn start_oauth_session_for_target(
        &self,
        input: OAuthSessionStart,
    ) -> Result<OAuthSessionSnapshot, ProviderManagerError> {
        let OAuthSessionStart {
            owner_user_id,
            kind,
            label,
            group_label,
            priority,
            visibility,
            account_id,
            target,
        } = input;
        if matches!(
            kind,
            ProviderKind::OpenAiCompatible | ProviderKind::AnthropicCompatible
        ) {
            return Err(ProviderManagerError::InvalidInput(
                "provider does not support OAuth onboarding",
            ));
        }
        let label = label.trim().to_owned();
        if label.is_empty() {
            return Err(ProviderManagerError::InvalidInput(
                "provider account label must not be empty",
            ));
        }
        let group_label = normalize_group_label(group_label)?;
        let started = self
            .control
            .start_oauth(kind)
            .await
            .map_err(ProviderManagerError::OAuthStart)?;
        let session_id = Uuid::new_v4().to_string();
        let snapshot = OAuthSessionSnapshot {
            id: session_id.clone(),
            owner_user_id: owner_user_id.clone(),
            visibility,
            provider: kind,
            account_id: account_id.clone(),
            label: label.clone(),
            group_label: group_label.clone(),
            priority,
            status: OAuthSessionStatus::Pending,
            challenge: started.challenge,
            error: None,
        };
        self.oauth_sessions().insert(
            session_id.clone(),
            OAuthSessionEntry {
                snapshot: snapshot.clone(),
                abort: None,
            },
        );

        let manager = self.clone();
        let task_session_id = session_id.clone();
        let handle = tokio::spawn(async move {
            let result = match started.pending.complete().await {
                Ok(credential_json) => {
                    if !manager.begin_oauth_provisioning(&task_session_id) {
                        return;
                    }
                    if target == OAuthSessionTarget::Reauthenticate {
                        manager
                            .update_oauth_credential_from_json(
                                &owner_user_id,
                                &account_id,
                                credential_json,
                            )
                            .await
                            .map(|_| ())
                            .map_err(|error| error.to_string())
                    } else {
                        manager
                            .create_account(
                                &owner_user_id,
                                kind,
                                AccountProvisioningInput::CredentialJson {
                                    id: account_id,
                                    label,
                                    group_label,
                                    credential_json,
                                },
                                priority,
                                visibility,
                                unix_timestamp(),
                            )
                            .await
                            .map(|_| ())
                            .map_err(|error| error.to_string())
                    }
                }
                Err(error) => Err(error.to_string()),
            };
            manager.finish_oauth_session(&task_session_id, result);
        });
        let abort = handle.abort_handle();
        if let Some(entry) = self.oauth_sessions().get_mut(&session_id)
            && entry.snapshot.status == OAuthSessionStatus::Pending
        {
            entry.abort = Some(abort);
        }

        Ok(snapshot)
    }

    pub fn oauth_session(
        &self,
        actor_user_id: &str,
        session_id: &str,
    ) -> Option<OAuthSessionSnapshot> {
        self.oauth_sessions()
            .get(session_id)
            .filter(|entry| entry.snapshot.owner_user_id == actor_user_id)
            .map(|entry| entry.snapshot.clone())
    }

    pub fn cancel_oauth_session(
        &self,
        actor_user_id: &str,
        session_id: &str,
    ) -> Option<OAuthSessionSnapshot> {
        let mut sessions = self.oauth_sessions();
        let entry = sessions.get_mut(session_id)?;
        if entry.snapshot.owner_user_id != actor_user_id {
            return None;
        }
        cancel_pending_oauth(entry);
        Some(entry.snapshot.clone())
    }

    pub async fn list_accounts(
        &self,
        actor_user_id: &str,
    ) -> Result<Vec<ProviderAccountSummary>, ProviderManagerError> {
        Ok(self
            .repository
            .list_provider_accounts(actor_user_id)
            .await?)
    }

    /// Load the complete account fleet for an already-authorized operations
    /// view. The HTTP layer is responsible for enforcing `super_admin` before
    /// calling this method.
    pub async fn list_all_accounts(
        &self,
    ) -> Result<Vec<ProviderAccountSummary>, ProviderManagerError> {
        Ok(self.repository.list_all_provider_accounts().await?)
    }

    pub fn claim_unowned_account_access(&self, owner_user_id: &str) {
        self.control.claim_unowned_account_access(owner_user_id);
    }

    pub async fn get_account(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
    ) -> Result<ProviderAccountSummary, ProviderManagerError> {
        Ok(account_summary(
            &self.load_visible_account(actor_user_id, account_id).await?,
        ))
    }

    pub async fn cached_quota(
        &self,
        actor_user_id: &str,
        account: &ProviderAccountSummary,
        now: i64,
    ) -> ProviderQuotaView {
        if !self.control.supports_quota(account.provider) {
            return ProviderQuotaView::unsupported();
        }
        let observation = self.control.quota_observation(&account.id).await;
        self.cached_quota_entry_with_observation(
            &account.id,
            account.credential_revision,
            observation,
        )
        .map_or_else(ProviderQuotaView::supported_without_snapshot, |entry| {
            quota_cache_view(&entry, account.owner_user_id.as_deref(), actor_user_id, now)
        })
    }

    pub async fn quota(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        now: i64,
    ) -> Result<ProviderQuotaView, ProviderManagerError> {
        self.fetch_quota_view(actor_user_id, account_id, now, QuotaFetchMode::Automatic)
            .await
    }

    pub async fn refresh_quota(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        now: i64,
    ) -> Result<ProviderQuotaView, ProviderManagerError> {
        self.fetch_quota_view(actor_user_id, account_id, now, QuotaFetchMode::Force)
            .await
    }

    pub async fn create_account(
        &self,
        owner_user_id: &str,
        kind: ProviderKind,
        input: AccountProvisioningInput,
        priority: u32,
        visibility: ProviderVisibility,
        now: i64,
    ) -> Result<CreatedProviderAccount, ProviderManagerError> {
        let prepared = self.control.prepare_account(kind, input)?;
        let stored = StoredProviderAccount {
            id: prepared.id,
            owner_user_id: Some(owner_user_id.to_owned()),
            visibility,
            provider: prepared.provider,
            label: prepared.label,
            group_label: prepared.group_label,
            priority,
            config_json: prepared.config_json,
            enabled: prepared.enabled,
            auth_state: AccountAuthState::Active,
            safe_error_code: None,
            created_at: now,
            updated_at: now,
            credential: StoredCredential {
                kind: prepared.credential.kind,
                revision: 0,
                format_version: prepared.credential.format_version,
                credential_json: prepared.credential.credential_json,
                expires_at: prepared.credential.expires_at,
                last_refreshed_at: prepared.credential.last_refreshed_at,
                updated_at: now,
            },
        };
        let runtime_account = self.control.build_account(stored.clone())?;
        let discovered = self.models.discover(runtime_account.as_ref()).await?;
        let models = self
            .commit_candidate(
                stored.clone(),
                runtime_account,
                discovered,
                true,
                true,
                None,
            )
            .await?;
        Ok(CreatedProviderAccount {
            account: account_summary(&stored),
            models: ModelCatalogSnapshot { models },
        })
    }

    pub async fn update_account(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        mut update: ProviderAccountUpdate,
    ) -> Result<ProviderAccountSummary, ProviderManagerError> {
        self.load_owned_account(actor_user_id, account_id).await?;
        let gate = self.account_gate(account_id);
        let _guard = gate.lock().await;
        let current = self.load_owned_account(actor_user_id, account_id).await?;
        update.group_label = normalize_group_label(update.group_label)?;
        let update = self
            .control
            .prepare_account_update(current.provider, update)?;
        let reset_models = current.config_json != update.config_json;
        let rebuild_runtime = reset_models || current.priority != update.priority;
        if !rebuild_runtime {
            let access_changed = current.visibility != update.visibility;
            if !self
                .repository
                .update_provider_account(account_id, update)
                .await?
            {
                return Err(ProviderManagerError::NotFound);
            }
            let stored = self.load_account(account_id).await?;
            if access_changed {
                self.control
                    .update_account_access(account_id, stored.access());
            }
            return Ok(account_summary(&stored));
        }
        let mut candidate = current.clone();
        candidate.label = update.label;
        candidate.group_label = update.group_label;
        candidate.priority = update.priority;
        candidate.config_json = update.config_json;
        candidate.visibility = update.visibility;
        candidate.updated_at = update.updated_at;
        let runtime_account = self.control.build_account(candidate.clone())?;
        let discovered = self.models.discover(runtime_account.as_ref()).await?;
        self.commit_candidate(
            candidate.clone(),
            runtime_account,
            discovered,
            true,
            reset_models,
            Some(current.credential.revision),
        )
        .await?;
        Ok(account_summary(&candidate))
    }

    pub async fn update_account_with_credential(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        mut update: ProviderAccountUpdate,
        replacement: ProviderCredentialReplacement,
    ) -> Result<ProviderAccountSummary, ProviderManagerError> {
        self.load_owned_account(actor_user_id, account_id).await?;
        let gate = self.account_gate(account_id);
        let _guard = gate.lock().await;
        let current = self.load_owned_account(actor_user_id, account_id).await?;
        update.group_label = normalize_group_label(update.group_label)?;
        let update = self
            .control
            .prepare_account_update(current.provider, update)?;
        let reset_models = current.config_json != update.config_json;
        let mut candidate = current.clone();
        candidate.label = update.label;
        candidate.group_label = update.group_label;
        candidate.priority = update.priority;
        candidate.config_json = update.config_json;
        candidate.visibility = update.visibility;
        candidate.updated_at = update.updated_at;
        candidate.auth_state = AccountAuthState::Active;
        candidate.safe_error_code = None;
        candidate.credential = replacement_credential(&current, replacement)?;
        self.control
            .validate_credential_replacement(current.provider, &candidate.credential)?;
        let runtime_account = self.control.build_account(candidate.clone())?;
        let discovered = self.models.discover(runtime_account.as_ref()).await?;
        self.commit_candidate(
            candidate.clone(),
            runtime_account,
            discovered,
            true,
            reset_models,
            Some(current.credential.revision),
        )
        .await?;
        self.invalidate_quota(account_id);
        Ok(account_summary(&candidate))
    }

    pub async fn update_credential(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        replacement: ProviderCredentialReplacement,
    ) -> Result<ProviderAccountSummary, ProviderManagerError> {
        self.load_owned_account(actor_user_id, account_id).await?;
        let gate = self.account_gate(account_id);
        let _guard = gate.lock().await;
        let current = self.load_owned_account(actor_user_id, account_id).await?;
        let mut candidate = current.clone();
        candidate.updated_at = replacement.updated_at;
        candidate.auth_state = AccountAuthState::Active;
        candidate.safe_error_code = None;
        candidate.credential = replacement_credential(&current, replacement)?;
        self.control
            .validate_credential_replacement(current.provider, &candidate.credential)?;
        let runtime_account = self.control.build_account(candidate.clone())?;
        let discovered = self.models.discover(runtime_account.as_ref()).await?;
        self.commit_candidate(
            candidate.clone(),
            runtime_account,
            discovered,
            true,
            false,
            Some(current.credential.revision),
        )
        .await?;
        self.invalidate_quota(account_id);
        Ok(account_summary(&candidate))
    }

    async fn update_oauth_credential_from_json(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        credential_json: SecretString,
    ) -> Result<ProviderAccountSummary, ProviderManagerError> {
        let current = self.load_owned_account(actor_user_id, account_id).await?;
        if current.credential.kind != CredentialKind::Oauth {
            return Err(ProviderManagerError::InvalidInput(
                "provider account does not use OAuth credentials",
            ));
        }
        let prepared = self.control.prepare_account(
            current.provider,
            AccountProvisioningInput::CredentialJson {
                id: current.id.clone(),
                label: current.label.clone(),
                group_label: current.group_label.clone(),
                credential_json,
            },
        )?;
        let replacement = ProviderCredentialReplacement {
            kind: prepared.credential.kind,
            format_version: prepared.credential.format_version,
            credential_json: prepared.credential.credential_json,
            expires_at: prepared.credential.expires_at,
            last_refreshed_at: prepared.credential.last_refreshed_at,
            updated_at: unix_timestamp(),
        };

        self.update_credential(actor_user_id, account_id, replacement)
            .await
    }

    pub async fn set_account_enabled(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        enabled: bool,
        updated_at: i64,
    ) -> Result<ProviderAccountSummary, ProviderManagerError> {
        self.load_owned_account(actor_user_id, account_id).await?;
        let gate = self.account_gate(account_id);
        let _guard = gate.lock().await;
        let current = self.load_owned_account(actor_user_id, account_id).await?;
        let mut candidate = current.clone();
        candidate.enabled = enabled;
        candidate.updated_at = updated_at;
        let runtime_account = self.control.build_account(candidate.clone())?;
        let discovered = if enabled {
            self.models.discover(runtime_account.as_ref()).await?
        } else {
            Vec::new()
        };
        self.commit_candidate(
            candidate.clone(),
            runtime_account,
            discovered,
            enabled,
            false,
            Some(current.credential.revision),
        )
        .await?;
        Ok(account_summary(&candidate))
    }

    pub async fn delete_account(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
    ) -> Result<(), ProviderManagerError> {
        self.load_owned_account(actor_user_id, account_id).await?;
        let gate = self.account_gate(account_id);
        let _guard = gate.lock().await;
        self.load_owned_account(actor_user_id, account_id).await?;
        if !self.repository.delete_provider_account(account_id).await? {
            return Err(ProviderManagerError::NotFound);
        }
        self.invalidate_quota(account_id);
        self.control.remove_account(account_id).await;
        self.remove_account_gate(account_id);
        Ok(())
    }

    pub async fn list_models(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
    ) -> Result<Vec<StoredProviderModel>, ProviderManagerError> {
        self.load_visible_account(actor_user_id, account_id).await?;
        Ok(self
            .repository
            .list_provider_models(Some(account_id))
            .await?)
    }

    pub async fn refresh_models(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        now: i64,
    ) -> Result<ModelCatalogSnapshot, ProviderManagerError> {
        self.load_owned_account(actor_user_id, account_id).await?;
        let gate = self.account_gate(account_id);
        let _guard = gate.lock().await;
        let mut stored = self.load_owned_account(actor_user_id, account_id).await?;
        stored.updated_at = now;
        let account = self.control.build_account(stored.clone())?;
        let discovered = self.models.discover(account.as_ref()).await?;
        let models = self
            .commit_candidate(
                stored.clone(),
                account,
                discovered,
                true,
                false,
                Some(stored.credential.revision),
            )
            .await?;
        Ok(ModelCatalogSnapshot { models })
    }

    /// Re-discover every enabled account after the shared model catalog changes.
    /// Repository synchronization updates catalog-sourced prices and capabilities,
    /// then activation replaces the routing snapshot before the cycle completes.
    pub async fn refresh_enabled_model_catalogs(
        &self,
        now: i64,
    ) -> Result<(), ProviderManagerError> {
        let mut first_error = None;
        for stored in self.repository.load_enabled_accounts().await? {
            let result = async {
                let account_id = stored.id.clone();
                let gate = self.account_gate(&account_id);
                let _guard = gate.lock().await;
                let mut stored = self.load_account(&account_id).await?;
                if !stored.enabled {
                    return Ok(());
                }
                stored.updated_at = now;
                let account = self.control.build_account(stored.clone())?;
                let discovered = self.models.discover(account.as_ref()).await?;
                self.commit_candidate(
                    stored.clone(),
                    account,
                    discovered,
                    true,
                    false,
                    Some(stored.credential.revision),
                )
                .await?;
                Ok(())
            }
            .await;
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub async fn update_model(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        upstream_model: &str,
        update: ProviderModelOverride,
    ) -> Result<Vec<StoredProviderModel>, ProviderManagerError> {
        self.load_owned_account(actor_user_id, account_id).await?;
        let gate = self.account_gate(account_id);
        let _guard = gate.lock().await;
        self.load_owned_account(actor_user_id, account_id).await?;
        if !self
            .repository
            .update_provider_model(account_id, upstream_model, update)
            .await?
        {
            return Err(ProviderManagerError::NotFound);
        }
        let stored = self.load_account(account_id).await?;
        let models = self
            .repository
            .list_provider_models(Some(account_id))
            .await?;
        if stored.enabled {
            self.control
                .update_account_models(account_id, models.clone());
        }
        Ok(models)
    }

    async fn fetch_quota_view(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        now: i64,
        mode: QuotaFetchMode,
    ) -> Result<ProviderQuotaView, ProviderManagerError> {
        let visible = self.load_visible_account(actor_user_id, account_id).await?;
        if !self.control.supports_quota(visible.provider) {
            return Ok(ProviderQuotaView::unsupported());
        }
        let initial_credential_revision = visible.credential.revision;
        let initial_observation = self.control.quota_observation(account_id).await;
        let initial_entry = self.cached_quota_entry_with_observation(
            account_id,
            initial_credential_revision,
            initial_observation,
        );
        let initial_attempt = initial_entry.as_ref().map_or(0, |entry| entry.attempt);
        let gate = self.account_gate(account_id);
        let _guard = gate.lock().await;
        let account = self.load_visible_account(actor_user_id, account_id).await?;
        let owner_user_id = account.owner_user_id.as_deref();
        let observation = self.control.quota_observation(account_id).await;
        let observation_generation_at_start = observation
            .as_ref()
            .filter(|observation| observation.credential_revision == account.credential.revision)
            .map_or(0, |observation| observation.generation);
        let cached = self.cached_quota_entry_with_observation(
            account_id,
            account.credential.revision,
            observation,
        );
        let observation_generation_at_start =
            cached
                .as_ref()
                .map_or(observation_generation_at_start, |entry| {
                    entry
                        .last_observation_generation
                        .max(observation_generation_at_start)
                });

        if let Some(entry) = cached.as_ref() {
            if mode == QuotaFetchMode::Force
                && (account.credential.revision != initial_credential_revision
                    || entry.attempt > initial_attempt)
            {
                return Ok(quota_cache_view(entry, owner_user_id, actor_user_id, now));
            }
            if entry.last_error.is_some()
                && elapsed_seconds(now, entry.last_attempt_at) < QUOTA_RETRY_SECONDS
            {
                return Ok(quota_cache_view(entry, owner_user_id, actor_user_id, now));
            }
            if mode == QuotaFetchMode::Automatic
                && entry.last_error.is_none()
                && entry.last_full_fetch_at.is_some_and(|fetched_at| {
                    elapsed_seconds(now, fetched_at) < QUOTA_FRESH_SECONDS
                })
            {
                return Ok(quota_cache_view(entry, owner_user_id, actor_user_id, now));
            }
        }

        let next_attempt = cached
            .as_ref()
            .map_or(1, |entry| entry.attempt.saturating_add(1));
        let result = self.control.fetch_account_quota(account.clone()).await;
        match result {
            Ok(mut fetched) => {
                let latest = self.load_visible_account(actor_user_id, account_id).await?;
                if latest.credential.revision != fetched.credential_revision {
                    return Ok(ProviderQuotaView::failed(ProviderQuotaErrorKind::Internal));
                }
                fetched.snapshot.fetched_at = now;
                fetched.snapshot.last_observed_at = None;
                let latest_observation = self.control.quota_observation(account_id).await;
                let last_observation_generation = merge_new_observation(
                    &mut fetched.snapshot,
                    fetched.credential_revision,
                    observation_generation_at_start,
                    latest_observation,
                );
                let entry = QuotaCacheEntry {
                    credential_revision: fetched.credential_revision,
                    snapshot: Some(fetched.snapshot),
                    last_full_fetch_at: Some(now),
                    last_observation_generation,
                    last_error: None,
                    last_attempt_at: now,
                    attempt: next_attempt,
                };
                self.quota
                    .entries
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(account_id.clone(), entry.clone());
                Ok(quota_cache_view(
                    &entry,
                    latest.owner_user_id.as_deref(),
                    actor_user_id,
                    now,
                ))
            }
            Err(error) if error.kind() == ProviderQuotaErrorKind::Unsupported => {
                Ok(ProviderQuotaView::unsupported())
            }
            Err(error) => {
                eprintln!(
                    "quota fetch failed for account {}: {:?}: {error}",
                    account_id.as_str(),
                    error.kind()
                );
                let latest = self.load_visible_account(actor_user_id, account_id).await?;
                let cached =
                    cached.filter(|entry| entry.credential_revision == latest.credential.revision);
                let entry = QuotaCacheEntry {
                    credential_revision: latest.credential.revision,
                    snapshot: cached.as_ref().and_then(|entry| entry.snapshot.clone()),
                    last_full_fetch_at: cached.as_ref().and_then(|entry| entry.last_full_fetch_at),
                    last_observation_generation: cached
                        .as_ref()
                        .map_or(0, |entry| entry.last_observation_generation),
                    last_error: Some(error.kind()),
                    last_attempt_at: now,
                    attempt: next_attempt,
                };
                self.quota
                    .entries
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(account_id.clone(), entry.clone());
                Ok(quota_cache_view(
                    &entry,
                    latest.owner_user_id.as_deref(),
                    actor_user_id,
                    now,
                ))
            }
        }
    }

    fn cached_quota_entry_with_observation(
        &self,
        account_id: &AccountId,
        credential_revision: u64,
        observation: Option<ProviderQuotaObservation>,
    ) -> Option<QuotaCacheEntry> {
        let mut entries = self
            .quota
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if entries
            .get(account_id)
            .is_some_and(|entry| entry.credential_revision != credential_revision)
        {
            entries.remove(account_id);
            return None;
        }
        let entry = entries.get_mut(account_id)?;
        apply_observation(entry, observation);
        Some(entry.clone())
    }

    fn account_gate(&self, account_id: &AccountId) -> Arc<AsyncMutex<()>> {
        let mut gates = self
            .quota
            .gates
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(account_id).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(AsyncMutex::new(()));
        gates.insert(account_id.clone(), Arc::downgrade(&gate));
        gate
    }

    fn invalidate_quota(&self, account_id: &AccountId) {
        self.quota
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(account_id);
    }

    fn remove_account_gate(&self, account_id: &AccountId) {
        self.quota
            .gates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(account_id);
    }

    async fn load_account(
        &self,
        account_id: &AccountId,
    ) -> Result<StoredProviderAccount, ProviderManagerError> {
        self.repository
            .load_provider_account(account_id)
            .await?
            .ok_or(ProviderManagerError::NotFound)
    }

    async fn load_visible_account(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
    ) -> Result<StoredProviderAccount, ProviderManagerError> {
        let account = self.load_account(account_id).await?;
        match account.owner_user_id.as_deref() {
            Some(owner_user_id) if owner_user_id == actor_user_id => Ok(account),
            Some(_) if account.visibility == ProviderVisibility::Shared => Ok(account),
            Some(_) => Err(ProviderManagerError::NotFound),
            None => Err(ProviderManagerError::MissingOwner),
        }
    }

    async fn load_owned_account(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
    ) -> Result<StoredProviderAccount, ProviderManagerError> {
        let account = self.load_account(account_id).await?;
        match account.owner_user_id.as_deref() {
            Some(owner_user_id) if owner_user_id == actor_user_id => Ok(account),
            Some(_) if account.visibility == ProviderVisibility::Shared => {
                Err(ProviderManagerError::Forbidden)
            }
            Some(_) => Err(ProviderManagerError::NotFound),
            None => Err(ProviderManagerError::MissingOwner),
        }
    }

    async fn commit_candidate(
        &self,
        stored: StoredProviderAccount,
        account: Arc<dyn provider_core::ProviderAccount>,
        models: Vec<provider_core::DiscoveredProviderModel>,
        write_models: bool,
        reset_models: bool,
        expected_credential_revision: Option<u64>,
    ) -> Result<Vec<StoredProviderModel>, ProviderManagerError> {
        let create = expected_credential_revision.is_none();
        let outcome = self
            .repository
            .commit_provider_snapshot(
                ProviderSnapshot {
                    account: stored.clone(),
                    models,
                    write_models,
                    reset_models,
                },
                create,
                expected_credential_revision,
            )
            .await?;
        let models = match outcome {
            ProviderSnapshotWriteOutcome::Committed { models } => models,
            ProviderSnapshotWriteOutcome::Conflict => return Err(ProviderManagerError::Conflict),
            ProviderSnapshotWriteOutcome::NotFound => return Err(ProviderManagerError::NotFound),
        };
        if stored.enabled {
            self.control
                .install_account(
                    stored.provider,
                    account,
                    models.clone(),
                    stored.access(),
                    stored.priority,
                )
                .await;
        } else {
            self.control.remove_account(&stored.id).await;
        }
        Ok(models)
    }

    fn finish_oauth_session(&self, session_id: &str, result: Result<(), String>) {
        let mut sessions = self.oauth_sessions();
        let Some(entry) = sessions.get_mut(session_id) else {
            return;
        };
        if entry.snapshot.status != OAuthSessionStatus::Pending
            && entry.snapshot.status != OAuthSessionStatus::Provisioning
        {
            return;
        }
        entry.abort = None;
        match result {
            Ok(()) => {
                entry.snapshot.status = OAuthSessionStatus::Completed;
                entry.snapshot.error = None;
            }
            Err(error) => {
                entry.snapshot.status = OAuthSessionStatus::Failed;
                entry.snapshot.error = Some(error);
            }
        }
    }

    fn begin_oauth_provisioning(&self, session_id: &str) -> bool {
        let mut sessions = self.oauth_sessions();
        let Some(entry) = sessions.get_mut(session_id) else {
            return false;
        };
        begin_oauth_provisioning_entry(entry)
    }

    fn oauth_sessions(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, OAuthSessionEntry>> {
        self.oauth_sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
#[path = "manager_update_tests.rs"]
mod update_tests;

fn begin_oauth_provisioning_entry(entry: &mut OAuthSessionEntry) -> bool {
    if entry.snapshot.status != OAuthSessionStatus::Pending {
        return false;
    }
    entry.abort = None;
    entry.snapshot.status = OAuthSessionStatus::Provisioning;
    true
}

fn cancel_pending_oauth(entry: &mut OAuthSessionEntry) -> bool {
    if entry.snapshot.status != OAuthSessionStatus::Pending {
        return false;
    }
    if let Some(abort) = entry.abort.take() {
        abort.abort();
    }
    entry.snapshot.status = OAuthSessionStatus::Cancelled;
    entry.snapshot.error = None;
    true
}

fn generated_account_id() -> AccountId {
    match AccountId::new(Uuid::new_v4().to_string()) {
        Ok(id) => id,
        Err(_) => unreachable!("UUID account ID must not be empty"),
    }
}

fn replacement_credential(
    current: &StoredProviderAccount,
    replacement: ProviderCredentialReplacement,
) -> Result<StoredCredential, ProviderManagerError> {
    let revision = current
        .credential
        .revision
        .checked_add(1)
        .ok_or(ProviderManagerError::Conflict)?;
    Ok(StoredCredential {
        kind: replacement.kind,
        revision,
        format_version: replacement.format_version,
        credential_json: replacement.credential_json,
        expires_at: replacement.expires_at,
        last_refreshed_at: replacement.last_refreshed_at,
        updated_at: replacement.updated_at,
    })
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

fn elapsed_seconds(now: i64, then: i64) -> i64 {
    now.saturating_sub(then).max(0)
}

fn apply_observation(entry: &mut QuotaCacheEntry, observation: Option<ProviderQuotaObservation>) {
    let Some(observation) = observation.filter(|observation| {
        observation.credential_revision == entry.credential_revision
            && observation.generation > entry.last_observation_generation
    }) else {
        return;
    };
    entry.last_observation_generation = observation.generation;
    if let Some(snapshot) = entry.snapshot.as_mut() {
        merge_quota_groups(&mut snapshot.groups, observation.groups);
        snapshot.last_observed_at = Some(observation.observed_at);
    }
}

fn merge_new_observation(
    snapshot: &mut provider_core::ProviderQuotaSnapshot,
    credential_revision: u64,
    baseline_generation: u64,
    observation: Option<ProviderQuotaObservation>,
) -> u64 {
    let Some(observation) = observation.filter(|observation| {
        observation.credential_revision == credential_revision
            && observation.generation > baseline_generation
    }) else {
        return baseline_generation;
    };
    let generation = observation.generation;
    merge_quota_groups(&mut snapshot.groups, observation.groups);
    snapshot.last_observed_at = Some(observation.observed_at);
    generation
}

fn quota_cache_view(
    entry: &QuotaCacheEntry,
    owner_user_id: Option<&str>,
    actor_user_id: &str,
    now: i64,
) -> ProviderQuotaView {
    let snapshot = entry.snapshot.as_ref().and_then(|snapshot| {
        entry
            .last_full_fetch_at
            .filter(|fetched_at| elapsed_seconds(now, *fetched_at) <= QUOTA_STALE_SECONDS)
            .map(|_| {
                let mut snapshot = snapshot.clone();
                if owner_user_id != Some(actor_user_id) {
                    snapshot
                        .groups
                        .retain(|group| group.audience == QuotaGroupAudience::Shared);
                }
                snapshot
            })
    });
    let freshness = snapshot.as_ref().map(|_| {
        if entry.last_error.is_none()
            && entry
                .last_full_fetch_at
                .is_some_and(|fetched_at| elapsed_seconds(now, fetched_at) < QUOTA_FRESH_SECONDS)
        {
            ProviderQuotaFreshness::Fresh
        } else {
            ProviderQuotaFreshness::Stale
        }
    });
    ProviderQuotaView {
        support: ProviderQuotaSupport::Supported,
        freshness,
        snapshot,
        last_error: entry.last_error,
    }
}

fn normalize_group_label(group_label: String) -> Result<String, ProviderManagerError> {
    let group_label = group_label.trim().to_owned();
    if group_label.is_empty() || group_label.chars().count() > 64 {
        return Err(ProviderManagerError::InvalidInput(
            "provider group label must contain 1 to 64 characters",
        ));
    }
    Ok(group_label)
}

fn account_summary(account: &StoredProviderAccount) -> ProviderAccountSummary {
    ProviderAccountSummary {
        id: account.id.clone(),
        owner_user_id: account.owner_user_id.clone(),
        visibility: account.visibility,
        provider: account.provider,
        label: account.label.clone(),
        group_label: account.group_label.clone(),
        priority: account.priority,
        config_json: account.config_json.clone(),
        credential_kind: account.credential.kind,
        credential_revision: account.credential.revision,
        enabled: account.enabled,
        auth_state: account.auth_state,
        safe_error_code: account.safe_error_code.clone(),
        created_at: account.created_at,
        updated_at: account.updated_at,
    }
}

#[derive(Debug, Error)]
pub enum ProviderManagerError {
    #[error("{0}")]
    InvalidInput(&'static str),
    #[error("provider account was not found")]
    NotFound,
    #[error("provider account cannot be managed by this user")]
    Forbidden,
    #[error("provider account is missing an owner")]
    MissingOwner,
    #[error("provider account already exists or changed concurrently")]
    Conflict,
    #[error(transparent)]
    Repository(#[from] provider_core::AccountRepositoryError),
    #[error(transparent)]
    Control(#[from] ProviderControlError),
    #[error(transparent)]
    OAuthStart(ProviderControlError),
    #[error(transparent)]
    ModelCatalog(#[from] ModelCatalogError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use provider_core::{
        ProviderQuotaSnapshot, QuotaAmount, QuotaGroup, QuotaGroupScope, QuotaMetric,
        QuotaMetricKind, QuotaUnit,
    };

    #[test]
    fn oauth_provisioning_cannot_be_cancelled() {
        let mut entry = OAuthSessionEntry {
            snapshot: OAuthSessionSnapshot {
                id: "session".to_owned(),
                owner_user_id: "owner".to_owned(),
                visibility: ProviderVisibility::Private,
                provider: ProviderKind::Grok,
                account_id: AccountId::new("account").expect("account ID"),
                label: "Grok".to_owned(),
                group_label: "default".to_owned(),
                priority: 0,
                status: OAuthSessionStatus::Pending,
                challenge: ProviderOAuthChallenge {
                    verification_uri: "https://example.com/device".to_owned(),
                    verification_uri_complete: None,
                    user_code: "CODE".to_owned(),
                    expires_at: 1,
                    interval_seconds: 1,
                },
                error: None,
            },
            abort: None,
        };

        assert!(begin_oauth_provisioning_entry(&mut entry));
        assert_eq!(entry.snapshot.status, OAuthSessionStatus::Provisioning);
        assert!(!cancel_pending_oauth(&mut entry));
        assert_eq!(entry.snapshot.status, OAuthSessionStatus::Provisioning);
    }

    #[test]
    fn observation_updates_snapshot_without_changing_full_fetch_state() {
        let mut entry = cache_entry(7, 100, 1, 10);
        entry.last_error = Some(ProviderQuotaErrorKind::Upstream);
        entry.last_attempt_at = 120;
        entry.attempt = 3;

        apply_observation(&mut entry, Some(observation(7, 2, 1_000, 20)));

        assert_eq!(entry.last_full_fetch_at, Some(100));
        assert_eq!(entry.last_error, Some(ProviderQuotaErrorKind::Upstream));
        assert_eq!(entry.last_attempt_at, 120);
        assert_eq!(entry.attempt, 3);
        assert_eq!(entry.last_observation_generation, 2);
        assert_eq!(metric_used(&entry), Some(&QuotaAmount::Integer(20)));
        assert_eq!(
            entry
                .snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.last_observed_at),
            Some(1_000)
        );

        let recent = quota_cache_view(&entry, Some("owner"), "owner", 130);
        assert_eq!(recent.freshness, Some(ProviderQuotaFreshness::Stale));
        assert_eq!(recent.last_error, Some(ProviderQuotaErrorKind::Upstream));
        let expired = quota_cache_view(&entry, Some("owner"), "owner", 1_001);
        assert!(expired.snapshot.is_none());
        assert_eq!(expired.freshness, None);
    }

    #[test]
    fn observation_rejects_old_generation_and_credential_revision() {
        let mut entry = cache_entry(7, 100, 4, 10);

        apply_observation(&mut entry, Some(observation(8, 5, 200, 20)));
        apply_observation(&mut entry, Some(observation(7, 4, 200, 30)));

        assert_eq!(entry.last_observation_generation, 4);
        assert_eq!(metric_used(&entry), Some(&QuotaAmount::Integer(10)));
        assert_eq!(
            entry
                .snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.last_observed_at),
            None
        );
    }

    #[test]
    fn full_fetch_merges_only_observations_newer_than_its_baseline() {
        let mut fetched = snapshot(100, 10);
        let generation =
            merge_new_observation(&mut fetched, 7, 3, Some(observation(7, 4, 200, 20)));

        assert_eq!(generation, 4);
        assert_eq!(
            fetched.groups[0].metrics[0].used,
            Some(QuotaAmount::Integer(20))
        );
        assert_eq!(fetched.last_observed_at, Some(200));

        let mut fetched = snapshot(100, 10);
        let generation =
            merge_new_observation(&mut fetched, 7, 4, Some(observation(7, 4, 200, 20)));
        assert_eq!(generation, 4);
        assert_eq!(
            fetched.groups[0].metrics[0].used,
            Some(QuotaAmount::Integer(10))
        );
        assert_eq!(fetched.last_observed_at, None);
    }

    fn cache_entry(
        credential_revision: u64,
        fetched_at: i64,
        observation_generation: u64,
        used: i64,
    ) -> QuotaCacheEntry {
        QuotaCacheEntry {
            credential_revision,
            snapshot: Some(snapshot(fetched_at, used)),
            last_full_fetch_at: Some(fetched_at),
            last_observation_generation: observation_generation,
            last_error: None,
            last_attempt_at: fetched_at,
            attempt: 1,
        }
    }

    fn snapshot(fetched_at: i64, used: i64) -> ProviderQuotaSnapshot {
        ProviderQuotaSnapshot {
            account_id: "account".to_owned(),
            provider: ProviderKind::Codex,
            fetched_at,
            last_observed_at: None,
            groups: vec![quota_group(used)],
            warnings: Vec::new(),
        }
    }

    fn observation(
        credential_revision: u64,
        generation: u64,
        observed_at: i64,
        used: i64,
    ) -> ProviderQuotaObservation {
        ProviderQuotaObservation {
            credential_revision,
            generation,
            observed_at,
            groups: vec![quota_group(used)],
        }
    }

    fn quota_group(used: i64) -> QuotaGroup {
        QuotaGroup {
            key: "codex".to_owned(),
            scope: QuotaGroupScope::Aggregate,
            audience: QuotaGroupAudience::Shared,
            attributes: BTreeMap::new(),
            metrics: vec![QuotaMetric {
                key: "primary".to_owned(),
                kind: QuotaMetricKind::Usage,
                unit: QuotaUnit::Percent,
                used: Some(QuotaAmount::Integer(used)),
                remaining: None,
                limit: None,
                period: None,
                breakdown: Vec::new(),
            }],
        }
    }

    fn metric_used(entry: &QuotaCacheEntry) -> Option<&QuotaAmount> {
        entry
            .snapshot
            .as_ref()?
            .groups
            .first()?
            .metrics
            .first()?
            .used
            .as_ref()
    }
}
