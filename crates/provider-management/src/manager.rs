use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use provider_core::{
    AccountId, AccountProvisioningInput, CredentialKind, CredentialUpdate, CredentialWriteOutcome,
    ProviderAccountCreateOutcome, ProviderAccountSummary, ProviderAccountUpdate, ProviderControl,
    ProviderControlError, ProviderKind, ProviderManagementRepository, ProviderModelOverride,
    ProviderOAuthChallenge, ProviderVisibility, StoredProviderAccount, StoredProviderModel,
};
use secrecy::SecretString;
use thiserror::Error;
use tokio::task::AbortHandle;
use uuid::Uuid;

use crate::{ModelCatalogError, ModelCatalogService, ModelCatalogSnapshot};

pub struct CreatedProviderAccount {
    pub account: ProviderAccountSummary,
    pub models: ModelCatalogSnapshot,
}

pub struct DirectProviderAccountInput {
    pub kind: ProviderKind,
    pub label: String,
    pub config_json: String,
    pub api_key: Option<SecretString>,
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
    pub status: OAuthSessionStatus,
    pub challenge: ProviderOAuthChallenge,
    pub error: Option<String>,
}

struct OAuthSessionEntry {
    snapshot: OAuthSessionSnapshot,
    abort: Option<AbortHandle>,
}

#[derive(Clone)]
pub struct ProviderManager {
    repository: Arc<dyn ProviderManagementRepository>,
    control: Arc<dyn ProviderControl>,
    models: ModelCatalogService,
    oauth_sessions: Arc<Mutex<BTreeMap<String, OAuthSessionEntry>>>,
}

impl ProviderManager {
    #[must_use]
    pub fn new(
        repository: Arc<dyn ProviderManagementRepository>,
        control: Arc<dyn ProviderControl>,
    ) -> Self {
        Self {
            models: ModelCatalogService::new(repository.clone()),
            repository,
            control,
            oauth_sessions: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn create_direct_account(
        &self,
        owner_user_id: &str,
        input: DirectProviderAccountInput,
        now: i64,
    ) -> Result<CreatedProviderAccount, ProviderManagerError> {
        let id = generated_account_id();
        self.create_account(
            owner_user_id,
            input.kind,
            AccountProvisioningInput::Direct {
                id,
                label: input.label,
                config_json: input.config_json,
                api_key: input.api_key,
            },
            input.visibility,
            now,
        )
        .await
    }

    pub async fn import_grok_account(
        &self,
        owner_user_id: &str,
        label: String,
        credential_json: SecretString,
        visibility: ProviderVisibility,
        now: i64,
    ) -> Result<CreatedProviderAccount, ProviderManagerError> {
        let id = generated_account_id();
        self.create_account(
            owner_user_id,
            ProviderKind::Grok,
            AccountProvisioningInput::CredentialJson {
                id,
                label,
                credential_json,
            },
            visibility,
            now,
        )
        .await
    }

    pub async fn start_oauth_session(
        &self,
        owner_user_id: &str,
        kind: ProviderKind,
        label: String,
        visibility: ProviderVisibility,
    ) -> Result<OAuthSessionSnapshot, ProviderManagerError> {
        let label = label.trim().to_owned();
        if label.is_empty() {
            return Err(ProviderManagerError::InvalidInput(
                "provider account label must not be empty",
            ));
        }
        let started = self
            .control
            .start_oauth(kind)
            .await
            .map_err(ProviderManagerError::OAuthStart)?;
        let session_id = Uuid::new_v4().to_string();
        let account_id = generated_account_id();
        let owner_user_id = owner_user_id.to_owned();
        let snapshot = OAuthSessionSnapshot {
            id: session_id.clone(),
            owner_user_id: owner_user_id.clone(),
            visibility,
            provider: kind,
            account_id: account_id.clone(),
            label: label.clone(),
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
                Ok(credential_json) => manager
                    .create_account(
                        &owner_user_id,
                        kind,
                        AccountProvisioningInput::CredentialJson {
                            id: account_id,
                            label,
                            credential_json,
                        },
                        visibility,
                        unix_timestamp(),
                    )
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string()),
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
        if entry.snapshot.status == OAuthSessionStatus::Pending {
            if let Some(abort) = entry.abort.take() {
                abort.abort();
            }
            entry.snapshot.status = OAuthSessionStatus::Cancelled;
            entry.snapshot.error = None;
        }
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

    pub async fn create_account(
        &self,
        owner_user_id: &str,
        kind: ProviderKind,
        input: AccountProvisioningInput,
        visibility: ProviderVisibility,
        now: i64,
    ) -> Result<CreatedProviderAccount, ProviderManagerError> {
        let account = self.control.prepare_account(kind, input)?;
        match self
            .repository
            .create_provider_account(account.clone(), owner_user_id, visibility)
            .await?
        {
            ProviderAccountCreateOutcome::Created => {}
            ProviderAccountCreateOutcome::Conflict => {
                return Err(ProviderManagerError::Conflict);
            }
        }
        let stored = self.load_account(&account.id).await?;
        let runtime_account = self.control.build_account(stored.clone())?;
        let models = self.models.refresh(runtime_account.as_ref(), now).await?;
        self.control
            .activate_account(
                stored.provider,
                runtime_account,
                models.models.clone(),
                stored.access(),
            )
            .await?;
        Ok(CreatedProviderAccount {
            account: account_summary(&stored),
            models,
        })
    }

    pub async fn update_account(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        update: ProviderAccountUpdate,
    ) -> Result<ProviderAccountSummary, ProviderManagerError> {
        let current = self.load_owned_account(actor_user_id, account_id).await?;
        let update = self
            .control
            .prepare_account_update(current.provider, update)?;
        let rebuild_required = current.config_json != update.config_json;
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
        if rebuild_required {
            self.reconcile(stored.clone()).await?;
        }
        Ok(account_summary(&stored))
    }

    pub async fn update_credential(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        replacement: ProviderCredentialReplacement,
    ) -> Result<ProviderAccountSummary, ProviderManagerError> {
        let current = self.load_owned_account(actor_user_id, account_id).await?;
        let outcome = self
            .repository
            .compare_and_swap_credential(
                account_id,
                CredentialUpdate {
                    expected_revision: current.credential.revision,
                    kind: replacement.kind,
                    format_version: replacement.format_version,
                    credential_json: replacement.credential_json,
                    expires_at: replacement.expires_at,
                    last_refreshed_at: replacement.last_refreshed_at,
                    updated_at: replacement.updated_at,
                },
            )
            .await?;
        if outcome == CredentialWriteOutcome::Conflict {
            return Err(ProviderManagerError::Conflict);
        }
        let stored = self.load_account(account_id).await?;
        self.reconcile(stored.clone()).await?;
        Ok(account_summary(&stored))
    }

    pub async fn set_account_enabled(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        enabled: bool,
        updated_at: i64,
    ) -> Result<ProviderAccountSummary, ProviderManagerError> {
        self.load_owned_account(actor_user_id, account_id).await?;
        if !self
            .repository
            .set_provider_account_enabled(account_id, enabled, updated_at)
            .await?
        {
            return Err(ProviderManagerError::NotFound);
        }
        let stored = self.load_account(account_id).await?;
        self.reconcile(stored.clone()).await?;
        Ok(account_summary(&stored))
    }

    pub async fn delete_account(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
    ) -> Result<(), ProviderManagerError> {
        self.load_owned_account(actor_user_id, account_id).await?;
        if !self.repository.delete_provider_account(account_id).await? {
            return Err(ProviderManagerError::NotFound);
        }
        self.control.remove_account(account_id).await;
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
        let stored = self.load_owned_account(actor_user_id, account_id).await?;
        let account = self.control.build_account(stored.clone())?;
        let models = self.models.refresh(account.as_ref(), now).await?;
        if stored.enabled {
            self.control
                .activate_account(
                    stored.provider,
                    account,
                    models.models.clone(),
                    stored.access(),
                )
                .await?;
        }
        Ok(models)
    }

    pub async fn update_model(
        &self,
        actor_user_id: &str,
        account_id: &AccountId,
        upstream_model: &str,
        update: ProviderModelOverride,
    ) -> Result<Vec<StoredProviderModel>, ProviderManagerError> {
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

    async fn reconcile(&self, stored: StoredProviderAccount) -> Result<(), ProviderManagerError> {
        if !stored.enabled {
            self.control.remove_account(&stored.id).await;
            return Ok(());
        }
        let models = self
            .repository
            .list_provider_models(Some(&stored.id))
            .await?;
        let account = self.control.build_account(stored.clone())?;
        self.control
            .activate_account(stored.provider, account, models, stored.access())
            .await?;
        Ok(())
    }

    fn finish_oauth_session(&self, session_id: &str, result: Result<(), String>) {
        let mut sessions = self.oauth_sessions();
        let Some(entry) = sessions.get_mut(session_id) else {
            return;
        };
        if entry.snapshot.status != OAuthSessionStatus::Pending {
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

    fn oauth_sessions(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, OAuthSessionEntry>> {
        self.oauth_sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

fn generated_account_id() -> AccountId {
    match AccountId::new(Uuid::new_v4().to_string()) {
        Ok(id) => id,
        Err(_) => unreachable!("UUID account ID must not be empty"),
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

fn account_summary(account: &StoredProviderAccount) -> ProviderAccountSummary {
    ProviderAccountSummary {
        id: account.id.clone(),
        owner_user_id: account.owner_user_id.clone(),
        visibility: account.visibility,
        provider: account.provider,
        label: account.label.clone(),
        config_json: account.config_json.clone(),
        credential_kind: account.credential.kind,
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
