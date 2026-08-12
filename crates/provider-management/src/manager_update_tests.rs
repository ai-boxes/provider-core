use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use provider_core::{
    AccountAuthState, AccountId, AccountProvisioningInput, AccountRepository,
    AccountRepositoryError, AccountRuntimeState, CredentialKind, CredentialUpdate,
    CredentialWriteOutcome, DiscoveredProviderModel, NewProviderAccount, ProviderAccount,
    ProviderAccountAccess, ProviderAccountCreateOutcome, ProviderAccountSummary,
    ProviderAccountUpdate, ProviderControl, ProviderControlError, ProviderError, ProviderErrorKind,
    ProviderKind, ProviderManagementRepository, ProviderModelOverride, ProviderQuotaControl,
    ProviderQuotaError, ProviderQuotaErrorKind, ProviderQuotaFetch, ProviderRequest,
    ProviderSnapshot, ProviderSnapshotWriteOutcome, ProviderStream, ProviderVisibility,
    RefreshError, RefreshErrorKind, RefreshOutcome, RefreshTrigger, StartedProviderOAuth,
    StoredCredential, StoredProviderAccount, StoredProviderModel,
};
use secrecy::SecretString;

use super::ProviderManager;

#[tokio::test]
async fn metadata_only_update_does_not_discover_or_overwrite_concurrent_auth_state() {
    let repository = Arc::new(TestRepository::new(stored_account()));
    let control = Arc::new(TestControl::default());
    let manager = ProviderManager::new(repository.clone(), control.clone());
    let account_id = AccountId::new("account").expect("account ID");

    let updated = manager
        .update_account(
            "owner",
            &account_id,
            ProviderAccountUpdate {
                label: "Renamed".to_owned(),
                group_label: "new-group".to_owned(),
                priority: 5,
                config_json: r#"{"base_url":"https://old.example"}"#.to_owned(),
                visibility: ProviderVisibility::Shared,
                updated_at: 20,
            },
        )
        .await
        .expect("metadata update");

    assert_eq!(updated.label, "Renamed");
    assert_eq!(updated.group_label, "new-group");
    assert_eq!(updated.visibility, ProviderVisibility::Shared);
    assert_eq!(updated.auth_state, AccountAuthState::ReauthRequired);
    assert_eq!(
        updated.safe_error_code.as_deref(),
        Some("credential_expired")
    );
    assert_eq!(control.builds.load(Ordering::SeqCst), 0);
    assert_eq!(control.discoveries.load(Ordering::SeqCst), 0);
    assert_eq!(control.installs.load(Ordering::SeqCst), 0);
    assert_eq!(control.access_updates.load(Ordering::SeqCst), 1);

    assert!(repository.snapshots().is_empty());
    let stored = repository.account();
    assert_eq!(stored.auth_state, AccountAuthState::ReauthRequired);
    assert_eq!(
        stored.safe_error_code.as_deref(),
        Some("credential_expired")
    );
    assert_eq!(stored.credential.revision, 7);
}

#[tokio::test]
async fn configuration_update_rebuilds_discovers_and_commits_models() {
    let repository = Arc::new(TestRepository::new(stored_account()));
    let control = Arc::new(TestControl::default());
    let manager = ProviderManager::new(repository.clone(), control.clone());
    let account_id = AccountId::new("account").expect("account ID");

    manager
        .update_account(
            "owner",
            &account_id,
            ProviderAccountUpdate {
                label: "Renamed".to_owned(),
                group_label: "new-group".to_owned(),
                priority: 2,
                config_json: r#"{"base_url":"https://new.example"}"#.to_owned(),
                visibility: ProviderVisibility::Shared,
                updated_at: 20,
            },
        )
        .await
        .expect("configuration update");

    assert_eq!(control.builds.load(Ordering::SeqCst), 1);
    assert_eq!(control.discoveries.load(Ordering::SeqCst), 1);
    assert_eq!(control.installs.load(Ordering::SeqCst), 1);
    assert_eq!(control.access_updates.load(Ordering::SeqCst), 0);

    let snapshots = repository.snapshots();
    assert_eq!(snapshots.len(), 1);
    assert!(snapshots[0].write_models);
    assert!(snapshots[0].reset_models);
    assert_eq!(snapshots[0].models.len(), 1);
}

#[tokio::test]
async fn model_refresh_preserves_concurrent_auth_state() {
    let repository = Arc::new(TestRepository::new(stored_account()));
    let control = Arc::new(TestControl::default());
    let manager = ProviderManager::new(repository.clone(), control.clone());
    let account_id = AccountId::new("account").expect("account ID");

    manager
        .refresh_models("owner", &account_id, 20)
        .await
        .expect("model refresh");

    assert_eq!(control.discoveries.load(Ordering::SeqCst), 1);
    let stored = repository.account();
    assert_eq!(stored.auth_state, AccountAuthState::ReauthRequired);
    assert_eq!(
        stored.safe_error_code.as_deref(),
        Some("credential_expired")
    );
    assert_eq!(stored.credential.revision, 7);
}

struct TestRepository {
    account: Mutex<StoredProviderAccount>,
    snapshots: Mutex<Vec<ProviderSnapshot>>,
}

impl TestRepository {
    fn new(account: StoredProviderAccount) -> Self {
        Self {
            account: Mutex::new(account),
            snapshots: Mutex::new(Vec::new()),
        }
    }

    fn snapshots(&self) -> Vec<ProviderSnapshot> {
        self.snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn account(&self) -> StoredProviderAccount {
        self.account
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl AccountRepository for TestRepository {
    async fn load_enabled_accounts(
        &self,
    ) -> Result<Vec<StoredProviderAccount>, AccountRepositoryError> {
        panic!("not used by update_account tests")
    }

    async fn compare_and_swap_credential(
        &self,
        _account_id: &AccountId,
        _update: CredentialUpdate,
    ) -> Result<CredentialWriteOutcome, AccountRepositoryError> {
        panic!("not used by update_account tests")
    }

    async fn update_auth_state(
        &self,
        _account_id: &AccountId,
        _state: AccountAuthState,
        _safe_error_code: Option<&str>,
        _updated_at: i64,
    ) -> Result<(), AccountRepositoryError> {
        panic!("not used by update_account tests")
    }
}

#[async_trait]
impl ProviderManagementRepository for TestRepository {
    async fn list_provider_accounts(
        &self,
        _actor_user_id: &str,
    ) -> Result<Vec<ProviderAccountSummary>, AccountRepositoryError> {
        panic!("not used by update_account tests")
    }

    async fn load_provider_account(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<StoredProviderAccount>, AccountRepositoryError> {
        let account = self
            .account
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Ok((&account.id == account_id).then_some(account))
    }

    async fn commit_provider_snapshot(
        &self,
        snapshot: ProviderSnapshot,
        create: bool,
        expected_credential_revision: Option<u64>,
    ) -> Result<ProviderSnapshotWriteOutcome, AccountRepositoryError> {
        assert!(!create);
        assert_eq!(expected_credential_revision, Some(7));
        let mut account = self.account.lock().unwrap_or_else(PoisonError::into_inner);
        account.auth_state = AccountAuthState::ReauthRequired;
        account.safe_error_code = Some("credential_expired".to_owned());
        let mut candidate = snapshot.account.clone();
        if expected_credential_revision
            .is_some_and(|expected| candidate.credential.revision <= expected)
        {
            candidate.auth_state = account.auth_state;
            candidate
                .safe_error_code
                .clone_from(&account.safe_error_code);
        }
        *account = candidate;
        self.snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(snapshot);
        Ok(ProviderSnapshotWriteOutcome::Committed {
            models: vec![stored_model()],
        })
    }

    async fn create_provider_account(
        &self,
        _account: NewProviderAccount,
        _owner_user_id: &str,
        _visibility: ProviderVisibility,
    ) -> Result<ProviderAccountCreateOutcome, AccountRepositoryError> {
        panic!("not used by update_account tests")
    }

    async fn update_provider_account(
        &self,
        account_id: &AccountId,
        update: ProviderAccountUpdate,
    ) -> Result<bool, AccountRepositoryError> {
        let mut account = self.account.lock().unwrap_or_else(PoisonError::into_inner);
        if &account.id != account_id {
            return Ok(false);
        }
        // Simulate a background credential refresh marking the account between
        // the manager's initial read and the metadata-only repository update.
        account.auth_state = AccountAuthState::ReauthRequired;
        account.safe_error_code = Some("credential_expired".to_owned());
        account.label = update.label;
        account.group_label = update.group_label;
        account.priority = update.priority;
        account.config_json = update.config_json;
        account.visibility = update.visibility;
        account.updated_at = update.updated_at;
        Ok(true)
    }

    async fn update_provider_account_and_credential(
        &self,
        _account_id: &AccountId,
        _account: ProviderAccountUpdate,
        _credential: CredentialUpdate,
    ) -> Result<Option<CredentialWriteOutcome>, AccountRepositoryError> {
        panic!("not used by update_account tests")
    }

    async fn set_provider_account_enabled(
        &self,
        _account_id: &AccountId,
        _enabled: bool,
        _updated_at: i64,
    ) -> Result<bool, AccountRepositoryError> {
        panic!("not used by update_account tests")
    }

    async fn delete_provider_account(
        &self,
        _account_id: &AccountId,
    ) -> Result<bool, AccountRepositoryError> {
        panic!("not used by update_account tests")
    }

    async fn list_provider_models(
        &self,
        _account_id: Option<&AccountId>,
    ) -> Result<Vec<StoredProviderModel>, AccountRepositoryError> {
        panic!("not used by update_account tests")
    }

    async fn synchronize_provider_models(
        &self,
        _account_id: &AccountId,
        _models: Vec<DiscoveredProviderModel>,
        _synced_at: i64,
    ) -> Result<Vec<StoredProviderModel>, AccountRepositoryError> {
        panic!("not used by update_account tests")
    }

    async fn update_provider_model(
        &self,
        _account_id: &AccountId,
        _upstream_model: &str,
        _update: ProviderModelOverride,
    ) -> Result<bool, AccountRepositoryError> {
        panic!("not used by update_account tests")
    }
}

#[derive(Default)]
struct TestControl {
    builds: Arc<AtomicUsize>,
    discoveries: Arc<AtomicUsize>,
    installs: AtomicUsize,
    access_updates: AtomicUsize,
}

#[async_trait]
impl ProviderQuotaControl for TestControl {
    fn supports_quota(&self, _provider: ProviderKind) -> bool {
        false
    }

    async fn fetch_account_quota(
        &self,
        _account: StoredProviderAccount,
    ) -> Result<ProviderQuotaFetch, ProviderQuotaError> {
        Err(ProviderQuotaError::new(
            ProviderQuotaErrorKind::Unsupported,
            "unsupported",
        ))
    }
}

#[async_trait]
impl ProviderControl for TestControl {
    fn prepare_account(
        &self,
        _kind: ProviderKind,
        _input: AccountProvisioningInput,
    ) -> Result<NewProviderAccount, ProviderControlError> {
        panic!("not used by update_account tests")
    }

    fn prepare_account_update(
        &self,
        _kind: ProviderKind,
        update: ProviderAccountUpdate,
    ) -> Result<ProviderAccountUpdate, ProviderControlError> {
        Ok(update)
    }

    fn build_account(
        &self,
        account: StoredProviderAccount,
    ) -> Result<Arc<dyn ProviderAccount>, ProviderControlError> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(TestAccount {
            id: account.id,
            discoveries: self.discoveries.clone(),
        }))
    }

    async fn start_oauth(
        &self,
        _kind: ProviderKind,
    ) -> Result<StartedProviderOAuth, ProviderControlError> {
        Err(ProviderControlError::new(
            "not used by update_account tests",
        ))
    }

    async fn install_account(
        &self,
        _kind: ProviderKind,
        _account: Arc<dyn ProviderAccount>,
        _models: Vec<StoredProviderModel>,
        _access: ProviderAccountAccess,
        _priority: u32,
    ) {
        self.installs.fetch_add(1, Ordering::SeqCst);
    }

    fn update_account_access(
        &self,
        _account_id: &AccountId,
        _access: ProviderAccountAccess,
    ) -> bool {
        self.access_updates.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn update_account_models(
        &self,
        _account_id: &AccountId,
        _models: Vec<StoredProviderModel>,
    ) -> bool {
        panic!("not used by update_account tests")
    }

    fn claim_unowned_account_access(&self, _owner_user_id: &str) {}

    async fn remove_account(&self, _account_id: &AccountId) -> bool {
        panic!("not used by update_account tests")
    }
}

struct TestAccount {
    id: AccountId,
    discoveries: Arc<AtomicUsize>,
}

#[async_trait]
impl ProviderAccount for TestAccount {
    fn provider_name(&self) -> &'static str {
        "openai_compatible"
    }

    fn account_id(&self) -> &AccountId {
        &self.id
    }

    fn runtime_state(&self) -> AccountRuntimeState {
        AccountRuntimeState {
            generation: 0,
            next_refresh_at: None,
            auth_state: AccountAuthState::Active,
            persistence_pending: false,
        }
    }

    fn credential_revision(&self) -> u64 {
        7
    }

    async fn execute_stream(
        &self,
        _request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError> {
        Err(ProviderError::new(
            ProviderErrorKind::Internal,
            "not used by update_account tests",
        ))
    }

    async fn count_tokens(&self, _request: ProviderRequest) -> Result<u64, ProviderError> {
        Err(ProviderError::new(
            ProviderErrorKind::Internal,
            "not used by update_account tests",
        ))
    }

    async fn discover_models(&self) -> Result<Vec<DiscoveredProviderModel>, ProviderError> {
        self.discoveries.fetch_add(1, Ordering::SeqCst);
        Ok(vec![DiscoveredProviderModel {
            upstream_model: "test-model".to_owned(),
            input_modalities: None,
            metadata_json: "{}".to_owned(),
            routable: true,
            pricing: None,
        }])
    }

    async fn refresh_credentials(
        &self,
        _trigger: RefreshTrigger,
    ) -> Result<RefreshOutcome, RefreshError> {
        Err(RefreshError::new(
            RefreshErrorKind::Internal,
            "not used by update_account tests",
        ))
    }
}

fn stored_account() -> StoredProviderAccount {
    StoredProviderAccount {
        id: AccountId::new("account").expect("account ID"),
        owner_user_id: Some("owner".to_owned()),
        visibility: ProviderVisibility::Private,
        provider: ProviderKind::OpenAiCompatible,
        label: "Original".to_owned(),
        group_label: "default".to_owned(),
        priority: 5,
        config_json: r#"{"base_url":"https://old.example"}"#.to_owned(),
        enabled: true,
        auth_state: AccountAuthState::Active,
        safe_error_code: None,
        created_at: 10,
        updated_at: 10,
        credential: StoredCredential {
            kind: CredentialKind::ApiKey,
            revision: 7,
            format_version: 1,
            credential_json: SecretString::from("secret"),
            expires_at: None,
            last_refreshed_at: None,
            updated_at: 10,
        },
    }
}

fn stored_model() -> StoredProviderModel {
    StoredProviderModel {
        account_id: AccountId::new("account").expect("account ID"),
        upstream_model: "test-model".to_owned(),
        alias: None,
        enabled: true,
        available: true,
        routable: true,
        input_modalities: None,
        metadata_json: "{}".to_owned(),
        pricing: None,
        last_seen_at: Some(10),
        created_at: 10,
        updated_at: 10,
    }
}
