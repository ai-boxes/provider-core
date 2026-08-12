use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use provider_core::{
    AccountId, AccountProvisioningInput, AccountRepository, ManagedProviderDriver,
    NewProviderAccount, ProviderAccount, ProviderAccountAccess, ProviderAccountUpdate,
    ProviderControl, ProviderControlError, ProviderKind, ProviderQuotaControl, ProviderQuotaError,
    ProviderQuotaErrorKind, ProviderQuotaFetch, ProviderQuotaObservation, ProviderRouteCandidate,
    ProviderRouter, RefreshError, RefreshErrorKind, RefreshTrigger, StartedProviderOAuth,
    StoredProviderAccount, StoredProviderModel,
};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::{ProviderModelRouter, ProviderRuntime};

#[derive(Clone)]
pub struct ProviderRuntimeCatalog {
    inner: Arc<CatalogInner>,
}

struct CatalogInner {
    repository: Arc<dyn AccountRepository>,
    drivers: RwLock<BTreeMap<ProviderKind, Arc<dyn ManagedProviderDriver>>>,
    runtimes: RwLock<BTreeMap<ProviderKind, ProviderRuntime>>,
    router: ProviderModelRouter,
    detached_refresh_limit: Arc<Semaphore>,
    recovery_failures: RwLock<BTreeSet<AccountId>>,
    recovery_readiness: RwLock<Option<Arc<AtomicBool>>>,
}

#[derive(Debug, Error)]
pub enum ProviderRuntimeCatalogError {
    #[error("provider driver is already registered")]
    DuplicateDriver,
    #[error("provider driver type does not match its name")]
    DriverMismatch,
}

impl ProviderRuntimeCatalog {
    #[must_use]
    pub fn new(repository: Arc<dyn AccountRepository>) -> Self {
        Self {
            inner: Arc::new(CatalogInner {
                repository,
                drivers: RwLock::new(BTreeMap::new()),
                runtimes: RwLock::new(BTreeMap::new()),
                router: ProviderModelRouter::new(),
                detached_refresh_limit: Arc::new(Semaphore::new(4)),
                recovery_failures: RwLock::new(BTreeSet::new()),
                recovery_readiness: RwLock::new(None),
            }),
        }
    }

    pub fn register_driver(
        &self,
        driver: Arc<dyn ManagedProviderDriver>,
    ) -> Result<(), ProviderRuntimeCatalogError> {
        let kind = driver.kind();
        if kind.as_str() != driver.name() {
            return Err(ProviderRuntimeCatalogError::DriverMismatch);
        }
        let mut drivers = self
            .inner
            .drivers
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if drivers.contains_key(&kind) {
            return Err(ProviderRuntimeCatalogError::DuplicateDriver);
        }
        drivers.insert(kind, driver);
        Ok(())
    }

    pub async fn remove_account(&self, account_id: &AccountId) -> bool {
        let runtimes: Vec<_> = self
            .inner
            .runtimes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        let mut removed = false;
        for runtime in runtimes {
            removed |= runtime.remove(account_id).await;
        }
        self.inner.router.remove_account(account_id);
        self.clear_recovery_failure(account_id);
        removed
    }

    pub fn bind_recovery_readiness(&self, readiness: Arc<AtomicBool>) {
        *self
            .inner
            .recovery_readiness
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(readiness);
        self.publish_recovery_readiness();
    }

    pub fn mark_recovery_failed(&self, account_id: AccountId) {
        self.inner
            .recovery_failures
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(account_id);
        self.publish_recovery_readiness();
    }

    fn clear_recovery_failure(&self, account_id: &AccountId) {
        self.inner
            .recovery_failures
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(account_id);
        self.publish_recovery_readiness();
    }

    fn publish_recovery_readiness(&self) {
        let ready = self
            .inner
            .recovery_failures
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty();
        if let Some(readiness) = self
            .inner
            .recovery_readiness
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            readiness.store(ready, Ordering::Release);
        }
    }

    pub fn shutdown(&self) {
        for runtime in self
            .inner
            .runtimes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            runtime.shutdown();
        }
    }
}

#[async_trait]
impl ProviderQuotaControl for ProviderRuntimeCatalog {
    fn supports_quota(&self, provider: ProviderKind) -> bool {
        self.inner
            .drivers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&provider)
            .is_some_and(|driver| driver.supports_quota())
    }

    async fn fetch_account_quota(
        &self,
        account: StoredProviderAccount,
    ) -> Result<ProviderQuotaFetch, ProviderQuotaError> {
        if account.enabled {
            let runtime = self
                .inner
                .runtimes
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&account.provider)
                .cloned()
                .ok_or_else(|| {
                    ProviderQuotaError::new(
                        ProviderQuotaErrorKind::Internal,
                        "provider runtime is not registered",
                    )
                })?;
            return runtime.fetch_quota_for(&account.id).await;
        }

        let detached = self.build_account(account).map_err(|error| {
            ProviderQuotaError::new(ProviderQuotaErrorKind::Internal, error.to_string())
        })?;
        if !detached.runtime_state().available_for_requests() {
            return Err(ProviderQuotaError::new(
                ProviderQuotaErrorKind::Authentication,
                "provider account is not available",
            ));
        }
        fetch_detached_quota(detached, &self.inner.detached_refresh_limit).await
    }

    async fn quota_observation(&self, account_id: &AccountId) -> Option<ProviderQuotaObservation> {
        let runtimes: Vec<_> = self
            .inner
            .runtimes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        for runtime in runtimes {
            if let Some(observation) = runtime.quota_observation_for(account_id).await {
                return Some(observation);
            }
        }
        None
    }
}

#[async_trait]
impl ProviderControl for ProviderRuntimeCatalog {
    fn prepare_account(
        &self,
        kind: ProviderKind,
        input: AccountProvisioningInput,
    ) -> Result<NewProviderAccount, ProviderControlError> {
        let driver = self
            .inner
            .drivers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&kind)
            .cloned()
            .ok_or_else(|| ProviderControlError::new("provider type is not registered"))?;
        driver
            .prepare_account(input)
            .map_err(|error| ProviderControlError::new(error.message()))
    }

    fn build_account(
        &self,
        account: StoredProviderAccount,
    ) -> Result<Arc<dyn ProviderAccount>, ProviderControlError> {
        let driver = self
            .inner
            .drivers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&account.provider)
            .cloned()
            .ok_or_else(|| ProviderControlError::new("provider type is not registered"))?;
        driver
            .build_account(account, self.inner.repository.clone())
            .map_err(|error| ProviderControlError::new(error.message()))
    }

    fn prepare_account_update(
        &self,
        kind: ProviderKind,
        update: ProviderAccountUpdate,
    ) -> Result<ProviderAccountUpdate, ProviderControlError> {
        let driver = self
            .inner
            .drivers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&kind)
            .cloned()
            .ok_or_else(|| ProviderControlError::new("provider type is not registered"))?;
        driver
            .prepare_account_update(update)
            .map_err(|error| ProviderControlError::new(error.message()))
    }

    async fn start_oauth(
        &self,
        kind: ProviderKind,
    ) -> Result<StartedProviderOAuth, ProviderControlError> {
        let driver = self
            .inner
            .drivers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&kind)
            .cloned()
            .ok_or_else(|| ProviderControlError::new("provider type is not registered"))?;
        driver
            .start_oauth()
            .await
            .map_err(|error| ProviderControlError::new(error.message()))
    }

    async fn install_account(
        &self,
        kind: ProviderKind,
        account: Arc<dyn ProviderAccount>,
        models: Vec<StoredProviderModel>,
        access: ProviderAccountAccess,
        priority: u32,
    ) {
        let driver = self
            .inner
            .drivers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&kind)
            .cloned()
            .expect("candidate account provider driver must remain registered");
        let runtime = {
            let mut runtimes = self
                .inner
                .runtimes
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            runtimes
                .entry(kind)
                .or_insert_with(|| ProviderRuntime::new(driver))
                .clone()
        };
        let account_id = account.account_id().clone();
        runtime.replace(account.clone()).await;
        self.inner
            .router
            .replace_account_models(runtime, account, models, access, priority)
            .expect("candidate account must match its provider runtime");
        self.clear_recovery_failure(&account_id);
    }

    fn update_account_access(&self, account_id: &AccountId, access: ProviderAccountAccess) -> bool {
        self.inner.router.update_account_access(account_id, access)
    }

    fn update_account_models(
        &self,
        account_id: &AccountId,
        models: Vec<StoredProviderModel>,
    ) -> bool {
        self.inner.router.update_account_models(account_id, models)
    }

    fn claim_unowned_account_access(&self, owner_user_id: &str) {
        self.inner
            .router
            .claim_unowned_account_access(owner_user_id);
    }

    async fn remove_account(&self, account_id: &AccountId) -> bool {
        ProviderRuntimeCatalog::remove_account(self, account_id).await
    }
}

impl ProviderRouter for ProviderRuntimeCatalog {
    fn models(
        &self,
        user_id: &str,
        account_ids: Option<&std::collections::HashSet<provider_core::AccountId>>,
    ) -> Vec<provider_core::RoutableProviderModel> {
        self.inner.router.models(user_id, account_ids)
    }

    fn routes(
        &self,
        user_id: &str,
        routing_scope: &str,
        model: &str,
        native_formats: &[provider_core::WireFormat],
        session_id: Option<&str>,
        previous_response_id: Option<&str>,
        account_ids: Option<&std::collections::HashSet<provider_core::AccountId>>,
    ) -> Vec<ProviderRouteCandidate> {
        self.inner.router.routes(
            user_id,
            routing_scope,
            model,
            native_formats,
            session_id,
            previous_response_id,
            account_ids,
        )
    }

    fn commit_session_affinity(
        &self,
        routing_scope: &str,
        model: &str,
        session_id: Option<&str>,
        account_id: &provider_core::AccountId,
    ) {
        self.inner
            .router
            .commit_session_affinity(routing_scope, model, session_id, account_id);
    }

    fn record_route_failure(
        &self,
        account_id: &provider_core::AccountId,
        model: &str,
        reason: provider_core::ProviderFailoverReason,
    ) {
        self.inner
            .router
            .record_route_failure(account_id, model, reason);
    }

    fn record_route_success(&self, account_id: &provider_core::AccountId, model: &str) {
        self.inner.router.record_route_success(account_id, model);
    }

    fn bind_response_id(
        &self,
        routing_scope: &str,
        response_id: &str,
        account_id: &provider_core::AccountId,
    ) {
        self.inner
            .router
            .bind_response_id(routing_scope, response_id, account_id);
    }
}

async fn fetch_detached_quota(
    account: Arc<dyn ProviderAccount>,
    refresh_limit: &Arc<Semaphore>,
) -> Result<ProviderQuotaFetch, ProviderQuotaError> {
    let generation = account.runtime_state().generation;
    match fetch_quota_source(account.as_ref()).await {
        Err(error) if error.upstream_status() == Some(401) => {
            let _permit = refresh_limit.acquire().await.map_err(|_| {
                ProviderQuotaError::new(
                    ProviderQuotaErrorKind::Internal,
                    "provider refresh runtime stopped",
                )
            })?;
            if account.runtime_state().generation == generation {
                account
                    .refresh_credentials(RefreshTrigger::Unauthorized)
                    .await
                    .map_err(refresh_quota_error)?;
            }
            fetch_quota_source(account.as_ref()).await
        }
        result => result,
    }
}

async fn fetch_quota_source(
    account: &dyn ProviderAccount,
) -> Result<ProviderQuotaFetch, ProviderQuotaError> {
    let source = account.quota_source().ok_or_else(|| {
        ProviderQuotaError::new(
            ProviderQuotaErrorKind::Unsupported,
            "provider account does not support quota queries",
        )
    })?;
    source.fetch_quota().await
}

fn refresh_quota_error(error: RefreshError) -> ProviderQuotaError {
    let kind = match error.kind() {
        RefreshErrorKind::ReauthRequired => ProviderQuotaErrorKind::Authentication,
        RefreshErrorKind::Transient => ProviderQuotaErrorKind::Upstream,
        RefreshErrorKind::Internal => ProviderQuotaErrorKind::Internal,
    };
    ProviderQuotaError::new(kind, error.message())
}
