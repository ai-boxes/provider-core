use std::{
    collections::BTreeMap,
    sync::{Arc, PoisonError, RwLock},
};

use async_trait::async_trait;
use provider_core::{
    AccountId, AccountProvisioningInput, AccountRepository, ManagedProviderDriver,
    NewProviderAccount, ProviderAccount, ProviderAccountAccess, ProviderAccountUpdate,
    ProviderControl, ProviderControlError, ProviderKind, ProviderModel, ProviderRouteCandidate,
    ProviderRouter, StartedProviderOAuth, StoredProviderAccount, StoredProviderModel,
};
use thiserror::Error;

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
        removed
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

    async fn activate_account(
        &self,
        kind: ProviderKind,
        account: Arc<dyn ProviderAccount>,
        models: Vec<StoredProviderModel>,
        access: ProviderAccountAccess,
    ) -> Result<(), ProviderControlError> {
        let driver = self
            .inner
            .drivers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&kind)
            .cloned()
            .ok_or_else(|| ProviderControlError::new("provider type is not registered"))?;
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
        runtime.remove(account.account_id()).await;
        runtime
            .register(account.clone())
            .await
            .map_err(|error| ProviderControlError::new(error.to_string()))?;
        self.inner
            .router
            .replace_account_models(runtime, account, models, access)
            .map_err(|error| ProviderControlError::new(error.to_string()))?;
        Ok(())
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
    fn models(&self, user_id: &str) -> Vec<ProviderModel> {
        self.inner.router.models(user_id)
    }

    fn routes(&self, user_id: &str, model: &str) -> Vec<ProviderRouteCandidate> {
        self.inner.router.routes(user_id, model)
    }
}
