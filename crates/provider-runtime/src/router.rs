use std::{
    collections::{BTreeMap, hash_map::RandomState},
    hash::BuildHasher,
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use provider_core::{
    AccountId, ProviderAccount, ProviderError, ProviderModel, ProviderRequest, ProviderRoute,
    ProviderRouteCandidate, ProviderRouter, ProviderStream, StoredProviderModel, WireFormat,
};
use thiserror::Error;

use crate::ProviderRuntime;

#[derive(Clone)]
pub struct ProviderModelRouter {
    inner: Arc<RouterInner>,
}

struct RouterInner {
    accounts: RwLock<BTreeMap<AccountId, RoutedAccount>>,
    selection_state: RandomState,
    selection_counter: AtomicU64,
}

struct RoutedAccount {
    account: Arc<dyn ProviderAccount>,
    models: Vec<StoredProviderModel>,
    route: Arc<RuntimeAccountRoute>,
}

struct RuntimeAccountRoute {
    runtime: ProviderRuntime,
    account_id: AccountId,
}

#[derive(Debug, Error)]
pub enum ProviderModelRouterError {
    #[error("account provider does not match the runtime provider")]
    ProviderMismatch,
}

impl Default for ProviderModelRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderModelRouter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RouterInner {
                accounts: RwLock::new(BTreeMap::new()),
                selection_state: RandomState::new(),
                selection_counter: AtomicU64::new(0),
            }),
        }
    }

    pub fn replace_account_models(
        &self,
        runtime: ProviderRuntime,
        account: Arc<dyn ProviderAccount>,
        models: Vec<StoredProviderModel>,
    ) -> Result<(), ProviderModelRouterError> {
        if account.provider_name() != runtime.provider_name() {
            return Err(ProviderModelRouterError::ProviderMismatch);
        }
        let account_id = account.account_id().clone();
        let route = Arc::new(RuntimeAccountRoute {
            runtime,
            account_id: account_id.clone(),
        });
        self.accounts().insert(
            account_id,
            RoutedAccount {
                account,
                models,
                route,
            },
        );
        Ok(())
    }

    pub fn remove_account(&self, account_id: &AccountId) -> bool {
        self.accounts().remove(account_id).is_some()
    }

    fn accounts(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<AccountId, RoutedAccount>> {
        self.inner
            .accounts
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn account_snapshot(
        &self,
    ) -> std::sync::RwLockReadGuard<'_, BTreeMap<AccountId, RoutedAccount>> {
        self.inner
            .accounts
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl ProviderRouter for ProviderModelRouter {
    fn models(&self) -> Vec<ProviderModel> {
        let mut models = BTreeMap::new();
        for account in self.account_snapshot().values() {
            if !account.account.runtime_state().available_for_requests() {
                continue;
            }
            for model in account
                .models
                .iter()
                .filter(|model| model.enabled && model.available && model.routable)
            {
                let effective_model = model.effective_model().to_owned();
                models.entry(effective_model.clone()).or_insert_with(|| {
                    let mut provider_model = serde_json::from_str::<ProviderModel>(
                        &model.metadata_json,
                    )
                    .unwrap_or_else(|_| {
                        ProviderModel::new(&effective_model, account.account.provider_name())
                    });
                    provider_model.id = effective_model;
                    provider_model
                });
            }
        }
        models.into_values().collect()
    }

    fn routes(&self, model: &str) -> Vec<ProviderRouteCandidate> {
        let mut routes = Vec::new();
        for account in self.account_snapshot().values() {
            if !account.account.runtime_state().available_for_requests() {
                continue;
            }
            for provider_model in account.models.iter().filter(|provider_model| {
                provider_model.enabled
                    && provider_model.available
                    && provider_model.routable
                    && provider_model.effective_model() == model
            }) {
                routes.push(ProviderRouteCandidate {
                    upstream_model: provider_model.upstream_model.clone(),
                    route: account.route.clone(),
                });
            }
        }
        if routes.len() > 1 {
            let index = random_index(
                &self.inner.selection_state,
                &self.inner.selection_counter,
                routes.len(),
            );
            routes.rotate_left(index);
        }
        routes
    }
}

#[async_trait]
impl ProviderRoute for RuntimeAccountRoute {
    fn provider_name(&self) -> &'static str {
        self.runtime.provider_name()
    }

    fn native_format(&self) -> WireFormat {
        self.runtime.native_format()
    }

    async fn execute_stream(
        &self,
        request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError> {
        self.runtime
            .execute_stream_for(&self.account_id, request)
            .await
    }

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError> {
        self.runtime
            .count_tokens_for(&self.account_id, request)
            .await
    }
}

fn random_index(state: &RandomState, counter: &AtomicU64, length: usize) -> usize {
    let value = counter.fetch_add(1, Ordering::Relaxed);
    usize::try_from(state.hash_one(value)).unwrap_or_default() % length
}

#[cfg(test)]
mod tests {
    use futures_util::{StreamExt, stream};
    use provider_core::{
        AccountAuthState, AccountRuntimeState, RefreshError, RefreshOutcome, RefreshTrigger,
        RequestMetadata,
    };

    use super::*;

    struct TestDriver;

    impl provider_core::ProviderDriver for TestDriver {
        fn name(&self) -> &'static str {
            "test"
        }

        fn native_format(&self) -> WireFormat {
            WireFormat::OpenAiResponses
        }

        fn models(&self) -> &[ProviderModel] {
            &[]
        }
    }

    struct TestAccount {
        id: AccountId,
    }

    #[async_trait]
    impl ProviderAccount for TestAccount {
        fn provider_name(&self) -> &'static str {
            "test"
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

        async fn execute_stream(
            &self,
            request: ProviderRequest,
        ) -> Result<ProviderStream, ProviderError> {
            let output = format!("{}:{}", self.id, request.model);
            Ok(Box::pin(stream::once(async move {
                Ok(bytes::Bytes::from(output))
            })))
        }

        async fn count_tokens(&self, _request: ProviderRequest) -> Result<u64, ProviderError> {
            Ok(0)
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

    #[tokio::test]
    async fn deduplicates_public_models_and_keeps_account_specific_upstream_routes() {
        let runtime = ProviderRuntime::new(Arc::new(TestDriver));
        let first = Arc::new(TestAccount {
            id: AccountId::new("account-a").expect("account ID"),
        });
        let second = Arc::new(TestAccount {
            id: AccountId::new("account-b").expect("account ID"),
        });
        runtime
            .register(first.clone())
            .await
            .expect("first account");
        runtime
            .register(second.clone())
            .await
            .expect("second account");

        let router = ProviderModelRouter::new();
        router
            .replace_account_models(
                runtime.clone(),
                first.clone(),
                vec![
                    stored_model(&first.id, "upstream-a", "shared"),
                    non_routable_model(&first.id, "grok-imagine-image"),
                ],
            )
            .expect("first routes");
        router
            .replace_account_models(
                runtime.clone(),
                second.clone(),
                vec![stored_model(&second.id, "upstream-b", "shared")],
            )
            .expect("second routes");

        let models = router.models();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "shared");
        assert!(router.routes("grok-imagine-image").is_empty());

        let routes = router.routes("shared");
        assert_eq!(routes.len(), 2);
        let mut outputs = Vec::new();
        for route in routes {
            let stream = route
                .route
                .execute_stream(ProviderRequest {
                    format: WireFormat::OpenAiResponses,
                    model: route.upstream_model,
                    payload: bytes::Bytes::new(),
                    metadata: RequestMetadata::default(),
                })
                .await
                .expect("route stream");
            outputs.extend(
                stream
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
                    .expect("route output")
                    .into_iter()
                    .map(|output| String::from_utf8(output.to_vec()).expect("UTF-8")),
            );
        }
        outputs.sort();
        assert_eq!(
            outputs,
            vec!["account-a:upstream-a", "account-b:upstream-b"]
        );
        runtime.shutdown();
    }

    fn stored_model(
        account_id: &AccountId,
        upstream_model: &str,
        alias: &str,
    ) -> StoredProviderModel {
        StoredProviderModel {
            account_id: account_id.clone(),
            upstream_model: upstream_model.to_owned(),
            alias: Some(alias.to_owned()),
            enabled: true,
            available: true,
            routable: true,
            metadata_json: "{}".to_owned(),
            last_seen_at: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn non_routable_model(account_id: &AccountId, upstream_model: &str) -> StoredProviderModel {
        let mut model = stored_model(account_id, upstream_model, upstream_model);
        model.routable = false;
        model
    }
}
