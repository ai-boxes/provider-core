use std::{
    collections::{BTreeMap, HashMap, HashSet, hash_map::RandomState},
    hash::BuildHasher,
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use provider_core::{
    AccountId, ProviderAccount, ProviderAccountAccess, ProviderError, ProviderModel,
    ProviderRequest, ProviderRoute, ProviderRouteCandidate, ProviderRouter, ProviderStream,
    ProviderVisibility, RoutableProviderModel, StoredProviderModel, WireFormat,
};
use thiserror::Error;

use crate::ProviderRuntime;

#[derive(Clone)]
pub struct ProviderModelRouter {
    inner: Arc<RouterInner>,
}

const SESSION_AFFINITY_TTL: Duration = Duration::from_secs(60 * 60);
const SESSION_AFFINITY_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

struct RouterInner {
    accounts: RwLock<BTreeMap<AccountId, RoutedAccount>>,
    affinities: Mutex<SessionAffinities>,
    selection_state: RandomState,
    selection_counter: AtomicU64,
}

#[derive(Default)]
struct SessionAffinities {
    entries: HashMap<SessionAffinityKey, SessionAffinity>,
    last_cleanup: Option<Instant>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SessionAffinityKey {
    user_id: String,
    model: String,
    session_id: String,
}

struct SessionAffinity {
    account_id: AccountId,
    last_used: Instant,
}

struct RoutedAccount {
    account: Arc<dyn ProviderAccount>,
    access: ProviderAccountAccess,
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
                affinities: Mutex::new(SessionAffinities::default()),
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
        access: ProviderAccountAccess,
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
                access,
                models,
                route,
            },
        );
        Ok(())
    }

    pub fn remove_account(&self, account_id: &AccountId) -> bool {
        let removed = self.accounts().remove(account_id).is_some();
        if removed {
            self.affinities()
                .entries
                .retain(|_, affinity| affinity.account_id != *account_id);
        }
        removed
    }

    pub fn update_account_access(
        &self,
        account_id: &AccountId,
        access: ProviderAccountAccess,
    ) -> bool {
        let mut accounts = self.accounts();
        let Some(account) = accounts.get_mut(account_id) else {
            return false;
        };
        account.access = access;
        true
    }

    pub fn update_account_models(
        &self,
        account_id: &AccountId,
        models: Vec<StoredProviderModel>,
    ) -> bool {
        let mut accounts = self.accounts();
        let Some(account) = accounts.get_mut(account_id) else {
            return false;
        };
        account.models = models;
        true
    }

    pub fn claim_unowned_account_access(&self, owner_user_id: &str) {
        for account in self.accounts().values_mut() {
            if account.access.owner_user_id.is_none() {
                account.access.owner_user_id = Some(owner_user_id.to_owned());
                account.access.visibility = ProviderVisibility::Private;
            }
        }
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

    fn affinities(&self) -> std::sync::MutexGuard<'_, SessionAffinities> {
        self.inner
            .affinities
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl ProviderRouter for ProviderModelRouter {
    fn models(
        &self,
        user_id: &str,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Vec<RoutableProviderModel> {
        let mut models = BTreeMap::new();
        for account in self.account_snapshot().values() {
            if !account.access.allows(user_id)
                || !account.account.runtime_state().available_for_requests()
                || account_ids.is_some_and(|ids| !ids.contains(account.account.account_id()))
            {
                continue;
            }
            for model in account
                .models
                .iter()
                .filter(|model| model.enabled && model.available && model.routable)
            {
                let effective_model = model.effective_model().to_owned();
                let native_format = account.route.native_format();
                let entry = models.entry(effective_model.clone()).or_insert_with(|| {
                    let mut provider_model =
                        serde_json::from_str::<ProviderModel>(&model.metadata_json)
                            .expect("stored provider model metadata must be valid");
                    provider_model.id = effective_model;
                    RoutableProviderModel {
                        model: provider_model,
                        native_formats: Vec::new(),
                    }
                });
                if !entry.native_formats.contains(&native_format) {
                    entry.native_formats.push(native_format);
                }
            }
        }
        models.into_values().collect()
    }

    fn routes(
        &self,
        user_id: &str,
        model: &str,
        native_formats: &[WireFormat],
        session_id: Option<&str>,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Vec<ProviderRouteCandidate> {
        let mut routes = Vec::new();
        for (account_id, account) in self.account_snapshot().iter() {
            if !account.access.allows(user_id)
                || !account.account.runtime_state().available_for_requests()
                || !native_formats.contains(&account.route.native_format())
                || account_ids.is_some_and(|ids| !ids.contains(account_id))
            {
                continue;
            }
            for provider_model in account.models.iter().filter(|provider_model| {
                provider_model.enabled
                    && provider_model.available
                    && provider_model.routable
                    && provider_model.effective_model() == model
            }) {
                routes.push((
                    account_id.clone(),
                    ProviderRouteCandidate {
                        upstream_model: provider_model.upstream_model.clone(),
                        pricing: provider_model.pricing.clone(),
                        route: account.route.clone(),
                    },
                ));
            }
        }
        if routes.is_empty() {
            return Vec::new();
        }

        let Some(session_id) = session_id.map(str::trim).filter(|value| !value.is_empty()) else {
            randomize_routes(&self.inner, &mut routes);
            return routes.into_iter().map(|(_, route)| route).collect();
        };
        let key = SessionAffinityKey {
            user_id: user_id.to_owned(),
            model: model.to_owned(),
            session_id: session_id.to_owned(),
        };
        let now = Instant::now();
        let mut affinities = self.affinities();
        if affinities.last_cleanup.is_none_or(|last_cleanup| {
            now.duration_since(last_cleanup) >= SESSION_AFFINITY_CLEANUP_INTERVAL
        }) {
            affinities.entries.retain(|_, affinity| {
                now.duration_since(affinity.last_used) < SESSION_AFFINITY_TTL
            });
            affinities.last_cleanup = Some(now);
        }
        if let Some(affinity) = affinities.entries.get_mut(&key) {
            if now.duration_since(affinity.last_used) < SESSION_AFFINITY_TTL
                && let Some(index) = routes
                    .iter()
                    .position(|(account_id, _)| *account_id == affinity.account_id)
            {
                affinity.last_used = now;
                routes.rotate_left(index);
                return routes.into_iter().map(|(_, route)| route).collect();
            }
            affinities.entries.remove(&key);
        }

        randomize_routes(&self.inner, &mut routes);
        affinities.entries.insert(
            key,
            SessionAffinity {
                account_id: routes[0].0.clone(),
                last_used: now,
            },
        );
        routes.into_iter().map(|(_, route)| route).collect()
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
        pricing: Option<&provider_core::ProviderModelPricingRecord>,
        tracking: Option<&Arc<dyn provider_core::usage::RequestTracking>>,
    ) -> Result<ProviderStream, ProviderError> {
        self.runtime
            .execute_stream_for(&self.account_id, request, pricing, tracking)
            .await
    }

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError> {
        self.runtime
            .count_tokens_for(&self.account_id, request)
            .await
    }
}

fn randomize_routes(inner: &RouterInner, routes: &mut [(AccountId, ProviderRouteCandidate)]) {
    if routes.len() > 1 {
        let index = random_index(
            &inner.selection_state,
            &inner.selection_counter,
            routes.len(),
        );
        routes.rotate_left(index);
    }
}

fn random_index(state: &RandomState, counter: &AtomicU64, length: usize) -> usize {
    let value = counter.fetch_add(1, Ordering::Relaxed);
    let length = u64::try_from(length).expect("route count must fit u64");
    usize::try_from(state.hash_one(value) % length).expect("route index must fit usize")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use futures_util::{StreamExt, stream};
    use provider_core::{
        AccountAuthState, AccountRuntimeState, ProviderVisibility, RefreshError, RefreshOutcome,
        RefreshTrigger, RequestMetadata,
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

        fn credential_revision(&self) -> u64 {
            0
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
                access("owner-a", ProviderVisibility::Private),
            )
            .expect("first routes");
        router
            .replace_account_models(
                runtime.clone(),
                second.clone(),
                vec![stored_model(&second.id, "upstream-b", "shared")],
                access("owner-b", ProviderVisibility::Shared),
            )
            .expect("second routes");

        let models = router.models("owner-a", None);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].model.id, "shared");
        assert_eq!(models[0].native_formats, [WireFormat::OpenAiResponses]);
        assert!(
            router
                .routes(
                    "owner-a",
                    "grok-imagine-image",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None
                )
                .is_empty()
        );

        let routes = router.routes(
            "owner-a",
            "shared",
            &[WireFormat::OpenAiResponses],
            None,
            None,
        );
        assert_eq!(routes.len(), 2);
        let mut outputs = Vec::new();
        for route in routes {
            let stream = route
                .route
                .execute_stream(
                    ProviderRequest {
                        format: WireFormat::OpenAiResponses,
                        model: route.upstream_model,
                        payload: bytes::Bytes::new(),
                        metadata: RequestMetadata::default(),
                    },
                    None,
                    None,
                )
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

        let only_second = HashSet::from([second.id.clone()]);
        let filtered_models = router.models("owner-a", Some(&only_second));
        assert_eq!(filtered_models.len(), 1);
        assert_eq!(filtered_models[0].model.id, "shared");
        let filtered_routes = router.routes(
            "owner-a",
            "shared",
            &[WireFormat::OpenAiResponses],
            None,
            Some(&only_second),
        );
        assert_eq!(filtered_routes.len(), 1);
        assert_eq!(filtered_routes[0].upstream_model, "upstream-b");
        assert!(
            router
                .routes(
                    "owner-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    Some(&HashSet::new()),
                )
                .is_empty()
        );

        assert_eq!(
            router
                .routes(
                    "owner-b",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None
                )
                .len(),
            1
        );
        assert_eq!(
            router
                .routes(
                    "other-user",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None
                )
                .len(),
            1
        );

        assert!(
            router
                .update_account_access(&second.id, access("owner-b", ProviderVisibility::Private),)
        );
        assert!(
            router
                .routes(
                    "other-user",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None
                )
                .is_empty()
        );
        assert_eq!(
            router
                .routes(
                    "owner-b",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None
                )
                .len(),
            1
        );

        assert!(router.update_account_access(
            &first.id,
            ProviderAccountAccess {
                owner_user_id: None,
                visibility: ProviderVisibility::Private,
            },
        ));
        assert!(
            router
                .routes(
                    "owner-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None
                )
                .is_empty()
        );
        router.claim_unowned_account_access("owner-a");
        assert_eq!(
            router
                .routes(
                    "owner-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None
                )
                .len(),
            1
        );
        assert!(router.update_account_models(
            &first.id,
            vec![stored_model(&first.id, "upstream-a", "updated")],
        ));
        assert!(
            router
                .routes(
                    "owner-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None
                )
                .is_empty()
        );
        assert_eq!(
            router
                .routes(
                    "owner-a",
                    "updated",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None
                )
                .len(),
            1
        );
        runtime.shutdown();
    }

    #[tokio::test]
    async fn keeps_session_on_the_same_account_until_it_becomes_invalid() {
        let runtime = ProviderRuntime::new(Arc::new(TestDriver));
        let first = Arc::new(TestAccount {
            id: AccountId::new("affinity-a").expect("account ID"),
        });
        let second = Arc::new(TestAccount {
            id: AccountId::new("affinity-b").expect("account ID"),
        });
        for account in [&first, &second] {
            runtime
                .register(account.clone())
                .await
                .expect("register account");
        }

        let router = ProviderModelRouter::new();
        router
            .replace_account_models(
                runtime.clone(),
                first.clone(),
                vec![stored_model(&first.id, "upstream-a", "shared")],
                access("owner", ProviderVisibility::Shared),
            )
            .expect("first route");
        router
            .replace_account_models(
                runtime.clone(),
                second.clone(),
                vec![stored_model(&second.id, "upstream-b", "shared")],
                access("owner", ProviderVisibility::Shared),
            )
            .expect("second route");

        let first_selection = router.routes(
            "caller",
            "shared",
            &[WireFormat::OpenAiResponses],
            Some("cc_session"),
            None,
        );
        let selected_model = first_selection[0].upstream_model.clone();
        assert_eq!(
            router.routes(
                "caller",
                "shared",
                &[WireFormat::OpenAiResponses],
                Some("cc_session"),
                None
            )[0]
            .upstream_model,
            selected_model
        );
        assert_eq!(
            router
                .routes(
                    "caller",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    Some("different_session"),
                    None
                )
                .len(),
            2
        );

        let third = Arc::new(TestAccount {
            id: AccountId::new("affinity-c").expect("account ID"),
        });
        runtime
            .register(third.clone())
            .await
            .expect("register third account");
        router
            .replace_account_models(
                runtime.clone(),
                third.clone(),
                vec![stored_model(&third.id, "upstream-c", "shared")],
                access("owner", ProviderVisibility::Shared),
            )
            .expect("third route");
        assert_eq!(
            router.routes(
                "caller",
                "shared",
                &[WireFormat::OpenAiResponses],
                Some("cc_session"),
                None
            )[0]
            .upstream_model,
            selected_model
        );

        let selected_account = if selected_model == "upstream-a" {
            &first.id
        } else {
            &second.id
        };
        assert!(router.remove_account(selected_account));
        let replacement = router.routes(
            "caller",
            "shared",
            &[WireFormat::OpenAiResponses],
            Some("cc_session"),
            None,
        )[0]
        .upstream_model
        .clone();
        assert_ne!(replacement, selected_model);
        assert!(matches!(
            replacement.as_str(),
            "upstream-a" | "upstream-b" | "upstream-c"
        ));
        assert_eq!(
            router.routes(
                "caller",
                "shared",
                &[WireFormat::OpenAiResponses],
                Some("cc_session"),
                None
            )[0]
            .upstream_model,
            replacement
        );
        runtime.shutdown();
    }

    #[tokio::test]
    async fn removes_expired_affinity_during_route_selection() {
        let runtime = ProviderRuntime::new(Arc::new(TestDriver));
        let account = Arc::new(TestAccount {
            id: AccountId::new("affinity-account").expect("account ID"),
        });
        runtime
            .register(account.clone())
            .await
            .expect("register account");
        let router = ProviderModelRouter::new();
        router
            .replace_account_models(
                runtime.clone(),
                account.clone(),
                vec![stored_model(&account.id, "upstream", "shared")],
                access("owner", ProviderVisibility::Shared),
            )
            .expect("route");
        let expired_key = SessionAffinityKey {
            user_id: "caller".to_owned(),
            model: "shared".to_owned(),
            session_id: "expired-session".to_owned(),
        };
        router.affinities().entries.insert(
            expired_key.clone(),
            SessionAffinity {
                account_id: account.id.clone(),
                last_used: Instant::now() - SESSION_AFFINITY_TTL - Duration::from_secs(1),
            },
        );

        assert_eq!(
            router.routes(
                "caller",
                "shared",
                &[WireFormat::OpenAiResponses],
                Some("active-session"),
                None
            )[0]
            .upstream_model,
            "upstream"
        );
        let affinities = router.affinities();
        assert!(!affinities.entries.contains_key(&expired_key));
        assert!(affinities.entries.contains_key(&SessionAffinityKey {
            user_id: "caller".to_owned(),
            model: "shared".to_owned(),
            session_id: "active-session".to_owned(),
        }));
        drop(affinities);

        let expired_at = Instant::now() - SESSION_AFFINITY_TTL - Duration::from_secs(1);
        router.affinities().entries.insert(
            expired_key.clone(),
            SessionAffinity {
                account_id: account.id.clone(),
                last_used: expired_at,
            },
        );
        assert_eq!(
            router.routes(
                "caller",
                "shared",
                &[WireFormat::OpenAiResponses],
                Some("expired-session"),
                None
            )[0]
            .upstream_model,
            "upstream"
        );
        let affinities = router.affinities();
        assert!(affinities.entries[&expired_key].last_used > expired_at);
        drop(affinities);
        runtime.shutdown();
    }

    fn access(owner_user_id: &str, visibility: ProviderVisibility) -> ProviderAccountAccess {
        ProviderAccountAccess {
            owner_user_id: Some(owner_user_id.to_owned()),
            visibility,
        }
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
            metadata_json: serde_json::to_string(&ProviderModel::new(upstream_model, "test"))
                .expect("serialize provider model"),
            pricing: None,
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
