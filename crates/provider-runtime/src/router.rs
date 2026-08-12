use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use provider_core::{
    AccountId, ProviderAccount, ProviderAccountAccess, ProviderError, ProviderModel,
    ProviderModelInputModality, ProviderRequest, ProviderRoute, ProviderRouteCandidate,
    ProviderRouter, ProviderStream, ProviderVisibility, RoutableProviderModel, StoredProviderModel,
    WireFormat,
};
use thiserror::Error;

use crate::ProviderRuntime;

#[derive(Clone)]
pub struct ProviderModelRouter {
    inner: Arc<RouterInner>,
}

const SESSION_AFFINITY_TTL: Duration = Duration::from_secs(60 * 60);
const SESSION_AFFINITY_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(30);
const QUOTA_COOLDOWN: Duration = Duration::from_secs(5 * 60);
const AUTH_COOLDOWN: Duration = Duration::from_secs(30 * 60);
const PRECONNECT_COOLDOWN: Duration = Duration::from_secs(30);
const RESPONSE_BINDING_TTL: Duration = Duration::from_secs(60 * 60);

struct RouterInner {
    accounts: RwLock<BTreeMap<AccountId, RoutedAccount>>,
    affinities: Mutex<SessionAffinities>,
    selections: Mutex<HashMap<SelectionKey, u64>>,
    cooldowns: Mutex<HashMap<CooldownKey, Instant>>,
    response_bindings: Mutex<HashMap<ResponseBindingKey, ResponseBinding>>,
}

#[derive(Default)]
struct SessionAffinities {
    entries: HashMap<SessionAffinityKey, SessionAffinity>,
    last_cleanup: Option<Instant>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SessionAffinityKey {
    routing_scope: String,
    model: String,
    session_id: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SelectionKey {
    routing_scope: String,
    model: String,
    priority: u32,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CooldownKey {
    account_id: AccountId,
    model: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ResponseBindingKey {
    routing_scope: String,
    response_id: String,
}

struct ResponseBinding {
    account_id: AccountId,
    bound_at: Instant,
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
    priority: u32,
}

struct RuntimeAccountRoute {
    runtime: ProviderRuntime,
    account_id: AccountId,
    usage_profile: Option<provider_core::usage::ProviderUsageProfile>,
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
                selections: Mutex::new(HashMap::new()),
                cooldowns: Mutex::new(HashMap::new()),
                response_bindings: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn replace_account_models(
        &self,
        runtime: ProviderRuntime,
        account: Arc<dyn ProviderAccount>,
        models: Vec<StoredProviderModel>,
        access: ProviderAccountAccess,
        priority: u32,
    ) -> Result<(), ProviderModelRouterError> {
        if account.provider_name() != runtime.provider_name() {
            return Err(ProviderModelRouterError::ProviderMismatch);
        }
        let account_id = account.account_id().clone();
        let route = Arc::new(RuntimeAccountRoute {
            runtime,
            account_id: account_id.clone(),
            usage_profile: account.usage_profile(),
        });
        self.accounts().insert(
            account_id,
            RoutedAccount {
                account,
                access,
                models,
                route,
                priority,
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
            self.cooldowns()
                .retain(|key, _| key.account_id != *account_id);
            self.response_bindings()
                .retain(|_, binding| binding.account_id != *account_id);
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

    fn selections(&self) -> std::sync::MutexGuard<'_, HashMap<SelectionKey, u64>> {
        self.inner
            .selections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn cooldowns(&self) -> std::sync::MutexGuard<'_, HashMap<CooldownKey, Instant>> {
        self.inner
            .cooldowns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn response_bindings(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<ResponseBindingKey, ResponseBinding>> {
        self.inner
            .response_bindings
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
                    provider_model =
                        provider_model.with_input_modalities(model.input_modalities.clone());
                    RoutableProviderModel {
                        model: provider_model,
                        native_formats: Vec::new(),
                    }
                });
                let input_modalities = conservative_input_modalities(
                    entry.model.input_modalities.as_deref(),
                    model.input_modalities.as_deref(),
                );
                entry.model = entry.model.clone().with_input_modalities(input_modalities);
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
        routing_scope: &str,
        model: &str,
        native_formats: &[WireFormat],
        session_id: Option<&str>,
        previous_response_id: Option<&str>,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Vec<ProviderRouteCandidate> {
        let now = Instant::now();
        let mut cooldowns = self.cooldowns();
        cooldowns.retain(|_, until| *until > now);
        let mut routes = Vec::new();
        for (account_id, account) in self.account_snapshot().iter() {
            if !account.access.allows(user_id)
                || !account.account.runtime_state().available_for_requests()
                || !native_formats.contains(&account.route.native_format())
                || account_ids.is_some_and(|ids| !ids.contains(account_id))
                || cooldowns.contains_key(&CooldownKey {
                    account_id: account_id.clone(),
                    model: model.to_owned(),
                })
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
                        account_id: Some(account_id.clone()),
                        priority: account.priority,
                        upstream_model: provider_model.upstream_model.clone(),
                        input_modalities: provider_model.input_modalities.clone(),
                        responses_lite: model_uses_responses_lite(provider_model),
                        pricing: provider_model.pricing.clone(),
                        route: account.route.clone(),
                    },
                ));
            }
        }
        if routes.is_empty() {
            return Vec::new();
        }

        routes.sort_by(|left, right| {
            left.1
                .priority
                .cmp(&right.1.priority)
                .then(left.0.cmp(&right.0))
        });

        if let Some(previous_response_id) = previous_response_id {
            let mut bindings = self.response_bindings();
            bindings
                .retain(|_, binding| now.duration_since(binding.bound_at) < RESPONSE_BINDING_TTL);
            let bound = bindings
                .get(&ResponseBindingKey {
                    routing_scope: routing_scope.to_owned(),
                    response_id: previous_response_id.to_owned(),
                })
                .map(|binding| binding.account_id.clone());
            return bound
                .and_then(|bound| {
                    routes
                        .into_iter()
                        .find(|(account_id, _)| *account_id == bound)
                })
                .map(|(_, route)| vec![route])
                .unwrap_or_default();
        }

        let Some(session_id) = session_id.map(str::trim).filter(|value| !value.is_empty()) else {
            rotate_round_robin(self, routing_scope, model, &mut routes);
            return routes.into_iter().map(|(_, route)| route).collect();
        };
        let key = SessionAffinityKey {
            routing_scope: routing_scope.to_owned(),
            model: model.to_owned(),
            session_id: session_id.to_owned(),
        };
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

        drop(affinities);
        rotate_round_robin(self, routing_scope, model, &mut routes);
        routes.into_iter().map(|(_, route)| route).collect()
    }

    fn commit_session_affinity(
        &self,
        routing_scope: &str,
        model: &str,
        session_id: Option<&str>,
        account_id: &AccountId,
    ) {
        let Some(session_id) = session_id.map(str::trim).filter(|value| !value.is_empty()) else {
            return;
        };
        self.affinities().entries.insert(
            SessionAffinityKey {
                routing_scope: routing_scope.to_owned(),
                model: model.to_owned(),
                session_id: session_id.to_owned(),
            },
            SessionAffinity {
                account_id: account_id.clone(),
                last_used: Instant::now(),
            },
        );
    }

    fn record_route_failure(
        &self,
        account_id: &AccountId,
        model: &str,
        reason: provider_core::ProviderFailoverReason,
    ) {
        let duration = match reason {
            provider_core::ProviderFailoverReason::AuthenticationExhausted => AUTH_COOLDOWN,
            provider_core::ProviderFailoverReason::QuotaExhausted => QUOTA_COOLDOWN,
            provider_core::ProviderFailoverReason::RateLimited => RATE_LIMIT_COOLDOWN,
            provider_core::ProviderFailoverReason::PreconnectFailure => PRECONNECT_COOLDOWN,
        };
        self.cooldowns().insert(
            CooldownKey {
                account_id: account_id.clone(),
                model: model.to_owned(),
            },
            Instant::now() + duration,
        );
    }

    fn record_route_success(&self, account_id: &AccountId, model: &str) {
        self.cooldowns().remove(&CooldownKey {
            account_id: account_id.clone(),
            model: model.to_owned(),
        });
    }

    fn bind_response_id(&self, routing_scope: &str, response_id: &str, account_id: &AccountId) {
        self.response_bindings().insert(
            ResponseBindingKey {
                routing_scope: routing_scope.to_owned(),
                response_id: response_id.to_owned(),
            },
            ResponseBinding {
                account_id: account_id.clone(),
                bound_at: Instant::now(),
            },
        );
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

    fn supports_previous_response_id(&self) -> bool {
        self.runtime.provider_name() == "codex"
    }

    fn usage_profile(&self) -> Option<provider_core::usage::ProviderUsageProfile> {
        self.usage_profile
    }

    fn maximum_attempts(&self) -> u32 {
        2
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

fn model_uses_responses_lite(model: &StoredProviderModel) -> bool {
    serde_json::from_str::<serde_json::Value>(&model.metadata_json)
        .ok()
        .and_then(|metadata| {
            metadata
                .get("use_responses_lite")
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(false)
}

fn conservative_input_modalities(
    left: Option<&[ProviderModelInputModality]>,
    right: Option<&[ProviderModelInputModality]>,
) -> Option<Vec<ProviderModelInputModality>> {
    let (Some(left), Some(right)) = (left, right) else {
        return None;
    };
    let modalities = left
        .iter()
        .filter(|modality| right.contains(modality))
        .cloned()
        .collect::<Vec<_>>();
    (!modalities.is_empty()).then_some(modalities)
}

fn rotate_round_robin(
    router: &ProviderModelRouter,
    routing_scope: &str,
    model: &str,
    routes: &mut [(AccountId, ProviderRouteCandidate)],
) {
    if routes.len() <= 1 {
        return;
    }
    let priority = routes[0].1.priority;
    let tier_len = routes
        .iter()
        .take_while(|(_, candidate)| candidate.priority == priority)
        .count();
    let key = SelectionKey {
        routing_scope: routing_scope.to_owned(),
        model: model.to_owned(),
        priority,
    };
    let mut selections = router.selections();
    let cursor = selections.entry(key).or_default();
    let index = usize::try_from(*cursor % u64::try_from(tier_len).expect("tier length fits u64"))
        .expect("round-robin index fits usize");
    *cursor = cursor.wrapping_add(1);
    routes[..tier_len].rotate_left(index);
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
        let mut first_shared = stored_model(&first.id, "upstream-a", "shared");
        first_shared.input_modalities = Some(vec![
            ProviderModelInputModality::Text,
            ProviderModelInputModality::Image,
            ProviderModelInputModality::Audio,
        ]);
        let mut first_metadata: serde_json::Value =
            serde_json::from_str(&first_shared.metadata_json).expect("model metadata");
        first_metadata["use_responses_lite"] = serde_json::Value::Bool(true);
        first_shared.metadata_json =
            serde_json::to_string(&first_metadata).expect("serialize model metadata");
        router
            .replace_account_models(
                runtime.clone(),
                first.clone(),
                vec![
                    first_shared,
                    non_routable_model(&first.id, "grok-imagine-image"),
                ],
                access("owner-a", ProviderVisibility::Private),
                0,
            )
            .expect("first routes");
        let mut second_shared = stored_model(&second.id, "upstream-b", "shared");
        second_shared.input_modalities = Some(vec![
            ProviderModelInputModality::Text,
            ProviderModelInputModality::Pdf,
            ProviderModelInputModality::Audio,
        ]);
        router
            .replace_account_models(
                runtime.clone(),
                second.clone(),
                vec![second_shared],
                access("owner-b", ProviderVisibility::Shared),
                0,
            )
            .expect("second routes");

        let models = router.models("owner-a", None);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].model.id, "shared");
        assert_eq!(
            models[0].model.input_modalities,
            Some(vec![
                ProviderModelInputModality::Text,
                ProviderModelInputModality::Audio,
            ])
        );
        assert_eq!(models[0].native_formats, [WireFormat::OpenAiResponses]);
        assert!(
            router
                .routes(
                    "owner-a",
                    "owner-a",
                    "grok-imagine-image",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None,
                    None
                )
                .is_empty()
        );

        let routes = router.routes(
            "owner-a",
            "owner-a",
            "shared",
            &[WireFormat::OpenAiResponses],
            None,
            None,
            None,
        );
        assert_eq!(routes.len(), 2);
        assert!(
            routes
                .iter()
                .any(|route| { route.upstream_model == "upstream-a" && route.responses_lite })
        );
        assert!(
            routes
                .iter()
                .any(|route| { route.upstream_model == "upstream-b" && !route.responses_lite })
        );
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
            "owner-a",
            "shared",
            &[WireFormat::OpenAiResponses],
            None,
            None,
            Some(&only_second),
        );
        assert_eq!(filtered_routes.len(), 1);
        assert_eq!(filtered_routes[0].upstream_model, "upstream-b");
        assert!(
            router
                .routes(
                    "owner-a",
                    "owner-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None,
                    Some(&HashSet::new()),
                )
                .is_empty()
        );

        assert_eq!(
            router
                .routes(
                    "owner-b",
                    "owner-b",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
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
                    "other-user",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
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
                    "other-user",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None,
                    None
                )
                .is_empty()
        );
        assert_eq!(
            router
                .routes(
                    "owner-b",
                    "owner-b",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
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
                    "owner-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
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
                    "owner-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
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
                    "owner-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None,
                    None
                )
                .is_empty()
        );
        assert_eq!(
            router
                .routes(
                    "owner-a",
                    "owner-a",
                    "updated",
                    &[WireFormat::OpenAiResponses],
                    None,
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
                0,
            )
            .expect("first route");
        router
            .replace_account_models(
                runtime.clone(),
                second.clone(),
                vec![stored_model(&second.id, "upstream-b", "shared")],
                access("owner", ProviderVisibility::Shared),
                0,
            )
            .expect("second route");

        let first_selection = router.routes(
            "caller",
            "caller",
            "shared",
            &[WireFormat::OpenAiResponses],
            Some("cc_session"),
            None,
            None,
        );
        let selected_model = first_selection[0].upstream_model.clone();
        let selected_account = if selected_model == "upstream-a" {
            &first.id
        } else {
            &second.id
        };
        router.commit_session_affinity("caller", "shared", Some("cc_session"), selected_account);
        assert_eq!(
            router.routes(
                "caller",
                "caller",
                "shared",
                &[WireFormat::OpenAiResponses],
                Some("cc_session"),
                None,
                None,
            )[0]
            .upstream_model,
            selected_model
        );
        assert_eq!(
            router
                .routes(
                    "caller",
                    "caller",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    Some("different_session"),
                    None,
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
                0,
            )
            .expect("third route");
        assert_eq!(
            router.routes(
                "caller",
                "caller",
                "shared",
                &[WireFormat::OpenAiResponses],
                Some("cc_session"),
                None,
                None,
            )[0]
            .upstream_model,
            selected_model
        );

        assert!(router.remove_account(selected_account));
        let replacement = router.routes(
            "caller",
            "caller",
            "shared",
            &[WireFormat::OpenAiResponses],
            Some("cc_session"),
            None,
            None,
        )[0]
        .upstream_model
        .clone();
        let replacement_account = if replacement == "upstream-a" {
            &first.id
        } else if replacement == "upstream-b" {
            &second.id
        } else {
            &third.id
        };
        router.commit_session_affinity("caller", "shared", Some("cc_session"), replacement_account);
        assert_ne!(replacement, selected_model);
        assert!(matches!(
            replacement.as_str(),
            "upstream-a" | "upstream-b" | "upstream-c"
        ));
        assert_eq!(
            router.routes(
                "caller",
                "caller",
                "shared",
                &[WireFormat::OpenAiResponses],
                Some("cc_session"),
                None,
                None,
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
                0,
            )
            .expect("route");
        let expired_key = SessionAffinityKey {
            routing_scope: "caller".to_owned(),
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
                "caller",
                "shared",
                &[WireFormat::OpenAiResponses],
                Some("active-session"),
                None,
                None
            )[0]
            .upstream_model,
            "upstream"
        );
        router.commit_session_affinity("caller", "shared", Some("active-session"), &account.id);
        let affinities = router.affinities();
        assert!(!affinities.entries.contains_key(&expired_key));
        assert!(affinities.entries.contains_key(&SessionAffinityKey {
            routing_scope: "caller".to_owned(),
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
                "caller",
                "shared",
                &[WireFormat::OpenAiResponses],
                Some("expired-session"),
                None,
                None
            )[0]
            .upstream_model,
            "upstream"
        );
        let affinities = router.affinities();
        assert!(!affinities.entries.contains_key(&expired_key));
        drop(affinities);
        runtime.shutdown();
    }

    #[tokio::test]
    async fn priority_round_robin_cooldown_and_response_bindings_are_scoped() {
        let runtime = ProviderRuntime::new(Arc::new(TestDriver));
        let high_a = Arc::new(TestAccount {
            id: AccountId::new("priority-a").expect("account ID"),
        });
        let high_b = Arc::new(TestAccount {
            id: AccountId::new("priority-b").expect("account ID"),
        });
        let low = Arc::new(TestAccount {
            id: AccountId::new("priority-low").expect("account ID"),
        });
        for account in [&high_a, &high_b, &low] {
            runtime.register(account.clone()).await.expect("register");
        }
        let router = ProviderModelRouter::new();
        for (account, upstream, priority) in [
            (&high_a, "upstream-a", 0),
            (&high_b, "upstream-b", 0),
            (&low, "upstream-low", 10),
        ] {
            router
                .replace_account_models(
                    runtime.clone(),
                    account.clone(),
                    vec![stored_model(&account.id, upstream, "shared")],
                    access("owner", ProviderVisibility::Shared),
                    priority,
                )
                .expect("route");
        }

        let first = router.routes(
            "caller",
            "key-a",
            "shared",
            &[WireFormat::OpenAiResponses],
            None,
            None,
            None,
        );
        let second = router.routes(
            "caller",
            "key-a",
            "shared",
            &[WireFormat::OpenAiResponses],
            None,
            None,
            None,
        );
        assert_eq!(first[2].priority, 10);
        assert_eq!(second[2].priority, 10);
        assert_ne!(first[0].account_id, second[0].account_id);

        let cooled = first[0].account_id.clone().expect("account");
        router.record_route_failure(
            &cooled,
            "shared",
            provider_core::ProviderFailoverReason::RateLimited,
        );
        let after_cooldown = router.routes(
            "caller",
            "key-a",
            "shared",
            &[WireFormat::OpenAiResponses],
            None,
            None,
            None,
        );
        assert!(
            !after_cooldown
                .iter()
                .any(|candidate| candidate.account_id.as_ref() == Some(&cooled))
        );
        router.record_route_success(&cooled, "shared");
        assert!(
            router
                .routes(
                    "caller",
                    "key-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    None,
                    None,
                )
                .iter()
                .any(|candidate| candidate.account_id.as_ref() == Some(&cooled))
        );

        router.bind_response_id("key-a", "resp-1", &high_a.id);
        let bound = router.routes(
            "caller",
            "key-a",
            "shared",
            &[WireFormat::OpenAiResponses],
            None,
            Some("resp-1"),
            None,
        );
        assert_eq!(bound.len(), 1);
        assert_eq!(bound[0].account_id.as_ref(), Some(&high_a.id));
        assert!(
            router
                .routes(
                    "caller",
                    "key-b",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    Some("resp-1"),
                    None,
                )
                .is_empty()
        );
        assert!(
            router
                .routes(
                    "caller",
                    "key-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    Some("unknown"),
                    None,
                )
                .is_empty()
        );
        router.response_bindings().insert(
            ResponseBindingKey {
                routing_scope: "key-a".to_owned(),
                response_id: "expired".to_owned(),
            },
            ResponseBinding {
                account_id: high_b.id.clone(),
                bound_at: Instant::now() - RESPONSE_BINDING_TTL - Duration::from_secs(1),
            },
        );
        assert!(
            router
                .routes(
                    "caller",
                    "key-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    Some("expired"),
                    None,
                )
                .is_empty()
        );
        assert!(router.remove_account(&high_a.id));
        assert!(
            router
                .routes(
                    "caller",
                    "key-a",
                    "shared",
                    &[WireFormat::OpenAiResponses],
                    None,
                    Some("resp-1"),
                    None,
                )
                .is_empty()
        );
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
            input_modalities: None,
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
