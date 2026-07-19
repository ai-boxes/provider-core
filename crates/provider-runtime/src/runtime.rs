use std::{
    collections::{BTreeMap, HashMap},
    hash::{DefaultHasher, Hash, Hasher},
    sync::{Arc, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures_util::StreamExt;
use provider_core::{
    AccountId, Provider, ProviderAccount, ProviderDriver, ProviderError, ProviderErrorKind,
    ProviderModel, ProviderRequest, ProviderStream, RefreshError, RefreshErrorKind, RefreshOutcome,
    RefreshTrigger, WireFormat,
};
use thiserror::Error;
use tokio::{
    sync::{Mutex, RwLock, Semaphore, mpsc},
    task::JoinSet,
};
use tokio_util::{sync::CancellationToken, time::DelayQueue};

const DEFAULT_REFRESH_CONCURRENCY: usize = 4;
const REFRESH_BACKOFF_BASE: Duration = Duration::from_secs(30);
const REFRESH_BACKOFF_MAX: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub struct ProviderRuntime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    driver: Arc<dyn ProviderDriver>,
    accounts: RwLock<BTreeMap<AccountId, Arc<AccountEntry>>>,
    refresh_limit: Arc<Semaphore>,
    scheduler_tx: mpsc::UnboundedSender<SchedulerCommand>,
    cancellation: CancellationToken,
}

struct AccountEntry {
    account: Arc<dyn ProviderAccount>,
    refresh_gate: Mutex<()>,
}

enum SchedulerCommand {
    Reschedule(AccountId),
    Backoff(AccountId),
    Remove(AccountId),
}

#[derive(Debug, Error)]
pub enum ProviderRuntimeError {
    #[error("account provider does not match the runtime provider")]
    ProviderMismatch,
    #[error("provider account is already registered")]
    DuplicateAccount,
    #[error("provider refresh scheduler is not running")]
    SchedulerStopped,
}

impl ProviderRuntime {
    #[must_use]
    pub fn new(driver: Arc<dyn ProviderDriver>) -> Self {
        let (scheduler_tx, scheduler_rx) = mpsc::unbounded_channel();
        let cancellation = CancellationToken::new();
        let inner = Arc::new(RuntimeInner {
            driver,
            accounts: RwLock::new(BTreeMap::new()),
            refresh_limit: Arc::new(Semaphore::new(DEFAULT_REFRESH_CONCURRENCY)),
            scheduler_tx,
            cancellation: cancellation.clone(),
        });

        tokio::spawn(run_scheduler(
            Arc::downgrade(&inner),
            scheduler_rx,
            cancellation,
        ));
        Self { inner }
    }

    pub async fn register(
        &self,
        account: Arc<dyn ProviderAccount>,
    ) -> Result<(), ProviderRuntimeError> {
        if account.provider_name() != self.inner.driver.name() {
            return Err(ProviderRuntimeError::ProviderMismatch);
        }
        let account_id = account.account_id().clone();
        let mut accounts = self.inner.accounts.write().await;
        if accounts.contains_key(&account_id) {
            return Err(ProviderRuntimeError::DuplicateAccount);
        }
        accounts.insert(
            account_id.clone(),
            Arc::new(AccountEntry {
                account,
                refresh_gate: Mutex::new(()),
            }),
        );
        drop(accounts);

        if self
            .inner
            .scheduler_tx
            .send(SchedulerCommand::Reschedule(account_id.clone()))
            .is_err()
        {
            self.inner.accounts.write().await.remove(&account_id);
            return Err(ProviderRuntimeError::SchedulerStopped);
        }
        Ok(())
    }

    pub async fn remove(&self, account_id: &AccountId) -> bool {
        let removed = self
            .inner
            .accounts
            .write()
            .await
            .remove(account_id)
            .is_some();
        if removed {
            let _ = self
                .inner
                .scheduler_tx
                .send(SchedulerCommand::Remove(account_id.clone()));
        }
        removed
    }

    pub fn shutdown(&self) {
        self.inner.cancellation.cancel();
    }

    async fn selected_account(&self) -> Result<Arc<AccountEntry>, ProviderError> {
        let accounts = self.inner.accounts.read().await;
        let available: Vec<_> = accounts
            .values()
            .filter(|entry| entry.account.runtime_state().available_for_requests())
            .cloned()
            .collect();

        match available.as_slice() {
            [account] => Ok(account.clone()),
            [] => Err(ProviderError::new(
                ProviderErrorKind::Authentication,
                "no active provider account is available",
            )),
            _ => Err(ProviderError::new(
                ProviderErrorKind::Internal,
                "multiple active provider accounts require a selection policy",
            )),
        }
    }

    async fn refresh_entry(
        &self,
        entry: &Arc<AccountEntry>,
        expected_generation: u64,
        trigger: RefreshTrigger,
    ) -> Result<RefreshOutcome, RefreshError> {
        let _gate = entry.refresh_gate.lock().await;
        let state = entry.account.runtime_state();
        if state.generation != expected_generation {
            return Ok(RefreshOutcome { state });
        }

        let _permit = self.inner.refresh_limit.acquire().await.map_err(|_| {
            RefreshError::new(RefreshErrorKind::Internal, "refresh runtime stopped")
        })?;
        entry.account.refresh_credentials(trigger).await
    }

    fn report_refresh_result(
        &self,
        account_id: AccountId,
        result: &Result<RefreshOutcome, RefreshError>,
    ) {
        let command = match result {
            Ok(_) => SchedulerCommand::Reschedule(account_id),
            Err(error) if error.kind() == RefreshErrorKind::ReauthRequired => {
                SchedulerCommand::Remove(account_id)
            }
            Err(_) => SchedulerCommand::Backoff(account_id),
        };
        let _ = self.inner.scheduler_tx.send(command);
    }

    async fn account_entry(&self, account_id: &AccountId) -> Option<Arc<AccountEntry>> {
        self.inner.accounts.read().await.get(account_id).cloned()
    }
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[async_trait]
impl Provider for ProviderRuntime {
    fn name(&self) -> &'static str {
        self.inner.driver.name()
    }

    fn native_format(&self) -> WireFormat {
        self.inner.driver.native_format()
    }

    fn models(&self) -> &[ProviderModel] {
        self.inner.driver.models()
    }

    async fn execute_stream(
        &self,
        request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError> {
        let entry = self.selected_account().await?;
        let generation = entry.account.runtime_state().generation;
        let first_request = request.clone();

        match entry.account.execute_stream(first_request).await {
            Err(error) if error.upstream_status() == Some(401) => {
                let account_id = entry.account.account_id().clone();
                let refresh = self
                    .refresh_entry(&entry, generation, RefreshTrigger::Unauthorized)
                    .await;
                self.report_refresh_result(account_id, &refresh);
                refresh.map_err(refresh_provider_error)?;
                entry.account.execute_stream(request).await
            }
            result => result,
        }
    }

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError> {
        self.selected_account()
            .await?
            .account
            .count_tokens(request)
            .await
    }
}

fn refresh_provider_error(error: RefreshError) -> ProviderError {
    let kind = match error.kind() {
        RefreshErrorKind::ReauthRequired => ProviderErrorKind::Authentication,
        RefreshErrorKind::Transient => ProviderErrorKind::Upstream,
        RefreshErrorKind::Internal => ProviderErrorKind::Internal,
    };
    ProviderError::new(kind, error.message())
}

async fn run_scheduler(
    runtime: Weak<RuntimeInner>,
    mut commands: mpsc::UnboundedReceiver<SchedulerCommand>,
    cancellation: CancellationToken,
) {
    let mut queue = DelayQueue::new();
    let mut keys = HashMap::new();
    let mut failures = HashMap::<AccountId, u32>::new();
    let mut refreshes = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    SchedulerCommand::Reschedule(account_id) => {
                        failures.remove(&account_id);
                        schedule_account(&runtime, &mut queue, &mut keys, account_id).await;
                    }
                    SchedulerCommand::Backoff(account_id) => {
                        let attempts = failures.entry(account_id.clone()).or_default();
                        *attempts = attempts.saturating_add(1);
                        schedule_after(&mut queue, &mut keys, account_id.clone(), refresh_backoff(&account_id, *attempts));
                    }
                    SchedulerCommand::Remove(account_id) => {
                        failures.remove(&account_id);
                        remove_schedule(&mut queue, &mut keys, &account_id);
                    }
                }
            }
            Some(expired) = queue.next(), if !queue.is_empty() => {
                let account_id = expired.into_inner();
                keys.remove(&account_id);
                if let Some(inner) = runtime.upgrade() {
                    let provider_runtime = ProviderRuntime { inner };
                    if let Some(entry) = provider_runtime.account_entry(&account_id).await {
                        let generation = entry.account.runtime_state().generation;
                        refreshes.spawn(async move {
                            let result = provider_runtime
                                .refresh_entry(&entry, generation, RefreshTrigger::Scheduled)
                                .await;
                            (account_id, result)
                        });
                    }
                }
            }
            Some(result) = refreshes.join_next(), if !refreshes.is_empty() => {
                if let Ok((account_id, refresh)) = result {
                    match refresh {
                        Ok(_) => {
                            failures.remove(&account_id);
                            schedule_account(&runtime, &mut queue, &mut keys, account_id).await;
                        }
                        Err(error) if error.kind() == RefreshErrorKind::ReauthRequired => {
                            failures.remove(&account_id);
                            remove_schedule(&mut queue, &mut keys, &account_id);
                        }
                        Err(_) => {
                            let attempts = failures.entry(account_id.clone()).or_default();
                            *attempts = attempts.saturating_add(1);
                            let delay = refresh_backoff(&account_id, *attempts);
                            schedule_after(&mut queue, &mut keys, account_id, delay);
                        }
                    }
                }
            }
        }
    }

    refreshes.abort_all();
}

async fn schedule_account(
    runtime: &Weak<RuntimeInner>,
    queue: &mut DelayQueue<AccountId>,
    keys: &mut HashMap<AccountId, tokio_util::time::delay_queue::Key>,
    account_id: AccountId,
) {
    let Some(inner) = runtime.upgrade() else {
        return;
    };
    let account = inner.accounts.read().await.get(&account_id).cloned();
    let Some(account) = account else {
        remove_schedule(queue, keys, &account_id);
        return;
    };
    let state = account.account.runtime_state();
    let Some(refresh_at) = state.next_refresh_at else {
        remove_schedule(queue, keys, &account_id);
        return;
    };
    schedule_after(queue, keys, account_id, delay_until(refresh_at));
}

fn schedule_after(
    queue: &mut DelayQueue<AccountId>,
    keys: &mut HashMap<AccountId, tokio_util::time::delay_queue::Key>,
    account_id: AccountId,
    delay: Duration,
) {
    if let Some(key) = keys.get(&account_id) {
        queue.reset(key, delay);
        return;
    }
    let key = queue.insert(account_id.clone(), delay);
    keys.insert(account_id, key);
}

fn remove_schedule(
    queue: &mut DelayQueue<AccountId>,
    keys: &mut HashMap<AccountId, tokio_util::time::delay_queue::Key>,
    account_id: &AccountId,
) {
    if let Some(key) = keys.remove(account_id) {
        queue.remove(&key);
    }
}

fn delay_until(timestamp: i64) -> Duration {
    let now = unix_timestamp();
    if timestamp <= now {
        Duration::ZERO
    } else {
        Duration::from_secs(u64::try_from(timestamp - now).unwrap_or_default())
    }
}

fn refresh_backoff(account_id: &AccountId, attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(4);
    let factor = 1_u32 << exponent;
    let base = REFRESH_BACKOFF_BASE
        .saturating_mul(factor)
        .min(REFRESH_BACKOFF_MAX);
    let mut hasher = DefaultHasher::new();
    account_id.hash(&mut hasher);
    let jitter = Duration::from_secs(hasher.finish() % 16);
    base.saturating_add(jitter)
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use futures_util::stream;
    use provider_core::{AccountAuthState, AccountRuntimeState, RefreshOutcome, RequestMetadata};
    use tokio::sync::{Barrier, Notify};

    use super::*;

    struct UnauthorizedAccount {
        id: AccountId,
        generation: AtomicU64,
        refresh_calls: AtomicU64,
        execute_calls: AtomicU64,
        unauthorized_calls: AtomicU64,
        initial_requests: Barrier,
        unauthorized_ready: Notify,
        refresh_started: Notify,
        release_refresh: Notify,
    }

    struct TestDriver;

    impl ProviderDriver for TestDriver {
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

    #[async_trait]
    impl ProviderAccount for UnauthorizedAccount {
        fn provider_name(&self) -> &'static str {
            "test"
        }

        fn account_id(&self) -> &AccountId {
            &self.id
        }

        fn runtime_state(&self) -> AccountRuntimeState {
            AccountRuntimeState {
                generation: self.generation.load(Ordering::SeqCst),
                next_refresh_at: (self.generation.load(Ordering::SeqCst) == 0).then_some(0),
                auth_state: AccountAuthState::Active,
                persistence_pending: false,
            }
        }

        async fn execute_stream(
            &self,
            _request: ProviderRequest,
        ) -> Result<ProviderStream, ProviderError> {
            self.execute_calls.fetch_add(1, Ordering::SeqCst);
            if self.generation.load(Ordering::SeqCst) == 0 {
                self.initial_requests.wait().await;
                if self.unauthorized_calls.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
                    self.unauthorized_ready.notify_one();
                }
                return Err(ProviderError::new(
                    ProviderErrorKind::Authentication,
                    "upstream returned unauthorized",
                )
                .with_upstream_status(401));
            }
            Ok(Box::pin(stream::empty()))
        }

        async fn count_tokens(&self, _request: ProviderRequest) -> Result<u64, ProviderError> {
            Ok(0)
        }

        async fn refresh_credentials(
            &self,
            _trigger: RefreshTrigger,
        ) -> Result<RefreshOutcome, RefreshError> {
            self.refresh_calls.fetch_add(1, Ordering::SeqCst);
            self.refresh_started.notify_one();
            self.release_refresh.notified().await;
            self.generation.fetch_add(1, Ordering::SeqCst);
            Ok(RefreshOutcome {
                state: self.runtime_state(),
            })
        }
    }

    #[tokio::test]
    async fn background_and_unauthorized_requests_share_one_refresh() {
        let account = Arc::new(UnauthorizedAccount {
            id: AccountId::new("test-account").expect("valid account ID"),
            generation: AtomicU64::new(0),
            refresh_calls: AtomicU64::new(0),
            execute_calls: AtomicU64::new(0),
            unauthorized_calls: AtomicU64::new(0),
            initial_requests: Barrier::new(2),
            unauthorized_ready: Notify::new(),
            refresh_started: Notify::new(),
            release_refresh: Notify::new(),
        });
        let runtime = ProviderRuntime::new(Arc::new(TestDriver));
        runtime
            .register(account.clone())
            .await
            .expect("register account");
        account.refresh_started.notified().await;
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "test-model".to_owned(),
            payload: Default::default(),
            metadata: RequestMetadata::default(),
        };

        let request_runtime = runtime.clone();
        let requests = tokio::spawn(async move {
            tokio::join!(
                request_runtime.execute_stream(request.clone()),
                request_runtime.execute_stream(request)
            )
        });
        account.unauthorized_ready.notified().await;
        account.release_refresh.notify_one();
        let (first, second) = requests.await.expect("request task");
        runtime.shutdown();

        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(account.refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(account.generation.load(Ordering::SeqCst), 1);
        assert_eq!(account.execute_calls.load(Ordering::SeqCst), 4);
    }
}
