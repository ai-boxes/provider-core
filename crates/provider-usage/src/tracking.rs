//! Per-request tracking state: the in-memory reducer between the layers that
//! observe facts and the bounded writer that persists them.
//!
//! Everything about one logical request happens inside one process, so this needs
//! no event log, no versioned event stream and no idempotency keys. What it does
//! need is to be safe to touch from two places at once — the runtime, which knows
//! about dispatch, and the response stream, which knows when the response actually
//! ended — and to commit each terminal exactly once.
//!
//! Two rules the type system cannot express, both covered by tests:
//!
//! 1. Dispatch evidence only ever moves forward. Observing a response cannot be
//!    undone by a later "not invoked", or an attempt would claim less than it can
//!    prove.
//! 2. A terminal is committed once. A stream that ends and is then dropped must
//!    not write two attempts, which would double-count upstream usage.

use std::sync::{Arc, Mutex, MutexGuard};

use provider_core::{
    ProviderFailoverReason, ProviderKind, ProviderModelPricingRecord,
    usage::{
        AttemptTracking, NormalizationWarning, ProviderUsageProfile, RawUsageFields,
        RequestTracking, UsageContractSnapshot, normalize_usage,
    },
};

use crate::{
    attempt::{AttemptSequence, DispatchEvidence, TrackingGapReason, TrackingState},
    catalog::{component_prices_from_model_pricing, context_price_tiers_from_model_pricing},
    cost::{CostStatus, ObservedCatalogCost, compute_observed_catalog_cost},
    lifecycle::{DeliveryOutcome, ExecutionOutcome, merge_logical_terminal},
    price::{InlinePriceRecord, ModelInlinePriceRecordV2, PriceResolution},
    repository::{
        AttemptFacts, AttemptFailoverReason, AttemptOutcome, LogicalRequestStart,
        LogicalRequestTerminal, LogicalWriteOutcome, UsageRepository, UsageRepositoryError,
    },
    writer::{
        QuotaLedgerPermit, QuotaLedgerReceipt, QuotaLedgerWriter, UsageFact, UsageWrite,
        UsageWriter,
    },
};

/// Wall-clock source. A function pointer rather than a trait object: the only
/// thing needed is "now in unix milliseconds", and tests want to pin it.
pub type ClockMs = fn() -> i64;

/// Reads the system clock as unix milliseconds.
#[must_use]
pub fn system_clock_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after unix epoch")
        .as_millis()
        .try_into()
        .expect("unix timestamp must fit i64")
}

/// Entry point held by the server and the runtime.
pub struct UsageTracking {
    repository: Arc<dyn UsageRepository>,
    writer: Arc<UsageWriter>,
    quota_writer: Option<Arc<QuotaLedgerWriter>>,
    now_ms: ClockMs,
}

impl UsageTracking {
    #[must_use]
    pub fn new(repository: Arc<dyn UsageRepository>, writer: Arc<UsageWriter>) -> Self {
        Self::with_clock_and_quota_writer(repository, writer, None, system_clock_ms)
    }

    #[must_use]
    pub fn with_quota_writer(
        repository: Arc<dyn UsageRepository>,
        writer: Arc<UsageWriter>,
        quota_writer: Arc<QuotaLedgerWriter>,
    ) -> Self {
        Self::with_clock_and_quota_writer(repository, writer, Some(quota_writer), system_clock_ms)
    }

    #[must_use]
    pub fn with_clock(
        repository: Arc<dyn UsageRepository>,
        writer: Arc<UsageWriter>,
        now_ms: ClockMs,
    ) -> Self {
        Self::with_clock_and_quota_writer(repository, writer, None, now_ms)
    }

    #[must_use]
    fn with_clock_and_quota_writer(
        repository: Arc<dyn UsageRepository>,
        writer: Arc<UsageWriter>,
        quota_writer: Option<Arc<QuotaLedgerWriter>>,
        now_ms: ClockMs,
    ) -> Self {
        Self {
            repository,
            writer,
            quota_writer,
            now_ms,
        }
    }

    /// Persist the start of a logical request and return its tracker.
    ///
    /// This is the only tracking write on the request path, and it is fail-open:
    /// a database problem produces a gap-marked tracker, never an error the
    /// client could see.
    pub async fn begin_request(&self, start: LogicalRequestStart) -> Arc<LogicalTracker> {
        let start_gap = match self.repository.begin_logical_request(&start).await {
            Ok(LogicalWriteOutcome::Written | LogicalWriteOutcome::AlreadyKnown) => None,
            // The row is missing, so the terminal will have nothing to update.
            // Recording that now keeps the eventual gap honest about its cause.
            Ok(LogicalWriteOutcome::MissingRequest) | Err(_) => {
                Some(TrackingGapReason::WriteFailed)
            }
        };
        self.tracker(start, start_gap, None)
    }

    /// Begin a finite-quota request on the fail-closed accounting path.
    ///
    /// Queue capacity is acquired before the durable claim is created, so every
    /// admitted claim has an unsheddable route to settlement. The database
    /// stores the logical start and claim in one transaction.
    pub async fn begin_quota_request(
        &self,
        start: LogicalRequestStart,
    ) -> Result<Arc<LogicalTracker>, UsageRepositoryError> {
        let quota_writer = self
            .quota_writer
            .as_ref()
            .ok_or_else(|| UsageRepositoryError::new("quota ledger writer is unavailable"))?;
        let permit = quota_writer
            .reserve()
            .await
            .ok_or_else(|| UsageRepositoryError::new("quota ledger writer is unavailable"))?;
        self.repository.begin_quota_request(&start).await?;
        Ok(self.tracker(start, None, Some(permit)))
    }

    fn tracker(
        &self,
        start: LogicalRequestStart,
        start_gap: Option<TrackingGapReason>,
        quota_permit: Option<QuotaLedgerPermit>,
    ) -> Arc<LogicalTracker> {
        Arc::new(LogicalTracker {
            start,
            repository: Arc::clone(&self.repository),
            writer: Arc::clone(&self.writer),
            now_ms: self.now_ms,
            state: Mutex::new(LogicalState {
                start_gap,
                next_sequence: 1,
                final_attempt_id: None,
                final_attempt_sequence: None,
                final_attempt_execution: None,
                execution: None,
                delivery: None,
                quota_permit,
                quota_atoms: 0,
                quota_dispatched: false,
                quota_has_complete_cost: false,
                quota_attempts: Vec::new(),
                finished: false,
            }),
        })
    }

    #[must_use]
    pub fn quota_ledger_ready(&self) -> bool {
        self.quota_writer
            .as_ref()
            .is_none_or(|writer| writer.is_ready())
    }
}

/// What an attempt needs to know before it is dispatched. Everything here is
/// decided in memory: the contract is a per-provider constant and the price comes
/// from the catalog snapshot held at this moment, never re-read at completion.
#[derive(Clone, Debug)]
pub struct AttemptSpec {
    pub provider: ProviderKind,
    pub account_id: String,
    /// The model the attempt was prepared for.
    pub configured_model: Option<String>,
    pub contract: UsageContractSnapshot,
    pub price: PriceResolution,
}

struct LogicalState {
    start_gap: Option<TrackingGapReason>,
    next_sequence: u32,
    final_attempt_id: Option<String>,
    final_attempt_sequence: Option<AttemptSequence>,
    /// The upstream outcome of the final attempt. Kept separate from `execution`
    /// so a first attempt that a retry replaced cannot decide the logical status.
    final_attempt_execution: Option<ExecutionOutcome>,
    execution: Option<ExecutionOutcome>,
    delivery: Option<DeliveryOutcome>,
    quota_permit: Option<QuotaLedgerPermit>,
    quota_atoms: i128,
    quota_dispatched: bool,
    quota_has_complete_cost: bool,
    quota_attempts: Vec<AttemptFacts>,
    finished: bool,
}

pub struct LogicalTracker {
    start: LogicalRequestStart,
    repository: Arc<dyn UsageRepository>,
    writer: Arc<UsageWriter>,
    now_ms: ClockMs,
    state: Mutex<LogicalState>,
}

impl Drop for LogicalTracker {
    fn drop(&mut self) {
        // If the handler is cancelled before a response body exists, there is no
        // delivery wrapper left to close the logical request. Treat that path as
        // a client drop and let finish's idempotence protect normal terminals.
        let should_finish = {
            let mut state = self.lock();
            if state.finished {
                false
            } else {
                if state.delivery.is_none() {
                    state.delivery = Some(DeliveryOutcome::ClientDrop);
                }
                true
            }
        };
        if should_finish {
            let _ = self.finish();
        }
    }
}

impl LogicalTracker {
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.start.request_id
    }

    #[must_use]
    pub fn owner_user_id(&self) -> &str {
        &self.start.owner_user_id
    }

    /// The handle to pass down through the execution layers, so the code that
    /// actually makes upstream calls can open an attempt per call.
    #[must_use]
    pub fn request_tracking(self: &Arc<Self>) -> Arc<dyn RequestTracking> {
        Arc::new(RequestTrackingHandle(Arc::clone(self)))
    }

    /// Persist the dispatch boundary before the upstream can be invoked.
    pub async fn mark_quota_dispatched(&self) -> Result<(), UsageRepositoryError> {
        self.repository
            .mark_quota_request_dispatched(&self.start.request_id, (self.now_ms)())
            .await?;
        self.lock().quota_dispatched = true;
        Ok(())
    }

    /// Allocate the next attempt. Nothing is persisted yet; an attempt is written
    /// once, after its response reaches a terminal state.
    pub fn open_attempt(self: &Arc<Self>, spec: AttemptSpec) -> Arc<AttemptTracker> {
        let (attempt_id, sequence) = {
            let mut state = self.lock();
            let sequence = state.next_sequence;
            state.next_sequence = sequence.saturating_add(1);
            // Derived rather than random: unique within the request, stable, and
            // readable in a details view without another identifier to resolve.
            (format!("{}#{sequence}", self.start.request_id), sequence)
        };

        Arc::new(AttemptTracker {
            logical: Arc::clone(self),
            attempt_id,
            sequence: AttemptSequence(sequence),
            spec,
            started_at_ms: (self.now_ms)(),
            state: Mutex::new(AttemptState {
                evidence: DispatchEvidence::NotInvoked,
                raw_usage: None,
                provider_reported_model: None,
                first_token_at_ms: None,
                tracking: TrackingState::Complete,
                success_terminal: false,
                outcome: None,
                failover_reason: None,
                closed: false,
            }),
        })
    }

    /// Record how the upstream side ended. The first outcome wins: a later event
    /// cannot rewrite a terminal that was already decided.
    pub fn record_execution(&self, outcome: ExecutionOutcome) {
        let mut state = self.lock();
        if state.execution.is_none() {
            state.execution = Some(outcome);
        }
    }

    /// Record how the downstream delivery ended. First outcome wins, for the
    /// same reason.
    pub fn record_delivery(&self, outcome: DeliveryOutcome) {
        let mut state = self.lock();
        if state.delivery.is_none() {
            state.delivery = Some(outcome);
        }
    }

    /// Commit the logical terminal, exactly once.
    ///
    /// Safe to call from both the normal end of a response and a drop; only the
    /// first call writes.
    pub fn finish(&self) -> Option<QuotaLedgerReceipt> {
        let (terminal, quota) = {
            let mut state = self.lock();
            if state.finished {
                return None;
            }
            state.finished = true;

            // An explicitly reported outcome wins; otherwise the final attempt's
            // upstream outcome is the logical one. With neither, nothing is known,
            // and an unknown outcome is `incomplete` rather than a success.
            let execution = state
                .execution
                .or(state.final_attempt_execution)
                .unwrap_or(ExecutionOutcome::EofWithoutSuccessTerminal);
            let delivery = state.delivery.unwrap_or(DeliveryOutcome::Unknown);
            let terminal = LogicalRequestTerminal {
                request_id: self.start.request_id.clone(),
                completed_at_ms: (self.now_ms)(),
                status: merge_logical_terminal(execution, delivery),
                execution: Some(execution),
                delivery: Some(delivery),
                final_attempt_id: state.final_attempt_id.clone(),
                tracking: match state.start_gap {
                    Some(reason) => TrackingState::Gap { reason },
                    None => TrackingState::Complete,
                },
                // The start row is version 0, so any terminal is newer.
                state_version: 1,
            };
            let quota = state.quota_permit.take().map(|permit| {
                let entry = crate::repository::QuotaLedgerEntry {
                    entry_id: self.start.request_id.clone(),
                    api_key_id: self
                        .start
                        .api_key_id
                        .clone()
                        .expect("a reserved quota entry must belong to an API key"),
                    dispatched: state.quota_dispatched,
                    cost_atoms: (state.quota_dispatched && state.quota_has_complete_cost)
                        .then(|| state.quota_atoms.to_string()),
                    resolved_at_ms: terminal.completed_at_ms,
                    attempts: std::mem::take(&mut state.quota_attempts),
                };
                (permit, entry)
            });
            (terminal, quota)
        };

        let receipt = quota.map(|(permit, entry)| permit.submit(entry));

        self.writer.submit(UsageWrite {
            owner_user_id: self.start.owner_user_id.clone(),
            at_ms: terminal.completed_at_ms,
            fact: UsageFact::LogicalTerminal(terminal),
        });
        receipt
    }

    /// The highest-numbered attempt is the one the user's response came from, so
    /// pick by sequence rather than by close order: a retry that finishes out of
    /// order must not demote the attempt that actually served the response.
    fn note_final_attempt(
        &self,
        attempt_id: &str,
        sequence: AttemptSequence,
        execution: ExecutionOutcome,
    ) {
        let mut state = self.lock();
        if state
            .final_attempt_sequence
            .is_none_or(|best| sequence > best)
        {
            state.final_attempt_sequence = Some(sequence);
            state.final_attempt_id = Some(attempt_id.to_owned());
            state.final_attempt_execution = Some(execution);
        }
    }

    fn note_quota_result(&self, facts: &AttemptFacts) {
        let mut state = self.lock();
        if !facts.dispatch_evidence.is_confirmed_dispatch() {
            return;
        }
        state.quota_dispatched = true;
        if state.quota_permit.is_some() {
            state.quota_attempts.push(facts.clone());
        }
        if matches!(
            facts.cost.status,
            CostStatus::CompleteForObservedCatalogComponents
        ) {
            state.quota_has_complete_cost = true;
            state.quota_atoms = state
                .quota_atoms
                .checked_add(facts.cost.total_known.as_atoms())
                .expect("finite quota cost total must fit i128");
        }
    }

    /// A poisoned lock must not take down a proxy request, so recover the guard
    /// and keep going: worst case a fact is slightly stale, which is a gap-level
    /// concern, not a reason to fail a response.
    fn lock(&self) -> MutexGuard<'_, LogicalState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
}

struct AttemptState {
    evidence: DispatchEvidence,
    /// `None` until the response reported; `Some(None)` means it ended without
    /// usage, which is unknown rather than zero.
    raw_usage: Option<Option<RawUsageFields>>,
    provider_reported_model: Option<String>,
    first_token_at_ms: Option<i64>,
    tracking: TrackingState,
    /// Whether the upstream stream reached its documented successful terminal.
    success_terminal: bool,
    outcome: Option<AttemptOutcome>,
    failover_reason: Option<AttemptFailoverReason>,
    closed: bool,
}

pub struct AttemptTracker {
    logical: Arc<LogicalTracker>,
    attempt_id: String,
    sequence: AttemptSequence,
    spec: AttemptSpec,
    started_at_ms: i64,
    state: Mutex<AttemptState>,
}

impl AttemptTracker {
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Record the model the provider said it used, when it says anything.
    pub fn record_provider_model(&self, model: impl Into<String>) {
        let mut state = self.lock();
        if state.provider_reported_model.is_none() {
            state.provider_reported_model = Some(model.into());
        }
    }

    /// Record the raw usage the response carried. `None` means the response ended
    /// without usage — which is the provider reporting nothing, not a failure to
    /// look. For the latter, use [`Self::mark_observation_lost`].
    pub fn record_usage(&self, raw: Option<RawUsageFields>) {
        let mut state = self.lock();
        if state.raw_usage.is_none() {
            state.raw_usage = Some(raw);
        }
    }

    /// Record the first output token only once. The observer calls this while
    /// the response is still flowing, so the timestamp is measured before the
    /// terminal usage write rather than reconstructed from completion time.
    pub fn first_token_observed(&self) {
        let mut state = self.lock();
        if state.first_token_at_ms.is_none() {
            state.first_token_at_ms = Some((self.logical.now_ms)());
        }
    }

    /// The response could not be inspected, so its usage was never seen.
    ///
    /// Without this the attempt would store "the provider reported no usage",
    /// which is a different — and false — claim. Recording a gap says the absence
    /// is ours.
    pub fn mark_observation_lost(&self) {
        let mut state = self.lock();
        state.tracking = TrackingState::Gap {
            reason: TrackingGapReason::ObservationLost,
        };
    }

    pub fn cancel(&self, raw: Option<RawUsageFields>) {
        {
            let mut state = self.lock();
            if state.raw_usage.is_none() {
                state.raw_usage = Some(raw);
            }
            if matches!(state.tracking, TrackingState::Complete) {
                state.tracking = TrackingState::Gap {
                    reason: TrackingGapReason::AmbiguousCancel,
                };
            }
            state.outcome = Some(AttemptOutcome::Cancelled);
        }
        self.close();
    }

    /// What this attempt proved about the upstream side.
    ///
    /// Derived from evidence rather than reported, so it can never claim a success
    /// the response did not demonstrate.
    fn execution_outcome(state: &AttemptState) -> ExecutionOutcome {
        if !state.evidence.is_confirmed_dispatch() {
            // Nothing was sent, so the request definitively did not succeed.
            return ExecutionOutcome::StableFailure;
        }
        if state.success_terminal {
            ExecutionOutcome::StableSuccessTerminal
        } else {
            // The stream ended, but nothing proved it ended the way it should.
            ExecutionOutcome::EofWithoutSuccessTerminal
        }
    }

    /// Normalize, price and submit this attempt, exactly once.
    pub fn close(&self) {
        let (facts, execution) = {
            let mut state = self.lock();
            if state.closed {
                return;
            }
            state.closed = true;

            let mut observation =
                normalize_usage(state.raw_usage.take().flatten(), &self.spec.contract);
            if model_disagrees(
                self.spec.provider,
                self.spec.configured_model.as_deref(),
                state.provider_reported_model.as_deref(),
            ) && !observation
                .warnings
                .contains(&NormalizationWarning::ProviderModelMismatch)
            {
                // The price carried by this attempt was resolved for the
                // configured model, so a different served model makes the
                // estimate an estimate of the wrong thing. Recorded as a warning,
                // which turns the cost `partial` rather than presenting a number
                // that looks complete.
                observation
                    .warnings
                    .push(NormalizationWarning::ProviderModelMismatch);
            }
            // Nothing was sent, so nothing was metered and nothing can be
            // priced. Running the calculator here would report a shortfall
            // instead of the correct answer, which is that no call was made.
            let cost = if matches!(state.evidence, DispatchEvidence::NotInvoked) {
                ObservedCatalogCost::not_dispatched()
            } else {
                compute_observed_catalog_cost(&observation, &self.spec.contract, &self.spec.price)
            };

            let facts = AttemptFacts {
                attempt_id: self.attempt_id.clone(),
                logical_request_id: self.logical.start.request_id.clone(),
                sequence: self.sequence,
                provider: self.spec.provider,
                account_id: self.spec.account_id.clone(),
                configured_model: self.spec.configured_model.clone(),
                provider_reported_model: state.provider_reported_model.clone(),
                started_at_ms: self.started_at_ms,
                first_token_at_ms: state.first_token_at_ms,
                completed_at_ms: (self.logical.now_ms)(),
                outcome: Some(state.outcome.unwrap_or_else(|| {
                    if state.success_terminal {
                        AttemptOutcome::Succeeded
                    } else {
                        AttemptOutcome::Failed
                    }
                })),
                failover_reason: state.failover_reason,
                dispatch_evidence: state.evidence,
                tracking: state.tracking,
                contract: self.spec.contract,
                observation,
                price: self.spec.price.clone(),
                cost,
            };
            (facts, Self::execution_outcome(&state))
        };

        self.logical
            .note_final_attempt(&self.attempt_id, self.sequence, execution);
        self.logical.note_quota_result(&facts);
        self.logical.writer.submit(UsageWrite {
            owner_user_id: self.logical.start.owner_user_id.clone(),
            at_ms: facts.completed_at_ms,
            fact: UsageFact::Attempt(Box::new(facts)),
        });
    }

    /// Evidence only moves forward: an attempt must never claim less than it can
    /// already prove.
    fn advance(&self, evidence: DispatchEvidence) {
        let mut state = self.lock();
        if rank(evidence) > rank(state.evidence) {
            state.evidence = evidence;
        }
    }

    fn lock(&self) -> MutexGuard<'_, AttemptState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl Drop for AttemptTracker {
    fn drop(&mut self) {
        // A tracker dropped without closing means the task was cancelled while
        // the call was in flight. Whether the request reached the upstream is
        // genuinely unprovable, so the attempt is recorded with a gap rather than
        // silently vanishing or claiming an evidence level it cannot support.
        let unclosed = {
            let mut state = self.lock();
            if state.closed {
                false
            } else {
                state.tracking = TrackingState::Gap {
                    reason: TrackingGapReason::AmbiguousCancel,
                };
                state.outcome = Some(AttemptOutcome::Cancelled);
                true
            }
        };
        if unclosed {
            self.close();
        }
    }
}

/// Adapts a [`LogicalTracker`] to the `provider-core` seam that the execution
/// layers see. It exists only because opening an attempt needs a shared handle to
/// the request, which a bare `&self` trait method cannot provide.
struct RequestTrackingHandle(Arc<LogicalTracker>);

impl RequestTracking for RequestTrackingHandle {
    fn begin_attempt(
        &self,
        profile: ProviderUsageProfile,
        account_id: &str,
        configured_model: Option<&str>,
        pricing: Option<&ProviderModelPricingRecord>,
    ) -> Option<Arc<dyn AttemptTracking>> {
        let price = model_price_resolution(pricing);
        Some(self.0.open_attempt(AttemptSpec {
            provider: profile.provider,
            account_id: account_id.to_owned(),
            configured_model: configured_model.map(ToOwned::to_owned),
            contract: profile.contract,
            price,
        }))
    }
}

fn model_price_resolution(pricing: Option<&ProviderModelPricingRecord>) -> PriceResolution {
    let Some(pricing) = pricing else {
        return PriceResolution::ModelMappingMissing;
    };
    let Some(prices) = component_prices_from_model_pricing(&pricing.pricing) else {
        return PriceResolution::CatalogEntryInvalid;
    };
    let Some(tiers) = context_price_tiers_from_model_pricing(&pricing.pricing) else {
        return PriceResolution::CatalogEntryInvalid;
    };
    PriceResolution::Resolved(Box::new(InlinePriceRecord::ModelV2(
        ModelInlinePriceRecordV2 {
            format_version: 2,
            source: pricing.source,
            prices,
            tiers,
        },
    )))
}

impl AttemptTracking for AttemptTracker {
    fn stream_opened(&self) {
        // A stream to read is proof the provider answered.
        self.advance(DispatchEvidence::ResponseObserved);
    }

    fn first_token_observed(&self) {
        AttemptTracker::first_token_observed(self);
    }

    fn success_terminal_observed(&self) {
        self.lock().success_terminal = true;
    }

    fn provider_model_observed(&self, model: &str) {
        self.record_provider_model(model);
    }

    fn observation_lost(&self) {
        self.mark_observation_lost();
    }

    fn finished(&self, fields: Option<RawUsageFields>) {
        self.record_usage(fields);
        self.close();
    }

    fn cancelled(&self, fields: Option<RawUsageFields>) {
        self.cancel(fields);
    }

    fn failed(&self, answered: bool) {
        self.fail(answered, None);
    }

    fn failed_with_reason(&self, answered: bool, failover_reason: ProviderFailoverReason) {
        self.fail(answered, Some(failover_reason));
    }
}

impl AttemptTracker {
    fn fail(&self, answered: bool, failover_reason: Option<ProviderFailoverReason>) {
        self.advance(if answered {
            DispatchEvidence::ResponseObserved
        } else {
            // The send was attempted, but nothing proves the provider received it.
            DispatchEvidence::DispatchInvoked
        });
        {
            let mut state = self.lock();
            state.outcome = Some(AttemptOutcome::Failed);
            state.failover_reason = failover_reason.map(map_failover_reason);
        }
        self.close();
    }
}

const fn map_failover_reason(reason: ProviderFailoverReason) -> AttemptFailoverReason {
    match reason {
        ProviderFailoverReason::AuthenticationExhausted => {
            AttemptFailoverReason::AuthenticationExhausted
        }
        ProviderFailoverReason::QuotaExhausted => AttemptFailoverReason::QuotaExhausted,
        ProviderFailoverReason::RateLimited => AttemptFailoverReason::RateLimited,
        ProviderFailoverReason::PreconnectFailure => AttemptFailoverReason::PreconnectFailure,
    }
}

/// Whether the provider's own answer contradicts the model this attempt was
/// priced for.
///
/// The observed Codex terminals name the model exactly as it was requested, with
/// no dated snapshot suffix, so there is no evidenced normalization to apply. If a
/// provider does start answering with a decorated name this fires on every attempt
/// and those costs turn `partial` with a `model_mismatch` reason — visible and
/// self-explaining, since the recorded name says what happened.
///
/// Comparing literally can only ever over-report, never miss a substitution,
/// which is the right way round: a false alarm names the model that caused it and
/// still keeps the computed amount, whereas a tolerant rule would wave through
/// exactly the swaps worth catching (`gpt-5` answered by `gpt-5-mini` is a prefix
/// match and a real price difference).
///
/// Trimmed on both sides because drivers trim the model before sending it, so
/// whitespace a client happened to include is not a disagreement. An unnamed
/// model on either side is an absence, not a disagreement.
fn model_disagrees(
    provider: ProviderKind,
    configured: Option<&str>,
    reported: Option<&str>,
) -> bool {
    matches!(
        (configured, reported),
        (Some(configured), Some(reported))
            if !reported_model_matches(provider, configured.trim(), reported.trim())
    )
}

fn reported_model_matches(provider: ProviderKind, configured: &str, reported: &str) -> bool {
    configured == reported
        || (matches!(provider, ProviderKind::Grok)
            && reported.strip_suffix("-build") == Some(configured))
}

#[cfg(test)]
mod reported_model_tests {
    use super::reported_model_matches;
    use provider_core::ProviderKind;

    #[test]
    fn grok_build_suffix_is_the_same_reported_model() {
        assert!(reported_model_matches(
            ProviderKind::Grok,
            "grok-4.5",
            "grok-4.5-build",
        ));
        assert!(!reported_model_matches(
            ProviderKind::Codex,
            "gpt-5",
            "gpt-5-build",
        ));
        assert!(!reported_model_matches(
            ProviderKind::Grok,
            "grok-4.5",
            "grok-4.5-mini-build",
        ));
    }
}

const fn rank(evidence: DispatchEvidence) -> u8 {
    match evidence {
        DispatchEvidence::NotInvoked => 0,
        DispatchEvidence::DispatchInvoked => 1,
        DispatchEvidence::ResponseObserved => 2,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use provider_core::usage::{
        CacheCapability, CacheEligibility, CacheReportingExpectation, PricingContextBasis,
        PricingMode, TokenInclusionRules, TotalSource,
    };

    use super::*;
    use crate::{
        attempt::LogicalStatus,
        cost::{CostReason, CostStatus},
        money::{PRICE_SCALE, UnitPrice},
        price::{CatalogInlinePriceRecordV1, ComponentPrices, InlinePriceRecord},
        writer::DEFAULT_WRITE_QUEUE,
    };

    /// A clock that advances one millisecond per read, so started/completed times
    /// are distinguishable without a real sleep.
    fn ticking_clock() -> i64 {
        use std::sync::atomic::{AtomicI64, Ordering};
        static NOW: AtomicI64 = AtomicI64::new(1_700_000_000_000);
        NOW.fetch_add(1, Ordering::Relaxed)
    }

    fn codex_contract() -> UsageContractSnapshot {
        UsageContractSnapshot {
            contract_version: 1,
            normalization_version: 1,
            inclusion: TokenInclusionRules {
                input_includes_cache: true,
                input_categories_mutually_exclusive: false,
                reasoning_included_in_output: true,
                reasoning_applicable: true,
                audio_applicable: false,
                cache_write_applicable: false,
                missing_cache_read_means_zero: false,
                total_source: TotalSource::Reported,
            },
            cache_capability: CacheCapability::Supported,
            cache_eligibility: CacheEligibility::Eligible,
            cache_reporting_expectation: CacheReportingExpectation::Expected,
            pricing_context_basis: PricingContextBasis::EffectiveInput,
            pricing_mode: PricingMode::Default,
        }
    }

    fn priced() -> PriceResolution {
        let per_million = 10i128.pow(PRICE_SCALE);
        PriceResolution::Resolved(Box::new(InlinePriceRecord::CatalogV1(
            CatalogInlinePriceRecordV1 {
                format_version: 1,
                parser_version: 1,
                catalog_revision: "a".repeat(64),
                catalog_provider_id: "openai".to_owned(),
                catalog_model_id: "gpt-5-codex".to_owned(),
                mapping_revision: 1,
                prices: ComponentPrices {
                    uncached_input_per_million: Some(UnitPrice::from_scaled(per_million)),
                    cache_read_per_million: Some(UnitPrice::from_scaled(per_million / 10)),
                    output_per_million: Some(UnitPrice::from_scaled(10 * per_million)),
                    ..ComponentPrices::default()
                },
                context_tier: None,
                selected_tier: None,
                unmodeled_billable_component: false,
                unmodeled_pricing_rule: false,
            },
        )))
    }

    fn spec(price: PriceResolution) -> AttemptSpec {
        AttemptSpec {
            provider: ProviderKind::Codex,
            account_id: "account-1".to_owned(),
            configured_model: Some("gpt-5-codex".to_owned()),
            contract: codex_contract(),
            price,
        }
    }

    fn start(request_id: &str) -> LogicalRequestStart {
        LogicalRequestStart {
            request_id: request_id.to_owned(),
            owner_user_id: "user-1".to_owned(),
            api_key_id: Some("key-1".to_owned()),
            api_key_label: None,
            api_key_group_label: None,
            client_model_raw: Some("gpt-5-codex".to_owned()),
            routing_model: Some("gpt-5-codex".to_owned()),
            reasoning_effort: None,
            started_at_ms: 1_700_000_000_000,
        }
    }

    /// A Codex `response.completed` usage block: 120 input of which 100 cached.
    fn codex_usage() -> RawUsageFields {
        RawUsageFields {
            input: Some(120),
            cache_read: Some(100),
            cache_write: None,
            output: Some(8),
            reasoning: Some(4),
            input_audio: None,
            output_audio: None,
            image_input: None,
            image_output: None,
            total: Some(128),
        }
    }

    struct Harness {
        tracking: UsageTracking,
        writer: Arc<UsageWriter>,
        repository: Arc<crate::tests_support::TestRepository>,
    }

    async fn harness() -> Harness {
        let repository = Arc::new(crate::tests_support::TestRepository::default());
        let writer = Arc::new(UsageWriter::spawn(repository.clone(), DEFAULT_WRITE_QUEUE));
        let tracking = UsageTracking::with_clock(repository.clone(), writer.clone(), ticking_clock);
        Harness {
            tracking,
            writer,
            repository,
        }
    }

    #[tokio::test]
    async fn a_substituted_model_makes_the_estimate_partial() {
        let harness = harness().await;
        let logical = harness.tracking.begin_request(start("req-1")).await;
        let attempt = logical.open_attempt(spec(priced()));
        attempt.stream_opened();
        // Priced for `gpt-5-codex` but served by something else, so the amount is
        // an accurate estimate of the wrong model's price.
        attempt.record_provider_model("gpt-4o-mini");
        attempt.record_usage(Some(codex_usage()));
        attempt.close();
        logical.finish();
        assert!(harness.writer.drain(Duration::from_secs(5)).await);

        let facts = &harness.repository.attempts()[0];
        assert!(
            facts
                .observation
                .warnings
                .contains(&NormalizationWarning::ProviderModelMismatch)
        );
        assert_eq!(
            facts.cost.status,
            CostStatus::Partial,
            "a price for a model that did not answer must not look complete"
        );
        assert!(facts.cost.reasons.contains(&CostReason::ModelMismatch));
        // The number it could compute is still kept, just not as a complete one.
        assert_eq!(
            facts.cost.total_known.to_decimal_string(),
            "0.00011000000000"
        );
    }

    #[tokio::test]
    async fn client_drop_with_partial_cost_releases_the_quota_claim() {
        let repository = Arc::new(crate::tests_support::TestRepository::default());
        let writer = Arc::new(UsageWriter::spawn(repository.clone(), DEFAULT_WRITE_QUEUE));
        let quota_writer = Arc::new(QuotaLedgerWriter::spawn(repository.clone(), 1));
        let tracking = UsageTracking::with_clock_and_quota_writer(
            repository.clone(),
            writer,
            Some(quota_writer),
            ticking_clock,
        );
        let logical = tracking
            .begin_quota_request(start("req-client-drop"))
            .await
            .expect("quota request");

        let attempt = logical.open_attempt(spec(priced()));
        attempt.stream_opened();
        attempt.record_provider_model("gpt-4o-mini");
        attempt.finished(Some(codex_usage()));
        logical.record_delivery(DeliveryOutcome::ClientDrop);

        let receipt = logical.finish().expect("quota receipt");
        assert!(receipt.persisted().await);
        let entries = repository.quota_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_id, "req-client-drop");
        assert_eq!(entries[0].api_key_id, "key-1");
        assert!(entries[0].dispatched);
        assert_eq!(entries[0].cost_atoms, None);
    }

    #[tokio::test]
    async fn partial_attempt_does_not_erase_complete_quota_cost() {
        let repository = Arc::new(crate::tests_support::TestRepository::default());
        let writer = Arc::new(UsageWriter::spawn(repository.clone(), DEFAULT_WRITE_QUEUE));
        let quota_writer = Arc::new(QuotaLedgerWriter::spawn(repository.clone(), 1));
        let tracking = UsageTracking::with_clock_and_quota_writer(
            repository.clone(),
            writer,
            Some(quota_writer),
            ticking_clock,
        );
        let logical = tracking
            .begin_quota_request(start("req-mixed-cost"))
            .await
            .expect("quota request");
        logical
            .mark_quota_dispatched()
            .await
            .expect("dispatch marker");

        let complete = logical.open_attempt(spec(priced()));
        complete.stream_opened();
        complete.finished(Some(codex_usage()));

        let partial = logical.open_attempt(spec(priced()));
        partial.stream_opened();
        partial.record_provider_model("gpt-4o-mini");
        partial.finished(Some(codex_usage()));

        logical.record_delivery(DeliveryOutcome::CleanEof);
        let receipt = logical.finish().expect("quota receipt");
        assert!(receipt.persisted().await);

        let entries = repository.quota_entries();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].cost_atoms.is_some());
    }

    #[tokio::test]
    async fn quota_settlement_survives_saturation_of_the_usage_writer() {
        let stall = Arc::new(tokio::sync::Mutex::new(()));
        let held = stall.clone().lock_owned().await;
        let repository = Arc::new(crate::tests_support::TestRepository {
            stall: Some(stall),
            ..crate::tests_support::TestRepository::default()
        });
        let writer = Arc::new(UsageWriter::spawn(repository.clone(), 1));
        let quota_writer = Arc::new(QuotaLedgerWriter::spawn(repository.clone(), 1));
        let tracking = UsageTracking::with_clock_and_quota_writer(
            repository.clone(),
            writer.clone(),
            Some(quota_writer),
            ticking_clock,
        );

        for index in 0..8 {
            writer.submit(UsageWrite {
                owner_user_id: "user-1".to_owned(),
                at_ms: 1_700_000_000_000,
                fact: UsageFact::Gap(TrackingGapReason::WriterSaturated),
            });
            if writer.unrecorded_facts() > 0 {
                panic!("gap tally unexpectedly overflowed at {index}");
            }
        }

        let logical = tracking
            .begin_quota_request(start("req-saturated"))
            .await
            .expect("quota request");
        let attempt = logical.open_attempt(spec(priced()));
        attempt.stream_opened();
        attempt.finished(Some(codex_usage()));
        logical.record_delivery(DeliveryOutcome::CleanEof);
        let receipt = logical.finish().expect("quota receipt");

        drop(held);
        assert!(receipt.persisted().await);
        let entries = repository.quota_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_id, "req-saturated");
        assert!(entries[0].cost_atoms.is_some());
        assert_eq!(entries[0].attempts.len(), 1);
    }

    #[tokio::test]
    async fn a_failed_quota_claim_rejects_the_request() {
        let repository = Arc::new(crate::tests_support::TestRepository {
            fail_start: true,
            ..crate::tests_support::TestRepository::default()
        });
        let writer = Arc::new(UsageWriter::spawn(repository.clone(), DEFAULT_WRITE_QUEUE));
        let quota_writer = Arc::new(QuotaLedgerWriter::spawn(repository.clone(), 1));
        let tracking = UsageTracking::with_clock_and_quota_writer(
            repository,
            writer,
            Some(quota_writer),
            ticking_clock,
        );

        assert!(
            tracking
                .begin_quota_request(start("req-failed-claim"))
                .await
                .is_err(),
            "finite-quota accounting must fail closed before dispatch"
        );
    }

    #[tokio::test]
    async fn closing_twice_writes_one_attempt() {
        // A stream that ends and is then dropped must not double-count usage.
        let harness = harness().await;
        let logical = harness.tracking.begin_request(start("req-1")).await;
        let attempt = logical.open_attempt(spec(priced()));
        attempt.stream_opened();
        attempt.record_usage(Some(codex_usage()));

        attempt.close();
        attempt.close();
        logical.finish();
        logical.finish();
        assert!(harness.writer.drain(Duration::from_secs(5)).await);

        assert_eq!(harness.repository.attempts().len(), 1);
        assert_eq!(harness.repository.terminals().len(), 1);
    }

    #[tokio::test]
    async fn dispatch_evidence_never_moves_backwards() {
        let harness = harness().await;
        let logical = harness.tracking.begin_request(start("req-1")).await;
        let attempt = logical.open_attempt(spec(priced()));

        attempt.stream_opened();
        // A weaker signal must not erase what was already proven.
        attempt.advance(DispatchEvidence::DispatchInvoked);
        attempt.record_usage(Some(codex_usage()));
        attempt.close();
        logical.finish();
        assert!(harness.writer.drain(Duration::from_secs(5)).await);

        assert_eq!(
            harness.repository.attempts()[0].dispatch_evidence,
            DispatchEvidence::ResponseObserved
        );
    }

    #[tokio::test]
    async fn a_lost_observation_is_a_gap_not_a_silent_absence() {
        // Failing to look is a different fact from the provider reporting nothing.
        let harness = harness().await;
        let logical = harness.tracking.begin_request(start("req-1")).await;
        let attempt = logical.open_attempt(spec(priced()));
        attempt.stream_opened();
        attempt.mark_observation_lost();
        attempt.record_usage(None);
        attempt.close();
        logical.finish();
        assert!(harness.writer.drain(Duration::from_secs(5)).await);

        assert_eq!(
            harness.repository.attempts()[0].tracking,
            TrackingState::Gap {
                reason: TrackingGapReason::ObservationLost
            }
        );
    }

    #[tokio::test]
    async fn a_retry_makes_two_attempts_under_one_logical_request() {
        // This is the 401-refresh shape: one logical request, two upstream calls.
        let harness = harness().await;
        let logical = harness.tracking.begin_request(start("req-1")).await;

        // The first call answered with a failure status and no terminal.
        let first = logical.open_attempt(spec(priced()));
        first.failed(true);

        let second = logical.open_attempt(spec(priced()));
        second.stream_opened();
        second.success_terminal_observed();
        second.finished(Some(codex_usage()));

        logical.record_delivery(DeliveryOutcome::CleanEof);
        logical.finish();
        assert!(harness.writer.drain(Duration::from_secs(5)).await);

        let attempts = harness.repository.attempts();
        assert_eq!(attempts.len(), 2, "a refresh retry is a second attempt");
        assert_eq!(attempts[0].sequence, AttemptSequence(1));
        assert_eq!(attempts[1].sequence, AttemptSequence(2));
        assert_eq!(attempts[0].outcome, Some(AttemptOutcome::Failed));
        assert_eq!(attempts[0].failover_reason, None);
        assert_eq!(attempts[1].outcome, Some(AttemptOutcome::Succeeded));
        assert_eq!(attempts[1].failover_reason, None);
        let terminal = &harness.repository.terminals()[0];
        assert_eq!(
            terminal.final_attempt_id.as_deref(),
            Some("req-1#2"),
            "the user's response came from the last attempt"
        );
        assert_eq!(
            terminal.execution,
            Some(ExecutionOutcome::StableSuccessTerminal),
            "the retry decides the logical outcome, not the attempt it replaced"
        );
        assert_eq!(terminal.status, LogicalStatus::Succeeded);
        assert_eq!(
            attempts[0].dispatch_evidence,
            DispatchEvidence::ResponseObserved,
            "a failure status still proves the provider answered"
        );
    }

    #[tokio::test]
    async fn explicit_failover_reasons_are_persisted_on_failed_attempts() {
        let harness = harness().await;
        let logical = harness
            .tracking
            .begin_request(start("req-failover-reasons"))
            .await;
        let cases = [
            (
                ProviderFailoverReason::AuthenticationExhausted,
                AttemptFailoverReason::AuthenticationExhausted,
            ),
            (
                ProviderFailoverReason::QuotaExhausted,
                AttemptFailoverReason::QuotaExhausted,
            ),
            (
                ProviderFailoverReason::RateLimited,
                AttemptFailoverReason::RateLimited,
            ),
            (
                ProviderFailoverReason::PreconnectFailure,
                AttemptFailoverReason::PreconnectFailure,
            ),
        ];

        for (provider_reason, _) in cases {
            logical
                .open_attempt(spec(priced()))
                .failed_with_reason(false, provider_reason);
        }
        logical.finish();
        assert!(harness.writer.drain(Duration::from_secs(5)).await);

        let attempts = harness.repository.attempts();
        for (attempt, (_, expected_reason)) in attempts.iter().zip(cases) {
            assert_eq!(attempt.outcome, Some(AttemptOutcome::Failed));
            assert_eq!(attempt.failover_reason, Some(expected_reason));
        }
    }

    #[tokio::test]
    async fn cancelled_attempt_persists_cancelled_without_failover_reason() {
        let harness = harness().await;
        let logical = harness
            .tracking
            .begin_request(start("req-cancelled-attempt"))
            .await;
        let attempt = logical.open_attempt(spec(priced()));
        attempt.stream_opened();
        attempt.cancelled(Some(codex_usage()));
        logical.finish();
        assert!(harness.writer.drain(Duration::from_secs(5)).await);

        let facts = &harness.repository.attempts()[0];
        assert_eq!(facts.outcome, Some(AttemptOutcome::Cancelled));
        assert_eq!(facts.failover_reason, None);
        assert_eq!(
            facts.tracking,
            TrackingState::Gap {
                reason: TrackingGapReason::AmbiguousCancel
            }
        );
    }

    #[tokio::test]
    async fn dropping_logical_tracker_closes_cancelled_request() {
        let harness = harness().await;
        let logical = harness
            .tracking
            .begin_request(start("req-cancelled-logical"))
            .await;
        let attempt = logical.open_attempt(spec(priced()));
        attempt.failed(true);
        drop(attempt);
        drop(logical);

        assert!(harness.writer.drain(Duration::from_secs(5)).await);
        let terminal = &harness.repository.terminals()[0];
        assert_eq!(terminal.status, LogicalStatus::Canceled);
        assert_eq!(terminal.delivery, Some(DeliveryOutcome::ClientDrop));
        assert_eq!(
            terminal.execution,
            Some(ExecutionOutcome::EofWithoutSuccessTerminal)
        );
    }

    #[tokio::test]
    async fn an_out_of_order_close_keeps_the_highest_attempt_as_final() {
        let harness = harness().await;
        let logical = harness.tracking.begin_request(start("req-1")).await;
        let first = logical.open_attempt(spec(priced()));
        let second = logical.open_attempt(spec(priced()));

        second.stream_opened();
        second.finished(Some(codex_usage()));
        // The earlier attempt closes last; it must not become the final one.
        first.stream_opened();
        first.finished(None);
        logical.finish();
        assert!(harness.writer.drain(Duration::from_secs(5)).await);

        assert_eq!(
            harness.repository.terminals()[0]
                .final_attempt_id
                .as_deref(),
            Some("req-1#2")
        );
    }

    #[tokio::test]
    async fn an_unreported_outcome_is_incomplete_never_a_success() {
        let harness = harness().await;
        let logical = harness.tracking.begin_request(start("req-1")).await;
        // Nothing reported at all, as a task killed mid-flight would leave it.
        logical.finish();
        assert!(harness.writer.drain(Duration::from_secs(5)).await);

        let terminal = &harness.repository.terminals()[0];
        assert_eq!(terminal.status, LogicalStatus::Incomplete);
        assert_eq!(
            terminal.execution,
            Some(ExecutionOutcome::EofWithoutSuccessTerminal)
        );
        assert_eq!(terminal.delivery, Some(DeliveryOutcome::Unknown));
    }

    #[tokio::test]
    async fn a_failed_start_write_still_serves_the_request_and_reports_a_gap() {
        let repository = Arc::new(crate::tests_support::TestRepository {
            fail_start: true,
            ..crate::tests_support::TestRepository::default()
        });
        let writer = Arc::new(UsageWriter::spawn(repository.clone(), DEFAULT_WRITE_QUEUE));
        let tracking = UsageTracking::with_clock(repository.clone(), writer.clone(), ticking_clock);

        // begin_request must not fail: statistics never block a proxy request.
        let logical = tracking.begin_request(start("req-1")).await;
        let attempt = logical.open_attempt(spec(priced()));
        attempt.stream_opened();
        attempt.record_usage(Some(codex_usage()));
        attempt.close();
        logical.finish();
        assert!(writer.drain(Duration::from_secs(5)).await);

        assert_eq!(
            repository.terminals()[0].tracking,
            TrackingState::Gap {
                reason: TrackingGapReason::WriteFailed
            },
            "a terminal whose start never landed says so"
        );
    }
}
