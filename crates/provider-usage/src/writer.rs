//! The bounded in-process writer that persists usage facts off the proxy's path.
//!
//! Three properties define it, and each one exists to keep a statistics failure
//! from becoming a proxy failure:
//!
//! 1. **Bounded.** The queue has a fixed capacity and so does the shed-gap
//!    tally. A submission that does not fit is shed immediately rather than
//!    awaited, so no caller ever blocks on persistence and nothing grows without
//!    limit.
//! 2. **Fail-open.** A shed submission and a failed write both become a tracking
//!    gap: a counted admission that facts are missing, never a silent zero.
//! 3. **Not durable.** This is not a queue with delivery guarantees. A crash
//!    loses whatever is still in it, and health says so.
//!
//! Shed facts are tallied in memory rather than queued as gap events. A full
//! queue has no room for a gap event either, so queueing one would turn every
//! saturation into an unattributable loss; a per-minute tally needs no queue slot
//! and keeps the gap attached to the user whose request it was.
//!
//! A persistently broken database needs no circuit breaker here: the queue fills,
//! submissions shed with gaps, and the proxy is untouched. That is the same
//! outcome a breaker would produce, with nothing extra to get wrong.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::sync::{mpsc, oneshot};

use crate::{
    attempt::TrackingGapReason,
    repository::{
        AttemptFacts, LogicalRequestTerminal, LogicalWriteOutcome, QuotaLedgerEntry,
        UsageRepository,
    },
};

/// How many pending writes the queue holds before shedding.
///
/// Sized so a burst of terminals rides through while a stalled database still
/// costs bounded memory.
pub const DEFAULT_WRITE_QUEUE: usize = 1024;
pub const DEFAULT_QUOTA_QUEUE: usize = 1024;

/// Tracking gaps are counted per minute, so a saturated writer records a count
/// rather than one row per lost fact.
pub const GAP_BUCKET_MS: i64 = 60_000;

/// How many distinct `(owner, reason, minute)` tallies are held before shed facts
/// stop being attributable. Reached only with an implausible number of concurrent
/// users; past it, losses are still counted, just not per user.
const MAX_PENDING_GAP_KEYS: usize = 4096;

/// One fact to persist, with the identity and time needed to attribute a failure.
#[derive(Clone, Debug)]
pub struct UsageWrite {
    /// Carried on the envelope so that a write which fails is still attributable
    /// to the right user's gap bucket.
    pub owner_user_id: String,
    /// When the fact happened, used to place a gap in its bucket.
    pub at_ms: i64,
    pub fact: UsageFact,
}

#[derive(Clone, Debug)]
pub enum UsageFact {
    Attempt(Box<AttemptFacts>),
    LogicalTerminal(LogicalRequestTerminal),
    /// A gap the caller already knows about, such as a failed logical start.
    Gap(TrackingGapReason),
}

/// Whether a submission entered the queue. `Shed` is a normal, expected outcome
/// under load, not an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitOutcome {
    Queued,
    Shed,
}

/// What the queue carries. `Flush` is internal: it lets a drain wait for
/// everything submitted before it, without exposing a marker to callers.
enum Job {
    Write(UsageWrite),
    Flush(oneshot::Sender<()>),
}

pub struct UsageWriter {
    sender: mpsc::Sender<Job>,
    shed: Arc<ShedGaps>,
}

enum QuotaJob {
    Entry(QuotaLedgerEntry, oneshot::Sender<()>),
    Flush(oneshot::Sender<()>),
}

/// An unsheddable writer for the authoritative quota ledger. It retries the
/// current entry until SQLite accepts it, exposes failures to readiness, and
/// drains without a timeout during shutdown.
pub struct QuotaLedgerWriter {
    sender: mpsc::Sender<QuotaJob>,
    healthy: Arc<AtomicBool>,
    pending: Arc<AtomicU64>,
}

pub struct QuotaLedgerPermit {
    permit: mpsc::OwnedPermit<QuotaJob>,
    pending: Arc<AtomicU64>,
}

pub struct QuotaLedgerReceipt(oneshot::Receiver<()>);

impl QuotaLedgerReceipt {
    pub async fn persisted(self) -> bool {
        self.0.await.is_ok()
    }
}

impl QuotaLedgerPermit {
    pub fn submit(self, entry: QuotaLedgerEntry) -> QuotaLedgerReceipt {
        let (ack, acked) = oneshot::channel();
        self.pending.fetch_add(1, Ordering::Release);
        self.permit.send(QuotaJob::Entry(entry, ack));
        QuotaLedgerReceipt(acked)
    }
}

impl QuotaLedgerWriter {
    #[must_use]
    pub fn spawn(repository: Arc<dyn UsageRepository>, capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let healthy = Arc::new(AtomicBool::new(true));
        let pending = Arc::new(AtomicU64::new(0));
        tokio::spawn(run_quota_ledger(
            receiver,
            repository,
            Arc::clone(&healthy),
            Arc::clone(&pending),
        ));
        Self {
            sender,
            healthy,
            pending,
        }
    }

    pub async fn reserve(&self) -> Option<QuotaLedgerPermit> {
        if !self.healthy.load(Ordering::Acquire) {
            return None;
        }
        match self.sender.clone().reserve_owned().await {
            Ok(permit) if self.healthy.load(Ordering::Acquire) => Some(QuotaLedgerPermit {
                permit,
                pending: Arc::clone(&self.pending),
            }),
            Ok(_) => None,
            Err(_) => {
                self.healthy.store(false, Ordering::Release);
                None
            }
        }
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        !self.sender.is_closed()
            && self.healthy.load(Ordering::Acquire)
            && self.sender.capacity() > 0
    }

    #[must_use]
    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }

    pub async fn drain(&self) -> bool {
        let (ack, acked) = oneshot::channel();
        self.sender.send(QuotaJob::Flush(ack)).await.is_ok() && acked.await.is_ok()
    }
}

async fn run_quota_ledger(
    mut receiver: mpsc::Receiver<QuotaJob>,
    repository: Arc<dyn UsageRepository>,
    healthy: Arc<AtomicBool>,
    pending: Arc<AtomicU64>,
) {
    while let Some(job) = receiver.recv().await {
        match job {
            QuotaJob::Entry(entry, ack) => loop {
                match repository.record_quota_ledger_entry(&entry).await {
                    Ok(()) => {
                        healthy.store(true, Ordering::Release);
                        pending.fetch_sub(1, Ordering::Release);
                        let _ = ack.send(());
                        break;
                    }
                    Err(_) => {
                        healthy.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            },
            QuotaJob::Flush(ack) => {
                let _ = ack.send(());
            }
        }
    }
}

impl UsageWriter {
    /// Start the writer task. It stops when every [`UsageWriter`] is dropped.
    #[must_use]
    pub fn spawn(repository: Arc<dyn UsageRepository>, capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let shed = Arc::new(ShedGaps::default());
        tokio::spawn(run(receiver, repository, Arc::clone(&shed)));
        Self { sender, shed }
    }

    /// Hand a fact to the writer without waiting for it to be persisted.
    ///
    /// Never blocks and never fails. A fact that does not fit the queue is
    /// tallied as a gap for its user and minute.
    pub fn submit(&self, write: UsageWrite) -> SubmitOutcome {
        // A shed gap keeps its own reason; anything else is shed because the
        // writer could not keep up.
        let reason = match &write.fact {
            UsageFact::Gap(reason) => *reason,
            UsageFact::Attempt(_) | UsageFact::LogicalTerminal(_) => {
                TrackingGapReason::WriterSaturated
            }
        };
        let owner = write.owner_user_id.clone();
        let at_ms = write.at_ms;

        if self.sender.try_send(Job::Write(write)).is_ok() {
            return SubmitOutcome::Queued;
        }
        self.shed.tally(owner, reason, gap_bucket(at_ms));
        SubmitOutcome::Shed
    }

    /// Facts lost without a gap row to name them: either the tally was full, or
    /// the gap itself could not be persisted.
    #[must_use]
    pub fn unrecorded_facts(&self) -> u64 {
        self.shed.unrecorded()
    }

    /// Wait for everything already submitted to be persisted, up to `within`.
    ///
    /// Returns whether the drain completed in time. A timeout is not an error:
    /// this is best-effort, and shutdown must never block on a slow database.
    pub async fn drain(&self, within: Duration) -> bool {
        let (ack, acked) = oneshot::channel();
        if self.sender.send(Job::Flush(ack)).await.is_err() {
            return false;
        }
        tokio::time::timeout(within, acked).await.is_ok()
    }
}

/// Shed facts, aggregated per `(owner, reason, minute)` so they need no queue.
#[derive(Default)]
struct ShedGaps {
    counts: Mutex<HashMap<(String, TrackingGapReason, i64), u64>>,
    unrecorded: AtomicU64,
}

impl ShedGaps {
    fn tally(&self, owner_user_id: String, reason: TrackingGapReason, bucket_start_ms: i64) {
        let Ok(mut counts) = self.counts.lock() else {
            self.unrecorded.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let key = (owner_user_id, reason, bucket_start_ms);
        // Only refuse *new* keys at the cap, so an existing tally keeps counting
        // instead of a whole minute's losses going unattributed.
        if counts.len() >= MAX_PENDING_GAP_KEYS && !counts.contains_key(&key) {
            self.unrecorded.fetch_add(1, Ordering::Relaxed);
            return;
        }
        *counts.entry(key).or_insert(0) += 1;
    }

    /// Take everything tallied so far. The caller persists it, and hands back
    /// whatever failed.
    fn take(&self) -> Vec<((String, TrackingGapReason, i64), u64)> {
        match self.counts.lock() {
            Ok(mut counts) => counts.drain().collect(),
            Err(_) => Vec::new(),
        }
    }

    fn unrecorded(&self) -> u64 {
        self.unrecorded.load(Ordering::Relaxed)
    }

    fn give_up(&self, count: u64) {
        self.unrecorded.fetch_add(count, Ordering::Relaxed);
    }
}

async fn run(
    mut receiver: mpsc::Receiver<Job>,
    repository: Arc<dyn UsageRepository>,
    shed: Arc<ShedGaps>,
) {
    while let Some(job) = receiver.recv().await {
        match job {
            Job::Flush(ack) => {
                flush_shed(repository.as_ref(), shed.as_ref()).await;
                // Everything queued earlier has already been applied, because
                // the queue is processed in order.
                let _ = ack.send(());
            }
            Job::Write(write) => {
                apply(repository.as_ref(), write, shed.as_ref()).await;
                flush_shed(repository.as_ref(), shed.as_ref()).await;
            }
        }
    }
    // Whatever was shed on the way out is still worth admitting.
    flush_shed(repository.as_ref(), shed.as_ref()).await;
}

async fn apply(repository: &dyn UsageRepository, write: UsageWrite, shed: &ShedGaps) {
    let owner = write.owner_user_id;
    let at_ms = write.at_ms;
    let failure = match write.fact {
        UsageFact::Attempt(facts) => match repository.record_attempt(facts.as_ref()).await {
            Ok(()) => None,
            Err(_) => Some(TrackingGapReason::WriteFailed),
        },
        UsageFact::LogicalTerminal(terminal) => {
            match repository.complete_logical_request(&terminal).await {
                // A terminal for a request whose start never landed is exactly
                // the gap the fail-open start write promised to report.
                Ok(LogicalWriteOutcome::MissingRequest) | Err(_) => {
                    Some(TrackingGapReason::WriteFailed)
                }
                Ok(LogicalWriteOutcome::Written | LogicalWriteOutcome::AlreadyKnown) => None,
            }
        }
        UsageFact::Gap(reason) => Some(reason),
    };

    if let Some(reason) = failure {
        let written = repository
            .record_tracking_gap(&owner, reason, gap_bucket(at_ms), 1)
            .await;
        if written.is_err() {
            // The gap itself could not be persisted. Counting it in memory is
            // the last honest thing available.
            shed.give_up(1);
        }
    }
}

/// Persist the shed tally. A tally that cannot be written is counted rather than
/// retried forever, so a permanently broken database still terminates.
async fn flush_shed(repository: &dyn UsageRepository, shed: &ShedGaps) {
    for ((owner_user_id, reason, bucket_start_ms), count) in shed.take() {
        if repository
            .record_tracking_gap(&owner_user_id, reason, bucket_start_ms, count)
            .await
            .is_err()
        {
            shed.give_up(count);
        }
    }
}

/// The start of `at_ms`'s bucket. Uses floored division so pre-epoch values do
/// not land in a bucket ahead of themselves.
#[must_use]
pub const fn gap_bucket(at_ms: i64) -> i64 {
    at_ms - at_ms.rem_euclid(GAP_BUCKET_MS)
}

#[cfg(test)]
mod tests {
    use provider_core::{
        ProviderKind,
        usage::{
            CacheCapability, CacheEligibility, CacheReportingExpectation, PricingContextBasis,
            PricingMode, ProviderUsageObservation, TokenInclusionRules, TokenMetric, TotalSource,
            UsageContractSnapshot,
        },
    };

    use super::*;
    use crate::{
        attempt::{AttemptSequence, DispatchEvidence, LogicalStatus, TrackingState},
        cost::{CostStatus, ObservedCatalogCost},
        lifecycle::{DeliveryOutcome, ExecutionOutcome},
        money::UsdAtoms,
        price::PriceResolution,
        tests_support::TestRepository,
    };

    const AT_MS: i64 = 1_700_000_090_123;
    const BUCKET_MS: i64 = 1_700_000_040_000;

    fn quota_entry(id: &str) -> QuotaLedgerEntry {
        QuotaLedgerEntry {
            entry_id: id.to_owned(),
            api_key_id: "key-1".to_owned(),
            dispatched: true,
            cost_atoms: Some("1".to_owned()),
            resolved_at_ms: AT_MS,
        }
    }

    #[tokio::test]
    async fn quota_writer_applies_bounded_fail_closed_backpressure() {
        let repository = Arc::new(TestRepository {
            fail_facts: true,
            ..TestRepository::default()
        });
        let writer = QuotaLedgerWriter::spawn(repository, 1);
        writer
            .reserve()
            .await
            .expect("first quota permit")
            .submit(quota_entry("req-1"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while writer.is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer reports repository failure");
        assert!(writer.reserve().await.is_none());
        assert!(!writer.is_ready());
        assert_eq!(writer.pending(), 1);
    }

    #[tokio::test]
    async fn quota_writer_receipt_confirms_persistence_and_drain() {
        let repository = Arc::new(TestRepository::default());
        let writer = QuotaLedgerWriter::spawn(repository.clone(), 1);
        let receipt = writer
            .reserve()
            .await
            .expect("quota permit")
            .submit(quota_entry("req-success"));

        assert!(receipt.persisted().await);
        assert!(writer.drain().await);
        assert!(writer.is_ready());
        assert_eq!(writer.pending(), 0);
        assert_eq!(repository.quota_entries(), vec![quota_entry("req-success")]);
    }

    #[tokio::test]
    async fn quota_writer_is_not_ready_when_worker_exits() {
        let repository = Arc::new(TestRepository {
            panic_quota: true,
            ..TestRepository::default()
        });
        let writer = QuotaLedgerWriter::spawn(repository, 1);
        let _receipt = writer
            .reserve()
            .await
            .expect("quota permit")
            .submit(quota_entry("req-panic"));

        tokio::time::timeout(Duration::from_secs(1), async {
            while writer.is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("closed worker channel must fail readiness");
        assert!(!writer.is_ready());
    }

    fn attempt_write(attempt_id: &str) -> UsageWrite {
        UsageWrite {
            owner_user_id: "user-1".to_owned(),
            at_ms: AT_MS,
            fact: UsageFact::Attempt(Box::new(AttemptFacts {
                attempt_id: attempt_id.to_owned(),
                logical_request_id: "req-1".to_owned(),
                sequence: AttemptSequence(1),
                provider: ProviderKind::Codex,
                account_id: "account-1".to_owned(),
                configured_model: None,
                provider_reported_model: None,
                started_at_ms: 1_700_000_090_000,
                first_token_at_ms: None,
                completed_at_ms: AT_MS,
                dispatch_evidence: DispatchEvidence::ResponseObserved,
                tracking: TrackingState::Complete,
                contract: UsageContractSnapshot {
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
                },
                observation: ProviderUsageObservation {
                    uncached_input_tokens: TokenMetric::ProviderReported { value: 20 },
                    cache_read_input_tokens: TokenMetric::ProviderReported { value: 100 },
                    cache_write_input_tokens: TokenMetric::NotApplicable,
                    effective_input_tokens: TokenMetric::ProviderReported { value: 120 },
                    output_tokens: TokenMetric::ProviderReported { value: 8 },
                    reasoning_tokens: TokenMetric::ProviderReported { value: 0 },
                    input_audio_tokens: TokenMetric::NotApplicable,
                    output_audio_tokens: TokenMetric::NotApplicable,
                    total_tokens: TokenMetric::ProviderReported { value: 128 },
                    pricing_context_tokens: TokenMetric::ProviderReported { value: 120 },
                    billable: Vec::new(),
                    warnings: Vec::new(),
                },
                price: PriceResolution::CatalogUnavailable,
                cost: ObservedCatalogCost {
                    total_known: UsdAtoms::ZERO,
                    status: CostStatus::Unavailable,
                    reasons: Vec::new(),
                    calculator_version: 1,
                },
            })),
        }
    }

    fn terminal_write(request_id: &str) -> UsageWrite {
        UsageWrite {
            owner_user_id: "user-1".to_owned(),
            at_ms: AT_MS,
            fact: UsageFact::LogicalTerminal(LogicalRequestTerminal {
                request_id: request_id.to_owned(),
                completed_at_ms: AT_MS,
                status: LogicalStatus::Succeeded,
                execution: Some(ExecutionOutcome::StableSuccessTerminal),
                delivery: Some(DeliveryOutcome::CleanEof),
                final_attempt_id: Some("att-1".to_owned()),
                tracking: TrackingState::Complete,
                state_version: 1,
            }),
        }
    }

    #[tokio::test]
    async fn a_failed_write_becomes_a_gap_and_never_an_error() {
        let repository = Arc::new(TestRepository {
            fail_facts: true,
            ..TestRepository::default()
        });
        let writer = UsageWriter::spawn(repository.clone(), DEFAULT_WRITE_QUEUE);

        // Submitting still succeeds: the caller must not learn about, or wait
        // for, a database problem.
        assert_eq!(writer.submit(attempt_write("att-1")), SubmitOutcome::Queued);
        assert!(writer.drain(Duration::from_secs(5)).await);

        assert_eq!(
            repository.gaps(),
            vec![(
                "user-1".to_owned(),
                TrackingGapReason::WriteFailed,
                BUCKET_MS,
                1
            )],
            "a lost fact is admitted, in its own minute bucket"
        );
        assert_eq!(writer.unrecorded_facts(), 0);
    }

    #[tokio::test]
    async fn a_terminal_without_its_start_row_is_a_gap() {
        // The logical start write is fail-open, so this is how that earlier loss
        // surfaces rather than as a silently orphaned terminal.
        let repository = Arc::new(TestRepository {
            terminal_is_orphaned: true,
            ..TestRepository::default()
        });
        let writer = UsageWriter::spawn(repository.clone(), DEFAULT_WRITE_QUEUE);

        writer.submit(terminal_write("req-1"));
        assert!(writer.drain(Duration::from_secs(5)).await);

        assert_eq!(
            repository.gap_count(TrackingGapReason::WriteFailed),
            1,
            "an orphaned terminal must be reported, not accepted quietly"
        );
    }

    #[tokio::test]
    async fn a_full_queue_sheds_into_an_attributable_tally() {
        let stall = Arc::new(tokio::sync::Mutex::new(()));
        let held = stall.clone().lock_owned().await;
        let repository = Arc::new(TestRepository {
            stall: Some(stall),
            ..TestRepository::default()
        });
        // Capacity 1, and the writer is stuck on its first write, so everything
        // after the first couple of submissions has to be shed.
        let writer = UsageWriter::spawn(repository.clone(), 1);

        let mut shed = 0u64;
        for index in 0..8 {
            if writer.submit(attempt_write(&format!("att-{index}"))) == SubmitOutcome::Shed {
                shed += 1;
            }
        }
        assert!(shed > 0, "a bounded queue under load has to shed");
        assert_eq!(
            writer.unrecorded_facts(),
            0,
            "a shed fact is tallied against its user, not written off"
        );

        drop(held);
        assert!(writer.drain(Duration::from_secs(5)).await);

        assert_eq!(
            repository.gap_count(TrackingGapReason::WriterSaturated),
            shed,
            "every shed fact is accounted for exactly once"
        );
        assert!(
            repository
                .gaps()
                .iter()
                .all(|(owner, _, bucket, _)| owner == "user-1" && *bucket == BUCKET_MS),
            "shed gaps keep the owner and minute they came from"
        );
    }

    #[test]
    fn the_shed_tally_is_bounded() {
        let shed = ShedGaps::default();
        for index in 0..(MAX_PENDING_GAP_KEYS + 100) {
            shed.tally(
                format!("user-{index}"),
                TrackingGapReason::WriterSaturated,
                BUCKET_MS,
            );
        }
        assert_eq!(
            shed.take().len(),
            MAX_PENDING_GAP_KEYS,
            "the tally must not grow without limit"
        );
        assert_eq!(
            shed.unrecorded(),
            100,
            "losses past the cap are still counted, just not attributed"
        );
    }
}
