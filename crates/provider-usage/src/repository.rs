//! Persistence contract for observed usage facts.
//!
//! The write path has exactly two shapes, matching the terminal-time write
//! design: one small row when a logical request starts (the only tracking write
//! on the request path, and fail-open), and one complete row per attempt after
//! its response reached a terminal state.
//!
//! Every method is idempotent. The in-process writer carries IDs and a state
//! version rather than being a durable queue, so it may deliver an event twice
//! or late; a repository must tolerate that without inventing or losing facts.

use async_trait::async_trait;
use provider_core::{
    ProviderKind,
    usage::{ProviderUsageObservation, UsageContractSnapshot},
};
use thiserror::Error;

use crate::{
    attempt::{AttemptSequence, DispatchEvidence, LogicalStatus, TrackingGapReason, TrackingState},
    cost::ObservedCatalogCost,
    lifecycle::{DeliveryOutcome, ExecutionOutcome},
    price::PriceResolution,
};

/// A persistence failure. Callers treat this as fail-open: record a tracking gap
/// and keep serving the proxy response.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct UsageRepositoryError {
    message: String,
}

impl UsageRepositoryError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Identity and routing snapshot written right after authentication.
///
/// The identity fields are copies, not references: deleting the user, key,
/// account, or model later must not erase or rewrite history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalRequestStart {
    pub request_id: String,
    pub owner_user_id: String,
    pub api_key_id: Option<String>,
    /// API key identity at request time. These are snapshots, not lookups.
    pub api_key_label: Option<String>,
    pub api_key_group_label: Option<String>,
    /// The model string the client sent, before any alias resolution.
    pub client_model_raw: Option<String>,
    /// The model the router selected.
    pub routing_model: Option<String>,
    /// The reasoning level requested by the client, when one was supplied.
    pub reasoning_effort: Option<String>,
    pub started_at_ms: i64,
}

/// The terminal state of a logical request, committed only by the reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalRequestTerminal {
    pub request_id: String,
    pub completed_at_ms: i64,
    /// Must be terminal; `InProgress` is rejected.
    pub status: LogicalStatus,
    pub execution: Option<ExecutionOutcome>,
    pub delivery: Option<DeliveryOutcome>,
    pub final_attempt_id: Option<String>,
    pub tracking: TrackingState,
    /// Monotonic per-request version. A write whose version is not newer than
    /// the stored one is ignored, so this must be at least 1: the start row is
    /// version 0.
    pub state_version: u32,
}

/// What a logical-request write actually did. `MissingRequest` and `AlreadyKnown`
/// are normal outcomes under fail-open writing, not errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalWriteOutcome {
    /// The row was inserted or advanced.
    Written,
    /// The start row was never persisted, so there is nothing to complete. The
    /// caller records a tracking gap.
    MissingRequest,
    /// Nothing changed because the stored state is already at least this new:
    /// a redelivered start, or a terminal event that arrived late.
    AlreadyKnown,
}

/// One attempt's complete facts, written once after its response ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptFacts {
    pub attempt_id: String,
    pub logical_request_id: String,
    pub sequence: AttemptSequence,
    /// Provider kind and account, snapshotted for the same reason as identity.
    pub provider: ProviderKind,
    pub account_id: String,
    /// The model the attempt was prepared for.
    pub configured_model: Option<String>,
    /// The model the provider said it used, when it said anything.
    pub provider_reported_model: Option<String>,
    pub started_at_ms: i64,
    /// When the first output token was observed on the upstream stream.
    pub first_token_at_ms: Option<i64>,
    pub completed_at_ms: i64,
    pub dispatch_evidence: DispatchEvidence,
    pub tracking: TrackingState,
    pub contract: UsageContractSnapshot,
    pub observation: ProviderUsageObservation,
    /// Frozen from the routed provider model at attempt start and stored inline,
    /// so this attempt's cost never depends on later model-price changes.
    pub price: PriceResolution,
    pub cost: ObservedCatalogCost,
}

/// Terminal result for a legacy pre-dispatch quota reservation.
/// Only an observed exact cost is settled; an absent cost releases the
/// reservation without inventing spend. New finite-quota traffic charges via
/// attempt completion instead of creating reservations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaLedgerEntry {
    pub entry_id: String,
    pub api_key_id: String,
    pub dispatched: bool,
    pub cost_atoms: Option<String>,
    pub resolved_at_ms: i64,
}

/// The stored models.dev catalog. Exactly one is kept; an absent row means the
/// vendored seed is in effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCatalog {
    /// Hex-encoded SHA-256 of `body`, used as the revision an attempt inlines.
    pub revision: String,
    pub body: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// When this body was fetched, not when it was last checked.
    pub content_fetched_at_ms: i64,
    pub last_checked_at_ms: i64,
    /// A stable reason code. Never an upstream message, which could carry
    /// arbitrary text into logs and API responses.
    pub last_error_code: Option<String>,
}

#[async_trait]
pub trait UsageRepository: Send + Sync {
    /// Persist the start of a logical request. Re-submitting the same
    /// `request_id` is a no-op.
    async fn begin_logical_request(
        &self,
        start: &LogicalRequestStart,
    ) -> Result<LogicalWriteOutcome, UsageRepositoryError>;

    /// Persist a logical request's terminal state.
    ///
    /// Operational outcomes are retained even when they are not user-visible
    /// Usage. Read queries apply the Usage eligibility contract separately;
    /// quota settlement remains independent.
    async fn complete_logical_request(
        &self,
        terminal: &LogicalRequestTerminal,
    ) -> Result<LogicalWriteOutcome, UsageRepositoryError>;

    /// Persist one attempt. Re-submitting the same `attempt_id` is a no-op; a
    /// *different* attempt claiming an already-used sequence is an error,
    /// because that would silently duplicate upstream usage. Observed complete
    /// costs advance lifetime key spend unless a legacy reservation still owns
    /// that request's settlement.
    async fn record_attempt(&self, facts: &AttemptFacts) -> Result<(), UsageRepositoryError>;

    /// Persist a legacy quota-reservation terminal and update lifetime spend.
    async fn record_quota_ledger_entry(
        &self,
        entry: &QuotaLedgerEntry,
    ) -> Result<(), UsageRepositoryError>;

    /// Release every reservation left by a prior process. Without terminal
    /// usage facts, restart recovery cannot invent a billable amount.
    async fn recover_quota_reservations(&self, now_ms: i64) -> Result<u64, UsageRepositoryError>;

    /// Add `count` lost facts to a bucket, creating it if needed. Counting rather
    /// than inserting per loss is what keeps a saturated writer from turning
    /// lost rows into just as many gap rows.
    async fn record_tracking_gap(
        &self,
        owner_user_id: &str,
        reason: TrackingGapReason,
        bucket_start_ms: i64,
        count: u64,
    ) -> Result<(), UsageRepositoryError>;

    /// Close out logical requests a previous run left in flight, as
    /// `incomplete` with a `recovered_in_flight` gap. Returns how many were
    /// closed. Their terminal state is unknowable, so nothing is guessed.
    async fn recover_in_flight_requests(&self, now_ms: i64) -> Result<u64, UsageRepositoryError>;

    async fn load_logical_request(
        &self,
        request_id: &str,
    ) -> Result<Option<StoredLogicalRequest>, UsageRepositoryError>;

    async fn load_attempts(
        &self,
        request_id: &str,
    ) -> Result<Vec<AttemptFacts>, UsageRepositoryError>;

    /// Delete up to `batch` settled or released quota-ledger entries resolved
    /// before `cutoff_ms`. Active reservations are never eligible.
    async fn delete_resolved_quota_ledger_entries_before(
        &self,
        cutoff_ms: i64,
        batch: u32,
    ) -> Result<u64, UsageRepositoryError>;

    /// Delete up to `batch` finished logical requests that ended before
    /// `cutoff_ms`, together with everything belonging to them.
    ///
    /// Requests that have not finished are never deleted: they have no terminal
    /// time to compare, and their facts are still being written. Returns how many
    /// were removed, so the caller can tell a full batch from the tail.
    async fn delete_logical_requests_before(
        &self,
        cutoff_ms: i64,
        batch: u32,
    ) -> Result<u64, UsageRepositoryError>;

    /// Delete up to `batch` tracking-gap buckets that end at or before `cutoff_ms`.
    async fn delete_tracking_gaps_before(
        &self,
        cutoff_ms: i64,
        batch: u32,
    ) -> Result<u64, UsageRepositoryError>;

    async fn load_catalog(&self) -> Result<Option<StoredCatalog>, UsageRepositoryError>;

    /// Replace the stored catalog atomically.
    async fn store_catalog(&self, catalog: &StoredCatalog) -> Result<(), UsageRepositoryError>;

    /// Record that a refresh ran without replacing the body: a `304`, or a
    /// failure with a safe reason code. A no-op while no catalog is stored,
    /// since "never fetched" is already visible from [`Self::load_catalog`].
    async fn record_catalog_check(
        &self,
        checked_at_ms: i64,
        error_code: Option<&str>,
    ) -> Result<(), UsageRepositoryError>;
}

/// A logical request as stored, including whichever terminal fields are set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredLogicalRequest {
    pub start: LogicalRequestStart,
    pub status: LogicalStatus,
    pub completed_at_ms: Option<i64>,
    pub execution: Option<ExecutionOutcome>,
    pub delivery: Option<DeliveryOutcome>,
    pub final_attempt_id: Option<String>,
    pub tracking: TrackingState,
    pub state_version: u32,
}
