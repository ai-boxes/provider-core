//! Reading usage facts back out.
//!
//! Separate from [`crate::UsageRepository`] because the read side has different
//! obligations than the write side, and two of them are load-bearing:
//!
//! 1. **Owner scoping is structural.** Every query takes a [`UsageScope`], so
//!    there is no way to ask a question that spans users. A read that could
//!    forget the filter would be an access-control bug waiting to happen.
//! 2. **Nothing is silently totalled.** A complete estimate, the known part of a
//!    partial one, and an unavailable one are three separate outputs. Adding them
//!    together would present an incomplete number as a complete one.

use std::time::Duration;

use async_trait::async_trait;

use crate::{LogicalStatus, money::UsdAtoms, repository::UsageRepositoryError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaEstimateCompleteness {
    Complete,
    LowerBound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaLimitEstimatePoint {
    pub account_id: String,
    pub group_key: String,
    pub metric_key: String,
    pub metric_position: u32,
    pub period_kind: String,
    pub duration_seconds: Option<i64>,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    pub next_window_end_ms: Option<i64>,
    pub sampling_incomplete: bool,
    pub observed_at_ms: i64,
    pub used_hundredths: u64,
    pub observed_cost: UsdAtoms,
    pub estimated_limit_cost: UsdAtoms,
    pub completeness: QuotaEstimateCompleteness,
    pub priced_attempts: u64,
    pub dispatched_attempts: u64,
}

/// Longest range a single query may cover.
///
/// Tied to the retention window rather than picked separately: a wider range
/// would return silently truncated data that looks like a complete answer.
pub const MAX_QUERY_RANGE: Duration = crate::retention::DEFAULT_RETENTION;

/// A half-open UTC range, `[from, to)`, in unix milliseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeRange {
    pub from_ms: i64,
    pub to_ms: i64,
}

impl TimeRange {
    /// Reject a range that is empty, inverted, or wider than retention promises.
    pub fn new(from_ms: i64, to_ms: i64) -> Result<Self, TimeRangeError> {
        if to_ms <= from_ms {
            return Err(TimeRangeError::Empty);
        }
        let span = i64::try_from(MAX_QUERY_RANGE.as_millis())
            .expect("maximum usage query range must fit i64 milliseconds");
        if to_ms.saturating_sub(from_ms) > span {
            return Err(TimeRangeError::TooWide);
        }
        Ok(Self { from_ms, to_ms })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeRangeError {
    Empty,
    TooWide,
}

/// The scope of one query. Constructed per request, always with an owner.
#[derive(Clone, Debug)]
pub struct UsageScope {
    pub owner_user_id: String,
    /// Narrow to a single API key, when asked.
    pub api_key_id: Option<String>,
    /// Narrow the request list to the model captured on the request.
    pub client_model: Option<String>,
    /// Narrow the request list to the group captured on the request.
    pub group_label: Option<String>,
    pub range: TimeRange,
}

/// Observed dispatched usage for one Provider account in a half-open window.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccountWindowUsage {
    pub tokens: u64,
    pub dispatched_attempts: u64,
    pub complete_cost_attempts: u64,
    pub cost: CostTotals,
}

impl AccountWindowUsage {
    /// Catalog cost is only returned when every dispatched attempt in the window
    /// was fully priced. A partial sum would understate the window and inflate
    /// the implied quota.
    #[must_use]
    pub fn complete_cost_atoms(self) -> Option<UsdAtoms> {
        (self.dispatched_attempts > 0 && self.complete_cost_attempts == self.dispatched_attempts)
            .then_some(self.cost.atoms)
            .flatten()
    }
}

/// Token sums over a scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TokenTotals {
    pub cache_read_input: u64,
    pub effective_input: u64,
    pub output: u64,
}

/// Cache token totals over a scope.
///
/// The denominator includes only attempts that reported both effective input
/// and cache-read tokens. Missing cache detail is unknown, never a zero-token
/// miss. This makes the displayed rate a token ratio rather than the share of
/// requests that happened to contain any cache hit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheTotals {
    pub reported_input_tokens: u64,
    pub cache_read_input_tokens: u64,
}

/// Cost over attempts that were fully priced from the observed catalog.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CostTotals {
    pub atoms: Option<UsdAtoms>,
}

/// Everything an overview shows.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UsageOverview {
    /// Terminal logical requests that made at least one real upstream call.
    /// This count is independent of whether authoritative token usage exists.
    pub logical_requests: u64,
    pub tokens: TokenTotals,
    pub cache: CacheTotals,
    pub cost: CostTotals,
}

/// One row of the request list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestSummary {
    pub request_id: String,
    pub status: LogicalStatus,
    pub api_key_id: Option<String>,
    pub api_key_label: Option<String>,
    pub api_key_group_labels: Option<Vec<String>>,
    /// `None` only for records created before endpoint tracking was introduced.
    pub endpoint: Option<crate::repository::EndpointProtocol>,
    pub client_model_raw: Option<String>,
    pub reasoning_effort: Option<String>,
    pub started_at_ms: i64,
    pub completed_at_ms: i64,
    pub first_token_at_ms: Option<i64>,
    pub tokens: TokenTotals,
    pub cost: CostTotals,
}

/// A stable position in the request list, ordered by `(completed_at DESC, id DESC)`.
///
/// Keyset rather than an offset, so a row arriving during paging cannot make the
/// reader skip or repeat one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestCursor {
    pub completed_at_ms: i64,
    pub request_id: String,
}

/// A page of requests, plus where to continue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestPage {
    pub requests: Vec<RequestSummary>,
    /// Total requests in the complete filtered scope, independent of the cursor.
    pub total: u64,
    /// `None` when the page reached the end of the range.
    pub next: Option<RequestCursor>,
}

/// Largest page a caller may ask for.
pub const MAX_PAGE_SIZE: u32 = 200;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageFilterOptions {
    pub client_models: Vec<String>,
    pub group_labels: Vec<String>,
}

/// Actual terminal outcomes for requests whose final attempt used one Provider
/// account. Shared Provider health intentionally aggregates across owners; the
/// management layer authorizes which visible account ids may be requested.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHealthSummary {
    pub account_id: String,
    pub requests: u64,
    pub successes: u64,
    pub failures: u64,
}

/// Fleet-wide request health and latency for the operations dashboard.
///
/// The request counts use the same final-dispatched logical-request contract as
/// [`ProviderHealthSummary`]. Latency samples are intentionally separate from
/// those counts: a dispatched incomplete or canceled request may still have a
/// useful first-token or duration observation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OpsOverview {
    pub requests: u64,
    pub successes: u64,
    pub failures: u64,
    pub tokens: TokenTotals,
    pub cost: CostTotals,
    pub avg_response_ms: Option<u64>,
    pub ttft_p50_ms: Option<u64>,
    pub failure_layers: OpsFailureLayers,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OpsFailureLayers {
    pub upstream_failed_requests: u64,
    pub zero_dispatch_logical_failures: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OpsAccountMetrics {
    pub account_id: String,
    pub requests: u64,
    pub successes: u64,
    pub failures: u64,
    pub ttft_p50_ms: Option<u64>,
    pub duration_p95_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpsSeries {
    pub bucket_ms: i64,
    pub buckets: Vec<i64>,
    pub requests: Vec<u64>,
    pub failures: Vec<u64>,
}

impl Default for OpsSeries {
    fn default() -> Self {
        Self {
            bucket_ms: 60 * 60 * 1000,
            buckets: Vec::new(),
            requests: Vec::new(),
            failures: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OpsProviderMetrics {
    pub accounts: Vec<OpsAccountMetrics>,
    pub series: OpsSeries,
}

/// Read-side contract for the super-admin operations surface.
///
/// Unlike [`UsageQuery`], these methods never accept an owner scope. The
/// management layer supplies the account IDs that are visible to the caller;
/// the query layer then aggregates across all owners for those accounts.
#[async_trait]
pub trait OpsQuery: Send + Sync {
    async fn ops_overview(
        &self,
        account_ids: &[String],
        range: TimeRange,
        include_unattributed_zero_dispatch: bool,
    ) -> Result<OpsOverview, UsageRepositoryError>;

    async fn ops_providers(
        &self,
        account_ids: &[String],
        range: TimeRange,
    ) -> Result<OpsProviderMetrics, UsageRepositoryError>;

    /// Token totals for a range without loading latency or model facts.
    async fn ops_total_tokens(
        &self,
        account_ids: &[String],
        range: TimeRange,
    ) -> Result<TokenTotals, UsageRepositoryError>;

    /// Dispatched attempt usage for one account in a window.
    async fn account_window_usage(
        &self,
        account_id: &str,
        range: TimeRange,
    ) -> Result<AccountWindowUsage, UsageRepositoryError>;

    async fn provider_quota_estimates(
        &self,
        account_ids: &[String],
        range: TimeRange,
    ) -> Result<Vec<QuotaLimitEstimatePoint>, UsageRepositoryError>;
}

#[async_trait]
pub trait UsageQuery: OpsQuery + Send + Sync {
    /// Totals over the scope.
    async fn overview(&self, scope: &UsageScope) -> Result<UsageOverview, UsageRepositoryError>;

    /// Distinct request-list filter values over the complete time range.
    async fn filter_options(
        &self,
        scope: &UsageScope,
    ) -> Result<UsageFilterOptions, UsageRepositoryError>;

    /// Actual terminal outcomes for visible Provider accounts over a recent
    /// window. This is intentionally not owner-scoped because a shared
    /// Provider's operational health must include all internal users.
    async fn provider_health(
        &self,
        account_ids: &[String],
        range: TimeRange,
    ) -> Result<Vec<ProviderHealthSummary>, UsageRepositoryError>;

    /// One page of requests, newest first.
    async fn requests(
        &self,
        scope: &UsageScope,
        after: Option<&RequestCursor>,
        limit: u32,
    ) -> Result<RequestPage, UsageRepositoryError>;

    /// One request's final attempt, or `None` when it does not exist for this
    /// owner. The two are deliberately indistinguishable to the caller.
    async fn request_attempt(
        &self,
        scope: &UsageScope,
        request_id: &str,
    ) -> Result<Option<crate::repository::AttemptFacts>, UsageRepositoryError>;
}

/// Recombine a cost sum that SQL had to split to stay exact.
///
/// `SUM(cost_atoms)` overflows a 64-bit accumulator at about `$92,233`, which a
/// busy month can pass. Summing `atoms / 10^6` and `atoms % 10^6` separately keeps
/// both accumulators far from the limit, and this puts the exact total back
/// together with no rounding anywhere.
#[must_use]
pub const fn recombine_atoms(high: i64, low: i64) -> UsdAtoms {
    UsdAtoms::from_atoms(high as i128 * ATOM_SPLIT + low as i128)
}

/// The divisor SQL splits a cost sum by. Must match [`recombine_atoms`].
pub const ATOM_SPLIT: i128 = 1_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_must_be_non_empty_and_within_retention() {
        assert!(TimeRange::new(0, 1).is_ok());
        assert_eq!(TimeRange::new(5, 5), Err(TimeRangeError::Empty));
        assert_eq!(TimeRange::new(5, 4), Err(TimeRangeError::Empty));
        let span = i64::try_from(MAX_QUERY_RANGE.as_millis()).expect("span fits");
        assert!(TimeRange::new(0, span).is_ok());
        assert_eq!(TimeRange::new(0, span + 1), Err(TimeRangeError::TooWide));
    }
}
