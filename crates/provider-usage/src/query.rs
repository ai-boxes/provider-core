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

use crate::{money::UsdAtoms, repository::UsageRepositoryError};

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
    pub logical_requests: u64,
    pub tokens: TokenTotals,
    pub cache: CacheTotals,
    pub cost: CostTotals,
}

/// One row of the request list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestSummary {
    pub request_id: String,
    pub api_key_id: Option<String>,
    pub api_key_label: Option<String>,
    pub api_key_group_label: Option<String>,
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

#[async_trait]
pub trait UsageQuery: Send + Sync {
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
