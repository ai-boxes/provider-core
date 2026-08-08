//! Observed-usage facts: lifecycle status, price resolution and catalog cost.
//!
//! The shared vocabulary this builds on ([`provider_core::usage::TokenMetric`],
//! [`provider_core::usage::UsageContractSnapshot`] and friends) lives in
//! `provider-core` so drivers and the protocol layer can produce observations
//! without depending on this crate. What lives here is everything downstream of
//! an observation: attempt/logical status, money, price resolution and cost.
//!
//! Money is exact fixed-point throughout, and an absent price or quantity always
//! degrades a cost to `partial`/`unavailable` — it is never rendered as zero.

mod attempt;
mod catalog;
mod cost;
mod lifecycle;
mod money;
mod price;
mod query;
mod refresh;
mod repository;
mod retention;
#[cfg(test)]
mod tests_support;
mod tracking;
mod writer;

pub use attempt::{
    AttemptSequence, DispatchEvidence, LogicalStatus, TrackingGapReason, TrackingState,
};
pub use catalog::{
    CatalogParseError, CatalogPrices, CatalogSnapshot, MAX_CATALOG_BYTES, canonical_model_pricing,
    component_prices_from_model_pricing, context_price_tiers_from_model_pricing, parse_unit_price,
};
pub use cost::{
    CALCULATOR_VERSION, CostReason, CostStatus, ObservedCatalogCost, compute_observed_catalog_cost,
};
pub use lifecycle::{DeliveryOutcome, ExecutionOutcome, merge_logical_terminal};
pub use money::{AMOUNT_SCALE, PRICE_SCALE, UnitPrice, UsdAtoms, component_cost_atoms};
pub use price::{
    CatalogInlinePriceRecordV1, ComponentPrices, ContextPriceTier, InlinePriceRecord,
    ModelInlinePriceRecordV2, PriceResolution,
};
pub use query::{
    ATOM_SPLIT, AttributionBasis, CacheTotals, CostTotals, MAX_PAGE_SIZE, MAX_QUERY_RANGE,
    ProviderHealthSummary, RequestCursor, RequestPage, RequestSummary, TimeRange, TimeRangeError,
    TokenTotals, UsageFilterOptions, UsageOverview, UsageQuery, UsageScope, recombine_atoms,
};
pub use refresh::{
    CatalogFetch, CatalogFetchError, CatalogRefresher, CatalogSource, DEFAULT_REFRESH_PERIOD,
    MODELS_DEV_URL, RefreshOutcome, content_revision, reason,
};
pub use repository::{
    AttemptFacts, LogicalRequestStart, LogicalRequestTerminal, LogicalWriteOutcome,
    QuotaLedgerEntry, StoredCatalog, StoredLogicalRequest, UsageRepository, UsageRepositoryError,
};
pub use retention::{
    DEFAULT_RETENTION, DEFAULT_RETENTION_BATCH, DEFAULT_RETENTION_PERIOD, RetentionReport,
    RetentionWorker,
};
pub use tracking::{
    AttemptSpec, AttemptTracker, ClockMs, LogicalTracker, SpendObserver, UsageTracking,
    system_clock_ms,
};
pub use writer::{
    DEFAULT_QUOTA_QUEUE, DEFAULT_WRITE_QUEUE, GAP_BUCKET_MS, QuotaLedgerPermit, QuotaLedgerReceipt,
    QuotaLedgerWriter, SubmitOutcome, UsageFact, UsageWrite, UsageWriter, gap_bucket,
};
