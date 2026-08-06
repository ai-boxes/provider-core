//! Narrow usage contracts shared across the execution layers.
//!
//! Drivers select a verified [`UsageContractSnapshot`] for their provider, the
//! protocol layer decodes a response and produces a
//! [`ProviderUsageObservation`] under that contract, and the usage layer turns
//! observations into persisted facts and cost. Only the vocabulary they all need
//! lives here: no database, price catalog, cost, or dashboard concern.

mod cache;
mod contract;
mod normalize;
mod raw;
mod token;
mod tracking;

pub use cache::{
    CacheCapability, CacheEligibility, CacheHit, CacheReportingExpectation,
    counts_in_reporting_coverage, hit_from_cache_read,
};
pub use contract::{
    PricingContextBasis, PricingMode, TokenInclusionRules, TotalSource, UsageContractSnapshot,
};
pub use normalize::normalize_usage;
pub use raw::RawUsageFields;
pub use token::{
    BillableComponentCode, BillableObservation, BillableUnit, NormalizationWarning,
    ProviderUsageObservation, TokenMetric, TokenUnknownReason,
};
pub use tracking::{AttemptTracking, ProviderUsageProfile, RequestTracking};
