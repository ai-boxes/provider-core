//! Cache dimensions modeled separately so a hit rate is never shown without the
//! coverage that qualifies it.
//!
//! Capability and reporting expectation come from a per-provider-kind contract
//! constant; eligibility is the only dimension that varies per request. A
//! sample the current response cannot qualify (`Unknown` capability) is excluded
//! from the denominator, so a single response can never select itself in and
//! bias the rate.

use serde::{Deserialize, Serialize};

use super::token::TokenMetric;

/// Whether the provider/model can cache prompt input at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheCapability {
    Supported,
    Unsupported,
    Unknown,
}

/// Whether the current request asked for / could use caching.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheEligibility {
    Eligible,
    NotRequested,
    NotApplicable,
    Unknown,
}

/// Whether a successful terminal is expected to report cache usage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheReportingExpectation {
    Expected,
    NotExpected,
    Unknown,
}

/// A per-sample cache outcome derived only from the reported cache-read count.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheHit {
    Hit,
    Miss,
    /// No hit/miss can be derived (not reported, derived, or unknown).
    Excluded,
}

/// Derive hit/miss from the cache-read metric. Only an explicitly reported value
/// yields a verdict: `> 0` is a hit, an explicit `0` is a miss. Every other
/// variant is `Excluded` — a derived or unknown value is not evidence of either.
#[must_use]
pub const fn hit_from_cache_read(cache_read: TokenMetric) -> CacheHit {
    match cache_read {
        TokenMetric::ProviderReported { value } if value > 0 => CacheHit::Hit,
        TokenMetric::ProviderReported { value: 0 } => CacheHit::Miss,
        _ => CacheHit::Excluded,
    }
}

/// Whether a sample belongs in the cache reporting-coverage denominator.
///
/// The caller is still responsible for confirming a successful usage-bearing
/// terminal; this predicate only checks the locked contract dimensions.
#[must_use]
pub const fn counts_in_reporting_coverage(
    capability: CacheCapability,
    eligibility: CacheEligibility,
    expectation: CacheReportingExpectation,
) -> bool {
    matches!(capability, CacheCapability::Supported)
        && matches!(eligibility, CacheEligibility::Eligible)
        && matches!(expectation, CacheReportingExpectation::Expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage::token::TokenUnknownReason;

    #[test]
    fn non_reported_variants_are_excluded_not_miss() {
        assert_eq!(
            hit_from_cache_read(TokenMetric::NotReported),
            CacheHit::Excluded
        );
        assert_eq!(
            hit_from_cache_read(TokenMetric::DerivedFromReported {
                value: 0,
                rule_version: 1
            }),
            CacheHit::Excluded
        );
        assert_eq!(
            hit_from_cache_read(TokenMetric::Unknown {
                reason: TokenUnknownReason::Indeterminate
            }),
            CacheHit::Excluded
        );
    }
}
