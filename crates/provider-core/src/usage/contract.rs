//! The usage contract fixed for an attempt before its response is read.
//!
//! The contract is assembled at attempt start from a per-provider-kind constant
//! plus the request; the response never edits it. It is what makes token
//! normalization deterministic: whether the main input already includes cache
//! tokens, whether reasoning sits inside output, and where a total may come
//! from are decided here, not re-guessed while reading usage.

use serde::{Deserialize, Serialize};

use super::cache::{CacheCapability, CacheEligibility, CacheReportingExpectation};

/// How a provider's raw token fields include one another. Normalization applies
/// these rules instead of inferring inclusion from which fields happen to be
/// present.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenInclusionRules {
    /// The main input count already contains cache read/write tokens, so they
    /// must be split out rather than added again.
    pub input_includes_cache: bool,
    /// Uncached input, cache read, and cache write are mutually exclusive, so
    /// effective input may be summed from them.
    pub input_categories_mutually_exclusive: bool,
    /// Reasoning tokens are already counted inside output, so they must not be
    /// priced as additional output.
    pub reasoning_included_in_output: bool,
    /// Whether reasoning tokens are a field this provider/model reports at all.
    /// `false` makes the metric not-applicable rather than not-reported.
    pub reasoning_applicable: bool,
    /// Whether audio token fields apply to this provider/model.
    pub audio_applicable: bool,
    /// Whether this provider reports a separate cache-write (cache creation) count.
    pub cache_write_applicable: bool,
    /// Where a total token count may legitimately come from.
    pub total_source: TotalSource,
}

/// Where a `total_tokens` value is allowed to originate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TotalSource {
    /// The provider reports a total explicitly.
    Reported,
    /// The contract allows an unambiguous derived sum at this rule version.
    DerivedSum { rule_version: u16 },
    /// No total is available and none may be invented.
    Unavailable,
}

/// How `pricing_context_tokens` (used only to pick a context price tier) is
/// derived for this provider. `Unknown` forbids guessing a tier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingContextBasis {
    /// Tier selection uses the effective input token count.
    EffectiveInput,
    /// No reliable basis; a tiered price cannot be selected.
    Unknown,
}

/// A request mode/modifier that can change price, fixed before dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingMode {
    /// No price-affecting modifier applies; base prices are used.
    Default,
    /// A modifier may apply but could not be determined; cost is partial.
    Unknown,
}

/// The immutable contract fixed for one attempt before its response is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsageContractSnapshot {
    pub contract_version: u16,
    pub normalization_version: u16,
    pub inclusion: TokenInclusionRules,
    pub cache_capability: CacheCapability,
    pub cache_eligibility: CacheEligibility,
    pub cache_reporting_expectation: CacheReportingExpectation,
    pub pricing_context_basis: PricingContextBasis,
    pub pricing_mode: PricingMode,
}
