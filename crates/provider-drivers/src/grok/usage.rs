//! The Grok (xAI) usage contract.
//!
//! Grok speaks the OpenAI Responses wire format, so usage arrives at
//! `response.usage` in the same shape Codex uses and the existing extractor reads
//! it unchanged. What this file declares is the *semantics* of those numbers, and
//! that is where the two providers could still differ.
//!
//! Evidence, and the limits of it. Two facts are corroborated by three independent
//! implementations; one is inferred, and one is deliberately declared unknown.
//!
//! - **Field shape — corroborated.** `CLIProxyAPI` routes xAI terminals through
//!   the very same `ParseCodexUsage` helper it uses for Codex
//!   (`internal/runtime/executor/xai_executor.go`), so it never needed an
//!   xAI-specific reader. `OmniRoute` reads the same paths in its shared Responses
//!   extractor.
//! - **`input_tokens` already contains the cached portion — corroborated.**
//!   `OmniRoute`'s cost calculator subtracts cache from input before pricing it,
//!   with a comment saying the input figure already includes it. Adding cache on
//!   top would double-count.
//! - **`output_tokens` already contains `reasoning_tokens` — inferred, not
//!   measured.** This is the OpenAI Responses convention, which xAI is
//!   deliberately mimicking, and it is what the Codex fixtures show. No captured
//!   Grok terminal has confirmed it here. If the inference is wrong the reported
//!   total stops equalling `input + output`, `normalize_usage` raises
//!   `FieldConflict`, and the cost turns partial with `usage_field_conflict` —
//!   which is why shipping the inference is acceptable: being wrong is visible
//!   rather than silent. Notably `OmniRoute` prices reasoning *in addition to* the
//!   full output, which double-counts under this same convention; a working
//!   implementation is corroboration, not proof.
//! - **Cache reporting expectation — `Expected`.** models.dev prices `cache_read`
//!   for Grok models, and live Responses traffic reports
//!   `input_tokens_details.cached_tokens` on completed terminals. Treating a
//!   missing report as a miss is therefore the honest coverage rule.
//! - **No cache-write and no audio.** Neither appears in any of the three
//!   implementations' xAI paths, so both are declared inapplicable. A non-zero
//!   value for either still surfaces as `FieldConflict` rather than being dropped.

use provider_core::usage::{
    CacheCapability, CacheEligibility, CacheReportingExpectation, PricingContextBasis, PricingMode,
    TokenInclusionRules, TotalSource, UsageContractSnapshot,
};

/// Version of this contract's field semantics.
pub const GROK_CONTRACT_VERSION: u16 = 2;

/// Version of the derivation rules applied on top of it.
pub const GROK_NORMALIZATION_VERSION: u16 = 1;

/// Build the Grok usage contract for one attempt.
#[must_use]
pub const fn grok_usage_contract(
    cache_eligibility: CacheEligibility,
    pricing_mode: PricingMode,
) -> UsageContractSnapshot {
    UsageContractSnapshot {
        contract_version: GROK_CONTRACT_VERSION,
        normalization_version: GROK_NORMALIZATION_VERSION,
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
        cache_eligibility,
        cache_reporting_expectation: CacheReportingExpectation::Expected,
        pricing_context_basis: PricingContextBasis::EffectiveInput,
        pricing_mode,
    }
}

#[cfg(test)]
mod tests {
    use provider_core::usage::{
        CacheEligibility, CacheReportingExpectation, PricingMode, TokenMetric,
        counts_in_reporting_coverage,
    };
    use provider_core::{RawUsageFields, normalize_usage};

    use super::grok_usage_contract;

    #[test]
    fn responses_cache_read_is_recorded_as_coverage_evidence() {
        let contract = grok_usage_contract(CacheEligibility::Eligible, PricingMode::Default);
        assert_eq!(
            contract.cache_reporting_expectation,
            CacheReportingExpectation::Expected
        );
        assert!(counts_in_reporting_coverage(
            contract.cache_capability,
            contract.cache_eligibility,
            contract.cache_reporting_expectation,
        ));

        let fields = RawUsageFields::from_responses_usage(&serde_json::json!({
            "input_tokens": 120,
            "input_tokens_details": { "cached_tokens": 100 },
            "output_tokens": 8,
            "total_tokens": 128,
        }));
        let observation = normalize_usage(Some(fields), &contract);
        assert_eq!(
            observation.cache_read_input_tokens,
            TokenMetric::ProviderReported { value: 100 }
        );
    }

    #[test]
    fn missing_cache_read_stays_unreported_and_not_a_fabricated_zero() {
        let contract = grok_usage_contract(CacheEligibility::Eligible, PricingMode::Default);
        let fields = RawUsageFields::from_responses_usage(&serde_json::json!({
            "input_tokens": 120,
            "output_tokens": 8,
            "total_tokens": 128,
        }));
        let observation = normalize_usage(Some(fields), &contract);
        assert_eq!(
            observation.cache_read_input_tokens,
            TokenMetric::NotReported
        );
    }
}
