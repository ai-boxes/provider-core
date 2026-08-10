//! The verified Codex (OpenAI Responses) usage contract.
//!
//! Field semantics are taken from the shape Codex actually returns, cross-checked
//! against a working Codex proxy implementation:
//!
//! - `input_tokens` is the **total** input and already contains the cached
//!   portion reported at `input_tokens_details.cached_tokens`, so the uncached
//!   part must be derived by subtraction, never by addition.
//! - `output_tokens` already contains
//!   `output_tokens_details.reasoning_tokens`, so reasoning must not be priced
//!   again on top of output.
//! - Codex prompt caching is automatic and its cache writes are neither reported
//!   nor billed, so cache-write does not apply. Other upstreams speaking this same
//!   wire shape do send a cache-write counter, which is why extraction still reads
//!   it and this contract — not the extractor — rules it out.
//! - `input_tokens_details.image_tokens` bills at its own rate while being counted
//!   inside `input_tokens`, so it cannot be folded into the text input category.
//! - `total_tokens` is reported directly.
//!
//! Cache capability and reporting expectation are constants of this provider
//! kind; only eligibility and the price-affecting request mode vary per request,
//! so the caller supplies those.

use provider_core::usage::{
    CacheCapability, CacheEligibility, CacheReportingExpectation, PricingContextBasis, PricingMode,
    TokenInclusionRules, TotalSource, UsageContractSnapshot,
};

/// Version of this contract's field semantics.
pub const CODEX_CONTRACT_VERSION: u16 = 1;

/// Version of the derivation rules applied on top of it.
pub const CODEX_NORMALIZATION_VERSION: u16 = 1;

/// Build the Codex usage contract for one attempt.
#[must_use]
pub const fn codex_usage_contract(
    cache_eligibility: CacheEligibility,
    pricing_mode: PricingMode,
) -> UsageContractSnapshot {
    UsageContractSnapshot {
        contract_version: CODEX_CONTRACT_VERSION,
        normalization_version: CODEX_NORMALIZATION_VERSION,
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
    use super::*;
    use provider_core::usage::{
        BillableComponentCode, BillableObservation, BillableUnit, CacheHit, NormalizationWarning,
        RawUsageFields, TokenMetric, TokenUnknownReason, hit_from_cache_read, normalize_usage,
    };
    use serde_json::Value;

    // `usage_fixtures/` holds every captured Codex terminal, including the shapes
    // no test reads: they are the recorded evidence for the wire contract in
    // `codex_usage_contract`, which is why they stay on disk after the tests that
    // merely restated them were removed.
    const CACHE_HIT: &str = include_str!("usage_fixtures/completed_cache_hit.json");
    const NO_CACHE_DETAILS: &str =
        include_str!("usage_fixtures/completed_without_cache_details.json");
    const CACHED_EXCEEDS_INPUT: &str =
        include_str!("usage_fixtures/completed_cached_exceeds_input.json");
    const IMAGE_INPUT: &str = include_str!("usage_fixtures/completed_with_image_input.json");

    /// Pull the `response.usage` object out of a captured Codex terminal event.
    /// Returns `None` when the terminal carried no usage at all.
    fn usage_fields(fixture: &str) -> Option<RawUsageFields> {
        let event: Value = serde_json::from_str(fixture).expect("fixture is valid JSON");
        let usage = event.get("response")?.get("usage")?;
        Some(RawUsageFields::from_responses_usage(usage))
    }

    fn contract() -> UsageContractSnapshot {
        codex_usage_contract(CacheEligibility::Eligible, PricingMode::Default)
    }

    #[test]
    fn cache_hit_splits_input_without_double_counting() {
        let observed = normalize_usage(usage_fields(CACHE_HIT), &contract());

        // input_tokens (12480) already includes cached_tokens (11776).
        assert_eq!(
            observed.effective_input_tokens,
            TokenMetric::ProviderReported { value: 12_480 }
        );
        assert_eq!(
            observed.cache_read_input_tokens,
            TokenMetric::ProviderReported { value: 11_776 }
        );
        assert_eq!(
            observed.uncached_input_tokens,
            TokenMetric::DerivedFromReported {
                value: 704,
                rule_version: CODEX_NORMALIZATION_VERSION
            },
            "uncached input must be derived by subtraction, not by adding cache back"
        );
        assert_eq!(
            observed.output_tokens,
            TokenMetric::ProviderReported { value: 320 }
        );
        assert_eq!(
            observed.reasoning_tokens,
            TokenMetric::ProviderReported { value: 192 }
        );
        assert_eq!(
            observed.total_tokens,
            TokenMetric::ProviderReported { value: 12_800 }
        );
        assert_eq!(
            hit_from_cache_read(observed.cache_read_input_tokens),
            CacheHit::Hit
        );
        assert!(observed.warnings.is_empty());
    }

    #[test]
    fn absent_cache_details_is_not_reported_not_a_miss() {
        let observed = normalize_usage(usage_fields(NO_CACHE_DETAILS), &contract());

        assert_eq!(
            observed.cache_read_input_tokens,
            TokenMetric::NotReported,
            "a missing cache field must not be read as an explicit zero"
        );
        assert_eq!(
            hit_from_cache_read(observed.cache_read_input_tokens),
            CacheHit::Excluded,
            "not-reported is neither a hit nor a miss"
        );
        // Input is known but its cached split is not, so the categories cannot
        // be separated.
        assert_eq!(
            observed.uncached_input_tokens,
            TokenMetric::Unknown {
                reason: TokenUnknownReason::Indeterminate
            }
        );
        assert_eq!(
            observed.effective_input_tokens,
            TokenMetric::ProviderReported { value: 512 }
        );
    }

    #[test]
    fn cached_exceeding_input_is_a_conflict_not_a_clamp() {
        let observed = normalize_usage(usage_fields(CACHED_EXCEEDS_INPUT), &contract());

        assert_eq!(
            observed.uncached_input_tokens,
            TokenMetric::Unknown {
                reason: TokenUnknownReason::InvalidReported
            },
            "clamping to zero would invent a number"
        );
        assert!(
            observed
                .warnings
                .contains(&NormalizationWarning::FieldConflict)
        );
        // The conflict is contained: other fields stay usable.
        assert_eq!(
            observed.output_tokens,
            TokenMetric::ProviderReported { value: 32 }
        );
    }

    #[test]
    fn separately_priced_image_tokens_become_a_billable_observation() {
        // `input_tokens` includes image tokens, but images bill at their own rate.
        // Pricing all 3200 input tokens at the text rate would be wrong, so the
        // image quantity is preserved as an unmodeled billable component.
        let observed = normalize_usage(usage_fields(IMAGE_INPUT), &contract());

        assert_eq!(
            observed.billable,
            vec![BillableObservation {
                component_code: BillableComponentCode::ImageInputTokens,
                unit: BillableUnit::Tokens,
                quantity: 1800,
            }]
        );
    }
}
