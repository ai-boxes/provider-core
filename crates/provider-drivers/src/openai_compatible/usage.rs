//! Conservative usage semantics for OpenAI-compatible Chat Completions.

use provider_core::usage::{
    CacheCapability, CacheEligibility, CacheReportingExpectation, PricingContextBasis, PricingMode,
    TokenInclusionRules, TotalSource, UsageContractSnapshot,
};

pub const OPENAI_COMPATIBLE_CONTRACT_VERSION: u16 = 2;
pub const OPENAI_COMPATIBLE_NORMALIZATION_VERSION: u16 = 2;

#[must_use]
pub const fn openai_compatible_usage_contract() -> UsageContractSnapshot {
    UsageContractSnapshot {
        contract_version: OPENAI_COMPATIBLE_CONTRACT_VERSION,
        normalization_version: OPENAI_COMPATIBLE_NORMALIZATION_VERSION,
        inclusion: TokenInclusionRules {
            input_includes_cache: true,
            input_categories_mutually_exclusive: false,
            reasoning_included_in_output: true,
            reasoning_applicable: true,
            audio_applicable: true,
            cache_write_applicable: false,
            missing_cache_read_means_zero: true,
            total_source: TotalSource::Reported,
        },
        cache_capability: CacheCapability::Unknown,
        cache_eligibility: CacheEligibility::Unknown,
        cache_reporting_expectation: CacheReportingExpectation::Unknown,
        pricing_context_basis: PricingContextBasis::EffectiveInput,
        pricing_mode: PricingMode::Default,
    }
}

#[cfg(test)]
mod tests {
    use provider_core::usage::{RawUsageFields, TokenMetric, normalize_usage};

    use super::openai_compatible_usage_contract;

    #[test]
    fn chat_usage_normalizes_prompt_and_completion_tokens() {
        let fields = RawUsageFields::from_chat_completions_usage(&serde_json::json!({
            "prompt_tokens": 20,
            "completion_tokens": 7,
            "total_tokens": 27
        }));
        let observation = normalize_usage(Some(fields), &openai_compatible_usage_contract());
        assert_eq!(
            observation.effective_input_tokens,
            TokenMetric::ProviderReported { value: 20 }
        );
        assert_eq!(
            observation.output_tokens,
            TokenMetric::ProviderReported { value: 7 }
        );
        assert_eq!(
            observation.total_tokens,
            TokenMetric::ProviderReported { value: 27 }
        );
        assert_eq!(
            observation.cache_read_input_tokens,
            TokenMetric::DerivedFromReported {
                value: 0,
                rule_version: super::OPENAI_COMPATIBLE_NORMALIZATION_VERSION,
            }
        );
        assert_eq!(
            observation.uncached_input_tokens,
            TokenMetric::DerivedFromReported {
                value: 20,
                rule_version: super::OPENAI_COMPATIBLE_NORMALIZATION_VERSION,
            }
        );
    }
}
