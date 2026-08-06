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
//! - **Cache reporting expectation — declared `Unknown`.** models.dev prices
//!   `cache_read` for Grok models, so caching exists and is billable, but nothing
//!   observed says a successful terminal always reports it. `Unknown` keeps these
//!   attempts out of the cache-coverage denominator instead of turning every
//!   silent response into a fabricated miss.
//! - **No cache-write and no audio.** Neither appears in any of the three
//!   implementations' xAI paths, so both are declared inapplicable. A non-zero
//!   value for either still surfaces as `FieldConflict` rather than being dropped.

use provider_core::usage::{
    CacheCapability, CacheEligibility, CacheReportingExpectation, PricingContextBasis, PricingMode,
    TokenInclusionRules, TotalSource, UsageContractSnapshot,
};

/// Version of this contract's field semantics.
pub const GROK_CONTRACT_VERSION: u16 = 1;

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
            total_source: TotalSource::Reported,
        },
        cache_capability: CacheCapability::Supported,
        cache_eligibility,
        // Not `Expected`: see the module header. Claiming an expectation we have
        // not observed would turn every unreported cache read into a miss.
        cache_reporting_expectation: CacheReportingExpectation::Unknown,
        pricing_context_basis: PricingContextBasis::EffectiveInput,
        pricing_mode,
    }
}
