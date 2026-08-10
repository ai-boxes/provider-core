//! Turn raw provider counts into a normalized observation under a locked contract.
//!
//! The contract — not the shape of whatever fields happen to be present — decides
//! how the numbers relate. That is the difference between this and the usual
//! "guess from which key exists" approach: the same function serves a provider
//! whose input already includes cache tokens and one whose input categories are
//! mutually exclusive, with no provider-specific branch here.
//!
//! Nothing in this module can fail: a malformed or conflicting field degrades
//! that one metric to `Unknown` with a warning and never breaks the response.

use super::cache::CacheCapability;
use super::contract::{PricingContextBasis, TotalSource, UsageContractSnapshot};
use super::raw::RawUsageFields;
use super::token::{
    BillableComponentCode, BillableObservation, BillableUnit, NormalizationWarning,
    ProviderUsageObservation, TokenMetric, TokenUnknownReason,
};

/// Classify one raw field. An absent-but-applicable field is `NotReported`, an
/// inapplicable one is `NotApplicable`, and a negative one is `Unknown`.
fn classify(
    raw: Option<i64>,
    applicable: bool,
    warnings: &mut Vec<NormalizationWarning>,
) -> TokenMetric {
    if !applicable {
        // A value the contract says cannot apply does not promote the field; it
        // is recorded as a conflict so the evidence is not lost.
        if raw.is_some_and(|value| value != 0) {
            push_unique(warnings, NormalizationWarning::FieldConflict);
        }
        return TokenMetric::NotApplicable;
    }
    match raw {
        None => TokenMetric::NotReported,
        Some(value) => match u64::try_from(value) {
            Ok(value) => TokenMetric::ProviderReported { value },
            Err(_) => {
                push_unique(warnings, NormalizationWarning::NegativeValue);
                TokenMetric::Unknown {
                    reason: TokenUnknownReason::InvalidReported,
                }
            }
        },
    }
}

fn push_unique(warnings: &mut Vec<NormalizationWarning>, warning: NormalizationWarning) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

/// Whether a reported total agrees with `effective_input + output`.
///
/// Both directions matter and mean different things. A total *larger* than the sum
/// means the provider metered something these categories do not cover, so a cost
/// built from them is an undercount. A total *smaller* means our reading
/// double-counts — the classic cause being an inclusion rule that says a
/// sub-category sits inside its parent when it does not.
///
/// Undecidable cases answer `true`: this is a contradiction detector, and a
/// missing operand is not a contradiction. Audio is a deliberate gate rather than
/// an addend — no contract has yet evidenced whether a provider counts audio
/// inside `input`/`output` or beside them, so any positive audio count means the
/// expected sum is not known and the check must stay silent.
fn total_reconciles(
    total: TokenMetric,
    effective_input: TokenMetric,
    output: TokenMetric,
    input_audio: TokenMetric,
    output_audio: TokenMetric,
) -> bool {
    if [input_audio, output_audio]
        .iter()
        .any(|metric| metric.known_value().is_some_and(|value| value > 0))
    {
        return true;
    }
    let (Some(total), Some(input), Some(output)) = (
        total.known_value(),
        effective_input.known_value(),
        output.known_value(),
    ) else {
        return true;
    };
    input.checked_add(output) == Some(total)
}

const fn indeterminate() -> TokenMetric {
    TokenMetric::Unknown {
        reason: TokenUnknownReason::Indeterminate,
    }
}

/// A metric's contribution to a sum. `NotApplicable` contributes a real zero;
/// anything else without a known value makes the sum impossible.
const fn sum_contribution(metric: TokenMetric) -> Option<u64> {
    match metric {
        TokenMetric::NotApplicable => Some(0),
        other => other.known_value(),
    }
}

/// Record a positive token quantity that is billed at its own rate and therefore
/// cannot be folded into a single token category. Keeping it here is what stops a
/// separately-priced quantity from being silently charged at the text rate: the
/// cost calculator sees an unmodeled component and reports `partial`.
fn push_billable_tokens(
    billable: &mut Vec<BillableObservation>,
    component_code: BillableComponentCode,
    raw: Option<i64>,
    warnings: &mut Vec<NormalizationWarning>,
) {
    let Some(value) = raw else { return };
    match u64::try_from(value) {
        // A reported zero means the component was not used; there is nothing to
        // flag and no reason to degrade the cost.
        Ok(0) => {}
        Ok(quantity) => billable.push(BillableObservation {
            component_code,
            unit: BillableUnit::Tokens,
            quantity,
        }),
        Err(_) => push_unique(warnings, NormalizationWarning::NegativeValue),
    }
}

/// Normalize one response's usage.
///
/// `fields` is `None` when no usage-bearing terminal was observed (EOF or error
/// before a terminal); every metric is then `Unknown` for that reason rather than
/// zero.
#[must_use]
pub fn normalize_usage(
    fields: Option<RawUsageFields>,
    contract: &UsageContractSnapshot,
) -> ProviderUsageObservation {
    let Some(fields) = fields else {
        let unknown = TokenMetric::Unknown {
            reason: TokenUnknownReason::NoUsageTerminal,
        };
        return ProviderUsageObservation {
            uncached_input_tokens: unknown,
            cache_read_input_tokens: unknown,
            cache_write_input_tokens: unknown,
            effective_input_tokens: unknown,
            output_tokens: unknown,
            reasoning_tokens: unknown,
            input_audio_tokens: unknown,
            output_audio_tokens: unknown,
            total_tokens: unknown,
            pricing_context_tokens: unknown,
            billable: Vec::new(),
            warnings: Vec::new(),
        };
    };

    let mut warnings = Vec::new();
    let inclusion = contract.inclusion;
    let rule_version = contract.normalization_version;

    let cache_readable = !matches!(contract.cache_capability, CacheCapability::Unsupported);
    let reported_input = classify(fields.input, true, &mut warnings);
    let cache_read = if cache_readable
        && fields.cache_read.is_none()
        && reported_input.known_value().is_some()
        && inclusion.missing_cache_read_means_zero
    {
        TokenMetric::DerivedFromReported {
            value: 0,
            rule_version,
        }
    } else {
        classify(fields.cache_read, cache_readable, &mut warnings)
    };
    let cache_write = classify(
        fields.cache_write,
        cache_readable && inclusion.cache_write_applicable,
        &mut warnings,
    );
    let output = classify(fields.output, true, &mut warnings);
    let reasoning = classify(
        fields.reasoning,
        inclusion.reasoning_applicable,
        &mut warnings,
    );
    let input_audio = classify(
        fields.input_audio,
        inclusion.audio_applicable,
        &mut warnings,
    );
    let output_audio = classify(
        fields.output_audio,
        inclusion.audio_applicable,
        &mut warnings,
    );

    let (uncached_input, effective_input) = if inclusion.input_includes_cache {
        // The reported input is the effective total; the uncached part is what
        // remains after removing the cached portion.
        let uncached = match (reported_input.known_value(), cache_read) {
            (Some(input), TokenMetric::NotApplicable) => {
                TokenMetric::ProviderReported { value: input }
            }
            (Some(input), read) => match read.known_value() {
                Some(cached) => match input.checked_sub(cached) {
                    Some(value) => TokenMetric::DerivedFromReported {
                        value,
                        rule_version,
                    },
                    None => {
                        // Cached exceeding total input is a contradiction; clamping
                        // it to zero would invent a number, so it stays unknown.
                        push_unique(&mut warnings, NormalizationWarning::FieldConflict);
                        TokenMetric::Unknown {
                            reason: TokenUnknownReason::InvalidReported,
                        }
                    }
                },
                // Input is known but the cached split is not, so the categories
                // cannot be separated.
                None => indeterminate(),
            },
            (None, _) => reported_input,
        };
        (uncached, reported_input)
    } else if inclusion.input_categories_mutually_exclusive {
        // Categories are disjoint, so the effective input is their sum.
        let effective = match (
            sum_contribution(reported_input),
            sum_contribution(cache_read),
            sum_contribution(cache_write),
        ) {
            (Some(input), Some(read), Some(write)) => input
                .checked_add(read)
                .and_then(|partial| partial.checked_add(write))
                .map_or_else(
                    || {
                        push_unique(&mut warnings, NormalizationWarning::Overflow);
                        indeterminate()
                    },
                    |value| TokenMetric::DerivedFromReported {
                        value,
                        rule_version,
                    },
                ),
            _ => indeterminate(),
        };
        (reported_input, effective)
    } else {
        // Inclusion is unspecified, so no effective input may be inferred.
        (reported_input, indeterminate())
    };

    let total_tokens = match inclusion.total_source {
        TotalSource::Reported => classify(fields.total, true, &mut warnings),
        TotalSource::DerivedSum { rule_version } => {
            match (effective_input.known_value(), output.known_value()) {
                (Some(input), Some(out)) => input.checked_add(out).map_or_else(
                    || {
                        push_unique(&mut warnings, NormalizationWarning::Overflow);
                        indeterminate()
                    },
                    |value| TokenMetric::DerivedFromReported {
                        value,
                        rule_version,
                    },
                ),
                _ => indeterminate(),
            }
        }
        TotalSource::Unavailable => TokenMetric::NotApplicable,
    };

    // The reported total is the one fact that can contradict the contract's own
    // inclusion rules, so it is checked rather than merely stored. A contract that
    // says reasoning sits inside `output` when it actually sits beside it produces
    // no bad metric and no error — only a total that stops adding up, and a cost
    // that silently misses whatever was left out.
    if let TotalSource::Reported = inclusion.total_source
        && !total_reconciles(
            total_tokens,
            effective_input,
            output,
            input_audio,
            output_audio,
        )
    {
        push_unique(&mut warnings, NormalizationWarning::FieldConflict);
    }

    let pricing_context_tokens = match contract.pricing_context_basis {
        PricingContextBasis::EffectiveInput => effective_input,
        PricingContextBasis::Unknown => indeterminate(),
    };

    let mut billable = Vec::new();
    push_billable_tokens(
        &mut billable,
        BillableComponentCode::ImageInputTokens,
        fields.image_input,
        &mut warnings,
    );
    push_billable_tokens(
        &mut billable,
        BillableComponentCode::ImageOutputTokens,
        fields.image_output,
        &mut warnings,
    );

    ProviderUsageObservation {
        uncached_input_tokens: uncached_input,
        cache_read_input_tokens: cache_read,
        cache_write_input_tokens: cache_write,
        effective_input_tokens: effective_input,
        output_tokens: output,
        reasoning_tokens: reasoning,
        input_audio_tokens: input_audio,
        output_audio_tokens: output_audio,
        total_tokens,
        pricing_context_tokens,
        billable,
        warnings,
    }
}
