//! Tagged token metrics that keep unknown, not-reported, not-applicable, an
//! explicit zero, and a derived value all distinct from one another.

use serde::{Deserialize, Serialize};

/// Why a token field could not be resolved to a concrete count.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenUnknownReason {
    /// Applicability, inclusion, parse, or terminal state was insufficient to decide.
    Indeterminate,
    /// A reported value was negative, overflowed, or conflicted with the locked contract.
    InvalidReported,
    /// The stream ended before a usage-bearing terminal was observed.
    NoUsageTerminal,
}

/// One token field.
///
/// The tag is the only source of truth for a field's quality: an unknown value
/// is never represented as `0`, and a value the provider never sent is never
/// represented as an unknown. Downstream cost and coverage read these variants
/// directly rather than a second, independently mutable quality flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TokenMetric {
    /// The provider explicitly reported a non-negative integer, including zero.
    ProviderReported { value: u64 },
    /// Unambiguously derived from reported fields under a locked contract rule.
    DerivedFromReported { value: u64, rule_version: u16 },
    /// The locked contract confirms the field applies and a successful
    /// usage-bearing terminal should report it, but none was returned.
    NotReported,
    /// The locked contract confirms this field does not apply to this attempt.
    NotApplicable,
    /// Applicability, inclusion, parse, or terminal state was insufficient to decide.
    Unknown { reason: TokenUnknownReason },
}

impl TokenMetric {
    /// Classify a present, provider-reported integer. A negative value is not a
    /// count; it becomes `Unknown` so a malformed field never poisons a sum.
    #[must_use]
    pub fn from_reported_i64(value: i64) -> Self {
        match u64::try_from(value) {
            Ok(value) => Self::ProviderReported { value },
            Err(_) => Self::Unknown {
                reason: TokenUnknownReason::InvalidReported,
            },
        }
    }

    /// The concrete count when one is known (reported or derived), else `None`.
    /// `NotReported`, `NotApplicable`, and `Unknown` all return `None` — callers
    /// must decide what an absent value means rather than defaulting to zero.
    #[must_use]
    pub const fn known_value(self) -> Option<u64> {
        match self {
            Self::ProviderReported { value } | Self::DerivedFromReported { value, .. } => {
                Some(value)
            }
            Self::NotReported | Self::NotApplicable | Self::Unknown { .. } => None,
        }
    }

    /// True when a concrete count is available.
    #[must_use]
    pub const fn is_known(self) -> bool {
        self.known_value().is_some()
    }
}

/// A stable, closed set of billable components that cannot be safely folded into
/// a single token category. New codes are added only for a verified contract;
/// this is never populated from arbitrary provider field names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillableComponentCode {
    /// Cache-write tokens billed at the 5-minute TTL rate.
    CacheWrite5m,
    /// Cache-write tokens billed at the 1-hour TTL rate.
    CacheWrite1h,
    /// A server-side tool invocation billed per call.
    ServerToolCall,
    /// Image input tokens billed at their own rate. They are included in the
    /// provider's input count but must not be priced at the text input rate.
    ImageInputTokens,
    /// Image output tokens billed at their own rate.
    ImageOutputTokens,
}

/// The unit a [`BillableObservation`] quantity is counted in.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillableUnit {
    Tokens,
    Calls,
}

/// A bounded fact about a billable quantity that does not map to a single token
/// category. It is kept for cost completeness and diagnosis; it is not folded
/// into token totals, and a catalog that cannot price it makes the cost partial
/// rather than dropping the fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BillableObservation {
    pub component_code: BillableComponentCode,
    pub unit: BillableUnit,
    pub quantity: u64,
}

/// A stable, non-fatal signal raised while normalizing a provider's usage. It
/// records why a metric was downgraded without failing the proxy response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizationWarning {
    /// A reported field was negative.
    NegativeValue,
    /// An arithmetic step would overflow.
    Overflow,
    /// Reported fields disagreed under the locked contract's inclusion rules.
    FieldConflict,
    /// The provider reported a different model than the attempt was prepared for.
    ProviderModelMismatch,
}

/// The unified, provider-agnostic usage a single response was normalized into.
///
/// Every count is a [`TokenMetric`], so a consumer can always tell an explicit
/// zero from a missing or unknown value. Inclusion relationships (whether the
/// main input already contains cache tokens, whether reasoning is inside output)
/// are resolved during normalization under the locked contract, not re-guessed
/// here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderUsageObservation {
    pub uncached_input_tokens: TokenMetric,
    pub cache_read_input_tokens: TokenMetric,
    pub cache_write_input_tokens: TokenMetric,
    pub effective_input_tokens: TokenMetric,
    pub output_tokens: TokenMetric,
    pub reasoning_tokens: TokenMetric,
    pub input_audio_tokens: TokenMetric,
    pub output_audio_tokens: TokenMetric,
    pub total_tokens: TokenMetric,
    /// Used only to select a context price tier, never billed on its own.
    pub pricing_context_tokens: TokenMetric,
    pub billable: Vec<BillableObservation>,
    pub warnings: Vec<NormalizationWarning>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_reported_is_unknown_not_zero() {
        assert_eq!(
            TokenMetric::from_reported_i64(-1),
            TokenMetric::Unknown {
                reason: TokenUnknownReason::InvalidReported
            }
        );
    }
}
