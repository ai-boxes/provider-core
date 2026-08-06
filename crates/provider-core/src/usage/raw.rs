//! Raw, provider-reported usage counts before normalization.
//!
//! Every field is optional and signed: absent means the provider did not send it
//! (which is not the same as zero), and a negative value is kept as-is so
//! normalization can classify it as invalid rather than silently clamping it.
//! Only field *extraction* lives here; SSE framing stays in the protocol layer.

use serde_json::Value;

/// Wire-shape-agnostic bag of raw counts a provider reported.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawUsageFields {
    /// The provider's primary input count. Whether it already contains cache
    /// tokens is decided by the locked contract, not by this struct.
    pub input: Option<i64>,
    pub cache_read: Option<i64>,
    pub cache_write: Option<i64>,
    pub output: Option<i64>,
    pub reasoning: Option<i64>,
    pub input_audio: Option<i64>,
    pub output_audio: Option<i64>,
    /// Image tokens billed at their own rate rather than the text input rate.
    pub image_input: Option<i64>,
    pub image_output: Option<i64>,
    pub total: Option<i64>,
}

/// Read an integer field, treating a non-integer value as absent.
fn int_field(parent: &Value, key: &str) -> Option<i64> {
    parent.get(key)?.as_i64()
}

/// Read an integer from a nested details object, e.g.
/// `input_tokens_details.cached_tokens`.
fn nested_int(parent: &Value, object: &str, key: &str) -> Option<i64> {
    int_field(parent.get(object)?, key)
}

/// Read the first of several alternative keys in a details object. Upstreams that
/// speak this wire shape disagree on the cache-write key name, so a value under
/// any known alias is still evidence and must not be dropped.
fn nested_int_any(parent: &Value, object: &str, keys: &[&str]) -> Option<i64> {
    let details = parent.get(object)?;
    keys.iter().find_map(|key| int_field(details, key))
}

impl RawUsageFields {
    /// Extract counts from an OpenAI Responses-style `usage` object.
    ///
    /// Shared by every Responses upstream (Codex included). Note that
    /// `input_tokens` is the provider's *total* input on this wire shape; the
    /// cached portion is nested under `input_tokens_details.cached_tokens` and
    /// the contract records that it is included.
    ///
    /// Cache-write is read even though OpenAI itself never sends it: other
    /// upstreams speaking this shape do, and extraction must surface the fact so
    /// the locked contract — not this function — decides whether it applies.
    #[must_use]
    pub fn from_responses_usage(usage: &Value) -> Self {
        Self {
            input: int_field(usage, "input_tokens"),
            cache_read: nested_int(usage, "input_tokens_details", "cached_tokens"),
            cache_write: nested_int_any(
                usage,
                "input_tokens_details",
                &["cache_write_tokens", "cache_creation_tokens"],
            ),
            output: int_field(usage, "output_tokens"),
            reasoning: nested_int(usage, "output_tokens_details", "reasoning_tokens"),
            input_audio: nested_int(usage, "input_tokens_details", "audio_tokens"),
            output_audio: nested_int(usage, "output_tokens_details", "audio_tokens"),
            image_input: nested_int(usage, "input_tokens_details", "image_tokens"),
            image_output: nested_int(usage, "output_tokens_details", "image_tokens"),
            total: int_field(usage, "total_tokens"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_fields_stay_absent_not_zero() {
        let usage = serde_json::json!({ "input_tokens": 10, "output_tokens": 2 });
        let fields = RawUsageFields::from_responses_usage(&usage);
        assert_eq!(fields.cache_read, None, "missing cache field is not zero");
        assert_eq!(fields.reasoning, None);
        assert_eq!(fields.total, None);
    }
}
