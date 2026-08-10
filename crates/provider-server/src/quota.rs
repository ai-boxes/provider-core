use provider_core::WireFormat;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuotaRequestError {
    MissingOutputLimit,
    UnsupportedBillableContent,
}

pub(crate) fn maximum_text_output_tokens(
    format: WireFormat,
    payload: &Value,
) -> Result<u64, QuotaRequestError> {
    if contains_unbounded_billable_content(payload) {
        return Err(QuotaRequestError::UnsupportedBillableContent);
    }
    let field = match format {
        WireFormat::OpenAiResponses => "max_output_tokens",
        WireFormat::ClaudeMessages => "max_tokens",
        WireFormat::OpenAiChatCompletions => "max_completion_tokens",
    };
    payload
        .as_object()
        .and_then(|payload| payload.get(field))
        .and_then(Value::as_u64)
        .filter(|limit| *limit > 0)
        .ok_or(QuotaRequestError::MissingOutputLimit)
}

fn contains_unbounded_billable_content(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(contains_unbounded_billable_content),
        Value::Object(object) => {
            if object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind,
                        "audio"
                            | "document"
                            | "file"
                            | "image"
                            | "image_url"
                            | "input_audio"
                            | "input_file"
                            | "input_image"
                            | "computer_screenshot"
                    )
                })
            {
                return true;
            }
            object
                .get("modalities")
                .and_then(Value::as_array)
                .is_some_and(|modalities| {
                    modalities
                        .iter()
                        .any(|modality| modality.as_str() != Some("text"))
                })
                || object.values().any(contains_unbounded_billable_content)
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use provider_core::WireFormat;
    use serde_json::json;

    use super::{QuotaRequestError, maximum_text_output_tokens};

    #[test]
    fn each_public_protocol_requires_its_native_positive_output_limit() {
        assert_eq!(
            maximum_text_output_tokens(
                WireFormat::OpenAiResponses,
                &json!({ "max_output_tokens": 512 }),
            ),
            Ok(512)
        );
        assert_eq!(
            maximum_text_output_tokens(WireFormat::ClaudeMessages, &json!({ "max_tokens": 256 }),),
            Ok(256)
        );
        assert_eq!(
            maximum_text_output_tokens(WireFormat::OpenAiResponses, &json!({ "max_tokens": 512 }),),
            Err(QuotaRequestError::MissingOutputLimit)
        );
    }

    #[test]
    fn image_audio_and_file_inputs_are_not_admitted_under_a_finite_quota() {
        for payload in [
            json!({
                "max_output_tokens": 10,
                "input": [{ "type": "input_image", "image_url": "https://example.com/x" }]
            }),
            json!({
                "max_output_tokens": 10,
                "input": [{ "type": "input_audio", "audio": "..." }]
            }),
            json!({
                "max_output_tokens": 10,
                "input": [{ "type": "input_file", "file_id": "file-1" }]
            }),
            json!({ "max_output_tokens": 10, "modalities": ["text", "audio"] }),
        ] {
            assert_eq!(
                maximum_text_output_tokens(WireFormat::OpenAiResponses, &payload),
                Err(QuotaRequestError::UnsupportedBillableContent)
            );
        }
    }
}
