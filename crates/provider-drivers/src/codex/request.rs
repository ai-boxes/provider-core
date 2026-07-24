use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use provider_core::{
    ProviderError, ProviderErrorKind, ProviderRequest, RequestMetadata, WireFormat,
};
use serde_json::Value;

const ENCRYPTED_REASONING_INCLUDE: &str = "reasoning.encrypted_content";

pub(crate) struct PreparedCodexRequest {
    pub(crate) payload: Bytes,
    pub(crate) metadata: RequestMetadata,
}

pub(crate) fn prepare_request(
    request: ProviderRequest,
) -> Result<PreparedCodexRequest, ProviderError> {
    if request.format != WireFormat::OpenAiResponses {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Codex driver requires the OpenAI Responses format",
        ));
    }

    let model = request.model.trim();
    if model.is_empty() {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "model must not be empty",
        ));
    }

    let mut payload: Value = serde_json::from_slice(&request.payload).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Codex Responses request body must be valid JSON",
        )
    })?;
    let body = payload.as_object_mut().ok_or_else(|| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Codex Responses request body must be a JSON object",
        )
    })?;

    body.insert("model".to_owned(), Value::String(model.to_owned()));
    body.insert("stream".to_owned(), Value::Bool(true));
    body.insert("store".to_owned(), Value::Bool(false));
    ensure_encrypted_reasoning(body)?;
    remove_server_item_ids(body);
    normalize_reasoning(body);

    let mut metadata = request.metadata;
    metadata.session_id = normalized_string(metadata.session_id.as_deref());
    if let Some(session_id) = metadata.session_id.as_ref() {
        body.insert(
            "prompt_cache_key".to_owned(),
            Value::String(session_id.clone()),
        );
    }

    let payload = serde_json::to_vec(&payload).map(Bytes::from).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::Internal,
            "failed to serialize normalized Codex request",
        )
    })?;
    Ok(PreparedCodexRequest { payload, metadata })
}

fn ensure_encrypted_reasoning(
    body: &mut serde_json::Map<String, Value>,
) -> Result<(), ProviderError> {
    match body.get_mut("include") {
        None => {
            body.insert(
                "include".to_owned(),
                Value::Array(vec![Value::String(ENCRYPTED_REASONING_INCLUDE.to_owned())]),
            );
        }
        Some(Value::Array(include)) => {
            if !include
                .iter()
                .any(|value| value.as_str() == Some(ENCRYPTED_REASONING_INCLUDE))
            {
                include.push(Value::String(ENCRYPTED_REASONING_INCLUDE.to_owned()));
            }
        }
        Some(_) => {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Codex Responses include must be an array",
            ));
        }
    }
    Ok(())
}

fn remove_server_item_ids(body: &mut serde_json::Map<String, Value>) {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return;
    };
    for item in input {
        if let Some(object) = item.as_object_mut() {
            object.remove("id");
        }
    }
}

fn normalize_reasoning(body: &mut serde_json::Map<String, Value>) {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return;
    };
    input.retain_mut(|item| {
        let Some(item) = item.as_object_mut() else {
            return true;
        };
        if item.get("type").and_then(Value::as_str) != Some("reasoning") {
            return true;
        }
        item.remove("status");
        item.get("encrypted_content")
            .and_then(Value::as_str)
            .is_some_and(is_codex_encrypted_content)
    });
}

fn is_codex_encrypted_content(value: &str) -> bool {
    const MAX_LEN: usize = 32 * 1024 * 1024;
    let trimmed = value.trim();
    if trimmed != value {
        return false;
    }
    let value = trimmed;
    if value.is_empty()
        || value.len() > MAX_LEN
        || !value.starts_with("gAAAA")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
    {
        return false;
    }
    decode_codex_encrypted_content(value).is_some_and(|decoded| {
        if decoded.len() < 73 || decoded[0] != 0x80 {
            return false;
        }
        let ciphertext_len = decoded.len() - 1 - 8 - 16 - 32;
        ciphertext_len > 0 && ciphertext_len.is_multiple_of(16)
    })
}

fn decode_codex_encrypted_content(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .ok()
}

fn normalized_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use provider_core::RequestMetadata;

    use super::*;

    #[test]
    fn normalizes_required_fields_without_dropping_native_payload() {
        let mut metadata = RequestMetadata::default();
        metadata.thread_id = Some("thread-1".to_owned());
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.5".to_owned(),
            payload: bytes::Bytes::from_static(
                br#"{
                    "model":"caller-model",
                    "stream":false,
                    "store":true,
                    "include":["file_search_call.results"],
                    "input":[{
                        "id":"server-item-id",
                        "call_id":"call-1",
                        "type":"function_call_output",
                        "output":"ok"
                    }],
                    "client_metadata":{"caller":"kept"},
                    "stream_options":{"include_usage":true},
                    "previous_response_id":"response-1",
                    "unknown_field":{"kept":true}
                }"#,
            ),
            metadata: metadata.clone(),
        };

        let prepared = prepare_request(request).expect("prepared request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");

        assert_eq!(body["model"], "gpt-5.5");
        assert_eq!(body["stream"], true);
        assert_eq!(body["store"], false);
        assert_eq!(body["include"][0], "file_search_call.results");
        assert_eq!(body["include"][1], ENCRYPTED_REASONING_INCLUDE);
        assert!(body["input"][0].get("id").is_none());
        assert_eq!(body["input"][0]["call_id"], "call-1");
        assert_eq!(body["client_metadata"]["caller"], "kept");
        assert_eq!(body["stream_options"]["include_usage"], true);
        assert_eq!(body["previous_response_id"], "response-1");
        assert_eq!(body["unknown_field"]["kept"], true);
        assert_eq!(prepared.metadata, metadata);
    }

    #[test]
    fn syncs_session_cache_key_and_filters_reasoning() {
        let mut encoded = vec![0x80];
        encoded.extend([0; 8]);
        encoded.extend([0x11; 16 + 16 + 32]);
        let codex_signature = URL_SAFE_NO_PAD.encode(encoded);
        let payload = serde_json::to_vec(&serde_json::json!({
            "prompt_cache_key": "caller-key",
            "input": [
                {
                    "type": "reasoning",
                    "summary": [],
                    "encrypted_content": "Eclaude-signature"
                },
                {
                    "type": "reasoning",
                    "status": "completed",
                    "summary": [],
                    "encrypted_content": codex_signature
                },
                {
                    "type": "message",
                    "role": "user",
                    "content": "continue"
                }
            ]
        }))
        .expect("request JSON");
        let mut metadata = RequestMetadata::default();
        metadata.session_id = Some(" cc_session ".to_owned());
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.5".to_owned(),
            payload: payload.into(),
            metadata,
        };

        let prepared = prepare_request(request).expect("prepared request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");

        assert_eq!(body["prompt_cache_key"], "cc_session");
        assert_eq!(prepared.metadata.session_id.as_deref(), Some("cc_session"));
        assert_eq!(body["input"].as_array().expect("input").len(), 2);
        assert_eq!(body["input"][0]["encrypted_content"], codex_signature);
        assert!(body["input"][0].get("status").is_none());
        assert_eq!(body["input"][1]["type"], "message");
    }

    #[test]
    fn preserves_caller_cache_key_without_internal_session() {
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.5".to_owned(),
            payload: bytes::Bytes::from_static(br#"{"prompt_cache_key":"caller-key"}"#),
            metadata: RequestMetadata::default(),
        };

        let prepared = prepare_request(request).expect("prepared request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");

        assert_eq!(body["prompt_cache_key"], "caller-key");
    }

    #[test]
    fn rejects_non_array_include() {
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.5".to_owned(),
            payload: bytes::Bytes::from_static(br#"{"include":"reasoning.encrypted_content"}"#),
            metadata: RequestMetadata::default(),
        };

        let error = match prepare_request(request) {
            Ok(_) => panic!("invalid include must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    }
}
