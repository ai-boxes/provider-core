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

    if request.metadata.responses_lite {
        normalize_responses_lite(body)?;
    }

    normalize_agent_messages(body)?;
    strip_unreadable_encrypted_content(body);
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

fn normalize_responses_lite(
    body: &mut serde_json::Map<String, Value>,
) -> Result<(), ProviderError> {
    let tools = match body.remove("tools") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(tools)) => tools,
        Some(_) => {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Codex Responses Lite tools must be an array",
            ));
        }
    };
    let instructions = match body.remove("instructions") {
        None | Some(Value::Null) => None,
        Some(Value::String(instructions)) => {
            let instructions = instructions.trim();
            (!instructions.is_empty()).then(|| instructions.to_owned())
        }
        Some(_) => {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Codex Responses Lite instructions must be a string",
            ));
        }
    };
    let input = body.remove("input").unwrap_or(Value::Array(Vec::new()));
    let mut input = match input {
        Value::Array(input) => input,
        Value::String(text) => vec![serde_json::json!({
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": text}],
        })],
        _ => {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Codex Responses Lite input must be a string or an array",
            ));
        }
    };

    strip_image_details(&mut input);
    let already_has_additional_tools = input
        .first()
        .is_some_and(|item| item.get("type").and_then(Value::as_str) == Some("additional_tools"));
    if !already_has_additional_tools {
        let mut prefix = vec![serde_json::json!({
            "type": "additional_tools",
            "role": "developer",
            "tools": tools,
        })];
        if let Some(instructions) = instructions {
            prefix.push(serde_json::json!({
                "type": "message",
                "role": "developer",
                "content": [{"type": "input_text", "text": instructions}],
            }));
        }
        prefix.append(&mut input);
        input = prefix;
    } else if !tools.is_empty() || instructions.is_some() {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Codex Responses Lite request must not mix top-level tools or instructions with additional_tools input",
        ));
    }

    body.insert("input".to_owned(), Value::Array(input));
    body.insert("parallel_tool_calls".to_owned(), Value::Bool(false));
    set_all_turns_reasoning_context(body)?;
    Ok(())
}

fn set_all_turns_reasoning_context(
    body: &mut serde_json::Map<String, Value>,
) -> Result<(), ProviderError> {
    match body.get_mut("reasoning") {
        None | Some(Value::Null) => {
            body.insert(
                "reasoning".to_owned(),
                serde_json::json!({"context": "all_turns"}),
            );
        }
        Some(Value::Object(reasoning)) => {
            reasoning.insert("context".to_owned(), Value::String("all_turns".to_owned()));
        }
        Some(_) => {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Codex Responses Lite reasoning must be an object",
            ));
        }
    }
    Ok(())
}

fn strip_image_details(input: &mut [Value]) {
    for item in input {
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        if let Some(Value::Array(content)) = item.get_mut("content") {
            for part in content {
                if part.get("type").and_then(Value::as_str) == Some("input_image")
                    && let Some(part) = part.as_object_mut()
                {
                    part.remove("detail");
                }
            }
        }
        if matches!(
            item.get("type").and_then(Value::as_str),
            Some("function_call_output" | "custom_tool_call_output")
        ) && let Some(Value::Array(output)) = item.get_mut("output")
        {
            for part in output {
                if part.get("type").and_then(Value::as_str) == Some("input_image")
                    && let Some(part) = part.as_object_mut()
                {
                    part.remove("detail");
                }
            }
        }
    }
}

fn normalize_agent_messages(
    body: &mut serde_json::Map<String, Value>,
) -> Result<(), ProviderError> {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return Ok(());
    };
    let mut normalized_input = Vec::with_capacity(input.len());
    for mut item in std::mem::take(input) {
        let Some(item_object) = item.as_object_mut() else {
            normalized_input.push(item);
            continue;
        };
        if item_object.get("type").and_then(Value::as_str) != Some("agent_message") {
            normalized_input.push(item);
            continue;
        }
        let keep = {
            let content = item_object
                .get_mut("content")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    ProviderError::new(
                        ProviderErrorKind::InvalidRequest,
                        "Codex agent_message requires content items",
                    )
                })?;
            let mut normalized_content = Vec::with_capacity(content.len());
            for mut part in std::mem::take(content) {
                let part_object = part.as_object_mut().ok_or_else(|| {
                    ProviderError::new(
                        ProviderErrorKind::InvalidRequest,
                        "Codex agent_message content items must be objects",
                    )
                })?;
                match part_object.get("type").and_then(Value::as_str) {
                    Some("input_text") => {
                        if !part_object.get("text").is_some_and(Value::is_string) {
                            return Err(ProviderError::new(
                                ProviderErrorKind::InvalidRequest,
                                "Codex agent_message text must be a string",
                            ));
                        }
                    }
                    Some("encrypted_content") => {
                        let Some(text) = part_object
                            .get("encrypted_content")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                        else {
                            if part_object.get("text").is_some_and(Value::is_null) {
                                continue;
                            }
                            return Err(ProviderError::new(
                                ProviderErrorKind::InvalidRequest,
                                "Codex agent_message encrypted_content must be a string",
                            ));
                        };
                        part_object
                            .insert("type".to_owned(), Value::String("input_text".to_owned()));
                        part_object.insert("text".to_owned(), Value::String(text));
                        part_object.remove("encrypted_content");
                    }
                    Some(content_type) => {
                        return Err(ProviderError::new(
                            ProviderErrorKind::InvalidRequest,
                            format!(
                                "Codex cannot replay agent_message content type `{content_type}`"
                            ),
                        ));
                    }
                    None => {
                        return Err(ProviderError::new(
                            ProviderErrorKind::InvalidRequest,
                            "Codex agent_message content requires a type",
                        ));
                    }
                }
                normalized_content.push(part);
            }
            *content = normalized_content;
            !content.is_empty()
        };
        if keep {
            normalized_input.push(item);
        }
    }
    *input = normalized_input;
    Ok(())
}

fn strip_unreadable_encrypted_content(body: &mut serde_json::Map<String, Value>) {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return;
    };
    input.retain(|item| {
        let Some(item) = item.as_object() else {
            return true;
        };
        item.get("type").and_then(Value::as_str) != Some("encrypted_content")
            || item.get("encrypted_content").is_some_and(Value::is_string)
    });
    for item in input {
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        for field in ["content", "output"] {
            let Some(Value::Array(parts)) = item.get_mut(field) else {
                continue;
            };
            parts.retain(|part| {
                let Some(part) = part.as_object() else {
                    return true;
                };
                part.get("type").and_then(Value::as_str) != Some("encrypted_content")
                    || part.get("encrypted_content").is_some_and(Value::is_string)
            });
        }
    }
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
    fn normalizes_responses_lite_transport_contract() {
        let mut metadata = RequestMetadata::default();
        metadata.responses_lite = true;
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.6-sol".to_owned(),
            payload: bytes::Bytes::from_static(br#"{
                "instructions":"review carefully",
                "tools":[{"type":"custom","name":"exec"}],
                "parallel_tool_calls":true,
                "reasoning":{"effort":"high","context":"current_turn"},
                "input":[{"type":"message","role":"user","content":[
                    {"type":"input_image","image_url":"data:image/png;base64,AA==","detail":"original"},
                    {"type":"input_text","text":"review this"}
                ]}]
            }"#),
            metadata,
        };

        let prepared = prepare_request(request).expect("Responses Lite request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        assert!(body.get("instructions").is_none());
        assert!(body.get("tools").is_none());
        assert_eq!(body["input"][0]["type"], "additional_tools");
        assert_eq!(body["input"][0]["role"], "developer");
        assert_eq!(body["input"][0]["tools"][0]["name"], "exec");
        assert_eq!(body["input"][1]["role"], "developer");
        assert_eq!(body["input"][1]["content"][0]["text"], "review carefully");
        assert_eq!(body["input"][2]["role"], "user");
        assert!(body["input"][2]["content"][0].get("detail").is_none());
        assert_eq!(body["parallel_tool_calls"], false);
        assert_eq!(body["reasoning"]["effort"], "high");
        assert_eq!(body["reasoning"]["context"], "all_turns");
        assert!(prepared.metadata.responses_lite);
    }

    #[test]
    fn preserves_already_normalized_responses_lite_input() {
        let mut metadata = RequestMetadata::default();
        metadata.responses_lite = true;
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.6-luna".to_owned(),
            payload: bytes::Bytes::from_static(
                br#"{"input":[{"type":"additional_tools","role":"developer","tools":[]},{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]}]}"#,
            ),
            metadata,
        };

        let prepared = prepare_request(request).expect("already normalized request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        assert_eq!(body["input"].as_array().expect("input").len(), 2);
        assert_eq!(body["input"][0]["type"], "additional_tools");
        assert_eq!(body["parallel_tool_calls"], false);
        assert_eq!(body["reasoning"]["context"], "all_turns");
    }

    #[test]
    fn replays_recorded_agent_message_without_invalid_ciphertext() {
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.6-luna".to_owned(),
            payload: bytes::Bytes::from_static(include_bytes!(
                "fixtures/agent_message_session_01a01e85.json"
            )),
            metadata: RequestMetadata::default(),
        };

        let prepared = prepare_request(request).expect("recorded agent message request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        let item = &body["input"][0];

        assert_eq!(item["type"], "agent_message");
        assert!(item.get("role").is_none());
        assert_eq!(item["author"], "/root");
        assert_eq!(item["recipient"], "/root/backend_analysis");
        assert_eq!(
            item["internal_chat_message_metadata_passthrough"]["turn_id"],
            "01a01e85-e653-7f70-8d97-8537dace76dc"
        );
        assert!(item["content"].as_array().is_some_and(|content| {
            content
                .iter()
                .all(|part| part["type"] == "input_text" && part["text"].is_string())
        }));
        assert_eq!(item["content"][1]["text"], "对仓库做后端只读分析……");
        assert!(
            item["content"]
                .as_array()
                .expect("agent message content")
                .iter()
                .all(|part| part.get("encrypted_content").is_none())
        );
    }

    #[test]
    fn drops_agent_message_without_readable_content() {
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.5".to_owned(),
            payload: bytes::Bytes::from_static(
                br#"{"input":[{"type":"agent_message","content":[{"type":"encrypted_content","text":null}]}]}"#,
            ),
            metadata: RequestMetadata::default(),
        };

        let prepared = prepare_request(request).expect("empty agent message request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        assert!(body["input"].as_array().is_some_and(Vec::is_empty));
    }

    #[test]
    fn leaves_regular_codex_messages_unchanged() {
        let input = serde_json::json!([{
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "continue"}]
        }]);
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.5".to_owned(),
            payload: serde_json::to_vec(&serde_json::json!({"input": input.clone()}))
                .expect("request JSON")
                .into(),
            metadata: RequestMetadata::default(),
        };

        let prepared = prepare_request(request).expect("regular Codex request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");

        assert_eq!(body["input"], input);
    }

    #[test]
    fn strips_unreadable_encrypted_content_markers() {
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.6-luna".to_owned(),
            payload: bytes::Bytes::from_static(
                br#"{
                    "input":[
                        {
                            "type":"message",
                            "role":"user",
                            "content":[
                                {"type":"encrypted_content","text":null},
                                {"type":"input_text","text":"continue"}
                            ]
                        },
                        {
                            "type":"function_call_output",
                            "call_id":"call-1",
                            "output":[
                                {"type":"encrypted_content","text":null},
                                {"type":"input_text","text":"result"},
                                {"type":"encrypted_content","encrypted_content":"opaque"}
                            ]
                        },
                        {"type":"encrypted_content","text":null}
                    ]
                }"#,
            ),
            metadata: RequestMetadata::default(),
        };

        let prepared = prepare_request(request).expect("request with empty encrypted markers");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");

        assert_eq!(body["input"].as_array().expect("input").len(), 2);
        assert_eq!(
            body["input"][0]["content"]
                .as_array()
                .expect("message content")
                .len(),
            1
        );
        assert_eq!(body["input"][0]["content"][0]["text"], "continue");
        assert_eq!(
            body["input"][1]["output"]
                .as_array()
                .expect("function output")
                .len(),
            2
        );
        assert_eq!(body["input"][1]["output"][0]["text"], "result");
        assert_eq!(body["input"][1]["output"][1]["encrypted_content"], "opaque");
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
