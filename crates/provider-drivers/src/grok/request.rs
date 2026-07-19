use bytes::Bytes;
use provider_core::{
    ProviderError, ProviderErrorKind, ProviderRequest, RequestMetadata, WireFormat,
};
use serde_json::{Map, Value};

const UNSUPPORTED_FIELDS: &[&str] = &[
    "previous_response_id",
    "prompt_cache_retention",
    "safety_identifier",
    "stream_options",
];

#[derive(Debug)]
pub(crate) struct PreparedGrokRequest {
    pub(crate) payload: Bytes,
    pub(crate) metadata: RequestMetadata,
}

pub(crate) fn prepare_request(
    request: ProviderRequest,
) -> Result<PreparedGrokRequest, ProviderError> {
    if request.format != WireFormat::OpenAiResponses {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok driver requires the OpenAI Responses format",
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
    for field in UNSUPPORTED_FIELDS {
        body.remove(*field);
    }

    normalize_tools(body);
    normalize_input(body);

    let mut metadata = request.metadata;
    metadata.session_id = normalized_string(metadata.session_id.as_deref()).or_else(|| {
        body.get("prompt_cache_key")
            .and_then(Value::as_str)
            .and_then(|value| normalized_string(Some(value)))
    });
    if let Some(session_id) = metadata.session_id.as_ref() {
        body.insert(
            "prompt_cache_key".to_owned(),
            Value::String(session_id.clone()),
        );
    }

    let payload = serde_json::to_vec(&payload).map(Bytes::from).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::Internal,
            "failed to serialize normalized Grok request",
        )
    })?;

    Ok(PreparedGrokRequest { payload, metadata })
}

fn normalized_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn normalize_tools(body: &mut Map<String, Value>) {
    let Some(tools) = body.remove("tools") else {
        return;
    };
    let Value::Array(tools) = tools else {
        body.insert("tools".to_owned(), tools);
        return;
    };

    let normalized: Vec<Value> = tools.into_iter().filter_map(normalize_tool).collect();
    if normalized.is_empty() {
        body.remove("tool_choice");
        body.remove("parallel_tool_calls");
    } else {
        body.insert("tools".to_owned(), Value::Array(normalized));
    }
}

fn normalize_tool(mut tool: Value) -> Option<Value> {
    let Some(tool_object) = tool.as_object_mut() else {
        return Some(tool);
    };
    let Some(tool_type) = tool_object
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return Some(tool);
    };

    match tool_type.as_str() {
        "tool_search" | "image_generation" => return None,
        "custom" => {
            if tool_object.get("name").and_then(Value::as_str) == Some("apply_patch") {
                return None;
            }
            tool_object.insert("type".to_owned(), Value::String("function".to_owned()));
            tool_object
                .entry("parameters".to_owned())
                .or_insert_with(empty_object_schema);
        }
        "function" => {
            tool_object
                .entry("parameters".to_owned())
                .or_insert_with(empty_object_schema);
        }
        "web_search" => {
            tool_object.remove("external_web_access");
        }
        _ => {}
    }

    Some(tool)
}

fn empty_object_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {}
    })
}

fn normalize_input(body: &mut Map<String, Value>) {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return;
    };

    input.retain_mut(normalize_input_item);
}

fn normalize_input_item(item: &mut Value) -> bool {
    let Some(item_object) = item.as_object_mut() else {
        return true;
    };
    let Some(item_type) = item_object.get("type").and_then(Value::as_str) else {
        return true;
    };

    match item_type {
        "custom_tool_call" => {
            let has_call_id = non_empty_field(item_object, "call_id");
            let has_name = non_empty_field(item_object, "name");
            if !has_call_id || !has_name {
                return false;
            }

            let input = item_object.remove("input").unwrap_or(Value::Null);
            item_object.insert("type".to_owned(), Value::String("function_call".to_owned()));
            item_object.insert(
                "arguments".to_owned(),
                Value::String(custom_tool_arguments(input)),
            );
        }
        "custom_tool_call_output" => {
            if !non_empty_field(item_object, "call_id") {
                return false;
            }

            let output = item_object.remove("output").unwrap_or(Value::Null);
            item_object.insert(
                "type".to_owned(),
                Value::String("function_call_output".to_owned()),
            );
            item_object.insert(
                "output".to_owned(),
                Value::String(custom_tool_output(output)),
            );
        }
        _ => {}
    }

    true
}

fn non_empty_field(object: &Map<String, Value>, field: &str) -> bool {
    object
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn custom_tool_arguments(input: Value) -> String {
    match input {
        Value::String(text) => match serde_json::from_str::<Value>(text.trim()) {
            Ok(Value::Object(object)) => Value::Object(object).to_string(),
            _ => serde_json::json!({ "input": text }).to_string(),
        },
        Value::Object(object) => Value::Object(object).to_string(),
        Value::Null => "{}".to_owned(),
        value => serde_json::json!({ "input": value }).to_string(),
    }
}

fn custom_tool_output(output: Value) -> String {
    match output {
        Value::String(text) => text,
        Value::Null => String::new(),
        value => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_codex_request_for_grok() {
        let payload = Bytes::from_static(
            br#"{
                "model":"client-model",
                "stream":false,
                "stream_options":{"include_usage":true},
                "previous_response_id":"resp_previous",
                "prompt_cache_key":" session-from-body ",
                "tools":[
                    {"type":"custom","name":"shell"},
                    {"type":"custom","name":"apply_patch"},
                    {"type":"function","name":"lookup"},
                    {"type":"tool_search"},
                    {"type":"web_search","external_web_access":true}
                ],
                "input":[
                    {"type":"custom_tool_call","call_id":"call_1","name":"shell","input":"pwd"},
                    {"type":"custom_tool_call_output","call_id":"call_1","output":{"ok":true}}
                ]
            }"#,
        );
        let mut request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload,
            metadata: RequestMetadata::default(),
        };
        request.metadata.session_id = Some(" metadata-session ".to_owned());

        let prepared = prepare_request(request).expect("prepared request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

        assert_eq!(body["model"], "grok-4.5");
        assert_eq!(body["stream"], true);
        assert!(body.get("stream_options").is_none());
        assert!(body.get("previous_response_id").is_none());
        assert_eq!(body["prompt_cache_key"], "metadata-session");
        assert_eq!(
            prepared.metadata.session_id.as_deref(),
            Some("metadata-session")
        );
        assert_eq!(body["tools"].as_array().expect("tools").len(), 3);
        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(body["tools"][0]["parameters"]["type"], "object");
        assert_eq!(body["tools"][1]["parameters"]["type"], "object");
        assert!(body["tools"][2].get("external_web_access").is_none());
        assert_eq!(body["input"][0]["type"], "function_call");
        assert_eq!(body["input"][0]["arguments"], r#"{"input":"pwd"}"#);
        assert_eq!(body["input"][1]["type"], "function_call_output");
        assert_eq!(body["input"][1]["output"], r#"{"ok":true}"#);
    }

    #[test]
    fn rejects_invalid_json_without_echoing_request() {
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(br#"{"secret":"do-not-echo""#),
            metadata: RequestMetadata::default(),
        };

        let error = prepare_request(request).expect_err("invalid JSON");

        assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
        assert!(!error.message().contains("do-not-echo"));
    }
}
