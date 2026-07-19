use bytes::Bytes;
use provider_core::{ProviderError, ProviderErrorKind, ProviderRequest, WireFormat};
use serde_json::{Map, Value};

use super::response::AnthropicResponseTranslator;

const DEFAULT_MAX_TOKENS: u64 = 4096;

pub(crate) fn prepare_request(
    request: ProviderRequest,
) -> Result<(ProviderRequest, AnthropicResponseTranslator), ProviderError> {
    if request.format != WireFormat::OpenAiResponses {
        return Err(invalid_request(
            "Anthropic adapter requires the OpenAI Responses protocol",
        ));
    }
    let source: Value = serde_json::from_slice(&request.payload)
        .map_err(|_| invalid_request("Responses request body must be valid JSON"))?;
    let source = source
        .as_object()
        .ok_or_else(|| invalid_request("Responses request body must be a JSON object"))?;

    let mut system = Vec::new();
    if let Some(instructions) = source
        .get("instructions")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        system.push(text_block(instructions));
    }
    let mut messages = Vec::new();
    append_input(source.get("input"), &mut system, &mut messages)?;

    let mut body = Map::new();
    body.insert("model".to_owned(), Value::String(request.model.clone()));
    body.insert("messages".to_owned(), Value::Array(messages));
    body.insert("stream".to_owned(), Value::Bool(true));
    body.insert(
        "max_tokens".to_owned(),
        source
            .get("max_output_tokens")
            .cloned()
            .unwrap_or_else(|| Value::Number(DEFAULT_MAX_TOKENS.into())),
    );
    if !system.is_empty() {
        body.insert("system".to_owned(), Value::Array(system));
    }
    copy_fields(source, &mut body, &["temperature", "top_p"]);
    if let Some(stop) = source.get("stop") {
        body.insert(
            "stop_sequences".to_owned(),
            match stop {
                Value::String(_) => Value::Array(vec![stop.clone()]),
                _ => stop.clone(),
            },
        );
    }
    if let Some(tools) = convert_tools(source.get("tools"))? {
        body.insert("tools".to_owned(), Value::Array(tools));
    }
    if let Some(choice) = convert_tool_choice(
        source.get("tool_choice"),
        source.get("parallel_tool_calls").and_then(Value::as_bool),
    ) {
        body.insert("tool_choice".to_owned(), choice);
    }

    let payload = serde_json::to_vec(&Value::Object(body))
        .map(Bytes::from)
        .map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "failed to serialize converted Anthropic request",
            )
        })?;
    let model = request.model;
    Ok((
        ProviderRequest {
            format: WireFormat::ClaudeMessages,
            model: model.clone(),
            payload,
            metadata: request.metadata,
        },
        AnthropicResponseTranslator::new(model),
    ))
}

fn append_input(
    input: Option<&Value>,
    system: &mut Vec<Value>,
    messages: &mut Vec<Value>,
) -> Result<(), ProviderError> {
    let input = input.ok_or_else(|| invalid_request("Responses request requires input"))?;
    match input {
        Value::String(text) => push_message(messages, "user", vec![text_block(text)]),
        Value::Array(items) => {
            for item in items {
                append_input_item(item, system, messages)?;
            }
        }
        _ => return Err(invalid_request("Responses input must be text or an array")),
    }
    Ok(())
}

fn append_input_item(
    item: &Value,
    system: &mut Vec<Value>,
    messages: &mut Vec<Value>,
) -> Result<(), ProviderError> {
    let item = item
        .as_object()
        .ok_or_else(|| invalid_request("Responses input items must be JSON objects"))?;
    match item
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("message")
    {
        "message" => append_message(item, system, messages),
        "reasoning" => {
            let mut blocks = Vec::new();
            let thinking = item
                .get("summary")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|part| part.get("text").and_then(Value::as_str))
                .collect::<String>();
            let signature = item
                .get("encrypted_content")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !thinking.is_empty() || !signature.is_empty() {
                blocks.push(serde_json::json!({
                    "type": "thinking",
                    "thinking": thinking,
                    "signature": signature
                }));
                push_message(messages, "assistant", blocks);
            }
            Ok(())
        }
        "function_call" | "custom_tool_call" => {
            let call_id = required_string(item, "call_id", "tool call requires call_id")?;
            let name = required_string(item, "name", "tool call requires name")?;
            let input = item
                .get("arguments")
                .or_else(|| item.get("input"))
                .map(json_value)
                .transpose()?
                .unwrap_or_else(|| Value::Object(Map::new()));
            push_message(
                messages,
                "assistant",
                vec![serde_json::json!({
                    "type": "tool_use",
                    "id": call_id,
                    "name": name,
                    "input": input
                })],
            );
            Ok(())
        }
        "function_call_output" | "custom_tool_call_output" => {
            let call_id = required_string(item, "call_id", "tool output requires call_id")?;
            let content = item.get("output").map(json_string).unwrap_or_default();
            push_message(
                messages,
                "user",
                vec![serde_json::json!({
                    "type": "tool_result",
                    "tool_use_id": call_id,
                    "content": content
                })],
            );
            Ok(())
        }
        _ => Err(invalid_request("unsupported Responses input item")),
    }
}

fn append_message(
    message: &Map<String, Value>,
    system: &mut Vec<Value>,
    messages: &mut Vec<Value>,
) -> Result<(), ProviderError> {
    let role = required_string(message, "role", "Responses message requires role")?;
    let content = message
        .get("content")
        .ok_or_else(|| invalid_request("Responses message requires content"))?;
    let blocks = content_blocks(content)?;
    match role {
        "developer" | "system" => system.extend(blocks),
        "user" | "assistant" => push_message(messages, role, blocks),
        _ => return Err(invalid_request("unsupported Responses message role")),
    }
    Ok(())
}

fn content_blocks(content: &Value) -> Result<Vec<Value>, ProviderError> {
    match content {
        Value::String(text) => Ok(vec![text_block(text)]),
        Value::Array(parts) => parts
            .iter()
            .map(|part| {
                let part = part
                    .as_object()
                    .ok_or_else(|| invalid_request("Responses content parts must be objects"))?;
                match part.get("type").and_then(Value::as_str).unwrap_or_default() {
                    "input_text" | "output_text" | "text" => Ok(text_block(
                        part.get("text").and_then(Value::as_str).unwrap_or_default(),
                    )),
                    _ => Err(invalid_request("unsupported Responses content part")),
                }
            })
            .collect(),
        _ => Err(invalid_request(
            "Responses message content must be text or an array",
        )),
    }
}

fn push_message(messages: &mut Vec<Value>, role: &str, blocks: Vec<Value>) {
    if blocks.is_empty() {
        return;
    }
    if let Some(last) = messages.last_mut().and_then(Value::as_object_mut)
        && last.get("role").and_then(Value::as_str) == Some(role)
        && let Some(content) = last.get_mut("content").and_then(Value::as_array_mut)
    {
        content.extend(blocks);
        return;
    }
    messages.push(serde_json::json!({ "role": role, "content": blocks }));
}

fn convert_tools(tools: Option<&Value>) -> Result<Option<Vec<Value>>, ProviderError> {
    let Some(tools) = tools else {
        return Ok(None);
    };
    let tools = tools
        .as_array()
        .ok_or_else(|| invalid_request("Responses tools must be an array"))?;
    let mut converted = Vec::new();
    for tool in tools {
        let tool = tool
            .as_object()
            .ok_or_else(|| invalid_request("Responses tools must contain objects"))?;
        let tool_type = tool.get("type").and_then(Value::as_str).unwrap_or_default();
        if !matches!(tool_type, "function" | "custom") {
            continue;
        }
        let name = required_string(tool, "name", "Responses tool requires name")?;
        let input_schema = if tool_type == "custom" {
            serde_json::json!({
                "type": "object",
                "properties": { "input": { "type": "string" } },
                "required": ["input"]
            })
        } else {
            tool.get("parameters")
                .cloned()
                .unwrap_or_else(empty_object_schema)
        };
        let mut converted_tool = serde_json::json!({
            "name": name,
            "input_schema": input_schema
        });
        if let Some(description) = tool.get("description").and_then(Value::as_str) {
            converted_tool["description"] = Value::String(description.to_owned());
        }
        converted.push(converted_tool);
    }
    Ok((!converted.is_empty()).then_some(converted))
}

fn convert_tool_choice(choice: Option<&Value>, parallel: Option<bool>) -> Option<Value> {
    let mut converted = match choice {
        Some(Value::String(value)) if value == "required" => serde_json::json!({ "type": "any" }),
        Some(Value::String(value)) if value == "none" => return None,
        Some(Value::Object(choice))
            if choice.get("type").and_then(Value::as_str) == Some("function") =>
        {
            serde_json::json!({
                "type": "tool",
                "name": choice.get("name").and_then(Value::as_str).unwrap_or_default()
            })
        }
        Some(_) => serde_json::json!({ "type": "auto" }),
        None if parallel == Some(false) => serde_json::json!({ "type": "auto" }),
        None => return None,
    };
    if parallel == Some(false) {
        converted["disable_parallel_tool_use"] = Value::Bool(true);
    }
    Some(converted)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    message: &'static str,
) -> Result<&'a str, ProviderError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_request(message))
}

fn json_value(value: &Value) -> Result<Value, ProviderError> {
    match value {
        Value::String(value) => serde_json::from_str(value)
            .map_err(|_| invalid_request("tool call arguments must be valid JSON")),
        value => Ok(value.clone()),
    }
}

fn json_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn text_block(text: &str) -> Value {
    serde_json::json!({ "type": "text", "text": text })
}

fn empty_object_schema() -> Value {
    serde_json::json!({ "type": "object", "properties": {} })
}

fn copy_fields(source: &Map<String, Value>, target: &mut Map<String, Value>, fields: &[&str]) {
    for field in fields {
        if let Some(value) = source.get(*field) {
            target.insert((*field).to_owned(), value.clone());
        }
    }
}

fn invalid_request(message: &'static str) -> ProviderError {
    ProviderError::new(ProviderErrorKind::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use provider_core::RequestMetadata;

    use super::*;

    #[test]
    fn converts_responses_messages_and_tools_to_anthropic() {
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "upstream-model".to_owned(),
            payload: Bytes::from_static(
                br#"{
                    "model":"client-model",
                    "instructions":"Follow instructions.",
                    "max_output_tokens":512,
                    "tools":[{"type":"function","name":"shell","parameters":{"type":"object"}}],
                    "input":[
                        {"type":"message","role":"user","content":"hello"},
                        {"type":"function_call","call_id":"call_1","name":"shell","arguments":"{\"cmd\":\"pwd\"}"},
                        {"type":"function_call_output","call_id":"call_1","output":"/code/provider"}
                    ]
                }"#,
            ),
            metadata: RequestMetadata::default(),
        };

        let (request, _) = prepare_request(request).expect("converted request");
        let body: Value = serde_json::from_slice(&request.payload).expect("request JSON");

        assert_eq!(request.format, WireFormat::ClaudeMessages);
        assert_eq!(body["model"], "upstream-model");
        assert_eq!(body["stream"], true);
        assert_eq!(body["max_tokens"], 512);
        assert_eq!(body["system"][0]["text"], "Follow instructions.");
        assert_eq!(body["messages"][1]["content"][0]["id"], "call_1");
        assert_eq!(body["messages"][2]["content"][0]["type"], "tool_result");
        assert_eq!(body["tools"][0]["name"], "shell");
    }
}
