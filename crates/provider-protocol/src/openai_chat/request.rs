use bytes::Bytes;
use provider_core::{ProviderError, ProviderErrorKind, ProviderRequest, WireFormat};
use serde_json::{Map, Value};

use super::response::ChatResponseTranslator;

pub(crate) fn prepare_request(
    request: ProviderRequest,
) -> Result<(ProviderRequest, ChatResponseTranslator), ProviderError> {
    if request.format != WireFormat::OpenAiResponses {
        return Err(invalid_request(
            "Chat Completions adapter requires the OpenAI Responses protocol",
        ));
    }

    let source: Value = serde_json::from_slice(&request.payload)
        .map_err(|_| invalid_request("Responses request body must be valid JSON"))?;
    let source = source
        .as_object()
        .ok_or_else(|| invalid_request("Responses request body must be a JSON object"))?;

    let mut messages = Vec::new();
    if let Some(instructions) = source
        .get("instructions")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        messages.push(serde_json::json!({
            "role": "system",
            "content": instructions
        }));
    }
    append_input(source.get("input"), &mut messages)?;

    let mut body = Map::new();
    body.insert("model".to_owned(), Value::String(request.model.clone()));
    body.insert("messages".to_owned(), Value::Array(messages));
    body.insert("stream".to_owned(), Value::Bool(true));
    copy_fields(
        source,
        &mut body,
        &[
            "frequency_penalty",
            "parallel_tool_calls",
            "presence_penalty",
            "seed",
            "stop",
            "temperature",
            "top_p",
            "user",
        ],
    );
    if let Some(max_tokens) = source.get("max_output_tokens").cloned() {
        body.insert("max_tokens".to_owned(), max_tokens);
    }
    if let Some(effort) = source
        .get("reasoning")
        .and_then(Value::as_object)
        .and_then(|reasoning| reasoning.get("effort"))
        .cloned()
    {
        body.insert("reasoning_effort".to_owned(), effort);
    }
    if let Some(tools) = convert_tools(source.get("tools"))? {
        body.insert("tools".to_owned(), Value::Array(tools));
    }
    if let Some(choice) = convert_tool_choice(source.get("tool_choice")) {
        body.insert("tool_choice".to_owned(), choice);
    }

    let payload = serde_json::to_vec(&Value::Object(body))
        .map(Bytes::from)
        .map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "failed to serialize converted Chat Completions request",
            )
        })?;
    let model = request.model;
    Ok((
        ProviderRequest {
            format: WireFormat::OpenAiChatCompletions,
            model: model.clone(),
            payload,
            metadata: request.metadata,
        },
        ChatResponseTranslator::new(model),
    ))
}

fn append_input(input: Option<&Value>, messages: &mut Vec<Value>) -> Result<(), ProviderError> {
    let input = input.ok_or_else(|| invalid_request("Responses request requires input"))?;
    match input {
        Value::String(text) => {
            messages.push(serde_json::json!({ "role": "user", "content": text }));
        }
        Value::Array(items) => {
            for item in items {
                append_input_item(item, messages)?;
            }
        }
        _ => return Err(invalid_request("Responses input must be text or an array")),
    }
    Ok(())
}

fn append_input_item(item: &Value, messages: &mut Vec<Value>) -> Result<(), ProviderError> {
    let item = item
        .as_object()
        .ok_or_else(|| invalid_request("Responses input items must be JSON objects"))?;
    match item
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("message")
    {
        "message" => append_message(item, messages),
        "function_call" | "custom_tool_call" => {
            let call_id = required_string(item, "call_id", "tool call requires call_id")?;
            let name = required_string(item, "name", "tool call requires name")?;
            let arguments = item
                .get("arguments")
                .or_else(|| item.get("input"))
                .map(json_string)
                .unwrap_or_else(|| "{}".to_owned());
            messages.push(serde_json::json!({
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": { "name": name, "arguments": arguments }
                }]
            }));
            Ok(())
        }
        "function_call_output" | "custom_tool_call_output" => {
            let call_id = required_string(item, "call_id", "tool output requires call_id")?;
            let content = item.get("output").map(json_string).unwrap_or_default();
            messages.push(serde_json::json!({
                "role": "tool",
                "tool_call_id": call_id,
                "content": content
            }));
            Ok(())
        }
        "reasoning" => Ok(()),
        _ => Err(invalid_request("unsupported Responses input item")),
    }
}

fn append_message(
    message: &Map<String, Value>,
    messages: &mut Vec<Value>,
) -> Result<(), ProviderError> {
    let role = required_string(message, "role", "Responses message requires role")?;
    let role = match role {
        "developer" | "system" => "system",
        "user" => "user",
        "assistant" => "assistant",
        _ => return Err(invalid_request("unsupported Responses message role")),
    };
    let content = message
        .get("content")
        .ok_or_else(|| invalid_request("Responses message requires content"))?;
    messages.push(serde_json::json!({
        "role": role,
        "content": chat_content(content)?
    }));
    Ok(())
}

fn chat_content(content: &Value) -> Result<Value, ProviderError> {
    match content {
        Value::String(_) => Ok(content.clone()),
        Value::Array(parts) => {
            let mut converted = Vec::with_capacity(parts.len());
            for part in parts {
                let part = part
                    .as_object()
                    .ok_or_else(|| invalid_request("Responses content parts must be objects"))?;
                match part.get("type").and_then(Value::as_str).unwrap_or_default() {
                    "input_text" | "output_text" | "text" => {
                        converted.push(serde_json::json!({
                            "type": "text",
                            "text": part.get("text").and_then(Value::as_str).unwrap_or_default()
                        }));
                    }
                    "input_image" => {
                        let url = part
                            .get("image_url")
                            .and_then(Value::as_str)
                            .ok_or_else(|| invalid_request("input_image requires image_url"))?;
                        converted.push(serde_json::json!({
                            "type": "image_url",
                            "image_url": { "url": url }
                        }));
                    }
                    _ => return Err(invalid_request("unsupported Responses content part")),
                }
            }
            Ok(Value::Array(converted))
        }
        _ => Err(invalid_request(
            "Responses message content must be text or an array",
        )),
    }
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
        let parameters = if tool_type == "custom" {
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
        let mut function = serde_json::json!({
            "name": name,
            "parameters": parameters
        });
        if let Some(description) = tool.get("description").and_then(Value::as_str) {
            function["description"] = Value::String(description.to_owned());
        }
        if let Some(strict) = tool.get("strict").and_then(Value::as_bool) {
            function["strict"] = Value::Bool(strict);
        }
        converted.push(serde_json::json!({ "type": "function", "function": function }));
    }
    Ok((!converted.is_empty()).then_some(converted))
}

fn convert_tool_choice(choice: Option<&Value>) -> Option<Value> {
    let choice = choice?;
    if choice.is_string() {
        return Some(choice.clone());
    }
    let choice = choice.as_object()?;
    (choice.get("type").and_then(Value::as_str) == Some("function"))
        .then(|| {
            choice.get("name").and_then(Value::as_str).map(|name| {
                serde_json::json!({
                    "type": "function",
                    "function": { "name": name }
                })
            })
        })
        .flatten()
}

fn copy_fields(source: &Map<String, Value>, target: &mut Map<String, Value>, fields: &[&str]) {
    for field in fields {
        if let Some(value) = source.get(*field) {
            target.insert((*field).to_owned(), value.clone());
        }
    }
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

fn json_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn empty_object_schema() -> Value {
    serde_json::json!({ "type": "object", "properties": {} })
}

fn invalid_request(message: &'static str) -> ProviderError {
    ProviderError::new(ProviderErrorKind::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use provider_core::{RequestMetadata, WireFormat};

    use super::*;

    #[test]
    fn converts_responses_messages_and_tools_to_chat_completions() {
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
                        {"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]},
                        {"type":"function_call","call_id":"call_1","name":"shell","arguments":"{\"cmd\":\"pwd\"}"},
                        {"type":"function_call_output","call_id":"call_1","output":"/code/provider"}
                    ]
                }"#,
            ),
            metadata: RequestMetadata::default(),
        };

        let (request, _) = prepare_request(request).expect("converted request");
        let body: Value = serde_json::from_slice(&request.payload).expect("request JSON");

        assert_eq!(request.format, WireFormat::OpenAiChatCompletions);
        assert_eq!(body["model"], "upstream-model");
        assert_eq!(body["stream"], true);
        assert_eq!(body["max_tokens"], 512);
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][2]["tool_calls"][0]["id"], "call_1");
        assert_eq!(body["messages"][3]["role"], "tool");
        assert_eq!(body["tools"][0]["function"]["name"], "shell");
    }
}
