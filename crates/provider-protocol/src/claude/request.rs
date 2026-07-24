use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use provider_core::{ProviderError, ProviderErrorKind, ProviderRequest, ProxyRequest, WireFormat};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::response::{ClaudeResponseContext, ClaudeResponseTranslator};

const CLAUDE_CODE_ATTRIBUTION_PREFIX: &str = "x-anthropic-billing-header:";
const SYSTEM_REMINDER_START: &str = "<system-reminder>";
const SYSTEM_REMINDER_END: &str = "</system-reminder>";

pub(crate) fn prepare_responses_request(
    request: ProxyRequest,
) -> Result<(ProviderRequest, ClaudeResponseTranslator), ProviderError> {
    if request.format != WireFormat::ClaudeMessages {
        return Err(invalid_request(
            "Claude request adapter requires the Claude Messages protocol",
        ));
    }

    let model = request.model.trim().to_owned();
    if model.is_empty() {
        return Err(invalid_request("model must not be empty"));
    }

    let source: Value = serde_json::from_slice(&request.payload)
        .map_err(|_| invalid_request("Claude Messages request body must be valid JSON"))?;
    let source = source
        .as_object()
        .ok_or_else(|| invalid_request("Claude Messages request body must be a JSON object"))?;

    let messages = source
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_request("Claude Messages request requires a messages array"))?;
    let (tool_names, reverse_tool_names) = build_tool_name_maps(source.get("tools"));
    let call_ids = build_call_id_map(messages);
    let web_search_tools = web_search_tool_names(source.get("tools"));

    let mut input = Vec::new();
    append_claude_system(source.get("system"), &mut input)?;
    append_claude_messages(messages, &tool_names, &call_ids, &mut input)?;

    let mut body = Map::new();
    body.insert("model".to_owned(), Value::String(model.clone()));
    body.insert("input".to_owned(), Value::Array(input));
    body.insert("stream".to_owned(), Value::Bool(true));
    body.insert("store".to_owned(), Value::Bool(false));
    body.insert(
        "include".to_owned(),
        serde_json::json!(["reasoning.encrypted_content"]),
    );
    body.insert("reasoning".to_owned(), claude_reasoning(source));

    if let Some(max_tokens) = source.get("max_tokens").and_then(Value::as_u64) {
        body.insert(
            "max_output_tokens".to_owned(),
            Value::Number(max_tokens.into()),
        );
    }
    copy_number(source, &mut body, "temperature");
    copy_number(source, &mut body, "top_p");
    if let Some(tools) = convert_claude_tools(source.get("tools"), &tool_names)? {
        body.insert("tools".to_owned(), Value::Array(tools));
        body.insert(
            "tool_choice".to_owned(),
            convert_claude_tool_choice(source.get("tool_choice"), &tool_names, &web_search_tools),
        );
        let parallel = source
            .get("tool_choice")
            .and_then(Value::as_object)
            .and_then(|choice| choice.get("disable_parallel_tool_use"))
            .and_then(Value::as_bool)
            != Some(true);
        body.insert("parallel_tool_calls".to_owned(), Value::Bool(parallel));
    }

    let payload = serde_json::to_vec(&Value::Object(body))
        .map(Bytes::from)
        .map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "failed to serialize converted Claude request",
            )
        })?;
    let upstream = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: model.clone(),
        payload,
        metadata: request.metadata,
    };

    Ok((
        upstream,
        ClaudeResponseTranslator::new(ClaudeResponseContext::new(model, reverse_tool_names)),
    ))
}

fn invalid_request(message: &'static str) -> ProviderError {
    ProviderError::new(ProviderErrorKind::InvalidRequest, message)
}

fn append_claude_system(
    system: Option<&Value>,
    input: &mut Vec<Value>,
) -> Result<(), ProviderError> {
    let Some(system) = system else {
        return Ok(());
    };

    let texts: Vec<String> = match system {
        Value::String(text) => system_text(text).map(str::to_owned).into_iter().collect(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| {
                let part = part.as_object()?;
                (part.get("type").and_then(Value::as_str) == Some("text"))
                    .then(|| part.get("text").and_then(Value::as_str).unwrap_or_default())
            })
            .filter_map(|text| system_text(text).map(str::to_owned))
            .collect(),
        _ => return Err(invalid_request("Claude system must be text or an array")),
    };

    if !texts.is_empty() {
        let content: Vec<Value> = texts
            .into_iter()
            .map(|text| serde_json::json!({ "type": "input_text", "text": text }))
            .collect();
        input.push(serde_json::json!({
            "type": "message",
            "role": "developer",
            "content": content
        }));
    }
    Ok(())
}

fn append_claude_messages(
    messages: &[Value],
    tool_names: &HashMap<String, String>,
    call_ids: &HashMap<String, String>,
    input: &mut Vec<Value>,
) -> Result<(), ProviderError> {
    for message in messages {
        let message = message
            .as_object()
            .ok_or_else(|| invalid_request("Claude messages must contain JSON objects"))?;
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Claude message role is required"))?;
        let content = message
            .get("content")
            .ok_or_else(|| invalid_request("Claude message content is required"))?;

        if role == "system" {
            append_message_system_reminder(content, input);
            continue;
        }
        if !matches!(role, "user" | "assistant") {
            return Err(invalid_request(
                "Claude message role must be user, assistant, or system",
            ));
        }

        match content {
            Value::String(text) => push_message(input, role, vec![text_part(role, text)]),
            Value::Array(parts) => append_claude_content(parts, role, tool_names, call_ids, input)?,
            _ => {
                return Err(invalid_request(
                    "Claude message content must be text or an array",
                ));
            }
        }
    }
    Ok(())
}

fn append_message_system_reminder(content: &Value, input: &mut Vec<Value>) {
    let texts = match content {
        Value::String(text) => system_text(text).into_iter().collect::<Vec<_>>(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(Value::as_object)
            .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .filter_map(system_text)
            .collect(),
        _ => Vec::new(),
    };
    if texts.is_empty() {
        return;
    }
    let reminder = format!(
        "{SYSTEM_REMINDER_START}\n{}\n{SYSTEM_REMINDER_END}",
        texts.join("\n")
    );
    push_message(input, "user", vec![text_part("user", &reminder)]);
}

fn system_text(text: &str) -> Option<&str> {
    (!text.trim().is_empty()
        && !text
            .trim_start()
            .starts_with(CLAUDE_CODE_ATTRIBUTION_PREFIX))
    .then_some(text)
}

fn append_claude_content(
    parts: &[Value],
    role: &str,
    tool_names: &HashMap<String, String>,
    call_ids: &HashMap<String, String>,
    input: &mut Vec<Value>,
) -> Result<(), ProviderError> {
    let mut message_parts = Vec::new();
    for part in parts {
        let part = part
            .as_object()
            .ok_or_else(|| invalid_request("Claude content blocks must be JSON objects"))?;
        match part.get("type").and_then(Value::as_str).unwrap_or_default() {
            "text" => message_parts.push(text_part(
                role,
                part.get("text").and_then(Value::as_str).unwrap_or_default(),
            )),
            "image" if role == "user" => {
                let image_url = claude_image_data_url(part)?;
                message_parts.push(serde_json::json!({
                    "type": "input_image",
                    "image_url": image_url,
                    "detail": "auto"
                }));
            }
            "thinking" if role == "assistant" => {
                flush_message_parts(input, role, &mut message_parts);
                let signature = part
                    .get("signature")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                if let Some(signature) = signature {
                    input.push(serde_json::json!({
                        "type": "reasoning",
                        "summary": [],
                        "encrypted_content": signature
                    }));
                }
            }
            "tool_use" if role == "assistant" => {
                flush_message_parts(input, role, &mut message_parts);
                let call_id = required_string(part, "id", "Claude tool_use requires an id")?;
                let call_id = mapped_call_id(call_ids, call_id);
                let original_name =
                    required_string(part, "name", "Claude tool_use requires a name")?;
                let name = tool_names
                    .get(original_name)
                    .map(String::as_str)
                    .unwrap_or(original_name);
                let arguments = part
                    .get("input")
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new()))
                    .to_string();
                input.push(serde_json::json!({
                    "type": "function_call",
                    "call_id": call_id,
                    "name": name,
                    "arguments": arguments
                }));
            }
            "tool_result" if role == "user" => {
                flush_message_parts(input, role, &mut message_parts);
                let call_id = required_string(
                    part,
                    "tool_use_id",
                    "Claude tool_result requires a tool_use_id",
                )?;
                let call_id = mapped_call_id(call_ids, call_id);
                let output = claude_tool_result_output(part.get("content"))?;
                input.push(serde_json::json!({
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": output
                }));
            }
            "redacted_thinking"
            | "tool_reference"
            | "server_tool_use"
            | "web_search_tool_result" => {}
            block_type => {
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidRequest,
                    format!("unsupported Claude content block: {block_type}"),
                ));
            }
        }
    }
    flush_message_parts(input, role, &mut message_parts);
    Ok(())
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

fn text_part(role: &str, text: &str) -> Value {
    let part_type = if role == "assistant" {
        "output_text"
    } else {
        "input_text"
    };
    serde_json::json!({ "type": part_type, "text": text })
}

fn push_message(input: &mut Vec<Value>, role: &str, content: Vec<Value>) {
    if content.is_empty() {
        return;
    }
    input.push(serde_json::json!({
        "type": "message",
        "role": role,
        "content": content
    }));
}

fn flush_message_parts(input: &mut Vec<Value>, role: &str, parts: &mut Vec<Value>) {
    if parts.is_empty() {
        return;
    }
    push_message(input, role, std::mem::take(parts));
}

fn claude_tool_result_output(content: Option<&Value>) -> Result<Value, ProviderError> {
    Ok(match content {
        Some(Value::String(text)) => Value::String(text.clone()),
        Some(Value::Array(parts)) => {
            let mut output = Vec::new();
            for part in parts {
                let Some(part) = part.as_object() else {
                    continue;
                };
                match part.get("type").and_then(Value::as_str) {
                    Some("text") => output.push(serde_json::json!({
                        "type": "input_text",
                        "text": part.get("text").and_then(Value::as_str).unwrap_or_default()
                    })),
                    Some("image") => {
                        let image_url = claude_image_data_url(part)?;
                        output.push(serde_json::json!({
                            "type": "input_image",
                            "image_url": image_url,
                            "detail": "auto"
                        }));
                    }
                    _ => {}
                }
            }
            if output.iter().all(|part| part["type"] == "input_text") {
                Value::String(
                    output
                        .iter()
                        .filter_map(|part| part.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
            } else {
                Value::Array(output)
            }
        }
        Some(value) => Value::String(value.to_string()),
        None => Value::String(String::new()),
    })
}

fn claude_image_data_url(part: &Map<String, Value>) -> Result<String, ProviderError> {
    let source = part
        .get("source")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_request("Claude image requires a source object"))?;
    let data = source
        .get("data")
        .or_else(|| source.get("base64"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_request("Claude image requires base64 data"))?;
    let media_type = source
        .get("media_type")
        .or_else(|| source.get("mime_type"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("application/octet-stream");
    Ok(format!("data:{media_type};base64,{data}"))
}

fn build_tool_name_maps(
    tools: Option<&Value>,
) -> (HashMap<String, String>, HashMap<String, String>) {
    let Some(tools) = tools.and_then(Value::as_array) else {
        return (HashMap::new(), HashMap::new());
    };
    let mut original_to_upstream = HashMap::new();
    let mut upstream_to_original = HashMap::new();
    let mut used = HashSet::new();

    for tool in tools {
        let Some(name) = tool
            .as_object()
            .and_then(|tool| tool.get("name"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let upstream = unique_tool_name(name, &mut used);
        original_to_upstream.insert(name.to_owned(), upstream.clone());
        upstream_to_original.insert(upstream, name.to_owned());
    }

    (original_to_upstream, upstream_to_original)
}

fn build_call_id_map(messages: &[Value]) -> HashMap<String, String> {
    let mut call_ids = HashMap::new();
    for part in messages
        .iter()
        .filter_map(|message| message.get("content"))
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(Value::as_object)
    {
        let call_id = match part.get("type").and_then(Value::as_str) {
            Some("tool_use") => part.get("id"),
            Some("tool_result") => part.get("tool_use_id"),
            _ => None,
        }
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
        if let Some(call_id) = call_id {
            call_ids
                .entry(call_id.to_owned())
                .or_insert_with(|| shorten_call_id(call_id));
        }
    }
    call_ids
}

fn mapped_call_id<'a>(call_ids: &'a HashMap<String, String>, call_id: &'a str) -> &'a str {
    call_ids.get(call_id).map(String::as_str).unwrap_or(call_id)
}

fn shorten_call_id(call_id: &str) -> String {
    const LIMIT: usize = 64;
    const HASH_HEX_LEN: usize = 16;
    if call_id.len() <= LIMIT {
        return call_id.to_owned();
    }
    let digest = Sha256::digest(call_id.as_bytes());
    let mut hash = String::with_capacity(HASH_HEX_LEN);
    for byte in digest.iter().take(HASH_HEX_LEN / 2) {
        use std::fmt::Write;
        let _ = write!(hash, "{byte:02x}");
    }
    let suffix = format!("_{hash}");
    format!(
        "{}{suffix}",
        truncate_utf8(call_id, LIMIT.saturating_sub(suffix.len()))
    )
}

fn web_search_tool_names(tools: Option<&Value>) -> HashSet<String> {
    tools
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter(|tool| is_claude_web_search_tool(tool))
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn is_claude_web_search_tool(tool: &Map<String, Value>) -> bool {
    matches!(
        tool.get("type").and_then(Value::as_str),
        Some("web_search_20250305" | "web_search_20260209")
    )
}

fn unique_tool_name(name: &str, used: &mut HashSet<String>) -> String {
    const LIMIT: usize = 64;
    let base = truncate_utf8(name, LIMIT);
    if used.insert(base.clone()) {
        return base;
    }

    for index in 1.. {
        let suffix = format!("_{index}");
        let prefix = truncate_utf8(name, LIMIT.saturating_sub(suffix.len()));
        let candidate = format!("{prefix}{suffix}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("tool name suffix space is unbounded")
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn convert_claude_tools(
    tools: Option<&Value>,
    names: &HashMap<String, String>,
) -> Result<Option<Vec<Value>>, ProviderError> {
    let Some(tools) = tools else {
        return Ok(None);
    };
    let tools = tools
        .as_array()
        .ok_or_else(|| invalid_request("Claude tools must be an array"))?;
    if tools.is_empty() {
        return Ok(None);
    }

    let mut converted = Vec::with_capacity(tools.len());
    for tool in tools {
        let tool = tool
            .as_object()
            .ok_or_else(|| invalid_request("Claude tools must contain JSON objects"))?;
        if is_claude_web_search_tool(tool) {
            let mut converted_tool = serde_json::json!({ "type": "web_search" });
            if let Some(domains) = tool.get("allowed_domains").and_then(Value::as_array) {
                converted_tool["filters"] = serde_json::json!({
                    "allowed_domains": domains
                });
            }
            if let Some(location) = tool.get("user_location").and_then(Value::as_object) {
                converted_tool["user_location"] = Value::Object(location.clone());
            }
            converted.push(converted_tool);
            continue;
        }
        let original_name = required_string(tool, "name", "Claude tool requires a name")?;
        let name = names
            .get(original_name)
            .map(String::as_str)
            .unwrap_or(original_name);
        let parameters = tool
            .get("input_schema")
            .cloned()
            .unwrap_or_else(empty_object_schema);
        let mut converted_tool = serde_json::json!({
            "type": "function",
            "name": name,
            "parameters": parameters,
            "strict": false
        });
        if let Some(description) = tool.get("description").and_then(Value::as_str) {
            converted_tool["description"] = Value::String(description.to_owned());
        }
        converted.push(converted_tool);
    }
    Ok(Some(converted))
}

fn convert_claude_tool_choice(
    choice: Option<&Value>,
    tool_names: &HashMap<String, String>,
    web_search_tools: &HashSet<String>,
) -> Value {
    let Some(choice) = choice else {
        return Value::String("auto".to_owned());
    };
    if let Some(choice) = choice.as_str() {
        return match choice {
            "none" => Value::String("none".to_owned()),
            _ => Value::String("auto".to_owned()),
        };
    }
    let Some(choice) = choice.as_object() else {
        return Value::String("auto".to_owned());
    };

    match choice.get("type").and_then(Value::as_str) {
        Some("any") => Value::String("required".to_owned()),
        Some("none") => Value::String("none".to_owned()),
        Some("tool") => choice
            .get("name")
            .and_then(Value::as_str)
            .map(|name| {
                if web_search_tools.contains(name) {
                    serde_json::json!({ "type": "web_search" })
                } else {
                    serde_json::json!({
                        "type": "function",
                        "name": tool_names.get(name).map(String::as_str).unwrap_or(name)
                    })
                }
            })
            .unwrap_or_else(|| Value::String("auto".to_owned())),
        _ => Value::String("auto".to_owned()),
    }
}

fn copy_number(source: &Map<String, Value>, target: &mut Map<String, Value>, field: &str) {
    if let Some(value) = source.get(field).filter(|value| value.is_number()) {
        target.insert(field.to_owned(), value.clone());
    }
}

fn claude_reasoning(source: &Map<String, Value>) -> Value {
    let effort = match source
        .get("thinking")
        .and_then(Value::as_object)
        .and_then(|thinking| {
            thinking
                .get("type")
                .and_then(Value::as_str)
                .map(|kind| (kind, thinking))
        }) {
        Some(("disabled", _)) => "none",
        Some(("adaptive" | "auto", _)) => source
            .get("output_config")
            .and_then(Value::as_object)
            .and_then(|config| config.get("effort"))
            .and_then(Value::as_str)
            .unwrap_or("xhigh"),
        Some(("enabled", thinking)) => thinking
            .get("budget_tokens")
            .and_then(Value::as_u64)
            .map(reasoning_effort_for_budget)
            .unwrap_or("medium"),
        _ => "medium",
    };
    serde_json::json!({ "effort": effort, "summary": "auto" })
}

fn reasoning_effort_for_budget(budget: u64) -> &'static str {
    match budget {
        0 => "none",
        1..=512 => "minimal",
        513..=1024 => "low",
        1025..=8192 => "medium",
        8193..=24576 => "high",
        _ => "xhigh",
    }
}

fn empty_object_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {}
    })
}

#[cfg(test)]
mod tests {
    use provider_core::{ProxyRequest, WireFormat};

    use super::*;

    #[test]
    fn converts_claude_messages_to_responses() {
        let payload = Bytes::from_static(
            br#"{
                "model":"placeholder",
                "max_tokens":2048,
                "system":"Follow the repository instructions.",
                "thinking":{"type":"enabled","budget_tokens":10000},
                "tool_choice":{"type":"any"},
                "tools":[{
                    "name":"shell",
                    "description":"Run a command",
                    "input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}
                }],
                "messages":[
                    {"role":"user","content":"inspect the repository"},
                    {"role":"assistant","content":[
                        {"type":"thinking","thinking":"check files","signature":"sig_1"},
                        {"type":"text","text":"I will inspect it."},
                        {"type":"tool_use","id":"call_1","name":"shell","input":{"cmd":"pwd"}}
                    ]},
                    {"role":"user","content":[
                        {"type":"tool_result","tool_use_id":"call_1","content":"/code/provider"}
                    ]}
                ]
            }"#,
        );
        let request = ProxyRequest::new(WireFormat::ClaudeMessages, "grok-4.5", payload)
            .expect("request envelope");

        let (prepared, _) = prepare_responses_request(request).expect("converted request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("converted JSON");

        assert_eq!(body["model"], "grok-4.5");
        assert_eq!(body["stream"], true);
        assert_eq!(body["max_output_tokens"], 2048);
        assert_eq!(body["reasoning"]["effort"], "high");
        assert_eq!(body["tool_choice"], "required");
        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(
            body["tools"][0]["parameters"]["properties"]["cmd"]["type"],
            "string"
        );
        assert_eq!(body["input"][0]["role"], "developer");
        assert_eq!(body["input"][2]["type"], "reasoning");
        assert_eq!(body["input"][2]["summary"], serde_json::json!([]));
        assert_eq!(body["input"][2]["encrypted_content"], "sig_1");
        assert!(!body.to_string().contains("check files"));
        assert_eq!(body["input"][4]["type"], "function_call");
        assert_eq!(body["input"][4]["arguments"], r#"{"cmd":"pwd"}"#);
        assert_eq!(body["input"][5]["type"], "function_call_output");
        assert_eq!(body["input"][5]["output"], "/code/provider");
    }

    #[test]
    fn accepts_claude_code_system_messages_and_drops_attribution() {
        let payload = Bytes::from_static(
            br#"{
                "system":[
                    {"type":"text","text":"x-anthropic-billing-header: fingerprint"},
                    {"type":"text","text":"Follow repository instructions."}
                ],
                "messages":[
                    {"role":"system","content":"x-anthropic-billing-header: request metadata"},
                    {"role":"system","content":[
                        {"type":"text","text":"Files changed on disk."}
                    ]},
                    {"role":"user","content":"continue"}
                ]
            }"#,
        );
        let request = ProxyRequest::new(WireFormat::ClaudeMessages, "grok-4.5", payload)
            .expect("request envelope");

        let (prepared, _) = prepare_responses_request(request).expect("converted request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("converted JSON");

        assert_eq!(body["input"].as_array().expect("input").len(), 3);
        assert_eq!(body["input"][0]["role"], "developer");
        assert_eq!(
            body["input"][0]["content"][0]["text"],
            "Follow repository instructions."
        );
        assert_eq!(body["input"][1]["role"], "user");
        assert_eq!(
            body["input"][1]["content"][0]["text"],
            "<system-reminder>\nFiles changed on disk.\n</system-reminder>"
        );
        assert_eq!(body["input"][2]["content"][0]["text"], "continue");
        assert!(!body.to_string().contains("x-anthropic-billing-header:"));
    }

    #[test]
    fn converts_images_web_search_and_long_tool_ids() {
        let call_id = format!("toolu_{}", "a".repeat(100));
        let payload = serde_json::to_vec(&serde_json::json!({
            "temperature": 0.4,
            "top_p": 0.8,
            "tools": [{
                "type": "web_search_20250305",
                "name": "web_search",
                "allowed_domains": ["example.com"]
            }],
            "tool_choice": { "type": "tool", "name": "web_search" },
            "messages": [
                {"role":"user","content":[
                    {"type":"text","text":"inspect"},
                    {"type":"image","source":{
                        "type":"base64","media_type":"image/png","data":"aGVsbG8="
                    }},
                    {"type":"tool_reference","tool_name":"deferred"}
                ]},
                {"role":"assistant","content":[
                    {"type":"redacted_thinking","data":"opaque"},
                    {"type":"tool_use","id":call_id,"name":"lookup","input":{"q":"x"}}
                ]},
                {"role":"user","content":[
                    {"type":"tool_result","tool_use_id":call_id,"content":[
                        {"type":"text","text":"result"},
                        {"type":"image","source":{
                            "type":"base64","mime_type":"image/jpeg","base64":"aW1hZ2U="
                        }}
                    ]},
                    {"type":"server_tool_use","id":"server_1","name":"web_search"},
                    {"type":"web_search_tool_result","tool_use_id":"server_1","content":[]}
                ]}
            ]
        }))
        .expect("request JSON");
        let request = ProxyRequest::new(WireFormat::ClaudeMessages, "grok-4.5", payload.into())
            .expect("request envelope");

        let (prepared, _) = prepare_responses_request(request).expect("converted request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("converted JSON");

        assert_eq!(body["temperature"], 0.4);
        assert_eq!(body["top_p"], 0.8);
        assert_eq!(body["tools"][0]["type"], "web_search");
        assert_eq!(
            body["tools"][0]["filters"]["allowed_domains"][0],
            "example.com"
        );
        assert_eq!(body["tool_choice"]["type"], "web_search");
        assert_eq!(body["input"][0]["content"][1]["type"], "input_image");
        assert_eq!(
            body["input"][0]["content"][1]["image_url"],
            "data:image/png;base64,aGVsbG8="
        );
        let mapped_call_id = body["input"][1]["call_id"]
            .as_str()
            .expect("mapped call ID");
        assert!(mapped_call_id.len() <= 64);
        assert_eq!(body["input"][2]["call_id"], mapped_call_id);
        assert_eq!(body["input"][2]["output"][0]["type"], "input_text");
        assert_eq!(body["input"][2]["output"][1]["type"], "input_image");
    }

    #[test]
    fn drops_historical_thinking_without_signature() {
        let payload = Bytes::from_static(
            br#"{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"do not replay"},{"type":"text","text":"visible answer"}]}]}"#,
        );
        let request = ProxyRequest::new(WireFormat::ClaudeMessages, "grok-4.5", payload)
            .expect("request envelope");

        let (prepared, _) = prepare_responses_request(request).expect("converted request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("converted JSON");

        assert_eq!(body["input"].as_array().expect("input").len(), 1);
        assert_eq!(body["input"][0]["content"][0]["text"], "visible answer");
        assert!(!body.to_string().contains("do not replay"));
    }

    #[test]
    fn rejects_unknown_claude_content_with_its_type() {
        let payload = Bytes::from_static(
            br#"{"messages":[{"role":"user","content":[{"type":"future_block"}]}]}"#,
        );
        let request = ProxyRequest::new(WireFormat::ClaudeMessages, "grok-4.5", payload)
            .expect("request envelope");

        let error = match prepare_responses_request(request) {
            Ok(_) => panic!("unsupported block should fail"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
        assert_eq!(
            error.message(),
            "unsupported Claude content block: future_block"
        );
    }
}
