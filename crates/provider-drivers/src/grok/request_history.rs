use provider_core::{ProviderError, ProviderErrorKind};
use serde_json::{Map, Value};
use std::collections::HashSet;

pub(super) fn reject_unresolved_item_references(
    body: &Map<String, Value>,
) -> Result<(), ProviderError> {
    let Some(Value::Array(input)) = body.get("input") else {
        return Ok(());
    };
    for item in input {
        if item.get("type").and_then(Value::as_str) == Some("item_reference") {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Grok continuation state is unavailable to resolve item_reference; resend complete input history",
            ));
        }
    }
    Ok(())
}

pub(super) fn reject_unknown_input_item_types(
    body: &Map<String, Value>,
) -> Result<(), ProviderError> {
    let Some(Value::Array(input)) = body.get("input") else {
        return Ok(());
    };
    for item in input {
        let Some(item) = item.as_object() else {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Grok input items must be JSON objects",
            ));
        };
        match item.get("type").and_then(Value::as_str).map(str::trim) {
            None => {
                if item
                    .get("role")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .is_some_and(|role| !role.is_empty())
                {
                    continue;
                }
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidRequest,
                    "Grok input items require a supported type or role",
                ));
            }
            Some(
                "message"
                | "function_call"
                | "function_call_output"
                | "reasoning"
                | "compaction"
                | "compaction_summary",
            ) => {}
            Some(item_type) => {
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidRequest,
                    format!("Grok HTTP Responses does not support input item type `{item_type}`"),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_tool_output_context(body: &Map<String, Value>) -> Result<(), ProviderError> {
    let Some(Value::Array(input)) = body.get("input") else {
        return Ok(());
    };
    let mut context_ids = HashSet::new();
    for item in input {
        let Some(item) = item.as_object() else {
            continue;
        };
        let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
        if item_type == "function_call"
            && let Some(call_id) = item_call_id(item)
        {
            context_ids.insert(call_id);
        }
    }
    for item in input {
        let Some(item) = item.as_object() else {
            continue;
        };
        let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
        if item_type != "function_call_output" {
            continue;
        }
        let Some(call_id) = item_call_id(item) else {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Grok tool output requires a non-empty call_id",
            ));
        };
        if !context_ids.contains(call_id) {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Grok tool output requires matching tool call context in input; previous_response_id-only continuation is unsupported",
            ));
        }
    }
    Ok(())
}
pub(super) fn normalize_input(body: &mut Map<String, Value>) -> Result<(), ProviderError> {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return Ok(());
    };

    let mut normalized = Vec::with_capacity(input.len());
    for mut item in std::mem::take(input) {
        if normalize_input_item(&mut item)? {
            normalized.push(item);
        }
    }
    *input = normalized;
    Ok(())
}
fn normalize_input_item(item: &mut Value) -> Result<bool, ProviderError> {
    let Some(item_object) = item.as_object_mut() else {
        return Ok(true);
    };
    let Some(item_type) = item_object
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        strip_internal_item_fields(item_object);
        return Ok(true);
    };

    match item_type.as_str() {
        "compaction_trigger" => return Ok(false),
        "agent_message" => return normalize_agent_message(item_object),
        "custom_tool_call" => {
            if !non_empty_field(item_object, "call_id") || !non_empty_field(item_object, "name") {
                return Ok(false);
            }
            let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
            let name = item_object.remove("name").unwrap_or(Value::Null);
            let input = item_object.remove("input").unwrap_or(Value::Null);
            item_object.clear();
            item_object.insert("type".to_owned(), Value::String("function_call".to_owned()));
            item_object.insert("call_id".to_owned(), call_id);
            item_object.insert("name".to_owned(), name);
            item_object.insert(
                "arguments".to_owned(),
                Value::String(custom_tool_arguments(input)),
            );
        }
        "custom_tool_call_output" => {
            if !non_empty_field(item_object, "call_id") {
                return Ok(false);
            }
            let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
            let output = item_object.remove("output").unwrap_or(Value::Null);
            rebuild_function_output(item_object, call_id, custom_tool_output(output));
        }
        "tool_search_call" => {
            if !non_empty_field(item_object, "call_id") {
                return Err(invalid_request(
                    "Grok cannot safely replay tool_search_call without a call_id",
                ));
            }
            let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
            let arguments = item_object.remove("arguments").unwrap_or(Value::Null);
            rebuild_function_call(item_object, call_id, "tool_search", arguments);
        }
        "tool_search_output" => {
            if !non_empty_field(item_object, "call_id") {
                return Err(invalid_request(
                    "Grok cannot safely replay tool_search_output without a call_id",
                ));
            }
            let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
            let tools = item_object
                .remove("tools")
                .unwrap_or(Value::Array(Vec::new()));
            rebuild_function_output(item_object, call_id, custom_tool_output(tools));
        }
        "apply_patch_call" => {
            if !non_empty_field(item_object, "call_id") {
                return Ok(false);
            }
            let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
            let operation = item_object.remove("operation").unwrap_or(Value::Null);
            rebuild_function_call(item_object, call_id, "apply_patch", operation);
        }
        "apply_patch_call_output" => {
            if !non_empty_field(item_object, "call_id") {
                return Ok(false);
            }
            let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
            let status = item_object.remove("status").unwrap_or(Value::Null);
            let output = item_object.remove("output").unwrap_or(Value::Null);
            rebuild_function_output(
                item_object,
                call_id,
                serde_json::json!({ "status": status, "output": output }).to_string(),
            );
        }
        "program" => {
            if !non_empty_field(item_object, "call_id") {
                return Ok(false);
            }
            let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
            let code = item_object.remove("code").unwrap_or(Value::Null);
            let fingerprint = item_object.remove("fingerprint").unwrap_or(Value::Null);
            rebuild_function_call(
                item_object,
                call_id,
                "program",
                serde_json::json!({ "code": code, "fingerprint": fingerprint }),
            );
        }
        "program_output" => {
            if !non_empty_field(item_object, "call_id") {
                return Ok(false);
            }
            let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
            let status = item_object.remove("status").unwrap_or(Value::Null);
            let result = item_object.remove("result").unwrap_or(Value::Null);
            rebuild_function_output(
                item_object,
                call_id,
                serde_json::json!({ "status": status, "result": result }).to_string(),
            );
        }
        "web_search_call" => {
            return Ok(convert_hosted_tool_call(
                item_object,
                "web_search",
                HostedCallArgs::Action,
            ));
        }
        "file_search_call" => {
            reject_hosted_tool_results(item_object, &["results"])?;
            return Ok(convert_hosted_tool_call(
                item_object,
                "file_search",
                HostedCallArgs::ActionOrRest,
            ));
        }
        "computer_call" => {
            return Ok(convert_hosted_tool_call(
                item_object,
                "computer",
                HostedCallArgs::Action,
            ));
        }
        "computer_call_output" => return Ok(convert_hosted_tool_output(item_object)),
        "code_interpreter_call" => {
            reject_hosted_tool_results(item_object, &["outputs"])?;
            return Ok(convert_hosted_tool_call(
                item_object,
                "code_interpreter",
                HostedCallArgs::ActionOrRest,
            ));
        }
        "code_interpreter_call_output" => return Ok(convert_hosted_tool_output(item_object)),
        "image_generation_call" => {
            reject_hosted_tool_results(item_object, &["result"])?;
            return Ok(convert_hosted_tool_call(
                item_object,
                "image_generation",
                HostedCallArgs::ActionOrRest,
            ));
        }
        "local_shell_call" | "shell_call" => {
            return Ok(convert_hosted_tool_call(
                item_object,
                "local_shell",
                HostedCallArgs::Action,
            ));
        }
        "local_shell_call_output" | "shell_call_output" => {
            return Ok(convert_hosted_tool_output(item_object));
        }
        "mcp_tool_call" => {
            if !ensure_call_id(item_object) || !non_empty_field(item_object, "name") {
                return Err(invalid_request(
                    "Grok replayed mcp_tool_call requires call_id and name",
                ));
            }
            let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
            let name = item_object
                .remove("name")
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_default();
            let arguments = item_object.remove("arguments").unwrap_or(Value::Null);
            rebuild_function_call(item_object, call_id, &name, arguments);
        }
        "mcp_tool_call_output" => {
            if !non_empty_field(item_object, "call_id") {
                return Err(invalid_request(
                    "Grok replayed mcp_tool_call_output requires a call_id",
                ));
            }
            let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
            let output = item_object.remove("output").unwrap_or(Value::Null);
            rebuild_function_output(item_object, call_id, custom_tool_output(output));
        }
        "mcp_call"
        | "mcp_list_tools"
        | "mcp_approval_request"
        | "mcp_approval_response"
        | "context_compaction" => return Err(unsupported_history_item(&item_type)),
        _ => strip_internal_item_fields(item_object),
    }

    Ok(true)
}

fn normalize_agent_message(item_object: &mut Map<String, Value>) -> Result<bool, ProviderError> {
    {
        let content = item_object
            .get_mut("content")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| invalid_request("Grok agent_message requires content items"))?;
        let mut normalized_content = Vec::with_capacity(content.len());
        for mut part in std::mem::take(content) {
            let part_object = part.as_object_mut().ok_or_else(|| {
                invalid_request("Grok agent_message content items must be objects")
            })?;
            match part_object.get("type").and_then(Value::as_str) {
                Some("input_text") => {
                    if !part_object.get("text").is_some_and(Value::is_string) {
                        return Err(invalid_request("Grok agent_message text must be a string"));
                    }
                    normalized_content.push(part);
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
                        return Err(invalid_request(
                            "Grok agent_message encrypted_content must be a string",
                        ));
                    };
                    part_object.insert("type".to_owned(), Value::String("input_text".to_owned()));
                    part_object.insert("text".to_owned(), Value::String(text));
                    part_object.remove("encrypted_content");
                    normalized_content.push(part);
                }
                Some(content_type) => {
                    return Err(invalid_request(format!(
                        "Grok cannot replay agent_message content type `{content_type}`"
                    )));
                }
                None => {
                    return Err(invalid_request(
                        "Grok agent_message content requires a type",
                    ));
                }
            }
        }
        *content = normalized_content;
        if content.is_empty() {
            return Ok(false);
        }
    }
    item_object.insert("type".to_owned(), Value::String("message".to_owned()));
    item_object.insert("role".to_owned(), Value::String("user".to_owned()));
    Ok(true)
}

fn rebuild_function_call(
    item_object: &mut Map<String, Value>,
    call_id: Value,
    name: &str,
    arguments: Value,
) {
    item_object.clear();
    item_object.insert("type".to_owned(), Value::String("function_call".to_owned()));
    item_object.insert("call_id".to_owned(), call_id);
    item_object.insert("name".to_owned(), Value::String(name.to_owned()));
    item_object.insert(
        "arguments".to_owned(),
        Value::String(json_object_string(arguments)),
    );
}

fn rebuild_function_output(item_object: &mut Map<String, Value>, call_id: Value, output: String) {
    item_object.clear();
    item_object.insert(
        "type".to_owned(),
        Value::String("function_call_output".to_owned()),
    );
    item_object.insert("call_id".to_owned(), call_id);
    item_object.insert("output".to_owned(), Value::String(output));
}

fn reject_hosted_tool_results(
    item_object: &Map<String, Value>,
    result_fields: &[&str],
) -> Result<(), ProviderError> {
    if let Some(field) = result_fields.iter().find(|field| {
        item_object
            .get(**field)
            .is_some_and(|value| !value.is_null())
    }) {
        let item_type = item_object
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("hosted_tool_call");
        return Err(invalid_request(format!(
            "Grok cannot preserve `{field}` result semantics from `{item_type}` history"
        )));
    }
    Ok(())
}

fn strip_internal_item_fields(item_object: &mut Map<String, Value>) {
    item_object.remove("phase");
    item_object.remove("encrypted_function_args");
    item_object.remove("internal_chat_message_metadata_passthrough");
}

fn unsupported_history_item(item_type: &str) -> ProviderError {
    invalid_request(format!(
        "Grok cannot safely replay Responses history item type `{item_type}`"
    ))
}

fn invalid_request(message: impl Into<String>) -> ProviderError {
    ProviderError::new(ProviderErrorKind::InvalidRequest, message.into())
}

#[derive(Clone, Copy)]
enum HostedCallArgs {
    Action,
    ActionOrRest,
}

fn item_call_id(item: &Map<String, Value>) -> Option<&str> {
    item.get("call_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            item.get("id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
}

fn ensure_call_id(item_object: &mut Map<String, Value>) -> bool {
    if non_empty_field(item_object, "call_id") {
        return true;
    }
    let Some(call_id) = item_object
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return false;
    };
    item_object.insert("call_id".to_owned(), Value::String(call_id));
    true
}

fn convert_hosted_tool_call(
    item_object: &mut Map<String, Value>,
    name: &str,
    args: HostedCallArgs,
) -> bool {
    if !ensure_call_id(item_object) {
        return false;
    }
    let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
    let arguments = match args {
        HostedCallArgs::Action => item_object.remove("action").unwrap_or(Value::Null),
        HostedCallArgs::ActionOrRest => {
            if let Some(action) = item_object.remove("action") {
                action
            } else {
                let mut rest = Map::new();
                let keys = item_object.keys().cloned().collect::<Vec<_>>();
                for key in keys {
                    if matches!(
                        key.as_str(),
                        "type" | "id" | "call_id" | "status" | "name" | "arguments"
                    ) {
                        continue;
                    }
                    if let Some(value) = item_object.remove(&key) {
                        rest.insert(key, value);
                    }
                }
                Value::Object(rest)
            }
        }
    };
    rebuild_function_call(item_object, call_id, name, arguments);
    true
}

fn convert_hosted_tool_output(item_object: &mut Map<String, Value>) -> bool {
    if !ensure_call_id(item_object) {
        return false;
    }
    let call_id = item_object.remove("call_id").unwrap_or(Value::Null);
    let output = item_object.remove("output").unwrap_or(Value::Null);
    rebuild_function_output(item_object, call_id, custom_tool_output(output));
    true
}

fn json_object_string(value: Value) -> String {
    match value {
        Value::String(value) => value,
        Value::Null => "{}".to_owned(),
        value => value.to_string(),
    }
}

fn non_empty_field(object: &Map<String, Value>, field: &str) -> bool {
    object
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn custom_tool_arguments(input: Value) -> String {
    let input = match input {
        Value::String(text) => text,
        Value::Null => String::new(),
        value => value.to_string(),
    };
    serde_json::json!({ "input": input }).to_string()
}

fn custom_tool_output(output: Value) -> String {
    match output {
        Value::String(text) => text,
        Value::Null => String::new(),
        value => value.to_string(),
    }
}
