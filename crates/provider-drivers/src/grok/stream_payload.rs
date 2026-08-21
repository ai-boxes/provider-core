use serde_json::Value;
use std::collections::HashMap;

use super::super::request::{GrokToolMappings, NamespaceToolRef};
use super::{ClientToolCall, ClientToolKind};

pub(super) fn normalize_reasoning_payload(payload: &mut Value) -> bool {
    let mut changed = match payload.get("type").and_then(Value::as_str) {
        Some("response.reasoning_text.delta") => {
            payload["type"] = Value::String("response.reasoning_summary_text.delta".to_owned());
            normalize_summary_index(payload);
            true
        }
        Some("response.content_part.added")
            if payload.pointer("/part/type").and_then(Value::as_str) == Some("reasoning_text") =>
        {
            payload["type"] = Value::String("response.reasoning_summary_part.added".to_owned());
            payload["part"]["type"] = Value::String("summary_text".to_owned());
            normalize_summary_index(payload);
            true
        }
        Some("response.content_part.done")
            if payload.pointer("/part/type").and_then(Value::as_str) == Some("reasoning_text") =>
        {
            payload["type"] = Value::String("response.reasoning_summary_part.done".to_owned());
            payload["part"]["type"] = Value::String("summary_text".to_owned());
            normalize_summary_index(payload);
            true
        }
        _ => false,
    };
    if let Some(item) = payload.get_mut("item") {
        changed |= normalize_reasoning_item(item);
    }
    if let Some(output) = payload
        .get_mut("response")
        .and_then(|response| response.get_mut("output"))
        .and_then(Value::as_array_mut)
    {
        for item in output {
            changed |= normalize_reasoning_item(item);
        }
    }
    changed
}

pub(super) fn normalize_reasoning_text_done(payload: &mut Value) {
    payload["type"] = Value::String("response.reasoning_summary_text.done".to_owned());
    normalize_summary_index(payload);
}

pub(super) fn normalize_reasoning_part_done(payload: &mut Value) {
    payload["type"] = Value::String("response.reasoning_summary_part.done".to_owned());
    let text = payload
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    payload["part"] = serde_json::json!({ "type": "summary_text", "text": text });
    if let Some(object) = payload.as_object_mut() {
        object.remove("text");
    }
    normalize_summary_index(payload);
}

fn normalize_summary_index(payload: &mut Value) {
    if payload.get("summary_index").is_none()
        && let Some(content_index) = payload.get("content_index").cloned()
    {
        payload["summary_index"] = content_index;
    }
    if let Some(object) = payload.as_object_mut() {
        object.remove("content_index");
    }
}

fn normalize_reasoning_item(item: &mut Value) -> bool {
    let Some(object) = item.as_object_mut() else {
        return false;
    };
    if object.get("type").and_then(Value::as_str) != Some("reasoning") {
        return false;
    }
    let mut changed = false;
    if let Some(summary) = object.get_mut("summary").and_then(Value::as_array_mut) {
        for part in summary {
            if part.get("type").and_then(Value::as_str) == Some("reasoning_text") {
                part["type"] = Value::String("summary_text".to_owned());
                changed = true;
            }
        }
    }
    let reasoning_parts = object
        .get("content")
        .and_then(Value::as_array)
        .map(|content| {
            content
                .iter()
                .filter(|part| part.get("type").and_then(Value::as_str) == Some("reasoning_text"))
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !reasoning_parts.is_empty() {
        let mut summary = Vec::with_capacity(reasoning_parts.len());
        for mut part in reasoning_parts {
            part["type"] = Value::String("summary_text".to_owned());
            summary.push(part);
        }
        object.insert("summary".to_owned(), Value::Array(summary));
        object.remove("content");
        changed = true;
    }
    changed
}

pub(super) fn is_terminal_response_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "response.completed"
            | "response.done"
            | "response.incomplete"
            | "response.failed"
            | "response.cancelled"
            | "response.canceled"
    )
}

pub(super) fn restore_terminal_tool_payload(
    payload: &mut Value,
    mappings: &GrokToolMappings,
) -> bool {
    let Some(output) = payload
        .get_mut("response")
        .and_then(|response| response.get_mut("output"))
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    let mut changed = false;
    for item in output {
        changed |= restore_tool_item(item, mappings);
    }
    changed
}

pub(super) fn restore_namespace_event(payload: &mut Value, mappings: &GrokToolMappings) -> bool {
    let mut changed = payload
        .get_mut("item")
        .is_some_and(|item| restore_namespace_tool_item(item, &mappings.namespace_tools));
    if matches!(
        payload.get("type").and_then(Value::as_str),
        Some("response.function_call_arguments.delta" | "response.function_call_arguments.done")
    ) && let Some(reference) = payload
        .get("name")
        .and_then(Value::as_str)
        .and_then(|name| mappings.namespace_tools.get(name))
        .cloned()
    {
        payload["name"] = Value::String(reference.name);
        changed = true;
    }
    changed
}

fn restore_tool_item(item: &mut Value, mappings: &GrokToolMappings) -> bool {
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if mappings.custom_tools.contains(&name) {
        let arguments = item
            .get("arguments")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let input = custom_tool_input(arguments);
        let mut changed = restore_custom_item_value(item, &input);
        changed |= restore_custom_namespace(item, &name, &mappings.namespace_tools);
        return changed;
    }
    if mappings.tool_search && name == "tool_search" {
        return restore_tool_search_item_value(item, true);
    }
    restore_namespace_tool_item(item, &mappings.namespace_tools)
}

pub(super) fn restore_client_tool_item(
    payload: &mut Value,
    field: &str,
    call: &ClientToolCall,
    input: &str,
) -> bool {
    payload.get_mut(field).is_some_and(|item| match call.kind {
        ClientToolKind::Custom => {
            let changed = restore_custom_item_value(item, input);
            if let Some(object) = item.as_object_mut() {
                object.insert("name".to_owned(), Value::String(call.name.clone()));
                if let Some(namespace) = &call.namespace {
                    object.insert("namespace".to_owned(), Value::String(namespace.clone()));
                }
            }
            changed
        }
        ClientToolKind::ToolSearch => restore_tool_search_item_value(item, false),
    })
}

fn restore_custom_namespace(
    item: &mut Value,
    upstream_name: &str,
    namespace_tools: &HashMap<String, NamespaceToolRef>,
) -> bool {
    let Some(reference) = namespace_tools.get(upstream_name) else {
        return false;
    };
    let Some(item) = item.as_object_mut() else {
        return false;
    };
    item.insert("name".to_owned(), Value::String(reference.name.clone()));
    item.insert(
        "namespace".to_owned(),
        Value::String(reference.namespace.clone()),
    );
    true
}
fn restore_custom_item_value(item: &mut Value, input: &str) -> bool {
    let Some(item) = item.as_object_mut() else {
        return false;
    };
    if item.get("type").and_then(Value::as_str) != Some("function_call") {
        return false;
    }
    item.insert(
        "type".to_owned(),
        Value::String("custom_tool_call".to_owned()),
    );
    item.insert("input".to_owned(), Value::String(input.to_owned()));
    item.remove("arguments");
    item.remove("namespace");
    true
}

fn restore_tool_search_item_value(item: &mut Value, terminal: bool) -> bool {
    let Some(item) = item.as_object_mut() else {
        return false;
    };
    if item.get("type").and_then(Value::as_str) != Some("function_call") {
        return false;
    }
    item.insert(
        "type".to_owned(),
        Value::String("tool_search_call".to_owned()),
    );
    item.remove("name");
    item.remove("namespace");
    if terminal {
        item.insert("execution".to_owned(), Value::String("client".to_owned()));
        if let Some(arguments) = item.get("arguments").and_then(Value::as_str)
            && let Ok(arguments) = serde_json::from_str::<Value>(arguments)
        {
            item.insert("arguments".to_owned(), arguments);
        }
    } else if item
        .get("arguments")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        item.insert("arguments".to_owned(), Value::String("{}".to_owned()));
    }
    true
}

pub(super) fn custom_tool_input(arguments: &str) -> String {
    serde_json::from_str::<Value>(arguments)
        .ok()
        .and_then(|value| value.get("input").cloned())
        .map(|input| match input {
            Value::String(value) => value,
            Value::Null => String::new(),
            value => value.to_string(),
        })
        .unwrap_or_default()
}

fn restore_namespace_tool_item(
    item: &mut Value,
    namespace_tools: &HashMap<String, NamespaceToolRef>,
) -> bool {
    let Some(item) = item.as_object_mut() else {
        return false;
    };
    if item.get("type").and_then(Value::as_str) != Some("function_call") {
        return false;
    }
    let Some(reference) = item
        .get("name")
        .and_then(Value::as_str)
        .and_then(|name| namespace_tools.get(name))
    else {
        return false;
    };
    item.insert("name".to_owned(), Value::String(reference.name.clone()));
    item.insert(
        "namespace".to_owned(),
        Value::String(reference.namespace.clone()),
    );
    true
}
