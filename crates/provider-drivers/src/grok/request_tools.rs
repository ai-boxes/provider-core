use super::{GrokToolMappings, NamespaceToolRef};
use provider_core::{ProviderError, ProviderErrorKind};
use serde_json::{Map, Value};
use std::collections::HashSet;

const COLLABORATION_MESSAGE_TOOLS: &[&str] = &["spawn_agent", "send_message", "followup_task"];

pub(super) fn normalize_tools(
    body: &mut Map<String, Value>,
) -> Result<GrokToolMappings, ProviderError> {
    let mut mappings = GrokToolMappings::default();
    let Some(tools) = body.remove("tools") else {
        normalize_tool_controls_without_tools(body)?;
        return Ok(mappings);
    };
    if tools.is_null() {
        normalize_tool_controls_without_tools(body)?;
        return Ok(mappings);
    }
    let Value::Array(tools) = tools else {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok tools must be an array",
        ));
    };

    let mut tools = tools;
    strip_collaboration_message_encryption(&mut tools);
    let tools = flatten_namespace_tools(tools);
    let mut normalized = Vec::new();
    for (tool, namespace_reference) in tools {
        let was_custom = tool.get("type").and_then(Value::as_str) == Some("custom");
        let was_tool_search = tool.get("type").and_then(Value::as_str) == Some("tool_search");
        let tool = if was_tool_search {
            if mappings.tool_search {
                continue;
            }
            mappings.tool_search = true;
            tool_search_proxy_tool()
        } else if let Some(tool) = normalize_tool(tool) {
            tool
        } else {
            continue;
        };
        if let Some(name) = tool.get("name").and_then(Value::as_str).map(str::to_owned) {
            if was_custom {
                mappings.custom_tools.insert(name.clone());
            }
            if let Some(namespace_reference) = namespace_reference {
                mappings.namespace_tools.insert(name, namespace_reference);
            }
        }
        normalized.push(tool);
    }
    let mut unique_tools = HashSet::new();
    for key in normalized.iter().filter_map(tool_key) {
        if !unique_tools.insert(key) {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Grok tool names must remain unique after namespace normalization",
            ));
        }
    }
    if normalized.is_empty() {
        normalize_tool_controls_without_tools(body)?;
    } else {
        body.insert("tools".to_owned(), Value::Array(normalized));
        normalize_tool_choice(body)?;
    }
    Ok(mappings)
}

fn strip_collaboration_message_encryption(tools: &mut [Value]) {
    for tool in tools {
        let Some(tool_object) = tool.as_object_mut() else {
            continue;
        };
        if tool_object.get("type").and_then(Value::as_str) == Some("namespace") {
            if let Some(Value::Array(nested_tools)) = tool_object.get_mut("tools") {
                strip_collaboration_message_encryption(nested_tools);
            }
            continue;
        }
        if tool_object.get("type").and_then(Value::as_str) != Some("function") {
            continue;
        }
        if !COLLABORATION_MESSAGE_TOOLS.contains(
            &tool_object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) {
            continue;
        }
        let Some(message) = tool_object
            .get_mut("parameters")
            .and_then(Value::as_object_mut)
            .and_then(|parameters| parameters.get_mut("properties"))
            .and_then(Value::as_object_mut)
            .and_then(|properties| properties.get_mut("message"))
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        message.remove("encrypted");
    }
}

fn normalize_tool_controls_without_tools(
    body: &mut Map<String, Value>,
) -> Result<(), ProviderError> {
    body.remove("parallel_tool_calls");
    let Some(choice) = body.remove("tool_choice") else {
        return Ok(());
    };
    let optional = match &choice {
        Value::String(mode) => matches!(mode.as_str(), "auto" | "none"),
        Value::Object(choice) => choice
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|mode| matches!(mode, "auto" | "none")),
        Value::Null => true,
        _ => false,
    };
    if optional {
        Ok(())
    } else {
        Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok tool_choice requires at least one supported tool",
        ))
    }
}

fn flatten_namespace_tools(tools: Vec<Value>) -> Vec<(Value, Option<NamespaceToolRef>)> {
    let mut flattened = Vec::new();
    for mut tool in tools {
        let Some(tool_object) = tool.as_object_mut() else {
            flattened.push((tool, None));
            continue;
        };
        if tool_object.get("type").and_then(Value::as_str) != Some("namespace") {
            flattened.push((tool, None));
            continue;
        }
        let namespace = tool_object
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let nested = tool_object.remove("tools");
        let (Some(namespace), Some(Value::Array(nested))) = (namespace, nested) else {
            continue;
        };
        for mut nested_tool in nested {
            let Some(nested_object) = nested_tool.as_object_mut() else {
                continue;
            };
            let Some(name) = nested_object
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
            else {
                continue;
            };
            let qualified = qualify_namespace_tool_name(&namespace, &name);
            nested_object.insert("name".to_owned(), Value::String(qualified.clone()));
            flattened.push((
                nested_tool,
                Some(NamespaceToolRef {
                    namespace: namespace.clone(),
                    name,
                }),
            ));
        }
    }
    flattened
}

fn qualify_namespace_tool_name(namespace: &str, name: &str) -> String {
    if name.starts_with("mcp__") {
        name.to_owned()
    } else {
        format!("{}__{}", namespace.trim_end_matches("__"), name)
    }
}

pub(super) fn promote_additional_tools(body: &mut Map<String, Value>) {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return;
    };
    let mut promoted = Vec::new();
    input.retain_mut(|item| {
        let Some(item) = item.as_object_mut() else {
            return true;
        };
        if item.get("type").and_then(Value::as_str) != Some("additional_tools") {
            return true;
        }
        if let Some(Value::Array(tools)) = item.remove("tools") {
            promoted.extend(tools);
        }
        false
    });
    if promoted.is_empty() {
        return;
    }
    match body.get_mut("tools") {
        Some(Value::Array(tools)) => tools.extend(promoted),
        None | Some(Value::Null) => {
            body.insert("tools".to_owned(), Value::Array(promoted));
        }
        Some(_) => {}
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
        "image_generation" | "namespace" => return None,
        "custom" => {
            tool_object.insert("type".to_owned(), Value::String("function".to_owned()));
            tool_object.remove("format");
            tool_object.insert("parameters".to_owned(), custom_tool_schema());
        }
        "function" => {
            normalize_function_parameters(tool_object);
        }
        "web_search" => {
            tool_object.remove("external_web_access");
        }
        _ => {}
    }

    Some(tool)
}

fn tool_search_proxy_tool() -> Value {
    serde_json::json!({
        "type": "function",
        "name": "tool_search",
        "description": "Search and load Codex tools, plugins, connectors, and MCP namespaces for the current task.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query for tools or connectors to load."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of tool groups to return."
                }
            },
            "required": ["query"]
        }
    })
}

fn normalize_tool_choice(body: &mut Map<String, Value>) -> Result<(), ProviderError> {
    let available = body
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(tool_key)
        .collect::<HashSet<_>>();
    let Some(mut value) = body.remove("tool_choice") else {
        return Ok(());
    };
    if value.get("type").and_then(Value::as_str) == Some("web_search") {
        value = serde_json::json!({
            "type": "allowed_tools",
            "mode": "required",
            "tools": [value]
        });
    }
    let Some(choice) = value.as_object_mut() else {
        body.insert("tool_choice".to_owned(), value);
        return Ok(());
    };
    if choice.get("type").and_then(Value::as_str) == Some("allowed_tools") {
        let Some(Value::Array(tools)) = choice.get_mut("tools") else {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Grok allowed_tools choice requires a tools array",
            ));
        };
        tools.retain_mut(|tool| normalize_tool_choice_ref(tool, &available));
        if !tools.is_empty() {
            body.insert("tool_choice".to_owned(), value);
            return Ok(());
        }
        let required = choice.get("mode").and_then(Value::as_str) == Some("required");
        return if required {
            Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Grok required allowed_tools choice contains no supported tools",
            ))
        } else {
            Ok(())
        };
    }
    if normalize_tool_choice_ref(&mut value, &available) {
        body.insert("tool_choice".to_owned(), value);
        Ok(())
    } else {
        Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok forced tool_choice does not reference a supported tool",
        ))
    }
}

fn normalize_tool_choice_ref(value: &mut Value, available: &HashSet<(String, String)>) -> bool {
    let Some(choice) = value.as_object_mut() else {
        return false;
    };
    let Some(tool_type) = choice
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return false;
    };
    if matches!(tool_type.as_str(), "image_generation" | "namespace") {
        return false;
    }
    if tool_type == "tool_search" {
        choice.insert("type".to_owned(), Value::String("function".to_owned()));
        choice.insert("name".to_owned(), Value::String("tool_search".to_owned()));
    }
    if tool_type == "custom" {
        choice.insert("type".to_owned(), Value::String("function".to_owned()));
    }
    if let Some(namespace) = choice
        .remove("namespace")
        .and_then(|value| value.as_str().map(str::to_owned))
        && let Some(name) = choice
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
    {
        choice.insert(
            "name".to_owned(),
            Value::String(qualify_namespace_tool_name(&namespace, &name)),
        );
    }
    let normalized_type = if matches!(tool_type.as_str(), "custom" | "tool_search") {
        "function"
    } else {
        tool_type.as_str()
    };
    let name = choice
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    available.contains(&(normalized_type.to_owned(), name.to_owned()))
}
pub(super) fn normalize_input_namespace_calls(body: &mut Map<String, Value>) {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return;
    };
    for item in input {
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        if !matches!(
            item.get("type").and_then(Value::as_str),
            Some("function_call" | "custom_tool_call")
        ) {
            continue;
        }
        let Some(namespace) = item
            .remove("namespace")
            .and_then(|value| value.as_str().map(str::to_owned))
        else {
            continue;
        };
        let Some(name) = item.get("name").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        item.insert(
            "name".to_owned(),
            Value::String(qualify_namespace_tool_name(&namespace, &name)),
        );
    }
}

fn tool_key(tool: &Value) -> Option<(String, String)> {
    let tool = tool.as_object()?;
    let tool_type = tool.get("type")?.as_str()?.to_owned();
    let name = tool
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Some((tool_type, name))
}
fn empty_object_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {}
    })
}

fn safe_function_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {},
        "additionalProperties": true
    })
}

fn normalize_function_parameters(tool: &mut Map<String, Value>) {
    let name = tool.get("name").and_then(Value::as_str).unwrap_or_default();
    let is_automation_update = name.eq_ignore_ascii_case("codex_app__automation_update");
    let mut parameters = tool
        .remove("parameters")
        .filter(|value| !value.is_null())
        .unwrap_or_else(empty_object_schema);

    normalize_object_root_union_branches(&mut parameters);
    let needs_safe_schema = is_automation_update || !root_unions_are_object_only(&parameters);
    tool.insert(
        "parameters".to_owned(),
        if needs_safe_schema {
            safe_function_schema()
        } else {
            parameters
        },
    );
    if needs_safe_schema && tool.get("strict").and_then(Value::as_bool) == Some(true) {
        tool.insert("strict".to_owned(), Value::Bool(false));
    }
}

fn normalize_object_root_union_branches(parameters: &mut Value) {
    let Some(parameters) = parameters.as_object_mut() else {
        return;
    };
    if parameters.get("type").and_then(Value::as_str) != Some("object") {
        return;
    }
    for union_name in ["anyOf", "oneOf"] {
        let Some(Value::Array(branches)) = parameters.get_mut(union_name) else {
            continue;
        };
        for branch in branches {
            let Some(branch) = branch.as_object_mut() else {
                continue;
            };
            if !branch.contains_key("type") {
                branch.insert("type".to_owned(), Value::String("object".to_owned()));
            }
        }
    }
}

fn root_unions_are_object_only(parameters: &Value) -> bool {
    let Some(parameters) = parameters.as_object() else {
        return true;
    };
    for union_name in ["anyOf", "oneOf"] {
        let Some(Value::Array(branches)) = parameters.get(union_name) else {
            continue;
        };
        if branches.iter().any(|branch| {
            branch
                .get("type")
                .is_none_or(|schema_type| !schema_type_is_object_only(schema_type))
        }) {
            return false;
        }
    }
    true
}

fn schema_type_is_object_only(schema_type: &Value) -> bool {
    match schema_type {
        Value::String(value) => value.trim().eq_ignore_ascii_case("object"),
        Value::Array(values) if !values.is_empty() => values.iter().all(|value| {
            value
                .as_str()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("object"))
        }),
        _ => false,
    }
}

fn custom_tool_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "input": { "type": "string" }
        },
        "required": ["input"],
        "additionalProperties": false
    })
}
