use bytes::Bytes;
use provider_core::{
    ProviderError, ProviderErrorKind, ProviderRequest, RequestMetadata, WireFormat,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const UNSUPPORTED_FIELDS: &[&str] = &[
    "previous_response_id",
    "prompt_cache_retention",
    "safety_identifier",
    "stream_options",
];

#[derive(Debug)]
pub(crate) struct PreparedGrokRequest {
    pub(crate) payload: Bytes,
    pub(crate) model: String,
    pub(crate) metadata: RequestMetadata,
    pub(crate) tool_mappings: GrokToolMappings,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GrokToolMappings {
    pub(crate) custom_tools: HashSet<String>,
    pub(crate) namespace_tools: HashMap<String, NamespaceToolRef>,
    pub(crate) tool_search: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceToolRef {
    pub(crate) namespace: String,
    pub(crate) name: String,
}

#[path = "request_history.rs"]
mod request_history;
#[path = "request_reasoning.rs"]
mod request_reasoning;
#[path = "request_tools.rs"]
mod request_tools;

use request_history::{
    normalize_input, reject_unknown_input_item_types, reject_unresolved_item_references,
    validate_tool_output_context,
};
use request_reasoning::{normalize_model_fields, normalize_reasoning};
use request_tools::{normalize_input_namespace_calls, normalize_tools, promote_additional_tools};

pub(crate) fn prepare_request(
    request: ProviderRequest,
) -> Result<PreparedGrokRequest, ProviderError> {
    if request.format != WireFormat::OpenAiResponses {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok driver requires the OpenAI Responses format",
        ));
    }

    let model = request.model.trim().to_owned();
    if model.is_empty() {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "model must not be empty",
        ));
    }
    let mut payload: Value = serde_json::from_slice(&request.payload).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok Responses request body must be valid JSON",
        )
    })?;
    let body = payload.as_object_mut().ok_or_else(|| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok Responses request body must be a JSON object",
        )
    })?;
    if request.metadata.previous_response_id.is_some()
        || body
            .get("previous_response_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok HTTP Responses requires complete input history and does not support previous_response_id",
        ));
    }

    body.insert("model".to_owned(), Value::String(model.clone()));
    body.insert("stream".to_owned(), Value::Bool(true));
    for field in UNSUPPORTED_FIELDS {
        body.remove(*field);
    }
    normalize_model_fields(body, &model);

    promote_additional_tools(body);
    let tool_mappings = normalize_tools(body)?;
    normalize_input_namespace_calls(body);
    reject_unresolved_item_references(body)?;
    normalize_input(body)?;
    normalize_reasoning(body);
    reject_unknown_input_item_types(body)?;
    validate_tool_output_context(body)?;

    let mut metadata = request.metadata;
    metadata.session_id = normalized_string(metadata.routing_session_id.as_deref())
        .or_else(|| normalized_string(metadata.session_id.as_deref()))
        .or_else(|| {
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

    Ok(PreparedGrokRequest {
        payload,
        model,
        metadata,
        tool_mappings,
    })
}

pub(crate) fn strip_encrypted_reasoning_for_retry(
    request: &ProviderRequest,
) -> Result<Option<ProviderRequest>, ProviderError> {
    let mut payload: Value = serde_json::from_slice(&request.payload).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok Responses request body must be valid JSON",
        )
    })?;
    let Some(body) = payload.as_object_mut() else {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok Responses request body must be a JSON object",
        ));
    };
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return Ok(None);
    };

    let mut changed = false;
    input.retain_mut(|item| {
        let Some(item) = item.as_object_mut() else {
            return true;
        };
        let is_reasoning = item.get("type").and_then(Value::as_str) == Some("reasoning");
        let is_compaction = matches!(
            item.get("type").and_then(Value::as_str),
            Some("compaction" | "compaction_summary")
        );
        if (!is_reasoning && !is_compaction) || !item.contains_key("encrypted_content") {
            return true;
        }
        changed = true;
        if !is_reasoning {
            return false;
        }
        item.remove("encrypted_content");
        if item.get("content").is_some_and(Value::is_null) {
            item.remove("content");
        }
        item.len() > 1
    });
    if !changed {
        return Ok(None);
    }

    let payload = serde_json::to_vec(&payload).map(Bytes::from).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::Internal,
            "failed to serialize Grok encrypted reasoning retry",
        )
    })?;
    let mut retry = request.clone();
    retry.payload = payload;
    Ok(Some(retry))
}

fn normalized_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    include!("request_tests.rs");
}
