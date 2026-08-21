use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::StreamExt;
use provider_core::{
    ProviderError, ProviderErrorKind, ProviderRequest, ProviderStream, RequestMetadata,
};
use serde_json::{Map, Value};

const REPLAY_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_REPLAY_SESSIONS: usize = 128;
const MAX_REPLAY_ITEMS: usize = 64;
const MAX_REPLAY_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct GrokReplayScope {
    routing_scope: String,
    model: String,
    session_id: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct GrokReplayKey {
    scope: GrokReplayScope,
    response_id: String,
}

#[derive(Clone)]
struct ReplayEntry {
    items: Vec<Value>,
    stored_at: Instant,
}

#[derive(Default)]
pub(crate) struct GrokReplayCache {
    entries: Mutex<HashMap<GrokReplayKey, ReplayEntry>>,
}

impl GrokReplayCache {
    pub(crate) fn prepare_request(
        &self,
        mut request: ProviderRequest,
    ) -> Result<(ProviderRequest, Option<GrokReplayScope>), ProviderError> {
        let scope = replay_scope(&request.metadata, &request.model);
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
        let previous_response_id = request
            .metadata
            .previous_response_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                body.get("previous_response_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            });
        let expanded_references = if input_has_item_reference(body) {
            let Some(scope) = scope.as_ref() else {
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidRequest,
                    "Grok continuation state is unavailable; resend complete input history",
                ));
            };
            expand_item_references(body, self, scope, previous_response_id.as_deref())?;
            true
        } else {
            false
        };
        let output_call_ids = tool_output_call_ids(body);
        let entry = scope
            .as_ref()
            .and_then(|scope| {
                if previous_response_id.is_some()
                    || !output_call_ids.is_empty()
                    || !scope.session_id.is_empty()
                {
                    Some(self.entry(scope, previous_response_id.as_deref(), &output_call_ids))
                } else {
                    None
                }
            })
            .flatten();
        // item_reference expansion already materializes the referenced history.
        // Running inject on top of that would duplicate assistant/tool items.
        let replayed = if expanded_references {
            false
        } else {
            entry
                .as_ref()
                .is_some_and(|entry| inject_replay_items(body, &entry.items))
        };

        if previous_response_id.is_some()
            && (entry.is_none() || !replayed)
            && !request_contains_complete_history(body)
        {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Grok continuation state is unavailable; resend complete input history",
            ));
        }
        let output_call_ids = tool_output_call_ids(body);
        if has_unpaired_tool_outputs(body, &output_call_ids) {
            // Keep the pre-expansion fail-closed gate, and only tighten it when
            // this turn already claimed reconstruction via expansion or inject.
            // A self-contained body that still carries previous_response_id is
            // left for request.rs validation instead of being rejected here.
            let cache_miss = entry.is_none() || !replayed;
            let should_reject =
                expanded_references || replayed || (previous_response_id.is_none() && cache_miss);
            if should_reject {
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidRequest,
                    "Grok tool continuation state is unavailable or ambiguous; resend complete input history",
                ));
            }
        }
        if previous_response_id.is_some() || replayed || expanded_references {
            body.remove("previous_response_id");
            request.metadata.previous_response_id = None;
        }
        request.payload = serde_json::to_vec(&payload).map(Bytes::from).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "failed to serialize Grok replay request",
            )
        })?;
        Ok((request, scope))
    }

    pub(crate) fn observe_stream(
        self: &Arc<Self>,
        scope: Option<GrokReplayScope>,
        stream: ProviderStream,
    ) -> ProviderStream {
        let Some(scope) = scope else {
            return stream;
        };
        let cache = self.clone();
        Box::pin(futures_util::stream::unfold(
            (stream, String::new(), false),
            move |(mut stream, mut response_id, mut terminal_seen)| {
                let cache = cache.clone();
                let scope = scope.clone();
                async move {
                    let Some(chunk) = stream.next().await else {
                        if !terminal_seen && !response_id.is_empty() {
                            cache.invalidate_response_id(&scope, &response_id);
                        }
                        return None;
                    };
                    if let Ok(bytes) = &chunk
                        && let Some(mut payload) = frame_payload(bytes)
                    {
                        match payload.get("type").and_then(Value::as_str) {
                            Some("response.created") => {
                                if let Some(id) = payload
                                    .pointer("/response/id")
                                    .and_then(Value::as_str)
                                    .map(str::trim)
                                    .filter(|value| !value.is_empty())
                                {
                                    response_id = id.to_owned();
                                }
                            }
                            Some("response.completed") => {
                                if payload
                                    .pointer("/response/id")
                                    .and_then(Value::as_str)
                                    .is_none()
                                    && !response_id.is_empty()
                                {
                                    if !payload.get("response").is_some_and(Value::is_object) {
                                        payload["response"] = Value::Object(Map::new());
                                    }
                                    payload["response"]["id"] = Value::String(response_id.clone());
                                }
                                cache.store_completed(&scope, &payload);
                                terminal_seen = true;
                            }
                            Some(
                                "response.failed"
                                | "response.incomplete"
                                | "response.cancelled"
                                | "response.canceled",
                            ) => {
                                if payload
                                    .pointer("/response/id")
                                    .and_then(Value::as_str)
                                    .is_none()
                                    && !response_id.is_empty()
                                {
                                    if !payload.get("response").is_some_and(Value::is_object) {
                                        payload["response"] = Value::Object(Map::new());
                                    }
                                    payload["response"]["id"] = Value::String(response_id.clone());
                                }
                                cache.invalidate_terminal(&scope, &payload);
                                terminal_seen = true;
                            }
                            _ => {}
                        }
                    }
                    if chunk.is_err() && !terminal_seen && !response_id.is_empty() {
                        cache.invalidate_response_id(&scope, &response_id);
                    }
                    Some((chunk, (stream, response_id, terminal_seen)))
                }
            },
        ))
    }

    fn cached_items_for_session(&self, scope: &GrokReplayScope) -> Vec<Value> {
        debug_assert!(!scope.session_id.is_empty());
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|_, entry| now.duration_since(entry.stored_at) < REPLAY_TTL);
        let mut matched = entries
            .iter()
            .filter(|(key, _)| {
                key.scope.routing_scope == scope.routing_scope
                    && key.scope.model == scope.model
                    && key.scope.session_id == scope.session_id
            })
            .collect::<Vec<_>>();
        matched.sort_by_key(|(_, entry)| entry.stored_at);
        matched
            .into_iter()
            .flat_map(|(_, entry)| entry.items.iter().cloned())
            .collect()
    }

    fn entry(
        &self,
        scope: &GrokReplayScope,
        previous_response_id: Option<&str>,
        output_call_ids: &[String],
    ) -> Option<ReplayEntry> {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|_, entry| now.duration_since(entry.stored_at) < REPLAY_TTL);
        if let Some(previous_response_id) = previous_response_id {
            let candidates = entries
                .iter()
                .filter(|(key, _)| {
                    key.response_id == previous_response_id
                        && key.scope.routing_scope == scope.routing_scope
                        && key.scope.model == scope.model
                })
                .collect::<Vec<_>>();
            if !scope.session_id.is_empty() {
                let exact_candidates = candidates
                    .iter()
                    .filter(|(key, _)| key.scope.session_id == scope.session_id)
                    .collect::<Vec<_>>();
                match exact_candidates.as_slice() {
                    [(_, entry)] => return Some((*entry).clone()),
                    [] => {}
                    _ => return None,
                }
            }
            return (candidates.len() == 1).then(|| candidates[0].1.clone());
        }
        if scope.session_id.is_empty() && output_call_ids.is_empty() {
            return None;
        }
        if entries
            .iter()
            .filter(|(key, _)| key.scope == *scope)
            .max_by_key(|(_, entry)| entry.stored_at)
            .is_some_and(|(_, entry)| entry.items.is_empty())
        {
            return None;
        }
        let candidates = entries
            .iter()
            .filter(|(key, entry)| {
                key.scope == *scope
                    && (output_call_ids.is_empty()
                        || replay_entry_matches_outputs(entry, output_call_ids))
            })
            .collect::<Vec<_>>();
        if !output_call_ids.is_empty() && candidates.len() != 1 {
            return None;
        }
        candidates
            .into_iter()
            .max_by_key(|(_, entry)| entry.stored_at)
            .map(|(_, entry)| entry.clone())
    }

    fn store_completed(&self, scope: &GrokReplayScope, payload: &Value) {
        let Some(response) = payload.get("response").and_then(Value::as_object) else {
            return;
        };
        let response_id = response
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_default()
            .to_owned();
        let mut items = Vec::new();
        let mut too_many_items = false;
        if let Some(output) = response.get("output").and_then(Value::as_array) {
            for item in output.iter().filter(|item| is_replayable_item(item)) {
                if items.len() >= MAX_REPLAY_ITEMS {
                    too_many_items = true;
                    break;
                }
                items.push(item.clone());
            }
        }
        let bytes = serde_json::to_vec(&items).map_or(usize::MAX, |items| items.len());
        if too_many_items || bytes > MAX_REPLAY_BYTES {
            items.clear();
        }
        self.store_entry(scope, &response_id, items);
    }

    fn invalidate_terminal(&self, scope: &GrokReplayScope, payload: &Value) {
        let Some(response_id) = payload
            .pointer("/response/id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        self.invalidate_response_id(scope, response_id);
    }

    fn invalidate_response_id(&self, scope: &GrokReplayScope, response_id: &str) {
        self.store_entry(scope, response_id, Vec::new());
    }

    fn store_entry(&self, scope: &GrokReplayScope, response_id: &str, items: Vec<Value>) {
        if response_id.trim().is_empty() {
            return;
        }
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let key = GrokReplayKey {
            scope: scope.clone(),
            response_id: response_id.trim().to_owned(),
        };
        if entries.len() >= MAX_REPLAY_SESSIONS && !entries.contains_key(&key) {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.stored_at)
                .map(|(scope, _)| scope.clone());
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key,
            ReplayEntry {
                items,
                stored_at: Instant::now(),
            },
        );
    }
}

fn replay_scope(metadata: &RequestMetadata, model: &str) -> Option<GrokReplayScope> {
    let routing_scope = metadata.routing_scope.as_deref()?.trim();
    let model = model.trim();
    if routing_scope.is_empty() || model.is_empty() {
        return None;
    }
    Some(GrokReplayScope {
        routing_scope: routing_scope.to_owned(),
        model: model.to_owned(),
        session_id: metadata
            .routing_session_id
            .as_deref()
            .or(metadata.session_id.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_default()
            .to_owned(),
    })
}

fn inject_replay_items(body: &mut Map<String, Value>, cached: &[Value]) -> bool {
    if let Some(Value::String(text)) = body.get("input").cloned() {
        if !cached.iter().any(|item| {
            matches!(
                item.get("type").and_then(Value::as_str),
                Some("reasoning" | "message")
            )
        }) {
            return false;
        }
        body.insert(
            "input".to_owned(),
            Value::Array(vec![serde_json::json!({
                "role": "user",
                "content": text,
            })]),
        );
    }
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return false;
    };
    let output_call_ids = input
        .iter()
        .filter_map(|item| {
            matches!(
                item.get("type").and_then(Value::as_str),
                Some(
                    "function_call_output"
                        | "custom_tool_call_output"
                        | "local_shell_call_output"
                        | "tool_search_output"
                        | "mcp_tool_call_output"
                )
            )
            .then(|| {
                item.get("call_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .flatten()
        })
        .collect::<Vec<_>>();
    let existing_call_ids = input
        .iter()
        .filter(|item| {
            matches!(
                item.get("type").and_then(Value::as_str),
                Some(
                    "function_call"
                        | "custom_tool_call"
                        | "local_shell_call"
                        | "tool_search_call"
                        | "mcp_tool_call"
                )
            )
        })
        .filter_map(|item| {
            item.get("call_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    let has_assistant = input.iter().any(|item| {
        item.get("role").and_then(Value::as_str) == Some("assistant")
            || item.get("type").and_then(Value::as_str) == Some("reasoning")
    });
    let mut replay = Vec::new();
    for item in cached {
        let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
        let include = match item_type {
            "reasoning" | "message" => !has_assistant,
            "function_call" | "custom_tool_call" | "local_shell_call" | "tool_search_call"
            | "mcp_tool_call" => {
                item.get("call_id")
                    .and_then(Value::as_str)
                    .is_some_and(|call_id| {
                        output_call_ids.iter().any(|output| output == call_id)
                            && !existing_call_ids.iter().any(|existing| existing == call_id)
                    })
            }
            _ => false,
        };
        if include {
            replay.push(item.clone());
        }
    }
    if replay.is_empty() {
        return false;
    }
    replay.append(input);
    *input = replay;
    true
}

fn tool_output_call_ids(body: &Map<String, Value>) -> Vec<String> {
    body.get("input")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            matches!(
                item.get("type").and_then(Value::as_str),
                Some(
                    "function_call_output"
                        | "custom_tool_call_output"
                        | "local_shell_call_output"
                        | "tool_search_output"
                        | "mcp_tool_call_output"
                )
            )
        })
        .filter_map(|item| {
            item.get("call_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|call_id| !call_id.is_empty())
                .map(str::to_owned)
        })
        .collect()
}

fn replay_entry_matches_outputs(entry: &ReplayEntry, output_call_ids: &[String]) -> bool {
    output_call_ids.iter().all(|output_call_id| {
        entry.items.iter().any(|item| {
            matches!(
                item.get("type").and_then(Value::as_str),
                Some(
                    "function_call"
                        | "custom_tool_call"
                        | "local_shell_call"
                        | "tool_search_call"
                        | "mcp_tool_call"
                )
            ) && item.get("call_id").and_then(Value::as_str) == Some(output_call_id)
        })
    })
}

fn has_unpaired_tool_outputs(body: &Map<String, Value>, output_call_ids: &[String]) -> bool {
    if output_call_ids.is_empty() {
        return false;
    }
    let calls = body
        .get("input")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            matches!(
                item.get("type").and_then(Value::as_str),
                Some(
                    "function_call"
                        | "custom_tool_call"
                        | "local_shell_call"
                        | "tool_search_call"
                        | "mcp_tool_call"
                )
            )
        })
        .filter_map(|item| item.get("call_id").and_then(Value::as_str))
        .collect::<Vec<_>>();
    output_call_ids
        .iter()
        .any(|output| !calls.iter().any(|call| *call == output))
}

fn request_contains_complete_history(body: &Map<String, Value>) -> bool {
    let Some(Value::Array(input)) = body.get("input") else {
        return false;
    };
    input.iter().any(|item| {
        matches!(
            item.get("type").and_then(Value::as_str),
            Some(
                "reasoning"
                    | "function_call"
                    | "custom_tool_call"
                    | "local_shell_call"
                    | "tool_search_call"
                    | "mcp_tool_call"
            )
        ) || item.get("role").and_then(Value::as_str) == Some("assistant")
    })
}

fn input_has_item_reference(body: &Map<String, Value>) -> bool {
    body.get("input")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|item| item.get("type").and_then(Value::as_str) == Some("item_reference"))
}

fn expand_item_references(
    body: &mut Map<String, Value>,
    cache: &GrokReplayCache,
    scope: &GrokReplayScope,
    previous_response_id: Option<&str>,
) -> Result<(), ProviderError> {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return Ok(());
    };

    let cached_items = if let Some(previous_response_id) = previous_response_id {
        cache
            .entry(scope, Some(previous_response_id), &[])
            .map(|entry| entry.items)
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::InvalidRequest,
                    "Grok continuation state is unavailable to resolve item_reference; resend complete input history",
                )
            })?
    } else {
        if scope.session_id.is_empty() {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Grok continuation state is unavailable to resolve item_reference; resend complete input history",
            ));
        }
        cache.cached_items_for_session(scope)
    };

    let mut index = HashMap::<String, Value>::new();
    let mut local_ids = HashSet::new();
    let mut ambiguous_ids = HashSet::new();
    for item in input.iter() {
        if item.get("type").and_then(Value::as_str) == Some("item_reference") {
            continue;
        }
        if let Some(id) = item
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let id = id.to_owned();
            if !local_ids.insert(id.clone()) {
                ambiguous_ids.insert(id.clone());
            }
            index.entry(id).or_insert_with(|| item.clone());
        }
    }
    for item in cached_items {
        if let Some(id) = item
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let id = id.to_owned();
            if local_ids.contains(&id) {
                continue;
            }
            if index.insert(id.clone(), item).is_some() {
                ambiguous_ids.insert(id);
            }
        }
    }

    let mut unresolved = false;
    for item in input.iter_mut() {
        let Some(item_object) = item.as_object() else {
            continue;
        };
        if item_object.get("type").and_then(Value::as_str) != Some("item_reference") {
            continue;
        }
        let Some(id) = item_object
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
        else {
            unresolved = true;
            continue;
        };
        match index.get(&id).filter(|_| !ambiguous_ids.contains(&id)) {
            Some(resolved) => *item = resolved.clone(),
            None => unresolved = true,
        }
    }

    if unresolved {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Grok continuation state is unavailable or ambiguous for item_reference; resend complete input history",
        ));
    }
    Ok(())
}

fn is_replayable_item(item: &Value) -> bool {
    matches!(
        item.get("type").and_then(Value::as_str),
        Some(
            "reasoning"
                | "message"
                | "function_call"
                | "custom_tool_call"
                | "local_shell_call"
                | "tool_search_call"
                | "mcp_tool_call"
        )
    )
}

fn frame_payload(frame: &[u8]) -> Option<Value> {
    let mut data = Vec::new();
    for line in sse_lines(frame) {
        let Some(part) = line
            .strip_prefix(b"data: ")
            .or_else(|| line.strip_prefix(b"data:"))
        else {
            continue;
        };
        if !data.is_empty() {
            data.push(b'\n');
        }
        data.extend_from_slice(part);
    }
    serde_json::from_slice(&data).ok()
}

fn sse_lines(frame: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < frame.len() {
        if !matches!(frame[index], b'\r' | b'\n') {
            index += 1;
            continue;
        }
        lines.push(&frame[start..index]);
        let crlf = frame[index] == b'\r' && frame.get(index + 1) == Some(&b'\n');
        index += if crlf { 2 } else { 1 };
        start = index;
    }
    if start < frame.len() {
        lines.push(&frame[start..]);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use provider_core::WireFormat;

    fn request(payload: Value, routing_scope: &str) -> ProviderRequest {
        let mut metadata = RequestMetadata::default();
        metadata.session_id = Some("session-1".to_owned());
        metadata.routing_scope = Some(routing_scope.to_owned());
        ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: serde_json::to_vec(&payload).expect("request JSON").into(),
            metadata,
        }
    }

    fn store(cache: &GrokReplayCache, routing_scope: &str) {
        let request = request(serde_json::json!({"input":"first"}), routing_scope);
        let scope = replay_scope(&request.metadata, &request.model).expect("scope");
        cache.store_completed(
            &scope,
            &serde_json::json!({
                "type":"response.completed",
                "response":{
                    "id":"resp_1",
                    "output":[
                        {"type":"reasoning","encrypted_content":"opaque","summary":[]},
                        {"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"}
                    ]
                }
            }),
        );
    }

    #[test]
    fn injects_matching_tool_context_and_strips_previous_response_id() {
        let cache = GrokReplayCache::default();
        store(&cache, "key-a");
        let mut request = request(
            serde_json::json!({
                "previous_response_id":"resp_1",
                "input":[{"type":"function_call_output","call_id":"call_1","output":"done"}]
            }),
            "key-a",
        );
        request.metadata.previous_response_id = Some("resp_1".to_owned());

        let (prepared, _) = cache.prepare_request(request).expect("replayed request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        assert!(body.get("previous_response_id").is_none());
        assert_eq!(body["input"][0]["type"], "reasoning");
        assert_eq!(body["input"][1]["type"], "function_call");
        assert_eq!(body["input"][2]["type"], "function_call_output");
        assert_eq!(prepared.metadata.previous_response_id, None);
    }

    #[test]
    fn rejects_unknown_or_cross_key_continuation() {
        let cache = GrokReplayCache::default();
        store(&cache, "key-a");
        let mut request = request(
            serde_json::json!({
                "previous_response_id":"resp_1",
                "input":[{"type":"function_call_output","call_id":"call_1","output":"done"}]
            }),
            "key-b",
        );
        request.metadata.previous_response_id = Some("resp_1".to_owned());

        let error = cache
            .prepare_request(request)
            .expect_err("cross-key replay must fail");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
        assert!(error.message().contains("complete input history"));
    }

    #[test]
    fn replays_previous_response_without_a_session_seed() {
        let cache = GrokReplayCache::default();
        store(&cache, "key-a");
        let mut request = request(
            serde_json::json!({
                "previous_response_id":"resp_1",
                "input":[{"type":"function_call_output","call_id":"call_1","output":"done"}]
            }),
            "key-a",
        );
        request.metadata.session_id = None;
        request.metadata.previous_response_id = Some("resp_1".to_owned());

        let (prepared, _) = cache.prepare_request(request).expect("response-id replay");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        assert_eq!(body["input"][0]["type"], "reasoning");
        assert_eq!(body["input"][1]["call_id"], "call_1");
        assert_eq!(body["input"][2]["call_id"], "call_1");
        assert!(body.get("previous_response_id").is_none());
    }

    #[test]
    fn replays_previous_response_into_scalar_input() {
        let cache = GrokReplayCache::default();
        let base = request(serde_json::json!({"input":"first"}), "key-a");
        let scope = replay_scope(&base.metadata, &base.model).expect("scope");
        cache.store_completed(
            &scope,
            &serde_json::json!({
                "type":"response.completed",
                "response":{
                    "id":"resp_scalar",
                    "output":[
                        {"type":"reasoning","summary":[]},
                        {"type":"message","role":"assistant","content":"prior"}
                    ]
                }
            }),
        );
        let mut continuation = request(
            serde_json::json!({
                "previous_response_id":"resp_scalar",
                "input":"continue"
            }),
            "key-a",
        );
        continuation.metadata.session_id = None;
        continuation.metadata.previous_response_id = Some("resp_scalar".to_owned());

        let (prepared, _) = cache
            .prepare_request(continuation)
            .expect("scalar response-id replay");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        assert_eq!(body["input"][0]["type"], "reasoning");
        assert_eq!(body["input"][1]["role"], "assistant");
        assert_eq!(body["input"][2]["role"], "user");
        assert_eq!(body["input"][2]["content"], "continue");
    }

    #[test]
    fn accepts_self_contained_history_without_cache() {
        let cache = GrokReplayCache::default();
        let mut request = request(
            serde_json::json!({
                "previous_response_id":"resp_old",
                "input":[
                    {"type":"message","role":"assistant","content":"prior"},
                    {"type":"message","role":"user","content":"next"}
                ]
            }),
            "key-a",
        );
        request.metadata.previous_response_id = Some("resp_old".to_owned());

        let (prepared, _) = cache.prepare_request(request).expect("complete history");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        assert!(body.get("previous_response_id").is_none());
    }

    #[test]
    fn preserves_multiple_response_branches_in_one_session() {
        let cache = GrokReplayCache::default();
        let base = request(serde_json::json!({"input":"first"}), "key-a");
        let scope = replay_scope(&base.metadata, &base.model).expect("scope");
        for (response_id, call_id) in [("resp_1", "call_1"), ("resp_2", "call_2")] {
            cache.store_completed(
                &scope,
                &serde_json::json!({
                    "type":"response.completed",
                    "response":{
                        "id":response_id,
                        "output":[{
                            "type":"function_call",
                            "call_id":call_id,
                            "name":"lookup",
                            "arguments":"{}"
                        }]
                    }
                }),
            );
        }
        let mut branch = request(
            serde_json::json!({
                "previous_response_id":"resp_1",
                "input":[{"type":"function_call_output","call_id":"call_1","output":"done"}]
            }),
            "key-a",
        );
        branch.metadata.previous_response_id = Some("resp_1".to_owned());

        let (prepared, _) = cache.prepare_request(branch).expect("older branch replay");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        assert_eq!(body["input"][0]["call_id"], "call_1");
        assert_eq!(body["input"][1]["call_id"], "call_1");

        let branch_without_previous = request(
            serde_json::json!({
                "input":[{"type":"function_call_output","call_id":"call_1","output":"done"}]
            }),
            "key-a",
        );
        let (prepared, _) = cache
            .prepare_request(branch_without_previous)
            .expect("call-matched branch replay");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        assert_eq!(body["input"][0]["call_id"], "call_1");
        assert_eq!(body["input"][1]["call_id"], "call_1");
    }

    #[test]
    fn rejects_ambiguous_call_id_without_previous_response_id() {
        let cache = GrokReplayCache::default();
        let base = request(serde_json::json!({"input":"first"}), "key-a");
        let scope = replay_scope(&base.metadata, &base.model).expect("scope");
        for response_id in ["resp_1", "resp_2"] {
            cache.store_completed(
                &scope,
                &serde_json::json!({
                    "type":"response.completed",
                    "response":{
                        "id":response_id,
                        "output":[{
                            "type":"function_call",
                            "call_id":"shared_call",
                            "name":"lookup",
                            "arguments":"{}"
                        }]
                    }
                }),
            );
        }
        let continuation = request(
            serde_json::json!({
                "input":[{
                    "type":"function_call_output",
                    "call_id":"shared_call",
                    "output":"done"
                }]
            }),
            "key-a",
        );
        let error = cache
            .prepare_request(continuation)
            .expect_err("ambiguous branch must fail closed");
        assert!(error.message().contains("ambiguous"));
    }

    #[test]
    fn tombstones_non_replayable_completion_instead_of_reusing_old_state() {
        let cache = GrokReplayCache::default();
        store(&cache, "key-a");
        let base = request(serde_json::json!({"input":"next"}), "key-a");
        let scope = replay_scope(&base.metadata, &base.model).expect("scope");
        cache.store_completed(
            &scope,
            &serde_json::json!({
                "type":"response.completed",
                "response":{"id":"resp_2","output":[]}
            }),
        );

        let (prepared, _) = cache.prepare_request(base).expect("new turn");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");
        assert_eq!(body["input"], "next");
    }

    #[test]
    fn over_limit_completion_does_not_partially_replay() {
        let cache = GrokReplayCache::default();
        let base = request(serde_json::json!({"input":"first"}), "key-a");
        let scope = replay_scope(&base.metadata, &base.model).expect("scope");
        let output = (0..=MAX_REPLAY_ITEMS)
            .map(|index| {
                serde_json::json!({
                    "type":"function_call",
                    "call_id":format!("call_{index}"),
                    "name":"lookup",
                    "arguments":"{}"
                })
            })
            .collect::<Vec<_>>();
        cache.store_completed(
            &scope,
            &serde_json::json!({
                "type":"response.completed",
                "response":{"id":"resp_1","output":output}
            }),
        );
        let continuation = request(
            serde_json::json!({
                "input":[{"type":"function_call_output","call_id":"call_1","output":"done"}]
            }),
            "key-a",
        );
        let error = cache
            .prepare_request(continuation)
            .expect_err("over-limit replay must fail closed");
        assert!(error.message().contains("ambiguous"));
    }

    #[test]
    fn parses_bare_cr_terminal_frames() {
        let payload = frame_payload(
            b"event: response.completed\rdata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\"}}\r\r",
        )
        .expect("bare CR payload");
        assert_eq!(payload["response"]["id"], "resp_1");
    }

    #[test]
    fn expands_item_reference_from_replay_cache() {
        let cache = GrokReplayCache::default();
        let base = request(serde_json::json!({"input":"first"}), "key-ref");
        let scope = replay_scope(&base.metadata, &base.model).expect("scope");
        cache.store_completed(
            &scope,
            &serde_json::json!({
                "type":"response.completed",
                "response":{
                    "id":"resp_ref",
                    "output":[
                        {"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"cached"}]},
                        {"type":"function_call","id":"fc_1","call_id":"call_1","name":"lookup","arguments":"{}"}
                    ]
                }
            }),
        );

        let continuation = request(
            serde_json::json!({
                "input":[
                    {"type":"item_reference","id":"msg_1"},
                    {"type":"item_reference","id":"fc_1"},
                    {"type":"function_call_output","call_id":"call_1","output":"done"},
                    {"type":"message","role":"user","content":"continue"}
                ]
            }),
            "key-ref",
        );
        let (prepared, _) = cache
            .prepare_request(continuation)
            .expect("expanded references");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("json");
        assert_eq!(body["input"][0]["type"], "message");
        assert_eq!(body["input"][0]["id"], "msg_1");
        assert_eq!(body["input"][1]["type"], "function_call");
        assert_eq!(body["input"][1]["call_id"], "call_1");
        assert_eq!(body["input"][2]["type"], "function_call_output");
        assert!(
            body["input"]
                .as_array()
                .expect("input")
                .iter()
                .all(|item| item.get("type").and_then(Value::as_str) != Some("item_reference"))
        );
    }

    #[test]
    fn rejects_unresolved_item_reference() {
        let cache = GrokReplayCache::default();
        let request = request(
            serde_json::json!({
                "input":[
                    {"type":"item_reference","id":"missing_1"},
                    {"type":"message","role":"user","content":"continue"}
                ]
            }),
            "key-ref-miss",
        );
        let error = cache
            .prepare_request(request)
            .expect_err("missing reference");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
        assert!(error.message().contains("item_reference"));
    }

    #[test]
    fn resolves_item_reference_only_within_the_selected_session() {
        let cache = GrokReplayCache::default();
        for (session_id, response_id, text) in [
            ("session-a", "resp-a", "from-a"),
            ("session-b", "resp-b", "from-b"),
        ] {
            let mut base = request(serde_json::json!({"input":"first"}), "key-ref-scope");
            base.metadata.session_id = Some(session_id.to_owned());
            let scope = replay_scope(&base.metadata, &base.model).expect("scope");
            cache.store_completed(
                &scope,
                &serde_json::json!({
                    "type":"response.completed",
                    "response":{
                        "id":response_id,
                        "output":[{
                            "type":"message",
                            "id":"msg-shared",
                            "role":"assistant",
                            "content":[{"type":"output_text","text":text}]
                        }]
                    }
                }),
            );
        }

        let mut continuation = request(
            serde_json::json!({
                "input":[{"type":"item_reference","id":"msg-shared"}]
            }),
            "key-ref-scope",
        );
        continuation.metadata.session_id = Some("session-a".to_owned());
        let (prepared, _) = cache
            .prepare_request(continuation)
            .expect("session-scoped reference");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("json");
        assert_eq!(body["input"][0]["content"][0]["text"], "from-a");
    }

    #[test]
    fn previous_response_id_resolves_across_rotating_session_metadata() {
        let cache = GrokReplayCache::default();
        let mut base = request(serde_json::json!({"input":"first"}), "key-rotating-session");
        base.metadata.session_id = Some("request-1".to_owned());
        let scope = replay_scope(&base.metadata, &base.model).expect("scope");
        cache.store_completed(
            &scope,
            &serde_json::json!({
                "type":"response.completed",
                "response":{
                    "id":"resp-rotating",
                    "output":[{
                        "type":"message",
                        "role":"assistant",
                        "content":[{"type":"output_text","text":"prior"}]
                    }]
                }
            }),
        );

        let mut continuation = request(
            serde_json::json!({
                "previous_response_id":"resp-rotating",
                "input":"continue"
            }),
            "key-rotating-session",
        );
        continuation.metadata.session_id = Some("request-2".to_owned());
        continuation.metadata.previous_response_id = Some("resp-rotating".to_owned());
        let (prepared, replay_scope) = cache
            .prepare_request(continuation)
            .expect("response ID must identify replay across rotating request metadata");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("json");

        assert!(replay_scope.is_some());
        assert!(body.get("previous_response_id").is_none());
        assert_eq!(body["input"][0]["role"], "assistant");
    }

    #[test]
    fn previous_response_id_scopes_item_reference_to_the_exact_response() {
        let cache = GrokReplayCache::default();
        let base = request(serde_json::json!({"input":"first"}), "key-exact-reference");
        let scope = replay_scope(&base.metadata, &base.model).expect("scope");
        for (response_id, text) in [
            ("resp-target", "from-target-response"),
            ("resp-other", "from-other-response"),
        ] {
            cache.store_completed(
                &scope,
                &serde_json::json!({
                    "type":"response.completed",
                    "response":{
                        "id":response_id,
                        "output":[{
                            "type":"message",
                            "id":"msg-shared",
                            "role":"assistant",
                            "content":[{"type":"output_text","text":text}]
                        }]
                    }
                }),
            );
        }

        let mut continuation = request(
            serde_json::json!({
                "previous_response_id":"resp-target",
                "input":[{"type":"item_reference","id":"msg-shared"}]
            }),
            "key-exact-reference",
        );
        continuation.metadata.previous_response_id = Some("resp-target".to_owned());
        let (prepared, _) = cache
            .prepare_request(continuation)
            .expect("previous response must scope item_reference resolution");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("json");

        assert!(body.get("previous_response_id").is_none());
        assert_eq!(
            body["input"][0]["content"][0]["text"],
            "from-target-response"
        );
    }

    #[test]
    fn replayed_local_shell_and_mcp_calls_normalize_with_current_outputs() {
        let cache = GrokReplayCache::default();
        let base = request(serde_json::json!({"input":"run tools"}), "key-native-tools");
        let scope = replay_scope(&base.metadata, &base.model).expect("scope");
        cache.store_completed(
            &scope,
            &serde_json::json!({
                "type":"response.completed",
                "response":{
                    "id":"resp-native-tools",
                    "output":[
                        {
                            "type":"local_shell_call",
                            "call_id":"shell-1",
                            "status":"completed",
                            "action":{"type":"exec","command":["pwd"]}
                        },
                        {
                            "type":"mcp_tool_call",
                            "call_id":"mcp-1",
                            "name":"docs.search",
                            "server_label":"docs",
                            "arguments":{"q":"grok"}
                        }
                    ]
                }
            }),
        );

        let mut continuation = request(
            serde_json::json!({
                "previous_response_id":"resp-native-tools",
                "input":[
                    {"type":"local_shell_call_output","call_id":"shell-1","output":"/tmp"},
                    {"type":"mcp_tool_call_output","call_id":"mcp-1","output":{"hits":1}}
                ]
            }),
            "key-native-tools",
        );
        continuation.metadata.previous_response_id = Some("resp-native-tools".to_owned());
        let (replayed, _) = cache
            .prepare_request(continuation)
            .expect("native tool calls must replay");
        let prepared = crate::grok::request::prepare_request(replayed)
            .expect("replayed native tools must normalize for Grok");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("json");
        let input = body["input"].as_array().expect("normalized input");

        assert_eq!(input.len(), 4);
        assert_eq!(input[0]["type"], "function_call");
        assert_eq!(input[0]["call_id"], "shell-1");
        assert_eq!(input[0]["name"], "local_shell");
        assert_eq!(input[1]["type"], "function_call");
        assert_eq!(input[1]["call_id"], "mcp-1");
        assert_eq!(input[1]["name"], "docs.search");
        assert_eq!(input[2]["type"], "function_call_output");
        assert_eq!(input[2]["call_id"], "shell-1");
        assert_eq!(input[2]["output"], "/tmp");
        assert_eq!(input[3]["type"], "function_call_output");
        assert_eq!(input[3]["call_id"], "mcp-1");
        assert_eq!(input[3]["output"], r#"{"hits":1}"#);
    }

    #[test]
    fn rejects_ambiguous_previous_response_id_without_an_exact_session() {
        let cache = GrokReplayCache::default();
        for session_id in ["session-a", "session-b"] {
            let mut base = request(
                serde_json::json!({"input":"first"}),
                "key-duplicate-response",
            );
            base.metadata.session_id = Some(session_id.to_owned());
            let scope = replay_scope(&base.metadata, &base.model).expect("scope");
            cache.store_completed(
                &scope,
                &serde_json::json!({
                    "type":"response.completed",
                    "response":{
                        "id":"resp-duplicate",
                        "output":[{
                            "type":"message",
                            "role":"assistant",
                            "content":[{"type":"output_text","text":session_id}]
                        }]
                    }
                }),
            );
        }

        let mut continuation = request(
            serde_json::json!({
                "previous_response_id":"resp-duplicate",
                "input":"continue"
            }),
            "key-duplicate-response",
        );
        continuation.metadata.session_id = Some("session-c".to_owned());
        continuation.metadata.previous_response_id = Some("resp-duplicate".to_owned());

        let error = cache
            .prepare_request(continuation)
            .expect_err("ambiguous response IDs without an exact session must be rejected");
        assert!(
            error
                .message()
                .contains("continuation state is unavailable")
        );
    }

    #[test]
    fn rejects_unscoped_or_ambiguous_item_reference() {
        let cache = GrokReplayCache::default();
        let base = request(serde_json::json!({"input":"first"}), "key-ref-ambiguous");
        let scope = replay_scope(&base.metadata, &base.model).expect("scope");
        for (response_id, text) in [("resp-a", "first"), ("resp-b", "second")] {
            cache.store_completed(
                &scope,
                &serde_json::json!({
                    "type":"response.completed",
                    "response":{
                        "id":response_id,
                        "output":[{
                            "type":"message",
                            "id":"msg-duplicate",
                            "role":"assistant",
                            "content":[{"type":"output_text","text":text}]
                        }]
                    }
                }),
            );
        }

        let ambiguous = request(
            serde_json::json!({
                "input":[{"type":"item_reference","id":"msg-duplicate"}]
            }),
            "key-ref-ambiguous",
        );
        let error = cache
            .prepare_request(ambiguous)
            .expect_err("duplicate cached IDs must be rejected");
        assert!(error.message().contains("ambiguous"));

        let mut unscoped = request(
            serde_json::json!({
                "input":[{"type":"item_reference","id":"msg-duplicate"}]
            }),
            "key-ref-ambiguous",
        );
        unscoped.metadata.session_id = None;
        let error = cache
            .prepare_request(unscoped)
            .expect_err("unscoped references must be rejected");
        assert!(error.message().contains("item_reference"));
    }

    #[test]
    fn accepts_self_contained_local_shell_history_without_cache() {
        let cache = GrokReplayCache::default();
        let request = request(
            serde_json::json!({
                "input":[
                    {"type":"local_shell_call","call_id":"shell_1","action":{"type":"exec","command":["pwd"]}},
                    {"type":"local_shell_call_output","call_id":"shell_1","output":"/tmp"},
                    {"type":"message","role":"user","content":"continue"}
                ]
            }),
            "key-shell",
        );
        let (prepared, _) = cache
            .prepare_request(request)
            .expect("self-contained local_shell history");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("json");
        assert_eq!(body["input"][0]["type"], "local_shell_call");
        assert_eq!(body["input"][1]["type"], "local_shell_call_output");
    }

    #[test]
    fn defers_unpaired_outputs_when_previous_response_has_complete_history() {
        let cache = GrokReplayCache::default();
        let request = request(
            serde_json::json!({
                "previous_response_id":"resp_missing",
                "input":[
                    {"type":"message","role":"assistant","content":[{"type":"output_text","text":"prior"}]},
                    {"type":"function_call_output","call_id":"call_missing","output":"done"},
                    {"type":"message","role":"user","content":"continue"}
                ]
            }),
            "key-defer",
        );
        let (prepared, _) = cache
            .prepare_request(request)
            .expect("complete history should defer unpaired validation");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("json");
        assert!(body.get("previous_response_id").is_none());
        assert_eq!(body["input"][1]["type"], "function_call_output");
    }
}
