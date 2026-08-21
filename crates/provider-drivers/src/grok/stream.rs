use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, stream};
use provider_core::{ProviderError, ProviderErrorKind, ProviderStream};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Duration;

use super::request::GrokToolMappings;

#[path = "stream_payload.rs"]
mod stream_payload;
#[path = "stream_sse.rs"]
mod stream_sse;
#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;

use self::stream_payload::{
    custom_tool_input, is_terminal_response_event, normalize_reasoning_part_done,
    normalize_reasoning_payload, normalize_reasoning_text_done, restore_client_tool_item,
    restore_namespace_event, restore_terminal_tool_payload,
};
use self::stream_sse::{
    find_sse_frame_end, ping_comment, rewrite_sse_frame, sse_data_payload, sse_event_name,
};

const MAX_TOOL_SSE_FRAME_SIZE: usize = 8 * 1024 * 1024;
const GROK_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_ITEM_ID_LENGTH: usize = 64;
const ITEM_ID_NAMESPACE: uuid::Uuid = uuid::Uuid::from_u128(0x4d5f8e2a_2e45_4f41_a23f_4be6b96e1a7c);

pub(super) fn restore_tool_stream(
    inner: ProviderStream,
    tool_mappings: GrokToolMappings,
    model: &str,
) -> ProviderStream {
    let model = model.to_owned();
    struct State {
        inner: ProviderStream,
        pending: BytesMut,
        ready: VecDeque<Bytes>,
        restorer: GrokToolStreamRestorer,
        eof: bool,
        terminal_error: Option<ProviderError>,
    }

    Box::pin(stream::unfold(
        State {
            inner,
            pending: BytesMut::new(),
            ready: VecDeque::new(),
            restorer: GrokToolStreamRestorer::new(tool_mappings),
            eof: false,
            terminal_error: None,
        },
        move |mut state| {
            let model = model.clone();
            async move {
                loop {
                    if let Some(frame) = state.ready.pop_front() {
                        return Some((Ok(frame), state));
                    }
                    if let Some(frame_end) = find_sse_frame_end(&state.pending) {
                        if frame_end > MAX_TOOL_SSE_FRAME_SIZE {
                            let error = ProviderError::new(
                                ProviderErrorKind::Upstream,
                                "Grok upstream tool event exceeded the frame limit",
                            );
                            if !state.restorer.terminal_seen() {
                                state.ready.push_back(state.restorer.failure_frame(
                                    &model,
                                    "upstream_frame_too_large",
                                    "Grok upstream tool event exceeded the frame limit",
                                ));
                            }
                            state.terminal_error = Some(error);
                            state.pending.clear();
                            state.eof = true;
                            continue;
                        }
                        let frame = state.pending.split_to(frame_end).freeze();
                        state.ready.extend(state.restorer.restore_frame(&frame));
                        continue;
                    }
                    if state.eof {
                        if let Some(error) = state.terminal_error.take() {
                            return Some((Err(error), state));
                        }
                        if state.pending.is_empty() {
                            if !state.restorer.terminal_seen() {
                                state.ready.push_back(state.restorer.failure_frame(
                                    &model,
                                    "upstream_stream_ended",
                                    "Grok upstream stream ended before response completion",
                                ));
                                continue;
                            }
                            return None;
                        }
                        state.pending.clear();
                        if !state.restorer.terminal_seen() {
                            state.ready.push_back(state.restorer.failure_frame(
                                &model,
                                "upstream_incomplete_sse_frame",
                                "Grok upstream stream ended with an incomplete SSE frame",
                            ));
                        }
                        continue;
                    }
                    match tokio::time::timeout(GROK_STREAM_IDLE_TIMEOUT, state.inner.next()).await {
                        Err(_) => {
                            let error = ProviderError::new(
                                ProviderErrorKind::Upstream,
                                "Grok upstream stream idle timeout",
                            )
                            .with_failover_reason(
                                provider_core::ProviderFailoverReason::CapacityExhausted,
                            );
                            if !state.restorer.terminal_seen() {
                                state.ready.push_back(state.restorer.failure_frame(
                                    &model,
                                    "upstream_stream_timeout",
                                    "Grok upstream stream timed out before response completion",
                                ));
                            }
                            state.terminal_error = Some(error);
                            state.eof = true;
                        }
                        Ok(Some(Ok(chunk))) => {
                            state.pending.extend_from_slice(&chunk);
                            if state.pending.len() > MAX_TOOL_SSE_FRAME_SIZE
                                && find_sse_frame_end(&state.pending).is_none()
                            {
                                let error = ProviderError::new(
                                    ProviderErrorKind::Upstream,
                                    "Grok upstream tool event exceeded the frame limit",
                                );
                                if !state.restorer.terminal_seen() {
                                    state.ready.push_back(state.restorer.failure_frame(
                                        &model,
                                        "upstream_frame_too_large",
                                        "Grok upstream tool event exceeded the frame limit",
                                    ));
                                }
                                state.terminal_error = Some(error);
                                state.pending.clear();
                                state.eof = true;
                            }
                        }
                        Ok(Some(Err(error))) => {
                            if state.restorer.terminal_seen() {
                                state.eof = true;
                            } else {
                                state.ready.push_back(state.restorer.failure_frame(
                                    &model,
                                    "upstream_stream_error",
                                    "Grok upstream stream failed before response completion",
                                ));
                                state.terminal_error = Some(error);
                                state.eof = true;
                            }
                        }
                        Ok(None) => state.eof = true,
                    }
                }
            }
        },
    ))
}

#[derive(Clone, Debug)]
struct ClientToolCall {
    kind: ClientToolKind,
    upstream_name: String,
    name: String,
    namespace: Option<String>,
    call_id: String,
    item_id: String,
    output_index: i64,
    arguments: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientToolKind {
    Custom,
    ToolSearch,
}

struct GrokToolStreamRestorer {
    mappings: GrokToolMappings,
    client_tool_calls: Vec<ClientToolCall>,
    completed_items: BTreeMap<i64, Value>,
    completed_items_fallback: Vec<Value>,
    next_sequence: Option<i64>,
    response_id: Option<String>,
    item_ids: HashMap<String, String>,
    used_item_ids: HashSet<String>,
    next_generated_item_id: u64,
    terminal_seen: bool,
}

impl GrokToolStreamRestorer {
    fn new(mappings: GrokToolMappings) -> Self {
        Self {
            mappings,
            client_tool_calls: Vec::new(),
            completed_items: BTreeMap::new(),
            completed_items_fallback: Vec::new(),
            next_sequence: None,
            response_id: None,
            item_ids: HashMap::new(),
            used_item_ids: HashSet::new(),
            next_generated_item_id: 0,
            terminal_seen: false,
        }
    }

    fn terminal_seen(&self) -> bool {
        self.terminal_seen
    }

    fn failure_frame(&mut self, model: &str, code: &str, message: &str) -> Bytes {
        self.terminal_seen = true;
        let response_id = self.response_id.clone().unwrap_or_else(|| {
            let id = format!("resp_{}", uuid::Uuid::new_v4().simple());
            self.response_id = Some(id.clone());
            id
        });
        let payload = serde_json::json!({
            "type": "response.failed",
            "response": {
                "id": response_id,
                "object": "response",
                "model": model,
                "status": "failed",
                "output": [],
                "error": {"code": code, "message": message}
            }
        });
        let data = serde_json::to_vec(&payload).unwrap_or_else(|_| {
            br#"{"type":"response.failed","response":{"status":"failed","output":[]}}"#.to_vec()
        });
        let mut frame = Vec::with_capacity(data.len() + 32);
        frame.extend_from_slice(b"event: response.failed\ndata: ");
        frame.extend_from_slice(&data);
        frame.extend_from_slice(b"\n\n");
        Bytes::from(frame)
    }

    fn restore_frame(&mut self, frame: &[u8]) -> Vec<Bytes> {
        if sse_event_name(frame) == Some("ping") {
            return vec![ping_comment(frame)];
        }
        let Some(data) = sse_data_payload(frame) else {
            return vec![Bytes::copy_from_slice(frame)];
        };
        let Ok(payload) = serde_json::from_slice::<Value>(&data) else {
            return vec![Bytes::copy_from_slice(frame)];
        };
        self.restore_payload(payload)
            .into_iter()
            .map(|payload| rewrite_sse_frame(frame, &payload))
            .collect()
    }

    fn restore_payload(&mut self, mut payload: Value) -> Vec<Value> {
        let mut event_type = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if let Some(id) = payload
            .pointer("/response/id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            self.response_id = Some(id.to_owned());
        }
        if event_type == "response.completed"
            && let Some(status) = payload
                .pointer("/response/status")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|status| !status.is_empty() && *status != "completed")
        {
            event_type = match status {
                "incomplete" => "response.incomplete",
                "cancelled" => "response.cancelled",
                "canceled" => "response.canceled",
                _ => "response.failed",
            }
            .to_owned();
            payload["type"] = Value::String(event_type.clone());
            if let Some(response) = payload.get_mut("response").and_then(Value::as_object_mut)
                && !response.contains_key("error")
            {
                response.insert(
                    "error".to_owned(),
                    serde_json::json!({
                        "code": "upstream_non_success_terminal",
                        "message": "Grok upstream returned a non-success terminal status"
                    }),
                );
            }
        }
        let sequence = payload.get("sequence_number").and_then(Value::as_i64);
        self.begin_sequence(sequence);
        let item_ids_changed = self.normalize_item_ids(&mut payload);

        if event_type == "response.reasoning_text.done" {
            let mut text_done = payload.clone();
            normalize_reasoning_text_done(&mut text_done);
            let text_done = self.resequence(text_done, sequence, true);
            normalize_reasoning_part_done(&mut payload);
            return vec![text_done, self.generated_event(payload)];
        }
        let reasoning_changed = item_ids_changed | normalize_reasoning_payload(&mut payload);

        if is_terminal_response_event(&event_type) {
            self.terminal_seen = true;
            let mut changed = reasoning_changed;
            changed |= self.patch_terminal_output(&mut payload);
            changed |= restore_terminal_tool_payload(&mut payload, &self.mappings);
            return vec![self.resequence(payload, sequence, changed)];
        }

        match event_type.as_str() {
            "response.output_item.added" => {
                let client_tool = self.record_client_tool_item(&payload);
                let changed = reasoning_changed
                    | if let Some(index) = client_tool {
                        restore_client_tool_item(
                            &mut payload,
                            "item",
                            &self.client_tool_calls[index],
                            "",
                        )
                    } else {
                        restore_namespace_event(&mut payload, &self.mappings)
                    };
                vec![self.resequence(payload, sequence, changed)]
            }
            "response.function_call_arguments.delta" => {
                if let Some(index) = self.client_tool_call_for(&payload) {
                    if let Some(delta) = payload.get("delta").and_then(Value::as_str) {
                        self.client_tool_calls[index].arguments.push_str(delta);
                    }
                    return Vec::new();
                }
                let changed =
                    reasoning_changed | restore_namespace_event(&mut payload, &self.mappings);
                vec![self.resequence(payload, sequence, changed)]
            }
            "response.function_call_arguments.done" => {
                let Some(index) = self.client_tool_call_for(&payload) else {
                    let changed =
                        reasoning_changed | restore_namespace_event(&mut payload, &self.mappings);
                    return vec![self.resequence(payload, sequence, changed)];
                };
                if let Some(arguments) = payload.get("arguments").and_then(Value::as_str)
                    && !arguments.is_empty()
                {
                    self.client_tool_calls[index].arguments = arguments.to_owned();
                }
                let call = self.client_tool_calls[index].clone();
                if call.kind == ClientToolKind::ToolSearch {
                    return Vec::new();
                }
                let input = custom_tool_input(&call.arguments);
                let mut events = Vec::with_capacity(2);
                if !input.is_empty() {
                    events.push(self.generated_event(serde_json::json!({
                        "type": "response.custom_tool_call_input.delta",
                        "output_index": call.output_index,
                        "item_id": call.item_id,
                        "delta": input,
                    })));
                }
                events.push(self.generated_event(serde_json::json!({
                    "type": "response.custom_tool_call_input.done",
                    "output_index": call.output_index,
                    "item_id": call.item_id,
                    "call_id": call.call_id,
                    "name": call.name,
                    "input": input,
                })));
                if let Some(namespace) = call.namespace {
                    events.last_mut().expect("generated input done event")["namespace"] =
                        Value::String(namespace);
                }
                events
            }
            "response.output_item.done" => {
                let client_tool = self.record_client_tool_item(&payload);
                let changed = reasoning_changed
                    | if let Some(index) = client_tool {
                        let call = self.client_tool_calls[index].clone();
                        let input = custom_tool_input(&call.arguments);
                        let changed = restore_client_tool_item(&mut payload, "item", &call, &input);
                        self.client_tool_calls.remove(index);
                        changed
                    } else {
                        restore_namespace_event(&mut payload, &self.mappings)
                    };
                self.record_completed_item(&payload);
                vec![self.resequence(payload, sequence, changed)]
            }
            _ => {
                let changed =
                    reasoning_changed | restore_namespace_event(&mut payload, &self.mappings);
                vec![self.resequence(payload, sequence, changed)]
            }
        }
    }

    fn begin_sequence(&mut self, sequence: Option<i64>) {
        if self.next_sequence.is_none() {
            self.next_sequence = sequence;
        }
    }

    fn resequence(&mut self, mut payload: Value, sequence: Option<i64>, changed: bool) -> Value {
        let Some(next) = self.next_sequence else {
            return payload;
        };
        if changed || sequence != Some(next) {
            payload["sequence_number"] = Value::from(next);
        }
        self.next_sequence = Some(next.saturating_add(1));
        payload
    }

    fn generated_event(&mut self, mut payload: Value) -> Value {
        if let Some(next) = self.next_sequence {
            payload["sequence_number"] = Value::from(next);
            self.next_sequence = Some(next.saturating_add(1));
        }
        payload
    }

    fn normalize_item_ids(&mut self, payload: &mut Value) -> bool {
        let mut changed = false;
        if let Some(object) = payload.as_object_mut() {
            changed |= self.normalize_item_id_field(object, "item_id");
        }
        if let Some(item) = payload.get_mut("item").and_then(Value::as_object_mut) {
            changed |= self.normalize_item_id_field(item, "id");
        }
        if let Some(output) = payload
            .pointer_mut("/response/output")
            .and_then(Value::as_array_mut)
        {
            for item in output {
                if let Some(item) = item.as_object_mut() {
                    changed |= self.normalize_item_id_field(item, "id");
                }
            }
        }
        changed
    }

    fn normalize_item_id_field(
        &mut self,
        object: &mut serde_json::Map<String, Value>,
        field: &str,
    ) -> bool {
        let Some(item_id) = object.get(field).and_then(Value::as_str).map(str::to_owned) else {
            return false;
        };
        let normalized = self.normalized_item_id(&item_id);
        if normalized == item_id {
            return false;
        }
        object.insert(field.to_owned(), Value::String(normalized));
        true
    }

    fn normalized_item_id(&mut self, item_id: &str) -> String {
        if let Some(normalized) = self.item_ids.get(item_id) {
            return normalized.clone();
        }
        let mut normalized = if item_id.chars().count() <= MAX_ITEM_ID_LENGTH
            && !self.used_item_ids.contains(item_id)
        {
            item_id.to_owned()
        } else {
            format!(
                "grok_item_{}",
                uuid::Uuid::new_v5(&ITEM_ID_NAMESPACE, item_id.as_bytes()).simple()
            )
        };
        while self.used_item_ids.contains(&normalized) {
            self.next_generated_item_id = self.next_generated_item_id.saturating_add(1);
            normalized = format!(
                "grok_item_{}_{}",
                uuid::Uuid::new_v5(&ITEM_ID_NAMESPACE, item_id.as_bytes()).simple(),
                self.next_generated_item_id
            );
        }
        self.item_ids.insert(item_id.to_owned(), normalized.clone());
        self.used_item_ids.insert(normalized.clone());
        normalized
    }

    fn record_client_tool_item(&mut self, payload: &Value) -> Option<usize> {
        let item = payload.get("item")?.as_object()?;
        if item.get("type").and_then(Value::as_str) != Some("function_call") {
            return None;
        }
        let name = item.get("name")?.as_str()?;
        let kind = if self.mappings.custom_tools.contains(name) {
            ClientToolKind::Custom
        } else if self.mappings.tool_search && name == "tool_search" {
            ClientToolKind::ToolSearch
        } else {
            return None;
        };
        let item_id = item.get("id").and_then(Value::as_str).unwrap_or_default();
        let call_id = item
            .get("call_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let output_index = payload
            .get("output_index")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        let existing = self.client_tool_calls.iter().position(|call| {
            (!item_id.is_empty() && call.item_id == item_id)
                || (!call_id.is_empty() && call.call_id == call_id)
                || (item_id.is_empty()
                    && call_id.is_empty()
                    && call.output_index == output_index
                    && call.upstream_name == name)
        });
        let index = existing.unwrap_or_else(|| {
            let reference = self.mappings.namespace_tools.get(name);
            self.client_tool_calls.push(ClientToolCall {
                kind,
                upstream_name: name.to_owned(),
                name: reference.map_or_else(|| name.to_owned(), |item| item.name.clone()),
                namespace: reference.map(|item| item.namespace.clone()),
                call_id: call_id.to_owned(),
                item_id: item_id.to_owned(),
                output_index,
                arguments: String::new(),
            });
            self.client_tool_calls.len() - 1
        });
        if let Some(arguments) = item.get("arguments").and_then(Value::as_str)
            && !arguments.is_empty()
        {
            self.client_tool_calls[index].arguments = arguments.to_owned();
        }
        Some(index)
    }

    fn client_tool_call_for(&self, payload: &Value) -> Option<usize> {
        let item_id = payload
            .get("item_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let call_id = payload
            .get("call_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let output_index = payload.get("output_index").and_then(Value::as_i64);
        let name = payload
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        self.client_tool_calls.iter().position(|call| {
            (!item_id.is_empty() && call.item_id == item_id)
                || (!call_id.is_empty() && call.call_id == call_id)
                || output_index.is_some_and(|value| call.output_index == value)
                || (item_id.is_empty()
                    && call_id.is_empty()
                    && output_index.is_none()
                    && !name.is_empty()
                    && call.upstream_name == name)
        })
    }

    fn record_completed_item(&mut self, payload: &Value) {
        let Some(item) = payload.get("item").cloned() else {
            return;
        };
        if let Some(index) = payload.get("output_index").and_then(Value::as_i64) {
            self.completed_items.insert(index, item);
        } else {
            self.completed_items_fallback.push(item);
        }
    }

    fn patch_terminal_output(&self, payload: &mut Value) -> bool {
        let Some(response) = payload.get_mut("response").and_then(Value::as_object_mut) else {
            return false;
        };
        if response
            .get("output")
            .and_then(Value::as_array)
            .is_some_and(|output| !output.is_empty())
        {
            return false;
        }
        if self.completed_items.is_empty() && self.completed_items_fallback.is_empty() {
            return false;
        }
        let mut output = self.completed_items.values().cloned().collect::<Vec<_>>();
        output.extend(self.completed_items_fallback.iter().cloned());
        response.insert("output".to_owned(), Value::Array(output));
        true
    }
}
