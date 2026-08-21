use std::collections::{HashMap, HashSet, VecDeque};

use bytes::Bytes;
use futures_util::{StreamExt, stream};
use provider_core::{ProviderError, ProviderErrorKind, ProviderStream, ResponseTranslator};
use serde_json::Value;

use crate::sse::SseDecoder;

#[derive(Debug)]
pub(crate) struct ChatCompletionsResponseContext {
    model: String,
    include_usage: bool,
}

impl ChatCompletionsResponseContext {
    pub(crate) fn new(model: String, include_usage: bool) -> Self {
        Self {
            model,
            include_usage,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ChatCompletionsResponseTranslator {
    context: ChatCompletionsResponseContext,
}

impl ChatCompletionsResponseTranslator {
    pub(crate) fn new(context: ChatCompletionsResponseContext) -> Self {
        Self { context }
    }
}

impl ResponseTranslator for ChatCompletionsResponseTranslator {
    fn translate_stream(self: Box<Self>, stream: ProviderStream) -> ProviderStream {
        adapt_responses_stream_to_chat(stream, self.context)
    }
}

fn adapt_responses_stream_to_chat(
    upstream: ProviderStream,
    context: ChatCompletionsResponseContext,
) -> ProviderStream {
    let state = ChatStreamAdapter {
        upstream,
        decoder: SseDecoder::default(),
        converter: ChatEventConverter::new(context),
        output: VecDeque::new(),
        finished: false,
    };
    Box::pin(stream::unfold(state, |mut state| async move {
        let item = state.next_output().await?;
        Some((item, state))
    }))
}

struct ChatStreamAdapter {
    upstream: ProviderStream,
    decoder: SseDecoder,
    converter: ChatEventConverter,
    output: VecDeque<Result<Bytes, ProviderError>>,
    finished: bool,
}

impl ChatStreamAdapter {
    async fn next_output(&mut self) -> Option<Result<Bytes, ProviderError>> {
        loop {
            if let Some(output) = self.output.pop_front() {
                return Some(output);
            }
            if self.finished {
                return None;
            }
            match self.upstream.next().await {
                Some(Ok(chunk)) => match self.decoder.push(&chunk) {
                    Ok(frames) => {
                        for data in frames {
                            self.convert_data(data);
                        }
                    }
                    Err(_) => {
                        self.finished = true;
                        return Some(Err(crate::sse::frame_too_large_error()));
                    }
                },
                Some(Err(error)) => {
                    self.finished = true;
                    return Some(Err(error));
                }
                None => {
                    if let Some(data) = self.decoder.finish() {
                        self.convert_data(data);
                    }
                    self.finished = true;
                }
            }
        }
    }

    fn convert_data(&mut self, data: Bytes) {
        if data == "[DONE]" {
            return;
        }
        match serde_json::from_slice::<Value>(&data) {
            Ok(event) => self
                .output
                .extend(self.converter.convert(&event).into_iter().map(Ok)),
            Err(_) => self.output.push_back(Err(ProviderError::new(
                ProviderErrorKind::Upstream,
                "Responses upstream returned an invalid SSE JSON event",
            ))),
        }
    }
}

struct ChatEventConverter {
    id: String,
    model: String,
    include_usage: bool,
    created: u64,
    role_emitted: bool,
    emitted_text: bool,
    emitted_reasoning: bool,
    emitted_tools: bool,
    tool_indexes: HashMap<String, u64>,
    tool_names: HashMap<u64, String>,
    tool_arguments_emitted: HashSet<u64>,
    next_tool_index: u64,
}

impl ChatEventConverter {
    fn new(context: ChatCompletionsResponseContext) -> Self {
        Self {
            id: String::new(),
            model: context.model,
            include_usage: context.include_usage,
            created: 0,
            role_emitted: false,
            emitted_text: false,
            emitted_reasoning: false,
            emitted_tools: false,
            tool_indexes: HashMap::new(),
            tool_names: HashMap::new(),
            tool_arguments_emitted: HashSet::new(),
            next_tool_index: 0,
        }
    }

    fn convert(&mut self, event: &Value) -> Vec<Bytes> {
        let mut output = Vec::new();
        match event
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "response.created" => {
                let response = event.get("response").unwrap_or(&Value::Null);
                self.capture_response(response);
                self.emit_role(&mut output);
            }
            "response.reasoning_text.delta" | "response.reasoning_summary_text.delta" => {
                self.emit_role(&mut output);
                let delta = event
                    .get("delta")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !delta.is_empty() {
                    self.emitted_reasoning = true;
                    output.push(self.chunk(serde_json::json!({"reasoning_content":delta}), None));
                }
            }
            "response.output_text.delta" => {
                self.emit_role(&mut output);
                let delta = event
                    .get("delta")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !delta.is_empty() {
                    self.emitted_text = true;
                    output.push(self.chunk(serde_json::json!({"content":delta}), None));
                }
            }
            "response.output_item.added" => {
                let item = event.get("item").unwrap_or(&Value::Null);
                if item.get("type").and_then(Value::as_str) == Some("function_call") {
                    self.emit_tool_start(item, &mut output);
                }
            }
            "response.function_call_arguments.delta" => {
                self.emit_tool_arguments(event, true, &mut output);
            }
            "response.function_call_arguments.done" => {
                self.emit_tool_arguments(event, false, &mut output);
            }
            "response.output_item.done" => self.output_item_done(event, &mut output),
            "response.completed" | "response.incomplete" => {
                self.complete(event, &mut output);
            }
            "error" => output.push(chat_error(event.get("error").unwrap_or(event))),
            "response.failed" => output.push(chat_error(
                event
                    .get("response")
                    .and_then(|response| response.get("error"))
                    .unwrap_or(event),
            )),
            "response.canceled" | "response.cancelled" => output.push(chat_error(
                &serde_json::json!({"type":"api_error","message":"Upstream response was canceled"}),
            )),
            _ => {}
        }
        output
    }

    fn capture_response(&mut self, response: &Value) {
        if let Some(id) = response.get("id").and_then(Value::as_str) {
            self.id = id.to_owned();
        }
        if let Some(model) = response.get("model").and_then(Value::as_str) {
            self.model = model.to_owned();
        }
        self.created = response
            .get("created_at")
            .and_then(Value::as_u64)
            .unwrap_or(self.created);
    }

    fn emit_role(&mut self, output: &mut Vec<Bytes>) {
        if self.role_emitted {
            return;
        }
        output.push(self.chunk(serde_json::json!({"role":"assistant","content":null}), None));
        self.role_emitted = true;
    }

    fn emit_tool_start(&mut self, item: &Value, output: &mut Vec<Bytes>) {
        self.emit_role(output);
        let index = self.tool_index_for_item(item);
        let id = item
            .get("call_id")
            .or_else(|| item.get("id"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
        if !name.is_empty() {
            self.tool_names.insert(index, name.to_owned());
        }
        self.emitted_tools = true;
        output.push(self.chunk(
            serde_json::json!({
                "tool_calls":[{
                    "index":index,
                    "id":id,
                    "type":"function",
                    "function":{"name":name,"arguments":""}
                }]
            }),
            None,
        ));
    }

    fn emit_tool_arguments(&mut self, event: &Value, delta: bool, output: &mut Vec<Bytes>) {
        let key = tool_key(event);
        let index = self.tool_index(&key);
        let arguments = if delta {
            event.get("delta")
        } else {
            event.get("arguments")
        }
        .and_then(Value::as_str)
        .unwrap_or_default();
        if arguments.is_empty() || (!delta && self.tool_arguments_emitted.contains(&index)) {
            return;
        }
        self.tool_arguments_emitted.insert(index);
        self.emitted_tools = true;
        output.push(self.chunk(
            serde_json::json!({
                "tool_calls":[{"index":index,"function":{"arguments":arguments}}]
            }),
            None,
        ));
    }

    fn output_item_done(&mut self, event: &Value, output: &mut Vec<Bytes>) {
        let item = event.get("item").unwrap_or(&Value::Null);
        match item.get("type").and_then(Value::as_str) {
            Some("message") if !self.emitted_text => {
                let text = item
                    .get("content")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|part| part.get("type").and_then(Value::as_str) == Some("output_text"))
                    .filter_map(|part| part.get("text").and_then(Value::as_str))
                    .collect::<String>();
                if !text.is_empty() {
                    self.emit_role(output);
                    self.emitted_text = true;
                    output.push(self.chunk(serde_json::json!({"content":text}), None));
                }
            }
            Some("function_call") => {
                let index = self.tool_index_for_item(item);
                if !self.tool_names.contains_key(&index) {
                    self.emit_tool_start(item, output);
                }
                if let Some(arguments) = item.get("arguments").and_then(Value::as_str)
                    && !self.tool_arguments_emitted.contains(&index)
                    && !arguments.is_empty()
                {
                    self.tool_arguments_emitted.insert(index);
                    output.push(self.chunk(
                        serde_json::json!({
                            "tool_calls":[{"index":index,"function":{"arguments":arguments}}]
                        }),
                        None,
                    ));
                }
            }
            _ => {}
        }
    }

    fn complete(&mut self, event: &Value, output: &mut Vec<Bytes>) {
        self.emit_role(output);
        let response = event.get("response").unwrap_or(&Value::Null);
        self.capture_response(response);
        let incomplete_reason = response
            .get("incomplete_details")
            .and_then(|details| details.get("reason"))
            .and_then(Value::as_str);
        let finish_reason = if self.emitted_tools {
            "tool_calls"
        } else if incomplete_reason
            .is_some_and(|reason| matches!(reason, "max_output_tokens" | "max_tokens"))
        {
            "length"
        } else if incomplete_reason == Some("content_filter") {
            "content_filter"
        } else {
            "stop"
        };
        output.push(self.chunk(serde_json::json!({}), Some(finish_reason)));
        if self.include_usage
            && let Some(usage) = response.get("usage")
        {
            output.push(sse_data(serde_json::json!({
                "id": self.id(),
                "object":"chat.completion.chunk",
                "created":self.created,
                "model":self.model,
                "choices":[],
                "usage":chat_usage(usage)
            })));
        }
        output.push(Bytes::from_static(b"data: [DONE]\n\n"));
    }

    fn tool_index(&mut self, key: &str) -> u64 {
        if let Some(index) = self.tool_indexes.get(key) {
            return *index;
        }
        let index = self.next_tool_index;
        self.next_tool_index += 1;
        self.tool_indexes.insert(key.to_owned(), index);
        index
    }

    fn tool_index_for_item(&mut self, item: &Value) -> u64 {
        let call_id = item.get("call_id").and_then(Value::as_str);
        let item_id = item.get("id").and_then(Value::as_str);
        let existing = call_id
            .and_then(|key| self.tool_indexes.get(key).copied())
            .or_else(|| item_id.and_then(|key| self.tool_indexes.get(key).copied()));
        let index = existing.unwrap_or_else(|| {
            let index = self.next_tool_index;
            self.next_tool_index += 1;
            index
        });
        if let Some(call_id) = call_id {
            self.tool_indexes.insert(call_id.to_owned(), index);
        }
        if let Some(item_id) = item_id {
            self.tool_indexes.insert(item_id.to_owned(), index);
        }
        index
    }

    fn chunk(&self, delta: Value, finish_reason: Option<&str>) -> Bytes {
        let mut chunk = serde_json::json!({
            "id":self.id(),
            "object":"chat.completion.chunk",
            "created":self.created,
            "model":self.model,
            "choices":[{
                "index":0,
                "delta":delta,
                "finish_reason":finish_reason
            }]
        });
        if self.include_usage {
            chunk
                .as_object_mut()
                .expect("Chat Completions chunk must be an object")
                .insert("usage".to_owned(), Value::Null);
        }
        sse_data(chunk)
    }

    fn id(&self) -> &str {
        if self.id.is_empty() {
            "chatcmpl-provider"
        } else {
            &self.id
        }
    }
}

fn tool_key(value: &Value) -> String {
    value
        .get("call_id")
        .or_else(|| value.get("item_id"))
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("tool")
        .to_owned()
}

fn chat_usage(usage: &Value) -> Value {
    let input = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output = usage
        .get("output_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cached = usage
        .get("input_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let reasoning = usage
        .get("output_tokens_details")
        .and_then(|details| details.get("reasoning_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    serde_json::json!({
        "prompt_tokens":input,
        "completion_tokens":output,
        "total_tokens":usage.get("total_tokens").and_then(Value::as_u64).unwrap_or(input.saturating_add(output)),
        "prompt_tokens_details":{"cached_tokens":cached},
        "completion_tokens_details":{"reasoning_tokens":reasoning}
    })
}

fn chat_error(error: &Value) -> Bytes {
    let error_type = error
        .get("type")
        .or_else(|| error.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("api_error");
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or(error_type);
    sse_data(serde_json::json!({
        "error":{"type":error_type,"message":message}
    }))
}

fn sse_data(data: Value) -> Bytes {
    Bytes::from(format!("data: {data}\n\n"))
}

#[cfg(test)]
mod tests;
