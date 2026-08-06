use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use futures_util::{StreamExt, stream};
use provider_core::{ProviderError, ProviderErrorKind, ProviderStream, ResponseTranslator};
use serde_json::Value;

use crate::sse::SseDecoder;

#[derive(Debug)]
pub(crate) struct ClaudeResponseContext {
    model: String,
    tool_names: HashMap<String, String>,
}

impl ClaudeResponseContext {
    pub(crate) fn new(model: String, tool_names: HashMap<String, String>) -> Self {
        Self { model, tool_names }
    }
}

pub(crate) struct ClaudeResponseTranslator {
    context: ClaudeResponseContext,
}

impl ClaudeResponseTranslator {
    pub(crate) fn new(context: ClaudeResponseContext) -> Self {
        Self { context }
    }
}

impl ResponseTranslator for ClaudeResponseTranslator {
    fn translate_stream(self: Box<Self>, stream: ProviderStream) -> ProviderStream {
        adapt_responses_stream_to_claude(stream, self.context)
    }
}

fn adapt_responses_stream_to_claude(
    upstream: ProviderStream,
    context: ClaudeResponseContext,
) -> ProviderStream {
    let state = ClaudeStreamAdapter {
        upstream,
        decoder: SseDecoder::default(),
        converter: ClaudeEventConverter::new(context),
        output: VecDeque::new(),
        finished: false,
    };

    Box::pin(stream::unfold(state, |mut state| async move {
        let item = state.next_output().await?;
        Some((item, state))
    }))
}

struct ClaudeStreamAdapter {
    upstream: ProviderStream,
    decoder: SseDecoder,
    converter: ClaudeEventConverter,
    output: VecDeque<Result<Bytes, ProviderError>>,
    finished: bool,
}

impl ClaudeStreamAdapter {
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

struct ClaudeEventConverter {
    model: String,
    tool_names: HashMap<String, String>,
    block_index: u64,
    open_block: Option<OpenBlock>,
    thinking_signature: Option<String>,
    pending_tool: Option<PendingTool>,
    emitted_text: bool,
    emitted_tool: bool,
    web_search_requests: u64,
}

impl ClaudeEventConverter {
    fn new(context: ClaudeResponseContext) -> Self {
        Self {
            model: context.model,
            tool_names: context.tool_names,
            block_index: 0,
            open_block: None,
            thinking_signature: None,
            pending_tool: None,
            emitted_text: false,
            emitted_tool: false,
            web_search_requests: 0,
        }
    }

    fn convert(&mut self, event: &Value) -> Vec<Bytes> {
        let mut output = Vec::new();
        match event
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "error" => output.push(claude_error(event)),
            "response.created" => {
                let response = event.get("response").unwrap_or(&Value::Null);
                output.push(sse_event(
                    "message_start",
                    serde_json::json!({
                        "type": "message_start",
                        "message": {
                            "id": response.get("id").and_then(Value::as_str).unwrap_or_default(),
                            "type": "message",
                            "role": "assistant",
                            "model": response.get("model").and_then(Value::as_str).unwrap_or(&self.model),
                            "content": [],
                            "stop_reason": null,
                            "stop_sequence": null,
                            "usage": { "input_tokens": 0, "output_tokens": 0 }
                        }
                    }),
                ));
            }
            "response.output_item.added" => self.output_item_added(event, &mut output),
            "response.reasoning_summary_part.added" => {
                self.start_thinking(&mut output);
            }
            "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
                self.start_thinking(&mut output);
                let index = self.current_index();
                output.push(sse_event(
                    "content_block_delta",
                    serde_json::json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "thinking_delta",
                            "thinking": event.get("delta").and_then(Value::as_str).unwrap_or_default()
                        }
                    }),
                ));
            }
            "response.content_part.added" => {
                match event
                    .get("part")
                    .and_then(|part| part.get("type"))
                    .and_then(Value::as_str)
                {
                    Some("output_text") => self.start_text(&mut output),
                    Some("reasoning_text") => self.start_thinking(&mut output),
                    _ => {}
                }
            }
            "response.output_text.delta" => {
                self.start_text(&mut output);
                self.emitted_text = true;
                let index = self.current_index();
                output.push(sse_event(
                    "content_block_delta",
                    serde_json::json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "text_delta",
                            "text": event.get("delta").and_then(Value::as_str).unwrap_or_default()
                        }
                    }),
                ));
            }
            "response.content_part.done" => {
                if event
                    .get("part")
                    .and_then(|part| part.get("type"))
                    .and_then(Value::as_str)
                    == Some("output_text")
                {
                    self.close_block(&mut output);
                }
            }
            "response.function_call_arguments.delta" => {
                self.function_arguments(event, true, &mut output);
            }
            "response.function_call_arguments.done" => {
                self.function_arguments(event, false, &mut output);
            }
            "response.output_item.done" => self.output_item_done(event, &mut output),
            "response.completed" | "response.incomplete" => {
                self.complete(event, &mut output);
            }
            _ => {}
        }
        output
    }

    fn output_item_added(&mut self, event: &Value, output: &mut Vec<Bytes>) {
        let item = event.get("item").unwrap_or(&Value::Null);
        match item.get("type").and_then(Value::as_str) {
            Some("reasoning") => {
                self.thinking_signature = item
                    .get("encrypted_content")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            Some("function_call") => {
                self.close_block(output);
                let call_id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if name.is_empty() {
                    self.pending_tool = Some(PendingTool {
                        call_id,
                        name,
                        arguments: String::new(),
                    });
                } else {
                    self.start_tool(call_id, name, output);
                }
            }
            _ => {}
        }
    }

    fn output_item_done(&mut self, event: &Value, output: &mut Vec<Bytes>) {
        let item = event.get("item").unwrap_or(&Value::Null);
        match item.get("type").and_then(Value::as_str) {
            Some("reasoning") => {
                if let Some(signature) = item.get("encrypted_content").and_then(Value::as_str) {
                    self.thinking_signature = Some(signature.to_owned());
                }
                if self.thinking_signature.is_some()
                    && !matches!(self.open_block, Some(OpenBlock::Thinking { .. }))
                {
                    self.start_thinking(output);
                }
                if matches!(self.open_block, Some(OpenBlock::Thinking { .. })) {
                    self.close_block(output);
                }
            }
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
                    self.start_text(output);
                    let index = self.current_index();
                    output.push(sse_event(
                        "content_block_delta",
                        serde_json::json!({
                            "type": "content_block_delta",
                            "index": index,
                            "delta": { "type": "text_delta", "text": text }
                        }),
                    ));
                    self.emitted_text = true;
                    self.close_block(output);
                }
            }
            Some("function_call") => {
                if !matches!(self.open_block, Some(OpenBlock::Tool { .. })) {
                    let pending = self.pending_tool.take();
                    let call_id = item
                        .get("call_id")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .or_else(|| pending.as_ref().map(|tool| tool.call_id.clone()))
                        .unwrap_or_default();
                    let name = item
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .or_else(|| pending.as_ref().map(|tool| tool.name.clone()))
                        .unwrap_or_default();
                    self.start_tool(call_id, name, output);
                    if let Some(arguments) = pending
                        .as_ref()
                        .map(|tool| tool.arguments.as_str())
                        .filter(|arguments| !arguments.is_empty())
                    {
                        self.emit_tool_arguments(arguments, output);
                    }
                }
                let emitted_arguments = matches!(
                    self.open_block,
                    Some(OpenBlock::Tool {
                        arguments_emitted: true,
                        ..
                    })
                );
                if !emitted_arguments
                    && let Some(arguments) = item.get("arguments").and_then(Value::as_str)
                {
                    self.emit_tool_arguments(arguments, output);
                }
                self.close_block(output);
            }
            Some("web_search_call") => self.emit_web_search(item, output),
            _ => {}
        }
    }

    fn emit_web_search(&mut self, item: &Value, output: &mut Vec<Bytes>) {
        self.close_block(output);
        let id = item
            .get("id")
            .or_else(|| item.get("call_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("web_search_{}", self.block_index));
        let query = item
            .get("action")
            .and_then(|action| action.get("query"))
            .or_else(|| item.get("query"))
            .and_then(Value::as_str)
            .unwrap_or_default();

        let tool_index = self.block_index;
        output.push(sse_event(
            "content_block_start",
            serde_json::json!({
                "type": "content_block_start",
                "index": tool_index,
                "content_block": {
                    "type": "server_tool_use",
                    "id": id.clone(),
                    "name": "web_search",
                    "input": {}
                }
            }),
        ));
        if !query.is_empty() {
            output.push(sse_event(
                "content_block_delta",
                serde_json::json!({
                    "type": "content_block_delta",
                    "index": tool_index,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": serde_json::json!({ "query": query }).to_string()
                    }
                }),
            ));
        }
        output.push(sse_event(
            "content_block_stop",
            serde_json::json!({ "type": "content_block_stop", "index": tool_index }),
        ));
        self.block_index += 1;

        let content = web_search_results(item);
        let result_index = self.block_index;
        output.push(sse_event(
            "content_block_start",
            serde_json::json!({
                "type": "content_block_start",
                "index": result_index,
                "content_block": {
                    "type": "web_search_tool_result",
                    "tool_use_id": id,
                    "content": content
                }
            }),
        ));
        output.push(sse_event(
            "content_block_stop",
            serde_json::json!({ "type": "content_block_stop", "index": result_index }),
        ));
        self.block_index += 1;
        self.web_search_requests += 1;
    }

    fn function_arguments(&mut self, event: &Value, is_delta: bool, output: &mut Vec<Bytes>) {
        let value = if is_delta {
            event.get("delta")
        } else {
            event.get("arguments")
        }
        .and_then(Value::as_str)
        .unwrap_or_default();

        if matches!(self.open_block, Some(OpenBlock::Tool { .. })) {
            let already_emitted = matches!(
                self.open_block,
                Some(OpenBlock::Tool {
                    arguments_emitted: true,
                    ..
                })
            );
            if is_delta || !already_emitted {
                self.emit_tool_arguments(value, output);
            }
        } else if let Some(pending) = self.pending_tool.as_mut()
            && (is_delta || pending.arguments.is_empty())
        {
            if is_delta {
                pending.arguments.push_str(value);
            } else {
                pending.arguments = value.to_owned();
            }
        }
    }

    fn complete(&mut self, event: &Value, output: &mut Vec<Bytes>) {
        self.close_block(output);
        let response = event.get("response").unwrap_or(&Value::Null);
        let usage = response.get("usage").unwrap_or(&Value::Null);
        let cached = usage
            .get("input_tokens_details")
            .and_then(|details| details.get("cached_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let input_tokens = usage
            .get("input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .saturating_sub(cached);
        let output_tokens = usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let mut claude_usage = serde_json::json!({
            "input_tokens": input_tokens,
            "output_tokens": output_tokens
        });
        if cached > 0 {
            claude_usage["cache_read_input_tokens"] = Value::Number(cached.into());
        }
        if self.web_search_requests > 0 {
            claude_usage["server_tool_use"] = serde_json::json!({
                "web_search_requests": self.web_search_requests
            });
        }
        let upstream_stop_reason =
            response
                .get("stop_reason")
                .and_then(Value::as_str)
                .or_else(|| {
                    response
                        .get("incomplete_details")
                        .and_then(|details| details.get("reason"))
                        .and_then(Value::as_str)
                });
        let stop_reason = if self.emitted_tool {
            "tool_use"
        } else if upstream_stop_reason
            .is_some_and(|reason| matches!(reason, "max_tokens" | "max_output_tokens"))
        {
            "max_tokens"
        } else if upstream_stop_reason == Some("content_filter") {
            "refusal"
        } else if upstream_stop_reason.is_some_and(|reason| {
            matches!(
                reason,
                "end_turn" | "stop_sequence" | "pause_turn" | "refusal"
            )
        }) {
            upstream_stop_reason.unwrap_or("end_turn")
        } else if response
            .get("incomplete_details")
            .and_then(|details| details.get("reason"))
            .and_then(Value::as_str)
            == Some("model_context_window_exceeded")
        {
            "model_context_window_exceeded"
        } else {
            "end_turn"
        };
        let stop_sequence = response
            .get("stop_sequence")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or(Value::Null);
        output.push(sse_event(
            "message_delta",
            serde_json::json!({
                "type": "message_delta",
                "delta": { "stop_reason": stop_reason, "stop_sequence": stop_sequence },
                "usage": claude_usage
            }),
        ));
        output.push(sse_event(
            "message_stop",
            serde_json::json!({ "type": "message_stop" }),
        ));
    }

    fn start_thinking(&mut self, output: &mut Vec<Bytes>) {
        if matches!(self.open_block, Some(OpenBlock::Thinking { .. })) {
            return;
        }
        self.close_block(output);
        let index = self.block_index;
        output.push(sse_event(
            "content_block_start",
            serde_json::json!({
                "type": "content_block_start",
                "index": index,
                "content_block": { "type": "thinking", "thinking": "" }
            }),
        ));
        self.open_block = Some(OpenBlock::Thinking { index });
    }

    fn start_text(&mut self, output: &mut Vec<Bytes>) {
        if matches!(self.open_block, Some(OpenBlock::Text { .. })) {
            return;
        }
        self.close_block(output);
        let index = self.block_index;
        output.push(sse_event(
            "content_block_start",
            serde_json::json!({
                "type": "content_block_start",
                "index": index,
                "content_block": { "type": "text", "text": "" }
            }),
        ));
        self.open_block = Some(OpenBlock::Text { index });
    }

    fn start_tool(&mut self, call_id: String, name: String, output: &mut Vec<Bytes>) {
        self.close_block(output);
        let index = self.block_index;
        let name = self.tool_names.get(&name).cloned().unwrap_or(name);
        output.push(sse_event(
            "content_block_start",
            serde_json::json!({
                "type": "content_block_start",
                "index": index,
                "content_block": {
                    "type": "tool_use",
                    "id": call_id,
                    "name": name,
                    "input": {}
                }
            }),
        ));
        self.open_block = Some(OpenBlock::Tool {
            index,
            arguments_emitted: false,
        });
        self.emitted_tool = true;
    }

    fn emit_tool_arguments(&mut self, arguments: &str, output: &mut Vec<Bytes>) {
        let Some(OpenBlock::Tool {
            index,
            arguments_emitted,
        }) = self.open_block.as_mut()
        else {
            return;
        };
        output.push(sse_event(
            "content_block_delta",
            serde_json::json!({
                "type": "content_block_delta",
                "index": *index,
                "delta": { "type": "input_json_delta", "partial_json": arguments }
            }),
        ));
        *arguments_emitted = true;
    }

    fn close_block(&mut self, output: &mut Vec<Bytes>) {
        let Some(block) = self.open_block.take() else {
            return;
        };
        let index = block.index();
        if matches!(block, OpenBlock::Thinking { .. })
            && let Some(signature) = self.thinking_signature.take()
        {
            output.push(sse_event(
                "content_block_delta",
                serde_json::json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": { "type": "signature_delta", "signature": signature }
                }),
            ));
        }
        output.push(sse_event(
            "content_block_stop",
            serde_json::json!({ "type": "content_block_stop", "index": index }),
        ));
        self.block_index = index + 1;
    }

    fn current_index(&self) -> u64 {
        self.open_block
            .as_ref()
            .map(OpenBlock::index)
            .unwrap_or(self.block_index)
    }
}

enum OpenBlock {
    Thinking { index: u64 },
    Text { index: u64 },
    Tool { index: u64, arguments_emitted: bool },
}

impl OpenBlock {
    const fn index(&self) -> u64 {
        match self {
            Self::Thinking { index } | Self::Text { index } | Self::Tool { index, .. } => *index,
        }
    }
}

struct PendingTool {
    call_id: String,
    name: String,
    arguments: String,
}

fn web_search_results(item: &Value) -> Vec<Value> {
    item.get("results")
        .and_then(Value::as_array)
        .or_else(|| {
            item.get("action")
                .and_then(|action| action.get("sources"))
                .and_then(Value::as_array)
        })
        .into_iter()
        .flatten()
        .filter_map(|result| {
            let url = result
                .get("url")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())?;
            let title = result
                .get("title")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or(url);
            Some(serde_json::json!({
                "type": "web_search_result",
                "title": title,
                "url": url,
                "page_age": null
            }))
        })
        .collect()
}

fn claude_error(event: &Value) -> Bytes {
    let error = event.get("error").unwrap_or(&Value::Null);
    let error_type = error
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("api_error");
    let error_type = if error_type == "invalid_request" {
        "invalid_request_error"
    } else {
        error_type
    };
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| event.get("message").and_then(Value::as_str))
        .unwrap_or(error_type);
    sse_event(
        "error",
        serde_json::json!({
            "type": "error",
            "error": { "type": error_type, "message": message }
        }),
    )
}

fn sse_event(event: &str, data: Value) -> Bytes {
    Bytes::from(format!("event: {event}\ndata: {data}\n\n"))
}

#[cfg(test)]
mod tests {
    use futures_util::{StreamExt, stream};

    use super::*;

    #[tokio::test]
    async fn converts_split_responses_events_to_claude_blocks() {
        let upstream: ProviderStream = Box::pin(stream::iter([
            Ok(Bytes::from_static(
                b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"grok-4.5\"}}\n\nevent: reasoning\ndata: {\"type\":\"response.reasoning_text.delta\",\"delta\":\"think\"}\n\nevent: done\ndata: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"reasoning\",\"encrypted_content\":\"sig_1\"}}\n\nevent: text\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hel",
            )),
            Ok(Bytes::from_static(
                b"lo\"}\n\nevent: text_done\ndata: {\"type\":\"response.content_part.done\",\"part\":{\"type\":\"output_text\"}}\n\nevent: tool\ndata: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_1\",\"name\":\"shell\"}}\n\nevent: args\ndata: {\"type\":\"response.function_call_arguments.delta\",\"delta\":\"{\\\"cmd\\\":\\\"pwd\\\"}\"}\n\nevent: tool_done\ndata: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_1\",\"name\":\"shell\",\"arguments\":\"{\\\"cmd\\\":\\\"pwd\\\"}\"}}\n\nevent: completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":4}}}\n\n",
            )),
        ]));
        let converted = adapt_responses_stream_to_claude(
            upstream,
            ClaudeResponseContext::new("grok-4.5".to_owned(), HashMap::new()),
        )
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("converted stream")
        .concat();
        let output = String::from_utf8(converted).expect("UTF-8 SSE");

        assert!(output.contains("event: message_start"));
        assert!(output.contains(r#""type":"thinking_delta""#));
        assert!(output.contains(r#""thinking":"think""#));
        assert!(output.contains(r#""type":"signature_delta""#));
        assert!(output.contains(r#""signature":"sig_1""#));
        assert!(output.contains(r#""type":"text_delta""#));
        assert!(output.contains(r#""text":"hello""#));
        assert!(output.contains(r#""type":"tool_use""#));
        assert!(output.contains(r#""id":"call_1""#));
        assert!(output.contains(r#""name":"shell""#));
        assert!(output.contains(r#""type":"input_json_delta""#));
        assert!(output.contains(r#""partial_json":"{\"cmd\":\"pwd\"}""#));
        assert!(output.contains(r#""stop_reason":"tool_use""#));
        assert!(output.contains("event: message_stop"));
    }

    #[tokio::test]
    async fn converts_web_search_and_incomplete_reason() {
        let upstream: ProviderStream = Box::pin(stream::iter([Ok(Bytes::from_static(
            br#"event: created
data: {"type":"response.created","response":{"id":"resp_1","model":"grok-4.5"}}

event: search
data: {"type":"response.output_item.done","item":{"type":"web_search_call","id":"ws_1","action":{"type":"search","query":"weather","sources":[{"url":"https://example.com","title":"Weather"}]}}}

event: incomplete
data: {"type":"response.incomplete","response":{"incomplete_details":{"reason":"content_filter"},"usage":{"input_tokens":3,"output_tokens":1,"input_tokens_details":{"cached_tokens":1}}}}

"#,
        ))]));
        let converted = adapt_responses_stream_to_claude(
            upstream,
            ClaudeResponseContext::new("grok-4.5".to_owned(), HashMap::new()),
        )
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("converted stream")
        .concat();
        let output = String::from_utf8(converted).expect("UTF-8 SSE");

        assert!(output.contains(r#""type":"server_tool_use""#));
        assert!(output.contains(r#""id":"ws_1""#));
        assert!(output.contains(r#""partial_json":"{\"query\":\"weather\"}""#));
        assert!(output.contains(r#""type":"web_search_tool_result""#));
        assert!(output.contains(r#""url":"https://example.com""#));
        assert!(output.contains(r#""web_search_requests":1"#));
        assert!(output.contains(r#""cache_read_input_tokens":1"#));
        assert!(output.contains(r#""input_tokens":2"#));
        assert!(output.contains(r#""stop_reason":"refusal""#));
        assert!(output.contains("event: message_stop"));
    }
}
