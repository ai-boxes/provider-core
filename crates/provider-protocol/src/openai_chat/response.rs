use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;
use futures_util::{StreamExt, stream};
use provider_core::{ProviderError, ProviderErrorKind, ProviderStream, ResponseTranslator};
use serde_json::Value;

use crate::sse::SseDecoder;

pub(crate) struct ChatResponseTranslator {
    model: String,
}

impl ChatResponseTranslator {
    pub(crate) fn new(model: String) -> Self {
        Self { model }
    }
}

impl ResponseTranslator for ChatResponseTranslator {
    fn translate_stream(self: Box<Self>, stream: ProviderStream) -> ProviderStream {
        adapt_chat_stream(stream, self.model)
    }
}

fn adapt_chat_stream(upstream: ProviderStream, model: String) -> ProviderStream {
    let state = ChatStreamAdapter {
        upstream,
        decoder: SseDecoder::default(),
        converter: ChatEventConverter::new(model),
        output: VecDeque::new(),
        upstream_finished: false,
        completion_emitted: false,
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
    upstream_finished: bool,
    completion_emitted: bool,
}

impl ChatStreamAdapter {
    async fn next_output(&mut self) -> Option<Result<Bytes, ProviderError>> {
        loop {
            if let Some(output) = self.output.pop_front() {
                return Some(output);
            }
            if self.upstream_finished {
                if !self.completion_emitted {
                    self.completion_emitted = true;
                    self.output
                        .extend(self.converter.finish().into_iter().map(Ok));
                    continue;
                }
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
                        self.upstream_finished = true;
                        return Some(Err(crate::sse::frame_too_large_error()));
                    }
                },
                Some(Err(error)) => {
                    self.upstream_finished = true;
                    return Some(Err(error));
                }
                None => {
                    if let Some(data) = self.decoder.finish() {
                        self.convert_data(data);
                    }
                    self.upstream_finished = true;
                }
            }
        }
    }

    fn convert_data(&mut self, data: Bytes) {
        if data == "[DONE]" {
            self.upstream_finished = true;
            return;
        }
        match serde_json::from_slice::<Value>(&data) {
            Ok(event) => self
                .output
                .extend(self.converter.convert(&event).into_iter().map(Ok)),
            Err(_) => self.output.push_back(Err(ProviderError::new(
                ProviderErrorKind::Upstream,
                "Chat Completions upstream returned an invalid SSE JSON event",
            ))),
        }
    }
}

struct ChatEventConverter {
    model: String,
    response_id: String,
    started: bool,
    text_started: bool,
    text: String,
    reasoning_started: bool,
    reasoning: String,
    tools: BTreeMap<u64, ToolCall>,
    finish_reason: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
}

impl ChatEventConverter {
    fn new(model: String) -> Self {
        Self {
            model,
            response_id: "resp_chat_compatible".to_owned(),
            started: false,
            text_started: false,
            text: String::new(),
            reasoning_started: false,
            reasoning: String::new(),
            tools: BTreeMap::new(),
            finish_reason: None,
            input_tokens: 0,
            output_tokens: 0,
        }
    }

    fn convert(&mut self, event: &Value) -> Vec<Bytes> {
        if let Some(error) = event.get("error") {
            return vec![responses_event(
                "error",
                serde_json::json!({ "type": "error", "error": error }),
            )];
        }
        if let Some(id) = event
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        {
            self.response_id = id.to_owned();
        }
        if let Some(model) = event
            .get("model")
            .and_then(Value::as_str)
            .filter(|model| !model.is_empty())
        {
            self.model = model.to_owned();
        }

        let mut output = Vec::new();
        self.start_response(&mut output);
        if let Some(usage) = event.get("usage") {
            self.input_tokens = usage
                .get("prompt_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(self.input_tokens);
            self.output_tokens = usage
                .get("completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(self.output_tokens);
        }
        for choice in event
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                self.finish_reason = Some(reason.to_owned());
            }
            let delta = choice.get("delta").unwrap_or(&Value::Null);
            if let Some(reasoning) = delta
                .get("reasoning_content")
                .or_else(|| delta.get("reasoning"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            {
                self.start_reasoning(&mut output);
                self.reasoning.push_str(reasoning);
                output.push(responses_event(
                    "response.reasoning_text.delta",
                    serde_json::json!({
                        "type": "response.reasoning_text.delta",
                        "item_id": self.reasoning_id(),
                        "output_index": 0,
                        "content_index": 0,
                        "delta": reasoning
                    }),
                ));
            }
            if let Some(content) = delta
                .get("content")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            {
                self.start_text(&mut output);
                self.text.push_str(content);
                output.push(responses_event(
                    "response.output_text.delta",
                    serde_json::json!({
                        "type": "response.output_text.delta",
                        "item_id": self.message_id(),
                        "output_index": self.text_output_index(),
                        "content_index": 0,
                        "delta": content
                    }),
                ));
            }
            if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for tool_call in tool_calls {
                    self.tool_delta(tool_call, &mut output);
                }
            }
        }
        output
    }

    fn start_response(&mut self, output: &mut Vec<Bytes>) {
        if self.started {
            return;
        }
        self.started = true;
        output.push(responses_event(
            "response.created",
            serde_json::json!({
                "type": "response.created",
                "response": {
                    "id": self.response_id,
                    "object": "response",
                    "status": "in_progress",
                    "model": self.model,
                    "output": []
                }
            }),
        ));
    }

    fn start_reasoning(&mut self, output: &mut Vec<Bytes>) {
        if self.reasoning_started {
            return;
        }
        self.reasoning_started = true;
        output.push(responses_event(
            "response.output_item.added",
            serde_json::json!({
                "type": "response.output_item.added",
                "output_index": 0,
                "item": { "id": self.reasoning_id(), "type": "reasoning", "summary": [] }
            }),
        ));
    }

    fn start_text(&mut self, output: &mut Vec<Bytes>) {
        if self.text_started {
            return;
        }
        self.text_started = true;
        let output_index = self.text_output_index();
        output.push(responses_event(
            "response.output_item.added",
            serde_json::json!({
                "type": "response.output_item.added",
                "output_index": output_index,
                "item": {
                    "id": self.message_id(),
                    "type": "message",
                    "status": "in_progress",
                    "role": "assistant",
                    "content": []
                }
            }),
        ));
        output.push(responses_event(
            "response.content_part.added",
            serde_json::json!({
                "type": "response.content_part.added",
                "item_id": self.message_id(),
                "output_index": output_index,
                "content_index": 0,
                "part": { "type": "output_text", "text": "", "annotations": [] }
            }),
        ));
    }

    fn tool_delta(&mut self, delta: &Value, output: &mut Vec<Bytes>) {
        let index = delta.get("index").and_then(Value::as_u64).unwrap_or(0);
        let output_index = self.tool_output_index(index);
        let entry = self.tools.entry(index).or_insert_with(|| ToolCall {
            id: format!("call_{index}"),
            name: String::new(),
            arguments: String::new(),
            started: false,
        });
        if let Some(id) = delta
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        {
            entry.id = id.to_owned();
        }
        if let Some(function) = delta.get("function") {
            if let Some(name) = function.get("name").and_then(Value::as_str) {
                entry.name.push_str(name);
            }
            if !entry.started {
                entry.started = true;
                output.push(responses_event(
                    "response.output_item.added",
                    serde_json::json!({
                        "type": "response.output_item.added",
                        "output_index": output_index,
                        "item": {
                            "id": format!("fc_{}", entry.id),
                            "type": "function_call",
                            "status": "in_progress",
                            "call_id": entry.id,
                            "name": entry.name,
                            "arguments": ""
                        }
                    }),
                ));
            }
            if let Some(arguments) = function
                .get("arguments")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            {
                entry.arguments.push_str(arguments);
                output.push(responses_event(
                    "response.function_call_arguments.delta",
                    serde_json::json!({
                        "type": "response.function_call_arguments.delta",
                        "item_id": format!("fc_{}", entry.id),
                        "output_index": output_index,
                        "delta": arguments
                    }),
                ));
            }
        }
    }

    fn finish(&mut self) -> Vec<Bytes> {
        let mut output = Vec::new();
        self.start_response(&mut output);
        let mut response_output = Vec::new();
        if self.reasoning_started {
            let item = serde_json::json!({
                "id": self.reasoning_id(),
                "type": "reasoning",
                "summary": if self.reasoning.is_empty() {
                    Vec::<Value>::new()
                } else {
                    vec![serde_json::json!({ "type": "summary_text", "text": self.reasoning })]
                }
            });
            output.push(responses_event(
                "response.output_item.done",
                serde_json::json!({
                    "type": "response.output_item.done",
                    "output_index": 0,
                    "item": item
                }),
            ));
            response_output.push(item);
        }
        if self.text_started {
            let output_index = self.text_output_index();
            let part = serde_json::json!({
                "type": "output_text",
                "text": self.text,
                "annotations": []
            });
            output.push(responses_event(
                "response.output_text.done",
                serde_json::json!({
                    "type": "response.output_text.done",
                    "item_id": self.message_id(),
                    "output_index": output_index,
                    "content_index": 0,
                    "text": self.text
                }),
            ));
            output.push(responses_event(
                "response.content_part.done",
                serde_json::json!({
                    "type": "response.content_part.done",
                    "item_id": self.message_id(),
                    "output_index": output_index,
                    "content_index": 0,
                    "part": part
                }),
            ));
            let item = serde_json::json!({
                "id": self.message_id(),
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [part]
            });
            output.push(responses_event(
                "response.output_item.done",
                serde_json::json!({
                    "type": "response.output_item.done",
                    "output_index": output_index,
                    "item": item
                }),
            ));
            response_output.push(item);
        }
        for (index, tool) in &self.tools {
            let output_index = self.tool_output_index(*index);
            let item = serde_json::json!({
                "id": format!("fc_{}", tool.id),
                "type": "function_call",
                "status": "completed",
                "call_id": tool.id,
                "name": tool.name,
                "arguments": tool.arguments
            });
            output.push(responses_event(
                "response.function_call_arguments.done",
                serde_json::json!({
                    "type": "response.function_call_arguments.done",
                    "item_id": format!("fc_{}", tool.id),
                    "output_index": output_index,
                    "arguments": tool.arguments
                }),
            ));
            output.push(responses_event(
                "response.output_item.done",
                serde_json::json!({
                    "type": "response.output_item.done",
                    "output_index": output_index,
                    "item": item
                }),
            ));
            response_output.push(item);
        }
        let incomplete = self.finish_reason.as_deref() == Some("length");
        let event_type = if incomplete {
            "response.incomplete"
        } else {
            "response.completed"
        };
        let mut response = serde_json::json!({
            "id": self.response_id,
            "object": "response",
            "status": if incomplete { "incomplete" } else { "completed" },
            "model": self.model,
            "output": response_output,
            "usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "total_tokens": self.input_tokens.saturating_add(self.output_tokens)
            }
        });
        if incomplete {
            response["incomplete_details"] = serde_json::json!({ "reason": "max_output_tokens" });
        }
        output.push(responses_event(
            event_type,
            serde_json::json!({ "type": event_type, "response": response }),
        ));
        output
    }

    fn reasoning_id(&self) -> String {
        format!("rs_{}", self.response_id)
    }

    fn message_id(&self) -> String {
        format!("msg_{}", self.response_id)
    }

    fn text_output_index(&self) -> u64 {
        u64::from(self.reasoning_started)
    }

    fn tool_output_index(&self, tool_index: u64) -> u64 {
        u64::from(self.reasoning_started) + u64::from(self.text_started) + tool_index
    }
}

struct ToolCall {
    id: String,
    name: String,
    arguments: String,
    started: bool,
}

fn responses_event(event: &str, data: Value) -> Bytes {
    Bytes::from(format!("event: {event}\ndata: {data}\n\n"))
}

#[cfg(test)]
mod tests {
    use futures_util::{StreamExt, stream};

    use super::*;

    #[tokio::test]
    async fn converts_chat_text_and_tool_deltas_to_responses_events() {
        let upstream: ProviderStream = Box::pin(stream::iter([
            Ok(Bytes::from_static(
                b"data: {\"id\":\"chat_1\",\"model\":\"model-a\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n",
            )),
            Ok(Bytes::from_static(
                b"data: {\"id\":\"chat_1\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"shell\",\"arguments\":\"{\\\"cmd\\\":\\\"pwd\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n",
            )),
        ]));
        let output = adapt_chat_stream(upstream, "fallback".to_owned())
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("converted stream")
            .concat();
        let output = String::from_utf8(output).expect("UTF-8 SSE");

        assert!(output.contains("response.output_text.delta"));
        assert!(output.contains("response.function_call_arguments.delta"));
        assert!(output.contains(r#""name":"shell""#));
        assert!(output.contains(r#""input_tokens":3"#));
        assert!(output.contains("response.completed"));
    }
}
