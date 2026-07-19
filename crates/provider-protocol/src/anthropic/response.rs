use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;
use futures_util::{StreamExt, stream};
use provider_core::{ProviderError, ProviderErrorKind, ProviderStream, ResponseTranslator};
use serde_json::Value;

use crate::sse::SseDecoder;

pub(crate) struct AnthropicResponseTranslator {
    model: String,
}

impl AnthropicResponseTranslator {
    pub(crate) fn new(model: String) -> Self {
        Self { model }
    }
}

impl ResponseTranslator for AnthropicResponseTranslator {
    fn translate_stream(self: Box<Self>, stream: ProviderStream) -> ProviderStream {
        adapt_anthropic_stream(stream, self.model)
    }
}

fn adapt_anthropic_stream(upstream: ProviderStream, model: String) -> ProviderStream {
    let state = AnthropicStreamAdapter {
        upstream,
        decoder: SseDecoder::default(),
        converter: AnthropicEventConverter::new(model),
        output: VecDeque::new(),
        upstream_finished: false,
        completion_emitted: false,
    };
    Box::pin(stream::unfold(state, |mut state| async move {
        let item = state.next_output().await?;
        Some((item, state))
    }))
}

struct AnthropicStreamAdapter {
    upstream: ProviderStream,
    decoder: SseDecoder,
    converter: AnthropicEventConverter,
    output: VecDeque<Result<Bytes, ProviderError>>,
    upstream_finished: bool,
    completion_emitted: bool,
}

impl AnthropicStreamAdapter {
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
                Some(Ok(chunk)) => {
                    for data in self.decoder.push(&chunk) {
                        self.convert_data(data);
                    }
                }
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
        match serde_json::from_slice::<Value>(&data) {
            Ok(event) => {
                if event.get("type").and_then(Value::as_str) == Some("message_stop") {
                    self.upstream_finished = true;
                }
                self.output
                    .extend(self.converter.convert(&event).into_iter().map(Ok));
            }
            Err(_) => self.output.push_back(Err(ProviderError::new(
                ProviderErrorKind::Upstream,
                "Anthropic upstream returned an invalid SSE JSON event",
            ))),
        }
    }
}

struct AnthropicEventConverter {
    model: String,
    response_id: String,
    started: bool,
    next_output_index: u64,
    blocks: BTreeMap<u64, Block>,
    response_output: Vec<Value>,
    stop_reason: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
}

impl AnthropicEventConverter {
    fn new(model: String) -> Self {
        Self {
            model,
            response_id: "resp_anthropic_compatible".to_owned(),
            started: false,
            next_output_index: 0,
            blocks: BTreeMap::new(),
            response_output: Vec::new(),
            stop_reason: None,
            input_tokens: 0,
            output_tokens: 0,
        }
    }

    fn convert(&mut self, event: &Value) -> Vec<Bytes> {
        let mut output = Vec::new();
        match event
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "error" => output.push(responses_event(
                "error",
                serde_json::json!({
                    "type": "error",
                    "error": event.get("error").cloned().unwrap_or(Value::Null)
                }),
            )),
            "message_start" => {
                let message = event.get("message").unwrap_or(&Value::Null);
                if let Some(id) = message
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                {
                    self.response_id = id.to_owned();
                }
                if let Some(model) = message
                    .get("model")
                    .and_then(Value::as_str)
                    .filter(|model| !model.is_empty())
                {
                    self.model = model.to_owned();
                }
                self.input_tokens = message
                    .get("usage")
                    .and_then(|usage| usage.get("input_tokens"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                self.start_response(&mut output);
            }
            "content_block_start" => {
                self.start_response(&mut output);
                self.start_block(event, &mut output);
            }
            "content_block_delta" => self.block_delta(event, &mut output),
            "content_block_stop" => {
                if let Some(index) = event.get("index").and_then(Value::as_u64) {
                    self.finish_block(index, &mut output);
                }
            }
            "message_delta" => {
                self.stop_reason = event
                    .get("delta")
                    .and_then(|delta| delta.get("stop_reason"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                self.output_tokens = event
                    .get("usage")
                    .and_then(|usage| usage.get("output_tokens"))
                    .and_then(Value::as_u64)
                    .unwrap_or(self.output_tokens);
            }
            "message_stop" => {}
            _ => {}
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

    fn start_block(&mut self, event: &Value, output: &mut Vec<Bytes>) {
        let index = event.get("index").and_then(Value::as_u64).unwrap_or(0);
        let content = event.get("content_block").unwrap_or(&Value::Null);
        let output_index = self.next_output_index;
        self.next_output_index += 1;
        match content
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "text" => {
                let item_id = format!("msg_{}_{}", self.response_id, index);
                let initial = content
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                output.push(responses_event(
                    "response.output_item.added",
                    serde_json::json!({
                        "type": "response.output_item.added",
                        "output_index": output_index,
                        "item": {
                            "id": item_id,
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
                        "item_id": item_id,
                        "output_index": output_index,
                        "content_index": 0,
                        "part": { "type": "output_text", "text": "", "annotations": [] }
                    }),
                ));
                if !initial.is_empty() {
                    output.push(output_text_delta(&item_id, output_index, &initial));
                }
                self.blocks.insert(
                    index,
                    Block::Text {
                        output_index,
                        item_id,
                        text: initial,
                    },
                );
            }
            "thinking" => {
                let item_id = format!("rs_{}_{}", self.response_id, index);
                let thinking = content
                    .get("thinking")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let signature = content
                    .get("signature")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                output.push(responses_event(
                    "response.output_item.added",
                    serde_json::json!({
                        "type": "response.output_item.added",
                        "output_index": output_index,
                        "item": { "id": item_id, "type": "reasoning", "summary": [] }
                    }),
                ));
                if !thinking.is_empty() {
                    output.push(reasoning_delta(&item_id, output_index, &thinking));
                }
                self.blocks.insert(
                    index,
                    Block::Thinking {
                        output_index,
                        item_id,
                        thinking,
                        signature,
                    },
                );
            }
            "tool_use" => {
                let call_id = content
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let name = content
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let arguments = content
                    .get("input")
                    .filter(|value| !value.is_null())
                    .map(Value::to_string)
                    .unwrap_or_default();
                let item_id = format!("fc_{}", call_id);
                output.push(responses_event(
                    "response.output_item.added",
                    serde_json::json!({
                        "type": "response.output_item.added",
                        "output_index": output_index,
                        "item": {
                            "id": item_id,
                            "type": "function_call",
                            "status": "in_progress",
                            "call_id": call_id,
                            "name": name,
                            "arguments": ""
                        }
                    }),
                ));
                if !arguments.is_empty() && arguments != "{}" {
                    output.push(function_arguments_delta(&item_id, output_index, &arguments));
                }
                self.blocks.insert(
                    index,
                    Block::Tool {
                        output_index,
                        item_id,
                        call_id,
                        name,
                        arguments: if arguments == "{}" {
                            String::new()
                        } else {
                            arguments
                        },
                    },
                );
            }
            _ => {
                self.next_output_index = self.next_output_index.saturating_sub(1);
            }
        }
    }

    fn block_delta(&mut self, event: &Value, output: &mut Vec<Bytes>) {
        let Some(index) = event.get("index").and_then(Value::as_u64) else {
            return;
        };
        let delta = event.get("delta").unwrap_or(&Value::Null);
        let Some(block) = self.blocks.get_mut(&index) else {
            return;
        };
        match block {
            Block::Text {
                output_index,
                item_id,
                text,
            } => {
                if let Some(value) = delta.get("text").and_then(Value::as_str) {
                    text.push_str(value);
                    output.push(output_text_delta(item_id, *output_index, value));
                }
            }
            Block::Thinking {
                output_index,
                item_id,
                thinking,
                signature,
            } => match delta.get("type").and_then(Value::as_str) {
                Some("thinking_delta") => {
                    if let Some(value) = delta.get("thinking").and_then(Value::as_str) {
                        thinking.push_str(value);
                        output.push(reasoning_delta(item_id, *output_index, value));
                    }
                }
                Some("signature_delta") => {
                    if let Some(value) = delta.get("signature").and_then(Value::as_str) {
                        signature.push_str(value);
                    }
                }
                _ => {}
            },
            Block::Tool {
                output_index,
                item_id,
                arguments,
                ..
            } => {
                if let Some(value) = delta.get("partial_json").and_then(Value::as_str) {
                    arguments.push_str(value);
                    output.push(function_arguments_delta(item_id, *output_index, value));
                }
            }
        }
    }

    fn finish_block(&mut self, index: u64, output: &mut Vec<Bytes>) {
        let Some(block) = self.blocks.remove(&index) else {
            return;
        };
        let (output_index, item) = match block {
            Block::Text {
                output_index,
                item_id,
                text,
            } => {
                let part = serde_json::json!({
                    "type": "output_text",
                    "text": text,
                    "annotations": []
                });
                output.push(responses_event(
                    "response.output_text.done",
                    serde_json::json!({
                        "type": "response.output_text.done",
                        "item_id": item_id,
                        "output_index": output_index,
                        "content_index": 0,
                        "text": text
                    }),
                ));
                output.push(responses_event(
                    "response.content_part.done",
                    serde_json::json!({
                        "type": "response.content_part.done",
                        "item_id": item_id,
                        "output_index": output_index,
                        "content_index": 0,
                        "part": part
                    }),
                ));
                (
                    output_index,
                    serde_json::json!({
                        "id": item_id,
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [part]
                    }),
                )
            }
            Block::Thinking {
                output_index,
                item_id,
                thinking,
                signature,
            } => (
                output_index,
                serde_json::json!({
                    "id": item_id,
                    "type": "reasoning",
                    "summary": if thinking.is_empty() {
                        Vec::<Value>::new()
                    } else {
                        vec![serde_json::json!({ "type": "summary_text", "text": thinking })]
                    },
                    "encrypted_content": signature
                }),
            ),
            Block::Tool {
                output_index,
                item_id,
                call_id,
                name,
                arguments,
            } => {
                output.push(responses_event(
                    "response.function_call_arguments.done",
                    serde_json::json!({
                        "type": "response.function_call_arguments.done",
                        "item_id": item_id,
                        "output_index": output_index,
                        "arguments": arguments
                    }),
                ));
                (
                    output_index,
                    serde_json::json!({
                        "id": item_id,
                        "type": "function_call",
                        "status": "completed",
                        "call_id": call_id,
                        "name": name,
                        "arguments": arguments
                    }),
                )
            }
        };
        output.push(responses_event(
            "response.output_item.done",
            serde_json::json!({
                "type": "response.output_item.done",
                "output_index": output_index,
                "item": item
            }),
        ));
        self.response_output.push(item);
    }

    fn finish(&mut self) -> Vec<Bytes> {
        let mut output = Vec::new();
        self.start_response(&mut output);
        let indices: Vec<_> = self.blocks.keys().copied().collect();
        for index in indices {
            self.finish_block(index, &mut output);
        }
        let incomplete = self.stop_reason.as_deref() == Some("max_tokens");
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
            "output": self.response_output,
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
}

enum Block {
    Text {
        output_index: u64,
        item_id: String,
        text: String,
    },
    Thinking {
        output_index: u64,
        item_id: String,
        thinking: String,
        signature: String,
    },
    Tool {
        output_index: u64,
        item_id: String,
        call_id: String,
        name: String,
        arguments: String,
    },
}

fn output_text_delta(item_id: &str, output_index: u64, delta: &str) -> Bytes {
    responses_event(
        "response.output_text.delta",
        serde_json::json!({
            "type": "response.output_text.delta",
            "item_id": item_id,
            "output_index": output_index,
            "content_index": 0,
            "delta": delta
        }),
    )
}

fn reasoning_delta(item_id: &str, output_index: u64, delta: &str) -> Bytes {
    responses_event(
        "response.reasoning_text.delta",
        serde_json::json!({
            "type": "response.reasoning_text.delta",
            "item_id": item_id,
            "output_index": output_index,
            "content_index": 0,
            "delta": delta
        }),
    )
}

fn function_arguments_delta(item_id: &str, output_index: u64, delta: &str) -> Bytes {
    responses_event(
        "response.function_call_arguments.delta",
        serde_json::json!({
            "type": "response.function_call_arguments.delta",
            "item_id": item_id,
            "output_index": output_index,
            "delta": delta
        }),
    )
}

fn responses_event(event: &str, data: Value) -> Bytes {
    Bytes::from(format!("event: {event}\ndata: {data}\n\n"))
}

#[cfg(test)]
mod tests {
    use futures_util::{StreamExt, stream};

    use super::*;

    #[tokio::test]
    async fn converts_anthropic_text_and_tool_blocks_to_responses_events() {
        let upstream: ProviderStream = Box::pin(stream::iter([Ok(Bytes::from_static(
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"model-a\",\"usage\":{\"input_tokens\":3}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ))]));
        let output = adapt_anthropic_stream(upstream, "fallback".to_owned())
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("converted stream")
            .concat();
        let output = String::from_utf8(output).expect("UTF-8 SSE");

        assert!(output.contains("response.output_text.delta"));
        assert!(output.contains(r#""delta":"hello""#));
        assert!(output.contains(r#""input_tokens":3"#));
        assert!(output.contains("response.completed"));
    }
}
