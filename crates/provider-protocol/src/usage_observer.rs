//! Observes upstream usage by tapping the byte stream.
//!
//! This is a tee, not a second consumer: there is still exactly one poll chain
//! over the upstream body, and usage is decoded once. What it does add is one SSE
//! framing pass, and only where a translator frames the same bytes anyway:
//!
//! * `/v1/responses` to a Responses provider — the identity translator is pure
//!   pass-through, so this is the only framing that happens at all.
//! * `/v1/messages` to a Responses provider — the Claude translator frames too,
//!   so those bytes get scanned twice.
//!
//! That second case is measured and accepted: the extra work is a `\n\n` scan and
//! a copy, against the JSON translation and network I/O already on the same path.
//! Folding it into a single typed-event decode would mean reshaping
//! `ResponseTranslator` and turning today's zero-cost identity pass-through into
//! decode-and-replay. See the D1 entry in the plan document for the conditions
//! that would make that worth doing.
//!
//! Three properties this must never lose, each covered by a test below:
//!
//! 1. It is a tee, not a second consumer: bytes pass through byte-identical and
//!    the full response is never buffered.
//! 2. It reports exactly once — at EOF or on drop, whichever happens first.
//! 3. A dropped downstream drops the upstream immediately; a client disconnect
//!    must not leave it reading in the background.

use std::sync::Arc;

use bytes::Bytes;
use futures_util::{StreamExt, stream};
use provider_core::{
    ProviderError, ProviderStream,
    usage::{AttemptTracking, RawUsageFields},
};
use serde_json::Value;

use crate::sse::SseDecoder;

/// Wrap an upstream byte stream so its usage is observed in passing.
///
/// The attempt is told exactly once, when the response ends: either the usage it
/// carried, or `None` for a response that carried none.
#[must_use]
pub fn observe_responses_usage(
    upstream: ProviderStream,
    attempt: Arc<dyn AttemptTracking>,
) -> ProviderStream {
    observe_usage(upstream, attempt, extract_responses_facts)
}

/// Wrap an OpenAI Chat Completions byte stream so its usage is observed in passing.
#[must_use]
pub fn observe_chat_completions_usage(
    upstream: ProviderStream,
    attempt: Arc<dyn AttemptTracking>,
) -> ProviderStream {
    observe_usage(upstream, attempt, extract_chat_completions_facts)
}

type FrameExtractor = fn(&[u8]) -> Option<ObservedFrame>;

fn observe_usage(
    upstream: ProviderStream,
    attempt: Arc<dyn AttemptTracking>,
    extractor: FrameExtractor,
) -> ProviderStream {
    let state = UsageObservingStream {
        upstream,
        decoder: SseDecoder::default(),
        latest: None,
        attempt: Some(attempt),
        upstream_done: false,
        blind: false,
        extractor,
    };

    Box::pin(stream::unfold(state, |mut state| async move {
        let item = state.next_item().await?;
        Some((item, state))
    }))
}

struct UsageObservingStream {
    upstream: ProviderStream,
    decoder: SseDecoder,
    latest: Option<RawUsageFields>,
    /// Taken when the attempt is told, so it is told exactly once.
    attempt: Option<Arc<dyn AttemptTracking>>,
    upstream_done: bool,
    /// Set when the upstream framing became unparseable. Observation stops; the
    /// response itself is unaffected.
    blind: bool,
    extractor: FrameExtractor,
}

impl UsageObservingStream {
    async fn next_item(&mut self) -> Option<Result<Bytes, ProviderError>> {
        if self.upstream_done {
            return None;
        }

        match self.upstream.next().await {
            Some(Ok(chunk)) => {
                self.inspect(&chunk);
                // The chunk is forwarded untouched; inspection only reads a copy
                // the decoder keeps.
                Some(Ok(chunk))
            }
            // An error is forwarded verbatim and does not end the stream here:
            // truncating on error would break byte-for-byte pass-through. The
            // report happens at EOF or on drop, so nothing is lost either way.
            Some(Err(error)) => Some(Err(error)),
            None => {
                self.upstream_done = true;
                if let Some(frame) = self.decoder.finish() {
                    self.inspect_frame(&frame);
                }
                self.report();
                None
            }
        }
    }

    fn inspect(&mut self, chunk: &[u8]) {
        if self.blind {
            return;
        }
        match self.decoder.push(chunk) {
            Ok(frames) => {
                for frame in frames {
                    self.inspect_frame(&frame);
                }
            }
            Err(_) => {
                // An oversized frame stops observation and nothing more. Unlike a
                // translator, an observer may not turn this into a client-visible
                // error: the bytes must keep flowing exactly as they arrived. The
                // attempt is told the absence is ours, so it is not recorded as
                // "the provider reported no usage".
                self.blind = true;
                if let Some(attempt) = &self.attempt {
                    attempt.observation_lost();
                }
            }
        }
    }

    fn inspect_frame(&mut self, frame: &[u8]) {
        let Some(observed) = (self.extractor)(frame) else {
            return;
        };
        if let Some(attempt) = &self.attempt {
            if let Some(model) = &observed.model {
                attempt.provider_model_observed(model);
            }
            if observed.success_terminal {
                // Proof the stream ended the way the protocol says it should,
                // which is what separates a success from a stream that merely
                // stopped.
                attempt.success_terminal_observed();
            }
            if observed.first_token {
                attempt.first_token_observed();
            }
        }
        // A later terminal supersedes an earlier one — but a frame that carried
        // no usage does not erase usage already observed.
        if observed.fields.is_some() {
            self.latest = observed.fields;
        }
    }

    /// Tell the attempt the response ended. Safe to call more than once; only the
    /// first call reports.
    fn report(&mut self) {
        if let Some(attempt) = self.attempt.take() {
            attempt.finished(self.latest.take());
        }
    }
}

impl Drop for UsageObservingStream {
    fn drop(&mut self) {
        // A client disconnect drops us mid-stream: report whatever was already
        // observed instead of losing it, and let `upstream` drop so no
        // background reading continues.
        self.report();
    }
}

/// What one frame proved, in the three dimensions this observer reads: how much
/// was metered, which model answered, and whether the stream ended properly.
/// Each is independent — a frame can carry any subset.
struct ObservedFrame {
    fields: Option<RawUsageFields>,
    /// The model the provider says it served, when the frame names one.
    model: Option<String>,
    /// Whether this frame carries the first non-empty output delta.
    first_token: bool,
    success_terminal: bool,
}

/// Pull the terminal facts out of one decoded SSE data frame of an OpenAI
/// Responses stream, or `None` if it carried none.
///
/// The pre-check keeps the JSON parse off every content delta. It admits the
/// successful terminal *by name* as well as anything mentioning usage, because a
/// `response.completed` that reports no usage is still the only proof that the
/// stream ended the way the protocol says it should — gating on `usage` alone
/// recorded those responses as merely having stopped.
fn extract_responses_facts(frame: &[u8]) -> Option<ObservedFrame> {
    if !contains_subslice(frame, b"usage")
        && !contains_subslice(frame, COMPLETED_EVENT.as_bytes())
        && !FIRST_TOKEN_EVENT_TYPES
            .iter()
            .any(|event| contains_subslice(frame, event.as_bytes()))
    {
        return None;
    }
    let event: Value = serde_json::from_slice(frame).ok()?;
    let event_type = event.get("type").and_then(Value::as_str);
    let response = event.get("response");
    let usage = response
        .and_then(|response| response.get("usage"))
        .or_else(|| event.get("usage"))
        // A `usage` that is not an object carries no counts; treating it as
        // present would fabricate a report the provider never made.
        .filter(|usage| usage.is_object());
    let model = response
        .and_then(|response| response.get("model"))
        .or_else(|| event.get("model"))
        .and_then(Value::as_str)
        // An empty name is an absence; an implausibly long one is not a model
        // identifier, and this value reaches storage, so it is bounded here
        // rather than trusted at the length a 1 MiB frame allows.
        .filter(|model| !model.is_empty() && model.len() <= MAX_MODEL_LEN)
        .map(ToOwned::to_owned);
    let success_terminal = event.get("type").and_then(Value::as_str) == Some(COMPLETED_EVENT);
    let first_token = event_type
        .is_some_and(|event_type| FIRST_TOKEN_EVENT_TYPES.contains(&event_type))
        && event
            .get("delta")
            .and_then(Value::as_str)
            .is_some_and(|delta| !delta.is_empty());

    if usage.is_none() && model.is_none() && !success_terminal && !first_token {
        return None;
    }
    Some(ObservedFrame {
        fields: usage.map(RawUsageFields::from_responses_usage),
        model,
        first_token,
        success_terminal,
    })
}

/// Pull usage and lifecycle facts from one OpenAI Chat Completions SSE frame.
fn extract_chat_completions_facts(frame: &[u8]) -> Option<ObservedFrame> {
    if frame == b"[DONE]" {
        return Some(ObservedFrame {
            fields: None,
            model: None,
            first_token: false,
            success_terminal: true,
        });
    }
    if !contains_subslice(frame, b"usage")
        && !contains_subslice(frame, b"model")
        && !contains_subslice(frame, b"choices")
    {
        return None;
    }

    let event: Value = serde_json::from_slice(frame).ok()?;
    let usage = event.get("usage").filter(|usage| usage.is_object());
    let model = event
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| !model.is_empty() && model.len() <= MAX_MODEL_LEN)
        .map(ToOwned::to_owned);
    let choices = event.get("choices").and_then(Value::as_array);
    let success_terminal = choices.is_some_and(|choices| {
        choices.iter().any(|choice| {
            choice
                .get("finish_reason")
                .is_some_and(|reason| !reason.is_null())
        })
    });
    let first_token = choices.is_some_and(|choices| {
        choices
            .iter()
            .any(|choice| choice.get("delta").is_some_and(chat_delta_has_output))
    });

    if usage.is_none() && model.is_none() && !success_terminal && !first_token {
        return None;
    }
    Some(ObservedFrame {
        fields: usage.map(RawUsageFields::from_chat_completions_usage),
        model,
        first_token,
        success_terminal,
    })
}

fn chat_delta_has_output(delta: &Value) -> bool {
    ["content", "reasoning_content", "reasoning"]
        .iter()
        .any(|field| {
            delta
                .get(field)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        })
        || delta
            .get("tool_calls")
            .and_then(Value::as_array)
            .is_some_and(|calls| {
                calls.iter().any(|call| {
                    call.get("function").is_some_and(|function| {
                        ["arguments", "name"].iter().any(|field| {
                            function
                                .get(field)
                                .and_then(Value::as_str)
                                .is_some_and(|value| !value.is_empty())
                        })
                    })
                })
            })
}

/// The Responses event that marks a stream's successful end.
const COMPLETED_EVENT: &str = "response.completed";

/// Output events that carry the first user-visible token or tool argument.
/// Item-start events are intentionally excluded because they can arrive before
/// any token has been produced.
const FIRST_TOKEN_EVENT_TYPES: &[&str] = &[
    "response.output_text.delta",
    "response.reasoning_text.delta",
    "response.reasoning_summary_text.delta",
    "response.function_call_arguments.delta",
];

/// Longest model name accepted from an upstream response.
const MAX_MODEL_LEN: usize = 200;

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use futures_util::StreamExt;

    use super::*;

    /// Records what the observer told the attempt.
    #[derive(Default)]
    struct RecordingAttempt {
        finished: Mutex<Option<Option<RawUsageFields>>>,
        observation_lost: Mutex<bool>,
        first_token: Mutex<bool>,
        success_terminal: Mutex<bool>,
        model: Mutex<Option<String>>,
    }

    impl RecordingAttempt {
        fn reported(&self) -> Option<Option<RawUsageFields>> {
            *self.finished.lock().expect("finished lock")
        }

        fn lost(&self) -> bool {
            *self.observation_lost.lock().expect("lost lock")
        }

        fn saw_success_terminal(&self) -> bool {
            *self.success_terminal.lock().expect("terminal lock")
        }

        fn saw_first_token(&self) -> bool {
            *self.first_token.lock().expect("first token lock")
        }
    }

    impl AttemptTracking for RecordingAttempt {
        fn stream_opened(&self) {}

        fn first_token_observed(&self) {
            *self.first_token.lock().expect("first token lock") = true;
        }

        fn success_terminal_observed(&self) {
            *self.success_terminal.lock().expect("terminal lock") = true;
        }

        fn provider_model_observed(&self, model: &str) {
            *self.model.lock().expect("model lock") = Some(model.to_owned());
        }

        fn observation_lost(&self) {
            *self.observation_lost.lock().expect("lost lock") = true;
        }

        fn finished(&self, fields: Option<RawUsageFields>) {
            let mut slot = self.finished.lock().expect("finished lock");
            assert!(slot.is_none(), "an attempt must be told exactly once");
            *slot = Some(fields);
        }

        fn failed(&self, _answered: bool) {}
    }

    fn recording_attempt() -> (Arc<RecordingAttempt>, Arc<dyn AttemptTracking>) {
        let attempt = Arc::new(RecordingAttempt::default());
        (Arc::clone(&attempt), attempt)
    }

    fn byte_stream(chunks: Vec<&'static str>) -> ProviderStream {
        Box::pin(stream::iter(
            chunks
                .into_iter()
                .map(|chunk| Ok(Bytes::from_static(chunk.as_bytes()))),
        ))
    }

    const COMPLETED: &str = concat!(
        "data: {\"type\":\"response.completed\",\"response\":",
        "{\"model\":\"gpt-5-codex\",\"usage\":",
        "{\"input_tokens\":120,\"input_tokens_details\":{\"cached_tokens\":100},",
        "\"output_tokens\":8,\"total_tokens\":128}}}\n\n"
    );

    #[tokio::test]
    async fn bytes_pass_through_unchanged() {
        let (observed, attempt) = recording_attempt();
        let chunks = vec![
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n",
            COMPLETED,
        ];
        let stream = observe_responses_usage(byte_stream(chunks.clone()), attempt);

        let forwarded: Vec<Bytes> = stream.map(|item| item.expect("no error")).collect().await;
        let expected: Vec<Bytes> = chunks
            .iter()
            .map(|chunk| Bytes::from_static(chunk.as_bytes()))
            .collect();
        assert_eq!(forwarded, expected, "a tee must not alter the payload");
        assert!(observed.reported().is_some());
        assert!(observed.saw_first_token());
    }

    #[tokio::test]
    async fn chat_completions_usage_and_terminal_are_observed_without_changing_bytes() {
        let (observed, attempt) = recording_attempt();
        let chunks = vec![
            "data: {\"id\":\"chat_1\",\"model\":\"qwen-max\",\"choices\":[{\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chat_1\",\"model\":\"qwen-max\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":4,\"total_tokens\":16}}\n\n",
            "data: [DONE]\n\n",
        ];
        let stream = observe_chat_completions_usage(byte_stream(chunks.clone()), attempt);

        let forwarded: Vec<Bytes> = stream.map(|item| item.expect("no error")).collect().await;
        let expected: Vec<Bytes> = chunks
            .iter()
            .map(|chunk| Bytes::from_static(chunk.as_bytes()))
            .collect();
        assert_eq!(forwarded, expected, "a tee must not alter the payload");

        let fields = observed
            .reported()
            .expect("attempt told")
            .expect("usage observed");
        assert_eq!(fields.input, Some(12));
        assert_eq!(fields.output, Some(4));
        assert_eq!(fields.total, Some(16));
        assert_eq!(
            observed.model.lock().expect("model lock").as_deref(),
            Some("qwen-max")
        );
        assert!(observed.saw_first_token());
        assert!(observed.saw_success_terminal());
    }

    #[tokio::test]
    async fn usage_outside_the_completed_event_is_not_a_success_terminal() {
        // A stream that reports usage on an incomplete or failed event has not
        // demonstrated success, and must not be recorded as if it had.
        let (observed, attempt) = recording_attempt();
        let incomplete = concat!(
            "data: {\"type\":\"response.incomplete\",\"response\":{\"usage\":",
            "{\"input_tokens\":5,\"output_tokens\":1,\"total_tokens\":6}}}\n\n"
        );
        let stream = observe_responses_usage(byte_stream(vec![incomplete]), attempt);
        let _: Vec<_> = stream.collect().await;

        assert!(!observed.saw_success_terminal());
        let fields = observed
            .reported()
            .expect("attempt told")
            .expect("usage is still recorded");
        assert_eq!(fields.input, Some(5), "the usage it did report is kept");
    }

    #[tokio::test]
    async fn terminal_without_usage_reports_none_but_still_proves_success() {
        let (observed, attempt) = recording_attempt();
        let stream = observe_responses_usage(
            byte_stream(vec![
                "data: {\"type\":\"response.completed\",\"response\":{}}\n\n",
            ]),
            attempt,
        );
        let _: Vec<_> = stream.collect().await;

        assert_eq!(
            observed.reported().expect("attempt told"),
            None,
            "no usage must be reported as absent, never as zero"
        );
        assert!(
            observed.saw_success_terminal(),
            "a response that ends properly but meters nothing still succeeded"
        );
    }

    #[tokio::test]
    async fn dropping_mid_stream_still_reports_once() {
        let (observed, attempt) = recording_attempt();
        let mut stream =
            observe_responses_usage(byte_stream(vec![COMPLETED, "data: x\n\n"]), attempt);

        // Read only the terminal event, then drop as a disconnecting client would.
        let _first = stream.next().await.expect("first chunk");
        assert!(
            observed.reported().is_none(),
            "reporting happens at the end, not per chunk"
        );
        drop(stream);

        let fields = observed
            .reported()
            .expect("drop reported")
            .expect("usage observed before the drop");
        assert_eq!(fields.input, Some(120));
    }

    #[tokio::test]
    async fn upstream_error_passes_through_without_truncating() {
        let (observed, attempt) = recording_attempt();
        // A chunk after the error must still be forwarded: an observer may not
        // change what the client receives.
        let failing: ProviderStream = Box::pin(stream::iter(vec![
            Ok(Bytes::from_static(COMPLETED.as_bytes())),
            Err(ProviderError::new(
                provider_core::ProviderErrorKind::Upstream,
                "boom",
            )),
            Ok(Bytes::from_static(b"data: trailing\n\n")),
        ]));
        let stream = observe_responses_usage(failing, attempt);

        let items: Vec<_> = stream.collect().await;
        assert_eq!(items.len(), 3, "nothing may be dropped after an error");
        assert!(items[1].is_err(), "the error must reach the client");
        assert!(items[2].is_ok());

        let fields = observed
            .reported()
            .expect("told at eof")
            .expect("usage seen before the error is kept");
        assert_eq!(fields.input, Some(120));
    }

    #[tokio::test]
    async fn an_oversized_frame_blinds_the_observer_without_touching_the_response() {
        let (observed, attempt) = recording_attempt();
        // A frame far past the decoder's cap: observation must give up, but the
        // client must still receive every byte and no error.
        let huge = "x".repeat(crate::sse::MAX_PENDING_FRAME + 1);
        let upstream: ProviderStream = Box::pin(stream::iter(vec![
            Ok(Bytes::from(huge.clone())),
            Ok(Bytes::from_static(COMPLETED.as_bytes())),
        ]));
        let stream = observe_responses_usage(upstream, attempt);

        let items: Vec<_> = stream.collect().await;
        assert_eq!(items.len(), 2);
        assert!(
            items.iter().all(Result::is_ok),
            "an observer must never inject an error into the response"
        );
        let forwarded: Vec<Bytes> = items
            .into_iter()
            .map(|item| item.expect("checked above"))
            .collect();
        assert_eq!(forwarded[0], Bytes::from(huge));
        assert_eq!(forwarded[1], Bytes::from_static(COMPLETED.as_bytes()));

        assert!(
            observed.lost(),
            "the attempt must be told the absence is ours, not the provider's"
        );
        assert_eq!(observed.reported().expect("attempt told"), None);
    }
}
