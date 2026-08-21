use provider_core::{ProxyRequest, RequestMetadata, WireFormat};
use serde_json::Value;

use super::*;

fn convert(body: Value) -> Value {
    let request = ProxyRequest::new(
        WireFormat::OpenAiChatCompletions,
        body["model"].as_str().unwrap_or("model"),
        Bytes::from(serde_json::to_vec(&body).expect("request JSON")),
    )
    .expect("proxy request")
    .with_metadata(RequestMetadata::default());
    let (request, _) = prepare_responses_request(request).expect("converted request");
    assert_eq!(request.format, WireFormat::OpenAiResponses);
    serde_json::from_slice(&request.payload).expect("Responses JSON")
}

#[test]
fn converts_deepseek_harness_chat_request() {
    let body = convert(serde_json::json!({
        "model": "gpt-5.6-sol",
        "messages": [
            {"role":"system","content":"be useful"},
            {"role":"user","content":"inspect"},
            {"role":"assistant","content":"","reasoning_content":"private","tool_calls":[{
                "id":"call_1","type":"function","function":{"name":"exec","arguments":"{\"cmd\":\"pwd\"}"}
            }]},
            {"role":"tool","tool_call_id":"call_1","content":"/tmp"}
        ],
        "stream": true,
        "stream_options": {"include_usage": true},
        "thinking": {"type":"enabled"},
        "reasoning_effort": "high",
        "max_tokens": 4096,
        "tools": [{"type":"function","function":{"name":"exec","description":"run","parameters":{"type":"object"}}}]
    }));

    assert_eq!(body["model"], "gpt-5.6-sol");
    assert_eq!(body["stream"], true);
    assert_eq!(body["store"], false);
    assert_eq!(body["max_output_tokens"], 4096);
    assert_eq!(body["reasoning"]["effort"], "high");
    assert_eq!(body["input"][0]["role"], "developer");
    assert_eq!(body["input"][2]["type"], "reasoning");
    assert_eq!(body["input"][2]["summary"][0]["text"], "private");
    assert_eq!(body["input"][3]["type"], "function_call");
    assert_eq!(body["input"][4]["type"], "function_call_output");
    assert_eq!(body["tools"][0]["name"], "exec");
    assert!(body.to_string().find("reasoning_content").is_none());
}

#[test]
fn disabled_thinking_omits_responses_reasoning() {
    let body = convert(serde_json::json!({
        "model":"gpt-5.6-luna",
        "messages":[{"role":"user","content":"title"}],
        "stream":true,
        "thinking":{"type":"disabled"}
    }));
    assert!(body.get("reasoning").is_none());
}

#[test]
fn rejects_invalid_include_usage() {
    let body = serde_json::json!({
        "model":"gpt-5.6-luna",
        "messages":[{"role":"user","content":"hello"}],
        "stream_options":{"include_usage":"yes"}
    });
    let request = ProxyRequest::new(
        WireFormat::OpenAiChatCompletions,
        "gpt-5.6-luna",
        Bytes::from(serde_json::to_vec(&body).expect("request JSON")),
    )
    .expect("proxy request");
    let error = prepare_responses_request(request).expect_err("include_usage is invalid");
    assert!(error.message().contains("include_usage"));
}

#[test]
fn reads_include_usage_only_when_explicitly_enabled() {
    assert!(
        !include_usage(
            serde_json::json!({})
                .as_object()
                .expect("empty JSON object")
        )
        .expect("include_usage")
    );
    assert!(
        !include_usage(
            serde_json::json!({"stream_options":{"include_usage":false}})
                .as_object()
                .expect("false stream options object")
        )
        .expect("include_usage")
    );
    assert!(
        include_usage(
            serde_json::json!({"stream_options":{"include_usage":true}})
                .as_object()
                .expect("true stream options object")
        )
        .expect("include_usage")
    );
}

#[test]
fn rejects_chat_fields_that_cannot_be_preserved() {
    let body = serde_json::json!({
        "model":"gpt-5.6-luna",
        "messages":[{"role":"user","content":"hello"}],
        "stream":true,
        "stop":["END"]
    });
    let request = ProxyRequest::new(
        WireFormat::OpenAiChatCompletions,
        "gpt-5.6-luna",
        Bytes::from(serde_json::to_vec(&body).expect("request JSON")),
    )
    .expect("proxy request");
    let error = prepare_responses_request(request).expect_err("stop is unsupported");
    assert!(error.message().contains("stop"));
}

#[test]
fn honours_either_spelling_of_the_output_token_cap() {
    let current = convert(serde_json::json!({
        "model":"gpt-5.6-luna",
        "messages":[{"role":"user","content":"hello"}],
        "max_completion_tokens":512
    }));
    assert_eq!(current["max_output_tokens"], 512);

    // Both spellings present: the deprecated one must not win.
    let both = convert(serde_json::json!({
        "model":"gpt-5.6-luna",
        "messages":[{"role":"user","content":"hello"}],
        "max_tokens":256,
        "max_completion_tokens":512
    }));
    assert_eq!(both["max_output_tokens"], 512);
}
