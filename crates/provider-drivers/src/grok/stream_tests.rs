use super::super::request::NamespaceToolRef;
use super::*;

#[test]
fn restores_namespace_tool_calls_in_stream_events() {
    let mappings = GrokToolMappings {
        namespace_tools: HashMap::from([(
            "codex_app__inner".to_owned(),
            NamespaceToolRef {
                namespace: "codex_app".to_owned(),
                name: "inner".to_owned(),
            },
        )]),
        tool_search: false,
        ..GrokToolMappings::default()
    };
    let mut restorer = GrokToolStreamRestorer::new(mappings);
    let frame = br#"event: response.output_item.done
data: {"type":"response.output_item.done","item":{"type":"function_call","name":"codex_app__inner","call_id":"call_1","arguments":"{}"}}

"#;

    let restored = restorer.restore_frame(frame).remove(0);
    let data = restored
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(b"data: "))
        .expect("data line");
    let payload: Value = serde_json::from_slice(data).expect("restored event JSON");

    assert_eq!(payload["item"]["name"], "inner");
    assert_eq!(payload["item"]["namespace"], "codex_app");
    assert_eq!(payload["item"]["call_id"], "call_1");

    let crlf_frame = b"event: response.output_item.done\r\ndata: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"name\":\"codex_app__inner\"}}\r\n\r\n";
    let restored = restorer.restore_frame(crlf_frame).remove(0);
    assert!(restored.ends_with(b"\r\n\r\n"));
    assert_eq!(find_sse_frame_end(&restored), Some(restored.len()));
}

#[test]
fn normalizes_long_item_ids_across_stream_events() {
    let long_id = "x".repeat(83);
    let mut restorer = GrokToolStreamRestorer::new(GrokToolMappings::default());
    let frame = |payload: Value| {
        format!(
            "data: {}\n\n",
            serde_json::to_string(&payload).expect("event JSON")
        )
    };

    let added = restorer.restore_frame(
        frame(serde_json::json!({
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {"type": "message", "id": long_id.clone(), "role": "assistant"}
        }))
        .as_bytes(),
    );
    let added = frame_payload(&added[0]);
    let normalized_id = added["item"]["id"]
        .as_str()
        .expect("normalized item ID")
        .to_owned();
    assert_ne!(normalized_id, long_id);
    assert!(normalized_id.len() <= MAX_ITEM_ID_LENGTH);

    let delta = restorer.restore_frame(
        frame(serde_json::json!({
            "type": "response.output_text.delta",
            "item_id": long_id.clone(),
            "delta": "hello"
        }))
        .as_bytes(),
    );
    assert_eq!(frame_payload(&delta[0])["item_id"], normalized_id);

    let done = restorer.restore_frame(
        frame(serde_json::json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {"type": "message", "id": long_id.clone(), "role": "assistant"}
        }))
        .as_bytes(),
    );
    assert_eq!(frame_payload(&done[0])["item"]["id"], normalized_id);

    let completed = restorer.restore_frame(
        frame(serde_json::json!({
            "type": "response.completed",
            "response": {
                "output": [{"type": "message", "id": long_id, "role": "assistant"}]
            }
        }))
        .as_bytes(),
    );
    assert_eq!(
        frame_payload(&completed[0])["response"]["output"][0]["id"],
        normalized_id
    );
}

#[test]
fn restores_custom_tool_stream_lifecycle_and_sequences() {
    let mut restorer = GrokToolStreamRestorer::new(GrokToolMappings {
        custom_tools: std::collections::HashSet::from(["shell".to_owned()]),
        ..GrokToolMappings::default()
    });
    let added = restorer.restore_frame(
        b"data: {\"type\":\"response.output_item.added\",\"sequence_number\":7,\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"item_1\",\"call_id\":\"call_1\",\"name\":\"shell\",\"arguments\":\"\",\"status\":\"in_progress\"}}\n\n",
    );
    assert_eq!(added.len(), 1);
    let added = frame_payload(&added[0]);
    assert_eq!(added["sequence_number"], 7);
    assert_eq!(added["item"]["type"], "custom_tool_call");
    assert_eq!(added["item"]["input"], "");
    assert!(added["item"].get("arguments").is_none());

    let delta = restorer.restore_frame(
        b"data: {\"type\":\"response.function_call_arguments.delta\",\"sequence_number\":8,\"output_index\":0,\"item_id\":\"item_1\",\"delta\":\"{\\\"input\\\":\\\"pw\"}\n\n",
    );
    assert!(delta.is_empty());
    let done = restorer.restore_frame(
        b"data: {\"type\":\"response.function_call_arguments.done\",\"sequence_number\":9,\"output_index\":0,\"item_id\":\"item_1\",\"call_id\":\"call_1\",\"name\":\"shell\",\"arguments\":\"{\\\"input\\\":\\\"pwd\\\"}\"}\n\n",
    );
    assert_eq!(done.len(), 2);
    let input_delta = frame_payload(&done[0]);
    assert_eq!(input_delta["type"], "response.custom_tool_call_input.delta");
    assert_eq!(input_delta["sequence_number"], 8);
    assert_eq!(input_delta["delta"], "pwd");
    let input_done = frame_payload(&done[1]);
    assert_eq!(input_done["type"], "response.custom_tool_call_input.done");
    assert_eq!(input_done["sequence_number"], 9);
    assert_eq!(input_done["input"], "pwd");

    let closed = restorer.restore_frame(
        b"data: {\"type\":\"response.output_item.done\",\"sequence_number\":10,\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"item_1\",\"call_id\":\"call_1\",\"name\":\"shell\",\"arguments\":\"{\\\"input\\\":\\\"pwd\\\"}\",\"status\":\"completed\"}}\n\n",
    );
    let closed = frame_payload(&closed[0]);
    assert_eq!(closed["sequence_number"], 10);
    assert_eq!(closed["item"]["type"], "custom_tool_call");
    assert_eq!(closed["item"]["input"], "pwd");
}

#[test]
fn restores_custom_tools_in_terminal_response_events() {
    let mut restorer = GrokToolStreamRestorer::new(GrokToolMappings {
        custom_tools: std::collections::HashSet::from(["terminal__exec".to_owned()]),
        namespace_tools: HashMap::from([(
            "terminal__exec".to_owned(),
            NamespaceToolRef {
                namespace: "terminal".to_owned(),
                name: "exec".to_owned(),
            },
        )]),
        tool_search: false,
    });
    let frames = restorer.restore_frame(
        b"data: {\"type\":\"response.completed\",\"sequence_number\":4,\"response\":{\"output\":[{\"type\":\"function_call\",\"id\":\"item_1\",\"call_id\":\"call_1\",\"name\":\"terminal__exec\",\"arguments\":\"{\\\"input\\\":\\\"pwd\\\"}\"}]}}\n\n",
    );
    let payload = frame_payload(&frames[0]);
    assert_eq!(payload["response"]["output"][0]["type"], "custom_tool_call");
    assert_eq!(payload["response"]["output"][0]["name"], "exec");
    assert_eq!(payload["response"]["output"][0]["namespace"], "terminal");
    assert_eq!(payload["response"]["output"][0]["input"], "pwd");
    assert!(payload["response"]["output"][0].get("arguments").is_none());
}

#[test]
fn restores_interleaved_namespaced_custom_calls_consistently() {
    let mut restorer = GrokToolStreamRestorer::new(GrokToolMappings {
        custom_tools: std::collections::HashSet::from([
            "terminal__exec".to_owned(),
            "shell".to_owned(),
        ]),
        namespace_tools: HashMap::from([(
            "terminal__exec".to_owned(),
            NamespaceToolRef {
                namespace: "terminal".to_owned(),
                name: "exec".to_owned(),
            },
        )]),
        tool_search: false,
    });
    let first_added = restorer.restore_frame(
        b"event: response.output_item.added\r\ndata: {\"type\":\"response.output_item.added\",\"sequence_number\":0,\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"item_1\",\"call_id\":\"call_1\",\"name\":\"terminal__exec\",\"arguments\":\"\"}}\r\n\r\n",
    );
    assert!(first_added[0].ends_with(b"\r\n\r\n"));
    let first_added = frame_payload(&first_added[0]);
    assert_eq!(first_added["item"]["type"], "custom_tool_call");
    assert_eq!(first_added["item"]["name"], "exec");
    assert_eq!(first_added["item"]["namespace"], "terminal");

    restorer.restore_frame(
        b"data: {\"type\":\"response.output_item.added\",\"sequence_number\":1,\"output_index\":1,\"item\":{\"type\":\"function_call\",\"id\":\"item_2\",\"call_id\":\"call_2\",\"name\":\"shell\",\"arguments\":\"\"}}\n\n",
    );
    assert!(
        restorer
            .restore_frame(
                b"data: {\"type\":\"response.function_call_arguments.delta\",\"sequence_number\":2,\"output_index\":0,\"item_id\":\"item_1\",\"delta\":\"{\\\"input\\\":\\\"first\\\"}\"}\n\n",
            )
            .is_empty()
    );
    assert!(
        restorer
            .restore_frame(
                b"data: {\"type\":\"response.function_call_arguments.delta\",\"sequence_number\":3,\"output_index\":1,\"item_id\":\"item_2\",\"delta\":\"{\\\"input\\\":\\\"second\\\"}\"}\n\n",
            )
            .is_empty()
    );
    let second_done = restorer.restore_frame(
        b"data: {\"type\":\"response.function_call_arguments.done\",\"sequence_number\":4,\"output_index\":1,\"item_id\":\"item_2\",\"call_id\":\"call_2\",\"name\":\"shell\"}\n\n",
    );
    let second_done = frame_payload(second_done.last().expect("second done event"));
    assert_eq!(second_done["sequence_number"], 3);
    assert_eq!(second_done["name"], "shell");
    assert_eq!(second_done["input"], "second");

    let first_done = restorer.restore_frame(
        b"data: {\"type\":\"response.function_call_arguments.done\",\"sequence_number\":5,\"output_index\":0,\"item_id\":\"item_1\",\"call_id\":\"call_1\",\"name\":\"terminal__exec\"}\n\n",
    );
    let first_done = frame_payload(first_done.last().expect("first done event"));
    assert_eq!(first_done["sequence_number"], 5);
    assert_eq!(first_done["name"], "exec");
    assert_eq!(first_done["namespace"], "terminal");
    assert_eq!(first_done["input"], "first");
}

#[test]
fn restores_tool_search_stream_and_terminal_lifecycle() {
    let mut restorer = GrokToolStreamRestorer::new(GrokToolMappings {
        tool_search: true,
        ..GrokToolMappings::default()
    });
    let added = restorer.restore_frame(
        b"data: {\"type\":\"response.output_item.added\",\"sequence_number\":0,\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"search_item\",\"call_id\":\"search_1\",\"name\":\"tool_search\",\"arguments\":\"\"}}\n\n",
    );
    let added = frame_payload(&added[0]);
    assert_eq!(added["item"]["type"], "tool_search_call");
    assert!(added["item"].get("name").is_none());
    assert_eq!(added["item"]["arguments"], "{}");

    assert!(
        restorer
            .restore_frame(
                b"data: {\"type\":\"response.function_call_arguments.delta\",\"sequence_number\":1,\"output_index\":0,\"item_id\":\"search_item\",\"delta\":\"{\\\"query\\\":\\\"git\\\"}\"}\n\n",
            )
            .is_empty()
    );
    assert!(
        restorer
            .restore_frame(
                b"data: {\"type\":\"response.function_call_arguments.done\",\"sequence_number\":2,\"output_index\":0,\"item_id\":\"search_item\",\"arguments\":\"{\\\"query\\\":\\\"git\\\"}\"}\n\n",
            )
            .is_empty()
    );
    let done = restorer.restore_frame(
        b"data: {\"type\":\"response.output_item.done\",\"sequence_number\":3,\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"search_item\",\"call_id\":\"search_1\",\"name\":\"tool_search\",\"arguments\":\"{\\\"query\\\":\\\"git\\\"}\"}}\n\n",
    );
    let done = frame_payload(&done[0]);
    assert_eq!(done["sequence_number"], 1);
    assert_eq!(done["item"]["type"], "tool_search_call");
    assert!(done["item"].get("name").is_none());

    let completed = restorer.restore_frame(
        b"data: {\"type\":\"response.completed\",\"sequence_number\":4,\"response\":{\"output\":[{\"type\":\"function_call\",\"id\":\"search_item\",\"call_id\":\"search_1\",\"name\":\"tool_search\",\"arguments\":\"{\\\"query\\\":\\\"git\\\"}\"}]}}\n\n",
    );
    let completed = frame_payload(&completed[0]);
    assert_eq!(completed["sequence_number"], 2);
    assert_eq!(
        completed["response"]["output"][0]["type"],
        "tool_search_call"
    );
    assert_eq!(completed["response"]["output"][0]["execution"], "client");
    assert_eq!(
        completed["response"]["output"][0]["arguments"]["query"],
        "git"
    );
}

#[test]
fn filters_billing_ping_frames_for_strict_responses_clients() {
    let mut restorer = GrokToolStreamRestorer::new(GrokToolMappings::default());

    let lf = restorer.restore_frame(
        b"event: ping\ndata: {\"type\":\"ping\",\"x-opencode-type\":\"inference-cost\"}\n\n",
    );
    assert_eq!(lf, vec![Bytes::from_static(b": ping\n\n")]);

    let crlf = restorer.restore_frame(b"event: ping\r\ndata: {\"type\":\"ping\"}\r\n\r\n");
    assert_eq!(crlf, vec![Bytes::from_static(b": ping\r\n\r\n")]);

    let cr = restorer.restore_frame(b"event: ping\rdata: {\"type\":\"ping\"}\r\r");
    assert_eq!(cr, vec![Bytes::from_static(b": ping\r\r")]);
    assert_eq!(find_sse_frame_end(b"event: ping\r\rnext"), Some(13));
}

#[test]
fn normalizes_reasoning_events_and_resequences_expanded_done() {
    let mut restorer = GrokToolStreamRestorer::new(GrokToolMappings::default());
    let delta = restorer.restore_frame(
        b"event: response.reasoning_text.delta\ndata: {\"type\":\"response.reasoning_text.delta\",\"sequence_number\":3,\"item_id\":\"rs_1\",\"content_index\":0,\"delta\":\"think\"}\n\n",
    );
    let delta = frame_payload(&delta[0]);
    assert_eq!(delta["type"], "response.reasoning_summary_text.delta");
    assert_eq!(delta["summary_index"], 0);
    assert!(delta.get("content_index").is_none());

    let done = restorer.restore_frame(
        b"event: response.reasoning_text.done\ndata: {\"type\":\"response.reasoning_text.done\",\"sequence_number\":4,\"item_id\":\"rs_1\",\"content_index\":0,\"text\":\"think\"}\n\n",
    );
    assert_eq!(done.len(), 2);
    let text_done = frame_payload(&done[0]);
    let part_done = frame_payload(&done[1]);
    assert_eq!(text_done["type"], "response.reasoning_summary_text.done");
    assert_eq!(text_done["sequence_number"], 4);
    assert_eq!(part_done["type"], "response.reasoning_summary_part.done");
    assert_eq!(part_done["sequence_number"], 5);
    assert_eq!(part_done["part"]["type"], "summary_text");
    assert_eq!(part_done["part"]["text"], "think");
}

#[test]
fn rebuilds_missing_terminal_output_from_completed_items() {
    let mut restorer = GrokToolStreamRestorer::new(GrokToolMappings::default());
    let item = restorer.restore_frame(
        b"data: {\"type\":\"response.output_item.done\",\"sequence_number\":0,\"output_index\":2,\"item\":{\"type\":\"message\",\"id\":\"msg_1\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"hello\"}]}}\n\n",
    );
    assert_eq!(item.len(), 1);

    let completed = restorer.restore_frame(
        b"data: {\"type\":\"response.completed\",\"sequence_number\":1,\"response\":{\"id\":\"resp_1\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
    );
    let completed = frame_payload(&completed[0]);
    assert_eq!(completed["response"]["output"][0]["id"], "msg_1");
    assert_eq!(
        completed["response"]["output"][0]["content"][0]["text"],
        "hello"
    );
}

#[test]
fn accepts_multiline_sse_json_and_emits_one_data_line() {
    let mut restorer = GrokToolStreamRestorer::new(GrokToolMappings::default());
    let frames = restorer.restore_frame(
        b"event: response.created\ndata: {\"type\":\ndata: \"response.created\",\"sequence_number\":0}\n\n",
    );
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0]
            .split(|byte| *byte == b'\n')
            .filter(|line| line.starts_with(b"data:"))
            .count(),
        1
    );
    assert_eq!(frame_payload(&frames[0])["type"], "response.created");
}

#[tokio::test]
async fn emits_failed_terminal_when_upstream_ends_without_completion() {
    let upstream: ProviderStream = Box::pin(stream::iter([
        Ok::<Bytes, ProviderError>(Bytes::from_static(
            b"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\n",
        )),
        Ok(Bytes::from_static(
            b"data: {\"type\":\"response.output_text.delta\"}",
        )),
    ]));
    let mut restored = restore_tool_stream(upstream, GrokToolMappings::default(), "grok-4.5");
    let mut failure = None;
    let mut partial_forwarded = false;
    while let Some(chunk) = restored.next().await {
        let chunk = chunk.expect("terminal failure is sent as SSE");
        let Some(data) = sse_data_payload(&chunk) else {
            continue;
        };
        let payload: Value = serde_json::from_slice(&data).expect("event JSON");
        if payload["type"] == "response.failed" {
            failure = Some(payload);
        } else if payload["type"] == "response.output_text.delta" {
            partial_forwarded = true;
        }
    }
    let failure = failure.expect("missing response.failed terminal");
    assert!(
        !partial_forwarded,
        "incomplete SSE data must not be forwarded"
    );
    assert_eq!(failure["response"]["id"], "resp_1");
    assert_eq!(failure["response"]["model"], "grok-4.5");
    assert_eq!(failure["response"]["status"], "failed");
}

#[test]
fn normalizes_non_success_completed_status_to_failure_terminal() {
    let mut restorer = GrokToolStreamRestorer::new(GrokToolMappings::default());
    let frames = restorer.restore_frame(
        b"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_failed\",\"status\":\"failed\",\"output\":[]}}\n\n",
    );
    let payload = frame_payload(&frames[0]);
    assert_eq!(payload["type"], "response.failed");
    assert_eq!(payload["response"]["status"], "failed");
    assert_eq!(
        payload["response"]["error"]["code"],
        "upstream_non_success_terminal"
    );
    assert!(restorer.terminal_seen());
}

fn frame_payload(frame: &[u8]) -> Value {
    let data = frame
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(b"data: "))
        .expect("data line");
    serde_json::from_slice(data).expect("event JSON")
}
