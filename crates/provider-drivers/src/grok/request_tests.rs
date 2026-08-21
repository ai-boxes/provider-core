use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};

#[test]
fn normalizes_codex_request_for_grok() {
    let payload = Bytes::from_static(
        br#"{
                "model":"client-model",
                "stream":false,
                "stream_options":{"include_usage":true},
                "prompt_cache_key":" session-from-body ",
                "tools":[
                    {"type":"custom","name":"shell"},
                    {"type":"custom","name":"apply_patch"},
                    {"type":"function","name":"lookup"},
                    {"type":"tool_search"},
                    {"type":"web_search","external_web_access":true}
                ],
                "input":[
                    {"type":"custom_tool_call","call_id":"call_1","name":"shell","input":"pwd"},
                    {"type":"custom_tool_call_output","call_id":"call_1","output":{"ok":true}}
                ]
            }"#,
    );
    let mut request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload,
        metadata: RequestMetadata::default(),
    };
    request.metadata.session_id = Some(" metadata-session ".to_owned());

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["model"], "grok-4.5");
    assert_eq!(body["stream"], true);
    assert!(body.get("stream_options").is_none());
    assert_eq!(body["prompt_cache_key"], "metadata-session");
    assert_eq!(
        prepared.metadata.session_id.as_deref(),
        Some("metadata-session")
    );
    assert_eq!(body["tools"].as_array().expect("tools").len(), 5);
    assert_eq!(body["tools"][0]["type"], "function");
    assert_eq!(body["tools"][0]["parameters"]["type"], "object");
    assert_eq!(body["tools"][0]["parameters"]["required"][0], "input");
    assert_eq!(
        body["tools"][0]["parameters"]["additionalProperties"],
        false
    );
    assert_eq!(body["tools"][1]["name"], "apply_patch");
    assert_eq!(body["tools"][1]["parameters"]["required"][0], "input");
    assert_eq!(body["tools"][2]["parameters"]["type"], "object");
    assert_eq!(body["tools"][3]["name"], "tool_search");
    assert!(body["tools"][4].get("external_web_access").is_none());
    assert_eq!(body["input"][0]["type"], "function_call");
    assert_eq!(body["input"][0]["arguments"], r#"{"input":"pwd"}"#);
    assert_eq!(body["input"][1]["type"], "function_call_output");
    assert_eq!(body["input"][1]["output"], r#"{"ok":true}"#);
    assert!(prepared.tool_mappings.custom_tools.contains("shell"));
    assert!(prepared.tool_mappings.custom_tools.contains("apply_patch"));
    assert!(prepared.tool_mappings.tool_search);
}

#[test]
fn strips_collaboration_message_encryption_markers() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                "tools":[
                    {
                        "type":"namespace",
                        "name":"collaboration",
                        "tools":[
                            {"type":"function","name":"spawn_agent","parameters":{"type":"object","properties":{"message":{"type":"string","encrypted":true}}}},
                            {"type":"function","name":"followup_task","parameters":{"type":"object","properties":{"message":{"type":"string","encrypted":true}}}},
                            {"type":"function","name":"unrelated_tool","parameters":{"type":"object","properties":{"message":{"type":"string","encrypted":true},"data":{"encrypted":"keep-me"}}}}
                        ]
                    }
                ],
                "input":[
                    {"type":"additional_tools","tools":[{"type":"function","name":"send_message","parameters":{"type":"object","properties":{"message":{"type":"string","encrypted":true}}}}]},
                    {"type":"agent_message","id":"amsg_child","author":"/root","recipient":"/root/worker","content":[{"type":"input_text","text":"Payload:\n"},{"type":"encrypted_content","encrypted_content":"delegated task"}],"internal_chat_message_metadata_passthrough":{"turn_id":"turn_child"}}
                ]
            }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("collaboration tool schemas");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    let tools = body["tools"].as_array().expect("tools");

    for name in [
        "collaboration__spawn_agent",
        "collaboration__followup_task",
        "send_message",
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("missing tool {name}"));
        assert!(
            tool["parameters"]["properties"]["message"]
                .get("encrypted")
                .is_none()
        );
    }

    assert_eq!(body["input"][0]["type"], "message");
    assert_eq!(body["input"][0]["role"], "user");
    assert_eq!(body["input"][0]["content"][1]["type"], "input_text");
    assert_eq!(body["input"][0]["content"][1]["text"], "delegated task");

    let unrelated = tools
        .iter()
        .find(|tool| tool["name"] == "collaboration__unrelated_tool")
        .expect("unrelated tool");
    assert_eq!(
        unrelated["parameters"]["properties"]["message"]["encrypted"],
        true
    );
    assert_eq!(
        unrelated["parameters"]["properties"]["data"]["encrypted"],
        "keep-me"
    );
}

#[test]
fn converts_agent_messages_into_user_messages() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[
                        {
                            "type":"agent_message",
                            "id":"agent_1",
                            "author":"/root/reviewer",
                            "recipient":"/root",
                            "content":[
                                {"type":"input_text","text":"first finding"},
                                {"type":"input_text","text":"second finding"}
                            ],
                            "internal_chat_message_metadata_passthrough":{"turn_id":"turn_1"}
                        }
                    ]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("agent message history");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["input"][0]["type"], "message");
    assert_eq!(body["input"][0]["role"], "user");
    assert_eq!(body["input"][0]["id"], "agent_1");
    assert_eq!(body["input"][0]["author"], "/root/reviewer");
    assert_eq!(body["input"][0]["recipient"], "/root");
    assert_eq!(body["input"][0]["content"][0]["type"], "input_text");
    assert_eq!(body["input"][0]["content"][0]["text"], "first finding");
    assert_eq!(body["input"][0]["content"][1]["type"], "input_text");
    assert_eq!(body["input"][0]["content"][1]["text"], "second finding");
    assert_eq!(
        body["input"][0]["internal_chat_message_metadata_passthrough"]["turn_id"],
        "turn_1"
    );
    assert!(
        body["input"]
            .as_array()
            .expect("input")
            .iter()
            .all(|item| item["type"] != "agent_message")
    );
}

#[test]
fn converts_encrypted_agent_message_text() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[{
                        "type":"agent_message",
                        "author":"/root/worker",
                        "recipient":"/root",
                        "content":[
                            {"type":"input_text","text":"Payload:"},
                            {"type":"encrypted_content","encrypted_content":"delegated task"}
                        ]
                    }]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("encrypted agent message text");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    assert_eq!(body["input"][0]["type"], "message");
    assert_eq!(body["input"][0]["role"], "user");
    assert_eq!(body["input"][0]["content"][0]["type"], "input_text");
    assert_eq!(body["input"][0]["content"][0]["text"], "Payload:");
    assert_eq!(body["input"][0]["content"][1]["type"], "input_text");
    assert_eq!(body["input"][0]["content"][1]["text"], "delegated task");
    assert!(
        body["input"][0]["content"][1]
            .get("encrypted_content")
            .is_none()
    );
}

#[test]
fn drops_unreadable_agent_message_encrypted_content() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[{
                        "type":"agent_message",
                        "content":[
                            {"type":"encrypted_content","text":null},
                            {"type":"input_text","text":"continue"}
                        ]
                    }]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("agent message with empty encrypted content");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["input"][0]["type"], "message");
    assert_eq!(
        body["input"][0]["content"]
            .as_array()
            .expect("message content")
            .len(),
        1
    );
    assert_eq!(body["input"][0]["content"][0]["text"], "continue");
}

#[test]
fn drops_agent_message_without_readable_content() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{"input":[{"type":"agent_message","content":[{"type":"encrypted_content","text":null}]}]}"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("empty agent message request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    assert!(body["input"].as_array().is_some_and(Vec::is_empty));
}

#[test]
fn rejects_non_string_encrypted_agent_message_content() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[{
                        "type":"agent_message",
                        "author":"/root/worker",
                        "recipient":"/root",
                        "content":[
                            {"type":"encrypted_content","encrypted_content":{"value":"opaque"}}
                        ]
                    }]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let error = prepare_request(request).expect_err("non-string encrypted agent message");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(
        error
            .message()
            .contains("encrypted_content must be a string")
    );
}

#[test]
fn preserves_agent_message_text_whitespace() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[{
                        "type":"agent_message",
                        "author":"/root/worker",
                        "recipient":"/root",
                        "content":[
                            {"type":"input_text","text":"  indented\n"},
                            {"type":"input_text","text":"\ntrailing  "}
                        ]
                    }]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("whitespace-sensitive agent message");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    assert_eq!(body["input"][0]["content"][0]["text"], "  indented\n");
    assert_eq!(body["input"][0]["content"][1]["text"], "\ntrailing  ");
}

#[test]
fn rejects_invalid_json_without_echoing_request() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(br#"{"secret":"do-not-echo""#),
        metadata: RequestMetadata::default(),
    };

    let error = prepare_request(request).expect_err("invalid JSON");

    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(!error.message().contains("do-not-echo"));
}

#[test]
fn rejects_previous_response_id_instead_of_silently_dropping_context() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{"previous_response_id":"resp_previous","input":"continue"}"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let error = prepare_request(request).expect_err("unsupported continuation");

    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(error.message().contains("complete input history"));
}

#[test]
fn drops_cross_provider_reasoning_signatures_and_keeps_grok_replay() {
    let grok_signature = STANDARD_NO_PAD.encode((0_u8..64).collect::<Vec<_>>());
    let payload = serde_json::to_vec(&serde_json::json!({
        "input": [
            {
                "type": "reasoning",
                "summary": [{"type":"summary_text","text":"Claude summary"}],
                "encrypted_content": "Eclaude-signature"
            },
            {
                "type": "reasoning",
                "status": "completed",
                "content": null,
                "summary": [{"type":"summary_text","text":"Grok summary"}],
                "encrypted_content": grok_signature
            }
        ]
    }))
    .expect("request JSON");
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: payload.into(),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["input"].as_array().expect("input").len(), 2);
    assert_eq!(body["input"][0]["summary"][0]["text"], "Claude summary");
    assert!(body["input"][0].get("encrypted_content").is_none());
    assert_eq!(body["input"][1]["encrypted_content"], grok_signature);
    assert_eq!(body["input"][1]["summary"][0]["text"], "Grok summary");
    assert!(body["input"][1].get("status").is_none());
    assert!(body["input"][1].get("content").is_none());
}

#[test]
fn strips_only_encrypted_reasoning_for_recovery_retry() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(br#"{
                "input":[
                    {"type":"reasoning","summary":[{"type":"summary_text","text":"keep"}],"content":null,"encrypted_content":"opaque"},
                    {"type":"compaction","encrypted_content":"opaque"},
                    {"type":"message","role":"user","content":"continue"}
                ]
            }"#),
            metadata: RequestMetadata::default(),
        };

    let retry = strip_encrypted_reasoning_for_retry(&request)
        .expect("retry request")
        .expect("changed request");
    let body: Value = serde_json::from_slice(&retry.payload).expect("retry JSON");

    assert_eq!(body["input"].as_array().expect("input").len(), 2);
    assert_eq!(body["input"][0]["summary"][0]["text"], "keep");
    assert!(body["input"][0].get("encrypted_content").is_none());
    assert!(body["input"][0].get("content").is_none());
    assert_eq!(body["input"][1]["type"], "message");
}

#[test]
fn promotes_additional_tools_and_prunes_orphaned_choices() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                "tools":[
                    {"type":"function","name":"lookup","parameters":null},
                    {"type":"tool_search"},
                    {"type":"namespace","name":"codex_app","tools":[
                        {"type":"function","name":"inner"}
                    ]}
                ],
                "tool_choice":{"type":"allowed_tools","mode":"required","tools":[
                    {"type":"function","name":"lookup"},
                    {"type":"tool_search"},
                    {"type":"function","namespace":"codex_app","name":"inner"}
                ]},
                "input":[
                    {"type":"additional_tools","role":"developer","tools":[
                        {"type":"function","name":"extra"}
                    ]},
                    {"type":"message","role":"user","content":"hello"}
                ]
            }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["tools"].as_array().expect("tools").len(), 4);
    assert_eq!(body["tools"][0]["parameters"]["type"], "object");
    assert_eq!(body["tools"][1]["name"], "tool_search");
    assert_eq!(body["tools"][2]["name"], "codex_app__inner");
    assert_eq!(body["tools"][3]["name"], "extra");
    assert_eq!(body["tools"][3]["parameters"]["type"], "object");
    assert_eq!(body["input"].as_array().expect("input").len(), 1);
    assert_eq!(
        body["tool_choice"]["tools"]
            .as_array()
            .expect("choices")
            .len(),
        3
    );
    assert_eq!(body["tool_choice"]["tools"][0]["name"], "lookup");
    assert_eq!(body["tool_choice"]["tools"][1]["name"], "tool_search");
    assert_eq!(body["tool_choice"]["tools"][2]["name"], "codex_app__inner");
    assert_eq!(
        prepared
            .tool_mappings
            .namespace_tools
            .get("codex_app__inner"),
        Some(&NamespaceToolRef {
            namespace: "codex_app".to_owned(),
            name: "inner".to_owned(),
        })
    );
}

#[test]
fn rejects_unpaired_tool_outputs_before_upstream() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(
                br#"{"input":[{"type":"function_call_output","call_id":"call_missing","output":"done"}]}"#,
            ),
            metadata: RequestMetadata::default(),
        };

    let error = prepare_request(request).expect_err("unpaired output");

    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(error.message().contains("matching tool call context"));
}

#[test]
fn rejects_namespace_tool_name_collisions() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                "tools":[
                    {"type":"function","name":"codex_app__inner"},
                    {"type":"namespace","name":"codex_app","tools":[
                        {"type":"function","name":"inner"}
                    ]}
                ],
                "input":"hello"
            }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let error = prepare_request(request).expect_err("namespace collision");

    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(error.message().contains("unique"));
}

#[test]
fn normalizes_namespaced_custom_tool_history_with_reversible_mappings() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(
                br#"{
                    "tools":[{"type":"namespace","name":"terminal","tools":[
                        {"type":"custom","name":"exec","format":{"type":"text"}}
                    ]}],
                    "input":[
                        {"type":"custom_tool_call","namespace":"terminal","name":"exec","call_id":"call_1","input":"pwd"},
                        {"type":"custom_tool_call_output","call_id":"call_1","output":"done"}
                    ]
                }"#,
            ),
            metadata: RequestMetadata::default(),
        };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["tools"][0]["type"], "function");
    assert_eq!(body["tools"][0]["name"], "terminal__exec");
    assert_eq!(body["input"][0]["type"], "function_call");
    assert_eq!(body["input"][0]["name"], "terminal__exec");
    assert!(body["input"][0].get("namespace").is_none());
    assert_eq!(body["input"][0]["arguments"], r#"{"input":"pwd"}"#);
    assert!(
        prepared
            .tool_mappings
            .custom_tools
            .contains("terminal__exec")
    );
    assert_eq!(
        prepared.tool_mappings.namespace_tools.get("terminal__exec"),
        Some(&NamespaceToolRef {
            namespace: "terminal".to_owned(),
            name: "exec".to_owned(),
        })
    );
}

#[test]
fn normalizes_tool_search_declaration_choice_and_history() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(
                br#"{
                    "tools":[{"type":"tool_search"}],
                    "tool_choice":{"type":"tool_search"},
                    "input":[
                        {"type":"tool_search_call","call_id":"search_1","arguments":{"query":"git"},"execution":"client"},
                        {
                            "type":"tool_search_output",
                            "call_id":"search_1",
                            "status":"completed",
                            "execution":"client",
                            "tools":[{"type":"function","name":"git_status"}]
                        }
                    ]
                }"#,
            ),
            metadata: RequestMetadata::default(),
        };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    assert_eq!(body["tools"][0]["type"], "function");
    assert_eq!(body["tools"][0]["name"], "tool_search");
    assert_eq!(body["tool_choice"]["type"], "function");
    assert_eq!(body["tool_choice"]["name"], "tool_search");
    assert_eq!(body["input"][0]["type"], "function_call");
    assert_eq!(body["input"][0]["name"], "tool_search");
    assert_eq!(body["input"][0]["arguments"], r#"{"query":"git"}"#);
    assert_eq!(body["input"][1]["type"], "function_call_output");
    assert_eq!(
        body["input"][1]["output"],
        r#"[{"name":"git_status","type":"function"}]"#
    );
    assert!(prepared.tool_mappings.tool_search);
}

#[test]
fn rejects_server_tool_search_history_without_call_id() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(
                br#"{
                    "input":[
                        {"type":"tool_search_call","call_id":null,"execution":"server","arguments":{"query":"git"}},
                        {"type":"tool_search_output","call_id":null,"execution":"server","tools":[]}
                    ]
                }"#,
            ),
            metadata: RequestMetadata::default(),
        };

    let error = prepare_request(request).expect_err("server tool search without call id");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(error.message().contains("tool_search_call"));
    assert!(error.message().contains("without a call_id"));
}

#[test]
fn preserves_namespaced_apply_patch_with_response_mappings() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                "tools":[
                    {"type":"namespace","name":"codex_app","tools":[
                        {"type":"custom","name":"apply_patch"}
                    ]}
                ],
                "input":"hello"
            }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("prepared request");

    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    assert_eq!(body["tools"][0]["name"], "codex_app__apply_patch");
    assert!(
        prepared
            .tool_mappings
            .custom_tools
            .contains("codex_app__apply_patch")
    );
    assert_eq!(
        prepared
            .tool_mappings
            .namespace_tools
            .get("codex_app__apply_patch"),
        Some(&NamespaceToolRef {
            namespace: "codex_app".to_owned(),
            name: "apply_patch".to_owned(),
        })
    );
}

#[test]
fn rewrites_forced_tool_search_to_its_function_proxy() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                "tools":[
                    {"type":"function","name":"lookup"},
                    {"type":"tool_search"}
                ],
                "tool_choice":{"type":"tool_search"},
                "input":"hello"
            }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    assert_eq!(body["tool_choice"]["type"], "function");
    assert_eq!(body["tool_choice"]["name"], "tool_search");
    assert!(prepared.tool_mappings.tool_search);
}

#[test]
fn accepts_high_entropy_32_byte_grok_content_without_broad_prefix_rejection() {
    let mut decoded = (0_u8..32).collect::<Vec<_>>();
    decoded[0] = 0x12;
    let encrypted_content = STANDARD_NO_PAD.encode(decoded);
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: serde_json::to_vec(&serde_json::json!({
            "input": [{
                "type": "reasoning",
                "summary": [{"type":"summary_text","text":"keep"}],
                "encrypted_content": encrypted_content
            }]
        }))
        .expect("request JSON")
        .into(),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["input"][0]["encrypted_content"], encrypted_content);
}

#[test]
fn removes_low_entropy_content_but_preserves_reasoning_summary() {
    let encrypted_content = STANDARD_NO_PAD.encode([0xa5; 64]);
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: serde_json::to_vec(&serde_json::json!({
            "input": [{
                "type": "reasoning",
                "summary": [{"type":"summary_text","text":"keep"}],
                "encrypted_content": encrypted_content
            }]
        }))
        .expect("request JSON")
        .into(),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["input"][0]["summary"][0]["text"], "keep");
    assert!(body["input"][0].get("encrypted_content").is_none());
}

#[test]
fn normalizes_root_union_schemas_and_automation_update_safely() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(br#"{
                "tools":[
                    {"type":"function","name":"crop","strict":true,"parameters":{
                        "type":"object","oneOf":[{"required":["radius"]},{"required":["size"]}]
                    }},
                    {"type":"function","name":"nullable","strict":true,"parameters":{
                        "anyOf":[{"type":"object"},{"type":"null"}]
                    }},
                    {"type":"function","name":"codex_app__automation_update","strict":true,"parameters":{
                        "type":"object","oneOf":[{"type":"object"}],"$defs":{"large":{}}
                    }}
                ],
                "input":"hello"
            }"#),
            metadata: RequestMetadata::default(),
        };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["tools"][0]["parameters"]["oneOf"][0]["type"], "object");
    assert_eq!(body["tools"][0]["strict"], true);
    for index in [1, 2] {
        assert_eq!(body["tools"][index]["parameters"]["type"], "object");
        assert_eq!(
            body["tools"][index]["parameters"]["additionalProperties"],
            true
        );
        assert_eq!(body["tools"][index]["strict"], false);
        assert!(body["tools"][index]["parameters"].get("anyOf").is_none());
        assert!(body["tools"][index]["parameters"].get("oneOf").is_none());
    }
}

#[test]
fn rewrites_forced_web_search_as_required_allowed_tools() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(
                br#"{"tools":[{"type":"web_search"}],"tool_choice":{"type":"web_search"},"input":"hello"}"#,
            ),
            metadata: RequestMetadata::default(),
        };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["tool_choice"]["type"], "allowed_tools");
    assert_eq!(body["tool_choice"]["mode"], "required");
    assert_eq!(body["tool_choice"]["tools"][0]["type"], "web_search");
}

#[test]
fn cleans_model_specific_sampling_and_reasoning_fields() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "xai/grok-4.20-0309-non-reasoning".to_owned(),
        payload: Bytes::from_static(
            br#"{
                "input":"hello",
                "stop":["done"],
                "presence_penalty":0.1,
                "logprobs":true,
                "top_logprobs":5,
                "reasoning":{"effort":"high","summary":"auto"},
                "reasoningEffort":"max"
            }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");

    assert_eq!(body["stop"][0], "done");
    assert_eq!(body["presence_penalty"], 0.1);
    assert!(body.get("logprobs").is_none());
    assert!(body.get("top_logprobs").is_none());
    assert_eq!(body["reasoning"]["summary"], "auto");
    assert!(body["reasoning"].get("effort").is_none());
    assert!(body.get("reasoning_effort").is_none());
    assert!(body.get("reasoningEffort").is_none());
}

#[test]
fn rejects_item_reference_instead_of_silently_dropping_context() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[
                        {"type":"item_reference","id":"msg_1"},
                        {"type":"message","role":"user","content":"continue"}
                    ]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let error = prepare_request(request).expect_err("item_reference must be rejected");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(error.message().contains("item_reference"));
    assert!(error.message().contains("complete input history"));
}

#[test]
fn rejects_tool_output_that_only_has_item_reference_context() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[
                        {"type":"item_reference","id":"call_1"},
                        {"type":"function_call_output","call_id":"call_1","output":"done"}
                    ]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let error = prepare_request(request).expect_err("reference-only tool continuation");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(error.message().contains("item_reference"));
}

#[test]
fn strips_compaction_trigger_control_items() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[
                        {"type":"message","role":"user","content":"hello"},
                        {"type":"compaction_trigger"}
                    ]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    assert_eq!(body["input"].as_array().expect("input").len(), 1);
    assert_eq!(body["input"][0]["type"], "message");
}

#[test]
fn converts_local_shell_history_to_function_items() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(
                br#"{
                    "input":[
                        {"type":"local_shell_call","call_id":"shell_1","status":"completed","action":{"type":"exec","command":["ls"]}},
                        {"type":"local_shell_call_output","call_id":"shell_1","output":"ok"},
                        {"type":"message","role":"user","content":"continue"}
                    ]
                }"#,
            ),
            metadata: RequestMetadata::default(),
        };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    assert_eq!(body["input"][0]["type"], "function_call");
    assert_eq!(body["input"][0]["name"], "local_shell");
    let shell_args: Value = serde_json::from_str(
        body["input"][0]["arguments"]
            .as_str()
            .expect("local_shell arguments"),
    )
    .expect("local_shell arguments json");
    assert_eq!(shell_args["type"], "exec");
    assert_eq!(shell_args["command"], serde_json::json!(["ls"]));
    assert_eq!(body["input"][1]["type"], "function_call_output");
    assert_eq!(body["input"][1]["output"], "ok");
    assert_eq!(body["input"][2]["type"], "message");
}

#[test]
fn converts_web_search_call_history_into_function_call() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[
                        {
                            "type":"web_search_call",
                            "id":"ws_1",
                            "status":"completed",
                            "action":{"type":"search","query":"weather tokyo"}
                        },
                        {"type":"message","role":"user","content":"hi"}
                    ]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let prepared = prepare_request(request).expect("web_search_call history");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    assert_eq!(body["input"][0]["type"], "function_call");
    assert_eq!(body["input"][0]["name"], "web_search");
    assert_eq!(body["input"][0]["call_id"], "ws_1");
    let args: Value = serde_json::from_str(
        body["input"][0]["arguments"]
            .as_str()
            .expect("web_search arguments"),
    )
    .expect("web_search arguments json");
    assert_eq!(args["type"], "search");
    assert_eq!(args["query"], "weather tokyo");
    assert_eq!(body["input"][1]["type"], "message");
}

#[test]
fn rejects_hosted_tool_history_with_embedded_results() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(
                br#"{
                    "input":[
                        {"type":"file_search_call","id":"fs_1","status":"completed","queries":["docs"],"results":[{"file_id":"f1"}]}
                    ]
                }"#,
            ),
            metadata: RequestMetadata::default(),
        };

    let error = prepare_request(request).expect_err("embedded hosted-tool results");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(error.message().contains("results"));
    assert!(error.message().contains("file_search_call"));
}

#[test]
fn converts_apply_patch_and_program_history_without_leaking_fields() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(
                br#"{
                    "input":[
                        {
                            "type":"apply_patch_call",
                            "id":"ap_1",
                            "call_id":"patch_1",
                            "status":"completed",
                            "caller":{"type":"direct"},
                            "operation":{"type":"update_file","path":"a.txt","diff":"@@"}
                        },
                        {"type":"apply_patch_call_output","call_id":"patch_1","status":"completed","output":"Done"},
                        {"type":"program","id":"prog_1","call_id":"program_1","code":"return 1","fingerprint":"fp"},
                        {"type":"program_output","id":"out_1","call_id":"program_1","status":"completed","result":"1"}
                    ]
                }"#,
            ),
            metadata: RequestMetadata::default(),
        };

    let prepared = prepare_request(request).expect("apply patch and program history");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    let input = body["input"].as_array().expect("input");
    assert_eq!(input[0]["type"], "function_call");
    assert_eq!(input[0]["name"], "apply_patch");
    assert_eq!(input[0]["call_id"], "patch_1");
    assert!(input[0].get("id").is_none());
    assert!(input[0].get("status").is_none());
    assert!(input[0].get("caller").is_none());
    assert_eq!(input[1]["type"], "function_call_output");
    assert_eq!(input[2]["type"], "function_call");
    assert_eq!(input[2]["name"], "program");
    assert_eq!(input[3]["type"], "function_call_output");
}

#[test]
fn rejects_official_history_types_that_cannot_be_replayed_safely() {
    for item_type in [
        "mcp_call",
        "mcp_list_tools",
        "mcp_approval_request",
        "mcp_approval_response",
        "context_compaction",
    ] {
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from(
                serde_json::json!({ "input": [{ "type": item_type }] }).to_string(),
            ),
            metadata: RequestMetadata::default(),
        };

        let error = prepare_request(request).expect_err("unsupported replay item");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
        assert!(error.message().contains(item_type));
        assert!(error.message().contains("cannot safely replay"));
    }
}

#[test]
fn validates_tool_pairing_after_lossy_normalization() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[
                        {"type":"custom_tool_call","call_id":"call_1","input":"pwd"},
                        {"type":"custom_tool_call_output","call_id":"call_1","output":"done"}
                    ]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let error = prepare_request(request).expect_err("orphaned normalized output");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(error.message().contains("matching tool call context"));
}

#[test]
fn rejects_unknown_input_item_types_after_normalization() {
    let request = ProviderRequest {
        format: WireFormat::OpenAiResponses,
        model: "grok-4.5".to_owned(),
        payload: Bytes::from_static(
            br#"{
                    "input":[
                        {"type":"audio_call","id":"aud_1","status":"completed"},
                        {"type":"message","role":"user","content":"hi"}
                    ]
                }"#,
        ),
        metadata: RequestMetadata::default(),
    };

    let error = prepare_request(request).expect_err("unknown item type");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert!(error.message().contains("audio_call"));
}

#[test]
fn converts_tool_search_history_without_tool_search_declaration() {
    let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "grok-4.5".to_owned(),
            payload: Bytes::from_static(
                br#"{
                    "input":[
                        {"type":"tool_search_call","call_id":"search_1","arguments":{"query":"git"},"execution":"client"},
                        {
                            "type":"tool_search_output",
                            "call_id":"search_1",
                            "status":"completed",
                            "execution":"client",
                            "tools":[{"type":"function","name":"git_status"}]
                        },
                        {"type":"message","role":"user","content":"hi"}
                    ]
                }"#,
            ),
            metadata: RequestMetadata::default(),
        };

    let prepared = prepare_request(request).expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.payload).expect("normalized JSON");
    assert_eq!(body["input"][0]["type"], "function_call");
    assert_eq!(body["input"][0]["name"], "tool_search");
    assert_eq!(body["input"][0]["arguments"], r#"{"query":"git"}"#);
    assert_eq!(body["input"][1]["type"], "function_call_output");
    assert_eq!(
        body["input"][1]["output"],
        r#"[{"name":"git_status","type":"function"}]"#
    );
    assert_eq!(body["input"][2]["type"], "message");
    assert!(!prepared.tool_mappings.tool_search);
}
