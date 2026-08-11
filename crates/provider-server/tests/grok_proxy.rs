use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::Response,
    routing::post,
};
use futures_util::stream;
use provider_auth::{ApiKeyAuthenticator, AuthService, CreateApiKeyInput};
use provider_core::{
    AccountId, CredentialKind, NewCredential, NewProviderAccount, ProviderKind,
    ProviderManagementRepository, ProviderVisibility, ProxyService,
};
use provider_drivers::grok::GrokDriver;
use provider_protocol::DefaultProtocolBridge;
use provider_runtime::ProviderRuntime;
use provider_storage::SqliteAccountRepository;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

#[derive(Clone, Debug)]
struct CapturedRequest {
    body: Value,
    conversation_id: String,
    session_id: String,
}

type CapturedRequests = Arc<Mutex<Vec<CapturedRequest>>>;

async fn grok_responses(
    State(captured): State<CapturedRequests>,
    request: Request,
) -> Response<Body> {
    let conversation_id = request
        .headers()
        .get("x-grok-conv-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let session_id = request
        .headers()
        .get("x-grok-session-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream request body");
    captured
        .lock()
        .expect("captured requests lock")
        .push(CapturedRequest {
            body: serde_json::from_slice(&body).expect("upstream request JSON"),
            conversation_id,
            session_id,
        });

    let chunks = stream::iter([Ok::<_, std::convert::Infallible>(Bytes::from_static(
        b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"grok-4.5\"}}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\nevent: response.content_part.done\ndata: {\"type\":\"response.content_part.done\",\"part\":{\"type\":\"output_text\"}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}}\n\n",
    ))]);

    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(chunks))
        .expect("mock Grok response")
}

async fn spawn(router: Router) -> (String, JoinHandle<std::io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let address = listener.local_addr().expect("test server address");
    let handle = tokio::spawn(axum::serve(listener, router).into_future());
    (format!("http://{address}"), handle)
}

#[tokio::test]
async fn proxies_codex_and_claude_through_mock_grok() {
    let captured = CapturedRequests::default();
    let upstream = Router::new()
        .route("/v1/responses", post(grok_responses))
        .with_state(captured.clone());
    let (upstream_url, upstream_server) = spawn(upstream).await;

    let driver = GrokDriver::for_test(format!("{upstream_url}/v1"));
    let runtime = ProviderRuntime::new(driver.clone());
    runtime
        .register(driver.test_account("mock-token"))
        .await
        .expect("register Grok account");
    let repository = Arc::new(
        SqliteAccountRepository::in_memory()
            .await
            .expect("repository"),
    );
    let auth = AuthService::new(repository.clone());
    let grant = auth
        .setup(
            "admin".to_owned(),
            SecretString::from("secret".to_owned()),
            unix_timestamp(),
        )
        .await
        .expect("initial setup");
    let now = unix_timestamp();
    repository
        .create_provider_account(
            NewProviderAccount {
                id: AccountId::new("acct-grok-1").expect("account ID"),
                provider: ProviderKind::Grok,
                label: "seed".to_owned(),
                group_label: "default".to_owned(),
                config_json: "{}".to_owned(),
                enabled: true,
                credential: NewCredential {
                    kind: CredentialKind::ApiKey,
                    format_version: 1,
                    credential_json: SecretString::from("seed-secret".to_owned()),
                    expires_at: None,
                    last_refreshed_at: None,
                },
            },
            grant.user.id.as_str(),
            ProviderVisibility::Private,
        )
        .await
        .expect("seed provider account");
    let api_keys = ApiKeyAuthenticator::load(repository)
        .await
        .expect("API key index");
    let created_key = api_keys
        .create(CreateApiKeyInput {
            owner_user_id: &grant.user.id,
            secret: SecretString::from("test-api-key"),
            group_label: "default".to_owned(),
            label: "test".to_owned(),
            expires_at: None,
            quota_limit_usd: None,
            now,
        })
        .await
        .expect("create API key");
    let api_key = created_key.key.expose_secret().to_owned();
    let service = ProxyService::new(
        Arc::new(runtime.clone()),
        Arc::new(DefaultProtocolBridge),
        provider_core::ProviderAccountAccess {
            owner_user_id: Some(grant.user.id.as_str().to_owned()),
            visibility: provider_core::ProviderVisibility::Private,
        },
    );
    let (server_url, server) = spawn(provider_server::router(service, api_keys)).await;
    let client = reqwest::Client::new();

    let codex = client
        .post(format!("{server_url}/v1/responses"))
        .bearer_auth(&api_key)
        .header("content-type", "application/json")
        .body(json!({ "model": "grok-4.5", "stream": false, "input": "hello" }).to_string())
        .send()
        .await
        .expect("Codex response")
        .text()
        .await
        .expect("Codex SSE");
    assert!(codex.contains("response.output_text.delta"));

    let claude = client
        .post(format!("{server_url}/v1/messages"))
        .header("x-api-key", &api_key)
        .header("content-type", "application/json")
        .body(
            json!({
                "model": "claude-fable-5-dd-gninosaer-non-9030-02.4-korg",
                "max_tokens": 128,
                "metadata": {
                    "user_id": "{\"device_id\":\"device-a\",\"session_id\":\"private-session-value\"}"
                },
                "messages": [
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "thinking",
                                "thinking": "visible thinking must not replay",
                                "signature": "Eclaude-signature"
                            },
                            { "type": "text", "text": "previous answer" }
                        ]
                    },
                    { "role": "user", "content": "hello" }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Claude response")
        .text()
        .await
        .expect("Claude SSE");
    assert!(claude.contains("event: message_start"));
    assert!(claude.contains(r#""type":"text_delta""#));
    assert!(claude.contains("event: message_stop"));

    let claude_second = client
        .post(format!("{server_url}/v1/messages"))
        .header("x-api-key", &api_key)
        .header("content-type", "application/json")
        .body(
            json!({
                "model": "claude-fable-5-dd-gninosaer-non-9030-02.4-korg",
                "max_tokens": 128,
                "metadata": {
                    "user_id": "{\"device_id\":\"device-b\",\"session_id\":\"private-session-value\"}"
                },
                "messages": [{ "role": "user", "content": "next" }]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("second Claude response")
        .text()
        .await
        .expect("second Claude SSE");
    assert!(claude_second.contains("event: message_stop"));

    let different_session = client
        .post(format!("{server_url}/v1/messages"))
        .header("x-api-key", &api_key)
        .header("content-type", "application/json")
        .body(
            json!({
                "model": "claude-fable-5-dd-gninosaer-non-9030-02.4-korg",
                "max_tokens": 128,
                "metadata": {
                    "user_id": "{\"session_id\":\"different-private-session\"}"
                },
                "messages": [{ "role": "user", "content": "other" }]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("different-session Claude response")
        .text()
        .await
        .expect("different-session Claude SSE");
    assert!(different_session.contains("event: message_stop"));

    let captured = captured.lock().expect("captured requests lock");
    assert_eq!(captured.len(), 4);
    assert_eq!(captured[0].body["model"], "grok-4.5");
    assert_eq!(captured[0].body["stream"], true);
    assert_eq!(captured[1].body["model"], "grok-4.20-0309-non-reasoning");
    assert_eq!(captured[1].body["input"][0]["role"], "assistant");
    assert_eq!(
        captured[1].body["input"][0]["content"][0]["text"],
        "previous answer"
    );
    assert!(
        !captured[1]
            .body
            .to_string()
            .contains("visible thinking must not replay")
    );
    assert!(!captured[1].body.to_string().contains("Eclaude-signature"));
    let cache_key = captured[1].body["prompt_cache_key"]
        .as_str()
        .expect("Claude prompt cache key");
    assert!(cache_key.starts_with("cc_"));
    assert!(!cache_key.contains("private-session-value"));
    assert_eq!(captured[1].conversation_id, cache_key);
    assert_eq!(captured[1].session_id, cache_key);
    assert_eq!(captured[2].body["prompt_cache_key"], cache_key);
    assert_eq!(captured[2].conversation_id, cache_key);
    assert_eq!(captured[2].session_id, cache_key);
    let different_cache_key = captured[3].body["prompt_cache_key"]
        .as_str()
        .expect("different prompt cache key");
    assert_ne!(different_cache_key, cache_key);
    assert_eq!(captured[3].conversation_id, different_cache_key);
    assert_eq!(captured[3].session_id, different_cache_key);

    runtime.shutdown();
    server.abort();
    upstream_server.abort();
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}
