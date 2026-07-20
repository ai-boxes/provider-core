use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::Response,
    routing::post,
};
use futures_util::stream;
use provider_auth::{ApiKeyAuthenticator, AuthService};
use provider_core::ProxyService;
use provider_drivers::grok::GrokDriver;
use provider_protocol::DefaultProtocolBridge;
use provider_runtime::ProviderRuntime;
use provider_storage::SqliteAccountRepository;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

type CapturedBodies = Arc<Mutex<Vec<Value>>>;

async fn grok_responses(
    State(captured): State<CapturedBodies>,
    request: Request,
) -> Response<Body> {
    let body = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream request body");
    captured
        .lock()
        .expect("captured bodies lock")
        .push(serde_json::from_slice(&body).expect("upstream request JSON"));

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
    let captured = CapturedBodies::default();
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
    let api_keys = ApiKeyAuthenticator::load(repository)
        .await
        .expect("API key index");
    let created_key = api_keys
        .create(
            &grant.user.id,
            "test".to_owned(),
            Some(SecretString::from("test-api-key-123".to_owned())),
            None,
            unix_timestamp(),
        )
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
                "model": "grok-4.5",
                "max_tokens": 128,
                "messages": [{ "role": "user", "content": "hello" }]
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

    let captured = captured.lock().expect("captured bodies lock");
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0]["model"], "grok-4.5");
    assert_eq!(captured[0]["stream"], true);
    assert_eq!(captured[1]["input"][0]["role"], "user");

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
