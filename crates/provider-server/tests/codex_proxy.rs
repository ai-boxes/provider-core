use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{Response, StatusCode},
    routing::{get, post},
};
use provider_auth::{ApiKeyAuthenticator, AuthService};
use provider_core::{ProviderKind, ProviderVisibility, ProxyService};
use provider_drivers::codex::CodexDriver;
use provider_management::ProviderManager;
use provider_protocol::DefaultProtocolBridge;
use provider_runtime::ProviderRuntimeCatalog;
use provider_storage::SqliteAccountRepository;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

#[derive(Clone, Default)]
struct CodexUpstreamState {
    response_calls: Arc<AtomicUsize>,
    refresh_calls: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

#[derive(Clone)]
struct CapturedRequest {
    authorization: String,
    body: Value,
}

async fn models() -> &'static str {
    r#"{"data":[{"id":"gpt-5.5","owned_by":"openai"}]}"#
}

async fn responses(State(state): State<CodexUpstreamState>, request: Request) -> Response<Body> {
    state.response_calls.fetch_add(1, Ordering::SeqCst);
    let authorization = request
        .headers()
        .get(reqwest::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .expect("Codex request body");
    let body: Value = serde_json::from_slice(&body).expect("Codex request JSON");
    state
        .requests
        .lock()
        .expect("Codex request capture lock")
        .push(CapturedRequest {
            authorization,
            body: body.clone(),
        });

    match body.get("input").and_then(Value::as_str) {
        Some("always-unauthorized") => Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error":{"code":"invalid_token"}}"#))
            .expect("unauthorized response"),
        Some("rate-limit") => Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("x-codex-primary-used-percent", "100")
            .body(Body::from(
                r#"{"error":{"code":"usage_limit_reached"}}"#,
            ))
            .expect("rate limit response"),
        _ => Response::builder()
            .status(StatusCode::OK)
            .header(reqwest::header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from(Bytes::from_static(
                b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-5.5\"}}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\nevent: response.content_part.done\ndata: {\"type\":\"response.content_part.done\",\"part\":{\"type\":\"output_text\"}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}}\n\n",
            )))
            .expect("stream response"),
    }
}

async fn refresh(State(state): State<CodexUpstreamState>, request: Request) -> Response<Body> {
    state.refresh_calls.fetch_add(1, Ordering::SeqCst);
    let body = to_bytes(request.into_body(), 64 * 1024)
        .await
        .expect("refresh request body");
    let body: Value = serde_json::from_slice(&body).expect("refresh request JSON");
    assert_eq!(body["refresh_token"], "old-refresh");
    Response::builder()
        .status(StatusCode::OK)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"access_token":"new-access"}"#))
        .expect("refresh response")
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
async fn proxies_responses_and_claude_with_one_unauthorized_retry() {
    let upstream_state = CodexUpstreamState::default();
    let upstream = Router::new()
        .route("/codex/models", get(models))
        .route("/codex/responses", post(responses))
        .route("/oauth/token", post(refresh))
        .with_state(upstream_state.clone());
    let (upstream_url, upstream_server) = spawn(upstream).await;

    let repository = Arc::new(
        SqliteAccountRepository::in_memory()
            .await
            .expect("repository"),
    );
    let auth = AuthService::new(repository.clone());
    let now = unix_timestamp();
    let grant = auth
        .setup(
            "admin".to_owned(),
            SecretString::from("secret".to_owned()),
            now,
        )
        .await
        .expect("initial setup");
    let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
    runtime
        .register_driver(CodexDriver::for_test(&upstream_url, &upstream_url))
        .expect("register Codex driver");
    let manager = ProviderManager::new(repository.clone(), runtime.clone());
    let _created_account = manager
        .create_credential_account(
            grant.user.id.as_str(),
            ProviderKind::Codex,
            "Codex".to_owned(),
            "default".to_owned(),
            SecretString::from(
                json!({
                    "type": "codex",
                    "auth_kind": "oauth",
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                    "id_token": "e30.e30.sig",
                    "last_refreshed_at": now
                })
                .to_string(),
            ),
            ProviderVisibility::Private,
            now,
        )
        .await
        .expect("create Codex account");

    let api_keys = ApiKeyAuthenticator::load(repository)
        .await
        .expect("API key index");
    let created_key = api_keys
        .create(
            &grant.user.id,
            "default".to_owned(),
            "test".to_owned(),
            None,
            None,
            now,
        )
        .await
        .expect("create API key");
    let api_key = created_key.key.expose_secret().to_owned();
    let service = ProxyService::with_router(runtime.clone(), Arc::new(DefaultProtocolBridge));
    let (server_url, server) = spawn(provider_server::router(service, api_keys)).await;
    let client = reqwest::Client::new();

    let responses_body = client
        .post(format!("{server_url}/v1/responses"))
        .bearer_auth(&api_key)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({ "model": "gpt-5.5", "stream": false, "input": "hello" }).to_string())
        .send()
        .await
        .expect("Responses request")
        .text()
        .await
        .expect("Responses SSE");
    assert!(responses_body.contains("response.output_text.delta"));

    let claude_body = client
        .post(format!("{server_url}/v1/messages"))
        .header("x-api-key", &api_key)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "model": "gpt-5.5",
                "max_tokens": 128,
                "messages": [{ "role": "user", "content": "hello" }]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Claude request")
        .text()
        .await
        .expect("Claude SSE");
    assert!(claude_body.contains("event: message_start"));
    assert!(claude_body.contains(r#""type":"text_delta""#));
    assert!(claude_body.contains("event: message_stop"));

    let unauthorized = client
        .post(format!("{server_url}/v1/responses"))
        .bearer_auth(&api_key)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "model": "gpt-5.5",
                "input": "always-unauthorized"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("unauthorized request");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(upstream_state.response_calls.load(Ordering::SeqCst), 4);
    assert_eq!(upstream_state.refresh_calls.load(Ordering::SeqCst), 1);

    let rate_limited = client
        .post(format!("{server_url}/v1/responses"))
        .bearer_auth(&api_key)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({ "model": "gpt-5.5", "input": "rate-limit" }).to_string())
        .send()
        .await
        .expect("rate limited request");
    assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let rate_limited: Value = serde_json::from_slice(
        &rate_limited
            .bytes()
            .await
            .expect("rate limited response body"),
    )
    .expect("rate limited response JSON");
    assert_eq!(rate_limited["error"]["type"], "rate_limit_error");
    assert_eq!(upstream_state.response_calls.load(Ordering::SeqCst), 5);
    assert_eq!(upstream_state.refresh_calls.load(Ordering::SeqCst), 1);

    let requests = upstream_state
        .requests
        .lock()
        .expect("Codex request capture lock");
    assert_eq!(requests[0].body["model"], "gpt-5.5");
    assert_eq!(requests[0].body["stream"], true);
    assert_eq!(requests[0].body["store"], false);
    assert_eq!(requests[1].body["input"][0]["role"], "user");
    assert_eq!(requests[2].authorization, "Bearer old-access");
    assert_eq!(requests[3].authorization, "Bearer new-access");
    assert_eq!(requests[4].authorization, "Bearer new-access");
    drop(requests);

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
