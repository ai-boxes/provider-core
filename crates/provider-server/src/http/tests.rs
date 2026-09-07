use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::to_bytes;
use futures_util::stream;
use provider_auth::{ApiKeyId, AuthService, UserId};
use provider_core::{
    AccountId, CredentialKind, NewCredential, NewProviderAccount, Provider, ProviderKind,
    ProviderManagementRepository, ProviderModel, ProviderRequest, ProviderStream,
    ProviderVisibility, RequestMetadata,
};
use provider_protocol::DefaultProtocolBridge;
use provider_storage::SqliteAccountRepository;
use secrecy::{ExposeSecret, SecretString};
use tokio::net::TcpListener;
use tower::ServiceExt;

use super::*;

struct TestPublicDir(PathBuf);

impl TestPublicDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("provider-core-ui-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).expect("create UI test directory");
        fs::write(path.join("index.html"), "<main>provider ui</main>").expect("write UI index");
        fs::write(path.join("app.js"), "console.log('provider ui')").expect("write UI asset");
        fs::create_dir(path.join("assets")).expect("create UI assets directory");
        fs::write(path.join("assets/app-HASH.js"), "console.log('hashed')")
            .expect("write hashed UI asset");
        Self(path)
    }
}

impl Drop for TestPublicDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn response_text(response: Response) -> String {
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read response body");
    String::from_utf8(body.to_vec()).expect("response UTF-8")
}

#[tokio::test]
async fn serves_ui_assets_and_browser_routes() {
    let public = TestPublicDir::new();
    let service = ui_service(&public.0);

    let asset = service
        .clone()
        .oneshot(
            Request::builder()
                .uri("/app.js")
                .body(Body::empty())
                .expect("asset request"),
        )
        .await
        .expect("infallible asset response");
    assert_eq!(asset.status(), StatusCode::OK);
    assert_eq!(asset.headers()[header::CACHE_CONTROL], "no-cache");
    assert_eq!(response_text(asset).await, "console.log('provider ui')");

    let hashed_asset = service
        .clone()
        .oneshot(
            Request::builder()
                .uri("/assets/app-HASH.js")
                .body(Body::empty())
                .expect("hashed asset request"),
        )
        .await
        .expect("infallible hashed asset response");
    assert_eq!(hashed_asset.status(), StatusCode::OK);
    assert_eq!(
        hashed_asset.headers()[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );

    let browser_route = service
        .oneshot(
            Request::builder()
                .uri("/providers/account-1")
                .header(header::ACCEPT, "text/html,application/xhtml+xml")
                .body(Body::empty())
                .expect("browser route request"),
        )
        .await
        .expect("infallible browser route response");
    assert_eq!(browser_route.status(), StatusCode::OK);
    assert_eq!(browser_route.headers()[header::CACHE_CONTROL], "no-cache");
    assert_eq!(
        response_text(browser_route).await,
        "<main>provider ui</main>"
    );
}

#[tokio::test]
async fn keeps_backend_and_non_browser_misses_as_not_found() {
    let public = TestPublicDir::new();
    let service = ui_service(&public.0);

    for uri in ["/api/v1/missing", "/v1/missing", "/readyz/missing"] {
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::ACCEPT, "text/html")
                    .body(Body::empty())
                    .expect("backend request"),
            )
            .await
            .expect("infallible backend response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }

    let response = service
        .oneshot(
            Request::builder()
                .uri("/missing.json")
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .expect("non-browser request"),
        )
        .await
        .expect("infallible non-browser response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn missing_ui_directory_stays_not_found() {
    let missing =
        std::env::temp_dir().join(format!("provider-core-missing-ui-{}", uuid::Uuid::new_v4()));
    let response = ui_service(missing)
        .oneshot(
            Request::builder()
                .uri("/providers")
                .header(header::ACCEPT, "text/html; charset=utf-8")
                .body(Body::empty())
                .expect("browser request"),
        )
        .await
        .expect("infallible missing UI response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

async fn seed_group_label(
    repository: Arc<SqliteAccountRepository>,
    owner: &UserId,
    account_id: &str,
    group_label: &str,
) {
    repository
        .create_provider_account(
            NewProviderAccount {
                id: AccountId::new(account_id).expect("account ID"),
                provider: ProviderKind::OpenAiCompatible,
                label: "seed".to_owned(),
                group_label: group_label.to_owned(),
                priority: 0,
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
            owner.as_str(),
            ProviderVisibility::Private,
        )
        .await
        .expect("seed provider account");
}

async fn response_json(response: reqwest::Response) -> Value {
    let body = response.bytes().await.expect("response body");
    serde_json::from_slice(&body).expect("response JSON")
}

fn padded_json(prefix: &str, suffix: &str, size: usize) -> String {
    let padding = size
        .checked_sub(prefix.len() + suffix.len())
        .expect("requested JSON size");
    let mut body = String::with_capacity(size);
    body.push_str(prefix);
    body.extend(std::iter::repeat_n('a', padding));
    body.push_str(suffix);
    assert_eq!(body.len(), size);
    body
}

#[test]
fn streaming_endpoints_require_explicit_true() {
    for protocol in [
        WireFormat::OpenAiResponses,
        WireFormat::OpenAiChatCompletions,
        WireFormat::ClaudeMessages,
    ] {
        for payload in [
            json!({ "model": "test" }),
            json!({ "model": "test", "stream": false }),
            json!({ "model": "test", "stream": "true" }),
        ] {
            let error = match require_stream_true(protocol, &payload) {
                Ok(()) => panic!("invalid stream declaration was accepted"),
                Err(error) => error,
            };
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
    assert!(require_stream_true(WireFormat::OpenAiResponses, &json!([])).is_err());
    assert!(
        require_stream_true(
            WireFormat::OpenAiChatCompletions,
            &json!({ "model": "test", "stream": true })
        )
        .is_ok()
    );
}

#[test]
fn provider_errors_preserve_safe_retry_timing_and_forbidden_status() {
    let limited = ProviderError::new(ProviderErrorKind::RateLimited, "limited")
        .with_retry_after(std::time::Duration::from_secs(45));
    let response = HttpError::from_provider(WireFormat::OpenAiResponses, limited).into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("45")
    );

    let forbidden = ProviderError::new(ProviderErrorKind::Authentication, "forbidden")
        .with_upstream_status(403);
    let response = HttpError::from_provider(WireFormat::OpenAiResponses, forbidden).into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

struct TestProvider {
    models: Vec<ProviderModel>,
    metadata: Arc<Mutex<Vec<RequestMetadata>>>,
    native_format: WireFormat,
}

#[async_trait]
impl Provider for TestProvider {
    fn name(&self) -> &'static str {
        "test"
    }

    fn native_format(&self) -> WireFormat {
        self.native_format
    }

    fn models(&self) -> &[ProviderModel] {
        &self.models
    }

    async fn execute_stream(
        &self,
        request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError> {
        self.metadata
            .lock()
            .expect("metadata capture lock")
            .push(request.metadata);
        let event = Bytes::from_static(
            b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{}}\n\n",
        );
        Ok(Box::pin(stream::once(async move { Ok(event) })))
    }

    async fn count_tokens(&self, _request: ProviderRequest) -> Result<u64, ProviderError> {
        Ok(42)
    }
}

#[tokio::test]
async fn streaming_routes_reject_non_true_stream_before_provider_execution() {
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
    seed_group_label(
        repository.clone(),
        &grant.user.id,
        "acct-stream-1",
        "default",
    )
    .await;
    let api_keys = ApiKeyAuthenticator::load(repository)
        .await
        .expect("API key index");
    let created_key = api_keys
        .create(CreateApiKeyInput {
            owner_user_id: &grant.user.id,
            secret: SecretString::from("stream-test-api-key"),
            group_labels: vec!["default".to_owned()],
            label: "stream-test".to_owned(),
            expires_at: None,
            quota_limit_usd: None,
            now: unix_timestamp(),
        })
        .await
        .expect("create API key");
    let api_key = created_key.key.expose_secret().to_owned();
    let executions = Arc::new(Mutex::new(Vec::new()));
    let service = ProxyService::new(
        Arc::new(TestProvider {
            models: vec![ProviderModel::new("test-model", "test")],
            metadata: executions.clone(),
            native_format: WireFormat::OpenAiResponses,
        }),
        Arc::new(DefaultProtocolBridge),
        provider_core::ProviderAccountAccess {
            owner_user_id: Some(grant.user.id.as_str().to_owned()),
            visibility: provider_core::ProviderVisibility::Private,
        },
    );
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let address = listener.local_addr().expect("test server address");
    let server = tokio::spawn(axum::serve(listener, router(service, api_keys)).into_future());
    let client = reqwest::Client::new();
    let base_url = format!("http://{address}");

    for (path, anthropic) in [
        ("/v1/responses", false),
        ("/v1/chat/completions", false),
        ("/v1/messages", true),
    ] {
        for stream in [
            None,
            Some(Value::Bool(false)),
            Some(Value::String("true".to_owned())),
        ] {
            let mut payload = json!({ "model": "test-model", "input": "hello", "messages": [] });
            if let Some(stream) = stream {
                payload["stream"] = stream;
            }
            let request = client
                .post(format!("{base_url}{path}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(payload.to_string());
            let response = if anthropic {
                request.header("x-api-key", &api_key)
            } else {
                request.bearer_auth(&api_key)
            }
            .send()
            .await
            .expect("invalid stream response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        }
    }
    assert!(
        executions
            .lock()
            .expect("execution capture lock")
            .is_empty()
    );
    server.abort();
}

#[tokio::test]
async fn requires_api_keys_and_supports_openai_and_anthropic_headers() {
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
    seed_group_label(repository.clone(), &grant.user.id, "acct-http-1", "default").await;
    let api_keys = ApiKeyAuthenticator::load(repository)
        .await
        .expect("API key index");
    let created_key = api_keys
        .create(CreateApiKeyInput {
            owner_user_id: &grant.user.id,
            secret: SecretString::from("test-api-key"),
            group_labels: vec!["default".to_owned()],
            label: "test".to_owned(),
            expires_at: None,
            quota_limit_usd: None,
            now,
        })
        .await
        .expect("create API key");
    let api_key = created_key.key.expose_secret().to_owned();
    let captured_metadata = Arc::new(Mutex::new(Vec::new()));
    let service = ProxyService::new(
        Arc::new(TestProvider {
            models: vec![
                ProviderModel::new("grok-4.5", "xai").with_input_modalities(Some(vec![
                    provider_core::ProviderModelInputModality::Text,
                    provider_core::ProviderModelInputModality::Image,
                ])),
            ],
            metadata: captured_metadata.clone(),
            native_format: WireFormat::OpenAiResponses,
        }),
        Arc::new(DefaultProtocolBridge),
        provider_core::ProviderAccountAccess {
            owner_user_id: Some(grant.user.id.as_str().to_owned()),
            visibility: provider_core::ProviderVisibility::Private,
        },
    );
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let address = listener.local_addr().expect("test server address");
    let server =
        tokio::spawn(axum::serve(listener, router(service, api_keys.clone())).into_future());
    let client = reqwest::Client::new();
    let base_url = format!("http://{address}");

    let claude_service = ProxyService::new(
        Arc::new(TestProvider {
            models: vec![ProviderModel::new("grok-4.5", "xai")],
            metadata: captured_metadata.clone(),
            native_format: WireFormat::ClaudeMessages,
        }),
        Arc::new(DefaultProtocolBridge),
        provider_core::ProviderAccountAccess {
            owner_user_id: Some(grant.user.id.as_str().to_owned()),
            visibility: provider_core::ProviderVisibility::Private,
        },
    );
    let claude_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Claude test server");
    let claude_address = claude_listener
        .local_addr()
        .expect("Claude test server address");
    let claude_server = tokio::spawn(
        axum::serve(claude_listener, router(claude_service, api_keys.clone())).into_future(),
    );
    let claude_base_url = format!("http://{claude_address}");

    let health = client
        .get(format!("{base_url}/healthz"))
        .send()
        .await
        .expect("health response");
    assert_eq!(health.status(), StatusCode::OK);

    let missing_key = client
        .get(format!("{base_url}/v1/models"))
        .send()
        .await
        .expect("missing API key response");
    assert_eq!(missing_key.status(), StatusCode::UNAUTHORIZED);

    let models = response_json(
        client
            .get(format!("{base_url}/v1/models"))
            .bearer_auth(&api_key)
            .send()
            .await
            .expect("models response"),
    )
    .await;
    assert_eq!(models["data"][0]["id"], "grok-4.5");
    assert_eq!(
        models["data"][0]["input_modalities"],
        json!(["text", "image"])
    );
    assert_eq!(models["data"][0]["supports_image_detail_original"], true);
    assert_eq!(models["object"], "list");

    let claude_models = response_json(
        client
            .get(format!("{claude_base_url}/v1/models"))
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01")
            .send()
            .await
            .expect("Claude models response"),
    )
    .await;
    assert!(claude_models.get("object").is_none());
    assert_eq!(claude_models["has_more"], false);
    assert_eq!(claude_models["data"][0]["id"], "claude-fable-5-dd-5.4-korg");
    assert_eq!(claude_models["data"][0]["type"], "model");
    assert_eq!(claude_models["data"][0]["display_name"], "grok-4.5");
    assert_eq!(claude_models["first_id"], claude_models["data"][0]["id"]);
    assert_eq!(claude_models["last_id"], claude_models["data"][0]["id"]);

    for (request_base_url, path) in [
        (base_url.as_str(), "/v1/responses"),
        (claude_base_url.as_str(), "/v1/messages"),
    ] {
        let mut request = client
            .post(format!("{request_base_url}{path}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                json!({ "model": "grok-4.5", "stream": true, "input": "hello", "messages": [] })
                    .to_string(),
            );
        request = if path == "/v1/messages" {
            request.header("x-api-key", &api_key)
        } else {
            request
                .bearer_auth(&api_key)
                .header("session-id", "session-1")
                .header("thread-id", "thread:1")
                .header("x-client-request-id", "request_1")
        };
        let response = request.send().await.expect("stream response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
    }
    let authenticated_key = AuthenticatedApiKey {
        key_id: created_key.summary.id.clone(),
        owner_user_id: grant.user.id.clone(),
        label: created_key.summary.label.clone(),
        group_labels: created_key.summary.group_labels.clone(),
        quota_limit_atoms: created_key.summary.quota_limit_atoms.clone(),
    };
    let mut expected_metadata = RequestMetadata::default();
    let expected_session = responses_cache_key(&authenticated_key, "grok-4.5", "session-1");
    expected_metadata.session_id = Some("session-1".to_owned());
    expected_metadata.thread_id = Some("thread:1".to_owned());
    expected_metadata.client_request_id = Some("request_1".to_owned());
    expected_metadata.routing_session_id = Some(expected_session);
    expected_metadata.routing_scope = Some(created_key.summary.id.to_string());
    let mut anthropic_metadata = RequestMetadata::default();
    anthropic_metadata.routing_scope = Some(created_key.summary.id.to_string());
    assert_eq!(
        captured_metadata
            .lock()
            .expect("metadata capture lock")
            .as_slice(),
        [expected_metadata, anthropic_metadata]
    );

    let invalid_metadata = client
        .post(format!("{base_url}/v1/responses"))
        .bearer_auth(&api_key)
        .header("session-id", "invalid value")
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({ "model": "grok-4.5", "stream": true, "input": "hello" }).to_string())
        .send()
        .await
        .expect("invalid metadata response");
    assert_eq!(invalid_metadata.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        captured_metadata
            .lock()
            .expect("metadata capture lock")
            .len(),
        2
    );

    let count = response_json(
        client
            .post(format!("{claude_base_url}/v1/messages/count_tokens"))
            .header("x-api-key", &api_key)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json!({ "model": "grok-4.5", "messages": [] }).to_string())
            .send()
            .await
            .expect("count response"),
    )
    .await;
    assert_eq!(count["input_tokens"], 42);

    let compressed = client
        .post(format!("{base_url}/v1/responses"))
        .bearer_auth(&api_key)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_ENCODING, "gzip")
        .body(r#"{"model":"grok-4.5","input":"hello"}"#)
        .send()
        .await
        .expect("compressed proxy request");
    assert_eq!(compressed.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let exact_body = padded_json(
        r#"{"model":"grok-4.5","stream":true,"input":""#,
        r#""}"#,
        MAX_PROXY_BODY_BYTES,
    );
    let exact_limit = client
        .post(format!("{base_url}/v1/responses"))
        .bearer_auth(&api_key)
        .header(header::CONTENT_TYPE, "application/json")
        .body(exact_body)
        .send()
        .await
        .expect("proxy request at body limit");
    assert_eq!(exact_limit.status(), StatusCode::OK);

    let oversized_body = padded_json(
        r#"{"model":"grok-4.5","input":""#,
        r#""}"#,
        MAX_PROXY_BODY_BYTES + 1,
    );
    let oversized = client
        .post(format!("{base_url}/v1/responses"))
        .bearer_auth(&api_key)
        .header(header::CONTENT_TYPE, "application/json")
        .body(oversized_body)
        .send()
        .await
        .expect("oversized proxy request");
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let chat_metadata = Arc::new(Mutex::new(Vec::new()));
    let chat_service = ProxyService::new(
        Arc::new(TestProvider {
            models: vec![ProviderModel::new("chat-model", "openai")],
            metadata: chat_metadata.clone(),
            native_format: WireFormat::OpenAiChatCompletions,
        }),
        Arc::new(DefaultProtocolBridge),
        provider_core::ProviderAccountAccess {
            owner_user_id: Some(grant.user.id.as_str().to_owned()),
            visibility: provider_core::ProviderVisibility::Private,
        },
    );
    let chat_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind chat test server");
    let chat_address = chat_listener.local_addr().expect("chat server address");
    let chat_server = tokio::spawn(
        axum::serve(chat_listener, router(chat_service, api_keys.clone())).into_future(),
    );
    let chat_base_url = format!("http://{chat_address}");

    let chat_response = client
        .post(format!("{chat_base_url}/v1/chat/completions"))
        .bearer_auth(&api_key)
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({ "model": "chat-model", "stream": true, "messages": [] }).to_string())
        .send()
        .await
        .expect("chat completions response");
    assert_eq!(chat_response.status(), StatusCode::OK);

    let isolated_response = client
        .post(format!("{chat_base_url}/v1/responses"))
        .bearer_auth(&api_key)
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({ "model": "chat-model", "stream": true, "input": "hello" }).to_string())
        .send()
        .await
        .expect("isolated responses request");
    assert_eq!(isolated_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(chat_metadata.lock().expect("chat metadata lock").len(), 1);
    chat_server.abort();
    claude_server.abort();

    api_keys
        .update(
            &grant.user.id,
            &created_key.summary.id,
            ApiKeyPatch {
                label: None,
                group_labels: None,
                enabled: Some(false),
                expires_at: None,
                quota_limit_usd: None,
                updated_at: unix_timestamp(),
            },
        )
        .await
        .expect("disable API key");
    let disabled_key = client
        .get(format!("{base_url}/v1/models"))
        .bearer_auth(&api_key)
        .send()
        .await
        .expect("disabled API key response");
    assert_eq!(disabled_key.status(), StatusCode::UNAUTHORIZED);

    server.abort();
}

#[test]
fn derives_isolated_claude_code_cache_keys() {
    let first_key = AuthenticatedApiKey {
        key_id: ApiKeyId::new("key-a").expect("API key ID"),
        owner_user_id: UserId::new("user-a").expect("user ID"),
        label: "first".to_owned(),
        group_labels: vec!["default".to_owned()],
        quota_limit_atoms: None,
    };
    let second_key = AuthenticatedApiKey {
        key_id: ApiKeyId::new("key-b").expect("API key ID"),
        owner_user_id: UserId::new("user-a").expect("user ID"),
        label: "second".to_owned(),
        group_labels: vec!["default".to_owned()],
        quota_limit_atoms: None,
    };
    let first = claude_code_cache_key(&first_key, "grok-4.5", "session-1");

    assert_eq!(
        first,
        claude_code_cache_key(&first_key, "grok-4.5", "session-1")
    );
    assert_ne!(
        first,
        claude_code_cache_key(&first_key, "grok-4.5", "session-2")
    );
    assert_ne!(
        first,
        claude_code_cache_key(&first_key, "grok-4.6", "session-1")
    );
    assert_ne!(
        first,
        claude_code_cache_key(&second_key, "grok-4.5", "session-1")
    );
    assert!(first.starts_with("cc_"));
    assert!(!first.contains("session-1"));
}

#[test]
fn extracts_routing_linkage_without_mutating_codex_transport() {
    let key = AuthenticatedApiKey {
        key_id: ApiKeyId::new("key-a").expect("API key ID"),
        owner_user_id: UserId::new("user-a").expect("user ID"),
        label: "first".to_owned(),
        group_labels: vec!["default".to_owned()],
        quota_limit_atoms: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "session-id",
        "client-session".parse().expect("session header"),
    );
    headers.insert(
        "x-codex-installation-id",
        "installation-header".parse().expect("installation header"),
    );
    headers.insert(
        "x-codex-turn-metadata",
        "not-json".parse().expect("opaque turn metadata"),
    );
    let body = Bytes::from_static(
        br#"{
        "model":"gpt-5.6-luna",
        "prompt_cache_key":"body-session",
        "previous_response_id":"",
        "client_metadata":{
            "turn_id":42,
            "x-codex-window-id":"window/with/path",
            "x-codex-turn-metadata":"not-json"
        }
    }"#,
    );
    let payload: Value = serde_json::from_slice(&body).expect("request JSON");

    let request = proxy_request_for_key_from_payload(
        WireFormat::OpenAiResponses,
        &headers,
        body.clone(),
        payload,
        &key,
    )
    .unwrap_or_else(|_| panic!("opaque Codex metadata must not be validated at ingress"));

    assert_eq!(request.payload, body);
    assert_eq!(
        request.metadata.session_id.as_deref(),
        Some("client-session")
    );
    assert_eq!(request.metadata.previous_response_id, None);
    assert_eq!(
        request.metadata.routing_session_id,
        Some(responses_cache_key(&key, "gpt-5.6-luna", "client-session"))
    );
}

#[test]
fn rejects_non_string_previous_response_id() {
    let key = AuthenticatedApiKey {
        key_id: ApiKeyId::new("key-a").expect("API key ID"),
        owner_user_id: UserId::new("user-a").expect("user ID"),
        label: "first".to_owned(),
        group_labels: vec!["default".to_owned()],
        quota_limit_atoms: None,
    };
    let body = Bytes::from_static(
        br#"{"model":"gpt-5.6-luna","previous_response_id":42,"input":"continue"}"#,
    );
    let payload: Value = serde_json::from_slice(&body).expect("request JSON");

    let result = proxy_request_for_key_from_payload(
        WireFormat::OpenAiResponses,
        &HeaderMap::new(),
        body,
        payload,
        &key,
    );

    assert!(result.is_err());
}

#[test]
fn isolates_chat_sessions_by_api_key() {
    let first_key = AuthenticatedApiKey {
        key_id: ApiKeyId::new("key-a").expect("API key ID"),
        owner_user_id: UserId::new("user-a").expect("user ID"),
        label: "first".to_owned(),
        group_labels: vec!["default".to_owned()],
        quota_limit_atoms: None,
    };
    let second_key = AuthenticatedApiKey {
        key_id: ApiKeyId::new("key-b").expect("API key ID"),
        owner_user_id: UserId::new("user-a").expect("user ID"),
        label: "second".to_owned(),
        group_labels: vec!["default".to_owned()],
        quota_limit_atoms: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "session-id",
        "shared-session".parse().expect("session header"),
    );
    headers.insert("thread-id", "raw-thread".parse().expect("thread header"));
    headers.insert(
        "x-client-request-id",
        "raw-request".parse().expect("request header"),
    );
    let body = Bytes::from_static(br#"{"model":"grok-4.5","messages":[]}"#);
    let payload: Value = serde_json::from_slice(&body).expect("request JSON");

    let first = proxy_request_for_key_from_payload(
        WireFormat::OpenAiChatCompletions,
        &headers,
        body.clone(),
        payload.clone(),
        &first_key,
    )
    .unwrap_or_else(|_| panic!("first chat request should be valid"));
    let second = proxy_request_for_key_from_payload(
        WireFormat::OpenAiChatCompletions,
        &headers,
        body,
        payload,
        &second_key,
    )
    .unwrap_or_else(|_| panic!("second chat request should be valid"));

    assert_ne!(first.metadata.session_id, second.metadata.session_id);
    assert!(
        first
            .metadata
            .session_id
            .as_deref()
            .is_some_and(|value| value.starts_with("rs_") && !value.contains("shared-session"))
    );
    assert_eq!(first.metadata.thread_id, first.metadata.session_id);
    assert_eq!(first.metadata.client_request_id, first.metadata.session_id);
}

#[test]
fn derives_an_internal_responses_session_without_rewriting_transport() {
    let key = AuthenticatedApiKey {
        key_id: ApiKeyId::new("key-a").expect("API key ID"),
        owner_user_id: UserId::new("user-a").expect("user ID"),
        label: "first".to_owned(),
        group_labels: vec!["default".to_owned()],
        quota_limit_atoms: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert("thread-id", "raw-thread".parse().expect("thread header"));
    headers.insert(
        "x-client-request-id",
        "raw-request".parse().expect("request header"),
    );
    let body = Bytes::from_static(br#"{"model":"gpt-5.5","input":"hello"}"#);
    let payload: Value = serde_json::from_slice(&body).expect("request JSON");

    let request = proxy_request_for_key_from_payload(
        WireFormat::OpenAiResponses,
        &headers,
        body,
        payload,
        &key,
    )
    .unwrap_or_else(|_| panic!("Responses request should be valid"));
    let payload: Value = serde_json::from_slice(&request.payload).expect("request JSON");
    let routing_session_id = request
        .metadata
        .routing_session_id
        .expect("derived routing session");

    assert!(routing_session_id.starts_with("rs_") && !routing_session_id.contains("raw-thread"));
    assert_eq!(request.metadata.session_id, None);
    assert_eq!(request.metadata.thread_id.as_deref(), Some("raw-thread"));
    assert_eq!(
        request.metadata.client_request_id.as_deref(),
        Some("raw-request")
    );
    assert!(payload.get("prompt_cache_key").is_none());
}

#[test]
fn does_not_treat_a_client_request_id_as_a_responses_session() {
    let key = AuthenticatedApiKey {
        key_id: ApiKeyId::new("key-a").expect("API key ID"),
        owner_user_id: UserId::new("user-a").expect("user ID"),
        label: "first".to_owned(),
        group_labels: vec!["default".to_owned()],
        quota_limit_atoms: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-client-request-id",
        "rotating-request-1".parse().expect("request header"),
    );
    let body = Bytes::from_static(br#"{"model":"grok-4.5","input":"hello"}"#);
    let payload: Value = serde_json::from_slice(&body).expect("request JSON");

    let request = proxy_request_for_key_from_payload(
        WireFormat::OpenAiResponses,
        &headers,
        body,
        payload,
        &key,
    )
    .unwrap_or_else(|_| panic!("Responses request should be valid"));

    assert_eq!(
        request.metadata.client_request_id.as_deref(),
        Some("rotating-request-1")
    );
    assert_eq!(request.metadata.routing_session_id, None);
}

#[test]
fn does_not_treat_a_rotating_response_id_as_a_session_id() {
    let key = AuthenticatedApiKey {
        key_id: ApiKeyId::new("key-a").expect("API key ID"),
        owner_user_id: UserId::new("user-a").expect("user ID"),
        label: "first".to_owned(),
        group_labels: vec!["default".to_owned()],
        quota_limit_atoms: None,
    };
    let headers = HeaderMap::new();
    let body = Bytes::from_static(
        br#"{"model":"grok-4.5","previous_response_id":"resp_previous","input":"continue"}"#,
    );
    let payload = serde_json::from_slice(&body).expect("request JSON");

    let request = match proxy_request_for_key_from_payload(
        WireFormat::OpenAiResponses,
        &headers,
        body,
        payload,
        &key,
    ) {
        Ok(request) => request,
        Err(_) => panic!("proxy request should be valid"),
    };
    let payload: Value = serde_json::from_slice(&request.payload).expect("normalized JSON");

    assert_eq!(
        request.metadata.previous_response_id.as_deref(),
        Some("resp_previous")
    );
    assert_eq!(request.metadata.session_id, None);
    assert_eq!(request.metadata.routing_session_id, None);
    assert!(payload.get("prompt_cache_key").is_none());
}

#[test]
fn derives_grok_session_from_native_conversation_header() {
    let key = AuthenticatedApiKey {
        key_id: ApiKeyId::new("key-a").expect("API key ID"),
        owner_user_id: UserId::new("user-a").expect("user ID"),
        label: "first".to_owned(),
        group_labels: vec!["default".to_owned()],
        quota_limit_atoms: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-grok-conv-id",
        "native-conversation"
            .parse()
            .expect("Grok conversation header"),
    );
    let body = Bytes::from_static(br#"{"model":"grok-4.5","input":"continue"}"#);
    let payload = serde_json::from_slice(&body).expect("request JSON");

    let request = proxy_request_for_key_from_payload(
        WireFormat::OpenAiResponses,
        &headers,
        body,
        payload,
        &key,
    )
    .unwrap_or_else(|_| panic!("Grok request should be valid"));
    let payload: Value = serde_json::from_slice(&request.payload).expect("request JSON");

    assert!(request
        .metadata
        .routing_session_id
        .as_deref()
        .is_some_and(|value| value.starts_with("rs_") && !value.contains("native-conversation")));
    assert_eq!(request.metadata.session_id, None);
    assert!(payload.get("prompt_cache_key").is_none());
}

#[test]
fn extracts_claude_code_session_with_expected_precedence() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "session-id",
        "fallback-session".parse().expect("fallback header"),
    );
    let payload: Value = serde_json::from_slice(
        br#"{
        "metadata":{"user_id":"{\"device_id\":\"device-a\",\"session_id\":\"payload-session\"}"}
    }"#,
    )
    .expect("payload JSON");
    let body = payload.as_object().expect("payload object");
    let payload_session = match claude_code_session_id(&headers, body, WireFormat::ClaudeMessages) {
        Ok(value) => value,
        Err(_) => panic!("payload session should be valid"),
    };
    assert_eq!(payload_session.as_deref(), Some("payload-session"));

    headers.insert(
        CLAUDE_CODE_SESSION_HEADER,
        "header-session".parse().expect("Claude session header"),
    );
    let header_session = match claude_code_session_id(&headers, body, WireFormat::ClaudeMessages) {
        Ok(value) => value,
        Err(_) => panic!("header session should be valid"),
    };
    assert_eq!(header_session.as_deref(), Some("header-session"));
}

#[test]
fn ignores_unstructured_claude_user_ids() {
    let headers = HeaderMap::new();
    let prefixed: Value = serde_json::from_slice(
        br#"{"metadata":{"user_id":"user_account_session_123e4567-e89b-12d3-a456-426614174000"}}"#,
    )
    .expect("prefixed JSON");
    let prefixed_session = match claude_code_session_id(
        &headers,
        prefixed.as_object().expect("prefixed object"),
        WireFormat::ClaudeMessages,
    ) {
        Ok(value) => value,
        Err(_) => panic!("prefixed user ID should be ignored"),
    };
    assert_eq!(prefixed_session, None);
    let bare: Value =
        serde_json::from_slice(br#"{"metadata":{"user_id":"same-user-across-chats"}}"#)
            .expect("bare JSON");
    let bare_session = match claude_code_session_id(
        &headers,
        bare.as_object().expect("bare object"),
        WireFormat::ClaudeMessages,
    ) {
        Ok(value) => value,
        Err(_) => panic!("bare user ID should be ignored"),
    };
    assert_eq!(bare_session, None);
}

#[test]
fn detects_claude_model_catalog_requests() {
    let mut headers = HeaderMap::new();
    assert_eq!(models_protocol(&headers), WireFormat::OpenAiResponses);

    headers.insert(
        header::USER_AGENT,
        "claude-cli/2.1.0".parse().expect("header"),
    );
    assert_eq!(models_protocol(&headers), WireFormat::ClaudeMessages);

    headers.remove(header::USER_AGENT);
    headers.insert("anthropic-version", "2023-06-01".parse().expect("header"));
    assert_eq!(models_protocol(&headers), WireFormat::ClaudeMessages);
}

#[test]
fn resolves_claude_catalog_model_ids_in_request_body() {
    let request = match proxy_request(
        WireFormat::ClaudeMessages,
        &HeaderMap::new(),
        Bytes::from_static(br#"{"model":"claude-fable-5-dd-5.4-korg","messages":[]}"#),
    ) {
        Ok(request) => request,
        Err(_) => panic!("proxy request should be valid"),
    };

    assert_eq!(request.model, "grok-4.5");
    let payload: Value = serde_json::from_slice(&request.payload).expect("request payload");
    assert_eq!(payload["model"], "grok-4.5");
}
