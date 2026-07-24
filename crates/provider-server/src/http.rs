use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use provider_auth::{ApiKeyAuthenticator, AuthService, AuthenticatedApiKey};
use provider_core::{
    ProviderError, ProviderErrorKind, ProxyRequest, ProxyRequestError, ProxyService,
    RequestMetadata, WireFormat,
};
use provider_management::ProviderManager;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const CLAUDE_MODEL_PREFIX: &str = "claude-fable-5-dd-";
const CLAUDE_CODE_SESSION_HEADER: &str = "x-claude-code-session-id";
const CLAUDE_CODE_SESSION_SUFFIX: &str = "_session_";

#[derive(Clone)]
struct AppState {
    service: ProxyService,
    api_keys: ApiKeyAuthenticator,
}

pub fn router(service: ProxyService, api_keys: ApiKeyAuthenticator) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/models", get(models))
        .route("/v1/responses", post(responses))
        .route("/v1/messages", post(messages))
        .route("/v1/messages/count_tokens", post(count_tokens))
        .with_state(AppState { service, api_keys })
}

pub fn router_with_management(
    service: ProxyService,
    manager: ProviderManager,
    auth: AuthService,
    api_keys: ApiKeyAuthenticator,
) -> Router {
    let auth_state =
        crate::auth_http::AuthHttpState::new(auth.clone(), api_keys.clone(), manager.clone());
    let management = crate::auth_http::protect(crate::management_http::router(manager), auth);
    router(service, api_keys)
        .merge(crate::auth_http::router(auth_state))
        .merge(management)
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn models(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, HttpError> {
    let protocol = models_protocol(&headers);
    let key = authenticate_api_key(&state.api_keys, &headers, protocol)?;
    let models = state.service.models(key.owner_user_id.as_str(), protocol);
    Ok(Json(match protocol {
        WireFormat::ClaudeMessages => claude_models_response(models),
        WireFormat::OpenAiResponses | WireFormat::OpenAiChatCompletions => json!({
            "object": "list",
            "data": models
        }),
    }))
}

fn models_protocol(headers: &HeaderMap) -> WireFormat {
    if headers
        .get("anthropic-version")
        .is_some_and(|value| !value.is_empty())
        || headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("claude-cli"))
    {
        WireFormat::ClaudeMessages
    } else {
        WireFormat::OpenAiResponses
    }
}

fn claude_models_response(models: Vec<provider_core::ProviderModel>) -> Value {
    let data = models
        .into_iter()
        .map(|model| {
            let id = ensure_claude_model_id(&model.id);
            let mut value = json!({
                "id": id,
                "type": "model",
                "display_name": model.id,
            });
            if let Some(created_at) = model.created.and_then(format_timestamp) {
                value["created_at"] = Value::String(created_at);
            }
            value
        })
        .collect::<Vec<_>>();
    let first_id = data
        .first()
        .and_then(|model| model.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let last_id = data
        .last()
        .and_then(|model| model.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    json!({
        "data": data,
        "has_more": false,
        "first_id": first_id,
        "last_id": last_id,
    })
}

fn format_timestamp(timestamp: u64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(i64::try_from(timestamp).ok()?)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn ensure_claude_model_id(id: &str) -> String {
    if id.starts_with("claude-") {
        id.to_owned()
    } else {
        format!(
            "{CLAUDE_MODEL_PREFIX}{}",
            id.chars().rev().collect::<String>()
        )
    }
}

fn resolve_claude_model_id(id: &str) -> String {
    id.strip_prefix(CLAUDE_MODEL_PREFIX)
        .map_or_else(|| id.to_owned(), |encoded| encoded.chars().rev().collect())
}

async fn responses(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, HttpError> {
    let key = authenticate_api_key(&state.api_keys, &headers, WireFormat::OpenAiResponses)?;
    proxy_stream(
        &state.service,
        key.owner_user_id.as_str(),
        WireFormat::OpenAiResponses,
        &headers,
        body,
    )
    .await
}

async fn messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, HttpError> {
    let key = authenticate_api_key(&state.api_keys, &headers, WireFormat::ClaudeMessages)?;
    let request = proxy_request_for_key(WireFormat::ClaudeMessages, &headers, body, &key)?;
    proxy_prepared_stream(&state.service, key.owner_user_id.as_str(), request).await
}

async fn count_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, HttpError> {
    let key = authenticate_api_key(&state.api_keys, &headers, WireFormat::ClaudeMessages)?;
    let request = proxy_request_for_key(WireFormat::ClaudeMessages, &headers, body, &key)?;
    let count = state
        .service
        .count_tokens(key.owner_user_id.as_str(), request)
        .await
        .map_err(|error| HttpError::from_provider(WireFormat::ClaudeMessages, error))?;

    Ok(Json(json!({ "input_tokens": count })))
}

async fn proxy_stream(
    service: &ProxyService,
    user_id: &str,
    protocol: WireFormat,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, HttpError> {
    let request = proxy_request(protocol, headers, body)?;
    proxy_prepared_stream(service, user_id, request).await
}

async fn proxy_prepared_stream(
    service: &ProxyService,
    user_id: &str,
    request: ProxyRequest,
) -> Result<Response, HttpError> {
    let protocol = request.format;
    let stream = service
        .execute_stream(user_id, request)
        .await
        .map_err(|error| HttpError::from_provider(protocol, error))?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(stream))
        .map_err(|_| HttpError::internal(protocol))
}

fn proxy_request(
    protocol: WireFormat,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<ProxyRequest, HttpError> {
    let mut payload: Value = serde_json::from_slice(&body)
        .map_err(|_| HttpError::invalid_request(protocol, "request body must be valid JSON"))?;
    let model = payload
        .as_object()
        .and_then(|payload| payload.get("model"))
        .and_then(Value::as_str)
        .ok_or_else(|| HttpError::invalid_request(protocol, "model must be a non-empty string"))?
        .to_owned();

    let model = if protocol == WireFormat::ClaudeMessages {
        resolve_claude_model_id(&model)
    } else {
        model
    };
    let body = if payload["model"].as_str() == Some(model.as_str()) {
        body
    } else {
        payload["model"] = Value::String(model.clone());
        Bytes::from(serde_json::to_vec(&payload).map_err(|_| HttpError::internal(protocol))?)
    };

    let request = ProxyRequest::new(protocol, model, body)
        .map_err(|error| HttpError::from_proxy_request(protocol, error))?;
    Ok(request.with_metadata(request_metadata(headers, protocol)?))
}

fn proxy_request_for_key(
    protocol: WireFormat,
    headers: &HeaderMap,
    body: Bytes,
    key: &AuthenticatedApiKey,
) -> Result<ProxyRequest, HttpError> {
    let mut request = proxy_request(protocol, headers, body)?;
    if protocol == WireFormat::ClaudeMessages {
        let mut payload: Value = serde_json::from_slice(&request.payload)
            .map_err(|_| HttpError::invalid_request(protocol, "request body must be valid JSON"))?;
        let Some(root) = payload.as_object_mut() else {
            return Err(HttpError::invalid_request(
                protocol,
                "request body must be a JSON object",
            ));
        };
        if let Some(session_id) = claude_code_session_id(headers, root, protocol)? {
            request.metadata.session_id =
                Some(claude_code_cache_key(key, &request.model, &session_id));
        }
        root.remove("metadata");
        request.payload = serde_json::to_vec(&payload)
            .map(Bytes::from)
            .map_err(|_| HttpError::internal(protocol))?;
    }
    Ok(request)
}

fn request_metadata(
    headers: &HeaderMap,
    protocol: WireFormat,
) -> Result<RequestMetadata, HttpError> {
    let mut metadata = RequestMetadata::default();
    metadata.session_id = metadata_header(headers, "session-id", protocol)?;
    metadata.thread_id = metadata_header(headers, "thread-id", protocol)?;
    metadata.client_request_id = metadata_header(headers, "x-client-request-id", protocol)?;
    Ok(metadata)
}

fn claude_code_session_id(
    headers: &HeaderMap,
    body: &Map<String, Value>,
    protocol: WireFormat,
) -> Result<Option<String>, HttpError> {
    if let Some(session_id) = metadata_header(headers, CLAUDE_CODE_SESSION_HEADER, protocol)? {
        return Ok(Some(session_id));
    }
    if let Some(user_id) = body
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("user_id"))
        .and_then(Value::as_str)
    {
        if let Ok(metadata) = serde_json::from_str::<Value>(user_id)
            && let Some(session_id) = metadata.get("session_id").and_then(Value::as_str)
        {
            return validated_session_id(session_id, protocol);
        }
        if let Some((_, session_id)) = user_id.rsplit_once(CLAUDE_CODE_SESSION_SUFFIX)
            && valid_legacy_claude_session_id(session_id)
        {
            return validated_session_id(session_id, protocol);
        }
    }
    metadata_header(headers, "session-id", protocol)
}

fn valid_legacy_claude_session_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() || byte == b'-')
}

fn validated_session_id(value: &str, protocol: WireFormat) -> Result<Option<String>, HttpError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if !valid_metadata_value(value) {
        return Err(HttpError::invalid_request(
            protocol,
            "request metadata header is invalid",
        ));
    }
    Ok(Some(value.to_owned()))
}

fn claude_code_cache_key(key: &AuthenticatedApiKey, model: &str, session_id: &str) -> String {
    let mut digest = Sha256::new();
    for value in [
        "claude-code-cache-v1",
        key.key_id.as_str(),
        key.owner_user_id.as_str(),
        model,
        session_id,
    ] {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(value.as_bytes());
    }
    let digest = digest.finalize();
    let mut encoded = String::with_capacity(35);
    encoded.push_str("cc_");
    for byte in digest.iter().take(16) {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn metadata_header(
    headers: &HeaderMap,
    name: &'static str,
    protocol: WireFormat,
) -> Result<Option<String>, HttpError> {
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| HttpError::invalid_request(protocol, "request metadata header is invalid"))?
        .trim();
    if value.is_empty() {
        return Ok(None);
    }
    if !valid_metadata_value(value) {
        return Err(HttpError::invalid_request(
            protocol,
            "request metadata header is invalid",
        ));
    }
    Ok(Some(value.to_owned()))
}

fn valid_metadata_value(value: &str) -> bool {
    value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}

fn authenticate_api_key(
    authenticator: &ApiKeyAuthenticator,
    headers: &HeaderMap,
    protocol: WireFormat,
) -> Result<AuthenticatedApiKey, HttpError> {
    let key = downstream_api_key(headers).ok_or_else(|| HttpError::authentication(protocol))?;
    authenticator
        .authenticate(key, unix_timestamp())
        .map_err(|_| HttpError::authentication(protocol))
}

fn downstream_api_key(headers: &HeaderMap) -> Option<&str> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_value);
    let x_api_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty());
    match (bearer, x_api_key) {
        (Some(bearer), Some(x_api_key)) if bearer != x_api_key => None,
        (Some(bearer), _) => Some(bearer),
        (None, Some(x_api_key)) => Some(x_api_key),
        (None, None) => None,
    }
}

fn bearer_value(value: &str) -> Option<&str> {
    let mut parts = value.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && parts.next().is_none() {
        Some(token)
    } else {
        None
    }
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

struct HttpError {
    status: StatusCode,
    body: Value,
}

impl HttpError {
    fn authentication(protocol: WireFormat) -> Self {
        Self::new(
            protocol,
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "invalid API key",
        )
    }

    fn invalid_request(protocol: WireFormat, message: &'static str) -> Self {
        Self::new(
            protocol,
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            message,
        )
    }

    fn internal(protocol: WireFormat) -> Self {
        Self::new(
            protocol,
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "internal server error",
        )
    }

    fn from_proxy_request(protocol: WireFormat, error: ProxyRequestError) -> Self {
        Self::invalid_request(
            protocol,
            match error {
                ProxyRequestError::EmptyModel => "model must be a non-empty string",
            },
        )
    }

    fn from_provider(protocol: WireFormat, error: ProviderError) -> Self {
        let (status, error_type) = match error.kind() {
            ProviderErrorKind::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request_error"),
            ProviderErrorKind::Authentication => (StatusCode::UNAUTHORIZED, "authentication_error"),
            ProviderErrorKind::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limit_error"),
            ProviderErrorKind::Upstream => (StatusCode::BAD_GATEWAY, "api_error"),
            ProviderErrorKind::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "api_error"),
        };
        Self::new(protocol, status, error_type, error.message())
    }

    fn new(protocol: WireFormat, status: StatusCode, error_type: &str, message: &str) -> Self {
        let body = match protocol {
            WireFormat::OpenAiResponses | WireFormat::OpenAiChatCompletions => json!({
                "error": { "type": error_type, "message": message }
            }),
            WireFormat::ClaudeMessages => json!({
                "type": "error",
                "error": { "type": error_type, "message": message }
            }),
        };
        Self { status, body }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use futures_util::stream;
    use provider_auth::{ApiKeyId, AuthService, UserId};
    use provider_core::{
        Provider, ProviderModel, ProviderRequest, ProviderStream, RequestMetadata,
    };
    use provider_protocol::DefaultProtocolBridge;
    use provider_storage::SqliteAccountRepository;
    use secrecy::{ExposeSecret, SecretString};
    use tokio::net::TcpListener;

    use super::*;

    async fn response_json(response: reqwest::Response) -> Value {
        let body = response.bytes().await.expect("response body");
        serde_json::from_slice(&body).expect("response JSON")
    }

    struct TestProvider {
        models: Vec<ProviderModel>,
        metadata: Arc<Mutex<Vec<RequestMetadata>>>,
    }

    #[async_trait]
    impl Provider for TestProvider {
        fn name(&self) -> &'static str {
            "test"
        }

        fn native_format(&self) -> WireFormat {
            WireFormat::OpenAiResponses
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
        let captured_metadata = Arc::new(Mutex::new(Vec::new()));
        let service = ProxyService::new(
            Arc::new(TestProvider {
                models: vec![ProviderModel::new("grok-4.5", "xai")],
                metadata: captured_metadata.clone(),
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
        assert_eq!(models["object"], "list");

        let claude_models = response_json(
            client
                .get(format!("{base_url}/v1/models"))
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

        for path in ["/v1/responses", "/v1/messages"] {
            let mut request = client
                .post(format!("{base_url}{path}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(json!({ "model": "grok-4.5", "input": "hello", "messages": [] }).to_string());
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
        let mut expected_metadata = RequestMetadata::default();
        expected_metadata.session_id = Some("session-1".to_owned());
        expected_metadata.thread_id = Some("thread:1".to_owned());
        expected_metadata.client_request_id = Some("request_1".to_owned());
        assert_eq!(
            captured_metadata
                .lock()
                .expect("metadata capture lock")
                .as_slice(),
            [expected_metadata, RequestMetadata::default()]
        );

        let invalid_metadata = client
            .post(format!("{base_url}/v1/responses"))
            .bearer_auth(&api_key)
            .header("session-id", "invalid value")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json!({ "model": "grok-4.5", "input": "hello" }).to_string())
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
                .post(format!("{base_url}/v1/messages/count_tokens"))
                .header("x-api-key", &api_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(json!({ "model": "grok-4.5", "messages": [] }).to_string())
                .send()
                .await
                .expect("count response"),
        )
        .await;
        assert_eq!(count["input_tokens"], 42);

        api_keys
            .update(
                &grant.user.id,
                &created_key.summary.id,
                Some(false),
                None,
                unix_timestamp(),
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
        };
        let second_key = AuthenticatedApiKey {
            key_id: ApiKeyId::new("key-b").expect("API key ID"),
            owner_user_id: UserId::new("user-a").expect("user ID"),
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
        let payload_session =
            match claude_code_session_id(&headers, body, WireFormat::ClaudeMessages) {
                Ok(value) => value,
                Err(_) => panic!("payload session should be valid"),
            };
        assert_eq!(payload_session.as_deref(), Some("payload-session"));

        headers.insert(
            CLAUDE_CODE_SESSION_HEADER,
            "header-session".parse().expect("Claude session header"),
        );
        let header_session =
            match claude_code_session_id(&headers, body, WireFormat::ClaudeMessages) {
                Ok(value) => value,
                Err(_) => panic!("header session should be valid"),
            };
        assert_eq!(header_session.as_deref(), Some("header-session"));
    }

    #[test]
    fn extracts_legacy_session_and_rejects_bare_user_id() {
        let headers = HeaderMap::new();
        let legacy: Value = serde_json::from_slice(
            br#"{"metadata":{"user_id":"user_account_session_123e4567-e89b-12d3-a456-426614174000"}}"#,
        )
        .expect("legacy JSON");
        let legacy_session = match claude_code_session_id(
            &headers,
            legacy.as_object().expect("legacy object"),
            WireFormat::ClaudeMessages,
        ) {
            Ok(value) => value,
            Err(_) => panic!("legacy session should be valid"),
        };
        assert_eq!(
            legacy_session.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
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
}
