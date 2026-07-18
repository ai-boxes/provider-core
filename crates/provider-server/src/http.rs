use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use provider_core::{
    Protocol, ProviderError, ProviderErrorKind, ProxyRequest, ProxyRequestError, ProxyService,
};
use serde_json::{Value, json};

#[derive(Clone)]
struct AppState {
    service: ProxyService,
}

pub fn router(service: ProxyService) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/models", get(models))
        .route("/v1/responses", post(responses))
        .route("/v1/messages", post(messages))
        .route("/v1/messages/count_tokens", post(count_tokens))
        .with_state(AppState { service })
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn models(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": state.service.models()
    }))
}

async fn responses(State(state): State<AppState>, body: Bytes) -> Result<Response, HttpError> {
    proxy_stream(&state.service, Protocol::CodexResponses, body).await
}

async fn messages(State(state): State<AppState>, body: Bytes) -> Result<Response, HttpError> {
    proxy_stream(&state.service, Protocol::ClaudeMessages, body).await
}

async fn count_tokens(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<Value>, HttpError> {
    let request = proxy_request(Protocol::ClaudeMessages, body)?;
    let count = state
        .service
        .count_tokens(request)
        .await
        .map_err(|error| HttpError::from_provider(Protocol::ClaudeMessages, error))?;

    Ok(Json(json!({ "input_tokens": count })))
}

async fn proxy_stream(
    service: &ProxyService,
    protocol: Protocol,
    body: Bytes,
) -> Result<Response, HttpError> {
    let request = proxy_request(protocol, body)?;
    let stream = service
        .execute_stream(request)
        .await
        .map_err(|error| HttpError::from_provider(protocol, error))?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(stream))
        .map_err(|_| HttpError::internal(protocol))
}

fn proxy_request(protocol: Protocol, body: Bytes) -> Result<ProxyRequest, HttpError> {
    let payload: Value = serde_json::from_slice(&body)
        .map_err(|_| HttpError::invalid_request(protocol, "request body must be valid JSON"))?;
    let model = payload
        .as_object()
        .and_then(|payload| payload.get("model"))
        .and_then(Value::as_str)
        .ok_or_else(|| HttpError::invalid_request(protocol, "model must be a non-empty string"))?;

    ProxyRequest::new(protocol, model, body)
        .map_err(|error| HttpError::from_proxy_request(protocol, error))
}

struct HttpError {
    status: StatusCode,
    body: Value,
}

impl HttpError {
    fn invalid_request(protocol: Protocol, message: &'static str) -> Self {
        Self::new(
            protocol,
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            message,
        )
    }

    fn internal(protocol: Protocol) -> Self {
        Self::new(
            protocol,
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "internal server error",
        )
    }

    fn from_proxy_request(protocol: Protocol, error: ProxyRequestError) -> Self {
        Self::invalid_request(
            protocol,
            match error {
                ProxyRequestError::EmptyModel => "model must be a non-empty string",
            },
        )
    }

    fn from_provider(protocol: Protocol, error: ProviderError) -> Self {
        let (status, error_type) = match error.kind() {
            ProviderErrorKind::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request_error"),
            ProviderErrorKind::Authentication => (StatusCode::UNAUTHORIZED, "authentication_error"),
            ProviderErrorKind::Upstream => (StatusCode::BAD_GATEWAY, "api_error"),
            ProviderErrorKind::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "api_error"),
        };
        Self::new(protocol, status, error_type, error.message())
    }

    fn new(protocol: Protocol, status: StatusCode, error_type: &str, message: &str) -> Self {
        let body = match protocol {
            Protocol::CodexResponses => json!({
                "error": { "type": error_type, "message": message }
            }),
            Protocol::ClaudeMessages => json!({
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
    use std::sync::Arc;

    use async_trait::async_trait;
    use futures_util::stream;
    use provider_core::{Provider, ProviderModel, ProviderStream};
    use tokio::net::TcpListener;

    use super::*;

    async fn response_json(response: reqwest::Response) -> Value {
        let body = response.bytes().await.expect("response body");
        serde_json::from_slice(&body).expect("response JSON")
    }

    struct TestProvider {
        models: Vec<ProviderModel>,
    }

    #[async_trait]
    impl Provider for TestProvider {
        fn name(&self) -> &'static str {
            "test"
        }

        fn models(&self) -> &[ProviderModel] {
            &self.models
        }

        async fn execute_stream(
            &self,
            request: ProxyRequest,
        ) -> Result<ProviderStream, ProviderError> {
            let event = match request.protocol {
                Protocol::CodexResponses => {
                    Bytes::from_static(b"event: response.completed\ndata: {}\n\n")
                }
                Protocol::ClaudeMessages => Bytes::from_static(
                    b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                ),
            };
            Ok(Box::pin(stream::once(async move { Ok(event) })))
        }

        async fn count_tokens(&self, _request: ProxyRequest) -> Result<u64, ProviderError> {
            Ok(42)
        }
    }

    #[tokio::test]
    async fn exposes_phase_one_http_contract() {
        let service = ProxyService::new(Arc::new(TestProvider {
            models: vec![ProviderModel::new("grok-4.5", "xai")],
        }));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let server = tokio::spawn(axum::serve(listener, router(service)).into_future());
        let client = reqwest::Client::new();
        let base_url = format!("http://{address}");

        let health = client
            .get(format!("{base_url}/healthz"))
            .send()
            .await
            .expect("health response");
        assert_eq!(health.status(), StatusCode::OK);

        let models = response_json(
            client
                .get(format!("{base_url}/v1/models"))
                .send()
                .await
                .expect("models response"),
        )
        .await;
        assert_eq!(models["data"][0]["id"], "grok-4.5");

        for path in ["/v1/responses", "/v1/messages"] {
            let response = client
                .post(format!("{base_url}{path}"))
                .bearer_auth("placeholder-key")
                .header(header::CONTENT_TYPE, "application/json")
                .body(json!({ "model": "grok-4.5", "input": "hello", "messages": [] }).to_string())
                .send()
                .await
                .expect("stream response");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("text/event-stream")
            );
        }

        let count = response_json(
            client
                .post(format!("{base_url}/v1/messages/count_tokens"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(json!({ "model": "grok-4.5", "messages": [] }).to_string())
                .send()
                .await
                .expect("count response"),
        )
        .await;
        assert_eq!(count["input_tokens"], 42);

        server.abort();
    }
}
