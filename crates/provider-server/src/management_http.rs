use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use provider_core::{
    AccountId, ProviderAccountSummary, ProviderAccountUpdate, ProviderKind, ProviderModelOverride,
    StoredProviderModel,
};
use provider_management::{
    CreatedProviderAccount, ModelCatalogSnapshot, OAuthSessionSnapshot, OAuthSessionStatus,
    ProviderManager, ProviderManagerError,
};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone)]
struct ManagementState {
    manager: ProviderManager,
}

pub(crate) fn router(manager: ProviderManager) -> Router {
    Router::new()
        .route("/api/v1/providers", get(list_accounts).post(create_account))
        .route(
            "/api/v1/providers/{account_id}",
            get(get_account)
                .patch(update_account)
                .delete(delete_account),
        )
        .route(
            "/api/v1/providers/{account_id}/enabled",
            put(set_account_enabled),
        )
        .route(
            "/api/v1/providers/{account_id}/models",
            get(list_models).patch(update_model),
        )
        .route(
            "/api/v1/providers/{account_id}/models/refresh",
            post(refresh_models),
        )
        .route("/api/v1/oauth/sessions", post(start_oauth_session))
        .route(
            "/api/v1/oauth/sessions/{session_id}",
            get(get_oauth_session).delete(cancel_oauth_session),
        )
        .with_state(ManagementState { manager })
}

async fn list_accounts(State(state): State<ManagementState>) -> Result<Json<Value>, ApiError> {
    let accounts = state.manager.list_accounts().await?;
    Ok(data(Value::Array(
        accounts.iter().map(account_json).collect(),
    )))
}

async fn get_account(
    State(state): State<ManagementState>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let account = state
        .manager
        .get_account(&parse_account_id(&account_id)?)
        .await?;
    Ok(data(account_json(&account)))
}

async fn create_account(
    State(state): State<ManagementState>,
    Json(request): Json<CreateAccountRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let created = match request {
        CreateAccountRequest::CredentialJson {
            provider,
            label,
            credential_json,
        } => {
            if provider != ProviderKind::Grok {
                return Err(ApiError::invalid_request(
                    "credential_json onboarding is only supported for Grok",
                ));
            }
            state
                .manager
                .import_grok_account(
                    label,
                    SecretString::from(json_document(credential_json)),
                    unix_timestamp(),
                )
                .await?
        }
        CreateAccountRequest::Direct {
            provider,
            label,
            base_url,
            api_key,
        } => {
            if provider == ProviderKind::Grok {
                return Err(ApiError::invalid_request(
                    "Grok requires credential_json or OAuth onboarding",
                ));
            }
            state
                .manager
                .create_direct_account(
                    provider,
                    label,
                    json!({ "base_url": base_url }).to_string(),
                    api_key.map(SecretString::from),
                    unix_timestamp(),
                )
                .await?
        }
    };
    Ok((StatusCode::CREATED, data(created_account_json(&created))))
}

async fn update_account(
    State(state): State<ManagementState>,
    Path(account_id): Path<String>,
    Json(request): Json<UpdateAccountRequest>,
) -> Result<Json<Value>, ApiError> {
    if request.label.is_none() && request.base_url.is_none() {
        return Err(ApiError::invalid_request(
            "account update requires label or base_url",
        ));
    }
    let account_id = parse_account_id(&account_id)?;
    let current = state.manager.get_account(&account_id).await?;
    let label = request.label.unwrap_or_else(|| current.label.clone());
    let config_json = match (current.provider, request.base_url) {
        (ProviderKind::Grok, Some(_)) => {
            return Err(ApiError::invalid_request(
                "Grok account base_url is managed by its credential",
            ));
        }
        (ProviderKind::Grok, None) => current.config_json,
        (_, base_url) => {
            let mut config: Value =
                serde_json::from_str(&current.config_json).map_err(|_| ApiError::internal())?;
            if let Some(base_url) = base_url {
                config["base_url"] = Value::String(base_url);
            }
            config.to_string()
        }
    };
    let account = state
        .manager
        .update_account(
            &account_id,
            ProviderAccountUpdate {
                label,
                config_json,
                updated_at: unix_timestamp(),
            },
        )
        .await?;
    Ok(data(account_json(&account)))
}

async fn set_account_enabled(
    State(state): State<ManagementState>,
    Path(account_id): Path<String>,
    Json(request): Json<SetEnabledRequest>,
) -> Result<Json<Value>, ApiError> {
    let account = state
        .manager
        .set_account_enabled(
            &parse_account_id(&account_id)?,
            request.enabled,
            unix_timestamp(),
        )
        .await?;
    Ok(data(account_json(&account)))
}

async fn delete_account(
    State(state): State<ManagementState>,
    Path(account_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state
        .manager
        .delete_account(&parse_account_id(&account_id)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_models(
    State(state): State<ManagementState>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let account_id = parse_account_id(&account_id)?;
    state.manager.get_account(&account_id).await?;
    let models = state.manager.list_models(Some(&account_id)).await?;
    Ok(data(Value::Array(models.iter().map(model_json).collect())))
}

async fn refresh_models(
    State(state): State<ManagementState>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let snapshot = state
        .manager
        .refresh_models(&parse_account_id(&account_id)?, unix_timestamp())
        .await?;
    Ok(data(model_snapshot_json(&snapshot)))
}

async fn update_model(
    State(state): State<ManagementState>,
    Path(account_id): Path<String>,
    Json(request): Json<UpdateModelRequest>,
) -> Result<Json<Value>, ApiError> {
    let upstream_model = request.upstream_model.trim();
    if upstream_model.is_empty() {
        return Err(ApiError::invalid_request(
            "upstream_model must not be empty",
        ));
    }
    let alias = request
        .alias
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let models = state
        .manager
        .update_model(
            &parse_account_id(&account_id)?,
            upstream_model,
            ProviderModelOverride {
                alias,
                enabled: request.enabled,
                updated_at: unix_timestamp(),
            },
        )
        .await?;
    Ok(data(Value::Array(models.iter().map(model_json).collect())))
}

async fn start_oauth_session(
    State(state): State<ManagementState>,
    Json(request): Json<StartOAuthRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let session = state
        .manager
        .start_oauth_session(request.provider, request.label)
        .await?;
    Ok((StatusCode::CREATED, data(oauth_session_json(&session))))
}

async fn get_oauth_session(
    State(state): State<ManagementState>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = state
        .manager
        .oauth_session(&session_id)
        .ok_or_else(ApiError::not_found)?;
    Ok(data(oauth_session_json(&session)))
}

async fn cancel_oauth_session(
    State(state): State<ManagementState>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = state
        .manager
        .cancel_oauth_session(&session_id)
        .ok_or_else(ApiError::not_found)?;
    Ok(data(oauth_session_json(&session)))
}

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
enum CreateAccountRequest {
    CredentialJson {
        provider: ProviderKind,
        label: String,
        credential_json: Value,
    },
    Direct {
        provider: ProviderKind,
        label: String,
        base_url: String,
        api_key: Option<String>,
    },
}

#[derive(Deserialize)]
struct UpdateAccountRequest {
    label: Option<String>,
    base_url: Option<String>,
}

#[derive(Deserialize)]
struct SetEnabledRequest {
    enabled: bool,
}

#[derive(Deserialize)]
struct UpdateModelRequest {
    upstream_model: String,
    alias: Option<String>,
    enabled: bool,
}

#[derive(Deserialize)]
struct StartOAuthRequest {
    provider: ProviderKind,
    label: String,
}

fn created_account_json(created: &CreatedProviderAccount) -> Value {
    json!({
        "account": account_json(&created.account),
        "models": model_snapshot_json(&created.models)
    })
}

fn account_json(account: &ProviderAccountSummary) -> Value {
    json!({
        "id": account.id.as_str(),
        "provider": account.provider.as_str(),
        "label": account.label,
        "config": serde_json::from_str::<Value>(&account.config_json).unwrap_or(Value::Null),
        "credential_kind": account.credential_kind.as_str(),
        "enabled": account.enabled,
        "auth_state": account.auth_state.as_str(),
        "safe_error_code": account.safe_error_code,
        "created_at": account.created_at,
        "updated_at": account.updated_at
    })
}

fn model_snapshot_json(snapshot: &ModelCatalogSnapshot) -> Value {
    json!({
        "source": snapshot.source,
        "models": snapshot.models.iter().map(model_json).collect::<Vec<_>>(),
        "warning": snapshot.warning
    })
}

fn model_json(model: &StoredProviderModel) -> Value {
    json!({
        "account_id": model.account_id.as_str(),
        "upstream_model": model.upstream_model,
        "alias": model.alias,
        "effective_model": model.effective_model(),
        "enabled": model.enabled,
        "available": model.available,
        "routable": model.routable,
        "metadata": serde_json::from_str::<Value>(&model.metadata_json).unwrap_or(Value::Null),
        "last_seen_at": model.last_seen_at,
        "created_at": model.created_at,
        "updated_at": model.updated_at
    })
}

fn oauth_session_json(session: &OAuthSessionSnapshot) -> Value {
    let status = match session.status {
        OAuthSessionStatus::Pending => "pending",
        OAuthSessionStatus::Completed => "completed",
        OAuthSessionStatus::Failed => "failed",
        OAuthSessionStatus::Cancelled => "cancelled",
    };
    json!({
        "id": session.id,
        "provider": session.provider.as_str(),
        "account_id": session.account_id.as_str(),
        "label": session.label,
        "status": status,
        "challenge": {
            "verification_uri": session.challenge.verification_uri,
            "verification_uri_complete": session.challenge.verification_uri_complete,
            "user_code": session.challenge.user_code,
            "expires_at": session.challenge.expires_at,
            "interval_seconds": session.challenge.interval_seconds
        },
        "error": session.error
    })
}

fn json_document(value: Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn parse_account_id(value: &str) -> Result<AccountId, ApiError> {
    AccountId::new(value).map_err(|_| ApiError::invalid_request("invalid provider account ID"))
}

fn data(value: Value) -> Json<Value> {
    Json(json!({ "data": value }))
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

struct ApiError {
    status: StatusCode,
    error_type: &'static str,
    message: String,
}

impl ApiError {
    fn invalid_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error_type: "invalid_request_error",
            message: message.to_owned(),
        }
    }

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error_type: "not_found_error",
            message: "resource was not found".to_owned(),
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error_type: "api_error",
            message: "internal server error".to_owned(),
        }
    }
}

impl From<ProviderManagerError> for ApiError {
    fn from(error: ProviderManagerError) -> Self {
        match error {
            ProviderManagerError::InvalidInput(message) => Self::invalid_request(message),
            ProviderManagerError::NotFound => Self::not_found(),
            ProviderManagerError::Conflict => Self {
                status: StatusCode::CONFLICT,
                error_type: "conflict_error",
                message: error.to_string(),
            },
            ProviderManagerError::Control(_) => Self {
                status: StatusCode::BAD_REQUEST,
                error_type: "invalid_request_error",
                message: error.to_string(),
            },
            ProviderManagerError::OAuthStart(_) => Self {
                status: StatusCode::BAD_GATEWAY,
                error_type: "upstream_error",
                message: error.to_string(),
            },
            ProviderManagerError::Repository(_) | ProviderManagerError::ModelCatalog(_) => {
                Self::internal()
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": { "type": self.error_type, "message": self.message }
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Router,
        extract::State,
        http::{HeaderMap, StatusCode, header},
        routing::get,
    };
    use provider_core::ProxyService;
    use provider_drivers::openai_compatible::OpenAiCompatibleDriver;
    use provider_management::ProviderManager;
    use provider_protocol::DefaultProtocolBridge;
    use provider_runtime::ProviderRuntimeCatalog;
    use provider_storage::SqliteAccountRepository;
    use tokio::net::TcpListener;

    use crate::router_with_management;

    #[tokio::test]
    async fn creates_compatible_accounts_without_returning_credentials() {
        let authorization = Arc::new(Mutex::new(Vec::<String>::new()));
        let upstream =
            Router::new()
                .route(
                    "/models",
                    get(
                        |State(authorization): State<Arc<Mutex<Vec<String>>>>,
                         headers: HeaderMap| async move {
                            authorization.lock().expect("authorization lock").push(
                                headers
                                    .get(reqwest::header::AUTHORIZATION)
                                    .and_then(|value| value.to_str().ok())
                                    .unwrap_or_default()
                                    .to_owned(),
                            );
                            r#"{"data":[{"id":"model-a","owned_by":"test"}]}"#
                        },
                    ),
                )
                .with_state(authorization.clone());
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let upstream_server = tokio::spawn(axum::serve(upstream_listener, upstream).into_future());

        let repository = Arc::new(
            SqliteAccountRepository::in_memory()
                .await
                .expect("repository"),
        );
        let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
        runtime
            .register_driver(Arc::new(OpenAiCompatibleDriver::new()))
            .expect("register driver");
        let manager = ProviderManager::new(repository, runtime.clone());
        let service = ProxyService::with_router(runtime.clone(), Arc::new(DefaultProtocolBridge));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind management server");
        let address = listener.local_addr().expect("management address");
        let server = tokio::spawn(
            axum::serve(listener, router_with_management(service, manager)).into_future(),
        );
        let client = reqwest::Client::new();
        let endpoint = format!("http://{address}/api/v1/providers");
        let base_url = format!("http://{upstream_address}");

        let with_key = client
            .post(&endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "direct",
                    "provider": "openai_compatible",
                    "label": "with key",
                    "base_url": base_url,
                    "api_key": "do-not-return"
                })
                .to_string(),
            )
            .send()
            .await
            .expect("create keyed account");
        assert_eq!(with_key.status(), StatusCode::CREATED);
        let with_key_body = with_key.text().await.expect("keyed response");
        assert!(!with_key_body.contains("do-not-return"));

        let without_key = client
            .post(&endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "direct",
                    "provider": "openai_compatible",
                    "label": "without key",
                    "base_url": base_url,
                    "api_key": ""
                })
                .to_string(),
            )
            .send()
            .await
            .expect("create keyless account");
        assert_eq!(without_key.status(), StatusCode::CREATED);

        server.abort();
        upstream_server.abort();
        runtime.shutdown();
        assert_eq!(
            authorization.lock().expect("authorization lock").as_slice(),
            ["Bearer do-not-return", ""]
        );
    }
}
