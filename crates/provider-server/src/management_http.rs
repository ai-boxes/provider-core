use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use provider_auth::AuthenticatedSession;
use provider_core::{
    AccountId, ProviderAccountSummary, ProviderAccountUpdate, ProviderKind, ProviderModelOverride,
    ProviderVisibility, StoredProviderModel,
};
use provider_management::{
    CreatedProviderAccount, DirectProviderAccountInput, ModelCatalogSnapshot, OAuthSessionSnapshot,
    OAuthSessionStatus, ProviderManager, ProviderManagerError,
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
        .route("/api/v1/providers/{account_id}/quota", get(get_quota))
        .route(
            "/api/v1/providers/{account_id}/quota/refresh",
            post(refresh_quota),
        )
        .route("/api/v1/oauth/sessions", post(start_oauth_session))
        .route(
            "/api/v1/oauth/sessions/{session_id}",
            get(get_oauth_session).delete(cancel_oauth_session),
        )
        .with_state(ManagementState { manager })
}

async fn list_accounts(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<Value>, ApiError> {
    let accounts = state
        .manager
        .list_accounts(session.user.id.as_str())
        .await?;
    let now = unix_timestamp();
    Ok(data(Value::Array(
        accounts
            .iter()
            .map(|account| {
                account_with_quota_json(
                    account,
                    state
                        .manager
                        .cached_quota(session.user.id.as_str(), account, now),
                )
            })
            .collect(),
    )))
}

async fn get_account(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let account = state
        .manager
        .get_account(session.user.id.as_str(), &parse_account_id(&account_id)?)
        .await?;
    Ok(data(account_json(&account)))
}

async fn create_account(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(request): Json<CreateAccountRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let created = match request {
        CreateAccountRequest::CredentialJson {
            provider,
            label,
            credential_json,
            visibility,
        } => {
            if provider != ProviderKind::Grok {
                return Err(ApiError::invalid_request(
                    "credential_json onboarding is only supported for Grok",
                ));
            }
            state
                .manager
                .import_grok_account(
                    session.user.id.as_str(),
                    label,
                    SecretString::from(json_document(credential_json)),
                    visibility.unwrap_or_default(),
                    unix_timestamp(),
                )
                .await?
        }
        CreateAccountRequest::Direct {
            provider,
            label,
            base_url,
            api_key,
            visibility,
        } => {
            if provider == ProviderKind::Grok {
                return Err(ApiError::invalid_request(
                    "Grok requires credential_json or OAuth onboarding",
                ));
            }
            state
                .manager
                .create_direct_account(
                    session.user.id.as_str(),
                    DirectProviderAccountInput {
                        kind: provider,
                        label,
                        config_json: json!({ "base_url": base_url }).to_string(),
                        api_key: api_key.map(SecretString::from),
                        visibility: visibility.unwrap_or_default(),
                    },
                    unix_timestamp(),
                )
                .await?
        }
    };
    Ok((StatusCode::CREATED, data(created_account_json(&created))))
}

async fn update_account(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
    Json(request): Json<UpdateAccountRequest>,
) -> Result<Json<Value>, ApiError> {
    if request.label.is_none() && request.base_url.is_none() && request.visibility.is_none() {
        return Err(ApiError::invalid_request(
            "account update requires label, base_url, or visibility",
        ));
    }
    let account_id = parse_account_id(&account_id)?;
    let current = state
        .manager
        .get_account(session.user.id.as_str(), &account_id)
        .await?;
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
            session.user.id.as_str(),
            &account_id,
            ProviderAccountUpdate {
                label,
                config_json,
                visibility: request.visibility.unwrap_or(current.visibility),
                updated_at: unix_timestamp(),
            },
        )
        .await?;
    Ok(data(account_json(&account)))
}

async fn set_account_enabled(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
    Json(request): Json<SetEnabledRequest>,
) -> Result<Json<Value>, ApiError> {
    let account = state
        .manager
        .set_account_enabled(
            session.user.id.as_str(),
            &parse_account_id(&account_id)?,
            request.enabled,
            unix_timestamp(),
        )
        .await?;
    Ok(data(account_json(&account)))
}

async fn delete_account(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state
        .manager
        .delete_account(session.user.id.as_str(), &parse_account_id(&account_id)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_models(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let account_id = parse_account_id(&account_id)?;
    let models = state
        .manager
        .list_models(session.user.id.as_str(), &account_id)
        .await?;
    Ok(data(Value::Array(models.iter().map(model_json).collect())))
}

async fn refresh_models(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let snapshot = state
        .manager
        .refresh_models(
            session.user.id.as_str(),
            &parse_account_id(&account_id)?,
            unix_timestamp(),
        )
        .await?;
    Ok(data(model_snapshot_json(&snapshot)))
}

async fn get_quota(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let quota = state
        .manager
        .quota(
            session.user.id.as_str(),
            &parse_account_id(&account_id)?,
            unix_timestamp(),
        )
        .await?;
    Ok(data(quota_json(&quota)?))
}

async fn refresh_quota(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let quota = state
        .manager
        .refresh_quota(
            session.user.id.as_str(),
            &parse_account_id(&account_id)?,
            unix_timestamp(),
        )
        .await?;
    Ok(data(quota_json(&quota)?))
}

async fn update_model(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
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
            session.user.id.as_str(),
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
    Extension(session): Extension<AuthenticatedSession>,
    Json(request): Json<StartOAuthRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let session = state
        .manager
        .start_oauth_session(
            session.user.id.as_str(),
            request.provider,
            request.label,
            request.visibility.unwrap_or_default(),
        )
        .await?;
    Ok((StatusCode::CREATED, data(oauth_session_json(&session))))
}

async fn get_oauth_session(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = state
        .manager
        .oauth_session(session.user.id.as_str(), &session_id)
        .ok_or_else(ApiError::not_found)?;
    Ok(data(oauth_session_json(&session)))
}

async fn cancel_oauth_session(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = state
        .manager
        .cancel_oauth_session(session.user.id.as_str(), &session_id)
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
        visibility: Option<ProviderVisibility>,
    },
    Direct {
        provider: ProviderKind,
        label: String,
        base_url: String,
        api_key: Option<String>,
        visibility: Option<ProviderVisibility>,
    },
}

#[derive(Deserialize)]
struct UpdateAccountRequest {
    label: Option<String>,
    base_url: Option<String>,
    visibility: Option<ProviderVisibility>,
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
    visibility: Option<ProviderVisibility>,
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
        "owner_user_id": account.owner_user_id,
        "visibility": account.visibility.as_str(),
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

fn account_with_quota_json(
    account: &ProviderAccountSummary,
    quota: provider_core::ProviderQuotaView,
) -> Value {
    let mut value = account_json(account);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "quota".to_owned(),
            serde_json::to_value(quota).unwrap_or(Value::Null),
        );
    }
    value
}

fn quota_json(quota: &provider_core::ProviderQuotaView) -> Result<Value, ApiError> {
    serde_json::to_value(quota).map_err(|_| ApiError::internal())
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
        "owner_user_id": session.owner_user_id,
        "visibility": session.visibility.as_str(),
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
            ProviderManagerError::Forbidden => Self {
                status: StatusCode::FORBIDDEN,
                error_type: "forbidden_error",
                message: error.to_string(),
            },
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
            ProviderManagerError::Repository(_)
            | ProviderManagerError::ModelCatalog(_)
            | ProviderManagerError::MissingOwner => Self::internal(),
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
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use axum::{
        Router,
        extract::State,
        http::{HeaderMap, StatusCode, header},
        routing::{get, post},
    };
    use provider_auth::{ApiKeyAuthenticator, AuthService, UserSummary};
    use provider_core::{
        AccountId, CredentialKind, ProviderManagementRepository, ProviderQuotaErrorKind,
        ProviderQuotaFreshness, ProviderQuotaSupport, ProxyService,
    };
    use provider_drivers::{grok::GrokDriver, openai_compatible::OpenAiCompatibleDriver};
    use provider_management::{ProviderCredentialReplacement, ProviderManager};
    use provider_protocol::DefaultProtocolBridge;
    use provider_runtime::ProviderRuntimeCatalog;
    use provider_storage::SqliteAccountRepository;
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::Value;
    use tokio::net::TcpListener;

    use crate::router_with_management;

    use super::unix_timestamp;

    #[derive(Clone, Default)]
    struct QuotaUpstreamState {
        billing_calls: Arc<AtomicUsize>,
        user_calls: Arc<AtomicUsize>,
        fail_billing: Arc<AtomicBool>,
    }

    async fn quota_models() -> &'static str {
        r#"{"data":[{"id":"grok-4.5","owned_by":"xai"}]}"#
    }

    async fn quota_user(State(state): State<QuotaUpstreamState>) -> &'static str {
        state.user_calls.fetch_add(1, Ordering::SeqCst);
        r#"{"userId":"upstream-user"}"#
    }

    async fn quota_billing(State(state): State<QuotaUpstreamState>) -> (StatusCode, &'static str) {
        state.billing_calls.fetch_add(1, Ordering::SeqCst);
        if state.fail_billing.load(Ordering::SeqCst) {
            return (StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"failed"}"#);
        }
        (
            StatusCode::OK,
            r#"{"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","start":"2026-07-16T02:27:51+00:00","end":"2026-07-23T02:27:51+00:00"},"creditUsagePercent":75.0,"onDemandCap":{"val":5000},"onDemandUsed":{"val":1250},"productUsage":[{"product":"GrokBuild","usagePercent":70.0}],"prepaidBalance":{"val":3000}}}"#,
        )
    }

    struct QuotaTestContext {
        upstream_state: QuotaUpstreamState,
        upstream_server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
        base_url: String,
        repository: Arc<SqliteAccountRepository>,
        runtime: Arc<ProviderRuntimeCatalog>,
        manager: ProviderManager,
        auth: AuthService,
        owner: UserSummary,
        member: UserSummary,
        member_access_token: SecretString,
        account_id: AccountId,
        now: i64,
    }

    async fn quota_test_context() -> QuotaTestContext {
        let upstream_state = QuotaUpstreamState::default();
        let upstream = Router::new()
            .route("/v1/models", get(quota_models))
            .route("/v1/user", get(quota_user))
            .route("/v1/billing", get(quota_billing))
            .with_state(upstream_state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind quota upstream");
        let address = listener.local_addr().expect("quota upstream address");
        let upstream_server = tokio::spawn(axum::serve(listener, upstream).into_future());
        let base_url = format!("http://{address}/v1");
        let repository = Arc::new(
            SqliteAccountRepository::in_memory()
                .await
                .expect("repository"),
        );
        let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
        runtime
            .register_driver(GrokDriver::for_test(base_url.clone()))
            .expect("register Grok driver");
        let auth = AuthService::new(repository.clone());
        let now = unix_timestamp();
        let owner_grant = auth
            .setup(
                "quota-owner".to_owned(),
                SecretString::from("secret1".to_owned()),
                now,
            )
            .await
            .expect("owner setup");
        let member = auth
            .create_user(
                &owner_grant.user,
                "quota-member".to_owned(),
                SecretString::from("secret2".to_owned()),
                now,
            )
            .await
            .expect("create member");
        let member_grant = auth
            .login(
                "quota-member".to_owned(),
                SecretString::from("secret2".to_owned()),
                now,
            )
            .await
            .expect("member login");
        let manager = ProviderManager::new(repository.clone(), runtime.clone());
        let credential_json = SecretString::from(
            serde_json::json!({
                "type": "xai",
                "auth_kind": "oauth",
                "access_token": "quota-token",
                "refresh_token": "quota-refresh",
                "token_endpoint": "https://auth.x.ai/oauth/token",
                "base_url": base_url.clone(),
                "disabled": false
            })
            .to_string(),
        );
        let created = manager
            .import_grok_account(
                owner_grant.user.id.as_str(),
                "shared Grok".to_owned(),
                credential_json,
                provider_core::ProviderVisibility::Shared,
                now,
            )
            .await
            .expect("create Grok account");

        QuotaTestContext {
            upstream_state,
            upstream_server,
            base_url,
            repository,
            runtime,
            manager,
            auth,
            owner: owner_grant.user,
            member,
            member_access_token: member_grant.access_token,
            account_id: created.account.id,
            now,
        }
    }

    #[tokio::test]
    async fn enforces_provider_ownership_without_returning_credentials() {
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

        let oauth_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind OAuth server");
        let oauth_address = oauth_listener.local_addr().expect("OAuth address");
        let oauth_base_url = format!("http://{oauth_address}");
        let discovery_body = serde_json::json!({
            "device_authorization_endpoint": format!("{oauth_base_url}/device"),
            "token_endpoint": format!("{oauth_base_url}/token")
        })
        .to_string();
        let oauth = Router::new()
            .route(
                "/discovery",
                get(move || {
                    let body = discovery_body.clone();
                    async move { body }
                }),
            )
            .route(
                "/device",
                post(|| async {
                    r#"{"device_code":"device-1","user_code":"CODE-1","verification_uri":"https://accounts.x.ai/device","expires_in":600,"interval":60}"#
                }),
            )
            .route(
                "/token",
                post(|| async { r#"{"error":"authorization_pending"}"# }),
            );
        let oauth_server = tokio::spawn(axum::serve(oauth_listener, oauth).into_future());

        let repository = Arc::new(
            SqliteAccountRepository::in_memory()
                .await
                .expect("repository"),
        );
        let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
        runtime
            .register_driver(Arc::new(OpenAiCompatibleDriver::new()))
            .expect("register driver");
        runtime
            .register_driver(GrokDriver::for_test_with_oauth(
                "http://127.0.0.1/unused",
                format!("{oauth_base_url}/discovery"),
            ))
            .expect("register Grok driver");
        let auth = AuthService::new(repository.clone());
        let grant = auth
            .setup(
                "admin".to_owned(),
                SecretString::from("secret".to_owned()),
                unix_timestamp(),
            )
            .await
            .expect("initial setup");
        auth.create_user(
            &grant.user,
            "member".to_owned(),
            SecretString::from("secret2".to_owned()),
            unix_timestamp(),
        )
        .await
        .expect("create member");
        let member_grant = auth
            .login(
                "member".to_owned(),
                SecretString::from("secret2".to_owned()),
                unix_timestamp(),
            )
            .await
            .expect("member login");
        let access_token = grant.access_token.expose_secret().to_owned();
        let member_access_token = member_grant.access_token.expose_secret().to_owned();
        let api_keys = ApiKeyAuthenticator::load(repository.clone())
            .await
            .expect("API key index");
        let manager = ProviderManager::new(repository, runtime.clone());
        let service = ProxyService::with_router(runtime.clone(), Arc::new(DefaultProtocolBridge));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind management server");
        let address = listener.local_addr().expect("management address");
        let server = tokio::spawn(
            axum::serve(
                listener,
                router_with_management(service, manager, auth, api_keys),
            )
            .into_future(),
        );
        let client = reqwest::Client::new();
        let endpoint = format!("http://{address}/api/v1/providers");
        let base_url = format!("http://{upstream_address}");

        let with_key = client
            .post(&endpoint)
            .bearer_auth(&access_token)
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
        let with_key_body: Value =
            serde_json::from_str(&with_key_body).expect("keyed response JSON");
        let private_account_id = with_key_body["data"]["account"]["id"]
            .as_str()
            .expect("private account ID")
            .to_owned();
        assert_eq!(
            with_key_body["data"]["account"]["owner_user_id"],
            grant.user.id.as_str()
        );
        assert_eq!(with_key_body["data"]["account"]["visibility"], "private");

        let without_key = client
            .post(&endpoint)
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "direct",
                    "provider": "openai_compatible",
                    "label": "without key",
                    "base_url": base_url,
                    "api_key": "",
                    "visibility": "shared"
                })
                .to_string(),
            )
            .send()
            .await
            .expect("create keyless account");
        assert_eq!(without_key.status(), StatusCode::CREATED);
        let without_key_body: Value =
            serde_json::from_slice(&without_key.bytes().await.expect("keyless response body"))
                .expect("keyless response JSON");
        let shared_account_id = without_key_body["data"]["account"]["id"]
            .as_str()
            .expect("shared account ID")
            .to_owned();

        let member_private = client
            .post(&endpoint)
            .bearer_auth(&member_access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "direct",
                    "provider": "openai_compatible",
                    "label": "member private",
                    "base_url": base_url,
                    "api_key": ""
                })
                .to_string(),
            )
            .send()
            .await
            .expect("create member private account");
        assert_eq!(member_private.status(), StatusCode::CREATED);
        let member_private_body: Value = serde_json::from_slice(
            &member_private
                .bytes()
                .await
                .expect("member private response body"),
        )
        .expect("member private response JSON");
        let member_private_id = member_private_body["data"]["account"]["id"]
            .as_str()
            .expect("member private account ID")
            .to_owned();

        let member_accounts = client
            .get(&endpoint)
            .bearer_auth(&member_access_token)
            .send()
            .await
            .expect("member provider list");
        assert_eq!(member_accounts.status(), StatusCode::OK);
        let member_accounts: Value = serde_json::from_slice(
            &member_accounts
                .bytes()
                .await
                .expect("member provider list body"),
        )
        .expect("member provider list JSON");
        let member_account_ids = member_accounts["data"]
            .as_array()
            .expect("member provider list")
            .iter()
            .filter_map(|account| account["id"].as_str())
            .collect::<Vec<_>>();
        assert!(!member_account_ids.contains(&private_account_id.as_str()));
        assert!(member_account_ids.contains(&shared_account_id.as_str()));
        assert!(member_account_ids.contains(&member_private_id.as_str()));

        let hidden_private = client
            .get(format!("{endpoint}/{private_account_id}"))
            .bearer_auth(&member_access_token)
            .send()
            .await
            .expect("hidden private provider");
        assert_eq!(hidden_private.status(), StatusCode::NOT_FOUND);

        let visible_shared = client
            .get(format!("{endpoint}/{shared_account_id}"))
            .bearer_auth(&member_access_token)
            .send()
            .await
            .expect("visible shared provider");
        assert_eq!(visible_shared.status(), StatusCode::OK);

        let shared_models = client
            .get(format!("{endpoint}/{shared_account_id}/models"))
            .bearer_auth(&member_access_token)
            .send()
            .await
            .expect("shared models");
        assert_eq!(shared_models.status(), StatusCode::OK);

        let shared_update = client
            .patch(format!("{endpoint}/{shared_account_id}"))
            .bearer_auth(&member_access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"label":"not allowed"}"#)
            .send()
            .await
            .expect("shared provider update");
        assert_eq!(shared_update.status(), StatusCode::FORBIDDEN);

        let shared_model_update = client
            .patch(format!("{endpoint}/{shared_account_id}/models"))
            .bearer_auth(&member_access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"upstream_model":"model-a","alias":"no","enabled":true}"#)
            .send()
            .await
            .expect("shared model update");
        assert_eq!(shared_model_update.status(), StatusCode::FORBIDDEN);

        let admin_cannot_read_member_private = client
            .get(format!("{endpoint}/{member_private_id}"))
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("admin private access");
        assert_eq!(
            admin_cannot_read_member_private.status(),
            StatusCode::NOT_FOUND
        );

        let oauth_session = client
            .post(format!("http://{address}/api/v1/oauth/sessions"))
            .bearer_auth(&member_access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"provider":"grok","label":"member oauth","visibility":"shared"}"#)
            .send()
            .await
            .expect("start member OAuth");
        assert_eq!(oauth_session.status(), StatusCode::CREATED);
        let oauth_session: Value =
            serde_json::from_slice(&oauth_session.bytes().await.expect("OAuth response body"))
                .expect("OAuth response JSON");
        assert_eq!(
            oauth_session["data"]["owner_user_id"],
            member_grant.user.id.as_str()
        );
        assert_eq!(oauth_session["data"]["visibility"], "shared");
        let oauth_session_id = oauth_session["data"]["id"]
            .as_str()
            .expect("OAuth session ID");
        let oauth_endpoint = format!("http://{address}/api/v1/oauth/sessions/{oauth_session_id}");

        let hidden_oauth = client
            .get(&oauth_endpoint)
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("hidden OAuth session");
        assert_eq!(hidden_oauth.status(), StatusCode::NOT_FOUND);

        let visible_oauth = client
            .get(&oauth_endpoint)
            .bearer_auth(&member_access_token)
            .send()
            .await
            .expect("owner OAuth session");
        assert_eq!(visible_oauth.status(), StatusCode::OK);

        let cancelled_oauth = client
            .delete(&oauth_endpoint)
            .bearer_auth(&member_access_token)
            .send()
            .await
            .expect("cancel OAuth session");
        assert_eq!(cancelled_oauth.status(), StatusCode::OK);

        server.abort();
        upstream_server.abort();
        oauth_server.abort();
        runtime.shutdown();
        assert_eq!(
            authorization.lock().expect("authorization lock").as_slice(),
            ["Bearer do-not-return", "", ""]
        );
    }

    #[tokio::test]
    async fn quota_http_filters_shared_billing_and_forces_refresh() {
        let context = quota_test_context().await;
        let upstream_state = context.upstream_state.clone();
        let repository = context.repository.clone();
        let runtime = context.runtime.clone();
        let manager = context.manager.clone();
        let auth = context.auth.clone();
        let owner = context.owner.clone();
        let member = context.member.clone();
        let member_access_token = context.member_access_token.clone();
        let account_id = context.account_id.clone();
        let now = context.now;

        let first = manager
            .quota(member.id.as_str(), &account_id, now)
            .await
            .expect("member quota");
        assert_eq!(first.support, ProviderQuotaSupport::Supported);
        assert_eq!(first.freshness, Some(ProviderQuotaFreshness::Fresh));
        assert_eq!(
            first
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.groups.len()),
            Some(1)
        );
        assert_eq!(
            first
                .snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.groups.first())
                .map(|group| group.key.as_str()),
            Some("grok")
        );
        let owner_summary = manager
            .get_account(owner.id.as_str(), &account_id)
            .await
            .expect("owner account");
        let owner_quota = manager.cached_quota(owner.id.as_str(), &owner_summary, now);
        assert_eq!(
            owner_quota
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.groups.len()),
            Some(2)
        );
        assert_eq!(upstream_state.user_calls.load(Ordering::SeqCst), 1);
        assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 1);

        let api_keys = ApiKeyAuthenticator::load(repository.clone())
            .await
            .expect("API key index");
        let service = ProxyService::with_router(runtime.clone(), Arc::new(DefaultProtocolBridge));
        let management_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind quota management server");
        let management_address = management_listener
            .local_addr()
            .expect("quota management address");
        let management_server = tokio::spawn(
            axum::serve(
                management_listener,
                router_with_management(service, manager.clone(), auth, api_keys),
            )
            .into_future(),
        );
        let client = reqwest::Client::new();
        let access_token = member_access_token.expose_secret();
        let endpoint = format!("http://{management_address}/api/v1/providers");
        let list_response = client
            .get(&endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .expect("quota provider list");
        let list_response: Value = serde_json::from_slice(
            &list_response
                .bytes()
                .await
                .expect("quota provider list body"),
        )
        .expect("quota provider list JSON");
        assert_eq!(list_response["data"][0]["quota"]["freshness"], "fresh");
        assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 1);
        let quota_response = client
            .get(format!("{endpoint}/{account_id}/quota"))
            .bearer_auth(access_token)
            .send()
            .await
            .expect("quota endpoint");
        let quota_response: Value =
            serde_json::from_slice(&quota_response.bytes().await.expect("quota endpoint body"))
                .expect("quota endpoint JSON");
        assert_eq!(quota_response["data"]["support"], "supported");
        assert_eq!(quota_response["data"]["freshness"], "fresh");
        assert_eq!(
            quota_response["data"]["snapshot"]["groups"][0]["metrics"][0]["breakdown"][0]["key"],
            "grok_build"
        );
        assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 1);
        let refresh_response = client
            .post(format!("{endpoint}/{account_id}/quota/refresh"))
            .bearer_auth(access_token)
            .send()
            .await
            .expect("refresh quota endpoint");
        assert_eq!(refresh_response.status(), StatusCode::OK);
        assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 2);
        management_server.abort();
        context.upstream_server.abort();
        runtime.shutdown();
    }

    #[tokio::test]
    async fn quota_cache_handles_singleflight_backoff_and_credential_replacement() {
        let context = quota_test_context().await;
        let upstream_state = context.upstream_state.clone();
        let repository = context.repository.clone();
        let runtime = context.runtime.clone();
        let manager = context.manager.clone();
        let base_url = context.base_url.clone();
        let owner = context.owner.clone();
        let member = context.member.clone();
        let account_id = context.account_id.clone();
        let now = context.now;

        manager
            .quota(member.id.as_str(), &account_id, now)
            .await
            .expect("initial quota");
        assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 1);

        let (first_refresh, second_refresh) = tokio::join!(
            manager.refresh_quota(member.id.as_str(), &account_id, now + 31),
            manager.refresh_quota(member.id.as_str(), &account_id, now + 31),
        );
        first_refresh.expect("first forced member refresh");
        second_refresh.expect("second forced member refresh");
        assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 2);

        manager
            .set_account_enabled(owner.id.as_str(), &account_id, false, now + 32)
            .await
            .expect("disable account");
        let disabled = manager
            .quota(member.id.as_str(), &account_id, now + 62)
            .await
            .expect("disabled quota");
        assert_eq!(disabled.freshness, Some(ProviderQuotaFreshness::Fresh));
        assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 3);
        assert!(
            !manager
                .get_account(owner.id.as_str(), &account_id)
                .await
                .expect("disabled account")
                .enabled
        );

        upstream_state.fail_billing.store(true, Ordering::SeqCst);
        let stale = manager
            .quota(member.id.as_str(), &account_id, now + 93)
            .await
            .expect("stale quota");
        assert_eq!(stale.freshness, Some(ProviderQuotaFreshness::Stale));
        assert_eq!(stale.last_error, Some(ProviderQuotaErrorKind::Upstream));
        assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 4);
        let backed_off = manager
            .refresh_quota(member.id.as_str(), &account_id, now + 94)
            .await
            .expect("quota failure backoff");
        assert_eq!(backed_off.freshness, Some(ProviderQuotaFreshness::Stale));
        assert_eq!(
            backed_off.last_error,
            Some(ProviderQuotaErrorKind::Upstream)
        );
        assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 4);

        let stored = repository
            .load_provider_account(&account_id)
            .await
            .expect("load account")
            .expect("stored account");
        assert!(
            stored
                .credential
                .credential_json
                .expose_secret()
                .contains("upstream_user_id")
        );
        manager
            .update_credential(
                owner.id.as_str(),
                &account_id,
                ProviderCredentialReplacement {
                    kind: CredentialKind::Oauth,
                    format_version: stored.credential.format_version,
                    credential_json: SecretString::from(
                        serde_json::json!({
                            "type": "xai",
                            "auth_kind": "oauth",
                            "access_token": "replacement-token",
                            "refresh_token": "replacement-refresh",
                            "upstream_user_id": "replacement-user",
                            "token_endpoint": "https://auth.x.ai/oauth/token",
                            "base_url": base_url,
                            "disabled": false
                        })
                        .to_string(),
                    ),
                    expires_at: None,
                    last_refreshed_at: None,
                    updated_at: now + 94,
                },
            )
            .await
            .expect("replace credential");
        let listed = manager
            .list_accounts(member.id.as_str())
            .await
            .expect("member account list");
        let summary = listed
            .iter()
            .find(|account| account.id == account_id)
            .expect("shared account summary");
        let cached = manager.cached_quota(member.id.as_str(), summary, now + 94);
        assert_eq!(cached.support, ProviderQuotaSupport::Supported);
        assert!(cached.snapshot.is_none());
        context.upstream_server.abort();
        runtime.shutdown();
    }
}
