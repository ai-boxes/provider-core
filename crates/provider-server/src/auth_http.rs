use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Extension, Path, Request, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    middleware,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use provider_auth::{
    ApiKeyAuthenticator, ApiKeyId, ApiKeySummary, AuthError, AuthService, AuthenticatedSession,
    CreatedApiKey, CreatedRegistrationCode, CredentialError, SessionGrant, StoredApiKey, UserId,
    UserSummary,
};
use provider_management::ProviderManager;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

#[derive(Clone)]
pub(crate) struct AuthHttpState {
    auth: AuthService,
    api_keys: ApiKeyAuthenticator,
    manager: ProviderManager,
}

impl AuthHttpState {
    #[must_use]
    pub(crate) fn new(
        auth: AuthService,
        api_keys: ApiKeyAuthenticator,
        manager: ProviderManager,
    ) -> Self {
        Self {
            auth,
            api_keys,
            manager,
        }
    }

    #[must_use]
    pub(crate) fn auth_service(&self) -> AuthService {
        self.auth.clone()
    }
}

pub(crate) fn router(state: AuthHttpState) -> Router {
    let protected = Router::new()
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/registration-codes", post(create_registration_code))
        .route("/api/v1/users/{user_id}", put(update_user))
        .route("/api/v1/users/{user_id}/password", put(reset_user_password))
        .route("/api/v1/keys", get(list_keys).post(create_key))
        .route("/api/v1/keys/generate", post(generate_key))
        .route(
            "/api/v1/keys/{key_id}",
            get(get_key).put(update_key).delete(delete_key),
        )
        .route_layer(middleware::from_fn_with_state(
            state.auth_service(),
            require_access,
        ));

    Router::new()
        .route("/api/v1/auth/setup", get(setup_required).post(setup))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/register", post(register_user))
        .route("/api/v1/auth/refresh", post(refresh))
        .merge(protected)
        .with_state(state)
}

pub(crate) fn protect(router: Router, auth: AuthService) -> Router {
    router.route_layer(middleware::from_fn_with_state(auth, require_access))
}

async fn setup_required(State(state): State<AuthHttpState>) -> Result<Json<Value>, AuthApiError> {
    Ok(data(json!({
        "required": state.auth.setup_required().await?
    })))
}

async fn setup(
    State(state): State<AuthHttpState>,
    request: Result<Json<UserCredentialsRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), AuthApiError> {
    let request = json_request(request)?;
    let grant = state
        .auth
        .setup(
            request.username,
            SecretString::from(request.password),
            unix_timestamp(),
        )
        .await?;
    state
        .manager
        .claim_unowned_account_access(grant.user.id.as_str());
    Ok((StatusCode::CREATED, data(session_grant_json(&grant))))
}

async fn login(
    State(state): State<AuthHttpState>,
    request: Result<Json<UserCredentialsRequest>, JsonRejection>,
) -> Result<Json<Value>, AuthApiError> {
    let request = json_request(request)?;
    let grant = state
        .auth
        .login(
            request.username,
            SecretString::from(request.password),
            unix_timestamp(),
        )
        .await?;
    Ok(data(session_grant_json(&grant)))
}

async fn register_user(
    State(state): State<AuthHttpState>,
    request: Result<Json<RegisterUserRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), AuthApiError> {
    let request = json_request(request)?;
    let grant = state
        .auth
        .register_user(
            &request.invitation_code,
            request.username,
            SecretString::from(request.password),
            unix_timestamp(),
        )
        .await?;
    Ok((StatusCode::CREATED, data(session_grant_json(&grant))))
}

async fn refresh(
    State(state): State<AuthHttpState>,
    request: Result<Json<RefreshRequest>, JsonRejection>,
) -> Result<Json<Value>, AuthApiError> {
    let request = json_request(request)?;
    let grant = state
        .auth
        .refresh(&request.refresh_token, unix_timestamp())
        .await?;
    Ok(data(session_grant_json(&grant)))
}

async fn logout(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<StatusCode, AuthApiError> {
    state
        .auth
        .logout_session(&session.session_id, unix_timestamp())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me(Extension(session): Extension<AuthenticatedSession>) -> Json<Value> {
    data(user_json(&session.user))
}

async fn list_users(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<Value>, AuthApiError> {
    let users = state.auth.list_users(&session.user).await?;
    Ok(data(Value::Array(users.iter().map(user_json).collect())))
}

async fn create_user(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
    request: Result<Json<UserCredentialsRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), AuthApiError> {
    let request = json_request(request)?;
    let user = state
        .auth
        .create_user(
            &session.user,
            request.username,
            SecretString::from(request.password),
            unix_timestamp(),
        )
        .await?;
    Ok((StatusCode::CREATED, data(user_json(&user))))
}

async fn create_registration_code(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<(StatusCode, Json<Value>), AuthApiError> {
    let code = state
        .auth
        .create_registration_code(&session.user, unix_timestamp())
        .await?;
    Ok((
        StatusCode::CREATED,
        data(created_registration_code_json(&code)),
    ))
}

async fn update_user(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(user_id): Path<String>,
    request: Result<Json<UpdateUserRequest>, JsonRejection>,
) -> Result<Json<Value>, AuthApiError> {
    let request = json_request(request)?;
    let user = state
        .auth
        .set_user_enabled(
            &session.user,
            &parse_user_id(&user_id)?,
            request.enabled,
            unix_timestamp(),
        )
        .await?;
    Ok(data(user_json(&user)))
}

async fn reset_user_password(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(user_id): Path<String>,
    request: Result<Json<ResetUserPasswordRequest>, JsonRejection>,
) -> Result<Json<Value>, AuthApiError> {
    let request = json_request(request)?;
    let user = state
        .auth
        .reset_user_password(
            &session.user,
            &parse_user_id(&user_id)?,
            SecretString::from(request.password),
            unix_timestamp(),
        )
        .await?;
    Ok(data(user_json(&user)))
}

async fn list_keys(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<Value>, AuthApiError> {
    let keys = state.api_keys.list(&session.user.id).await?;
    Ok(data(Value::Array(
        keys.iter().map(api_key_json).collect::<Result<_, _>>()?,
    )))
}

async fn generate_key(
    Extension(_session): Extension<AuthenticatedSession>,
) -> Result<Json<Value>, AuthApiError> {
    let key = provider_auth::issue_api_key(None).map_err(|_| AuthApiError::internal())?;
    Ok(data(json!({
        "key": key.secret.expose_secret()
    })))
}

async fn create_key(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
    request: Result<Json<CreateApiKeyRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), AuthApiError> {
    let request = json_request(request)?;
    let key = state
        .api_keys
        .create(
            &session.user.id,
            request.group_label,
            request.label,
            request.key.map(SecretString::from),
            request.expires_at,
            request.quota_limit_usd,
            unix_timestamp(),
        )
        .await?;
    Ok((StatusCode::CREATED, data(created_api_key_json(&key)?)))
}

async fn get_key(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(key_id): Path<String>,
) -> Result<Json<Value>, AuthApiError> {
    let key = state
        .api_keys
        .get(&session.user.id, &parse_api_key_id(&key_id)?)
        .await?;
    Ok(data(stored_api_key_json(&key)?))
}

async fn update_key(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(key_id): Path<String>,
    request: Result<Json<UpdateApiKeyRequest>, JsonRejection>,
) -> Result<Json<Value>, AuthApiError> {
    let request = json_request(request)?;
    if request.enabled.is_none()
        && request.label.is_none()
        && request.group_label.is_none()
        && request.expires_at.is_none()
        && request.quota_limit_usd.is_none()
    {
        return Err(AuthApiError::invalid_request(
            "at least one API key field must be provided",
        ));
    }
    let key = state
        .api_keys
        .update(
            &session.user.id,
            &parse_api_key_id(&key_id)?,
            request.label,
            request.group_label,
            request.enabled,
            request.expires_at.map(|value| value.0),
            request.quota_limit_usd.map(|value| value.0),
            unix_timestamp(),
        )
        .await?;
    Ok(data(api_key_json(&key)?))
}

async fn delete_key(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(key_id): Path<String>,
) -> Result<StatusCode, AuthApiError> {
    state
        .api_keys
        .delete(&session.user.id, &parse_api_key_id(&key_id)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn require_access(
    State(auth): State<AuthService>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthApiError> {
    let token = bearer_token(&headers)?;
    let session = auth.authenticate_access(token, unix_timestamp()).await?;
    request.extensions_mut().insert(session);
    Ok(next.run(request).await)
}

#[derive(Deserialize)]
struct UserCredentialsRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterUserRequest {
    username: String,
    password: String,
    invitation_code: String,
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    enabled: bool,
}

#[derive(Deserialize)]
struct ResetUserPasswordRequest {
    password: String,
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateApiKeyRequest {
    label: String,
    group_label: String,
    key: Option<String>,
    expires_at: Option<i64>,
    /// Positive USD decimal string, or omitted for unlimited.
    quota_limit_usd: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateApiKeyRequest {
    label: Option<String>,
    group_label: Option<String>,
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_optional_expiry")]
    expires_at: Option<NullableExpiry>,
    #[serde(default, deserialize_with = "deserialize_optional_quota")]
    quota_limit_usd: Option<NullableQuota>,
}

struct NullableQuota(Option<String>);

struct NullableExpiry(Option<i64>);

fn deserialize_optional_expiry<'de, D>(deserializer: D) -> Result<Option<NullableExpiry>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<i64>::deserialize(deserializer).map(|value| Some(NullableExpiry(value)))
}

fn deserialize_optional_quota<'de, D>(deserializer: D) -> Result<Option<NullableQuota>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| Some(NullableQuota(value)))
}

fn json_request<T>(request: Result<Json<T>, JsonRejection>) -> Result<T, AuthApiError> {
    request
        .map(|Json(request)| request)
        .map_err(|_| AuthApiError::invalid_request("request body must be valid JSON"))
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, AuthApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(AuthApiError::unauthorized)?;
    let mut parts = value.split_whitespace();
    let scheme = parts.next().ok_or_else(AuthApiError::unauthorized)?;
    let token = parts.next().ok_or_else(AuthApiError::unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || parts.next().is_some() {
        return Err(AuthApiError::unauthorized());
    }
    Ok(token)
}

fn parse_api_key_id(value: &str) -> Result<ApiKeyId, AuthApiError> {
    ApiKeyId::new(value).map_err(|_| AuthApiError::invalid_request("invalid API key ID"))
}

fn parse_user_id(value: &str) -> Result<UserId, AuthApiError> {
    UserId::new(value).map_err(|_| AuthApiError::invalid_request("invalid user ID"))
}

fn session_grant_json(grant: &SessionGrant) -> Value {
    json!({
        "user": user_json(&grant.user),
        "access_token": grant.access_token.expose_secret(),
        "refresh_token": grant.refresh_token.expose_secret(),
        "access_expires_at": grant.access_expires_at,
        "refresh_expires_at": grant.refresh_expires_at
    })
}

fn user_json(user: &UserSummary) -> Value {
    json!({
        "id": user.id.as_str(),
        "username": user.username,
        "role": user.role.as_str(),
        "enabled": user.enabled,
        "created_at": user.created_at,
        "updated_at": user.updated_at
    })
}

fn created_registration_code_json(code: &CreatedRegistrationCode) -> Value {
    json!({
        "code": code.code.expose_secret(),
        "expires_at": code.expires_at
    })
}

fn created_api_key_json(created: &CreatedApiKey) -> Result<Value, AuthApiError> {
    let mut value = api_key_json(&created.summary)?;
    value["key"] = Value::String(created.key.expose_secret().to_owned());
    Ok(value)
}

fn api_key_json(key: &ApiKeySummary) -> Result<Value, AuthApiError> {
    let quota_limit_usd = key
        .quota_limit_atoms
        .as_deref()
        .map(provider_auth::format_usd_atoms)
        .transpose()
        .map_err(|()| AuthApiError::internal())?;
    let spent_usd =
        provider_auth::format_usd_atoms(&key.spent_atoms).map_err(|()| AuthApiError::internal())?;
    Ok(json!({
        "id": key.id.as_str(),
        "owner_user_id": key.owner_user_id.as_str(),
        "group_label": key.group_label,
        "label": key.label,
        "key": key.key,
        "enabled": key.enabled,
        "expires_at": key.expires_at,
        "quota_limit_usd": quota_limit_usd,
        "spent_usd": spent_usd,
        "last_used_at": key.last_used_at,
        "created_at": key.created_at,
        "updated_at": key.updated_at
    }))
}

fn stored_api_key_json(key: &StoredApiKey) -> Result<Value, AuthApiError> {
    let quota_limit_usd = key
        .quota_limit_atoms
        .as_deref()
        .map(provider_auth::format_usd_atoms)
        .transpose()
        .map_err(|()| AuthApiError::internal())?;
    let spent_usd =
        provider_auth::format_usd_atoms(&key.spent_atoms).map_err(|()| AuthApiError::internal())?;
    Ok(json!({
        "id": key.id.as_str(),
        "owner_user_id": key.owner_user_id.as_str(),
        "group_label": key.group_label,
        "label": key.label,
        "key": key.key.expose_secret(),
        "enabled": key.enabled,
        "expires_at": key.expires_at,
        "quota_limit_usd": quota_limit_usd,
        "spent_usd": spent_usd,
        "last_used_at": key.last_used_at,
        "created_at": key.created_at,
        "updated_at": key.updated_at
    }))
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

struct AuthApiError {
    status: StatusCode,
    error_type: &'static str,
    message: &'static str,
}

impl AuthApiError {
    fn invalid_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error_type: "invalid_request_error",
            message,
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error_type: "authorization_error",
            message: "forbidden",
        }
    }

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error_type: "not_found_error",
            message: "resource was not found",
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error_type: "authentication_error",
            message: "authentication failed",
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error_type: "api_error",
            message: "internal server error",
        }
    }
}

impl From<AuthError> for AuthApiError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::AlreadyConfigured | AuthError::Conflict => Self {
                status: StatusCode::CONFLICT,
                error_type: "conflict_error",
                message: "resource already exists",
            },
            AuthError::InvalidCredentials
            | AuthError::InvalidAccessToken
            | AuthError::InvalidRefreshToken
            | AuthError::InvalidApiKey
            | AuthError::Credential(CredentialError::SessionExpired) => Self::unauthorized(),
            AuthError::Forbidden => Self::forbidden(),
            AuthError::NotFound => Self::not_found(),
            AuthError::InvalidRegistrationCode => {
                Self::invalid_request("invitation code is invalid or expired")
            }
            AuthError::GroupNotFound => {
                Self::invalid_request("no visible provider accounts use this group label")
            }
            AuthError::InvalidUsername
            | AuthError::InvalidLabel
            | AuthError::InvalidExpiry
            | AuthError::InvalidQuotaLimit
            | AuthError::InvalidGroup
            | AuthError::Credential(CredentialError::PasswordTooShort)
            | AuthError::Credential(CredentialError::PasswordTooLong)
            | AuthError::Credential(CredentialError::ApiKeyTooShort)
            | AuthError::Credential(CredentialError::ApiKeyTooLong) => {
                Self::invalid_request("request validation failed")
            }
            AuthError::QuotaExceeded | AuthError::QuotaInFlight => Self {
                status: StatusCode::TOO_MANY_REQUESTS,
                error_type: "insufficient_quota",
                message: "API key USD quota has been exhausted",
            },
            AuthError::PasswordTask
            | AuthError::QuotaLedgerUnavailable
            | AuthError::Repository(_)
            | AuthError::Credential(CredentialError::RandomSource)
            | AuthError::Credential(CredentialError::PasswordHash)
            | AuthError::Credential(CredentialError::TimestampOutOfRange) => Self::internal(),
        }
    }
}

impl IntoResponse for AuthApiError {
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
    use std::sync::Arc;

    use provider_core::{
        AccountId, CredentialKind, NewCredential, NewProviderAccount, ProviderKind,
        ProviderManagementRepository, ProviderVisibility,
    };
    use provider_management::ProviderManager;
    use provider_runtime::ProviderRuntimeCatalog;
    use provider_storage::SqliteAccountRepository;
    use tokio::net::TcpListener;

    use super::*;

    async fn seed_account_with_group(
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

    #[tokio::test]
    async fn auth_lifecycle_manages_retrievable_api_keys() {
        let repository = Arc::new(
            SqliteAccountRepository::in_memory()
                .await
                .expect("repository"),
        );
        let auth = AuthService::new(repository.clone());
        let api_keys = ApiKeyAuthenticator::load(repository.clone())
            .await
            .expect("API key index");
        let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
        let manager = ProviderManager::new(repository.clone(), runtime.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind auth server");
        let address = listener.local_addr().expect("auth address");
        let server = tokio::spawn(
            axum::serve(
                listener,
                router(AuthHttpState::new(auth, api_keys, manager)),
            )
            .into_future(),
        );
        let client = reqwest::Client::new();
        let base_url = format!("http://{address}");

        let setup_status = client
            .get(format!("{base_url}/api/v1/auth/setup"))
            .send()
            .await
            .expect("setup status");
        assert_eq!(setup_status.status(), StatusCode::OK);
        assert_eq!(response_json(setup_status).await["data"]["required"], true);

        let unauthenticated_me = client
            .get(format!("{base_url}/api/v1/auth/me"))
            .send()
            .await
            .expect("unauthenticated me");
        assert_eq!(unauthenticated_me.status(), StatusCode::UNAUTHORIZED);

        let setup = post_json(
            &client,
            format!("{base_url}/api/v1/auth/setup"),
            json!({ "username": "Admin", "password": "secret" }),
            None,
        )
        .await;
        assert_eq!(setup.status(), StatusCode::CREATED);
        let setup_body = response_json(setup).await;
        let access_token = response_secret(&setup_body, "access_token");
        let refresh_token = response_secret(&setup_body, "refresh_token");
        assert_eq!(setup_body["data"]["user"]["username"], "Admin");
        assert!(!setup_body.to_string().contains("password_hash"));

        let me = client
            .get(format!("{base_url}/api/v1/auth/me"))
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("authenticated me");
        assert_eq!(me.status(), StatusCode::OK);

        let unauthenticated_generation = post_json(
            &client,
            format!("{base_url}/api/v1/keys/generate"),
            json!({}),
            None,
        )
        .await;
        assert_eq!(
            unauthenticated_generation.status(),
            StatusCode::UNAUTHORIZED
        );

        let generated_key = post_json(
            &client,
            format!("{base_url}/api/v1/keys/generate"),
            json!({}),
            Some(&access_token),
        )
        .await;
        assert_eq!(generated_key.status(), StatusCode::OK);
        let generated_key = response_json(generated_key).await;
        let generated_key = generated_key["data"]["key"]
            .as_str()
            .expect("generated API key");
        assert_eq!(generated_key.len(), 43);
        assert!(
            generated_key.chars().all(
                |character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            )
        );
        let keys_after_generation = client
            .get(format!("{base_url}/api/v1/keys"))
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("list API keys after generation");
        assert_eq!(keys_after_generation.status(), StatusCode::OK);
        assert_eq!(
            response_json(keys_after_generation).await["data"]
                .as_array()
                .expect("API key list after generation")
                .len(),
            0
        );

        let owner_id = setup_body["data"]["user"]["id"]
            .as_str()
            .expect("setup user ID")
            .to_owned();
        seed_account_with_group(
            repository.clone(),
            &UserId::new(owner_id.clone()).expect("user ID"),
            "acct-auth-1",
            "shared-codex",
        )
        .await;
        let custom_key = "custom-key-12345";
        let created_key = post_json(
            &client,
            format!("{base_url}/api/v1/keys"),
            json!({
                "label": "local",
                "key": custom_key,
                "group_label": "shared-codex",
                "quota_limit_usd": "12.5"
            }),
            Some(&access_token),
        )
        .await;
        assert_eq!(created_key.status(), StatusCode::CREATED);
        let created_key = response_json(created_key).await;
        assert_eq!(created_key["data"]["key"], custom_key);
        assert_eq!(created_key["data"]["group_label"], "shared-codex");
        assert_eq!(created_key["data"]["quota_limit_usd"], "12.50000000000000");
        assert_eq!(created_key["data"]["spent_usd"], "0.00000000000000");
        let key_id = created_key["data"]["id"]
            .as_str()
            .expect("API key ID")
            .to_owned();

        let listed_keys = client
            .get(format!("{base_url}/api/v1/keys"))
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("list API keys");
        assert_eq!(listed_keys.status(), StatusCode::OK);
        let listed_keys = response_json(listed_keys).await;
        assert_eq!(listed_keys["data"][0]["key"], "cus**********345");
        assert!(!listed_keys.to_string().contains(custom_key));

        let retrieved_key = client
            .get(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("retrieve API key");
        assert_eq!(retrieved_key.status(), StatusCode::OK);
        assert_eq!(
            response_json(retrieved_key).await["data"]["key"],
            custom_key
        );

        let registration_code = client
            .post(format!("{base_url}/api/v1/registration-codes"))
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("create registration code");
        assert_eq!(registration_code.status(), StatusCode::CREATED);
        let registration_code = response_secret(&response_json(registration_code).await, "code");
        let conflicting_registration = post_json(
            &client,
            format!("{base_url}/api/v1/auth/register"),
            json!({
                "username": "ADMIN",
                "password": "secret2",
                "invitation_code": registration_code.clone()
            }),
            None,
        )
        .await;
        assert_eq!(conflicting_registration.status(), StatusCode::CONFLICT);
        let created_member = post_json(
            &client,
            format!("{base_url}/api/v1/auth/register"),
            json!({
                "username": "member",
                "password": "secret2",
                "invitation_code": registration_code.clone()
            }),
            None,
        )
        .await;
        assert_eq!(created_member.status(), StatusCode::CREATED);
        let created_member_body = response_json(created_member).await;
        let member_access = response_secret(&created_member_body, "access_token");
        assert_eq!(created_member_body["data"]["user"]["username"], "member");
        let reused_code = post_json(
            &client,
            format!("{base_url}/api/v1/auth/register"),
            json!({
                "username": "second-member",
                "password": "secret3",
                "invitation_code": registration_code
            }),
            None,
        )
        .await;
        assert_eq!(reused_code.status(), StatusCode::BAD_REQUEST);
        let malformed_code = post_json(
            &client,
            format!("{base_url}/api/v1/auth/register"),
            json!({
                "username": "third-member",
                "password": "secret4",
                "invitation_code": "not-a-code"
            }),
            None,
        )
        .await;
        assert_eq!(malformed_code.status(), StatusCode::BAD_REQUEST);

        let unauthenticated_code = client
            .post(format!("{base_url}/api/v1/registration-codes"))
            .send()
            .await
            .expect("reject unauthenticated registration code creation");
        assert_eq!(unauthenticated_code.status(), StatusCode::UNAUTHORIZED);

        let forbidden_code = client
            .post(format!("{base_url}/api/v1/registration-codes"))
            .bearer_auth(&member_access)
            .send()
            .await
            .expect("reject member registration code creation");
        assert_eq!(forbidden_code.status(), StatusCode::FORBIDDEN);

        let foreign_read = client
            .get(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&member_access)
            .send()
            .await
            .expect("foreign API key read");
        assert_eq!(foreign_read.status(), StatusCode::NOT_FOUND);

        let foreign_update = client
            .put(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&member_access)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"enabled":false}"#)
            .send()
            .await
            .expect("foreign API key update");
        assert_eq!(foreign_update.status(), StatusCode::NOT_FOUND);

        seed_account_with_group(
            repository.clone(),
            &UserId::new(owner_id.clone()).expect("user ID"),
            "acct-auth-2",
            "shared-claude",
        )
        .await;
        let renamed = client
            .put(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                json!({
                    "label": "renamed-local",
                    "group_label": "shared-claude",
                    "quota_limit_usd": "20"
                })
                .to_string(),
            )
            .send()
            .await
            .expect("update API key label and group");
        assert_eq!(renamed.status(), StatusCode::OK);
        let renamed = response_json(renamed).await;
        assert_eq!(renamed["data"]["label"], "renamed-local");
        assert_eq!(renamed["data"]["group_label"], "shared-claude");
        assert_eq!(renamed["data"]["quota_limit_usd"], "20.00000000000000");

        let unlimited = client
            .put(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"quota_limit_usd":null}"#)
            .send()
            .await
            .expect("clear API key quota");
        assert_eq!(unlimited.status(), StatusCode::OK);
        let unlimited = response_json(unlimited).await;
        assert_eq!(unlimited["data"]["quota_limit_usd"], Value::Null);
        assert_eq!(unlimited["data"]["spent_usd"], "0.00000000000000");

        for quota_limit_usd in ["", "0", "-1", "1.000000000000001"] {
            let invalid_quota = client
                .put(format!("{base_url}/api/v1/keys/{key_id}"))
                .bearer_auth(&access_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(json!({ "quota_limit_usd": quota_limit_usd }).to_string())
                .send()
                .await
                .expect("reject invalid API key quota");
            assert_eq!(invalid_quota.status(), StatusCode::BAD_REQUEST);
        }

        let unknown_field = client
            .put(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"quota_limit":10,"enabled":true}"#)
            .send()
            .await
            .expect("reject unknown API key field");
        assert_eq!(unknown_field.status(), StatusCode::BAD_REQUEST);

        let expires_at = unix_timestamp() + 3600;
        let updated_expiry = client
            .put(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json!({ "expires_at": expires_at }).to_string())
            .send()
            .await
            .expect("update API key expiry");
        assert_eq!(updated_expiry.status(), StatusCode::OK);
        let updated_expiry = response_json(updated_expiry).await;
        assert_eq!(updated_expiry["data"]["expires_at"], expires_at);
        assert_eq!(updated_expiry["data"]["enabled"], true);
        assert_eq!(updated_expiry["data"]["key"], "cus**********345");

        let invalid_expiry = client
            .put(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json!({ "expires_at": unix_timestamp() - 1 }).to_string())
            .send()
            .await
            .expect("reject expired API key expiry");
        assert_eq!(invalid_expiry.status(), StatusCode::BAD_REQUEST);

        let disabled = client
            .put(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"enabled":false}"#)
            .send()
            .await
            .expect("disable API key");
        assert_eq!(disabled.status(), StatusCode::OK);
        assert_eq!(response_json(disabled).await["data"]["enabled"], false);

        let invalid_group = client
            .put(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"enabled":false,"group_label":"missing"}"#)
            .send()
            .await
            .expect("reject missing provider group for disabled API key");
        assert_eq!(invalid_group.status(), StatusCode::BAD_REQUEST);

        let old_enabled_route = client
            .put(format!("{base_url}/api/v1/keys/{key_id}/enabled"))
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"enabled":true}"#)
            .send()
            .await
            .expect("old API key enabled route");
        assert_eq!(old_enabled_route.status(), StatusCode::NOT_FOUND);

        let cleared_expiry = client
            .put(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"enabled":true,"expires_at":null}"#)
            .send()
            .await
            .expect("clear API key expiry");
        assert_eq!(cleared_expiry.status(), StatusCode::OK);
        let cleared_expiry = response_json(cleared_expiry).await;
        assert_eq!(cleared_expiry["data"]["enabled"], true);
        assert_eq!(cleared_expiry["data"]["expires_at"], Value::Null);

        let empty_update = client
            .put(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body("{}")
            .send()
            .await
            .expect("empty API key update");
        assert_eq!(empty_update.status(), StatusCode::BAD_REQUEST);

        let deleted = client
            .delete(format!("{base_url}/api/v1/keys/{key_id}"))
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("delete API key");
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

        let remaining_keys = client
            .get(format!("{base_url}/api/v1/keys"))
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("list remaining API keys");
        assert_eq!(
            response_json(remaining_keys).await["data"]
                .as_array()
                .expect("remaining API keys")
                .len(),
            0
        );

        let refreshed = post_json(
            &client,
            format!("{base_url}/api/v1/auth/refresh"),
            json!({ "refresh_token": refresh_token }),
            None,
        )
        .await;
        assert_eq!(refreshed.status(), StatusCode::OK);
        let refreshed_body = response_json(refreshed).await;
        let rotated_access = response_secret(&refreshed_body, "access_token");
        let rotated_refresh = response_secret(&refreshed_body, "refresh_token");
        assert_ne!(rotated_access, access_token);
        assert_ne!(rotated_refresh, refresh_token);

        let reused_refresh = post_json(
            &client,
            format!("{base_url}/api/v1/auth/refresh"),
            json!({ "refresh_token": refresh_token }),
            None,
        )
        .await;
        assert_eq!(reused_refresh.status(), StatusCode::UNAUTHORIZED);

        let logout = client
            .post(format!("{base_url}/api/v1/auth/logout"))
            .bearer_auth(&rotated_access)
            .send()
            .await
            .expect("logout");
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);

        let logged_out_me = client
            .get(format!("{base_url}/api/v1/auth/me"))
            .bearer_auth(&rotated_access)
            .send()
            .await
            .expect("logged out me");
        assert_eq!(logged_out_me.status(), StatusCode::UNAUTHORIZED);

        server.abort();
        runtime.shutdown();
    }

    #[tokio::test]
    async fn super_admin_manages_users_and_revokes_sessions_on_password_reset() {
        let repository = Arc::new(
            SqliteAccountRepository::in_memory()
                .await
                .expect("repository"),
        );
        let auth = AuthService::new(repository.clone());
        let api_keys = ApiKeyAuthenticator::load(repository.clone())
            .await
            .expect("API key index");
        let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
        let manager = ProviderManager::new(repository.clone(), runtime.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind auth server");
        let address = listener.local_addr().expect("auth address");
        let server = tokio::spawn(
            axum::serve(
                listener,
                router(AuthHttpState::new(auth, api_keys, manager)),
            )
            .into_future(),
        );
        let client = reqwest::Client::new();
        let base_url = format!("http://{address}");

        let setup = post_json(
            &client,
            format!("{base_url}/api/v1/auth/setup"),
            json!({ "username": "Admin", "password": "secret" }),
            None,
        )
        .await;
        assert_eq!(setup.status(), StatusCode::CREATED);
        let setup_body = response_json(setup).await;
        let admin_access = response_secret(&setup_body, "access_token");
        let admin_id = setup_body["data"]["user"]["id"]
            .as_str()
            .expect("admin user ID")
            .to_owned();

        let created_member = post_json(
            &client,
            format!("{base_url}/api/v1/users"),
            json!({ "username": "Member", "password": "secret2" }),
            Some(&admin_access),
        )
        .await;
        assert_eq!(created_member.status(), StatusCode::CREATED);
        let created_member = response_json(created_member).await;
        assert_eq!(created_member["data"]["username"], "Member");
        assert_eq!(created_member["data"]["role"], "user");
        assert_eq!(created_member["data"]["enabled"], true);
        let member_id = created_member["data"]["id"]
            .as_str()
            .expect("member user ID")
            .to_owned();

        let listed_users = client
            .get(format!("{base_url}/api/v1/users"))
            .bearer_auth(&admin_access)
            .send()
            .await
            .expect("list users");
        assert_eq!(listed_users.status(), StatusCode::OK);
        assert_eq!(
            response_json(listed_users).await["data"]
                .as_array()
                .expect("user list")
                .len(),
            2
        );

        let member_login = post_json(
            &client,
            format!("{base_url}/api/v1/auth/login"),
            json!({ "username": "Member", "password": "secret2" }),
            None,
        )
        .await;
        assert_eq!(member_login.status(), StatusCode::OK);
        let member_login = response_json(member_login).await;
        let member_access = response_secret(&member_login, "access_token");

        let forbidden_list = client
            .get(format!("{base_url}/api/v1/users"))
            .bearer_auth(&member_access)
            .send()
            .await
            .expect("member list users");
        assert_eq!(forbidden_list.status(), StatusCode::FORBIDDEN);

        let self_disable = client
            .put(format!("{base_url}/api/v1/users/{admin_id}"))
            .bearer_auth(&admin_access)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"enabled":false}"#)
            .send()
            .await
            .expect("self disable");
        assert_eq!(self_disable.status(), StatusCode::FORBIDDEN);

        let disabled_member = client
            .put(format!("{base_url}/api/v1/users/{member_id}"))
            .bearer_auth(&admin_access)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"enabled":false}"#)
            .send()
            .await
            .expect("disable member");
        assert_eq!(disabled_member.status(), StatusCode::OK);
        assert_eq!(
            response_json(disabled_member).await["data"]["enabled"],
            false
        );

        let disabled_login = post_json(
            &client,
            format!("{base_url}/api/v1/auth/login"),
            json!({ "username": "Member", "password": "secret2" }),
            None,
        )
        .await;
        assert_eq!(disabled_login.status(), StatusCode::UNAUTHORIZED);

        let disabled_me = client
            .get(format!("{base_url}/api/v1/auth/me"))
            .bearer_auth(&member_access)
            .send()
            .await
            .expect("disabled member me");
        assert_eq!(disabled_me.status(), StatusCode::UNAUTHORIZED);

        let enabled_member = client
            .put(format!("{base_url}/api/v1/users/{member_id}"))
            .bearer_auth(&admin_access)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"enabled":true}"#)
            .send()
            .await
            .expect("enable member");
        assert_eq!(enabled_member.status(), StatusCode::OK);
        assert_eq!(response_json(enabled_member).await["data"]["enabled"], true);

        let member_login = post_json(
            &client,
            format!("{base_url}/api/v1/auth/login"),
            json!({ "username": "Member", "password": "secret2" }),
            None,
        )
        .await;
        assert_eq!(member_login.status(), StatusCode::OK);
        let member_access = response_secret(&response_json(member_login).await, "access_token");

        let reset_password = client
            .put(format!("{base_url}/api/v1/users/{member_id}/password"))
            .bearer_auth(&admin_access)
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"password":"secret3"}"#)
            .send()
            .await
            .expect("reset member password");
        assert_eq!(reset_password.status(), StatusCode::OK);
        assert!(
            !response_json(reset_password)
                .await
                .to_string()
                .contains("secret3")
        );

        let revoked_me = client
            .get(format!("{base_url}/api/v1/auth/me"))
            .bearer_auth(&member_access)
            .send()
            .await
            .expect("revoked member me");
        assert_eq!(revoked_me.status(), StatusCode::UNAUTHORIZED);

        let old_password_login = post_json(
            &client,
            format!("{base_url}/api/v1/auth/login"),
            json!({ "username": "Member", "password": "secret2" }),
            None,
        )
        .await;
        assert_eq!(old_password_login.status(), StatusCode::UNAUTHORIZED);

        let new_password_login = post_json(
            &client,
            format!("{base_url}/api/v1/auth/login"),
            json!({ "username": "Member", "password": "secret3" }),
            None,
        )
        .await;
        assert_eq!(new_password_login.status(), StatusCode::OK);

        server.abort();
        runtime.shutdown();
    }

    async fn post_json(
        client: &reqwest::Client,
        url: String,
        body: Value,
        bearer: Option<&str>,
    ) -> reqwest::Response {
        let mut request = client
            .post(url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        request.send().await.expect("JSON response")
    }

    async fn response_json(response: reqwest::Response) -> Value {
        serde_json::from_slice(&response.bytes().await.expect("response body"))
            .expect("response JSON")
    }

    fn response_secret(response: &Value, field: &str) -> String {
        response["data"][field]
            .as_str()
            .expect("secret response field")
            .to_owned()
    }
}
