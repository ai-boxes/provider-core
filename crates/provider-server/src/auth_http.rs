use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, Extension, Path, Request, State, rejection::JsonRejection,
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use provider_auth::{
    ApiKeyAuthenticator, ApiKeyId, ApiKeyPatch, ApiKeySummary, AuthError, AuthService,
    AuthenticatedSession, CreateApiKeyInput, CreatedApiKey, CreatedRegistrationCode,
    CredentialError, SessionGrant, UserId, UserSummary,
};
use provider_management::ProviderManager;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

const SESSION_COOKIE: &str = "pode_session";
pub(crate) const MAX_AUTH_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub(crate) struct AuthHttpState {
    auth: AuthService,
    api_keys: ApiKeyAuthenticator,
    manager: ProviderManager,
    rate_limits: Arc<AuthRateLimits>,
    trusted_proxy_ip: Option<IpAddr>,
}

impl AuthHttpState {
    #[must_use]
    pub(crate) fn new(
        auth: AuthService,
        api_keys: ApiKeyAuthenticator,
        manager: ProviderManager,
        trusted_proxy_ip: Option<IpAddr>,
    ) -> Self {
        Self {
            auth,
            api_keys,
            manager,
            rate_limits: Arc::new(AuthRateLimits {
                trusted_proxy_ip,
                ..AuthRateLimits::default()
            }),
            trusted_proxy_ip,
        }
    }

    #[must_use]
    pub(crate) fn auth_service(&self) -> AuthService {
        self.auth.clone()
    }
}

pub(crate) fn router(state: AuthHttpState) -> Router {
    let session_guard = SessionGuardState {
        auth: state.auth_service(),
    };
    let protected = Router::new()
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/registration-codes", post(create_registration_code))
        .route("/api/v1/users/{user_id}", put(update_user))
        .route("/api/v1/users/{user_id}/password", put(reset_user_password))
        .route("/api/v1/keys", get(list_keys).post(create_key))
        .route(
            "/api/v1/keys/{key_id}",
            get(get_key).put(update_key).delete(delete_key),
        )
        .route_layer(middleware::from_fn_with_state(
            session_guard,
            require_session,
        ));

    let login_route = Router::new()
        .route("/api/v1/auth/login", post(login))
        .route_layer(middleware::from_fn_with_state(
            AuthRateLimitState {
                limits: Arc::clone(&state.rate_limits),
                route: AuthRoute::Login,
            },
            require_auth_rate,
        ));
    let register_route = Router::new()
        .route("/api/v1/auth/register", post(register_user))
        .route_layer(middleware::from_fn_with_state(
            AuthRateLimitState {
                limits: Arc::clone(&state.rate_limits),
                route: AuthRoute::Register,
            },
            require_auth_rate,
        ));
    let setup_post_route = Router::new()
        .route("/api/v1/auth/setup", post(setup))
        .route_layer(middleware::from_fn_with_state(
            AuthRateLimitState {
                limits: Arc::clone(&state.rate_limits),
                route: AuthRoute::Setup,
            },
            require_auth_rate,
        ));

    Router::new()
        .route("/api/v1/auth/setup", get(setup_required))
        .merge(setup_post_route)
        .merge(login_route)
        .merge(register_route)
        .merge(protected)
        .layer(DefaultBodyLimit::max(MAX_AUTH_BODY_BYTES))
        .layer(middleware::from_fn(crate::http::reject_compressed_request))
        .layer(middleware::from_fn_with_state(
            state.trusted_proxy_ip,
            inject_cookie_security,
        ))
        .with_state(state)
}

pub(crate) fn protect(router: Router, auth: AuthService) -> Router {
    router.route_layer(middleware::from_fn_with_state(
        SessionGuardState { auth },
        require_session,
    ))
}

async fn setup_required(State(state): State<AuthHttpState>) -> Result<Json<Value>, AuthApiError> {
    Ok(data(json!({
        "required": state.auth.setup_required().await?
    })))
}

async fn setup(
    State(state): State<AuthHttpState>,
    Extension(cookie_security): Extension<CookieSecurity>,
    request: Result<Json<UserCredentialsRequest>, JsonRejection>,
) -> Result<Response, AuthApiError> {
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
    Ok(session_response(
        StatusCode::CREATED,
        &grant,
        cookie_security.secure,
    ))
}

async fn login(
    State(state): State<AuthHttpState>,
    Extension(cookie_security): Extension<CookieSecurity>,
    request: Result<Json<UserCredentialsRequest>, JsonRejection>,
) -> Result<Response, AuthApiError> {
    let request = json_request(request)?;
    let grant = state
        .auth
        .login(
            request.username,
            SecretString::from(request.password),
            unix_timestamp(),
        )
        .await?;
    Ok(session_response(
        StatusCode::OK,
        &grant,
        cookie_security.secure,
    ))
}

async fn register_user(
    State(state): State<AuthHttpState>,
    Extension(cookie_security): Extension<CookieSecurity>,
    request: Result<Json<RegisterUserRequest>, JsonRejection>,
) -> Result<Response, AuthApiError> {
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
    Ok(session_response(
        StatusCode::CREATED,
        &grant,
        cookie_security.secure,
    ))
}

async fn logout(
    State(state): State<AuthHttpState>,
    Extension(cookie_security): Extension<CookieSecurity>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Response, AuthApiError> {
    state
        .auth
        .logout_session(&session.session_id, unix_timestamp())
        .await?;
    Ok(clear_session_response(cookie_security.secure))
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
        .api_keys
        .set_user_enabled(
            &state.auth,
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

async fn create_key(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
    request: Result<Json<CreateApiKeyRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), AuthApiError> {
    let request = json_request(request)?;
    let key = state
        .api_keys
        .create(CreateApiKeyInput {
            owner_user_id: &session.user.id,
            secret: SecretString::from(request.key),
            group_label: request.group_label,
            label: request.label,
            expires_at: request.expires_at,
            quota_limit_usd: request.quota_limit_usd,
            now: unix_timestamp(),
        })
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
            ApiKeyPatch {
                label: request.label,
                group_label: request.group_label,
                enabled: request.enabled,
                expires_at: request.expires_at.map(|value| value.0),
                quota_limit_usd: request.quota_limit_usd.map(|value| value.0),
                updated_at: unix_timestamp(),
            },
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

#[derive(Clone, Copy)]
struct CookieSecurity {
    secure: bool,
}

#[derive(Clone)]
struct SessionGuardState {
    auth: AuthService,
}

async fn inject_cookie_security(
    State(trusted_proxy_ip): State<Option<IpAddr>>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.0);
    let secure = secure_cookie_for_request(peer, request.headers(), trusted_proxy_ip);
    request.extensions_mut().insert(CookieSecurity { secure });
    next.run(request).await
}

async fn require_session(
    State(state): State<SessionGuardState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthApiError> {
    let token = session_cookie(request.headers())?;
    let session = state
        .auth
        .authenticate_session(token, unix_timestamp())
        .await?;
    request.extensions_mut().insert(session);
    Ok(next.run(request).await)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
struct UpdateUserRequest {
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetUserPasswordRequest {
    password: String,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum AuthRoute {
    Setup,
    Login,
    Register,
}

#[derive(Clone)]
struct AuthRateLimitState {
    limits: Arc<AuthRateLimits>,
    route: AuthRoute,
}

async fn require_auth_rate(
    State(state): State<AuthRateLimitState>,
    request: Request,
    next: Next,
) -> Result<Response, AuthApiError> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.0);
    state.limits.check(state.route, peer, request.headers())?;
    Ok(next.run(request).await)
}

#[derive(Default)]
struct AuthRateLimits {
    windows: Mutex<HashMap<(AuthRoute, IpAddr), (i64, u32)>>,
    trusted_proxy_ip: Option<IpAddr>,
}

impl AuthRateLimits {
    fn check(
        &self,
        route: AuthRoute,
        peer: Option<SocketAddr>,
        headers: &HeaderMap,
    ) -> Result<(), AuthApiError> {
        let ip = client_ip(peer, headers, self.trusted_proxy_ip);
        let now = unix_timestamp();
        let minute = now.div_euclid(60);
        let limit = match route {
            AuthRoute::Setup => 3,
            AuthRoute::Login => 10,
            AuthRoute::Register => 5,
        };
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        windows.retain(|_, (window, _)| *window >= minute);
        let entry = windows.entry((route, ip)).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        if entry.1 >= limit {
            return Err(AuthApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                error_type: "rate_limit_error",
                message: "too many authentication attempts",
            });
        }
        entry.1 += 1;
        Ok(())
    }
}

fn client_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxy_ip: Option<IpAddr>,
) -> IpAddr {
    let peer_ip = peer.map(|peer| peer.ip());
    if peer_ip == trusted_proxy_ip
        && let Some(forwarded) = headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
    {
        return forwarded;
    }
    peer_ip.unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

fn secure_cookie_for_request(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxy_ip: Option<IpAddr>,
) -> bool {
    let peer_ip = peer.map(|peer| peer.ip());
    if peer_ip != trusted_proxy_ip {
        return false;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateApiKeyRequest {
    key: String,
    label: String,
    group_label: String,
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
    request.map(|Json(request)| request).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            AuthApiError::payload_too_large()
        } else {
            AuthApiError::invalid_request("request body must be valid JSON")
        }
    })
}

fn session_cookie(headers: &HeaderMap) -> Result<&str, AuthApiError> {
    let cookies = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(AuthApiError::unauthorized)?;
    let mut session = None;
    for cookie in cookies.split(';') {
        if let Some((name, value)) = cookie.trim().split_once('=')
            && name == SESSION_COOKIE
            && !value.is_empty()
            && session.replace(value).is_some()
        {
            return Err(AuthApiError::unauthorized());
        }
    }
    session.ok_or_else(AuthApiError::unauthorized)
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
        "expires_at": grant.expires_at
    })
}

fn session_response(status: StatusCode, grant: &SessionGrant, secure: bool) -> Response {
    let mut response = (status, data(session_grant_json(grant))).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie_header(
            grant.session_token.expose_secret(),
            grant.expires_at,
            secure,
        ),
    );
    response
}

fn clear_session_response(secure: bool) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let secure = if secure { "; Secure" } else { "" };
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}=; Path=/api/v1; HttpOnly; SameSite=Strict; Max-Age=0{secure}"
        ))
        .expect("static cookie attributes are valid"),
    );
    response
}

fn session_cookie_header(token: &str, expires_at: i64, secure: bool) -> HeaderValue {
    let max_age = expires_at.saturating_sub(unix_timestamp()).max(0);
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/api/v1; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
    ))
    .expect("URL-safe session token makes a valid cookie")
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

fn stored_api_key_json(key: &provider_auth::StoredApiKey) -> Result<Value, AuthApiError> {
    let quota_limit_usd = key
        .quota_limit_atoms
        .as_deref()
        .map(provider_auth::format_usd_atoms)
        .transpose()
        .map_err(|_| AuthApiError::internal())?;
    let spent_usd =
        provider_auth::format_usd_atoms(&key.spent_atoms).map_err(|_| AuthApiError::internal())?;
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

fn api_key_json(key: &ApiKeySummary) -> Result<Value, AuthApiError> {
    let quota_limit_usd = key
        .quota_limit_atoms
        .as_deref()
        .map(provider_auth::format_usd_atoms)
        .transpose()
        .map_err(|_| AuthApiError::internal())?;
    let spent_usd =
        provider_auth::format_usd_atoms(&key.spent_atoms).map_err(|_| AuthApiError::internal())?;
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

#[derive(Debug)]
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

    fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            error_type: "invalid_request_error",
            message: "request body is too large",
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
            | AuthError::InvalidSession
            | AuthError::InvalidApiKey => Self::unauthorized(),
            AuthError::Forbidden => Self::forbidden(),
            AuthError::NotFound => Self::not_found(),
            AuthError::InvalidRegistrationCode => {
                Self::invalid_request("invitation code is invalid or expired")
            }
            AuthError::GroupNotFound => {
                Self::invalid_request("no visible provider accounts use this group label")
            }
            AuthError::InvalidUsername
            | AuthError::InvalidApiKeyValue
            | AuthError::InvalidLabel
            | AuthError::InvalidExpiry
            | AuthError::InvalidQuotaLimit
            | AuthError::InvalidGroup
            | AuthError::Credential(CredentialError::PasswordTooShort)
            | AuthError::Credential(CredentialError::PasswordTooLong) => {
                Self::invalid_request("request validation failed")
            }
            AuthError::QuotaExceeded => Self {
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
mod focused_tests {
    use super::*;

    #[test]
    fn secure_cookie_requires_trusted_proxy_and_https_proto() {
        let trusted: IpAddr = "172.29.250.3".parse().expect("ip");
        let peer = SocketAddr::from(([172, 29, 250, 3], 443));
        let mut headers = HeaderMap::new();
        assert!(!secure_cookie_for_request(
            Some(peer),
            &headers,
            Some(trusted)
        ));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(secure_cookie_for_request(
            Some(peer),
            &headers,
            Some(trusted)
        ));
        let other = SocketAddr::from(([127, 0, 0, 1], 443));
        assert!(!secure_cookie_for_request(
            Some(other),
            &headers,
            Some(trusted)
        ));
        assert!(!secure_cookie_for_request(None, &headers, Some(trusted)));
    }

    #[test]
    fn session_cookie_marks_secure_only_when_requested() {
        let secure = session_cookie_header("opaque", unix_timestamp() + 60, true);
        let secure = secure.to_str().expect("cookie header");
        assert!(secure.starts_with("pode_session=opaque;"));
        assert!(secure.contains("; HttpOnly"));
        assert!(secure.contains("; SameSite=Strict"));
        assert!(secure.contains("; Secure"));

        let plain = session_cookie_header("opaque", unix_timestamp() + 60, false);
        let plain = plain.to_str().expect("cookie header");
        assert!(plain.contains("; HttpOnly"));
        assert!(plain.contains("; SameSite=Strict"));
        assert!(!plain.contains("; Secure"));
    }

    #[test]
    fn api_key_metadata_contains_only_the_masked_secret() {
        let summary = ApiKeySummary {
            id: ApiKeyId::new("key-id").expect("key ID"),
            owner_user_id: UserId::new("owner-id").expect("user ID"),
            group_label: "group".to_owned(),
            label: "label".to_owned(),
            key: "pod************************XYZ".to_owned(),
            enabled: true,
            expires_at: None,
            quota_limit_atoms: None,
            spent_atoms: "0".to_owned(),
            last_used_at: None,
            created_at: 1,
            updated_at: 1,
        };
        let value = api_key_json(&summary).expect("API key JSON");

        assert_eq!(value["key"], "pod************************XYZ");
    }

    #[test]
    fn api_key_detail_contains_the_complete_secret() {
        let key = provider_auth::StoredApiKey {
            id: ApiKeyId::new("key-id").expect("key ID"),
            owner_user_id: UserId::new("owner-id").expect("user ID"),
            group_label: "group".to_owned(),
            label: "label".to_owned(),
            key: SecretString::from("complete-api-key"),
            enabled: true,
            expires_at: None,
            quota_limit_atoms: None,
            spent_atoms: "0".to_owned(),
            last_used_at: None,
            created_at: 1,
            updated_at: 1,
        };
        let value = stored_api_key_json(&key).expect("API key detail JSON");

        assert_eq!(value["key"], "complete-api-key");
    }

    #[test]
    fn setup_has_a_dedicated_tighter_rate_limit() {
        let limits = AuthRateLimits::default();
        let headers = HeaderMap::new();
        let peer = Some("198.51.100.10:1234".parse().expect("peer"));
        for _ in 0..3 {
            assert!(limits.check(AuthRoute::Setup, peer, &headers).is_ok());
        }
        assert!(limits.check(AuthRoute::Setup, peer, &headers).is_err());
        assert!(limits.check(AuthRoute::Login, peer, &headers).is_ok());
    }
}
