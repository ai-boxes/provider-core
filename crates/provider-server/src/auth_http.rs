use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Extension, Request, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    middleware,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use provider_auth::{
    ApiKeyAuthenticator, ApiKeySummary, AuthError, AuthService, AuthenticatedSession,
    CreatedApiKey, CredentialError, SessionGrant, UserSummary,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone)]
pub(crate) struct AuthHttpState {
    auth: AuthService,
    api_keys: ApiKeyAuthenticator,
}

impl AuthHttpState {
    #[must_use]
    pub(crate) fn new(auth: AuthService, api_keys: ApiKeyAuthenticator) -> Self {
        Self { auth, api_keys }
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
        .route("/api/v1/keys", get(list_keys).post(create_key))
        .route_layer(middleware::from_fn_with_state(
            state.auth_service(),
            require_access,
        ));

    Router::new()
        .route("/api/v1/auth/setup", get(setup_required).post(setup))
        .route("/api/v1/auth/login", post(login))
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

async fn list_keys(
    State(state): State<AuthHttpState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<Value>, AuthApiError> {
    let keys = state.api_keys.list(&session.user.id).await?;
    Ok(data(Value::Array(keys.iter().map(api_key_json).collect())))
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
            request.label,
            request.key.map(SecretString::from),
            request.expires_at,
            unix_timestamp(),
        )
        .await?;
    Ok((StatusCode::CREATED, data(created_api_key_json(&key))))
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
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Deserialize)]
struct CreateApiKeyRequest {
    label: String,
    key: Option<String>,
    expires_at: Option<i64>,
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

fn session_grant_json(grant: &SessionGrant) -> Value {
    json!({
        "user": user_json(&grant.user),
        "access_token": grant.access_token.expose_secret(),
        "refresh_token": grant.refresh_token.expose_secret(),
        "access_expires_at": grant.access_expires_at,
        "refresh_expires_at": grant.refresh_expires_at,
        "absolute_expires_at": grant.absolute_expires_at
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

fn created_api_key_json(created: &CreatedApiKey) -> Value {
    let mut value = api_key_json(&created.summary);
    value["key"] = Value::String(created.key.expose_secret().to_owned());
    value
}

fn api_key_json(key: &ApiKeySummary) -> Value {
    json!({
        "id": key.id.as_str(),
        "owner_user_id": key.owner_user_id.as_str(),
        "label": key.label,
        "enabled": key.enabled,
        "expires_at": key.expires_at,
        "last_used_at": key.last_used_at,
        "created_at": key.created_at,
        "updated_at": key.updated_at
    })
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
            AuthError::Forbidden => Self {
                status: StatusCode::FORBIDDEN,
                error_type: "forbidden_error",
                message: "operation is not allowed",
            },
            AuthError::NotFound => Self {
                status: StatusCode::NOT_FOUND,
                error_type: "not_found_error",
                message: "resource was not found",
            },
            AuthError::InvalidUsername
            | AuthError::InvalidLabel
            | AuthError::InvalidExpiry
            | AuthError::Credential(CredentialError::PasswordTooShort)
            | AuthError::Credential(CredentialError::PasswordTooLong)
            | AuthError::Credential(CredentialError::ApiKeyTooShort)
            | AuthError::Credential(CredentialError::ApiKeyTooLong) => {
                Self::invalid_request("request validation failed")
            }
            AuthError::PasswordTask
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

    use provider_storage::SqliteAccountRepository;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn auth_lifecycle_rotates_secrets_and_never_lists_api_key_plaintext() {
        let repository = Arc::new(
            SqliteAccountRepository::in_memory()
                .await
                .expect("repository"),
        );
        let auth = AuthService::new(repository.clone());
        let api_keys = ApiKeyAuthenticator::load(repository)
            .await
            .expect("API key index");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind auth server");
        let address = listener.local_addr().expect("auth address");
        let server = tokio::spawn(
            axum::serve(listener, router(AuthHttpState::new(auth, api_keys))).into_future(),
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
        assert_eq!(setup_body["data"]["user"]["username"], "admin");
        assert!(!setup_body.to_string().contains("password_hash"));

        let me = client
            .get(format!("{base_url}/api/v1/auth/me"))
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("authenticated me");
        assert_eq!(me.status(), StatusCode::OK);

        let custom_key = "custom-key-12345";
        let created_key = post_json(
            &client,
            format!("{base_url}/api/v1/keys"),
            json!({ "label": "local", "key": custom_key }),
            Some(&access_token),
        )
        .await;
        assert_eq!(created_key.status(), StatusCode::CREATED);
        assert_eq!(response_json(created_key).await["data"]["key"], custom_key);

        let listed_keys = client
            .get(format!("{base_url}/api/v1/keys"))
            .bearer_auth(&access_token)
            .send()
            .await
            .expect("list API keys");
        assert_eq!(listed_keys.status(), StatusCode::OK);
        assert!(
            !listed_keys
                .text()
                .await
                .expect("API key list body")
                .contains(custom_key)
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
