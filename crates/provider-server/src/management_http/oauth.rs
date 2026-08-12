use super::{
    ManagementState,
    shared::{ApiError, data, json_request, require_super_admin},
};
use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::StatusCode,
};
use provider_auth::AuthenticatedSession;
use provider_core::{ProviderKind, ProviderVisibility};
use provider_management::{OAuthSessionSnapshot, OAuthSessionStatus};
use serde::Deserialize;
use serde_json::{Value, json};

pub(super) async fn start_oauth_session(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    request: Result<Json<StartOAuthRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    require_super_admin(&session)?;
    let request = json_request(request)?;
    let session = state
        .manager
        .start_oauth_session(
            session.user.id.as_str(),
            request.provider,
            request.label,
            request.group_label,
            request.priority.unwrap_or(0),
            request.visibility.unwrap_or_default(),
        )
        .await?;
    Ok((StatusCode::CREATED, data(oauth_session_json(&session))))
}

pub(super) async fn get_oauth_session(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_super_admin(&session)?;
    let session = state
        .manager
        .oauth_session(session.user.id.as_str(), &session_id)
        .ok_or_else(ApiError::not_found)?;
    Ok(data(oauth_session_json(&session)))
}

pub(super) async fn cancel_oauth_session(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_super_admin(&session)?;
    let session = state
        .manager
        .cancel_oauth_session(session.user.id.as_str(), &session_id)
        .ok_or_else(ApiError::not_found)?;
    Ok(data(oauth_session_json(&session)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StartOAuthRequest {
    provider: ProviderKind,
    label: String,
    group_label: String,
    priority: Option<u32>,
    visibility: Option<ProviderVisibility>,
}
fn oauth_session_json(session: &OAuthSessionSnapshot) -> Value {
    let status = match session.status {
        OAuthSessionStatus::Pending => "pending",
        OAuthSessionStatus::Provisioning => "provisioning",
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
        "group_label": session.group_label,
        "priority": session.priority,
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
