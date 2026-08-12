use super::{
    ManagementState,
    shared::{ApiError, data, parse_account_id, require_super_admin, unix_timestamp},
};
use axum::{
    Json,
    extract::{Extension, Path, State},
};
use provider_auth::AuthenticatedSession;
use serde_json::Value;

pub(super) async fn get_quota(
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

pub(super) async fn refresh_quota(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_super_admin(&session)?;
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
fn quota_json(quota: &provider_core::ProviderQuotaView) -> Result<Value, ApiError> {
    serde_json::to_value(quota).map_err(|_| ApiError::internal())
}
