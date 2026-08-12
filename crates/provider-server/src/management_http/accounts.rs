use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::StatusCode,
};
use provider_auth::AuthenticatedSession;
use provider_core::{
    ProviderAccountSummary, ProviderAccountUpdate, ProviderKind, ProviderVisibility,
};
use provider_drivers::compatible_api_key_credential;
use provider_management::{
    CreatedProviderAccount, CredentialProviderAccountInput, DirectProviderAccountInput,
    ProviderCredentialReplacement,
};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    ManagementState,
    models::model_snapshot_json,
    shared::{ApiError, data, json_request, parse_account_id, require_super_admin, unix_timestamp},
};

pub(super) async fn list_accounts(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<Value>, ApiError> {
    let accounts = state
        .manager
        .list_accounts(session.user.id.as_str())
        .await?;
    let now = unix_timestamp();
    let mut values = Vec::with_capacity(accounts.len());
    for account in &accounts {
        let quota = state
            .manager
            .cached_quota(session.user.id.as_str(), account, now)
            .await;
        values.push(account_with_quota_json(account, quota));
    }
    Ok(data(Value::Array(values)))
}

pub(super) async fn get_account(
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

pub(super) async fn create_account(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    request: Result<Json<CreateAccountRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    require_super_admin(&session)?;
    let request = json_request(request)?;
    let created = match request {
        CreateAccountRequest::CredentialJson {
            provider,
            label,
            group_label,
            credential_json,
            priority,
            visibility,
        } => {
            state
                .manager
                .create_credential_account(
                    session.user.id.as_str(),
                    CredentialProviderAccountInput {
                        kind: provider,
                        label,
                        group_label,
                        priority: priority.unwrap_or(0),
                        credential_json: SecretString::from(json_document(credential_json)),
                        visibility: visibility.unwrap_or_default(),
                    },
                    unix_timestamp(),
                )
                .await?
        }
        CreateAccountRequest::Direct {
            provider,
            label,
            group_label,
            base_url,
            api_key,
            priority,
            visibility,
        } => {
            state
                .manager
                .create_direct_account(
                    session.user.id.as_str(),
                    DirectProviderAccountInput {
                        kind: provider,
                        label,
                        group_label,
                        priority: priority.unwrap_or(0),
                        config_json: json!({ "base_url": base_url }).to_string(),
                        api_key: SecretString::from(api_key),
                        visibility: visibility.unwrap_or_default(),
                    },
                    unix_timestamp(),
                )
                .await?
        }
    };
    Ok((StatusCode::CREATED, data(created_account_json(&created))))
}

pub(super) async fn update_account(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
    request: Result<Json<UpdateAccountRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    require_super_admin(&session)?;
    let request = json_request(request)?;
    let UpdateAccountRequest {
        label,
        group_label,
        base_url,
        visibility,
        priority,
        api_key,
    } = request;
    if label.is_none()
        && group_label.is_none()
        && base_url.is_none()
        && visibility.is_none()
        && priority.is_none()
        && api_key.is_none()
    {
        return Err(ApiError::invalid_request(
            "account update requires label, group_label, base_url, visibility, priority, or api_key",
        ));
    }
    let account_id = parse_account_id(&account_id)?;
    let current = state
        .manager
        .get_account(session.user.id.as_str(), &account_id)
        .await?;
    if api_key.is_some()
        && !matches!(
            current.provider,
            ProviderKind::OpenAiCompatible | ProviderKind::AnthropicCompatible
        )
    {
        return Err(ApiError::invalid_request(
            "api_key updates are only supported for compatible providers",
        ));
    }
    let replacement = api_key
        .map(|value| {
            let value = value.trim().to_owned();
            if value.is_empty() {
                return Err(ApiError::invalid_request("api_key must not be empty"));
            }
            let (kind, format_version, credential_json) =
                compatible_api_key_credential(SecretString::from(value))
                    .map_err(|error| ApiError::invalid_request(error.message().to_owned()))?;
            Ok(ProviderCredentialReplacement {
                kind,
                format_version,
                credential_json,
                expires_at: None,
                last_refreshed_at: None,
                updated_at: unix_timestamp(),
            })
        })
        .transpose()?;
    let metadata_requested = label.is_some()
        || group_label.is_some()
        || base_url.is_some()
        || visibility.is_some()
        || priority.is_some();
    let metadata = if metadata_requested {
        let label = label.unwrap_or_else(|| current.label.clone());
        let group_label = group_label.unwrap_or_else(|| current.group_label.clone());
        let config_json = if let Some(base_url) = base_url {
            let mut config: Value =
                serde_json::from_str(&current.config_json).map_err(|_| ApiError::internal())?;
            let config = config.as_object_mut().ok_or_else(ApiError::internal)?;
            config.insert("base_url".to_owned(), Value::String(base_url));
            Value::Object(config.clone()).to_string()
        } else {
            current.config_json.clone()
        };
        Some(ProviderAccountUpdate {
            label,
            group_label,
            priority: priority.unwrap_or(current.priority),
            config_json,
            visibility: visibility.unwrap_or(current.visibility),
            updated_at: unix_timestamp(),
        })
    } else {
        None
    };
    let account = match (metadata, replacement) {
        (Some(metadata), Some(replacement)) => {
            state
                .manager
                .update_account_with_credential(
                    session.user.id.as_str(),
                    &account_id,
                    metadata,
                    replacement,
                )
                .await?
        }
        (Some(metadata), None) => {
            state
                .manager
                .update_account(session.user.id.as_str(), &account_id, metadata)
                .await?
        }
        (None, Some(replacement)) => {
            state
                .manager
                .update_credential(session.user.id.as_str(), &account_id, replacement)
                .await?
        }
        (None, None) => return Err(ApiError::invalid_request("account update is empty")),
    };
    Ok(data(account_json(&account)))
}

pub(super) async fn set_account_enabled(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
    request: Result<Json<SetEnabledRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    require_super_admin(&session)?;
    let request = json_request(request)?;
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

pub(super) async fn delete_account(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_super_admin(&session)?;
    state
        .manager
        .delete_account(session.user.id.as_str(), &parse_account_id(&account_id)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum CreateAccountRequest {
    CredentialJson {
        provider: ProviderKind,
        label: String,
        group_label: String,
        credential_json: Value,
        priority: Option<u32>,
        visibility: Option<ProviderVisibility>,
    },
    Direct {
        provider: ProviderKind,
        label: String,
        group_label: String,
        base_url: String,
        api_key: String,
        priority: Option<u32>,
        visibility: Option<ProviderVisibility>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpdateAccountRequest {
    label: Option<String>,
    group_label: Option<String>,
    base_url: Option<String>,
    visibility: Option<ProviderVisibility>,
    priority: Option<u32>,
    api_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetEnabledRequest {
    pub(super) enabled: bool,
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
        "group_label": account.group_label,
        "priority": account.priority,
        "config": serde_json::from_str::<Value>(&account.config_json)
            .expect("stored provider config must be valid JSON"),
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
    value
        .as_object_mut()
        .expect("provider account response must be an object")
        .insert(
            "quota".to_owned(),
            serde_json::to_value(quota).expect("provider quota must serialize"),
        );
    value
}
fn json_document(value: Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}
