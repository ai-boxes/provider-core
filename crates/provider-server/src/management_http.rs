use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{
        Extension, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use provider_auth::{AuthenticatedSession, UserRole};
use provider_core::{
    AccountId, ProviderAccountSummary, ProviderAccountUpdate, ProviderKind, ProviderModelOverride,
    ProviderModelPricing, ProviderVisibility, StoredProviderModel,
};
use provider_drivers::compatible_api_key_credential;
use provider_management::{
    CreatedProviderAccount, CredentialProviderAccountInput, DirectProviderAccountInput,
    ModelCatalogError, ModelCatalogSnapshot, OAuthSessionSnapshot, OAuthSessionStatus,
    ProviderCredentialReplacement, ProviderManager, ProviderManagerError,
};
use provider_usage::{
    ProviderHealthSummary, TimeRange, TimeRangeError, canonical_model_pricing, system_clock_ms,
};
use secrecy::SecretString;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

#[derive(Clone)]
struct ManagementState {
    manager: ProviderManager,
    usage: Option<crate::UsageServices>,
}

pub(crate) fn router(manager: ProviderManager, usage: Option<crate::UsageServices>) -> Router {
    Router::new()
        .route("/api/v1/providers", get(list_accounts).post(create_account))
        .route("/api/v1/providers/health", get(list_provider_health))
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
        .with_state(ManagementState { manager, usage })
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

async fn list_provider_health(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    params: Result<Query<ProviderHealthParams>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let params = query_request(params)?;
    let usage = state.usage.as_ref().ok_or_else(ApiError::internal)?;
    let accounts = state
        .manager
        .list_accounts(session.user.id.as_str())
        .await?;
    let range = params.range()?;
    let account_ids = accounts
        .iter()
        .map(|account| account.id.as_str().to_owned())
        .collect::<Vec<_>>();
    let summaries = usage
        .query
        .provider_health(&account_ids, range)
        .await
        .map_err(|_| ApiError::internal())?;
    let summaries = summaries
        .into_iter()
        .map(|summary| (summary.account_id.clone(), summary))
        .collect::<HashMap<_, _>>();

    let values = accounts
        .iter()
        .map(|account| {
            let summary = summaries.get(account.id.as_str());
            provider_health_json(account.id.as_str(), summary, range)
        })
        .collect::<Vec<_>>();

    Ok(data(json!({
        "from_ms": range.from_ms,
        "to_ms": range.to_ms,
        "accounts": values,
    })))
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

async fn update_account(
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
        api_key,
    } = request;
    if label.is_none()
        && group_label.is_none()
        && base_url.is_none()
        && visibility.is_none()
        && api_key.is_none()
    {
        return Err(ApiError::invalid_request(
            "account update requires label, group_label, base_url, visibility, or api_key",
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
    let metadata_requested =
        label.is_some() || group_label.is_some() || base_url.is_some() || visibility.is_some();
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

async fn set_account_enabled(
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

async fn delete_account(
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
    require_super_admin(&session)?;
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

async fn update_model(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
    request: Result<Json<UpdateModelRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    require_super_admin(&session)?;
    let request = json_request(request)?;
    let upstream_model = request.upstream_model.as_str();
    if upstream_model.is_empty() || upstream_model.trim() != upstream_model {
        return Err(ApiError::invalid_request(
            "upstream_model must not be empty or contain surrounding whitespace",
        ));
    }
    let alias = request
        .alias
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let pricing = updated_pricing(request.pricing_changed, request.pricing)?;
    let models = state
        .manager
        .update_model(
            session.user.id.as_str(),
            &parse_account_id(&account_id)?,
            upstream_model,
            ProviderModelOverride {
                alias,
                enabled: request.enabled,
                pricing,
                updated_at: unix_timestamp(),
            },
        )
        .await?;
    Ok(data(Value::Array(models.iter().map(model_json).collect())))
}

async fn start_oauth_session(
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
    require_super_admin(&session)?;
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
    require_super_admin(&session)?;
    let session = state
        .manager
        .cancel_oauth_session(session.user.id.as_str(), &session_id)
        .ok_or_else(ApiError::not_found)?;
    Ok(data(oauth_session_json(&session)))
}

fn require_super_admin(session: &AuthenticatedSession) -> Result<(), ApiError> {
    if session.user.role == UserRole::SuperAdmin {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum CreateAccountRequest {
    CredentialJson {
        provider: ProviderKind,
        label: String,
        group_label: String,
        credential_json: Value,
        visibility: Option<ProviderVisibility>,
    },
    Direct {
        provider: ProviderKind,
        label: String,
        group_label: String,
        base_url: String,
        api_key: String,
        visibility: Option<ProviderVisibility>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateAccountRequest {
    label: Option<String>,
    group_label: Option<String>,
    base_url: Option<String>,
    visibility: Option<ProviderVisibility>,
    api_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetEnabledRequest {
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderHealthParams {
    from_ms: Option<i64>,
    to_ms: Option<i64>,
}

impl ProviderHealthParams {
    fn range(&self) -> Result<TimeRange, ApiError> {
        let to_ms = self.to_ms.unwrap_or_else(system_clock_ms);
        let from_ms = self.from_ms.unwrap_or(to_ms - 24 * 60 * 60 * 1000);
        TimeRange::new(from_ms, to_ms).map_err(|error| match error {
            TimeRangeError::Empty => ApiError::invalid_request("to_ms must be after from_ms"),
            TimeRangeError::TooWide => {
                ApiError::invalid_request("range is wider than usage is retained for")
            }
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateModelRequest {
    upstream_model: String,
    alias: Option<String>,
    enabled: bool,
    pricing_changed: bool,
    #[serde(default)]
    pricing: ModelPricingPatch,
}

#[derive(Default)]
enum ModelPricingPatch {
    #[default]
    Missing,
    Null,
    Value(Box<UpdateModelPricingRequest>),
}

impl<'de> Deserialize<'de> for ModelPricingPatch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<UpdateModelPricingRequest>::deserialize(deserializer)
            .map(|pricing| pricing.map_or(Self::Null, |value| Self::Value(Box::new(value))))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateModelPricingRequest {
    input: Value,
    output: Value,
    cache_read: Value,
    cache_write: Value,
    reasoning: Value,
    input_audio: Value,
    output_audio: Value,
    tiers: Vec<UpdateModelPricingTierRequest>,
}

impl UpdateModelPricingRequest {
    fn into_model_pricing(self) -> Option<ProviderModelPricing> {
        Some(ProviderModelPricing {
            input: nullable_price(self.input)?,
            output: nullable_price(self.output)?,
            cache_read: nullable_price(self.cache_read)?,
            cache_write: nullable_price(self.cache_write)?,
            reasoning: nullable_price(self.reasoning)?,
            input_audio: nullable_price(self.input_audio)?,
            output_audio: nullable_price(self.output_audio)?,
            tiers: self
                .tiers
                .into_iter()
                .map(UpdateModelPricingTierRequest::into_model_pricing_tier)
                .collect::<Option<Vec<_>>>()?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateModelPricingTierRequest {
    threshold_tokens: u64,
    input: Value,
    output: Value,
    cache_read: Value,
    cache_write: Value,
    reasoning: Value,
    input_audio: Value,
    output_audio: Value,
}

impl UpdateModelPricingTierRequest {
    fn into_model_pricing_tier(self) -> Option<provider_core::ProviderModelPricingTier> {
        Some(provider_core::ProviderModelPricingTier {
            threshold_tokens: self.threshold_tokens,
            input: nullable_price(self.input)?,
            output: nullable_price(self.output)?,
            cache_read: nullable_price(self.cache_read)?,
            cache_write: nullable_price(self.cache_write)?,
            reasoning: nullable_price(self.reasoning)?,
            input_audio: nullable_price(self.input_audio)?,
            output_audio: nullable_price(self.output_audio)?,
        })
    }
}

fn nullable_price(value: Value) -> Option<Option<String>> {
    match value {
        Value::Null => Some(None),
        Value::String(value) => Some(Some(value)),
        _ => None,
    }
}

fn updated_pricing(
    pricing_changed: bool,
    pricing: ModelPricingPatch,
) -> Result<Option<Option<ProviderModelPricing>>, ApiError> {
    if !pricing_changed {
        return match pricing {
            ModelPricingPatch::Missing => Ok(None),
            ModelPricingPatch::Null | ModelPricingPatch::Value(_) => Err(
                ApiError::invalid_request("pricing must be omitted when pricing_changed is false"),
            ),
        };
    }

    match pricing {
        ModelPricingPatch::Missing => Err(ApiError::invalid_request(
            "pricing is required when pricing_changed is true",
        )),
        ModelPricingPatch::Null => Ok(Some(None)),
        ModelPricingPatch::Value(pricing) => {
            let pricing = (*pricing).into_model_pricing().ok_or_else(|| {
                ApiError::invalid_request("pricing fields must be decimal strings or null")
            })?;
            let pricing = canonical_model_pricing(&pricing).ok_or_else(|| {
                ApiError::invalid_request(
                    "pricing and tiers must contain valid plain non-negative decimals with strictly increasing thresholds",
                )
            })?;
            Ok(Some(Some(pricing)))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartOAuthRequest {
    provider: ProviderKind,
    label: String,
    group_label: String,
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
        "group_label": account.group_label,
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

fn provider_health_json(
    account_id: &str,
    summary: Option<&ProviderHealthSummary>,
    _range: TimeRange,
) -> Value {
    json!({
        "account_id": account_id,
        "requests": summary.map_or(0, |summary| summary.requests),
        "successes": summary.map_or(0, |summary| summary.successes),
        "failures": summary.map_or(0, |summary| summary.failures),
    })
}

fn quota_json(quota: &provider_core::ProviderQuotaView) -> Result<Value, ApiError> {
    serde_json::to_value(quota).map_err(|_| ApiError::internal())
}

fn model_snapshot_json(snapshot: &ModelCatalogSnapshot) -> Value {
    json!({
        "models": snapshot.models.iter().map(model_json).collect::<Vec<_>>()
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
        "metadata": serde_json::from_str::<Value>(&model.metadata_json)
            .expect("stored provider model metadata must be valid JSON"),
        "pricing": model.pricing.as_ref().map(|record| &record.pricing),
        "last_seen_at": model.last_seen_at,
        "created_at": model.created_at,
        "updated_at": model.updated_at
    })
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

fn json_request<T>(request: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    request.map(|Json(request)| request).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::payload_too_large()
        } else {
            ApiError::invalid_request("request body must be valid JSON")
        }
    })
}

fn query_request<T>(request: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    request
        .map(|Query(request)| request)
        .map_err(|_| ApiError::invalid_request("query parameters are invalid"))
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after unix epoch")
        .as_secs()
        .try_into()
        .expect("unix timestamp must fit i64")
}

struct ApiError {
    status: StatusCode,
    error_type: &'static str,
    message: String,
}

impl ApiError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error_type: "invalid_request_error",
            message: message.into(),
        }
    }

    fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            error_type: "invalid_request_error",
            message: "request body is too large".to_owned(),
        }
    }

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error_type: "not_found_error",
            message: "resource was not found".to_owned(),
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error_type: "forbidden_error",
            message: "super_admin role is required".to_owned(),
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
            ProviderManagerError::ModelCatalog(ModelCatalogError::Discovery(_)) => Self {
                status: StatusCode::BAD_GATEWAY,
                error_type: "upstream_error",
                message: error.to_string(),
            },
            ProviderManagerError::Repository(_) | ProviderManagerError::MissingOwner => {
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
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use axum::{
        Router,
        extract::State,
        http::{HeaderMap, HeaderValue, StatusCode, header},
        routing::{get, post},
    };
    use provider_auth::{
        ApiKeyAuthenticator, AuthService, AuthenticatedSession, SessionId, UserId, UserRole,
        UserSummary,
    };
    use provider_core::{
        AccountId, CredentialKind, ProviderKind, ProviderManagementRepository,
        ProviderQuotaErrorKind, ProviderQuotaFreshness, ProviderQuotaSupport, ProxyService,
    };
    use provider_drivers::{
        codex::CodexDriver, grok::GrokDriver, openai_compatible::OpenAiCompatibleDriver,
    };
    use provider_management::{
        CredentialProviderAccountInput, ProviderCredentialReplacement, ProviderManager,
    };
    use provider_protocol::DefaultProtocolBridge;
    use provider_runtime::ProviderRuntimeCatalog;
    use provider_storage::SqliteAccountRepository;
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::Value;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::{
        TlsAcceptor,
        rustls::{ServerConfig, pki_types::PrivateKeyDer},
    };

    use crate::{
        auth_http::MAX_AUTH_BODY_BYTES, http::MAX_MANAGEMENT_BODY_BYTES, router_with_management,
    };

    use super::{
        ModelPricingPatch, ProviderHealthParams, SetEnabledRequest, UpdateModelRequest,
        require_super_admin, unix_timestamp, updated_pricing,
    };

    fn management_headers(session_token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("pode_session={session_token}"))
                .expect("session cookie"),
        );
        headers
    }

    fn padded_json(prefix: &str, suffix: &str, size: usize) -> String {
        let padding = size
            .checked_sub(prefix.len() + suffix.len())
            .expect("requested JSON size");
        let mut body = String::with_capacity(size);
        body.push_str(prefix);
        body.extend(std::iter::repeat_n('a', padding));
        body.push_str(suffix);
        assert_eq!(body.len(), size);
        body
    }

    async fn assert_api_error(response: reqwest::Response, status: StatusCode, message: &str) {
        assert_eq!(response.status(), status);
        let body: Value = serde_json::from_str(
            &response
                .text()
                .await
                .expect("read management error response"),
        )
        .expect("management error response JSON");
        assert_eq!(body["error"]["type"], "invalid_request_error");
        assert_eq!(body["error"]["message"], message);
    }

    #[test]
    fn provider_mutations_require_super_admin() {
        let session = |role| AuthenticatedSession {
            session_id: SessionId::new("provider-role-test").expect("session ID"),
            user: UserSummary {
                id: UserId::new("provider-role-user").expect("user ID"),
                username: "provider-role-user".to_owned(),
                role,
                enabled: true,
                created_at: 1,
                updated_at: 1,
            },
        };
        assert!(require_super_admin(&session(UserRole::SuperAdmin)).is_ok());
        let error = require_super_admin(&session(UserRole::User)).expect_err("ordinary user");
        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn management_requests_reject_unknown_fields() {
        assert!(
            serde_json::from_str::<SetEnabledRequest>(r#"{"enabled":true,"extra":true}"#,).is_err()
        );
        assert!(serde_json::from_str::<ProviderHealthParams>(
            r#"{"from_ms":1,"to_ms":2,"extra":true}"#,
        )
        .is_err());
    }

    #[test]
    fn model_update_pricing_request_is_strict_and_preserves_field_presence() {
        let missing: UpdateModelRequest = serde_json::from_str(
            r#"{"upstream_model":"model-a","alias":null,"enabled":true,"pricing_changed":false}"#,
        )
        .expect("missing pricing field");
        assert!(matches!(missing.pricing, ModelPricingPatch::Missing));

        let null: UpdateModelRequest = serde_json::from_str(
            r#"{"upstream_model":"model-a","alias":null,"enabled":true,"pricing_changed":true,"pricing":null}"#,
        )
        .expect("explicit null pricing");
        assert!(matches!(null.pricing, ModelPricingPatch::Null));

        let value: UpdateModelRequest = serde_json::from_str(
            r#"{"upstream_model":"model-a","alias":null,"enabled":true,"pricing_changed":true,"pricing":{"input":"1","output":"2","cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[{"threshold_tokens":200000,"input":"2","output":"4","cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null}]}}"#,
        )
        .expect("complete pricing object");
        let ModelPricingPatch::Value(value) = value.pricing else {
            panic!("pricing value");
        };
        let pricing = value.into_model_pricing().expect("valid pricing fields");
        assert_eq!(pricing.tiers.len(), 1);
        assert_eq!(pricing.tiers[0].threshold_tokens, 200_000);

        assert!(
            serde_json::from_str::<UpdateModelRequest>(
                r#"{"upstream_model":"model-a","alias":null,"enabled":true,"pricing_changed":true,"pricing":{"input":"1","output":"2","cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[{"threshold_tokens":200000,"input":"2","output":"4","cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"extra":true}]}}"#,
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<UpdateModelRequest>(
                r#"{"upstream_model":"model-a","alias":null,"enabled":true,"pricing_changed":true,"pricing":{"input":"1","output":"2"}}"#,
            )
            .is_err()
        );

        assert!(matches!(
            updated_pricing(false, ModelPricingPatch::Missing),
            Ok(None)
        ));
        assert!(updated_pricing(false, ModelPricingPatch::Null).is_err());
        assert!(updated_pricing(true, ModelPricingPatch::Missing).is_err());
        assert!(matches!(
            updated_pricing(true, ModelPricingPatch::Null),
            Ok(Some(None))
        ));
    }

    async fn captured_models(
        State(authorization): State<Arc<Mutex<Vec<String>>>>,
        headers: HeaderMap,
    ) -> &'static str {
        authorization.lock().expect("authorization lock").push(
            headers
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
        );
        r#"{"data":[{"id":"model-a","owned_by":"test"}]}"#
    }

    async fn spawn_compatible_tls_upstream(
        authorization: Arc<Mutex<Vec<String>>>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let certified = rcgen::generate_simple_self_signed(vec!["api.example.test".to_owned()])
            .expect("compatible test certificate");
        let certificate = certified.cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .expect("compatible TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind compatible TLS upstream");
        let address = listener
            .local_addr()
            .expect("compatible TLS upstream address");
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let authorization = authorization.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut request = Vec::new();
                    let mut chunk = [0_u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                        if request.len() > 64 * 1024 {
                            return;
                        }
                    }
                    let request = String::from_utf8_lossy(&request);
                    let mut lines = request.lines();
                    let path = lines
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or_default();
                    let request_authorization = lines
                        .find_map(|line| {
                            line.split_once(':').and_then(|(name, value)| {
                                name.eq_ignore_ascii_case("authorization")
                                    .then(|| value.trim().to_owned())
                            })
                        })
                        .unwrap_or_default();
                    let (status, body) = if path == "/broken/models" {
                        ("502 Bad Gateway", r#"{"error":"failed"}"#)
                    } else {
                        authorization
                            .lock()
                            .expect("authorization lock")
                            .push(request_authorization);
                        ("200 OK", r#"{"data":[{"id":"model-a","owned_by":"test"}]}"#)
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (address, server)
    }

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
        owner_session_token: SecretString,
        member: UserSummary,
        member_session_token: SecretString,
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
            .create_credential_account(
                owner_grant.user.id.as_str(),
                CredentialProviderAccountInput {
                    kind: ProviderKind::Grok,
                    label: "shared Grok".to_owned(),
                    group_label: "default".to_owned(),
                    credential_json,
                    visibility: provider_core::ProviderVisibility::Shared,
                },
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
            owner_session_token: owner_grant.session_token,
            member,
            member_session_token: member_grant.session_token,
            account_id: created.account.id,
            now,
        }
    }

    #[tokio::test]
    async fn enforces_provider_ownership_without_returning_credentials() {
        let authorization = Arc::new(Mutex::new(Vec::<String>::new()));
        let upstream = Router::new()
            .route("/codex/models", get(captured_models))
            .with_state(authorization.clone());
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let upstream_server = tokio::spawn(axum::serve(upstream_listener, upstream).into_future());
        let (compatible_address, compatible_server) =
            spawn_compatible_tls_upstream(authorization.clone()).await;
        let compatible_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs("api.example.test", &[compatible_address])
            .build()
            .expect("compatible test client");

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
            .register_driver(OpenAiCompatibleDriver::for_test(compatible_client))
            .expect("register driver");
        runtime
            .register_driver(GrokDriver::for_test_with_oauth(
                "http://127.0.0.1/unused",
                format!("{oauth_base_url}/discovery"),
            ))
            .expect("register Grok driver");
        runtime
            .register_driver(CodexDriver::for_test(
                &format!("http://{upstream_address}"),
                &oauth_base_url,
            ))
            .expect("register Codex driver");
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
        let session_token = grant.session_token.expose_secret().to_owned();
        let member_session_token = member_grant.session_token.expose_secret().to_owned();
        let api_keys = ApiKeyAuthenticator::load(repository.clone())
            .await
            .expect("API key index");
        let manager = ProviderManager::new(repository.clone(), runtime.clone());
        let service = ProxyService::with_router(runtime.clone(), Arc::new(DefaultProtocolBridge));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind management server");
        let address = listener.local_addr().expect("management address");
        let server = tokio::spawn(
            axum::serve(
                listener,
                router_with_management(
                    service,
                    manager,
                    auth,
                    api_keys,
                ),
            )
            .into_future(),
        );
        let client = reqwest::Client::new();
        let endpoint = format!("http://{address}/api/v1/providers");
        let codex_base_url = format!("http://{upstream_address}");
        let compatible_base_url = format!("https://api.example.test:{}", compatible_address.port());

        let exact_auth_body = padded_json(
            r#"{"username":""#,
            r#"","password":"secret"}"#,
            MAX_AUTH_BODY_BYTES,
        );
        let exact_auth = client
            .post(format!("http://{address}/api/v1/auth/login"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(exact_auth_body)
            .send()
            .await
            .expect("auth request at body limit");
        assert_eq!(exact_auth.status(), StatusCode::BAD_REQUEST);
        let oversized_auth_body = padded_json(
            r#"{"username":""#,
            r#"","password":"secret"}"#,
            MAX_AUTH_BODY_BYTES + 1,
        );
        let oversized_auth = client
            .post(format!("http://{address}/api/v1/auth/login"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(oversized_auth_body)
            .send()
            .await
            .expect("oversized auth request");
        assert_eq!(oversized_auth.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let compressed_auth = client
            .post(format!("http://{address}/api/v1/auth/login"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_ENCODING, "gzip")
            .body(r#"{"username":"admin","password":"secret"}"#)
            .send()
            .await
            .expect("compressed auth request");
        assert_eq!(compressed_auth.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let exact_management_body =
            padded_json(r#"{"label":""#, r#""}"#, MAX_MANAGEMENT_BODY_BYTES);
        let exact_management = client
            .patch(format!("{endpoint}/missing-account"))
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(exact_management_body)
            .send()
            .await
            .expect("management request at body limit");
        assert_eq!(exact_management.status(), StatusCode::NOT_FOUND);
        let oversized_management_body =
            padded_json(r#"{"label":""#, r#""}"#, MAX_MANAGEMENT_BODY_BYTES + 1);
        let oversized_management = client
            .patch(format!("{endpoint}/missing-account"))
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(oversized_management_body)
            .send()
            .await
            .expect("oversized management request");
        assert_eq!(oversized_management.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let malformed_management = client
            .patch(format!("{endpoint}/missing-account"))
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body("{")
            .send()
            .await
            .expect("malformed management request");
        assert_api_error(
            malformed_management,
            StatusCode::BAD_REQUEST,
            "request body must be valid JSON",
        )
        .await;

        let unknown_management_field = client
            .patch(format!("{endpoint}/missing-account"))
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"label":"updated","extra":true}"#)
            .send()
            .await
            .expect("management request with unknown field");
        assert_api_error(
            unknown_management_field,
            StatusCode::BAD_REQUEST,
            "request body must be valid JSON",
        )
        .await;

        let invalid_health_query = client
            .get(format!("{endpoint}/health?from_ms=invalid"))
            .headers(management_headers(&session_token))
            .send()
            .await
            .expect("invalid provider health query");
        assert_api_error(
            invalid_health_query,
            StatusCode::BAD_REQUEST,
            "query parameters are invalid",
        )
        .await;

        let compressed_management = client
            .patch(format!("{endpoint}/missing-account"))
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_ENCODING, "gzip")
            .body(r#"{"label":"compressed"}"#)
            .send()
            .await
            .expect("compressed management request");
        assert_eq!(
            compressed_management.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let codex_direct = client
            .post(&endpoint)
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "direct",
                    "provider": "codex",
                    "label": "unsupported direct Codex",
                    "group_label": "default",
                    "base_url": codex_base_url,
                    "api_key": "not-an-oauth-credential"
                })
                .to_string(),
            )
            .send()
            .await
            .expect("reject direct Codex account");
        assert_eq!(codex_direct.status(), StatusCode::BAD_REQUEST);

        let compatible_credential = client
            .post(&endpoint)
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "credential_json",
                    "provider": "openai_compatible",
                    "label": "unsupported compatible credential",
                    "group_label": "default",
                    "credential_json": {"type": "codex"}
                })
                .to_string(),
            )
            .send()
            .await
            .expect("reject compatible credential document");
        assert_eq!(compatible_credential.status(), StatusCode::BAD_REQUEST);

        let unsupported_oauth = client
            .post(format!("http://{address}/api/v1/oauth/sessions"))
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                r#"{"provider":"openai_compatible","label":"unsupported oauth","group_label":"default"}"#,
            )
            .send()
            .await
            .expect("reject unsupported OAuth provider");
        assert_eq!(unsupported_oauth.status(), StatusCode::BAD_REQUEST);

        let failed_discovery = client
            .post(&endpoint)
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "direct",
                    "provider": "openai_compatible",
                    "label": "failed discovery",
                    "group_label": "default",
                    "base_url": format!("{compatible_base_url}/broken"),
                    "api_key": "failed-discovery-key"
                })
                .to_string(),
            )
            .send()
            .await
            .expect("fail account model discovery");
        assert_eq!(failed_discovery.status(), StatusCode::BAD_GATEWAY);
        let accounts_after_failure = client
            .get(&endpoint)
            .headers(management_headers(&session_token))
            .send()
            .await
            .expect("list accounts after failed creation");
        let accounts_after_failure: Value = serde_json::from_str(
            &accounts_after_failure
                .text()
                .await
                .expect("accounts after failed creation body"),
        )
        .expect("accounts after failed creation JSON");
        assert!(
            accounts_after_failure["data"]
                .as_array()
                .expect("provider accounts")
                .iter()
                .all(|account| account["label"] != "failed discovery"),
            "a failed model discovery must not leave a provider account"
        );

        let codex = client
            .post(&endpoint)
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "credential_json",
                    "provider": "codex",
                    "label": "Codex OAuth",
                    "group_label": "default",
                    "credential_json": {
                        "type": "codex",
                        "auth_kind": "oauth",
                        "access_token": "codex-access",
                        "refresh_token": "codex-refresh",
                        "id_token": "e30.e30.sig",
                        "last_refreshed_at": 1
                    }
                })
                .to_string(),
            )
            .send()
            .await
            .expect("create Codex credential account");
        assert_eq!(codex.status(), StatusCode::CREATED);
        let codex_body = codex.text().await.expect("Codex account response");
        assert!(!codex_body.contains("codex-access"));
        assert!(!codex_body.contains("codex-refresh"));
        let codex_body: Value = serde_json::from_str(&codex_body).expect("Codex account JSON");
        let codex_account_id = codex_body["data"]["account"]["id"]
            .as_str()
            .expect("Codex account ID");
        assert_eq!(codex_body["data"]["account"]["provider"], "codex");
        assert_eq!(
            codex_body["data"]["account"]["config"],
            serde_json::json!({})
        );

        let codex_base_url_update = client
            .patch(format!("{endpoint}/{codex_account_id}"))
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"base_url":"https://example.invalid"}"#)
            .send()
            .await
            .expect("reject Codex base URL update");
        assert_eq!(codex_base_url_update.status(), StatusCode::BAD_REQUEST);

        let with_key = client
            .post(&endpoint)
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "direct",
                    "provider": "openai_compatible",
                    "label": "with key",
                    "group_label": "default",
                    "base_url": compatible_base_url,
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

        let empty_update_key = client
            .patch(format!("{endpoint}/{private_account_id}"))
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"api_key":"  "}"#)
            .send()
            .await
            .expect("reject empty compatible API key update");
        assert_eq!(empty_update_key.status(), StatusCode::BAD_REQUEST);

        let updated_compatible = client
            .patch(format!("{endpoint}/{private_account_id}"))
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "label": "updated compatible",
                    "group_label": "default",
                    "api_key": "replacement-provider-key"
                })
                .to_string(),
            )
            .send()
            .await
            .expect("update compatible provider API key");
        assert_eq!(updated_compatible.status(), StatusCode::OK);
        let updated_compatible = updated_compatible
            .text()
            .await
            .expect("updated compatible response");
        assert!(!updated_compatible.contains("replacement-provider-key"));
        let updated_compatible: Value =
            serde_json::from_str(&updated_compatible).expect("updated compatible JSON");
        assert_eq!(updated_compatible["data"]["label"], "updated compatible");

        let refreshed_compatible = client
            .post(format!("{endpoint}/{private_account_id}/models/refresh"))
            .headers(management_headers(&session_token))
            .send()
            .await
            .expect("refresh compatible models with replacement API key");
        assert_eq!(refreshed_compatible.status(), StatusCode::OK);

        let empty_key = client
            .post(&endpoint)
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "direct",
                    "provider": "openai_compatible",
                    "label": "empty key",
                    "group_label": "default",
                    "base_url": compatible_base_url,
                    "api_key": ""
                })
                .to_string(),
            )
            .send()
            .await
            .expect("reject empty compatible API key");
        assert_eq!(empty_key.status(), StatusCode::BAD_REQUEST);

        let shared_account = client
            .post(&endpoint)
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "direct",
                    "provider": "openai_compatible",
                    "label": "shared account",
                    "group_label": "default",
                    "base_url": compatible_base_url,
                    "api_key": "shared-provider-key",
                    "visibility": "shared"
                })
                .to_string(),
            )
            .send()
            .await
            .expect("create shared account");
        assert_eq!(shared_account.status(), StatusCode::CREATED);
        let shared_account_body: Value = serde_json::from_slice(
            &shared_account
                .bytes()
                .await
                .expect("shared account response body"),
        )
        .expect("shared account response JSON");
        let shared_account_id = shared_account_body["data"]["account"]["id"]
            .as_str()
            .expect("shared account ID")
            .to_owned();

        let member_create = client
            .post(&endpoint)
            .headers(management_headers(&member_session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "method": "direct",
                    "provider": "openai_compatible",
                    "label": "member private",
                    "group_label": "default",
                    "base_url": compatible_base_url,
                    "api_key": "member-provider-key"
                })
                .to_string(),
            )
            .send()
            .await
            .expect("reject member provider creation");
        assert_eq!(member_create.status(), StatusCode::FORBIDDEN);

        let member_accounts = client
            .get(&endpoint)
            .headers(management_headers(&member_session_token))
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

        let hidden_private = client
            .get(format!("{endpoint}/{private_account_id}"))
            .headers(management_headers(&member_session_token))
            .send()
            .await
            .expect("hidden private provider");
        assert_eq!(hidden_private.status(), StatusCode::NOT_FOUND);

        let visible_shared = client
            .get(format!("{endpoint}/{shared_account_id}"))
            .headers(management_headers(&member_session_token))
            .send()
            .await
            .expect("visible shared provider");
        assert_eq!(visible_shared.status(), StatusCode::OK);

        let shared_models = client
            .get(format!("{endpoint}/{shared_account_id}/models"))
            .headers(management_headers(&member_session_token))
            .send()
            .await
            .expect("shared models");
        assert_eq!(shared_models.status(), StatusCode::OK);

        let shared_update = client
            .patch(format!("{endpoint}/{shared_account_id}"))
            .headers(management_headers(&member_session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"label":"not allowed"}"#)
            .send()
            .await
            .expect("shared provider update");
        assert_eq!(shared_update.status(), StatusCode::FORBIDDEN);

        let shared_model_update = client
            .patch(format!("{endpoint}/{shared_account_id}/models"))
            .headers(management_headers(&member_session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                r#"{"upstream_model":"model-a","alias":"no","enabled":true,"pricing_changed":false}"#,
            )
            .send()
            .await
            .expect("shared model update");
        assert_eq!(shared_model_update.status(), StatusCode::FORBIDDEN);

        let oauth_session = client
            .post(format!("http://{address}/api/v1/oauth/sessions"))
            .headers(management_headers(&session_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"provider":"grok","label":"admin oauth","group_label":"default","visibility":"shared"}"#)
            .send()
            .await
            .expect("start admin OAuth");
        assert_eq!(oauth_session.status(), StatusCode::CREATED);
        let oauth_session: Value =
            serde_json::from_slice(&oauth_session.bytes().await.expect("OAuth response body"))
                .expect("OAuth response JSON");
        assert_eq!(
            oauth_session["data"]["owner_user_id"],
            grant.user.id.as_str()
        );
        assert_eq!(oauth_session["data"]["visibility"], "shared");
        let oauth_session_id = oauth_session["data"]["id"]
            .as_str()
            .expect("OAuth session ID");
        let oauth_endpoint = format!("http://{address}/api/v1/oauth/sessions/{oauth_session_id}");

        let forbidden_oauth_read = client
            .get(&oauth_endpoint)
            .headers(management_headers(&member_session_token))
            .send()
            .await
            .expect("reject member OAuth read");
        assert_eq!(forbidden_oauth_read.status(), StatusCode::FORBIDDEN);

        let visible_oauth = client
            .get(&oauth_endpoint)
            .headers(management_headers(&session_token))
            .send()
            .await
            .expect("admin OAuth session");
        assert_eq!(visible_oauth.status(), StatusCode::OK);

        let forbidden_oauth_cancel = client
            .delete(&oauth_endpoint)
            .headers(management_headers(&member_session_token))
            .send()
            .await
            .expect("reject member OAuth cancellation");
        assert_eq!(forbidden_oauth_cancel.status(), StatusCode::FORBIDDEN);

        let cancelled_oauth = client
            .delete(&oauth_endpoint)
            .headers(management_headers(&session_token))
            .send()
            .await
            .expect("cancel admin OAuth session");
        assert_eq!(cancelled_oauth.status(), StatusCode::OK);

        server.abort();
        upstream_server.abort();
        compatible_server.abort();
        oauth_server.abort();
        runtime.shutdown();
        assert_eq!(
            authorization.lock().expect("authorization lock").as_slice(),
            [
                "Bearer codex-access",
                "Bearer do-not-return",
                "Bearer replacement-provider-key",
                "Bearer replacement-provider-key",
                "Bearer shared-provider-key",
            ]
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
        let owner_session_token = context.owner_session_token.clone();
        let member = context.member.clone();
        let member_session_token = context.member_session_token.clone();
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
        let owner_quota = manager
            .cached_quota(owner.id.as_str(), &owner_summary, now)
            .await;
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
                router_with_management(
                    service,
                    manager.clone(),
                    auth,
                    api_keys,
                ),
            )
            .into_future(),
        );
        let client = reqwest::Client::new();
        let session_token = member_session_token.expose_secret();
        let owner_session_token = owner_session_token.expose_secret();
        let endpoint = format!("http://{management_address}/api/v1/providers");
        let list_response = client
            .get(&endpoint)
            .headers(management_headers(session_token))
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
            .headers(management_headers(session_token))
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
        let forbidden_refresh = client
            .post(format!("{endpoint}/{account_id}/quota/refresh"))
            .headers(management_headers(session_token))
            .send()
            .await
            .expect("reject member quota refresh");
        assert_eq!(forbidden_refresh.status(), StatusCode::FORBIDDEN);
        assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 1);
        let refresh_response = client
            .post(format!("{endpoint}/{account_id}/quota/refresh"))
            .headers(management_headers(owner_session_token))
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
        let cached = manager
            .cached_quota(member.id.as_str(), summary, now + 94)
            .await;
        assert_eq!(cached.support, ProviderQuotaSupport::Supported);
        assert!(cached.snapshot.is_none());
        context.upstream_server.abort();
        runtime.shutdown();
    }
}
