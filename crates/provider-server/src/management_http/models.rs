use super::{
    ManagementState,
    shared::{ApiError, data, json_request, parse_account_id, require_super_admin, unix_timestamp},
};
use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
};
use provider_auth::AuthenticatedSession;
use provider_core::{
    ProviderModelInputModality, ProviderModelOverride, ProviderModelPricing, StoredProviderModel,
};
use provider_management::ModelCatalogSnapshot;
use provider_usage::canonical_model_pricing;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

pub(super) async fn list_models(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let account_id = parse_account_id(&account_id)?;
    let models = state
        .manager
        .list_models(session.user.id.as_str(), &account_id)
        .await?;
    Ok(data(models_json(&models)))
}

pub(super) async fn refresh_models(
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

pub(super) async fn update_model(
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
    let input_modalities = request.input_modalities.into_modalities()?;
    let models = state
        .manager
        .update_model(
            session.user.id.as_str(),
            &parse_account_id(&account_id)?,
            upstream_model,
            ProviderModelOverride {
                alias,
                enabled: request.enabled,
                input_modalities,
                pricing,
                updated_at: unix_timestamp(),
            },
        )
        .await?;
    Ok(data(models_json(&models)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpdateModelRequest {
    pub(super) upstream_model: String,
    pub(super) alias: Option<String>,
    pub(super) enabled: bool,
    pub(super) input_modalities: InputModalitiesPatch,
    pub(super) pricing_changed: bool,
    #[serde(default)]
    pub(super) pricing: ModelPricingPatch,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct InputModalitiesPatch(Value);

impl InputModalitiesPatch {
    pub(super) fn into_modalities(
        self,
    ) -> Result<Option<Vec<ProviderModelInputModality>>, ApiError> {
        let input_modalities: Option<Vec<ProviderModelInputModality>> = serde_json::from_value(
            self.0,
        )
        .map_err(|_| {
            ApiError::invalid_request(
                "input_modalities must be null or a non-empty array of unique supported modalities",
            )
        })?;
        provider_core::validate_input_modalities(input_modalities.as_deref())
            .map_err(ApiError::invalid_request)?;
        Ok(input_modalities)
    }
}

#[derive(Default)]
pub(super) enum ModelPricingPatch {
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
pub(super) struct UpdateModelPricingRequest {
    pub(super) input: Value,
    pub(super) output: Value,
    pub(super) cache_read: Value,
    pub(super) cache_write: Value,
    pub(super) reasoning: Value,
    pub(super) input_audio: Value,
    pub(super) output_audio: Value,
    pub(super) tiers: Vec<UpdateModelPricingTierRequest>,
}

impl UpdateModelPricingRequest {
    pub(super) fn into_model_pricing(self) -> Option<ProviderModelPricing> {
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
pub(super) struct UpdateModelPricingTierRequest {
    pub(super) threshold_tokens: u64,
    pub(super) input: Value,
    pub(super) output: Value,
    pub(super) cache_read: Value,
    pub(super) cache_write: Value,
    pub(super) reasoning: Value,
    pub(super) input_audio: Value,
    pub(super) output_audio: Value,
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

pub(super) fn updated_pricing(
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
pub(super) fn model_snapshot_json(snapshot: &ModelCatalogSnapshot) -> Value {
    json!({
        "models": models_json(&snapshot.models)
    })
}

fn models_json(models: &[StoredProviderModel]) -> Value {
    Value::Array(
        models
            .iter()
            .filter(|model| model_is_visible(model))
            .map(model_json)
            .collect(),
    )
}

pub(super) fn model_is_visible(model: &StoredProviderModel) -> bool {
    serde_json::from_str::<Value>(&model.metadata_json)
        .expect("stored provider model metadata must be valid JSON")
        .get("visibility")
        .and_then(Value::as_str)
        .is_none_or(|visibility| visibility == "list")
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
        "input_modalities": model.input_modalities,
        "supports_image_detail_original": model.input_modalities.as_deref().is_some_and(|modalities| {
            modalities.contains(&ProviderModelInputModality::Image)
        }),
        "metadata": serde_json::from_str::<Value>(&model.metadata_json)
            .expect("stored provider model metadata must be valid JSON"),
        "pricing": model.pricing.as_ref().map(|record| &record.pricing),
        "last_seen_at": model.last_seen_at,
        "created_at": model.created_at,
        "updated_at": model.updated_at
    })
}
