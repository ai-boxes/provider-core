//! Read-only usage endpoints for the dashboard.
//!
//! Session-authenticated, and the owner is always the logged-in user. There is
//! deliberately no way to ask about someone else's usage — not even for
//! `super_admin`, who administers accounts but has no business reading another
//! person's prompts-and-spend history.
//!
//! Usage describes the final attempt returned to the user. Public responses stay
//! limited to fields the dashboard presents; raw accounting facts remain in the
//! usage repository.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use provider_auth::AuthenticatedSession;
use provider_usage::{
    AttemptFacts, CacheTotals, ComponentPrices, CostStatus, CostTotals, InlinePriceRecord,
    RequestCursor, RequestSummary, TimeRange, TimeRangeError, TokenTotals, UnitPrice,
    UsageOverview, UsageQuery, UsageScope, component_cost_atoms, system_clock_ms,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// Everything the usage endpoints read from, plus the tracking the proxy path
/// writes with. One bundle so wiring cannot enable half of it.
#[derive(Clone)]
pub struct UsageServices {
    pub tracking: Arc<provider_usage::UsageTracking>,
    pub query: Arc<dyn UsageQuery>,
}

/// Default window when a caller does not give one: the last day.
const DEFAULT_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;
const DEFAULT_PAGE_SIZE: u32 = 15;

pub(crate) fn router(services: UsageServices) -> Router {
    Router::new()
        .route("/api/v1/usage/overview", get(overview))
        .route("/api/v1/usage/filters", get(filters))
        .route("/api/v1/usage/requests", get(requests))
        .route("/api/v1/usage/requests/{request_id}", get(request_detail))
        .with_state(services)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeParams {
    from_ms: Option<i64>,
    to_ms: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestParams {
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    api_key_id: Option<String>,
    model: Option<String>,
    group: Option<String>,
    cursor: Option<String>,
}

impl RangeParams {
    /// Build the scope for this request. The owner comes from the session, never
    /// from a parameter.
    fn scope(&self, session: &AuthenticatedSession) -> Result<UsageScope, ApiError> {
        let to_ms = self.to_ms.unwrap_or_else(system_clock_ms);
        let from_ms = self.from_ms.unwrap_or(to_ms - DEFAULT_WINDOW_MS);
        let range = TimeRange::new(from_ms, to_ms).map_err(|error| match error {
            TimeRangeError::Empty => ApiError::invalid_request("to_ms must be after from_ms"),
            TimeRangeError::TooWide => {
                ApiError::invalid_request("range is wider than usage is retained for")
            }
        })?;
        Ok(UsageScope {
            owner_user_id: session.user.id.as_str().to_owned(),
            api_key_id: None,
            client_model: None,
            group_label: None,
            range,
        })
    }
}

impl RequestParams {
    fn scope(&self, session: &AuthenticatedSession) -> Result<UsageScope, ApiError> {
        let mut scope = RangeParams {
            from_ms: self.from_ms,
            to_ms: self.to_ms,
        }
        .scope(session)?;
        scope.api_key_id =
            normalized_filter(self.api_key_id.clone(), "api_key_id must not be empty")?;
        scope.client_model = normalized_filter(self.model.clone(), "model must not be empty")?;
        scope.group_label = normalized_filter(self.group.clone(), "group must not be empty")?;
        Ok(scope)
    }
}

async fn overview(
    State(services): State<UsageServices>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(params): Query<RangeParams>,
) -> Result<Json<Value>, ApiError> {
    let scope = params.scope(&session)?;
    let overview = services
        .query
        .overview(&scope)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(data(overview_json(&scope, &overview)))
}

async fn filters(
    State(services): State<UsageServices>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(params): Query<RangeParams>,
) -> Result<Json<Value>, ApiError> {
    let scope = params.scope(&session)?;
    let options = services
        .query
        .filter_options(&scope)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(data(json!({
        "models": options.client_models,
        "groups": options.group_labels,
    })))
}

async fn requests(
    State(services): State<UsageServices>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(params): Query<RequestParams>,
) -> Result<Json<Value>, ApiError> {
    let scope = params.scope(&session)?;
    let cursor = params.cursor.as_deref().map(decode_cursor).transpose()?;
    let page = services
        .query
        .requests(&scope, cursor.as_ref(), DEFAULT_PAGE_SIZE)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(data(json!({
        "page_size": DEFAULT_PAGE_SIZE,
        "requests": page.requests.iter().map(request_json).collect::<Vec<_>>(),
        "next_cursor": page.next.as_ref().map(encode_cursor),
    })))
}

async fn request_detail(
    State(services): State<UsageServices>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(params): Query<RangeParams>,
    Path(request_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let scope = params.scope(&session)?;
    // A request belonging to someone else is reported as missing, which is what
    // the query layer returns for it.
    let attempt = services
        .query
        .request_attempt(&scope, &request_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::not_found)?;

    Ok(data(json!({
        "request_id": request_id,
        "attempt": attempt_json(&attempt),
    })))
}

fn overview_json(scope: &UsageScope, overview: &UsageOverview) -> Value {
    json!({
        "from_ms": scope.range.from_ms,
        "to_ms": scope.range.to_ms,
        "logical_requests": overview.logical_requests,
        "tokens": tokens_json(&overview.tokens),
        "cache": cache_json(&overview.cache),
        "cost": cost_json(&overview.cost),
    })
}

fn tokens_json(tokens: &TokenTotals) -> Value {
    json!({
        "cache_read_input": tokens.cache_read_input,
        "effective_input": tokens.effective_input,
        "output": tokens.output,
    })
}

fn cache_json(cache: &CacheTotals) -> Value {
    json!({
        "reported_input_tokens": cache.reported_input_tokens,
        "cache_read_input_tokens": cache.cache_read_input_tokens,
    })
}

fn cost_json(cost: &CostTotals) -> Value {
    json!({
        "usd": cost.atoms.map(|atoms| atoms.to_decimal_string()),
    })
}

fn request_json(request: &RequestSummary) -> Value {
    json!({
        "request_id": request.request_id,
        "api_key_id": request.api_key_id,
        "api_key_label": request.api_key_label,
        "api_key_group_label": request.api_key_group_label,
        "client_model": request.client_model_raw,
        "reasoning_effort": request.reasoning_effort,
        "started_at_ms": request.started_at_ms,
        "completed_at_ms": request.completed_at_ms,
        "first_token_at_ms": request.first_token_at_ms,
        "tokens": tokens_json(&request.tokens),
        "cost": cost_json(&request.cost),
    })
}

fn normalized_filter(
    value: Option<String>,
    empty_message: &'static str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| {
            let value = value.trim().to_owned();
            if value.is_empty() {
                return Err(ApiError::invalid_request(empty_message));
            }
            Ok(value)
        })
        .transpose()
}

fn attempt_json(attempt: &AttemptFacts) -> Value {
    let observation = &attempt.observation;
    let prices = selected_prices(attempt);
    let reasoning_tokens = if attempt.contract.inclusion.reasoning_included_in_output {
        provider_core::usage::TokenMetric::NotApplicable
    } else {
        observation.reasoning_tokens
    };
    json!({
        "cost": json!({
            "usd": matches!(
                attempt.cost.status,
                CostStatus::CompleteForObservedCatalogComponents
            )
                .then(|| attempt.cost.total_known.to_decimal_string()),
            "components": json!({
                "input_usd": component_cost_json(
                    observation.uncached_input_tokens,
                    prices.and_then(|prices| prices.uncached_input_per_million),
                ),
                "output_usd": component_cost_json(
                    observation.output_tokens,
                    prices.and_then(|prices| prices.output_per_million),
                ),
                "cache_read_usd": component_cost_json(
                    observation.cache_read_input_tokens,
                    prices.and_then(|prices| prices.cache_read_per_million),
                ),
                "cache_write_usd": component_cost_json(
                    observation.cache_write_input_tokens,
                    prices.and_then(|prices| prices.cache_write_per_million),
                ),
                "reasoning_usd": component_cost_json(
                    reasoning_tokens,
                    prices.and_then(|prices| prices.reasoning_per_million),
                ),
                "input_audio_usd": component_cost_json(
                    observation.input_audio_tokens,
                    prices.and_then(|prices| prices.input_audio_per_million),
                ),
                "output_audio_usd": component_cost_json(
                    observation.output_audio_tokens,
                    prices.and_then(|prices| prices.output_audio_per_million),
                ),
            }),
        }),
        "price": json!({
            "pricing_context_tokens": observation.pricing_context_tokens.known_value(),
            "tier_threshold_tokens": selected_tier_threshold(attempt),
            "input_per_million_usd": price_json(
                prices.and_then(|prices| prices.uncached_input_per_million),
            ),
            "output_per_million_usd": price_json(
                prices.and_then(|prices| prices.output_per_million),
            ),
            "cache_read_per_million_usd": price_json(
                prices.and_then(|prices| prices.cache_read_per_million),
            ),
            "cache_write_per_million_usd": price_json(
                prices.and_then(|prices| prices.cache_write_per_million),
            ),
            "reasoning_per_million_usd": price_json(
                prices.and_then(|prices| prices.reasoning_per_million),
            ),
            "input_audio_per_million_usd": price_json(
                prices.and_then(|prices| prices.input_audio_per_million),
            ),
            "output_audio_per_million_usd": price_json(
                prices.and_then(|prices| prices.output_audio_per_million),
            ),
        }),
    })
}

fn selected_prices(attempt: &AttemptFacts) -> Option<ComponentPrices> {
    let record = attempt.price.resolved()?;
    Some(record.prices_for_context(attempt.observation.pricing_context_tokens.known_value()))
}

fn selected_tier_threshold(attempt: &AttemptFacts) -> Option<u64> {
    let context_tokens = attempt.observation.pricing_context_tokens.known_value()?;
    match attempt.price.resolved()? {
        InlinePriceRecord::CatalogV1(record) => record
            .context_tier
            .filter(|tier| context_tokens > tier.threshold_tokens)
            .map(|tier| tier.threshold_tokens),
        InlinePriceRecord::ModelV2(record) => record
            .tiers
            .iter()
            .take_while(|tier| context_tokens > tier.threshold_tokens)
            .last()
            .map(|tier| tier.threshold_tokens),
    }
}

fn component_cost_json(
    tokens: provider_core::usage::TokenMetric,
    price: Option<UnitPrice>,
) -> Value {
    match (tokens.known_value(), price) {
        (Some(tokens), Some(price)) => component_cost_atoms(tokens, price)
            .map(|cost| Value::String(cost.to_decimal_string()))
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

fn price_json(price: Option<UnitPrice>) -> Value {
    price
        .map(|price| Value::String(price.to_decimal_string()))
        .unwrap_or(Value::Null)
}

/// `<completed_at_ms>:<request_id>`.
///
/// Opaque to callers but not secret: it only names a position they can already
/// see, and the owner filter is applied independently on every page.
fn encode_cursor(cursor: &RequestCursor) -> String {
    format!("{}:{}", cursor.completed_at_ms, cursor.request_id)
}

fn decode_cursor(raw: &str) -> Result<RequestCursor, ApiError> {
    let (completed_at_ms, request_id) = raw
        .split_once(':')
        .ok_or_else(|| ApiError::invalid_request("cursor is malformed"))?;
    if request_id.is_empty() {
        return Err(ApiError::invalid_request("cursor is malformed"));
    }
    Ok(RequestCursor {
        completed_at_ms: completed_at_ms
            .parse()
            .map_err(|_| ApiError::invalid_request("cursor is malformed"))?,
        request_id: request_id.to_owned(),
    })
}

fn data(value: Value) -> Json<Value> {
    Json(json!({ "data": value }))
}

pub(crate) struct ApiError {
    status: StatusCode,
    error_type: &'static str,
    message: &'static str,
}

impl ApiError {
    const fn invalid_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error_type: "invalid_request_error",
            message,
        }
    }

    const fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error_type: "not_found_error",
            message: "resource was not found",
        }
    }

    /// Storage failures are not described to the caller: the detail would leak
    /// internals and there is nothing actionable in it.
    const fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error_type: "api_error",
            message: "internal server error",
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
    use provider_core::{
        ProviderKind,
        usage::{
            CacheCapability, CacheEligibility, CacheReportingExpectation, PricingContextBasis,
            PricingMode, ProviderUsageObservation, TokenInclusionRules, TokenMetric, TotalSource,
            UsageContractSnapshot,
        },
    };
    use provider_usage::{
        AttemptSequence, CatalogInlinePriceRecordV1, ContextPriceTier, DispatchEvidence,
        InlinePriceRecord, PRICE_SCALE, PriceResolution, TrackingState,
        compute_observed_catalog_cost,
    };

    use super::*;

    const PRICE_UNIT: i128 = 10i128.pow(PRICE_SCALE);

    fn reported(value: u64) -> TokenMetric {
        TokenMetric::ProviderReported { value }
    }

    fn contract() -> UsageContractSnapshot {
        UsageContractSnapshot {
            contract_version: 1,
            normalization_version: 1,
            inclusion: TokenInclusionRules {
                input_includes_cache: false,
                input_categories_mutually_exclusive: true,
                reasoning_included_in_output: true,
                reasoning_applicable: false,
                audio_applicable: false,
                cache_write_applicable: false,
                missing_cache_read_means_zero: false,
                total_source: TotalSource::Reported,
            },
            cache_capability: CacheCapability::Supported,
            cache_eligibility: CacheEligibility::Eligible,
            cache_reporting_expectation: CacheReportingExpectation::Expected,
            pricing_context_basis: PricingContextBasis::EffectiveInput,
            pricing_mode: PricingMode::Default,
        }
    }

    fn attempt(dispatch_evidence: DispatchEvidence, pricing_context_tokens: u64) -> AttemptFacts {
        let contract = contract();
        let observation = ProviderUsageObservation {
            uncached_input_tokens: reported(100),
            cache_read_input_tokens: reported(50),
            cache_write_input_tokens: TokenMetric::NotApplicable,
            effective_input_tokens: reported(150),
            output_tokens: reported(20),
            reasoning_tokens: TokenMetric::NotApplicable,
            input_audio_tokens: TokenMetric::NotApplicable,
            output_audio_tokens: TokenMetric::NotApplicable,
            total_tokens: reported(170),
            pricing_context_tokens: reported(pricing_context_tokens),
            billable: Vec::new(),
            warnings: Vec::new(),
        };
        let price = PriceResolution::Resolved(Box::new(InlinePriceRecord::CatalogV1(
            CatalogInlinePriceRecordV1 {
                format_version: 1,
                parser_version: 1,
                catalog_revision: "catalog-test".to_owned(),
                catalog_provider_id: "test-provider".to_owned(),
                catalog_model_id: "test-model".to_owned(),
                mapping_revision: 1,
                prices: ComponentPrices {
                    uncached_input_per_million: Some(UnitPrice::from_scaled(2 * PRICE_UNIT)),
                    cache_read_per_million: Some(UnitPrice::from_scaled(PRICE_UNIT)),
                    output_per_million: Some(UnitPrice::from_scaled(6 * PRICE_UNIT)),
                    ..ComponentPrices::default()
                },
                context_tier: Some(ContextPriceTier {
                    threshold_tokens: 200,
                    prices: ComponentPrices {
                        uncached_input_per_million: Some(UnitPrice::from_scaled(5 * PRICE_UNIT)),
                        cache_read_per_million: Some(UnitPrice::from_scaled(PRICE_UNIT)),
                        output_per_million: Some(UnitPrice::from_scaled(30 * PRICE_UNIT)),
                        ..ComponentPrices::default()
                    },
                }),
                selected_tier: None,
                unmodeled_billable_component: false,
                unmodeled_pricing_rule: false,
            },
        )));
        let cost = compute_observed_catalog_cost(&observation, &contract, &price);

        AttemptFacts {
            outcome: None,
            failover_reason: None,
            attempt_id: "attempt-2".to_owned(),
            logical_request_id: "request-1".to_owned(),
            sequence: AttemptSequence(2),
            provider: ProviderKind::OpenAiCompatible,
            account_id: "account-1".to_owned(),
            configured_model: Some("test-model".to_owned()),
            provider_reported_model: Some("test-model".to_owned()),
            started_at_ms: 1,
            first_token_at_ms: Some(2),
            completed_at_ms: 3,
            dispatch_evidence,
            tracking: TrackingState::Complete,
            contract,
            observation,
            price,
            cost,
        }
    }

    #[test]
    fn request_detail_uses_context_tier_prices_and_exact_component_costs() {
        let value = attempt_json(&attempt(DispatchEvidence::ResponseObserved, 201));

        assert_eq!(value["price"]["input_per_million_usd"], "5.00000000");
        assert_eq!(value["price"]["output_per_million_usd"], "30.00000000");
        assert_eq!(value["price"]["pricing_context_tokens"], 201);
        assert_eq!(value["price"]["tier_threshold_tokens"], 200);
        assert_eq!(value["cost"]["components"]["input_usd"], "0.00050000000000");
        assert_eq!(
            value["cost"]["components"]["output_usd"],
            "0.00060000000000"
        );
        assert_eq!(
            value["cost"]["components"]["cache_read_usd"],
            "0.00005000000000"
        );
        assert_eq!(value["cost"]["usd"], "0.00115000000000");
    }

    #[test]
    fn context_tier_is_strictly_above_its_threshold() {
        let attempt = attempt(DispatchEvidence::ResponseObserved, 200);
        let prices = selected_prices(&attempt).expect("resolved prices");

        assert_eq!(
            prices.uncached_input_per_million,
            Some(UnitPrice::from_scaled(2 * PRICE_UNIT))
        );
        assert_eq!(
            prices.output_per_million,
            Some(UnitPrice::from_scaled(6 * PRICE_UNIT))
        );
    }
}
