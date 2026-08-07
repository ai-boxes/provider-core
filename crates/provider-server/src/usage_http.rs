//! Read-only usage endpoints for the dashboard.
//!
//! Session-authenticated, and the owner is always the logged-in user. There is
//! deliberately no way to ask about someone else's usage — not even for
//! `super_admin`, who administers accounts but has no business reading another
//! person's prompts-and-spend history.
//!
//! Every number is reported with what qualifies it: which attribution basis it
//! used, how many attempts had no known token count, how many costs were partial
//! or unavailable, and how many facts are known to be missing. A caller that
//! ignores those still cannot mistake a partial total for a complete one, because
//! the partial amount is never added into the complete one.

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
    AttemptFacts, AttributionBasis, CacheTotals, CatalogPrices, ComponentPrices, CostStatus,
    CostTotals, RequestCursor, RequestSummary, TimeRange, TimeRangeError, TokenTotals, UnitPrice,
    UsageOverview, UsageQuery, UsageRepository, UsageScope, UsageWriter, component_cost_atoms,
    system_clock_ms,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// Everything the usage endpoints read from, plus the tracking the proxy path
/// writes with. One bundle so wiring cannot enable half of it.
#[derive(Clone)]
pub struct UsageServices {
    pub tracking: Arc<provider_usage::UsageTracking>,
    pub query: Arc<dyn UsageQuery>,
    pub repository: Arc<dyn UsageRepository>,
    pub catalog: Arc<CatalogPrices>,
    pub writer: Arc<UsageWriter>,
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
        .route("/api/v1/usage/health", get(health))
        .with_state(services)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeParams {
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    basis: Option<String>,
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
            api_key_id: normalized_filter(self.api_key_id.clone(), "api_key_id must not be empty")?,
            client_model: normalized_filter(self.model.clone(), "model must not be empty")?,
            group_label: normalized_filter(self.group.clone(), "group must not be empty")?,
            range,
            basis: self.basis()?,
        })
    }

    fn basis(&self) -> Result<AttributionBasis, ApiError> {
        match self.basis.as_deref() {
            // The user-facing default: what the requests actually returned.
            None | Some("user_final_attempt") => Ok(AttributionBasis::UserFinalAttempt),
            Some("key_triggered_confirmed_dispatch") => {
                Ok(AttributionBasis::KeyTriggeredConfirmedDispatch)
            }
            Some(_) => Err(ApiError::invalid_request(
                "basis must be user_final_attempt or key_triggered_confirmed_dispatch",
            )),
        }
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
    let mut scope = params.scope(&session)?;
    scope.client_model = None;
    scope.group_label = None;
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
    Query(params): Query<RangeParams>,
) -> Result<Json<Value>, ApiError> {
    let scope = params.scope(&session)?;
    let cursor = params.cursor.as_deref().map(decode_cursor).transpose()?;
    let page = services
        .query
        .requests(&scope, cursor.as_ref(), DEFAULT_PAGE_SIZE)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(data(json!({
        "attribution_basis": basis_name(scope.basis),
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
    let attempts = services
        .query
        .request_attempts(&scope, &request_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::not_found)?;
    let final_attempt_id = services
        .repository
        .load_logical_request(&request_id)
        .await
        .map_err(|_| ApiError::internal())?
        .and_then(|request| request.final_attempt_id);

    Ok(data(json!({
        "request_id": request_id,
        "attempts": attempts
            .iter()
            .map(|attempt| attempt_json(
                attempt,
                is_attributed_attempt(scope.basis, final_attempt_id.as_deref(), attempt),
            ))
            .collect::<Vec<_>>(),
    })))
}

async fn health(State(services): State<UsageServices>) -> Result<Json<Value>, ApiError> {
    let catalog = services
        .repository
        .load_catalog()
        .await
        .map_err(|_| ApiError::internal())?;
    let installed = services.catalog.current();

    Ok(data(json!({
        "catalog": {
            // Present only when a catalog has been fetched at least once.
            "revision": catalog.as_ref().map(|stored| stored.revision.clone()),
            "content_fetched_at_ms": catalog.as_ref().map(|stored| stored.content_fetched_at_ms),
            "last_checked_at_ms": catalog.as_ref().map(|stored| stored.last_checked_at_ms),
            // A stable code, never an upstream message.
            "last_error_code": catalog.as_ref().and_then(|stored| stored.last_error_code.clone()),
            // What is actually pricing requests right now, which is not
            // necessarily what is stored if the stored body stopped parsing.
            "priced_models": installed.as_ref().map(|snapshot| snapshot.priced_model_count()),
            "pricing_active": installed.is_some(),
        },
        "writer": {
            // Facts lost with no gap row to name them. Non-zero means some usage
            // is missing and could not even be attributed.
            "unrecorded_facts": services.writer.unrecorded_facts(),
        },
    })))
}

const fn basis_name(basis: AttributionBasis) -> &'static str {
    match basis {
        AttributionBasis::UserFinalAttempt => "user_final_attempt",
        AttributionBasis::KeyTriggeredConfirmedDispatch => "key_triggered_confirmed_dispatch",
    }
}

fn overview_json(scope: &UsageScope, overview: &UsageOverview) -> Value {
    json!({
        "attribution_basis": basis_name(scope.basis),
        "from_ms": scope.range.from_ms,
        "to_ms": scope.range.to_ms,
        "as_of_ms": overview.as_of_ms,
        "logical_requests": overview.logical_requests,
        "attempts": overview.attempts,
        "tokens": tokens_json(&overview.tokens),
        "cache": cache_json(&overview.cache),
        "cost": cost_json(&overview.cost),
        // Facts these numbers are missing. A reader that shows totals without
        // this is presenting an undercount as a total.
        "tracking_gaps": overview.tracking_gaps,
    })
}

fn tokens_json(tokens: &TokenTotals) -> Value {
    json!({
        "uncached_input": tokens.uncached_input,
        "cache_read_input": tokens.cache_read_input,
        "cache_write_input": tokens.cache_write_input,
        "effective_input": tokens.effective_input,
        "output": tokens.output,
        "reasoning": tokens.reasoning,
        // Attempts that contributed nothing to `effective_input` because the
        // provider never reported it. Not zeroes.
        "attempts_with_unknown_input": tokens.attempts_with_unknown_input,
    })
}

fn cache_json(cache: &CacheTotals) -> Value {
    json!({
        "reported_input_tokens": cache.reported_input_tokens,
        "cache_read_input_tokens": cache.cache_read_input_tokens,
        "attempts_with_unknown_cache": cache.attempts_with_unknown_cache,
    })
}

fn cost_json(cost: &CostTotals) -> Value {
    json!({
        "basis": "observed_catalog",
        "complete_usd": cost.complete_atoms.to_decimal_string(),
        "complete_attempts": cost.complete_attempts,
        "partial_attempts": cost.partial_attempts,
        // No amount at all — never rendered as 0.
        "unavailable_attempts": cost.unavailable_attempts,
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

fn attempt_json(attempt: &AttemptFacts, attributed: bool) -> Value {
    let observation = &attempt.observation;
    let prices = selected_prices(attempt);
    json!({
        "attempt_id": attempt.attempt_id,
        "attributed": attributed,
        "sequence": attempt.sequence.0,
        "provider": attempt.provider.as_str(),
        "configured_model": attempt.configured_model,
        "provider_reported_model": attempt.provider_reported_model,
        "started_at_ms": attempt.started_at_ms,
        "first_token_at_ms": attempt.first_token_at_ms,
        "completed_at_ms": attempt.completed_at_ms,
        "dispatch_evidence": name(&attempt.dispatch_evidence),
        "tracking": encode(&attempt.tracking),
        // Each metric carries its own kind, so a client can tell an explicit zero
        // from a value the provider never reported.
        "tokens": json!({
            "uncached_input": encode(&observation.uncached_input_tokens),
            "cache_read_input": encode(&observation.cache_read_input_tokens),
            "cache_write_input": encode(&observation.cache_write_input_tokens),
            "effective_input": encode(&observation.effective_input_tokens),
            "output": encode(&observation.output_tokens),
            "reasoning": encode(&observation.reasoning_tokens),
            "total": encode(&observation.total_tokens),
        }),
        "cost": json!({
            "basis": "observed_catalog",
            "status": name(&attempt.cost.status),
            // Absent, not zero, when there is no amount.
            "usd": (!matches!(attempt.cost.status, CostStatus::Unavailable))
                .then(|| attempt.cost.total_known.to_decimal_string()),
            "reasons": attempt.cost.reasons.iter().map(name).collect::<Vec<_>>(),
            "calculator_version": attempt.cost.calculator_version,
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
            }),
        }),
        "price": json!({
            // The tag of the resolution, without inlining the whole price record.
            "resolution": encode(&attempt.price)
                .get("kind")
                .cloned()
                .expect("price resolution serialization must contain kind"),
            "catalog_revision": attempt.price.resolved()
                .and_then(|record| record.catalog_revision().map(ToOwned::to_owned)),
            "catalog_model_id": attempt.price.resolved()
                .and_then(|record| record.catalog_model_id().map(ToOwned::to_owned)),
            "source": attempt.price.resolved()
                .and_then(|record| record.source().map(|source| source.as_str())),
            "input_per_million_usd": price_json(
                prices.and_then(|prices| prices.uncached_input_per_million),
            ),
            "output_per_million_usd": price_json(
                prices.and_then(|prices| prices.output_per_million),
            ),
            "cache_read_per_million_usd": price_json(
                prices.and_then(|prices| prices.cache_read_per_million),
            ),
        }),
    })
}

fn is_attributed_attempt(
    basis: AttributionBasis,
    final_attempt_id: Option<&str>,
    attempt: &AttemptFacts,
) -> bool {
    match basis {
        AttributionBasis::UserFinalAttempt => final_attempt_id == Some(attempt.attempt_id.as_str()),
        AttributionBasis::KeyTriggeredConfirmedDispatch => {
            attempt.dispatch_evidence.is_confirmed_dispatch()
        }
    }
}

fn selected_prices(attempt: &AttemptFacts) -> Option<ComponentPrices> {
    let record = attempt.price.resolved()?;
    Some(record.prices_for_context(attempt.observation.pricing_context_tokens.known_value()))
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

/// Serialize a domain value for the API.
///
/// These types already derive snake_case `Serialize`, and it is the same encoding
/// the database stores. Reusing it keeps one vocabulary instead of a second,
/// hand-written one that could drift — a `Debug` string would render
/// `InProgress` as `inprogress`.
fn encode<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("usage domain value must serialize")
}

/// The snake_case name of a fieldless enum value.
fn name<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        Ok(_) => panic!("usage fieldless enum must serialize as a string"),
        Err(error) => panic!("usage fieldless enum must serialize: {error}"),
    }
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
    fn attribution_matches_the_requested_basis() {
        let dispatched = attempt(DispatchEvidence::ResponseObserved, 201);
        assert!(is_attributed_attempt(
            AttributionBasis::UserFinalAttempt,
            Some("attempt-2"),
            &dispatched,
        ));
        assert!(!is_attributed_attempt(
            AttributionBasis::UserFinalAttempt,
            Some("attempt-1"),
            &dispatched,
        ));
        assert!(is_attributed_attempt(
            AttributionBasis::KeyTriggeredConfirmedDispatch,
            None,
            &dispatched,
        ));

        let not_invoked = attempt(DispatchEvidence::NotInvoked, 201);
        assert!(!is_attributed_attempt(
            AttributionBasis::KeyTriggeredConfirmedDispatch,
            None,
            &not_invoked,
        ));
    }

    #[test]
    fn request_detail_uses_context_tier_prices_and_exact_component_costs() {
        let value = attempt_json(&attempt(DispatchEvidence::ResponseObserved, 201), true);

        assert_eq!(value["attributed"], true);
        assert_eq!(value["price"]["input_per_million_usd"], "5.00000000");
        assert_eq!(value["price"]["output_per_million_usd"], "30.00000000");
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
