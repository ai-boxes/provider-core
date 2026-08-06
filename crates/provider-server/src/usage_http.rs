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
    AttemptFacts, AttributionBasis, CacheTotals, CatalogPrices, CostStatus, CostTotals,
    MAX_PAGE_SIZE, RequestCursor, RequestSummary, SeriesBucket, TimeRange, TimeRangeError,
    TokenTotals, UsageOverview, UsageQuery, UsageRepository, UsageScope, UsageWriter,
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
const DEFAULT_PAGE_SIZE: u32 = 50;

pub(crate) fn router(services: UsageServices) -> Router {
    Router::new()
        .route("/api/v1/usage/overview", get(overview))
        .route("/api/v1/usage/series", get(series))
        .route("/api/v1/usage/keys", get(keys))
        .route("/api/v1/usage/requests", get(requests))
        .route("/api/v1/usage/requests/{request_id}", get(request_detail))
        .route("/api/v1/usage/health", get(health))
        .with_state(services)
}

#[derive(Deserialize)]
struct RangeParams {
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    basis: Option<String>,
    api_key_id: Option<String>,
    bucket: Option<String>,
    limit: Option<u32>,
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
            api_key_id: self.api_key_id.clone(),
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

    fn bucket(&self) -> Result<SeriesBucket, ApiError> {
        match self.bucket.as_deref() {
            None | Some("hour") => Ok(SeriesBucket::Hour),
            Some("day") => Ok(SeriesBucket::Day),
            Some(_) => Err(ApiError::invalid_request("bucket must be hour or day")),
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

async fn series(
    State(services): State<UsageServices>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(params): Query<RangeParams>,
) -> Result<Json<Value>, ApiError> {
    let scope = params.scope(&session)?;
    let bucket = params.bucket()?;
    let buckets = services
        .query
        .series(&scope, bucket)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(data(json!({
        "attribution_basis": basis_name(scope.basis),
        "bucket": match bucket { SeriesBucket::Hour => "hour", SeriesBucket::Day => "day" },
        "from_ms": scope.range.from_ms,
        "to_ms": scope.range.to_ms,
        // Buckets with nothing recorded are absent rather than zero: "nothing
        // happened" and "nothing was recorded" are different claims.
        "buckets": buckets.iter().map(|bucket| json!({
            "bucket_start_ms": bucket.bucket_start_ms,
            "logical_requests": bucket.logical_requests,
            "attempts": bucket.attempts,
            "tokens": tokens_json(&bucket.tokens),
            "cost": cost_json(&bucket.cost),
        })).collect::<Vec<_>>(),
    })))
}

async fn keys(
    State(services): State<UsageServices>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(params): Query<RangeParams>,
) -> Result<Json<Value>, ApiError> {
    let scope = params.scope(&session)?;
    let summaries = services
        .query
        .key_summaries(&scope)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(data(json!({
        "attribution_basis": basis_name(scope.basis),
        "from_ms": scope.range.from_ms,
        "to_ms": scope.range.to_ms,
        "keys": summaries.iter().map(|summary| json!({
            // Null for usage recorded without a key, kept distinct from a key id.
            "api_key_id": summary.api_key_id,
            "logical_requests": summary.logical_requests,
            "attempts": summary.attempts,
            "tokens": tokens_json(&summary.tokens),
            "cost": cost_json(&summary.cost),
        })).collect::<Vec<_>>(),
        // Says so rather than letting a truncated list look complete.
        "truncated": summaries.len() as u32 >= MAX_PAGE_SIZE,
    })))
}

async fn requests(
    State(services): State<UsageServices>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(params): Query<RangeParams>,
) -> Result<Json<Value>, ApiError> {
    let scope = params.scope(&session)?;
    let cursor = params.cursor.as_deref().map(decode_cursor).transpose()?;
    let limit = params.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE);
    let page = services
        .query
        .requests(&scope, cursor.as_ref(), limit)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(data(json!({
        "attribution_basis": basis_name(scope.basis),
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

    Ok(data(json!({
        "request_id": request_id,
        "attempts": attempts.iter().map(attempt_json).collect::<Vec<_>>(),
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
        "coverage_denominator": cache.coverage_denominator,
        "hits": cache.hits,
        "misses": cache.misses,
        // In the denominator but unreported. Counting these as misses would
        // understate the hit rate.
        "expected_but_unreported": cache.expected_but_unreported,
        "excluded": cache.excluded,
    })
}

fn cost_json(cost: &CostTotals) -> Value {
    json!({
        "basis": "observed_catalog",
        "complete_usd": cost.complete_atoms.to_decimal_string(),
        "complete_attempts": cost.complete_attempts,
        // Deliberately a separate number. Adding it to `complete_usd` would
        // present an incomplete estimate as a complete one.
        "partial_known_usd": cost.partial_known_atoms.to_decimal_string(),
        "partial_attempts": cost.partial_attempts,
        // No amount at all — never rendered as 0.
        "unavailable_attempts": cost.unavailable_attempts,
    })
}

fn request_json(request: &RequestSummary) -> Value {
    json!({
        "request_id": request.request_id,
        "api_key_id": request.api_key_id,
        "client_model": request.client_model_raw,
        "started_at_ms": request.started_at_ms,
        "completed_at_ms": request.completed_at_ms,
        "status": name(&request.status),
        "tracking": encode(&request.tracking),
        "attempts": request.attempts,
        "tokens": tokens_json(&request.tokens),
        "cost": cost_json(&request.cost),
    })
}

fn attempt_json(attempt: &AttemptFacts) -> Value {
    let observation = &attempt.observation;
    json!({
        "attempt_id": attempt.attempt_id,
        "sequence": attempt.sequence.0,
        "provider": attempt.provider.as_str(),
        "configured_model": attempt.configured_model,
        "provider_reported_model": attempt.provider_reported_model,
        "started_at_ms": attempt.started_at_ms,
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
        }),
        "price": json!({
            // The tag of the resolution, without inlining the whole price record.
            "resolution": encode(&attempt.price)
                .get("kind")
                .cloned()
                .unwrap_or(Value::Null),
            "catalog_revision": attempt.price.resolved()
                .map(|record| record.catalog_revision.clone()),
            "catalog_model_id": attempt.price.resolved()
                .map(|record| record.catalog_model_id.clone()),
        }),
    })
}

/// Serialize a domain value for the API.
///
/// These types already derive snake_case `Serialize`, and it is the same encoding
/// the database stores. Reusing it keeps one vocabulary instead of a second,
/// hand-written one that could drift — a `Debug` string would render
/// `InProgress` as `inprogress`.
fn encode<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// The snake_case name of a fieldless enum value.
fn name<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        _ => String::from("unknown"),
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
