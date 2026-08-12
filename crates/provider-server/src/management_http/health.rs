use super::{
    ManagementState,
    shared::{ApiError, data, query_request},
};
use axum::{
    Json,
    extract::{Extension, Query, State, rejection::QueryRejection},
};
use provider_auth::AuthenticatedSession;
use provider_usage::{ProviderHealthSummary, TimeRange, TimeRangeError, system_clock_ms};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

pub(super) async fn list_provider_health(
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderHealthParams {
    from_ms: Option<i64>,
    to_ms: Option<i64>,
}

impl ProviderHealthParams {
    pub(super) fn range(&self) -> Result<TimeRange, ApiError> {
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
