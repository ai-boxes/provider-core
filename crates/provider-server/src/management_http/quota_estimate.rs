use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Extension, Path, State},
};
use provider_auth::AuthenticatedSession;
use provider_core::{ProviderQuotaView, QuotaGroupScope, QuotaMetricKind, QuotaUnit};
use provider_usage::{QuotaEstimateCompleteness, QuotaLimitEstimatePoint, TimeRange};
use serde_json::{Value, json};

use super::{
    ManagementState,
    shared::{ApiError, data, parse_account_id, require_super_admin, unix_timestamp},
};

const HISTORY_MS: i64 = 90 * 24 * 60 * 60 * 1000;

pub(super) async fn estimate_history(
    State(state): State<ManagementState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_super_admin(&session)?;
    let account_id = parse_account_id(&account_id)?;
    state
        .manager
        .get_account(session.user.id.as_str(), &account_id)
        .await?;
    let now_ms = unix_timestamp().saturating_mul(1000);
    let from_ms = now_ms.saturating_sub(HISTORY_MS);
    let range = TimeRange::new(from_ms, now_ms).map_err(|_| ApiError::internal())?;
    let points = match state.usage.as_ref() {
        Some(usage) => usage
            .query
            .provider_quota_estimates(&[account_id.as_str().to_owned()], range)
            .await
            .map_err(|_| ApiError::internal())?,
        None => Vec::new(),
    };
    Ok(data(history_json(from_ms, now_ms, points)))
}

pub(super) async fn estimates_for_accounts(
    state: &ManagementState,
    account_ids: &[String],
) -> BTreeMap<String, Vec<QuotaLimitEstimatePoint>> {
    let Some(usage) = state.usage.as_ref() else {
        return BTreeMap::new();
    };
    let now_ms = unix_timestamp().saturating_mul(1000);
    let Ok(range) = TimeRange::new(now_ms.saturating_sub(HISTORY_MS), now_ms) else {
        return BTreeMap::new();
    };
    let Ok(points) = usage
        .query
        .provider_quota_estimates(account_ids, range)
        .await
    else {
        return BTreeMap::new();
    };
    let mut by_account = BTreeMap::<String, Vec<QuotaLimitEstimatePoint>>::new();
    for point in points {
        by_account
            .entry(point.account_id.clone())
            .or_default()
            .push(point);
    }
    by_account
}

pub(super) fn primary_estimate<'a>(
    quota: &ProviderQuotaView,
    points: &'a [QuotaLimitEstimatePoint],
) -> Option<&'a QuotaLimitEstimatePoint> {
    let snapshot = quota.snapshot.as_ref()?;
    let group = snapshot
        .groups
        .iter()
        .find(|group| group.scope == QuotaGroupScope::Aggregate)?;
    let metric = group.metrics.iter().find(|metric| {
        metric.kind == QuotaMetricKind::Usage && metric.unit == QuotaUnit::Percent
    })?;
    let period = metric.period.as_ref()?;
    let current_window_start_ms = period
        .starts_at
        .or_else(|| period.ends_at?.checked_sub(period.duration_seconds?))?
        .checked_mul(1000)?;
    let matching = |point: &&QuotaLimitEstimatePoint| {
        point.group_key == group.key
            && point.metric_key == metric.key
            && point.period_kind == period_kind(period.kind)
            && point.duration_seconds == period.duration_seconds
    };
    let previous = points
        .iter()
        .filter(matching)
        .filter(|point| {
            point.next_window_end_ms.is_some_and(|end| {
                period.ends_at.and_then(|value| value.checked_mul(1000)) == Some(end)
            }) || (point.next_window_end_ms.is_none()
                && point.window_end_ms <= current_window_start_ms
                && current_window_start_ms.saturating_sub(point.window_end_ms)
                    <= 5 * 60 * 1000)
        })
        .max_by_key(|point| point.window_end_ms);
    previous.or_else(|| {
        let current_window_end_ms = period.ends_at?.checked_mul(1000)?;
        points.iter().filter(matching).find(|point| {
            point.next_window_end_ms.is_none()
                && point.window_end_ms == current_window_end_ms
                && point.used_hundredths >= 10_000
        })
    })
}

fn period_kind(kind: provider_core::QuotaPeriodKind) -> &'static str {
    match kind {
        provider_core::QuotaPeriodKind::Weekly => "weekly",
        provider_core::QuotaPeriodKind::Monthly => "monthly",
        provider_core::QuotaPeriodKind::Rolling => "rolling",
        provider_core::QuotaPeriodKind::Unknown => "unknown",
    }
}

pub(super) fn estimate_json(point: &QuotaLimitEstimatePoint) -> Value {
    json!({
        "quota_group_key": point.group_key,
        "quota_metric_key": point.metric_key,
        "period_kind": point.period_kind,
        "duration_seconds": point.duration_seconds,
        "window_start_ms": point.window_start_ms,
        "window_end_ms": point.window_end_ms,
        "sampling_incomplete": point.sampling_incomplete,
        "observed_at_ms": point.observed_at_ms,
        "observed_used_percent": point.used_hundredths as f64 / 100.0,
        "observed_cost_usd": point.observed_cost.to_decimal_string(),
        "estimated_limit_cost_usd": point.estimated_limit_cost.to_decimal_string(),
        "cost_completeness": completeness(point.completeness),
        "priced_attempts": point.priced_attempts,
        "dispatched_attempts": point.dispatched_attempts
    })
}

fn history_json(from_ms: i64, to_ms: i64, points: Vec<QuotaLimitEstimatePoint>) -> Value {
    let mut series = BTreeMap::<(u32, String, String, String, Option<i64>), Vec<Value>>::new();
    for point in points {
        let key = (
            point.metric_position,
            point.group_key.clone(),
            point.metric_key.clone(),
            point.period_kind.clone(),
            point.duration_seconds,
        );
        series.entry(key).or_default().push(estimate_json(&point));
    }
    let series = series
        .into_iter()
        .map(
            |((_, group_key, metric_key, period_kind, duration_seconds), points)| {
                json!({
                    "group_key": group_key,
                    "metric_key": metric_key,
                    "period_kind": period_kind,
                    "duration_seconds": duration_seconds,
                    "points": points
                })
            },
        )
        .collect::<Vec<_>>();
    json!({ "from_ms": from_ms, "to_ms": to_ms, "series": series })
}

const fn completeness(value: QuotaEstimateCompleteness) -> &'static str {
    match value {
        QuotaEstimateCompleteness::Complete => "complete",
        QuotaEstimateCompleteness::LowerBound => "lower_bound",
    }
}

#[cfg(test)]
mod tests {
    use provider_core::{
        ProviderKind, ProviderQuotaFreshness, ProviderQuotaSnapshot, ProviderQuotaSupport,
        QuotaAmount, QuotaGroup, QuotaGroupAudience, QuotaMetric, QuotaPeriod, QuotaPeriodKind,
    };
    use provider_usage::UsdAtoms;

    use super::*;

    #[test]
    fn primary_estimate_requires_the_immediately_previous_window() {
        let quota = quota_view(2_000, 1_000);
        let older = estimate(0, 500_000);
        let previous = estimate(0, 1_000_000);

        assert_eq!(primary_estimate(&quota, &[older.clone()]), None);
        assert_eq!(
            primary_estimate(&quota, &[older, previous.clone()]),
            Some(&previous)
        );
    }

    #[test]
    fn primary_estimate_matches_an_early_reset_successor() {
        let quota = quota_view(2_000, 1_000);
        let mut previous = estimate(0, 1_500_000);
        previous.next_window_end_ms = Some(2_000_000);
        assert_eq!(
            primary_estimate(&quota, &[previous.clone()]),
            Some(&previous)
        );
        assert_eq!(
            primary_estimate(&quota_view(3_000, 1_000), &[previous]),
            None
        );
        let mut current = estimate(1_500_000, 2_000_000);
        current.sampling_incomplete = true;
        assert_eq!(estimate_json(&current)["sampling_incomplete"], true);
    }

    #[test]
    fn primary_estimate_falls_back_to_a_fully_used_current_window() {
        let quota = quota_view(2_000, 1_000);
        let current = estimate(1_000_000, 2_000_000);
        assert_eq!(primary_estimate(&quota, &[current.clone()]), Some(&current));

        let near_previous = estimate(0, 790_000);
        let mut wrong_period = near_previous.clone();
        wrong_period.period_kind = "weekly".to_owned();
        wrong_period.duration_seconds = Some(604_800);
        assert_eq!(
            primary_estimate(
                &quota,
                &[current.clone(), wrong_period, near_previous.clone()],
            ),
            Some(&near_previous)
        );

        let previous = estimate(0, 1_000_000);
        assert_eq!(
            primary_estimate(&quota, &[current.clone(), previous.clone()]),
            Some(&previous)
        );

        let mut incomplete = current;
        incomplete.used_hundredths = 9_999;
        assert_eq!(primary_estimate(&quota, &[incomplete]), None);
    }

    fn quota_view(window_end: i64, duration_seconds: i64) -> ProviderQuotaView {
        ProviderQuotaView {
            support: ProviderQuotaSupport::Supported,
            freshness: Some(ProviderQuotaFreshness::Fresh),
            snapshot: Some(ProviderQuotaSnapshot {
                account_id: "account-1".to_owned(),
                provider: ProviderKind::Codex,
                fetched_at: 1_500,
                last_observed_at: None,
                groups: vec![QuotaGroup {
                    key: "codex".to_owned(),
                    scope: QuotaGroupScope::Aggregate,
                    audience: QuotaGroupAudience::Shared,
                    attributes: BTreeMap::new(),
                    metrics: vec![QuotaMetric {
                        key: "primary".to_owned(),
                        kind: QuotaMetricKind::Usage,
                        unit: QuotaUnit::Percent,
                        used: Some(QuotaAmount::Integer(20)),
                        remaining: Some(QuotaAmount::Integer(80)),
                        limit: Some(QuotaAmount::Integer(100)),
                        period: Some(QuotaPeriod {
                            kind: QuotaPeriodKind::Rolling,
                            starts_at: None,
                            ends_at: Some(window_end),
                            duration_seconds: Some(duration_seconds),
                        }),
                        breakdown: Vec::new(),
                    }],
                }],
                warnings: Vec::new(),
            }),
            last_error: None,
        }
    }

    fn estimate(window_start_ms: i64, window_end_ms: i64) -> QuotaLimitEstimatePoint {
        QuotaLimitEstimatePoint {
            account_id: "account-1".to_owned(),
            group_key: "codex".to_owned(),
            metric_key: "primary".to_owned(),
            metric_position: 0,
            period_kind: "rolling".to_owned(),
            duration_seconds: Some(1_000),
            window_start_ms,
            window_end_ms,
            next_window_end_ms: None,
            sampling_incomplete: false,
            observed_at_ms: window_end_ms,
            used_hundredths: 10_000,
            observed_cost: UsdAtoms::from_atoms(20),
            estimated_limit_cost: UsdAtoms::from_atoms(40),
            completeness: QuotaEstimateCompleteness::Complete,
            priced_attempts: 1,
            dispatched_attempts: 1,
        }
    }
}
