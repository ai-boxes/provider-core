use provider_usage::{
    QuotaEstimateCompleteness, QuotaLimitEstimatePoint, TimeRange, UsageRepositoryError, UsdAtoms,
    recombine_atoms,
};
use sqlx::{AssertSqlSafe, Row, sqlite::SqliteRow};

use crate::{SqliteUsageRepository, usage::usage_error};

impl SqliteUsageRepository {
    pub(crate) async fn load_provider_quota_estimates(
        &self,
        account_ids: &[String],
        range: TimeRange,
    ) -> Result<Vec<QuotaLimitEstimatePoint>, UsageRepositoryError> {
        if account_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = vec!["?"; account_ids.len()].join(", ");
        let sql = format!(
            r#"
            WITH scoped AS (
                SELECT o.*
                FROM provider_quota_window_observations AS o
                INNER JOIN provider_credentials AS c
                    ON c.account_id = o.account_id
                   AND c.quota_identity_revision = o.credential_identity_revision
                WHERE o.account_id IN ({placeholders})
                  AND o.observed_at_ms <= ?
            ), ordered AS (
                SELECT *,
                    LAG(ends_at_ms) OVER metric AS previous_end_ms,
                    LAG(starts_at_ms) OVER metric AS previous_start_ms,
                    LAG(used_hundredths) OVER metric AS previous_used
                FROM scoped
                WINDOW metric AS (
                    PARTITION BY account_id, group_key, metric_key
                    ORDER BY observed_at_ms, observation_sequence
                )
            ), resets AS (
                SELECT * FROM ordered
                WHERE used_hundredths = 0 AND previous_used > 0
                  AND ends_at_ms <> previous_end_ms
                  AND observed_at_ms < previous_end_ms
            ), ranked AS (
                SELECT
                    o.account_id, o.credential_revision, o.credential_identity_revision,
                    o.group_key, o.metric_key,
                    o.metric_position, o.period_kind, o.starts_at_ms, o.ends_at_ms,
                    o.duration_seconds, o.observed_at_ms, o.used_hundredths,
                    incoming.observed_at_ms AS reset_start_ms,
                    outgoing.observed_at_ms AS reset_end_ms,
                    outgoing.ends_at_ms AS next_window_end_ms,
                    FIRST_VALUE(o.used_hundredths) OVER (
                        PARTITION BY o.account_id, o.group_key, o.metric_key, o.starts_at_ms, o.ends_at_ms
                        ORDER BY o.observed_at_ms DESC, o.observation_sequence DESC
                    ) AS latest_used_hundredths,
                    ROW_NUMBER() OVER (
                        PARTITION BY
                            o.account_id, o.group_key, o.metric_key,
                            o.starts_at_ms, o.ends_at_ms
                        ORDER BY (o.used_hundredths > 0) DESC, o.observed_at_ms DESC, o.observation_sequence DESC
                    ) AS observation_rank
                FROM ordered AS o
                LEFT JOIN resets AS incoming
                    ON incoming.account_id = o.account_id
                   AND incoming.group_key = o.group_key AND incoming.metric_key = o.metric_key
                   AND incoming.starts_at_ms = o.starts_at_ms AND incoming.ends_at_ms = o.ends_at_ms
                LEFT JOIN resets AS outgoing
                    ON outgoing.account_id = o.account_id
                   AND outgoing.group_key = o.group_key AND outgoing.metric_key = o.metric_key
                   AND outgoing.previous_start_ms = o.starts_at_ms
                   AND outgoing.previous_end_ms = o.ends_at_ms
                WHERE MAX(o.starts_at_ms, COALESCE(incoming.observed_at_ms, o.starts_at_ms)) >= ?
                  AND (incoming.observed_at_ms IS NULL OR
                    (o.observed_at_ms, o.observation_sequence) >= (incoming.observed_at_ms, incoming.observation_sequence))
                  AND (outgoing.observed_at_ms IS NULL OR
                    (o.observed_at_ms, o.observation_sequence) < (outgoing.observed_at_ms, outgoing.observation_sequence))
            ), latest AS (
                SELECT * FROM ranked
                WHERE observation_rank = 1
                  AND used_hundredths > 0
                  AND (ends_at_ms <= ? OR latest_used_hundredths >= 10000 OR reset_end_ms IS NOT NULL)
            )
            SELECT
                latest.account_id, latest.group_key, latest.metric_key,
                latest.metric_position, latest.period_kind, latest.duration_seconds,
                MAX(latest.starts_at_ms, COALESCE(latest.reset_start_ms, latest.starts_at_ms)) AS starts_at_ms,
                COALESCE(latest.reset_end_ms, latest.ends_at_ms) AS ends_at_ms,
                latest.observed_at_ms, latest.next_window_end_ms,
                latest.reset_start_ms IS NOT NULL AS sampling_incomplete,
                latest.used_hundredths,
                COUNT(a.id) AS dispatched_attempts,
                COALESCE(SUM(CASE WHEN a.cost_atoms IS NOT NULL THEN 1 ELSE 0 END), 0)
                    AS priced_attempts,
                COALESCE(SUM(CASE
                    WHEN a.cost_status = 'complete_for_observed_catalog_components' THEN 1
                    ELSE 0 END), 0) AS complete_attempts,
                COALESCE(SUM(CASE WHEN a.cost_atoms IS NOT NULL
                    THEN a.cost_atoms / 1000000 ELSE 0 END), 0) AS cost_high,
                COALESCE(SUM(CASE WHEN a.cost_atoms IS NOT NULL
                    THEN a.cost_atoms % 1000000 ELSE 0 END), 0) AS cost_low
            FROM latest
            LEFT JOIN usage_attempts AS a
                ON a.account_id = latest.account_id
               AND a.credential_identity_revision = latest.credential_identity_revision
               AND a.dispatch_evidence <> 'not_invoked'
               AND a.completed_at_ms >= MAX(latest.starts_at_ms, COALESCE(latest.reset_start_ms, latest.starts_at_ms))
               AND (latest.reset_start_ms IS NULL OR a.started_at_ms >= latest.reset_start_ms)
               AND a.completed_at_ms < latest.observed_at_ms + 1000
               AND (latest.reset_end_ms IS NULL OR a.completed_at_ms < latest.reset_end_ms)
            GROUP BY
                latest.account_id, latest.credential_revision,
                latest.credential_identity_revision, latest.group_key,
                latest.metric_key, latest.metric_position, latest.period_kind,
                latest.starts_at_ms, latest.ends_at_ms, latest.duration_seconds,
                latest.observed_at_ms, latest.used_hundredths,
                latest.reset_start_ms, latest.reset_end_ms, latest.next_window_end_ms
            ORDER BY latest.ends_at_ms, latest.metric_position, latest.metric_key
            "#,
        );
        let mut query = sqlx::query(AssertSqlSafe(sql));
        for account_id in account_ids {
            query = query.bind(account_id);
        }
        let rows = query
            .bind(range.to_ms)
            .bind(range.from_ms)
            .bind(range.to_ms)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| usage_error("failed to read provider quota estimates", error))?;
        rows.iter().filter_map(quota_estimate_point).collect()
    }
}

fn quota_estimate_point(
    row: &SqliteRow,
) -> Option<Result<QuotaLimitEstimatePoint, UsageRepositoryError>> {
    let result = (|| {
        let dispatched_attempts = count(row, "dispatched_attempts")?;
        let priced_attempts = count(row, "priced_attempts")?;
        let complete_attempts = count(row, "complete_attempts")?;
        let used_hundredths = count(row, "used_hundredths")?;
        if dispatched_attempts == 0 || priced_attempts == 0 || used_hundredths == 0 {
            return Ok(None);
        }
        let cost_high: i64 = row
            .try_get("cost_high")
            .map_err(|error| usage_error("failed to read quota estimate cost", error))?;
        let cost_low: i64 = row
            .try_get("cost_low")
            .map_err(|error| usage_error("failed to read quota estimate cost", error))?;
        let observed_cost = recombine_atoms(cost_high, cost_low);
        if observed_cost.as_atoms() <= 0 {
            return Ok(None);
        }
        let estimated_atoms = observed_cost
            .as_atoms()
            .checked_mul(10_000)
            .and_then(|value| value.checked_add(i128::from(used_hundredths / 2)))
            .and_then(|value| value.checked_div(i128::from(used_hundredths)))
            .ok_or_else(|| UsageRepositoryError::new("quota estimate overflowed"))?;
        let metric_position = row
            .try_get::<i64, _>("metric_position")
            .ok()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| UsageRepositoryError::new("stored quota metric position is invalid"))?;
        Ok(Some(QuotaLimitEstimatePoint {
            account_id: text(row, "account_id", "account")?,
            group_key: text(row, "group_key", "group")?,
            metric_key: text(row, "metric_key", "metric")?,
            metric_position,
            period_kind: text(row, "period_kind", "period")?,
            duration_seconds: row
                .try_get("duration_seconds")
                .map_err(|error| usage_error("failed to read quota estimate duration", error))?,
            window_start_ms: timestamp(row, "starts_at_ms")?,
            window_end_ms: timestamp(row, "ends_at_ms")?,
            next_window_end_ms: row
                .try_get("next_window_end_ms")
                .map_err(|error| usage_error("failed to read quota successor window", error))?,
            sampling_incomplete: row
                .try_get("sampling_incomplete")
                .map_err(|error| usage_error("failed to read quota sampling coverage", error))?,
            observed_at_ms: row
                .try_get("observed_at_ms")
                .map_err(|error| usage_error("failed to read quota estimate observation", error))?,
            used_hundredths,
            observed_cost,
            estimated_limit_cost: UsdAtoms::from_atoms(estimated_atoms),
            completeness: if complete_attempts == dispatched_attempts {
                QuotaEstimateCompleteness::Complete
            } else {
                QuotaEstimateCompleteness::LowerBound
            },
            priced_attempts,
            dispatched_attempts,
        }))
    })();
    match result {
        Ok(Some(point)) => Some(Ok(point)),
        Ok(None) => None,
        Err(error) => Some(Err(error)),
    }
}

fn count(row: &SqliteRow, column: &str) -> Result<u64, UsageRepositoryError> {
    let value: i64 = row
        .try_get(column)
        .map_err(|error| usage_error("failed to read quota estimate count", error))?;
    u64::try_from(value).map_err(|_| UsageRepositoryError::new("quota estimate count is invalid"))
}

fn text(row: &SqliteRow, column: &str, label: &str) -> Result<String, UsageRepositoryError> {
    row.try_get(column)
        .map_err(|error| usage_error(&format!("failed to read quota estimate {label}"), error))
}

fn timestamp(row: &SqliteRow, column: &str) -> Result<i64, UsageRepositoryError> {
    row.try_get(column)
        .map_err(|error| usage_error("failed to read quota estimate window", error))
}
