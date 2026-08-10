//! Indexed reads over usage facts.
//!
//! Every statement here starts from the same scoped `FROM`/`WHERE`, built by
//! [`scoped_from`], so the owner filter cannot be forgotten in one query and
//! present in another. Usage always describes the final attempt returned to the
//! user.
//!
//! The statements are assembled at runtime, which sqlx makes you vouch for. Only
//! compile-time SQL fragments and a clamped page size are interpolated. Every
//! caller value is a bound parameter, so no input reaches the SQL text.
//!
//! Cost sums are split before they are added: `SUM(cost_atoms)` overflows a 64-bit
//! accumulator at roughly `$92,233`, so each sum is taken over `atoms / 10^6` and
//! `atoms % 10^6` and recombined exactly in Rust. Nothing is rounded to make a
//! total fit.

use async_trait::async_trait;
use provider_usage::{
    ATOM_SPLIT, AttemptFacts, CacheTotals, CostTotals, MAX_PAGE_SIZE, ProviderHealthSummary,
    RequestCursor, RequestPage, RequestSummary, TokenTotals, UsageFilterOptions, UsageOverview,
    UsageQuery, UsageRepositoryError, UsageScope, recombine_atoms,
};
use sqlx::{AssertSqlSafe, Row, sqlite::SqliteRow};

use crate::{
    SqliteUsageRepository,
    usage::{attempt_facts, usage_error},
};

/// The scoped source every query reads from.
///
/// Bind order, once per query: owner, key, key, model, model, group, group, from, to.
fn scoped_from() -> &'static str {
    r#"
        FROM usage_logical_requests AS l
        LEFT JOIN usage_attempts AS a
          ON a.logical_request_id = l.request_id
         AND a.id = l.final_attempt_id
        WHERE l.owner_user_id = ?
          -- All placeholders are positional. A numbered one here would silently
          -- re-use the owner parameter and shift everything after it.
          AND (? IS NULL OR l.api_key_id = ?)
          AND (? IS NULL OR l.client_model_raw = ?)
          AND (? IS NULL OR l.api_key_group_label = ?)
          AND l.completed_at_ms >= ?
          AND l.completed_at_ms < ?
        "#
}

/// The aggregate columns shared by the overview and each series bucket.
const TOTALS_COLUMNS: &str = r#"
    COUNT(DISTINCT l.request_id) AS logical_requests,
    COALESCE(SUM(a.cache_read_input_tokens), 0) AS cache_read_input,
    COALESCE(SUM(a.effective_input_tokens), 0) AS effective_input,
    COALESCE(SUM(a.output_tokens), 0) AS output,
    COALESCE(SUM(CASE WHEN a.cost_status = 'complete_for_observed_catalog_components'
        THEN a.cost_atoms / 1000000 ELSE 0 END), 0) AS complete_high,
    COALESCE(SUM(CASE WHEN a.cost_status = 'complete_for_observed_catalog_components'
        THEN a.cost_atoms % 1000000 ELSE 0 END), 0) AS complete_low,
    COALESCE(SUM(CASE WHEN a.cost_status = 'complete_for_observed_catalog_components'
        THEN 1 ELSE 0 END), 0) AS complete_attempts
"#;

/// Cache-token columns used to calculate the window hit rate.
///
/// Both sides of the ratio come from the same attempts. An absent cache count
/// remains unknown and does not silently become a miss.
const CACHE_COLUMNS: &str = r#"
    COALESCE(SUM(CASE WHEN a.effective_input_tokens IS NOT NULL
                           AND a.cache_read_input_tokens IS NOT NULL
        THEN a.effective_input_tokens ELSE 0 END), 0) AS cache_reported_input,
    COALESCE(SUM(CASE WHEN a.effective_input_tokens IS NOT NULL
                           AND a.cache_read_input_tokens IS NOT NULL
        THEN a.cache_read_input_tokens ELSE 0 END), 0) AS cache_rate_read_input
"#;

#[async_trait]
impl UsageQuery for SqliteUsageRepository {
    async fn overview(&self, scope: &UsageScope) -> Result<UsageOverview, UsageRepositoryError> {
        let sql = format!("SELECT {TOTALS_COLUMNS}, {CACHE_COLUMNS} {}", scoped_from());
        let row = bind_scope(sqlx::query(AssertSqlSafe(sql)), scope)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| usage_error("failed to read usage overview", error))?;

        Ok(UsageOverview {
            logical_requests: count(&row, "logical_requests")?,
            tokens: token_totals(&row)?,
            cache: cache_totals(&row)?,
            cost: cost_totals(&row)?,
        })
    }

    async fn filter_options(
        &self,
        scope: &UsageScope,
    ) -> Result<UsageFilterOptions, UsageRepositoryError> {
        // Filter menus describe the complete range, not only the selected page
        // and not only the currently visible API keys.
        let mut unfiltered = scope.clone();
        unfiltered.client_model = None;
        unfiltered.group_label = None;

        let model_sql = format!(
            "SELECT DISTINCT l.client_model_raw AS value {} AND l.client_model_raw IS NOT NULL ORDER BY value",
            scoped_from()
        );
        let model_rows = bind_scope(sqlx::query(AssertSqlSafe(model_sql)), &unfiltered)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| usage_error("failed to read usage model filters", error))?;

        let group_sql = format!(
            "SELECT DISTINCT l.api_key_group_label AS value {} AND l.api_key_group_label IS NOT NULL ORDER BY value",
            scoped_from()
        );
        let group_rows = bind_scope(sqlx::query(AssertSqlSafe(group_sql)), &unfiltered)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| usage_error("failed to read usage group filters", error))?;

        Ok(UsageFilterOptions {
            client_models: model_rows.iter().map(|row| row.get("value")).collect(),
            group_labels: group_rows.iter().map(|row| row.get("value")).collect(),
        })
    }

    async fn provider_health(
        &self,
        account_ids: &[String],
        range: provider_usage::TimeRange,
    ) -> Result<Vec<ProviderHealthSummary>, UsageRepositoryError> {
        if account_ids.is_empty() {
            return Ok(Vec::new());
        }

        let placeholders = vec!["?"; account_ids.len()].join(", ");
        let sql = format!(
            r#"
            SELECT
                a.account_id,
                COUNT(DISTINCT l.request_id) AS requests,
                SUM(CASE WHEN l.logical_status = 'succeeded' THEN 1 ELSE 0 END) AS successes,
                SUM(CASE WHEN l.logical_status = 'failed' THEN 1 ELSE 0 END) AS failures
            FROM usage_logical_requests AS l
            INNER JOIN usage_attempts AS a
                ON a.id = l.final_attempt_id
            WHERE a.account_id IN ({placeholders})
              AND l.completed_at_ms >= ?
              AND l.completed_at_ms < ?
              AND l.logical_status IN ('succeeded', 'failed')
            GROUP BY a.account_id
            ORDER BY a.account_id
            "#,
        );
        let mut query = sqlx::query(AssertSqlSafe(sql));
        for account_id in account_ids {
            query = query.bind(account_id);
        }
        let rows = query
            .bind(range.from_ms)
            .bind(range.to_ms)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| usage_error("failed to read provider health", error))?;

        rows.iter()
            .map(|row| {
                Ok(ProviderHealthSummary {
                    account_id: row.get("account_id"),
                    requests: count(row, "requests")?,
                    successes: count(row, "successes")?,
                    failures: count(row, "failures")?,
                })
            })
            .collect()
    }

    async fn requests(
        &self,
        scope: &UsageScope,
        after: Option<&RequestCursor>,
        limit: u32,
    ) -> Result<RequestPage, UsageRepositoryError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(UsageRepositoryError::new("usage page size is invalid"));
        }
        // One extra row decides whether a next page exists without a second query.
        let fetch = i64::from(limit) + 1;
        // Keyset, not offset: a row inserted while paging cannot shift the window.
        let keyset = if after.is_some() {
            "AND (l.completed_at_ms < ? OR (l.completed_at_ms = ? AND l.request_id < ?))"
        } else {
            ""
        };
        let sql = format!(
            r#"
            SELECT
                l.request_id, l.api_key_id, l.api_key_label, l.api_key_group_label,
                l.client_model_raw, l.reasoning_effort,
                l.started_at_ms, l.completed_at_ms,
                (
                    SELECT first_token_at_ms
                    FROM usage_attempts AS final_attempt
                    WHERE final_attempt.id = l.final_attempt_id
                ) AS first_token_at_ms,
                {TOTALS_COLUMNS}
            {} {keyset}
            GROUP BY l.request_id
            ORDER BY l.completed_at_ms DESC, l.request_id DESC
            LIMIT {fetch}
            "#,
            scoped_from()
        );

        let mut query = bind_scope(sqlx::query(AssertSqlSafe(sql)), scope);
        if let Some(cursor) = after {
            query = query
                .bind(cursor.completed_at_ms)
                .bind(cursor.completed_at_ms)
                .bind(&cursor.request_id);
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|error| usage_error("failed to read usage requests", error))?;

        let has_more = rows.len() > limit as usize;
        let mut requests = Vec::with_capacity(rows.len().min(limit as usize));
        for row in rows.iter().take(limit as usize) {
            requests.push(request_summary(row)?);
        }
        let next = if has_more {
            requests.last().map(|last| RequestCursor {
                completed_at_ms: last.completed_at_ms,
                request_id: last.request_id.clone(),
            })
        } else {
            None
        };
        Ok(RequestPage { requests, next })
    }

    async fn request_attempt(
        &self,
        scope: &UsageScope,
        request_id: &str,
    ) -> Result<Option<AttemptFacts>, UsageRepositoryError> {
        let sql = format!(
            "SELECT a.* {} AND l.request_id = ? AND a.id IS NOT NULL LIMIT 1",
            scoped_from()
        );
        let row = bind_scope(sqlx::query(AssertSqlSafe(sql)), scope)
            .bind(request_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| usage_error("failed to read usage request attempt", error))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut facts = attempt_facts(row)?;
        facts.observation.billable = self.billable_for(&facts.attempt_id).await?;
        Ok(Some(facts))
    }
}

type SqliteQuery<'q> = sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments>;

/// Bind the scope, in the order [`scoped_from`] declares.
fn bind_scope<'q>(query: SqliteQuery<'q>, scope: &'q UsageScope) -> SqliteQuery<'q> {
    query
        .bind(&scope.owner_user_id)
        .bind(scope.api_key_id.as_deref())
        .bind(scope.api_key_id.as_deref())
        .bind(scope.client_model.as_deref())
        .bind(scope.client_model.as_deref())
        .bind(scope.group_label.as_deref())
        .bind(scope.group_label.as_deref())
        .bind(scope.range.from_ms)
        .bind(scope.range.to_ms)
}

fn count(row: &SqliteRow, column: &str) -> Result<u64, UsageRepositoryError> {
    let value: i64 = row
        .try_get(column)
        .map_err(|error| usage_error("failed to read usage count", error))?;
    u64::try_from(value)
        .map_err(|_| UsageRepositoryError::new(format!("usage count {column} is negative")))
}

fn token_totals(row: &SqliteRow) -> Result<TokenTotals, UsageRepositoryError> {
    Ok(TokenTotals {
        cache_read_input: count(row, "cache_read_input")?,
        effective_input: count(row, "effective_input")?,
        output: count(row, "output")?,
    })
}

fn cache_totals(row: &SqliteRow) -> Result<CacheTotals, UsageRepositoryError> {
    let reported_input_tokens = count(row, "cache_reported_input")?;
    let cache_read_input_tokens = count(row, "cache_rate_read_input")?;
    if cache_read_input_tokens > reported_input_tokens {
        return Err(UsageRepositoryError::new(
            "cache-read tokens exceed reported input tokens",
        ));
    }
    Ok(CacheTotals {
        reported_input_tokens,
        cache_read_input_tokens,
    })
}

fn cost_totals(row: &SqliteRow) -> Result<CostTotals, UsageRepositoryError> {
    let complete_attempts = count(row, "complete_attempts")?;
    Ok(CostTotals {
        atoms: (complete_attempts > 0)
            .then(|| split_sum(row, "complete_high", "complete_low"))
            .transpose()?,
    })
}

/// Recombine the two halves SQL summed separately. See the module header.
fn split_sum(
    row: &SqliteRow,
    high: &str,
    low: &str,
) -> Result<provider_usage::UsdAtoms, UsageRepositoryError> {
    let high: i64 = row
        .try_get(high)
        .map_err(|error| usage_error("failed to read usage cost high atoms", error))?;
    let low: i64 = row
        .try_get(low)
        .map_err(|error| usage_error("failed to read usage cost low atoms", error))?;
    debug_assert_eq!(ATOM_SPLIT, 1_000_000, "the SQL divisor must match");
    Ok(recombine_atoms(high, low))
}

fn request_summary(row: &SqliteRow) -> Result<RequestSummary, UsageRepositoryError> {
    Ok(RequestSummary {
        request_id: row.get("request_id"),
        api_key_id: row.get("api_key_id"),
        api_key_label: row.get("api_key_label"),
        api_key_group_label: row.get("api_key_group_label"),
        client_model_raw: row.get("client_model_raw"),
        reasoning_effort: row.get("reasoning_effort"),
        started_at_ms: row.get("started_at_ms"),
        completed_at_ms: row.get("completed_at_ms"),
        first_token_at_ms: row.get("first_token_at_ms"),
        tokens: token_totals(row)?,
        cost: cost_totals(row)?,
    })
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
        AttemptSequence, CatalogInlinePriceRecordV1, ComponentPrices, CostStatus, DeliveryOutcome,
        DispatchEvidence, ExecutionOutcome, InlinePriceRecord, LogicalRequestStart,
        LogicalRequestTerminal, LogicalStatus, ObservedCatalogCost, PRICE_SCALE, PriceResolution,
        TimeRange, TrackingState, UnitPrice, UsageRepository, UsdAtoms,
    };

    use super::*;
    use crate::SqliteAccountRepository;

    const HOUR: i64 = 60 * 60 * 1000;
    const T0: i64 = 1_700_000_000_000;

    async fn repository() -> SqliteUsageRepository {
        SqliteAccountRepository::in_memory()
            .await
            .expect("test database")
            .usage_repository()
    }

    fn contract() -> UsageContractSnapshot {
        UsageContractSnapshot {
            contract_version: 1,
            normalization_version: 1,
            inclusion: TokenInclusionRules {
                input_includes_cache: true,
                input_categories_mutually_exclusive: false,
                reasoning_included_in_output: true,
                reasoning_applicable: true,
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

    fn observation(cache_read: TokenMetric, output: u64) -> ProviderUsageObservation {
        ProviderUsageObservation {
            uncached_input_tokens: TokenMetric::ProviderReported { value: 20 },
            cache_read_input_tokens: cache_read,
            cache_write_input_tokens: TokenMetric::NotApplicable,
            effective_input_tokens: TokenMetric::ProviderReported { value: 120 },
            output_tokens: TokenMetric::ProviderReported { value: output },
            reasoning_tokens: TokenMetric::ProviderReported { value: 0 },
            input_audio_tokens: TokenMetric::NotApplicable,
            output_audio_tokens: TokenMetric::NotApplicable,
            total_tokens: TokenMetric::ProviderReported { value: 128 },
            pricing_context_tokens: TokenMetric::ProviderReported { value: 120 },
            billable: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn resolved_price() -> PriceResolution {
        PriceResolution::Resolved(Box::new(InlinePriceRecord::CatalogV1(
            CatalogInlinePriceRecordV1 {
                format_version: 1,
                parser_version: 1,
                catalog_revision: "a".repeat(64),
                catalog_provider_id: "openai".to_owned(),
                catalog_model_id: "gpt-5-codex".to_owned(),
                mapping_revision: 1,
                prices: ComponentPrices {
                    uncached_input_per_million: Some(UnitPrice::from_scaled(
                        10i128.pow(PRICE_SCALE),
                    )),
                    ..ComponentPrices::default()
                },
                context_tier: None,
                selected_tier: None,
                unmodeled_billable_component: false,
                unmodeled_pricing_rule: false,
            },
        )))
    }

    struct Written {
        request_id: String,
        owner: String,
        key: Option<String>,
        completed_at_ms: i64,
        cost: ObservedCatalogCost,
        evidence: DispatchEvidence,
        cache_read: TokenMetric,
        cache_reporting: CacheReportingExpectation,
        attempts: u32,
        status: LogicalStatus,
    }

    impl Written {
        fn new(request_id: &str, owner: &str, completed_at_ms: i64) -> Self {
            Self {
                request_id: request_id.to_owned(),
                owner: owner.to_owned(),
                key: Some("key-1".to_owned()),
                completed_at_ms,
                cost: ObservedCatalogCost {
                    total_known: UsdAtoms::from_atoms(2_000_000),
                    status: CostStatus::CompleteForObservedCatalogComponents,
                    reasons: Vec::new(),
                    calculator_version: 1,
                },
                evidence: DispatchEvidence::ResponseObserved,
                cache_read: TokenMetric::ProviderReported { value: 100 },
                cache_reporting: CacheReportingExpectation::Expected,
                attempts: 1,
                status: LogicalStatus::Succeeded,
            }
        }
    }

    /// Write one logical request with `attempts` attempts; the last is the final one.
    async fn write(repository: &SqliteUsageRepository, spec: &Written) {
        repository
            .begin_logical_request(&LogicalRequestStart {
                request_id: spec.request_id.clone(),
                owner_user_id: spec.owner.clone(),
                api_key_id: spec.key.clone(),
                api_key_label: None,
                api_key_group_label: None,
                client_model_raw: Some("gpt-5-codex".to_owned()),
                routing_model: Some("gpt-5-codex".to_owned()),
                reasoning_effort: None,
                started_at_ms: spec.completed_at_ms - 1000,
            })
            .await
            .expect("begin");

        let mut final_attempt = String::new();
        for sequence in 1..=spec.attempts {
            let attempt_id = format!("{}#{sequence}", spec.request_id);
            let mut attempt_contract = contract();
            attempt_contract.cache_reporting_expectation = spec.cache_reporting;
            repository
                .record_attempt(&AttemptFacts {
                    attempt_id: attempt_id.clone(),
                    logical_request_id: spec.request_id.clone(),
                    sequence: AttemptSequence(sequence),
                    provider: ProviderKind::Codex,
                    account_id: "account-1".to_owned(),
                    configured_model: Some("gpt-5-codex".to_owned()),
                    provider_reported_model: None,
                    started_at_ms: spec.completed_at_ms - 1000,
                    first_token_at_ms: None,
                    completed_at_ms: spec.completed_at_ms,
                    dispatch_evidence: spec.evidence,
                    tracking: TrackingState::Complete,
                    contract: attempt_contract,
                    observation: observation(spec.cache_read, 8),
                    price: resolved_price(),
                    cost: spec.cost.clone(),
                })
                .await
                .expect("record attempt");
            final_attempt = attempt_id;
        }

        repository
            .complete_logical_request(&LogicalRequestTerminal {
                request_id: spec.request_id.clone(),
                completed_at_ms: spec.completed_at_ms,
                status: spec.status,
                execution: Some(ExecutionOutcome::StableSuccessTerminal),
                delivery: Some(DeliveryOutcome::CleanEof),
                final_attempt_id: Some(final_attempt),
                tracking: TrackingState::Complete,
                state_version: 1,
            })
            .await
            .expect("complete");
    }

    fn scope(owner: &str) -> UsageScope {
        UsageScope {
            owner_user_id: owner.to_owned(),
            api_key_id: None,
            client_model: None,
            group_label: None,
            range: TimeRange::new(T0, T0 + 24 * HOUR).expect("range"),
        }
    }

    #[tokio::test]
    async fn one_owner_never_sees_another_owners_usage() {
        // The single most important property of this layer.
        let repository = repository().await;
        write(&repository, &Written::new("mine", "user-1", T0 + HOUR)).await;
        write(&repository, &Written::new("theirs", "user-2", T0 + HOUR)).await;

        let mine = repository
            .overview(&scope("user-1"))
            .await
            .expect("overview");
        assert_eq!(mine.logical_requests, 1);
        assert_eq!(mine.tokens.effective_input, 120);

        let theirs = repository
            .overview(&scope("user-2"))
            .await
            .expect("overview");
        assert_eq!(theirs.logical_requests, 1);

        let page = repository
            .requests(&scope("user-1"), None, 50)
            .await
            .expect("requests");
        assert_eq!(page.requests.len(), 1);
        assert_eq!(page.requests[0].request_id, "mine");
    }

    #[tokio::test]
    async fn another_owners_request_is_indistinguishable_from_a_missing_one() {
        let repository = repository().await;
        write(&repository, &Written::new("theirs", "user-2", T0 + HOUR)).await;

        assert!(
            repository
                .request_attempt(&scope("user-1"), "theirs")
                .await
                .expect("lookup")
                .is_none(),
            "reading across owners must not be possible"
        );
        assert!(
            repository
                .request_attempt(&scope("user-1"), "never-existed")
                .await
                .expect("lookup")
                .is_none()
        );
        assert!(
            repository
                .request_attempt(&scope("user-2"), "theirs")
                .await
                .expect("lookup")
                .is_some()
        );
    }

    #[tokio::test]
    async fn request_details_obey_the_complete_scope() {
        let repository = repository().await;
        write(&repository, &Written::new("inside", "user-1", T0 + HOUR)).await;

        let mut outside_range = scope("user-1");
        outside_range.range = TimeRange::new(T0 + 2 * HOUR, T0 + 3 * HOUR).expect("range");
        assert!(
            repository
                .request_attempt(&outside_range, "inside")
                .await
                .expect("outside range lookup")
                .is_none()
        );

        let mut wrong_model = scope("user-1");
        wrong_model.client_model = Some("another-model".to_owned());
        assert!(
            repository
                .request_attempt(&wrong_model, "inside")
                .await
                .expect("wrong model lookup")
                .is_none()
        );

        let mut wrong_group = scope("user-1");
        wrong_group.group_label = Some("another-group".to_owned());
        assert!(
            repository
                .request_attempt(&wrong_group, "inside")
                .await
                .expect("wrong group lookup")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_key_filter_narrows_without_widening() {
        let repository = repository().await;
        let mut other_key = Written::new("other", "user-1", T0 + HOUR);
        other_key.key = Some("key-2".to_owned());
        write(&repository, &Written::new("mine", "user-1", T0 + HOUR)).await;
        write(&repository, &other_key).await;

        let mut scoped = scope("user-1");
        assert_eq!(
            repository
                .overview(&scoped)
                .await
                .expect("all")
                .logical_requests,
            2,
            "no key filter sees both"
        );

        scoped.api_key_id = Some("key-1".to_owned());
        let one = repository.overview(&scoped).await.expect("one key");
        assert_eq!(one.logical_requests, 1);
        assert_eq!(one.tokens.effective_input, 120);
    }

    #[tokio::test]
    async fn usage_counts_only_the_final_attempt() {
        let repository = repository().await;
        let mut spec = Written::new("retried", "user-1", T0 + HOUR);
        spec.attempts = 3;
        write(&repository, &spec).await;

        let usage = repository.overview(&scope("user-1")).await.expect("usage");
        assert_eq!(usage.tokens.effective_input, 120);
        assert_eq!(usage.logical_requests, 1);
    }

    #[tokio::test]
    async fn provider_health_counts_only_known_successes_and_failures() {
        let repository = repository().await;
        let succeeded = Written::new("health-success", "user-1", T0 + HOUR);
        let mut failed = Written::new("health-failed", "user-1", T0 + HOUR);
        failed.status = LogicalStatus::Failed;
        let mut incomplete = Written::new("health-incomplete", "user-1", T0 + HOUR);
        incomplete.status = LogicalStatus::Incomplete;
        let mut canceled = Written::new("health-canceled", "user-1", T0 + HOUR);
        canceled.status = LogicalStatus::Canceled;
        for spec in [&succeeded, &failed, &incomplete, &canceled] {
            write(&repository, spec).await;
        }

        let health = repository
            .provider_health(
                &["account-1".to_owned()],
                TimeRange::new(T0, T0 + 2 * HOUR).expect("range"),
            )
            .await
            .expect("provider health");

        assert_eq!(health.len(), 1);
        assert_eq!(health[0].requests, 2);
        assert_eq!(health[0].successes, 1);
        assert_eq!(health[0].failures, 1);
    }

    #[tokio::test]
    async fn a_cost_sum_past_the_64_bit_limit_is_still_exact() {
        // This is why the sum is split: one i64 accumulator tops out near $92,233.
        let repository = repository().await;
        let per_attempt = 9_000_000_000_000_000_000i128 / 4;
        for index in 0..8 {
            let mut spec = Written::new(&format!("big-{index}"), "user-1", T0 + HOUR);
            spec.cost.total_known = UsdAtoms::from_atoms(per_attempt);
            write(&repository, &spec).await;
        }

        let overview = repository
            .overview(&scope("user-1"))
            .await
            .expect("overview");
        assert_eq!(
            overview.cost.atoms.expect("priced cost").as_atoms(),
            per_attempt * 8,
            "the total exceeds i64 and must still be exact"
        );
        assert!(overview.cost.atoms.expect("priced cost").as_atoms() > i128::from(i64::MAX));
    }

    #[tokio::test]
    async fn cache_rate_uses_tokens_and_excludes_unreported_cache_detail() {
        let repository = repository().await;
        let hit = Written::new("hit", "user-1", T0 + HOUR);

        let mut miss = Written::new("miss", "user-1", T0 + HOUR);
        miss.cache_read = TokenMetric::ProviderReported { value: 0 };

        let mut unreported = Written::new("unreported", "user-1", T0 + HOUR);
        unreported.cache_read = TokenMetric::NotReported;

        for spec in [&hit, &miss, &unreported] {
            write(&repository, spec).await;
        }

        let cache = repository
            .overview(&scope("user-1"))
            .await
            .expect("overview")
            .cache;
        assert_eq!(cache.reported_input_tokens, 240);
        assert_eq!(cache.cache_read_input_tokens, 100);
    }

    #[tokio::test]
    async fn cache_counts_include_unknown_when_a_value_was_reported() {
        let repository = repository().await;
        // Default Written cache_read is ProviderReported { 100 }.
        let mut unknown_hit = Written::new("unknown-hit", "user-1", T0 + HOUR);
        unknown_hit.cache_reporting = CacheReportingExpectation::Unknown;
        write(&repository, &unknown_hit).await;

        let cache = repository
            .overview(&scope("user-1"))
            .await
            .expect("overview")
            .cache;
        assert_eq!(cache.reported_input_tokens, 120);
        assert_eq!(cache.cache_read_input_tokens, 100);
    }

    #[tokio::test]
    async fn cache_counts_exclude_unknown_when_nothing_was_reported() {
        let repository = repository().await;
        let mut unknown = Written::new("unknown", "user-1", T0 + HOUR);
        unknown.cache_reporting = CacheReportingExpectation::Unknown;
        unknown.cache_read = TokenMetric::NotReported;
        write(&repository, &unknown).await;

        let cache = repository
            .overview(&scope("user-1"))
            .await
            .expect("overview")
            .cache;
        assert_eq!(cache.reported_input_tokens, 0);
        assert_eq!(cache.cache_read_input_tokens, 0);
    }

    #[tokio::test]
    async fn a_logical_request_without_attempts_is_still_queryable() {
        let repository = repository().await;
        repository
            .begin_logical_request(&LogicalRequestStart {
                request_id: "preflight-failure".to_owned(),
                owner_user_id: "user-1".to_owned(),
                api_key_id: Some("key-1".to_owned()),
                api_key_label: None,
                api_key_group_label: None,
                client_model_raw: None,
                routing_model: None,
                reasoning_effort: None,
                started_at_ms: T0 + HOUR - 1,
            })
            .await
            .expect("begin");
        repository
            .complete_logical_request(&LogicalRequestTerminal {
                request_id: "preflight-failure".to_owned(),
                completed_at_ms: T0 + HOUR,
                status: LogicalStatus::Failed,
                execution: Some(ExecutionOutcome::StableFailure),
                delivery: Some(DeliveryOutcome::ErrorBeforeBytes),
                final_attempt_id: None,
                tracking: TrackingState::Complete,
                state_version: 1,
            })
            .await
            .expect("complete");

        let scope = scope("user-1");
        let overview = repository.overview(&scope).await.expect("overview");
        assert_eq!(overview.logical_requests, 1);

        let page = repository
            .requests(&scope, None, 10)
            .await
            .expect("requests");
        assert_eq!(page.requests.len(), 1);
        assert_eq!(page.requests[0].request_id, "preflight-failure");
        assert_eq!(page.requests[0].tokens, TokenTotals::default());
        assert_eq!(page.requests[0].cost, CostTotals::default());
    }

    #[tokio::test]
    async fn a_range_bounds_what_is_counted() {
        let repository = repository().await;
        write(&repository, &Written::new("before", "user-1", T0 - HOUR)).await;
        write(&repository, &Written::new("inside", "user-1", T0 + HOUR)).await;
        write(
            &repository,
            &Written::new("after", "user-1", T0 + 48 * HOUR),
        )
        .await;

        let overview = repository
            .overview(&scope("user-1"))
            .await
            .expect("overview");
        assert_eq!(overview.logical_requests, 1);
    }

    #[tokio::test]
    async fn paging_is_stable_and_covers_every_request_once() {
        let repository = repository().await;
        for index in 0..5 {
            write(
                &repository,
                &Written::new(&format!("req-{index}"), "user-1", T0 + HOUR + index),
            )
            .await;
        }

        let scoped = scope("user-1");
        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let page = repository
                .requests(&scoped, cursor.as_ref(), 2)
                .await
                .expect("page");
            seen.extend(page.requests.iter().map(|row| row.request_id.clone()));
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert_eq!(
            seen,
            vec!["req-4", "req-3", "req-2", "req-1", "req-0"],
            "newest first, every request exactly once"
        );
    }

    #[tokio::test]
    async fn retention_never_deletes_a_request_that_has_not_finished() {
        // An in-flight request has no terminal time to compare, and its facts are
        // still being written. Deleting it would erase live data.
        let repository = repository().await;
        write(
            &repository,
            &Written::new("finished", "user-1", T0 - 100 * HOUR),
        )
        .await;
        repository
            .begin_logical_request(&LogicalRequestStart {
                request_id: "still-running".to_owned(),
                owner_user_id: "user-1".to_owned(),
                api_key_id: None,
                api_key_label: None,
                api_key_group_label: None,
                client_model_raw: None,
                routing_model: None,
                reasoning_effort: None,
                started_at_ms: T0 - 200 * HOUR,
            })
            .await
            .expect("begin");

        let deleted = repository
            .delete_logical_requests_before(T0, 100)
            .await
            .expect("delete");
        assert_eq!(deleted, 1, "only the finished request is removed");
        assert!(
            repository
                .load_logical_request("still-running")
                .await
                .expect("load")
                .is_some(),
            "an unfinished request survives regardless of how old it is"
        );
        assert!(
            repository
                .load_logical_request("finished")
                .await
                .expect("load")
                .is_none()
        );
    }
}
