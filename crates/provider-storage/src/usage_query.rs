//! Indexed reads over usage facts.
//!
//! Every statement here starts from the same scoped `FROM`/`WHERE`, built by
//! [`scoped_from`], so the owner filter cannot be forgotten in one query and
//! present in another. The attribution basis is the only part that varies, and it
//! varies by swapping one predicate.
//!
//! The statements are assembled at runtime, which sqlx makes you vouch for. What
//! gets interpolated is only ever a compile-time constant chosen by a Rust enum —
//! the basis predicate, a bucket width, a clamped page size. Every value that came
//! from a caller is a bound parameter, so no input reaches the SQL text.
//!
//! Cost sums are split before they are added: `SUM(cost_atoms)` overflows a 64-bit
//! accumulator at roughly `$92,233`, so each sum is taken over `atoms / 10^6` and
//! `atoms % 10^6` and recombined exactly in Rust. Nothing is rounded to make a
//! total fit.

use async_trait::async_trait;
use provider_usage::{
    ATOM_SPLIT, AttemptFacts, AttributionBasis, CacheTotals, CostTotals, MAX_PAGE_SIZE,
    ProviderHealthSummary, RequestCursor, RequestPage, RequestSummary, TokenTotals,
    UsageFilterOptions, UsageOverview, UsageQuery, UsageRepositoryError, UsageScope,
    recombine_atoms, system_clock_ms,
};
use sqlx::{AssertSqlSafe, Row, sqlite::SqliteRow};

use crate::{
    SqliteUsageRepository,
    usage::{attempt_facts, usage_error},
};

/// The scoped source every query reads from.
///
/// Bind order, once per query: owner, key, key, model, model, group, group, from, to.
fn scoped_from(basis: AttributionBasis) -> String {
    // `final_attempt_id` is what the user actually received; confirmed dispatch is
    // what the provider actually served, retries included.
    let basis_predicate = match basis {
        AttributionBasis::UserFinalAttempt => "a.id = l.final_attempt_id",
        AttributionBasis::KeyTriggeredConfirmedDispatch => {
            "a.dispatch_evidence IN ('dispatch_invoked', 'response_observed')"
        }
    };
    format!(
        r#"
        FROM usage_logical_requests AS l
        LEFT JOIN usage_attempts AS a
          ON a.logical_request_id = l.request_id
         AND {basis_predicate}
        WHERE l.owner_user_id = ?
          -- All placeholders are positional. A numbered one here would silently
          -- re-use the owner parameter and shift everything after it.
          AND (? IS NULL OR l.api_key_id = ?)
          AND (? IS NULL OR l.client_model_raw = ?)
          AND (? IS NULL OR l.api_key_group_label = ?)
          AND l.completed_at_ms >= ?
          AND l.completed_at_ms < ?
        "#
    )
}

/// The aggregate columns shared by the overview and each series bucket.
const TOTALS_COLUMNS: &str = r#"
    COUNT(a.id) AS attempts,
    COUNT(DISTINCT l.request_id) AS logical_requests,
    COALESCE(SUM(a.uncached_input_tokens), 0) AS uncached_input,
    COALESCE(SUM(a.cache_read_input_tokens), 0) AS cache_read_input,
    COALESCE(SUM(a.cache_write_input_tokens), 0) AS cache_write_input,
    COALESCE(SUM(a.effective_input_tokens), 0) AS effective_input,
    COALESCE(SUM(a.output_tokens), 0) AS output,
    COALESCE(SUM(a.reasoning_tokens), 0) AS reasoning,
    COUNT(a.id) - COUNT(a.effective_input_tokens) AS unknown_input,
    COALESCE(SUM(CASE WHEN a.cost_status = 'complete_for_observed_catalog_components'
        THEN a.cost_atoms / 1000000 ELSE 0 END), 0) AS complete_high,
    COALESCE(SUM(CASE WHEN a.cost_status = 'complete_for_observed_catalog_components'
        THEN a.cost_atoms % 1000000 ELSE 0 END), 0) AS complete_low,
    COALESCE(SUM(CASE WHEN a.cost_status = 'complete_for_observed_catalog_components'
        THEN 1 ELSE 0 END), 0) AS complete_attempts,
    COALESCE(SUM(CASE WHEN a.cost_status = 'partial' THEN 1 ELSE 0 END), 0) AS partial_attempts,
    COALESCE(SUM(CASE WHEN a.cost_status = 'unavailable' THEN 1 ELSE 0 END), 0) AS unavailable_attempts
"#;

/// Cache columns, following the contract's three dimensions.
///
/// Coverage includes an attempt when a report was expected, *or* when a cache
/// read value was actually observed. The latter matters for providers whose
/// contract still says reporting is unknown but which do report on some calls:
/// a known number is a hit or a miss, never an exclusion.
const CACHE_COLUMNS: &str = r#"
    COALESCE(SUM(CASE WHEN a.cache_capability = 'supported'
              AND a.cache_eligibility = 'eligible'
              AND (
                    a.cache_reporting_expectation = 'expected'
                    OR a.cache_read_input_tokens IS NOT NULL
                  )
        THEN 1 ELSE 0 END), 0) AS coverage_denominator,
    COALESCE(SUM(CASE WHEN a.cache_capability = 'supported'
              AND a.cache_eligibility = 'eligible'
              AND (
                    a.cache_reporting_expectation = 'expected'
                    OR a.cache_read_input_tokens IS NOT NULL
                  )
              AND a.cache_read_input_tokens > 0
        THEN 1 ELSE 0 END), 0) AS cache_hits,
    COALESCE(SUM(CASE WHEN a.cache_capability = 'supported'
              AND a.cache_eligibility = 'eligible'
              AND (
                    a.cache_reporting_expectation = 'expected'
                    OR a.cache_read_input_tokens IS NOT NULL
                  )
              AND a.cache_read_input_tokens = 0
        THEN 1 ELSE 0 END), 0) AS cache_misses,
    COALESCE(SUM(CASE WHEN a.cache_capability = 'supported'
              AND a.cache_eligibility = 'eligible'
              AND a.cache_reporting_expectation = 'expected'
              AND a.cache_read_input_tokens IS NULL
        THEN 1 ELSE 0 END), 0) AS cache_unreported
"#;

#[async_trait]
impl UsageQuery for SqliteUsageRepository {
    async fn overview(&self, scope: &UsageScope) -> Result<UsageOverview, UsageRepositoryError> {
        let sql = format!(
            "SELECT {TOTALS_COLUMNS}, {CACHE_COLUMNS} {}",
            scoped_from(scope.basis)
        );
        let row = bind_scope(sqlx::query(AssertSqlSafe(sql)), scope)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| usage_error("failed to read usage overview", error))?;

        Ok(UsageOverview {
            // The read's own clock, used only to explain concurrent differences.
            // Not the range's end: for a window ending in the future that would
            // date the snapshot ahead of when it was taken, and for a historical
            // window it would claim the numbers are as old as the data.
            as_of_ms: system_clock_ms(),
            logical_requests: count(&row, "logical_requests")?,
            attempts: count(&row, "attempts")?,
            tokens: token_totals(&row)?,
            cache: cache_totals(&row)?,
            cost: cost_totals(&row)?,
            tracking_gaps: self.tracking_gaps(scope).await?,
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
            scoped_from(unfiltered.basis)
        );
        let model_rows = bind_scope(sqlx::query(AssertSqlSafe(model_sql)), &unfiltered)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| usage_error("failed to read usage model filters", error))?;

        let group_sql = format!(
            "SELECT DISTINCT l.api_key_group_label AS value {} AND l.api_key_group_label IS NOT NULL ORDER BY value",
            scoped_from(unfiltered.basis)
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
            scoped_from(scope.basis)
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

    async fn request_attempts(
        &self,
        scope: &UsageScope,
        request_id: &str,
    ) -> Result<Option<Vec<AttemptFacts>>, UsageRepositoryError> {
        // The owner check is part of the lookup, so another user's request is
        // indistinguishable from one that does not exist.
        let owned: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT 1 FROM usage_logical_requests
            WHERE request_id = ? AND owner_user_id = ?
              AND (? IS NULL OR api_key_id = ?)
            "#,
        )
        .bind(request_id)
        .bind(&scope.owner_user_id)
        .bind(scope.api_key_id.as_deref())
        .bind(scope.api_key_id.as_deref())
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| usage_error("failed to check usage request owner", error))?;
        if owned.is_none() {
            return Ok(None);
        }

        let rows = sqlx::query(
            "SELECT * FROM usage_attempts WHERE logical_request_id = ? ORDER BY sequence",
        )
        .bind(request_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| usage_error("failed to read usage request attempts", error))?;

        let mut attempts = Vec::with_capacity(rows.len());
        for row in rows {
            let mut facts = attempt_facts(row)?;
            facts.observation.billable = self.billable_for(&facts.attempt_id).await?;
            attempts.push(facts);
        }
        Ok(Some(attempts))
    }
}

impl SqliteUsageRepository {
    /// Known bookkeeping losses whose bucket overlaps the range.
    async fn tracking_gaps(&self, scope: &UsageScope) -> Result<u64, UsageRepositoryError> {
        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(count), 0) FROM usage_tracking_gaps
            WHERE owner_user_id = ?
              AND bucket_start_ms >= ?
              AND bucket_start_ms < ?
            "#,
        )
        .bind(&scope.owner_user_id)
        .bind(scope.range.from_ms)
        .bind(scope.range.to_ms)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| usage_error("failed to read usage tracking gaps", error))?;
        u64::try_from(total)
            .map_err(|_| UsageRepositoryError::new("usage tracking gap count is invalid"))
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
        uncached_input: count(row, "uncached_input")?,
        cache_read_input: count(row, "cache_read_input")?,
        cache_write_input: count(row, "cache_write_input")?,
        effective_input: count(row, "effective_input")?,
        output: count(row, "output")?,
        reasoning: count(row, "reasoning")?,
        attempts_with_unknown_input: count(row, "unknown_input")?,
    })
}

fn cache_totals(row: &SqliteRow) -> Result<CacheTotals, UsageRepositoryError> {
    let denominator = count(row, "coverage_denominator")?;
    let attempts = count(row, "attempts")?;
    let excluded = attempts
        .checked_sub(denominator)
        .ok_or_else(|| UsageRepositoryError::new("cache coverage exceeds the attempt count"))?;
    Ok(CacheTotals {
        coverage_denominator: denominator,
        hits: count(row, "cache_hits")?,
        misses: count(row, "cache_misses")?,
        expected_but_unreported: count(row, "cache_unreported")?,
        excluded,
    })
}

fn cost_totals(row: &SqliteRow) -> Result<CostTotals, UsageRepositoryError> {
    Ok(CostTotals {
        complete_atoms: split_sum(row, "complete_high", "complete_low")?,
        complete_attempts: count(row, "complete_attempts")?,
        partial_attempts: count(row, "partial_attempts")?,
        unavailable_attempts: count(row, "unavailable_attempts")?,
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
        AttemptSequence, ComponentPrices, CostStatus, DeliveryOutcome, DispatchEvidence,
        ExecutionOutcome, InlinePriceRecord, LogicalRequestStart, LogicalRequestTerminal,
        LogicalStatus, ObservedCatalogCost, PRICE_SCALE, PriceResolution, TimeRange, TrackingState,
        UnitPrice, UsageRepository, UsdAtoms,
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
        PriceResolution::Resolved(Box::new(InlinePriceRecord {
            format_version: 1,
            parser_version: 1,
            catalog_revision: "a".repeat(64),
            catalog_provider_id: "openai".to_owned(),
            catalog_model_id: "gpt-5-codex".to_owned(),
            mapping_revision: 1,
            prices: ComponentPrices {
                uncached_input_per_million: Some(UnitPrice::from_scaled(10i128.pow(PRICE_SCALE))),
                ..ComponentPrices::default()
            },
            selected_tier: None,
            unmodeled_billable_component: false,
            unmodeled_pricing_rule: false,
        }))
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
                status: LogicalStatus::Succeeded,
                execution: Some(ExecutionOutcome::StableSuccessTerminal),
                delivery: Some(DeliveryOutcome::CleanEof),
                final_attempt_id: Some(final_attempt),
                tracking: TrackingState::Complete,
                state_version: 1,
            })
            .await
            .expect("complete");
    }

    fn scope(owner: &str, basis: AttributionBasis) -> UsageScope {
        UsageScope {
            owner_user_id: owner.to_owned(),
            api_key_id: None,
            client_model: None,
            group_label: None,
            range: TimeRange::new(T0, T0 + 24 * HOUR).expect("range"),
            basis,
        }
    }

    #[tokio::test]
    async fn one_owner_never_sees_another_owners_usage() {
        // The single most important property of this layer.
        let repository = repository().await;
        write(&repository, &Written::new("mine", "user-1", T0 + HOUR)).await;
        write(&repository, &Written::new("theirs", "user-2", T0 + HOUR)).await;

        let mine = repository
            .overview(&scope("user-1", AttributionBasis::UserFinalAttempt))
            .await
            .expect("overview");
        assert_eq!(mine.logical_requests, 1);
        assert_eq!(mine.attempts, 1);
        assert_eq!(mine.tokens.effective_input, 120);

        let theirs = repository
            .overview(&scope("user-2", AttributionBasis::UserFinalAttempt))
            .await
            .expect("overview");
        assert_eq!(theirs.logical_requests, 1);

        let page = repository
            .requests(
                &scope("user-1", AttributionBasis::UserFinalAttempt),
                None,
                50,
            )
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
                .request_attempts(
                    &scope("user-1", AttributionBasis::UserFinalAttempt),
                    "theirs"
                )
                .await
                .expect("lookup")
                .is_none(),
            "reading across owners must not be possible"
        );
        assert!(
            repository
                .request_attempts(
                    &scope("user-1", AttributionBasis::UserFinalAttempt),
                    "never-existed"
                )
                .await
                .expect("lookup")
                .is_none()
        );
        assert!(
            repository
                .request_attempts(
                    &scope("user-2", AttributionBasis::UserFinalAttempt),
                    "theirs"
                )
                .await
                .expect("lookup")
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_key_filter_narrows_without_widening() {
        let repository = repository().await;
        let mut other_key = Written::new("other", "user-1", T0 + HOUR);
        other_key.key = Some("key-2".to_owned());
        write(&repository, &Written::new("mine", "user-1", T0 + HOUR)).await;
        write(&repository, &other_key).await;

        let mut scoped = scope("user-1", AttributionBasis::UserFinalAttempt);
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
    async fn the_two_attribution_bases_count_retries_differently() {
        // Three attempts, one logical request: the user got one response, the
        // provider served three.
        let repository = repository().await;
        let mut spec = Written::new("retried", "user-1", T0 + HOUR);
        spec.attempts = 3;
        write(&repository, &spec).await;

        let user = repository
            .overview(&scope("user-1", AttributionBasis::UserFinalAttempt))
            .await
            .expect("user basis");
        assert_eq!(user.attempts, 1, "the user received one response");
        assert_eq!(user.tokens.effective_input, 120);

        let resource = repository
            .overview(&scope(
                "user-1",
                AttributionBasis::KeyTriggeredConfirmedDispatch,
            ))
            .await
            .expect("resource basis");
        assert_eq!(resource.attempts, 3, "the provider served three calls");
        assert_eq!(resource.tokens.effective_input, 360);
        assert_eq!(resource.logical_requests, 1, "still one request");
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
            .overview(&scope("user-1", AttributionBasis::UserFinalAttempt))
            .await
            .expect("overview");
        assert_eq!(
            overview.cost.complete_atoms.as_atoms(),
            per_attempt * 8,
            "the total exceeds i64 and must still be exact"
        );
        assert!(overview.cost.complete_atoms.as_atoms() > i128::from(i64::MAX));
    }

    #[tokio::test]
    async fn cache_coverage_separates_a_miss_from_an_unreported_read() {
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
            .overview(&scope("user-1", AttributionBasis::UserFinalAttempt))
            .await
            .expect("overview")
            .cache;
        assert_eq!(cache.coverage_denominator, 3);
        assert_eq!(cache.hits, 1);
        assert_eq!(cache.misses, 1, "a reported zero is a miss");
        assert_eq!(
            cache.expected_but_unreported, 1,
            "an unreported read is not a miss"
        );
        assert_eq!(cache.excluded, 0);
    }

    #[tokio::test]
    async fn cache_counts_include_unknown_when_a_value_was_reported() {
        let repository = repository().await;
        // Default Written cache_read is ProviderReported { 100 }.
        let mut unknown_hit = Written::new("unknown-hit", "user-1", T0 + HOUR);
        unknown_hit.cache_reporting = CacheReportingExpectation::Unknown;
        write(&repository, &unknown_hit).await;

        let cache = repository
            .overview(&scope("user-1", AttributionBasis::UserFinalAttempt))
            .await
            .expect("overview")
            .cache;
        assert_eq!(cache.coverage_denominator, 1);
        assert_eq!(
            cache.hits, 1,
            "a reported cache read is a hit even when expectation is unknown"
        );
        assert_eq!(cache.misses, 0);
        assert_eq!(cache.expected_but_unreported, 0);
        assert_eq!(cache.excluded, 0);
    }

    #[tokio::test]
    async fn cache_counts_exclude_unknown_when_nothing_was_reported() {
        let repository = repository().await;
        let mut unknown = Written::new("unknown", "user-1", T0 + HOUR);
        unknown.cache_reporting = CacheReportingExpectation::Unknown;
        unknown.cache_read = TokenMetric::NotReported;
        write(&repository, &unknown).await;

        let cache = repository
            .overview(&scope("user-1", AttributionBasis::UserFinalAttempt))
            .await
            .expect("overview")
            .cache;
        assert_eq!(cache.coverage_denominator, 0);
        assert_eq!(cache.hits, 0, "an excluded attempt cannot be a hit");
        assert_eq!(cache.misses, 0, "an excluded attempt cannot be a miss");
        assert_eq!(cache.expected_but_unreported, 0);
        assert_eq!(cache.excluded, 1);
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

        let scope = scope("user-1", AttributionBasis::UserFinalAttempt);
        let overview = repository.overview(&scope).await.expect("overview");
        assert_eq!(overview.logical_requests, 1);
        assert_eq!(overview.attempts, 0);
        assert_eq!(overview.tokens.attempts_with_unknown_input, 0);

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
            .overview(&scope("user-1", AttributionBasis::UserFinalAttempt))
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

        let scoped = scope("user-1", AttributionBasis::UserFinalAttempt);
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
