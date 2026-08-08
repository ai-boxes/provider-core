//! SQLite persistence for observed usage facts.
//!
//! Enum values are mapped to column text by explicit `match`, not by reusing a
//! serde rename. The vocabulary in the database is a schema decision guarded by
//! `CHECK` constraints, so adding a variant should fail to compile here and force
//! that decision, rather than silently write a value the schema rejects.
//!
//! Token counts follow one rule end to end: the column holds a known number, and
//! `NULL` means "not a known number". The reason it is not known lives in
//! `token_kinds_json`, which carries an entry for every metric that is *not* a
//! plain provider-reported value — so a fully reported attempt stores `{}`.

use async_trait::async_trait;
use provider_auth::add_atoms;
use provider_core::{
    ProviderKind,
    usage::{
        BillableComponentCode, BillableObservation, BillableUnit, CacheCapability,
        CacheEligibility, CacheReportingExpectation, NormalizationWarning, PricingContextBasis,
        PricingMode, ProviderUsageObservation, TokenInclusionRules, TokenMetric,
        TokenUnknownReason, UsageContractSnapshot,
    },
};
use provider_usage::{
    AttemptFacts, AttemptSequence, CostReason, CostStatus, DeliveryOutcome, DispatchEvidence,
    ExecutionOutcome, InlinePriceRecord, LogicalRequestStart, LogicalRequestTerminal,
    LogicalStatus, LogicalWriteOutcome, ObservedCatalogCost, PriceResolution, StoredCatalog,
    StoredLogicalRequest, TrackingGapReason, TrackingState, UsageRepository, UsageRepositoryError,
    UsdAtoms,
};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};

/// Observed-usage facts stored in the same SQLite database as accounts and auth.
///
/// One database keeps the deployment a single file to back up and a single set of
/// migrations. Usage writes happen after a response reaches its terminal state,
/// so they do not sit on the proxy's hot path and do not need a connection of
/// their own.
#[derive(Clone)]
pub struct SqliteUsageRepository {
    pub(crate) pool: SqlitePool,
}

impl SqliteUsageRepository {
    #[must_use]
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UsageRepository for SqliteUsageRepository {
    async fn begin_logical_request(
        &self,
        start: &LogicalRequestStart,
    ) -> Result<LogicalWriteOutcome, UsageRepositoryError> {
        // A duplicate start is a no-op: the writer may redeliver, and the row
        // already carries everything this event has.
        let result = sqlx::query(
            r#"
            INSERT INTO usage_logical_requests (
                request_id, owner_user_id, api_key_id, api_key_label, api_key_group_label,
                client_model_raw, routing_model,
                reasoning_effort, started_at_ms, logical_status, tracking_state, state_version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'in_progress', 'complete', 0)
            ON CONFLICT (request_id) DO NOTHING
            "#,
        )
        .bind(&start.request_id)
        .bind(&start.owner_user_id)
        .bind(start.api_key_id.as_deref())
        .bind(start.api_key_label.as_deref())
        .bind(start.api_key_group_label.as_deref())
        .bind(start.client_model_raw.as_deref())
        .bind(start.routing_model.as_deref())
        .bind(start.reasoning_effort.as_deref())
        .bind(start.started_at_ms)
        .execute(&self.pool)
        .await
        .map_err(|error| usage_error("failed to begin usage logical request", error))?;

        Ok(if result.rows_affected() == 0 {
            LogicalWriteOutcome::AlreadyKnown
        } else {
            LogicalWriteOutcome::Written
        })
    }

    async fn complete_logical_request(
        &self,
        terminal: &LogicalRequestTerminal,
    ) -> Result<LogicalWriteOutcome, UsageRepositoryError> {
        if !terminal.status.is_terminal() {
            return Err(UsageRepositoryError::new(
                "refusing to store a non-terminal logical status as terminal",
            ));
        }
        let (tracking_state, gap_reason) = tracking_columns(terminal.tracking);
        let state_version = i64::from(terminal.state_version);

        // The guard makes a late or duplicated event a no-op instead of a
        // rollback to older state.
        let result = sqlx::query(
            r#"
            UPDATE usage_logical_requests
            SET
                completed_at_ms = ?,
                logical_status = ?,
                execution_outcome = ?,
                delivery_outcome = ?,
                final_attempt_id = ?,
                tracking_state = ?,
                tracking_gap_reason = ?,
                state_version = ?
            WHERE request_id = ? AND state_version < ?
            "#,
        )
        .bind(terminal.completed_at_ms)
        .bind(logical_status_str(terminal.status))
        .bind(terminal.execution.map(execution_outcome_str))
        .bind(terminal.delivery.map(delivery_outcome_str))
        .bind(terminal.final_attempt_id.as_deref())
        .bind(tracking_state)
        .bind(gap_reason)
        .bind(state_version)
        .bind(&terminal.request_id)
        .bind(state_version)
        .execute(&self.pool)
        .await
        .map_err(|error| usage_error("failed to complete usage logical request", error))?;

        if result.rows_affected() > 0 {
            return Ok(LogicalWriteOutcome::Written);
        }

        // Nothing changed: either the start row was never persisted, or a newer
        // state is already stored. The two mean different things to the caller.
        // The follow-up read is safe because the bounded writer is the only
        // writer, so no concurrent insert can land between the two statements.
        let exists: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM usage_logical_requests WHERE request_id = ?")
                .bind(&terminal.request_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| usage_error("failed to check usage logical request", error))?;
        Ok(if exists.is_some() {
            LogicalWriteOutcome::AlreadyKnown
        } else {
            LogicalWriteOutcome::MissingRequest
        })
    }

    async fn record_attempt(&self, facts: &AttemptFacts) -> Result<(), UsageRepositoryError> {
        let contract = &facts.contract;
        let inclusion_json = serde_json::to_string(&contract.inclusion)
            .map_err(|error| usage_error("failed to encode usage inclusion rules", error))?;
        let (values, kinds) = split_observation(&facts.observation);
        let token_kinds_json = serde_json::to_string(&kinds)
            .map_err(|error| usage_error("failed to encode token metric kinds", error))?;
        let warnings_json = serde_json::to_string(
            &facts
                .observation
                .warnings
                .iter()
                .map(|warning| warning_str(*warning))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| usage_error("failed to encode normalization warnings", error))?;

        let price_json = match &facts.price {
            PriceResolution::Resolved(record) => Some(
                serde_json::to_string(record.as_ref())
                    .map_err(|error| usage_error("failed to encode inline price record", error))?,
            ),
            _ => None,
        };
        let record = facts.price.resolved();
        let cost = storable_cost(&facts.cost);
        let cost_reasons_json = serde_json::to_string(
            &cost
                .reasons
                .iter()
                .map(|reason| cost_reason_str(*reason))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| usage_error("failed to encode cost reasons", error))?;

        let (tracking_state, gap_reason) = tracking_columns(facts.tracking);

        // The schema forbids this too, but a CHECK failure says nothing useful.
        // An attempt that never crossed the transport gate cannot have observed
        // usage or a cost, and the caller wants to know it built one that did.
        if matches!(facts.dispatch_evidence, DispatchEvidence::NotInvoked)
            && (!matches!(cost.status, CostStatus::Unavailable)
                || values.effective_input.is_some()
                || values.output.is_some()
                || values.total.is_some())
        {
            return Err(UsageRepositoryError::new(
                "a not-invoked attempt cannot carry observed usage or a cost estimate",
            ));
        }

        // The attempt row and the lifetime API-key spend must commit together.
        // IMMEDIATE takes SQLite's write lock before reading spent_atoms, so two
        // concurrent completions cannot both calculate from the same old value.
        let mut transaction = self
            .pool
            .acquire()
            .await
            .map_err(|error| usage_error("failed to acquire usage write connection", error))?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .map_err(|error| usage_error("failed to start usage attempt transaction", error))?;

        // A redelivered attempt is a no-op. Only the primary key is excluded:
        // a *different* attempt id colliding on (request, sequence) must still
        // fail loudly, because ignoring it would double-count upstream usage.
        let inserted = sqlx::query(
            r#"
            INSERT INTO usage_attempts (
                id, logical_request_id, sequence,
                provider, account_id, configured_model, provider_reported_model,
                started_at_ms, first_token_at_ms, completed_at_ms, dispatch_evidence,
                tracking_state, tracking_gap_reason,
                contract_version, normalization_version, inclusion_json,
                cache_capability, cache_eligibility, cache_reporting_expectation,
                pricing_context_basis, pricing_mode,
                uncached_input_tokens, cache_read_input_tokens, cache_write_input_tokens,
                effective_input_tokens, output_tokens, reasoning_tokens,
                input_audio_tokens, output_audio_tokens, total_tokens,
                pricing_context_tokens,
                token_kinds_json, normalization_warnings_json,
                price_resolution, catalog_revision, selected_tier, price_json,
                calculator_version, cost_status, cost_atoms, cost_reasons_json
            )
            VALUES (
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?,
                ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(&facts.attempt_id)
        .bind(&facts.logical_request_id)
        .bind(i64::from(facts.sequence.0))
        .bind(facts.provider.as_str())
        .bind(&facts.account_id)
        .bind(facts.configured_model.as_deref())
        .bind(facts.provider_reported_model.as_deref())
        .bind(facts.started_at_ms)
        .bind(facts.first_token_at_ms)
        .bind(facts.completed_at_ms)
        .bind(dispatch_evidence_str(facts.dispatch_evidence))
        .bind(tracking_state)
        .bind(gap_reason)
        .bind(i64::from(contract.contract_version))
        .bind(i64::from(contract.normalization_version))
        .bind(&inclusion_json)
        .bind(cache_capability_str(contract.cache_capability))
        .bind(cache_eligibility_str(contract.cache_eligibility))
        .bind(cache_reporting_str(contract.cache_reporting_expectation))
        .bind(pricing_basis_str(contract.pricing_context_basis))
        .bind(pricing_mode_str(contract.pricing_mode))
        .bind(values.uncached_input)
        .bind(values.cache_read_input)
        .bind(values.cache_write_input)
        .bind(values.effective_input)
        .bind(values.output)
        .bind(values.reasoning)
        .bind(values.input_audio)
        .bind(values.output_audio)
        .bind(values.total)
        .bind(values.pricing_context)
        .bind(&token_kinds_json)
        .bind(&warnings_json)
        .bind(price_resolution_str(&facts.price))
        .bind(record.and_then(|record| record.catalog_revision()))
        .bind(record.and_then(|record| record.selected_tier()))
        .bind(price_json.as_deref())
        .bind(i64::from(cost.calculator_version))
        .bind(cost_status_str(cost.status))
        .bind(cost.atoms)
        .bind(&cost_reasons_json)
        .execute(&mut *transaction)
        .await
        .map_err(|error| usage_error("failed to record usage attempt", error))?;

        if inserted.rows_affected() > 0 {
            for observation in &facts.observation.billable {
                sqlx::query(
                    r#"
                    INSERT INTO usage_billable_observations (
                        attempt_id, component_code, unit, quantity
                    )
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT (attempt_id, component_code) DO UPDATE SET
                        unit = excluded.unit,
                        quantity = excluded.quantity
                    "#,
                )
                .bind(&facts.attempt_id)
                .bind(billable_code_str(observation.component_code))
                .bind(billable_unit_str(observation.unit))
                .bind(storable_quantity(observation.quantity)?)
                .execute(&mut *transaction)
                .await
                .map_err(|error| usage_error("failed to record billable observation", error))?;
            }
        }

        sqlx::query("COMMIT")
            .execute(&mut *transaction)
            .await
            .map_err(|error| usage_error("failed to commit usage attempt", error))?;
        Ok(())
    }

    async fn record_quota_ledger_entry(
        &self,
        entry: &provider_usage::QuotaLedgerEntry,
    ) -> Result<(), UsageRepositoryError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|error| usage_error("failed to acquire quota ledger connection", error))?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to start quota ledger transaction", error))?;
        let state = if entry.cost_atoms.is_some() {
            "charged"
        } else {
            "indeterminate"
        };
        let inserted = sqlx::query(
            r#"
            INSERT INTO api_key_quota_ledger
                (entry_id, api_key_id, cost_atoms, accounting_state, recorded_at_ms)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (entry_id) DO NOTHING
            "#,
        )
        .bind(&entry.entry_id)
        .bind(&entry.api_key_id)
        .bind(entry.cost_atoms.as_deref())
        .bind(state)
        .bind(entry.recorded_at_ms)
        .execute(&mut *connection)
        .await
        .map_err(|error| usage_error("failed to insert quota ledger entry", error))?;

        if inserted.rows_affected() > 0 {
            if let Some(atoms) = entry.cost_atoms.as_deref() {
                let spent: Option<String> =
                    sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = ?")
                        .bind(&entry.api_key_id)
                        .fetch_optional(&mut *connection)
                        .await
                        .map_err(|error| {
                            usage_error("failed to load API key quota spend", error)
                        })?;
                if let Some(spent) = spent {
                    let next = add_atoms(&spent, atoms)
                        .map_err(|_| UsageRepositoryError::new("API key spend overflowed"))?;
                    sqlx::query("UPDATE api_keys SET spent_atoms = ? WHERE id = ?")
                        .bind(next)
                        .bind(&entry.api_key_id)
                        .execute(&mut *connection)
                        .await
                        .map_err(|error| {
                            usage_error("failed to update API key quota spend", error)
                        })?;
                }
            } else {
                sqlx::query(
                    "UPDATE api_keys SET quota_accounting_state = 'indeterminate' WHERE id = ?",
                )
                .bind(&entry.api_key_id)
                .execute(&mut *connection)
                .await
                .map_err(|error| {
                    usage_error("failed to mark API key quota indeterminate", error)
                })?;
            }
        }
        sqlx::query("COMMIT")
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to commit quota ledger entry", error))?;
        Ok(())
    }

    async fn record_tracking_gap(
        &self,
        owner_user_id: &str,
        reason: TrackingGapReason,
        bucket_start_ms: i64,
        count: u64,
    ) -> Result<(), UsageRepositoryError> {
        let count = i64::try_from(count)
            .map_err(|_| UsageRepositoryError::new("tracking gap count is too large to store"))?;
        if count == 0 {
            return Ok(());
        }
        sqlx::query(
            r#"
            INSERT INTO usage_tracking_gaps (owner_user_id, reason, bucket_start_ms, count)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (owner_user_id, reason, bucket_start_ms) DO UPDATE SET
                count = count + excluded.count
            "#,
        )
        .bind(owner_user_id)
        .bind(gap_reason_str(reason))
        .bind(bucket_start_ms)
        .bind(count)
        .execute(&self.pool)
        .await
        .map_err(|error| usage_error("failed to record usage tracking gap", error))?;
        Ok(())
    }

    async fn recover_in_flight_requests(&self, now_ms: i64) -> Result<u64, UsageRepositoryError> {
        // A request a previous run left in flight has no knowable terminal. It
        // becomes `incomplete` with a gap, never a guessed success or failure.
        let result = sqlx::query(
            r#"
            UPDATE usage_logical_requests
            SET
                completed_at_ms = ?,
                logical_status = 'incomplete',
                execution_outcome = 'recovered_old_run_active',
                delivery_outcome = 'unknown',
                tracking_state = 'gap',
                tracking_gap_reason = 'recovered_in_flight',
                state_version = state_version + 1
            WHERE logical_status = 'in_progress'
            "#,
        )
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|error| usage_error("failed to recover in-flight usage requests", error))?;
        Ok(result.rows_affected())
    }

    async fn load_logical_request(
        &self,
        request_id: &str,
    ) -> Result<Option<StoredLogicalRequest>, UsageRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                request_id, owner_user_id, api_key_id, api_key_label, api_key_group_label,
                client_model_raw, routing_model,
                reasoning_effort, started_at_ms, completed_at_ms, logical_status, execution_outcome,
                delivery_outcome, final_attempt_id, tracking_state, tracking_gap_reason,
                state_version
            FROM usage_logical_requests
            WHERE request_id = ?
            "#,
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| usage_error("failed to load usage logical request", error))?;

        row.map(stored_logical_request).transpose()
    }

    async fn load_attempts(
        &self,
        request_id: &str,
    ) -> Result<Vec<AttemptFacts>, UsageRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT *
            FROM usage_attempts
            WHERE logical_request_id = ?
            ORDER BY sequence
            "#,
        )
        .bind(request_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| usage_error("failed to load usage attempts", error))?;

        let mut attempts = Vec::with_capacity(rows.len());
        for row in rows {
            let mut facts = attempt_facts(row)?;
            facts.observation.billable = self.billable_for(&facts.attempt_id).await?;
            attempts.push(facts);
        }
        Ok(attempts)
    }

    async fn delete_logical_requests_before(
        &self,
        cutoff_ms: i64,
        batch: u32,
    ) -> Result<u64, UsageRepositoryError> {
        // One statement per batch, so the transaction stays short enough not to
        // block the proxy's own writes. Attempts and billable observations go with
        // the request through `ON DELETE CASCADE`, which is what keeps retention a
        // whole-logical-unit operation.
        let result = sqlx::query(
            r#"
            DELETE FROM usage_logical_requests
            WHERE request_id IN (
                SELECT request_id FROM usage_logical_requests
                WHERE logical_status <> 'in_progress'
                  AND completed_at_ms IS NOT NULL
                  AND completed_at_ms < ?
                ORDER BY completed_at_ms, request_id
                LIMIT ?
            )
            "#,
        )
        .bind(cutoff_ms)
        .bind(i64::from(batch))
        .execute(&self.pool)
        .await
        .map_err(|error| usage_error("failed to delete expired usage requests", error))?;
        Ok(result.rows_affected())
    }

    async fn delete_tracking_gaps_before(
        &self,
        cutoff_ms: i64,
        batch: u32,
    ) -> Result<u64, UsageRepositoryError> {
        let last_expired_bucket = cutoff_ms.saturating_sub(provider_usage::GAP_BUCKET_MS);
        let result = sqlx::query(
            r#"
            DELETE FROM usage_tracking_gaps
            WHERE rowid IN (
                SELECT rowid FROM usage_tracking_gaps
                WHERE bucket_start_ms <= ?
                ORDER BY bucket_start_ms
                LIMIT ?
            )
            "#,
        )
        .bind(last_expired_bucket)
        .bind(i64::from(batch))
        .execute(&self.pool)
        .await
        .map_err(|error| usage_error("failed to delete expired usage gaps", error))?;
        Ok(result.rows_affected())
    }

    async fn load_catalog(&self) -> Result<Option<StoredCatalog>, UsageRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT revision, body, etag, last_modified, content_fetched_at_ms,
                   last_checked_at_ms, last_error_code
            FROM usage_catalog
            WHERE singleton = 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| usage_error("failed to load usage catalog", error))?;

        Ok(row.map(|row| StoredCatalog {
            revision: row.get("revision"),
            body: row.get("body"),
            etag: row.get("etag"),
            last_modified: row.get("last_modified"),
            content_fetched_at_ms: row.get("content_fetched_at_ms"),
            last_checked_at_ms: row.get("last_checked_at_ms"),
            last_error_code: row.get("last_error_code"),
        }))
    }

    async fn store_catalog(&self, catalog: &StoredCatalog) -> Result<(), UsageRepositoryError> {
        // A single statement, so a reader never sees a half-replaced catalog.
        sqlx::query(
            r#"
            INSERT INTO usage_catalog (
                singleton, revision, body, etag, last_modified,
                content_fetched_at_ms, last_checked_at_ms, last_error_code
            )
            VALUES (1, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (singleton) DO UPDATE SET
                revision = excluded.revision,
                body = excluded.body,
                etag = excluded.etag,
                last_modified = excluded.last_modified,
                content_fetched_at_ms = excluded.content_fetched_at_ms,
                last_checked_at_ms = excluded.last_checked_at_ms,
                last_error_code = excluded.last_error_code
            "#,
        )
        .bind(&catalog.revision)
        .bind(&catalog.body)
        .bind(catalog.etag.as_deref())
        .bind(catalog.last_modified.as_deref())
        .bind(catalog.content_fetched_at_ms)
        .bind(catalog.last_checked_at_ms)
        .bind(catalog.last_error_code.as_deref())
        .execute(&self.pool)
        .await
        .map_err(|error| usage_error("failed to store usage catalog", error))?;
        Ok(())
    }

    async fn record_catalog_check(
        &self,
        checked_at_ms: i64,
        error_code: Option<&str>,
    ) -> Result<(), UsageRepositoryError> {
        // Deliberately does not touch `body` or `revision`: a 304 or a failed
        // refresh must leave the last known good catalog in place.
        sqlx::query(
            r#"
            UPDATE usage_catalog
            SET last_checked_at_ms = ?, last_error_code = ?
            WHERE singleton = 1
            "#,
        )
        .bind(checked_at_ms)
        .bind(error_code)
        .execute(&self.pool)
        .await
        .map_err(|error| usage_error("failed to record usage catalog check", error))?;
        Ok(())
    }
}

#[cfg(any(test, feature = "test-util"))]
impl SqliteUsageRepository {
    /// The oldest recorded logical request.
    ///
    /// A test affordance only: production reads are owner-scoped and go through
    /// the query service, which must never expose an unfiltered lookup.
    #[doc(hidden)]
    pub async fn oldest_request_id(&self) -> Result<Option<String>, UsageRepositoryError> {
        sqlx::query_scalar(
            r#"
            SELECT request_id
            FROM usage_logical_requests
            ORDER BY started_at_ms, request_id
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| usage_error("failed to look up a usage request", error))
    }
}

impl SqliteUsageRepository {
    pub(crate) async fn billable_for(
        &self,
        attempt_id: &str,
    ) -> Result<Vec<BillableObservation>, UsageRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT component_code, unit, quantity
            FROM usage_billable_observations
            WHERE attempt_id = ?
            ORDER BY component_code
            "#,
        )
        .bind(attempt_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| usage_error("failed to load billable observations", error))?;

        rows.into_iter()
            .map(|row| {
                let code: String = row.get("component_code");
                let unit: String = row.get("unit");
                let quantity: i64 = row.get("quantity");
                Ok(BillableObservation {
                    component_code: billable_code_from(&code)?,
                    unit: billable_unit_from(&unit)?,
                    quantity: u64::try_from(quantity).map_err(|_| {
                        UsageRepositoryError::new("stored billable quantity is negative")
                    })?,
                })
            })
            .collect()
    }
}

/// A token metric split into what the column holds and what the sidecar JSON
/// holds. `kind` is `None` exactly when the metric is a plain provider-reported
/// number, which is the common case and stores nothing extra.
struct SplitMetric {
    value: Option<i64>,
    kind: Option<StoredKind>,
}

/// The non-plain half of a [`TokenMetric`], as stored in `token_kinds_json`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredKind {
    DerivedFromReported { rule_version: u16 },
    NotReported,
    NotApplicable,
    Unknown { reason: StoredUnknownReason },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredUnknownReason {
    Indeterminate,
    InvalidReported,
    NoUsageTerminal,
}

fn split_metric(metric: TokenMetric) -> SplitMetric {
    match metric {
        TokenMetric::ProviderReported { value } => match i64::try_from(value) {
            Ok(value) => SplitMetric {
                value: Some(value),
                kind: None,
            },
            // A count past i64 cannot be stored as a number, so it is recorded
            // as unknown rather than truncated into a plausible-looking one.
            Err(_) => SplitMetric {
                value: None,
                kind: Some(StoredKind::Unknown {
                    reason: StoredUnknownReason::InvalidReported,
                }),
            },
        },
        TokenMetric::DerivedFromReported {
            value,
            rule_version,
        } => match i64::try_from(value) {
            Ok(value) => SplitMetric {
                value: Some(value),
                kind: Some(StoredKind::DerivedFromReported { rule_version }),
            },
            Err(_) => SplitMetric {
                value: None,
                kind: Some(StoredKind::Unknown {
                    reason: StoredUnknownReason::InvalidReported,
                }),
            },
        },
        TokenMetric::NotReported => SplitMetric {
            value: None,
            kind: Some(StoredKind::NotReported),
        },
        TokenMetric::NotApplicable => SplitMetric {
            value: None,
            kind: Some(StoredKind::NotApplicable),
        },
        TokenMetric::Unknown { reason } => SplitMetric {
            value: None,
            kind: Some(StoredKind::Unknown {
                reason: match reason {
                    TokenUnknownReason::Indeterminate => StoredUnknownReason::Indeterminate,
                    TokenUnknownReason::InvalidReported => StoredUnknownReason::InvalidReported,
                    TokenUnknownReason::NoUsageTerminal => StoredUnknownReason::NoUsageTerminal,
                },
            }),
        },
    }
}

/// Rebuild a metric from its column and its optional stored kind.
///
/// Reading history must not fail, so the two shapes this code never writes — a
/// `NULL` column where a number was expected, and a negative count the schema
/// already forbids — read as unknown rather than as a fabricated or sign-flipped
/// number.
fn join_metric(value: Option<i64>, kind: Option<StoredKind>) -> TokenMetric {
    let counted = |value: i64| {
        u64::try_from(value).map_or(
            TokenMetric::Unknown {
                reason: TokenUnknownReason::InvalidReported,
            },
            |value| TokenMetric::ProviderReported { value },
        )
    };
    match kind {
        None => match value {
            Some(value) => counted(value),
            None => TokenMetric::Unknown {
                reason: TokenUnknownReason::Indeterminate,
            },
        },
        Some(StoredKind::DerivedFromReported { rule_version }) => match value {
            Some(value) => match u64::try_from(value) {
                Ok(value) => TokenMetric::DerivedFromReported {
                    value,
                    rule_version,
                },
                Err(_) => TokenMetric::Unknown {
                    reason: TokenUnknownReason::InvalidReported,
                },
            },
            None => TokenMetric::Unknown {
                reason: TokenUnknownReason::Indeterminate,
            },
        },
        Some(StoredKind::NotReported) => TokenMetric::NotReported,
        Some(StoredKind::NotApplicable) => TokenMetric::NotApplicable,
        Some(StoredKind::Unknown { reason }) => TokenMetric::Unknown {
            reason: match reason {
                StoredUnknownReason::Indeterminate => TokenUnknownReason::Indeterminate,
                StoredUnknownReason::InvalidReported => TokenUnknownReason::InvalidReported,
                StoredUnknownReason::NoUsageTerminal => TokenUnknownReason::NoUsageTerminal,
            },
        },
    }
}

/// The stored kinds, keyed by category. Serde omits the plain provider-reported
/// ones, so a fully reported attempt serializes to `{}`.
#[derive(Default, Serialize, Deserialize)]
struct StoredKinds {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uncached_input: Option<StoredKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cache_read_input: Option<StoredKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cache_write_input: Option<StoredKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effective_input: Option<StoredKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output: Option<StoredKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reasoning: Option<StoredKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input_audio: Option<StoredKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output_audio: Option<StoredKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total: Option<StoredKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pricing_context: Option<StoredKind>,
}

/// The column half of the same split: one nullable count per category.
#[derive(Default)]
struct StoredValues {
    uncached_input: Option<i64>,
    cache_read_input: Option<i64>,
    cache_write_input: Option<i64>,
    effective_input: Option<i64>,
    output: Option<i64>,
    reasoning: Option<i64>,
    input_audio: Option<i64>,
    output_audio: Option<i64>,
    total: Option<i64>,
    pricing_context: Option<i64>,
}

fn split_observation(observation: &ProviderUsageObservation) -> (StoredValues, StoredKinds) {
    let uncached_input = split_metric(observation.uncached_input_tokens);
    let cache_read_input = split_metric(observation.cache_read_input_tokens);
    let cache_write_input = split_metric(observation.cache_write_input_tokens);
    let effective_input = split_metric(observation.effective_input_tokens);
    let output = split_metric(observation.output_tokens);
    let reasoning = split_metric(observation.reasoning_tokens);
    let input_audio = split_metric(observation.input_audio_tokens);
    let output_audio = split_metric(observation.output_audio_tokens);
    let total = split_metric(observation.total_tokens);
    let pricing_context = split_metric(observation.pricing_context_tokens);

    (
        StoredValues {
            uncached_input: uncached_input.value,
            cache_read_input: cache_read_input.value,
            cache_write_input: cache_write_input.value,
            effective_input: effective_input.value,
            output: output.value,
            reasoning: reasoning.value,
            input_audio: input_audio.value,
            output_audio: output_audio.value,
            total: total.value,
            pricing_context: pricing_context.value,
        },
        StoredKinds {
            uncached_input: uncached_input.kind,
            cache_read_input: cache_read_input.kind,
            cache_write_input: cache_write_input.kind,
            effective_input: effective_input.kind,
            output: output.kind,
            reasoning: reasoning.kind,
            input_audio: input_audio.kind,
            output_audio: output_audio.kind,
            total: total.kind,
            pricing_context: pricing_context.kind,
        },
    )
}

/// The cost as it can actually be stored. An amount that does not fit an
/// `INTEGER` column is not truncated: the estimate becomes unavailable and says
/// why, because a wrong number is worse than an admitted absence.
struct StorableCost {
    status: CostStatus,
    atoms: Option<i64>,
    reasons: Vec<CostReason>,
    calculator_version: u16,
}

fn storable_cost(cost: &ObservedCatalogCost) -> StorableCost {
    if matches!(cost.status, CostStatus::Unavailable) {
        return StorableCost {
            status: CostStatus::Unavailable,
            atoms: None,
            reasons: cost.reasons.clone(),
            calculator_version: cost.calculator_version,
        };
    }
    match i64::try_from(cost.total_known.as_atoms()) {
        Ok(atoms) => StorableCost {
            status: cost.status,
            atoms: Some(atoms),
            reasons: cost.reasons.clone(),
            calculator_version: cost.calculator_version,
        },
        Err(_) => {
            let mut reasons = cost.reasons.clone();
            if !reasons.contains(&CostReason::ArithmeticOverflow) {
                reasons.push(CostReason::ArithmeticOverflow);
            }
            StorableCost {
                status: CostStatus::Unavailable,
                atoms: None,
                reasons,
                calculator_version: cost.calculator_version,
            }
        }
    }
}

/// A quantity too large for an `INTEGER` column is refused, not clamped: a
/// clamped number would read back as a real one.
fn storable_quantity(value: u64) -> Result<i64, UsageRepositoryError> {
    i64::try_from(value)
        .map_err(|_| UsageRepositoryError::new("billable quantity is too large to store"))
}

fn tracking_columns(tracking: TrackingState) -> (&'static str, Option<&'static str>) {
    match tracking {
        TrackingState::Complete => ("complete", None),
        TrackingState::Gap { reason } => ("gap", Some(gap_reason_str(reason))),
    }
}

pub(crate) fn tracking_from(
    state: &str,
    reason: Option<&str>,
) -> Result<TrackingState, UsageRepositoryError> {
    match (state, reason) {
        ("complete", None) => Ok(TrackingState::Complete),
        ("gap", Some(reason)) => Ok(TrackingState::Gap {
            reason: gap_reason_from(reason)?,
        }),
        _ => Err(UsageRepositoryError::new(
            "stored tracking state and gap reason disagree",
        )),
    }
}

const fn gap_reason_str(reason: TrackingGapReason) -> &'static str {
    match reason {
        TrackingGapReason::WriteFailed => "write_failed",
        TrackingGapReason::WriterSaturated => "writer_saturated",
        TrackingGapReason::RecoveredInFlight => "recovered_in_flight",
        TrackingGapReason::AmbiguousCancel => "ambiguous_cancel",
        TrackingGapReason::ObservationLost => "observation_lost",
    }
}

fn gap_reason_from(value: &str) -> Result<TrackingGapReason, UsageRepositoryError> {
    match value {
        "write_failed" => Ok(TrackingGapReason::WriteFailed),
        "writer_saturated" => Ok(TrackingGapReason::WriterSaturated),
        "recovered_in_flight" => Ok(TrackingGapReason::RecoveredInFlight),
        "ambiguous_cancel" => Ok(TrackingGapReason::AmbiguousCancel),
        "observation_lost" => Ok(TrackingGapReason::ObservationLost),
        other => Err(unknown_value("tracking gap reason", other)),
    }
}

const fn logical_status_str(status: LogicalStatus) -> &'static str {
    match status {
        LogicalStatus::InProgress => "in_progress",
        LogicalStatus::Succeeded => "succeeded",
        LogicalStatus::Failed => "failed",
        LogicalStatus::Canceled => "canceled",
        LogicalStatus::Incomplete => "incomplete",
    }
}

pub(crate) fn logical_status_from(value: &str) -> Result<LogicalStatus, UsageRepositoryError> {
    match value {
        "in_progress" => Ok(LogicalStatus::InProgress),
        "succeeded" => Ok(LogicalStatus::Succeeded),
        "failed" => Ok(LogicalStatus::Failed),
        "canceled" => Ok(LogicalStatus::Canceled),
        "incomplete" => Ok(LogicalStatus::Incomplete),
        other => Err(unknown_value("logical status", other)),
    }
}

const fn execution_outcome_str(outcome: ExecutionOutcome) -> &'static str {
    match outcome {
        ExecutionOutcome::StableSuccessTerminal => "stable_success_terminal",
        ExecutionOutcome::StableFailure => "stable_failure",
        ExecutionOutcome::TranslatorOrStreamError => "translator_or_stream_error",
        ExecutionOutcome::EofWithoutSuccessTerminal => "eof_without_success_terminal",
        ExecutionOutcome::RecoveredOldRunActive => "recovered_old_run_active",
    }
}

fn execution_outcome_from(value: &str) -> Result<ExecutionOutcome, UsageRepositoryError> {
    match value {
        "stable_success_terminal" => Ok(ExecutionOutcome::StableSuccessTerminal),
        "stable_failure" => Ok(ExecutionOutcome::StableFailure),
        "translator_or_stream_error" => Ok(ExecutionOutcome::TranslatorOrStreamError),
        "eof_without_success_terminal" => Ok(ExecutionOutcome::EofWithoutSuccessTerminal),
        "recovered_old_run_active" => Ok(ExecutionOutcome::RecoveredOldRunActive),
        other => Err(unknown_value("execution outcome", other)),
    }
}

const fn delivery_outcome_str(outcome: DeliveryOutcome) -> &'static str {
    match outcome {
        DeliveryOutcome::CleanEof => "clean_eof",
        DeliveryOutcome::ClientDrop => "client_drop",
        DeliveryOutcome::ErrorBeforeBytes => "error_before_bytes",
        DeliveryOutcome::ErrorAfterBytes => "error_after_bytes",
        DeliveryOutcome::Unknown => "unknown",
    }
}

fn delivery_outcome_from(value: &str) -> Result<DeliveryOutcome, UsageRepositoryError> {
    match value {
        "clean_eof" => Ok(DeliveryOutcome::CleanEof),
        "client_drop" => Ok(DeliveryOutcome::ClientDrop),
        "error_before_bytes" => Ok(DeliveryOutcome::ErrorBeforeBytes),
        "error_after_bytes" => Ok(DeliveryOutcome::ErrorAfterBytes),
        "unknown" => Ok(DeliveryOutcome::Unknown),
        other => Err(unknown_value("delivery outcome", other)),
    }
}

const fn dispatch_evidence_str(evidence: DispatchEvidence) -> &'static str {
    match evidence {
        DispatchEvidence::NotInvoked => "not_invoked",
        DispatchEvidence::DispatchInvoked => "dispatch_invoked",
        DispatchEvidence::ResponseObserved => "response_observed",
    }
}

fn dispatch_evidence_from(value: &str) -> Result<DispatchEvidence, UsageRepositoryError> {
    match value {
        "not_invoked" => Ok(DispatchEvidence::NotInvoked),
        "dispatch_invoked" => Ok(DispatchEvidence::DispatchInvoked),
        "response_observed" => Ok(DispatchEvidence::ResponseObserved),
        other => Err(unknown_value("dispatch evidence", other)),
    }
}

const fn cache_capability_str(capability: CacheCapability) -> &'static str {
    match capability {
        CacheCapability::Supported => "supported",
        CacheCapability::Unsupported => "unsupported",
        CacheCapability::Unknown => "unknown",
    }
}

fn cache_capability_from(value: &str) -> Result<CacheCapability, UsageRepositoryError> {
    match value {
        "supported" => Ok(CacheCapability::Supported),
        "unsupported" => Ok(CacheCapability::Unsupported),
        "unknown" => Ok(CacheCapability::Unknown),
        other => Err(unknown_value("cache capability", other)),
    }
}

const fn cache_eligibility_str(eligibility: CacheEligibility) -> &'static str {
    match eligibility {
        CacheEligibility::Eligible => "eligible",
        CacheEligibility::NotRequested => "not_requested",
        CacheEligibility::NotApplicable => "not_applicable",
        CacheEligibility::Unknown => "unknown",
    }
}

fn cache_eligibility_from(value: &str) -> Result<CacheEligibility, UsageRepositoryError> {
    match value {
        "eligible" => Ok(CacheEligibility::Eligible),
        "not_requested" => Ok(CacheEligibility::NotRequested),
        "not_applicable" => Ok(CacheEligibility::NotApplicable),
        "unknown" => Ok(CacheEligibility::Unknown),
        other => Err(unknown_value("cache eligibility", other)),
    }
}

const fn cache_reporting_str(expectation: CacheReportingExpectation) -> &'static str {
    match expectation {
        CacheReportingExpectation::Expected => "expected",
        CacheReportingExpectation::NotExpected => "not_expected",
        CacheReportingExpectation::Unknown => "unknown",
    }
}

fn cache_reporting_from(value: &str) -> Result<CacheReportingExpectation, UsageRepositoryError> {
    match value {
        "expected" => Ok(CacheReportingExpectation::Expected),
        "not_expected" => Ok(CacheReportingExpectation::NotExpected),
        "unknown" => Ok(CacheReportingExpectation::Unknown),
        other => Err(unknown_value("cache reporting expectation", other)),
    }
}

const fn pricing_basis_str(basis: PricingContextBasis) -> &'static str {
    match basis {
        PricingContextBasis::EffectiveInput => "effective_input",
        PricingContextBasis::Unknown => "unknown",
    }
}

fn pricing_basis_from(value: &str) -> Result<PricingContextBasis, UsageRepositoryError> {
    match value {
        "effective_input" => Ok(PricingContextBasis::EffectiveInput),
        "unknown" => Ok(PricingContextBasis::Unknown),
        other => Err(unknown_value("pricing context basis", other)),
    }
}

const fn pricing_mode_str(mode: PricingMode) -> &'static str {
    match mode {
        PricingMode::Default => "default",
        PricingMode::Unknown => "unknown",
    }
}

fn pricing_mode_from(value: &str) -> Result<PricingMode, UsageRepositoryError> {
    match value {
        "default" => Ok(PricingMode::Default),
        "unknown" => Ok(PricingMode::Unknown),
        other => Err(unknown_value("pricing mode", other)),
    }
}

const fn price_resolution_str(resolution: &PriceResolution) -> &'static str {
    match resolution {
        PriceResolution::Resolved(_) => "resolved",
        PriceResolution::CatalogUnavailable => "catalog_unavailable",
        PriceResolution::ProviderMappingMissing => "provider_mapping_missing",
        PriceResolution::ModelMappingMissing => "model_mapping_missing",
        PriceResolution::CostMissing => "cost_missing",
        PriceResolution::CatalogEntryInvalid => "catalog_entry_invalid",
        PriceResolution::PricingRuleUnsupported => "pricing_rule_unsupported",
        PriceResolution::PricingRuleConflict => "pricing_rule_conflict",
    }
}

fn price_resolution_from(
    value: &str,
    record: Option<String>,
) -> Result<PriceResolution, UsageRepositoryError> {
    if value == "resolved" {
        let json = record.ok_or_else(|| {
            UsageRepositoryError::new("a resolved price has no stored price record")
        })?;
        let record: InlinePriceRecord = serde_json::from_str(&json)
            .map_err(|error| usage_error("failed to decode inline price record", error))?;
        return Ok(PriceResolution::Resolved(Box::new(record)));
    }
    match value {
        "catalog_unavailable" => Ok(PriceResolution::CatalogUnavailable),
        "provider_mapping_missing" => Ok(PriceResolution::ProviderMappingMissing),
        "model_mapping_missing" => Ok(PriceResolution::ModelMappingMissing),
        "cost_missing" => Ok(PriceResolution::CostMissing),
        "catalog_entry_invalid" => Ok(PriceResolution::CatalogEntryInvalid),
        "pricing_rule_unsupported" => Ok(PriceResolution::PricingRuleUnsupported),
        "pricing_rule_conflict" => Ok(PriceResolution::PricingRuleConflict),
        other => Err(unknown_value("price resolution", other)),
    }
}

const fn cost_status_str(status: CostStatus) -> &'static str {
    match status {
        CostStatus::CompleteForObservedCatalogComponents => {
            "complete_for_observed_catalog_components"
        }
        CostStatus::Partial => "partial",
        CostStatus::Unavailable => "unavailable",
    }
}

fn cost_status_from(value: &str) -> Result<CostStatus, UsageRepositoryError> {
    match value {
        "complete_for_observed_catalog_components" => {
            Ok(CostStatus::CompleteForObservedCatalogComponents)
        }
        "partial" => Ok(CostStatus::Partial),
        "unavailable" => Ok(CostStatus::Unavailable),
        other => Err(unknown_value("cost status", other)),
    }
}

const fn cost_reason_str(reason: CostReason) -> &'static str {
    match reason {
        CostReason::CatalogUnavailable => "catalog_unavailable",
        CostReason::ProviderMappingMissing => "provider_mapping_missing",
        CostReason::ModelMappingMissing => "model_mapping_missing",
        CostReason::CostMissing => "cost_missing",
        CostReason::CatalogEntryInvalid => "catalog_entry_invalid",
        CostReason::PricingRuleUnsupported => "pricing_rule_unsupported",
        CostReason::PricingRuleConflict => "pricing_rule_conflict",
        CostReason::TierBasisUnavailable => "tier_basis_unavailable",
        CostReason::PriceModeUnknown => "price_mode_unknown",
        CostReason::UnmodeledBillableComponent => "unmodeled_billable_component",
        CostReason::ComponentPriceMissing => "component_price_missing",
        CostReason::UsageComponentMissing => "usage_component_missing",
        CostReason::InputCategorySplitUnavailable => "input_category_split_unavailable",
        CostReason::UsageFieldConflict => "usage_field_conflict",
        CostReason::ModelMismatch => "model_mismatch",
        CostReason::ArithmeticOverflow => "arithmetic_overflow",
        CostReason::NotDispatched => "not_dispatched",
    }
}

fn cost_reason_from(value: &str) -> Result<CostReason, UsageRepositoryError> {
    match value {
        "catalog_unavailable" => Ok(CostReason::CatalogUnavailable),
        "provider_mapping_missing" => Ok(CostReason::ProviderMappingMissing),
        "model_mapping_missing" => Ok(CostReason::ModelMappingMissing),
        "cost_missing" => Ok(CostReason::CostMissing),
        "catalog_entry_invalid" => Ok(CostReason::CatalogEntryInvalid),
        "pricing_rule_unsupported" => Ok(CostReason::PricingRuleUnsupported),
        "pricing_rule_conflict" => Ok(CostReason::PricingRuleConflict),
        "tier_basis_unavailable" => Ok(CostReason::TierBasisUnavailable),
        "price_mode_unknown" => Ok(CostReason::PriceModeUnknown),
        "unmodeled_billable_component" => Ok(CostReason::UnmodeledBillableComponent),
        "component_price_missing" => Ok(CostReason::ComponentPriceMissing),
        "usage_component_missing" => Ok(CostReason::UsageComponentMissing),
        "input_category_split_unavailable" => Ok(CostReason::InputCategorySplitUnavailable),
        "usage_field_conflict" => Ok(CostReason::UsageFieldConflict),
        "model_mismatch" => Ok(CostReason::ModelMismatch),
        "arithmetic_overflow" => Ok(CostReason::ArithmeticOverflow),
        "not_dispatched" => Ok(CostReason::NotDispatched),
        other => Err(unknown_value("cost reason", other)),
    }
}

const fn warning_str(warning: NormalizationWarning) -> &'static str {
    match warning {
        NormalizationWarning::NegativeValue => "negative_value",
        NormalizationWarning::Overflow => "overflow",
        NormalizationWarning::FieldConflict => "field_conflict",
        NormalizationWarning::ProviderModelMismatch => "provider_model_mismatch",
    }
}

fn warning_from(value: &str) -> Result<NormalizationWarning, UsageRepositoryError> {
    match value {
        "negative_value" => Ok(NormalizationWarning::NegativeValue),
        "overflow" => Ok(NormalizationWarning::Overflow),
        "field_conflict" => Ok(NormalizationWarning::FieldConflict),
        "provider_model_mismatch" => Ok(NormalizationWarning::ProviderModelMismatch),
        other => Err(unknown_value("normalization warning", other)),
    }
}

const fn billable_code_str(code: BillableComponentCode) -> &'static str {
    match code {
        BillableComponentCode::CacheWrite5m => "cache_write_5m",
        BillableComponentCode::CacheWrite1h => "cache_write_1h",
        BillableComponentCode::ServerToolCall => "server_tool_call",
        BillableComponentCode::ImageInputTokens => "image_input_tokens",
        BillableComponentCode::ImageOutputTokens => "image_output_tokens",
    }
}

fn billable_code_from(value: &str) -> Result<BillableComponentCode, UsageRepositoryError> {
    match value {
        "cache_write_5m" => Ok(BillableComponentCode::CacheWrite5m),
        "cache_write_1h" => Ok(BillableComponentCode::CacheWrite1h),
        "server_tool_call" => Ok(BillableComponentCode::ServerToolCall),
        "image_input_tokens" => Ok(BillableComponentCode::ImageInputTokens),
        "image_output_tokens" => Ok(BillableComponentCode::ImageOutputTokens),
        other => Err(unknown_value("billable component code", other)),
    }
}

const fn billable_unit_str(unit: BillableUnit) -> &'static str {
    match unit {
        BillableUnit::Tokens => "tokens",
        BillableUnit::Calls => "calls",
    }
}

fn billable_unit_from(value: &str) -> Result<BillableUnit, UsageRepositoryError> {
    match value {
        "tokens" => Ok(BillableUnit::Tokens),
        "calls" => Ok(BillableUnit::Calls),
        other => Err(unknown_value("billable unit", other)),
    }
}

fn stored_logical_request(row: SqliteRow) -> Result<StoredLogicalRequest, UsageRepositoryError> {
    let status: String = row.get("logical_status");
    let tracking_state: String = row.get("tracking_state");
    let gap_reason: Option<String> = row.get("tracking_gap_reason");
    let execution: Option<String> = row.get("execution_outcome");
    let delivery: Option<String> = row.get("delivery_outcome");
    let state_version: i64 = row.get("state_version");

    Ok(StoredLogicalRequest {
        start: LogicalRequestStart {
            request_id: row.get("request_id"),
            owner_user_id: row.get("owner_user_id"),
            api_key_id: row.get("api_key_id"),
            api_key_label: row.get("api_key_label"),
            api_key_group_label: row.get("api_key_group_label"),
            client_model_raw: row.get("client_model_raw"),
            routing_model: row.get("routing_model"),
            reasoning_effort: row.get("reasoning_effort"),
            started_at_ms: row.get("started_at_ms"),
        },
        status: logical_status_from(&status)?,
        completed_at_ms: row.get("completed_at_ms"),
        execution: execution
            .as_deref()
            .map(execution_outcome_from)
            .transpose()?,
        delivery: delivery.as_deref().map(delivery_outcome_from).transpose()?,
        final_attempt_id: row.get("final_attempt_id"),
        tracking: tracking_from(&tracking_state, gap_reason.as_deref())?,
        state_version: u32::try_from(state_version)
            .map_err(|_| UsageRepositoryError::new("stored state version is out of range"))?,
    })
}

pub(crate) fn attempt_facts(row: SqliteRow) -> Result<AttemptFacts, UsageRepositoryError> {
    let provider: String = row.get("provider");
    let provider: ProviderKind = provider
        .parse()
        .map_err(|_| unknown_value("provider kind", &provider))?;

    let inclusion_json: String = row.get("inclusion_json");
    let inclusion: TokenInclusionRules = serde_json::from_str(&inclusion_json)
        .map_err(|error| usage_error("failed to decode usage inclusion rules", error))?;

    let cache_capability: String = row.get("cache_capability");
    let cache_eligibility: String = row.get("cache_eligibility");
    let cache_reporting: String = row.get("cache_reporting_expectation");
    let pricing_basis: String = row.get("pricing_context_basis");
    let pricing_mode: String = row.get("pricing_mode");
    let contract_version: i64 = row.get("contract_version");
    let normalization_version: i64 = row.get("normalization_version");

    let contract = UsageContractSnapshot {
        contract_version: u16::try_from(contract_version)
            .map_err(|_| UsageRepositoryError::new("stored contract version is out of range"))?,
        normalization_version: u16::try_from(normalization_version).map_err(|_| {
            UsageRepositoryError::new("stored normalization version is out of range")
        })?,
        inclusion,
        cache_capability: cache_capability_from(&cache_capability)?,
        cache_eligibility: cache_eligibility_from(&cache_eligibility)?,
        cache_reporting_expectation: cache_reporting_from(&cache_reporting)?,
        pricing_context_basis: pricing_basis_from(&pricing_basis)?,
        pricing_mode: pricing_mode_from(&pricing_mode)?,
    };

    let kinds_json: String = row.get("token_kinds_json");
    let kinds: StoredKinds = serde_json::from_str(&kinds_json)
        .map_err(|error| usage_error("failed to decode token metric kinds", error))?;

    let warnings_json: String = row.get("normalization_warnings_json");
    let warning_codes: Vec<String> = serde_json::from_str(&warnings_json)
        .map_err(|error| usage_error("failed to decode normalization warnings", error))?;
    let warnings = warning_codes
        .iter()
        .map(|code| warning_from(code))
        .collect::<Result<Vec<_>, _>>()?;

    let observation = ProviderUsageObservation {
        uncached_input_tokens: join_metric(row.get("uncached_input_tokens"), kinds.uncached_input),
        cache_read_input_tokens: join_metric(
            row.get("cache_read_input_tokens"),
            kinds.cache_read_input,
        ),
        cache_write_input_tokens: join_metric(
            row.get("cache_write_input_tokens"),
            kinds.cache_write_input,
        ),
        effective_input_tokens: join_metric(
            row.get("effective_input_tokens"),
            kinds.effective_input,
        ),
        output_tokens: join_metric(row.get("output_tokens"), kinds.output),
        reasoning_tokens: join_metric(row.get("reasoning_tokens"), kinds.reasoning),
        input_audio_tokens: join_metric(row.get("input_audio_tokens"), kinds.input_audio),
        output_audio_tokens: join_metric(row.get("output_audio_tokens"), kinds.output_audio),
        total_tokens: join_metric(row.get("total_tokens"), kinds.total),
        pricing_context_tokens: join_metric(
            row.get("pricing_context_tokens"),
            kinds.pricing_context,
        ),
        // Filled in by the caller from usage_billable_observations.
        billable: Vec::new(),
        warnings,
    };

    let price_kind: String = row.get("price_resolution");
    let price_json: Option<String> = row.get("price_json");
    let price = price_resolution_from(&price_kind, price_json)?;

    let cost_status: String = row.get("cost_status");
    let cost_atoms: Option<i64> = row.get("cost_atoms");
    let cost_reasons_json: String = row.get("cost_reasons_json");
    let reason_codes: Vec<String> = serde_json::from_str(&cost_reasons_json)
        .map_err(|error| usage_error("failed to decode cost reasons", error))?;
    let calculator_version: i64 = row.get("calculator_version");

    let cost = ObservedCatalogCost {
        total_known: cost_atoms.map_or(UsdAtoms::ZERO, |atoms| UsdAtoms::from_atoms(atoms.into())),
        status: cost_status_from(&cost_status)?,
        reasons: reason_codes
            .iter()
            .map(|code| cost_reason_from(code))
            .collect::<Result<Vec<_>, _>>()?,
        calculator_version: u16::try_from(calculator_version)
            .map_err(|_| UsageRepositoryError::new("stored calculator version is out of range"))?,
    };

    let tracking_state: String = row.get("tracking_state");
    let gap_reason: Option<String> = row.get("tracking_gap_reason");
    let evidence: String = row.get("dispatch_evidence");
    let sequence: i64 = row.get("sequence");

    Ok(AttemptFacts {
        attempt_id: row.get("id"),
        logical_request_id: row.get("logical_request_id"),
        sequence: AttemptSequence(
            u32::try_from(sequence).map_err(|_| {
                UsageRepositoryError::new("stored attempt sequence is out of range")
            })?,
        ),
        provider,
        account_id: row.get("account_id"),
        configured_model: row.get("configured_model"),
        provider_reported_model: row.get("provider_reported_model"),
        started_at_ms: row.get("started_at_ms"),
        first_token_at_ms: row.get("first_token_at_ms"),
        completed_at_ms: row.get("completed_at_ms"),
        dispatch_evidence: dispatch_evidence_from(&evidence)?,
        tracking: tracking_from(&tracking_state, gap_reason.as_deref())?,
        contract,
        observation,
        price,
        cost,
    })
}

pub(crate) fn usage_error(operation: &str, error: impl std::fmt::Display) -> UsageRepositoryError {
    UsageRepositoryError::new(format!("{operation}: {error}"))
}

fn unknown_value(field: &str, value: &str) -> UsageRepositoryError {
    UsageRepositoryError::new(format!("stored {field} is not recognised: {value}"))
}

#[cfg(test)]
mod tests {
    use provider_usage::{CatalogInlinePriceRecordV1, ComponentPrices, PRICE_SCALE, UnitPrice};

    use super::*;
    use crate::SqliteAccountRepository;

    const PER_MILLION: i128 = 10i128.pow(PRICE_SCALE);

    async fn repository() -> SqliteUsageRepository {
        SqliteAccountRepository::in_memory()
            .await
            .expect("test database")
            .usage_repository()
    }

    fn start(request_id: &str) -> LogicalRequestStart {
        LogicalRequestStart {
            request_id: request_id.to_owned(),
            owner_user_id: "user-1".to_owned(),
            api_key_id: Some("key-1".to_owned()),
            api_key_label: None,
            api_key_group_label: None,
            client_model_raw: Some("gpt-5-codex".to_owned()),
            routing_model: Some("gpt-5-codex".to_owned()),
            reasoning_effort: None,
            started_at_ms: 1_700_000_000_000,
        }
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
                total_source: provider_core::usage::TotalSource::Reported,
            },
            cache_capability: CacheCapability::Supported,
            cache_eligibility: CacheEligibility::Eligible,
            cache_reporting_expectation: CacheReportingExpectation::Expected,
            pricing_context_basis: PricingContextBasis::EffectiveInput,
            pricing_mode: PricingMode::Default,
        }
    }

    /// One observation using every `TokenMetric` variant, so a round trip has to
    /// preserve each of them rather than just the common reported case.
    fn observation() -> ProviderUsageObservation {
        ProviderUsageObservation {
            uncached_input_tokens: TokenMetric::DerivedFromReported {
                value: 20,
                rule_version: 1,
            },
            cache_read_input_tokens: TokenMetric::ProviderReported { value: 100 },
            cache_write_input_tokens: TokenMetric::NotApplicable,
            effective_input_tokens: TokenMetric::ProviderReported { value: 120 },
            output_tokens: TokenMetric::ProviderReported { value: 8 },
            reasoning_tokens: TokenMetric::ProviderReported { value: 0 },
            input_audio_tokens: TokenMetric::NotApplicable,
            output_audio_tokens: TokenMetric::NotReported,
            total_tokens: TokenMetric::Unknown {
                reason: TokenUnknownReason::Indeterminate,
            },
            pricing_context_tokens: TokenMetric::ProviderReported { value: 120 },
            billable: vec![BillableObservation {
                component_code: BillableComponentCode::ImageInputTokens,
                unit: BillableUnit::Tokens,
                quantity: 42,
            }],
            warnings: vec![NormalizationWarning::FieldConflict],
        }
    }

    fn price_record() -> PriceResolution {
        PriceResolution::Resolved(Box::new(InlinePriceRecord::CatalogV1(
            CatalogInlinePriceRecordV1 {
                format_version: 1,
                parser_version: 1,
                catalog_revision: "a".repeat(64),
                catalog_provider_id: "openai".to_owned(),
                catalog_model_id: "gpt-5-codex".to_owned(),
                mapping_revision: 3,
                prices: ComponentPrices {
                    uncached_input_per_million: Some(UnitPrice::from_scaled(
                        125 * PER_MILLION / 100,
                    )),
                    cache_read_per_million: Some(UnitPrice::from_scaled(PER_MILLION / 8)),
                    output_per_million: Some(UnitPrice::from_scaled(10 * PER_MILLION)),
                    ..ComponentPrices::default()
                },
                context_tier: None,
                selected_tier: Some("context_over_200k".to_owned()),
                unmodeled_billable_component: true,
                unmodeled_pricing_rule: true,
            },
        )))
    }

    fn attempt(request_id: &str, attempt_id: &str, sequence: u32) -> AttemptFacts {
        AttemptFacts {
            attempt_id: attempt_id.to_owned(),
            logical_request_id: request_id.to_owned(),
            sequence: AttemptSequence(sequence),
            provider: ProviderKind::Codex,
            account_id: "account-1".to_owned(),
            configured_model: Some("gpt-5-codex".to_owned()),
            provider_reported_model: Some("gpt-5-codex".to_owned()),
            started_at_ms: 1_700_000_000_100,
            first_token_at_ms: None,
            completed_at_ms: 1_700_000_001_500,
            dispatch_evidence: DispatchEvidence::ResponseObserved,
            tracking: TrackingState::Complete,
            contract: contract(),
            observation: observation(),
            price: price_record(),
            cost: ObservedCatalogCost {
                total_known: UsdAtoms::from_atoms(2_512_500_000_000),
                status: CostStatus::Partial,
                reasons: vec![CostReason::UnmodeledBillableComponent],
                calculator_version: 1,
            },
        }
    }

    fn terminal(request_id: &str, attempt_id: &str, version: u32) -> LogicalRequestTerminal {
        LogicalRequestTerminal {
            request_id: request_id.to_owned(),
            completed_at_ms: 1_700_000_001_500,
            status: LogicalStatus::Succeeded,
            execution: Some(ExecutionOutcome::StableSuccessTerminal),
            delivery: Some(DeliveryOutcome::CleanEof),
            final_attempt_id: Some(attempt_id.to_owned()),
            tracking: TrackingState::Complete,
            state_version: version,
        }
    }

    #[tokio::test]
    async fn an_unknown_token_count_is_null_not_zero() {
        let repository = repository().await;
        repository
            .begin_logical_request(&start("req-1"))
            .await
            .expect("begin");
        repository
            .record_attempt(&attempt("req-1", "att-1", 1))
            .await
            .expect("record");

        // total_tokens was Unknown. It must not aggregate as a zero, and the
        // unknown must be countable.
        let (sum, known, rows): (Option<i64>, i64, i64) = sqlx::query_as(
            "SELECT SUM(total_tokens), COUNT(total_tokens), COUNT(*) FROM usage_attempts",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("aggregate");
        assert_eq!(sum, None, "an unknown count must not sum as zero");
        assert_eq!(known, 0);
        assert_eq!(rows, 1);

        let loaded = repository.load_attempts("req-1").await.expect("load");
        assert_eq!(
            loaded[0].observation.total_tokens,
            TokenMetric::Unknown {
                reason: TokenUnknownReason::Indeterminate
            }
        );
        // An explicit zero is a different fact and stays a known zero.
        assert_eq!(
            loaded[0].observation.reasoning_tokens,
            TokenMetric::ProviderReported { value: 0 }
        );
    }

    #[tokio::test]
    async fn quota_ledger_charges_complete_cost_and_marks_partial_indeterminate() {
        let repository = repository().await;
        sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, role, enabled, created_at, updated_at)
            VALUES ('user-1', 'quota-user', 'hash', 'user', 1, 1, 1)
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("insert quota user");
        sqlx::query(
            r#"
            INSERT INTO api_keys (
                id, owner_user_id, group_label, label, key, enabled,
                quota_limit_atoms, spent_atoms, created_at, updated_at
            )
            VALUES ('key-1', 'user-1', 'default', 'quota', 'quota-key-1', 1,
                    '9999999999999999', '0', 1, 1)
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("insert quota API key");

        repository
            .record_quota_ledger_entry(&provider_usage::QuotaLedgerEntry {
                entry_id: "req-partial".to_owned(),
                api_key_id: "key-1".to_owned(),
                cost_atoms: None,
                recorded_at_ms: 10,
            })
            .await
            .expect("record partial ledger entry");
        let (spent, state): (String, String) = sqlx::query_as(
            "SELECT spent_atoms, quota_accounting_state FROM api_keys WHERE id = 'key-1'",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("load quota after partial cost");
        assert_eq!((spent.as_str(), state.as_str()), ("0", "indeterminate"));

        repository
            .record_quota_ledger_entry(&provider_usage::QuotaLedgerEntry {
                entry_id: "req-complete".to_owned(),
                api_key_id: "key-1".to_owned(),
                cost_atoms: Some("2512500000000".to_owned()),
                recorded_at_ms: 11,
            })
            .await
            .expect("record complete ledger entry");
        repository
            .record_quota_ledger_entry(&provider_usage::QuotaLedgerEntry {
                entry_id: "req-complete".to_owned(),
                api_key_id: "key-1".to_owned(),
                cost_atoms: Some("2512500000000".to_owned()),
                recorded_at_ms: 11,
            })
            .await
            .expect("redeliver complete ledger entry");
        let spent: String =
            sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
                .fetch_one(&repository.pool)
                .await
                .expect("load spend after complete cost");
        assert_eq!(spent, "2512500000000");
    }

    #[tokio::test]
    async fn quota_ledger_survives_api_key_deletion_after_dispatch() {
        let repository = repository().await;
        sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, role, enabled, created_at, updated_at)
            VALUES ('user-1', 'quota-delete-user', 'hash', 'user', 1, 1, 1)
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("insert quota user");
        sqlx::query(
            r#"
            INSERT INTO api_keys (
                id, owner_user_id, group_label, label, key, enabled,
                quota_limit_atoms, spent_atoms, created_at, updated_at
            )
            VALUES ('key-deleted', 'user-1', 'default', 'quota', 'quota-key-deleted', 1,
                    '9999999999999999', '0', 1, 1)
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("insert quota API key");
        sqlx::query("DELETE FROM api_keys WHERE id = 'key-deleted'")
            .execute(&repository.pool)
            .await
            .expect("delete API key after dispatch");

        repository
            .record_quota_ledger_entry(&provider_usage::QuotaLedgerEntry {
                entry_id: "req-after-key-delete".to_owned(),
                api_key_id: "key-deleted".to_owned(),
                cost_atoms: Some("100".to_owned()),
                recorded_at_ms: 10,
            })
            .await
            .expect("record terminal ledger entry");

        let stored: (String, String) = sqlx::query_as(
            "SELECT api_key_id, cost_atoms FROM api_key_quota_ledger WHERE entry_id = ?",
        )
        .bind("req-after-key-delete")
        .fetch_one(&repository.pool)
        .await
        .expect("load terminal ledger entry");
        assert_eq!(stored, ("key-deleted".to_owned(), "100".to_owned()));
    }

    #[tokio::test]
    async fn an_unavailable_cost_is_null_never_a_zero_amount() {
        let repository = repository().await;
        repository
            .begin_logical_request(&start("req-1"))
            .await
            .expect("begin");
        let mut facts = attempt("req-1", "att-1", 1);
        facts.price = PriceResolution::ModelMappingMissing;
        facts.cost = ObservedCatalogCost {
            total_known: UsdAtoms::ZERO,
            status: CostStatus::Unavailable,
            reasons: vec![CostReason::ModelMappingMissing],
            calculator_version: 1,
        };
        repository.record_attempt(&facts).await.expect("record");

        let atoms: Option<i64> =
            sqlx::query_scalar("SELECT cost_atoms FROM usage_attempts WHERE id = 'att-1'")
                .fetch_one(&repository.pool)
                .await
                .expect("atoms");
        assert_eq!(atoms, None, "an unpriced attempt must not aggregate as $0");

        let loaded = repository.load_attempts("req-1").await.expect("load");
        assert_eq!(loaded[0].cost.status, CostStatus::Unavailable);
        assert_eq!(loaded[0].price, PriceResolution::ModelMappingMissing);
    }

    #[tokio::test]
    async fn exact_unit_prices_survive_a_round_trip() {
        // Prices are scaled integers, never floats. A JSON round trip that went
        // through a double would quietly change a historical cost.
        let repository = repository().await;
        repository
            .begin_logical_request(&start("req-1"))
            .await
            .expect("begin");
        let mut facts = attempt("req-1", "att-1", 1);
        let awkward = UnitPrice::from_scaled(123_456_789_987_654_321);
        facts.price = PriceResolution::Resolved(Box::new(InlinePriceRecord::CatalogV1(
            CatalogInlinePriceRecordV1 {
                format_version: 1,
                parser_version: 1,
                catalog_revision: "b".repeat(64),
                catalog_provider_id: "openai".to_owned(),
                catalog_model_id: "gpt-5-codex".to_owned(),
                mapping_revision: 1,
                prices: ComponentPrices {
                    uncached_input_per_million: Some(awkward),
                    ..ComponentPrices::default()
                },
                context_tier: None,
                selected_tier: None,
                unmodeled_billable_component: false,
                unmodeled_pricing_rule: false,
            },
        )));
        repository.record_attempt(&facts).await.expect("record");

        let loaded = repository.load_attempts("req-1").await.expect("load");
        let record = loaded[0].price.resolved().expect("resolved");
        assert_eq!(
            record.prices().uncached_input_per_million,
            Some(awkward),
            "an exact scaled price must not be rounded by persistence"
        );
    }

    #[tokio::test]
    async fn redelivering_an_attempt_is_a_no_op() {
        let repository = repository().await;
        repository
            .begin_logical_request(&start("req-1"))
            .await
            .expect("begin");
        let facts = attempt("req-1", "att-1", 1);
        repository.record_attempt(&facts).await.expect("first");
        repository
            .record_attempt(&facts)
            .await
            .expect("redelivered");

        let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_attempts")
            .fetch_one(&repository.pool)
            .await
            .expect("count");
        let billable: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_billable_observations")
            .fetch_one(&repository.pool)
            .await
            .expect("count");
        assert_eq!(attempts, 1);
        assert_eq!(billable, 1, "a redelivery must not duplicate billable rows");
    }

    #[tokio::test]
    async fn a_late_terminal_event_does_not_roll_back_newer_state() {
        let repository = repository().await;
        repository
            .begin_logical_request(&start("req-1"))
            .await
            .expect("begin");
        repository
            .complete_logical_request(&terminal("req-1", "att-2", 2))
            .await
            .expect("newer");

        let mut stale = terminal("req-1", "att-1", 1);
        stale.status = LogicalStatus::Failed;
        assert_eq!(
            repository
                .complete_logical_request(&stale)
                .await
                .expect("stale"),
            LogicalWriteOutcome::AlreadyKnown
        );

        let stored = repository
            .load_logical_request("req-1")
            .await
            .expect("load")
            .expect("present");
        assert_eq!(stored.status, LogicalStatus::Succeeded);
        assert_eq!(stored.final_attempt_id.as_deref(), Some("att-2"));
    }

    #[tokio::test]
    async fn recovery_closes_in_flight_requests_as_incomplete_with_a_gap() {
        let repository = repository().await;
        repository
            .begin_logical_request(&start("req-live"))
            .await
            .expect("begin");
        repository
            .begin_logical_request(&start("req-done"))
            .await
            .expect("begin");
        repository
            .complete_logical_request(&terminal("req-done", "att-1", 1))
            .await
            .expect("complete");

        assert_eq!(
            repository
                .recover_in_flight_requests(1_700_000_009_000)
                .await
                .expect("recover"),
            1,
            "only what a previous run left running is closed"
        );

        let recovered = repository
            .load_logical_request("req-live")
            .await
            .expect("load")
            .expect("present");
        assert_eq!(recovered.status, LogicalStatus::Incomplete);
        assert_eq!(recovered.completed_at_ms, Some(1_700_000_009_000));
        assert_eq!(
            recovered.tracking,
            TrackingState::Gap {
                reason: TrackingGapReason::RecoveredInFlight
            },
            "an unknowable terminal is admitted, not guessed"
        );
        assert_eq!(
            recovered.execution,
            Some(ExecutionOutcome::RecoveredOldRunActive)
        );

        let untouched = repository
            .load_logical_request("req-done")
            .await
            .expect("load")
            .expect("present");
        assert_eq!(untouched.status, LogicalStatus::Succeeded);
    }

    #[tokio::test]
    async fn deleting_a_logical_request_removes_its_attempts_and_billables() {
        // This is how retention works: one delete per logical unit, never a
        // partial delete that orphans an attempt or a metric.
        let repository = repository().await;
        repository
            .begin_logical_request(&start("req-1"))
            .await
            .expect("begin");
        repository
            .record_attempt(&attempt("req-1", "att-1", 1))
            .await
            .expect("record");

        sqlx::query("DELETE FROM usage_logical_requests WHERE request_id = 'req-1'")
            .execute(&repository.pool)
            .await
            .expect("delete");

        let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_attempts")
            .fetch_one(&repository.pool)
            .await
            .expect("count");
        let billable: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_billable_observations")
            .fetch_one(&repository.pool)
            .await
            .expect("count");
        assert_eq!(attempts, 0);
        assert_eq!(billable, 0);
    }
}
