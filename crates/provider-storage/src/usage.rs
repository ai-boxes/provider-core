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
    AttemptFacts, AttemptFailoverReason, AttemptOutcome, AttemptSequence, CostReason, CostStatus,
    DeliveryOutcome, DispatchEvidence, ExecutionOutcome, InlinePriceRecord, LogicalRequestStart,
    LogicalRequestTerminal, LogicalStatus, LogicalWriteOutcome, ObservedCatalogCost,
    PriceResolution, StoredCatalog, StoredLogicalRequest, TrackingGapReason, TrackingState,
    UsageRepository, UsageRepositoryError, UsdAtoms, gap_bucket,
};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqliteConnection, SqlitePool, sqlite::SqliteRow};

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

async fn insert_logical_request(
    connection: &mut SqliteConnection,
    start: &LogicalRequestStart,
) -> Result<LogicalWriteOutcome, UsageRepositoryError> {
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
    .execute(&mut *connection)
    .await
    .map_err(|error| usage_error("failed to begin usage logical request", error))?;

    Ok(if result.rows_affected() == 0 {
        LogicalWriteOutcome::AlreadyKnown
    } else {
        LogicalWriteOutcome::Written
    })
}

async fn add_api_key_spend(
    connection: &mut SqliteConnection,
    api_key_id: &str,
    atoms: &str,
) -> Result<(), UsageRepositoryError> {
    let spent: Option<String> = sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = ?")
        .bind(api_key_id)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| usage_error("failed to load API key spend", error))?;
    if let Some(spent) = spent {
        let next = add_atoms(&spent, atoms)
            .map_err(|_| UsageRepositoryError::new("API key spend overflowed"))?;
        sqlx::query("UPDATE api_keys SET spent_atoms = ? WHERE id = ?")
            .bind(next)
            .bind(api_key_id)
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to update API key spend", error))?;
    }
    Ok(())
}

#[async_trait]
impl UsageRepository for SqliteUsageRepository {
    async fn begin_logical_request(
        &self,
        start: &LogicalRequestStart,
    ) -> Result<LogicalWriteOutcome, UsageRepositoryError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|error| usage_error("failed to acquire usage start connection", error))?;
        insert_logical_request(&mut connection, start).await
    }

    async fn begin_quota_request(
        &self,
        start: &LogicalRequestStart,
    ) -> Result<LogicalWriteOutcome, UsageRepositoryError> {
        let api_key_id = start.api_key_id.as_deref().ok_or_else(|| {
            UsageRepositoryError::new("a quota request must belong to an API key")
        })?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|error| usage_error("failed to acquire quota start connection", error))?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to start quota request transaction", error))?;
        let result = async {
            let outcome = insert_logical_request(&mut connection, start).await?;
            sqlx::query(
                r#"
                INSERT INTO api_key_quota_ledger (
                    entry_id, api_key_id, reserved_atoms, state, reserved_at_ms
                )
                VALUES (?, ?, '0', 'reserved', ?)
                ON CONFLICT (entry_id) DO NOTHING
                "#,
            )
            .bind(&start.request_id)
            .bind(api_key_id)
            .bind(start.started_at_ms)
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to create quota accounting claim", error))?;
            let claimed_key: String = sqlx::query_scalar(
                "SELECT api_key_id FROM api_key_quota_ledger WHERE entry_id = ?",
            )
            .bind(&start.request_id)
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to verify quota accounting claim", error))?;
            if claimed_key != api_key_id {
                return Err(UsageRepositoryError::new(
                    "quota accounting claim belongs to a different API key",
                ));
            }
            Ok(outcome)
        }
        .await;
        match result {
            Ok(outcome) => {
                sqlx::query("COMMIT")
                    .execute(&mut *connection)
                    .await
                    .map_err(|error| usage_error("failed to commit quota request", error))?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                Err(error)
            }
        }
    }

    async fn mark_quota_request_dispatched(
        &self,
        request_id: &str,
        dispatched_at_ms: i64,
    ) -> Result<(), UsageRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE api_key_quota_ledger
            SET dispatched_at_ms = COALESCE(dispatched_at_ms, ?)
            WHERE entry_id = ? AND state = 'reserved'
            "#,
        )
        .bind(dispatched_at_ms)
        .bind(request_id)
        .execute(&self.pool)
        .await
        .map_err(|error| usage_error("failed to mark quota request dispatched", error))?;
        if result.rows_affected() == 1 {
            return Ok(());
        }

        let claim: Option<(String, Option<i64>)> = sqlx::query_as(
            "SELECT state, dispatched_at_ms FROM api_key_quota_ledger WHERE entry_id = ?",
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| usage_error("failed to verify quota dispatch marker", error))?;
        match claim {
            Some((state, Some(_))) if state == "reserved" => Ok(()),
            Some(_) => Err(UsageRepositoryError::new(
                "quota accounting claim is no longer reserved",
            )),
            None => Err(UsageRepositoryError::new(
                "quota accounting claim does not exist",
            )),
        }
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
        let state_version = i64::from(terminal.state_version);
        let (tracking_state, gap_reason) = tracking_columns(terminal.tracking);
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
        if facts.failover_reason.is_some() && facts.outcome != Some(AttemptOutcome::Failed) {
            return Err(UsageRepositoryError::new(
                "an attempt failover reason requires a failed attempt outcome",
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
        let result = async {
            let inserted = sqlx::query(
                r#"
            INSERT INTO usage_attempts (
                id, logical_request_id, sequence,
                provider, account_id, configured_model, provider_reported_model,
                started_at_ms, first_token_at_ms, completed_at_ms, attempt_outcome,
                failover_reason, dispatch_evidence,
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
                ?, ?, ?, ?, ?, ?,
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
            .bind(facts.outcome.map(attempt_outcome_str))
            .bind(facts.failover_reason.map(attempt_failover_reason_str))
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

                if matches!(
                    cost.status,
                    CostStatus::CompleteForObservedCatalogComponents
                ) && let Some(cost_atoms) = cost.atoms
                {
                    // Post-usage billing charges complete costs here when no quota
                    // claim owns the request's spend lifecycle.
                    let api_key_id = sqlx::query_scalar::<_, String>(
                        r#"
                    SELECT request_row.api_key_id
                    FROM usage_logical_requests AS request_row
                    WHERE request_row.request_id = ?
                      AND request_row.api_key_id IS NOT NULL
                      AND NOT EXISTS (
                          SELECT 1
                          FROM api_key_quota_ledger AS quota
                          WHERE quota.entry_id = request_row.request_id
                      )
                    "#,
                    )
                    .bind(&facts.logical_request_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(|error| {
                        usage_error("failed to resolve unreserved API key spend", error)
                    })?;
                    if let Some(api_key_id) = api_key_id {
                        let cost_atoms = cost_atoms.to_string();
                        add_api_key_spend(&mut transaction, &api_key_id, &cost_atoms).await?;
                    }
                }
            }

            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                sqlx::query("COMMIT")
                    .execute(&mut *transaction)
                    .await
                    .map_err(|error| usage_error("failed to commit usage attempt", error))?;
                Ok(())
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *transaction).await;
                Err(error)
            }
        }
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
        let result = async {
            let reservation = sqlx::query(
                r#"
                SELECT api_key_id, state, dispatched_at_ms
                FROM api_key_quota_ledger
                WHERE entry_id = ?
                "#,
            )
            .bind(&entry.entry_id)
            .fetch_optional(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to load quota reservation", error))?
            .ok_or_else(|| UsageRepositoryError::new("quota reservation does not exist"))?;
            let reserved_key_id: String = reservation
                .try_get("api_key_id")
                .map_err(|error| usage_error("failed to decode quota reservation key", error))?;
            let state: String = reservation
                .try_get("state")
                .map_err(|error| usage_error("failed to decode quota reservation state", error))?;
            let dispatched_at_ms: Option<i64> = reservation
                .try_get("dispatched_at_ms")
                .map_err(|error| usage_error("failed to decode quota dispatch marker", error))?;
            if reserved_key_id != entry.api_key_id {
                return Err(UsageRepositoryError::new(
                    "quota reservation belongs to a different API key",
                ));
            }
            if state != "reserved" {
                return Ok(());
            }

            if let Some(settled_atoms) = entry.cost_atoms.as_deref() {
                if !entry.dispatched || dispatched_at_ms.is_none() {
                    return Err(UsageRepositoryError::new(
                        "an undispatched quota reservation cannot carry a cost",
                    ));
                }
                sqlx::query(
                    r#"
                    UPDATE api_key_quota_ledger
                    SET state = 'settled', settled_atoms = ?, resolved_at_ms = ?
                    WHERE entry_id = ? AND state = 'reserved'
                    "#,
                )
                .bind(settled_atoms)
                .bind(entry.resolved_at_ms)
                .bind(&entry.entry_id)
                .execute(&mut *connection)
                .await
                .map_err(|error| usage_error("failed to settle quota reservation", error))?;
                add_api_key_spend(&mut connection, &entry.api_key_id, settled_atoms).await?;
            } else if !entry.dispatched {
                sqlx::query(
                    r#"
                    UPDATE api_key_quota_ledger
                    SET state = 'released', settled_atoms = NULL, resolved_at_ms = ?
                    WHERE entry_id = ? AND state = 'reserved'
                    "#,
                )
                .bind(entry.resolved_at_ms)
                .bind(&entry.entry_id)
                .execute(&mut *connection)
                .await
                .map_err(|error| usage_error("failed to release quota reservation", error))?;
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                sqlx::query("COMMIT")
                    .execute(&mut *connection)
                    .await
                    .map_err(|error| usage_error("failed to commit quota ledger entry", error))?;
                Ok(())
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                Err(error)
            }
        }
    }

    async fn recover_quota_reservations(&self, now_ms: i64) -> Result<u64, UsageRepositoryError> {
        let mut connection =
            self.pool.acquire().await.map_err(|error| {
                usage_error("failed to acquire quota recovery connection", error)
            })?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to start quota recovery transaction", error))?;
        let result = async {
        let rows = sqlx::query(
            r#"
            SELECT entry_id, api_key_id, dispatched_at_ms
            FROM api_key_quota_ledger
            WHERE state = 'reserved'
            ORDER BY entry_id
            "#,
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| usage_error("failed to load unresolved quota reservations", error))?;
            let mut recovered = 0_u64;
        for row in rows {
            let entry_id: String = row
                .try_get("entry_id")
                .map_err(|error| usage_error("failed to decode recovered quota entry", error))?;
            let api_key_id: String = row
                .try_get("api_key_id")
                .map_err(|error| usage_error("failed to decode recovered quota key", error))?;
            let dispatched_at_ms: Option<i64> = row
                .try_get("dispatched_at_ms")
                .map_err(|error| usage_error("failed to decode recovered dispatch marker", error))?;
            if dispatched_at_ms.is_none() {
                sqlx::query(
                    "UPDATE api_key_quota_ledger SET state = 'released', resolved_at_ms = ? WHERE entry_id = ? AND state = 'reserved'",
                )
                .bind(now_ms)
                .bind(&entry_id)
                .execute(&mut *connection)
                .await
                .map_err(|error| usage_error("failed to release undispatched quota claim", error))?;
                recovered = recovered
                    .checked_add(1)
                    .ok_or_else(|| UsageRepositoryError::new("too many quota claims to recover"))?;
                continue;
            }

            let costs: Vec<i64> = sqlx::query_scalar(
                r#"
                SELECT cost_atoms
                FROM usage_attempts
                WHERE logical_request_id = ?
                  AND cost_status = 'complete_for_observed_catalog_components'
                ORDER BY sequence
                "#,
            )
            .bind(&entry_id)
            .fetch_all(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to load recovered attempt costs", error))?;
            if costs.is_empty() {
                continue;
            }
            let mut settled_atoms = "0".to_owned();
            for cost in costs {
                settled_atoms = add_atoms(&settled_atoms, &cost.to_string())
                    .map_err(|_| UsageRepositoryError::new("recovered quota spend overflowed"))?;
            }
            sqlx::query(
                "UPDATE api_key_quota_ledger SET state = 'settled', settled_atoms = ?, resolved_at_ms = ? WHERE entry_id = ? AND state = 'reserved'",
            )
            .bind(&settled_atoms)
            .bind(now_ms)
            .bind(&entry_id)
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to settle recovered quota claim", error))?;
            add_api_key_spend(&mut connection, &api_key_id, &settled_atoms).await?;
            recovered = recovered
                .checked_add(1)
                .ok_or_else(|| UsageRepositoryError::new("too many quota claims to recover"))?;
        }
        Ok(recovered)
        }.await;
        match result {
            Ok(recovered) => {
                sqlx::query("COMMIT")
                    .execute(&mut *connection)
                    .await
                    .map_err(|error| usage_error("failed to commit quota recovery", error))?;
                Ok(recovered)
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                Err(error)
            }
        }
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
        let mut connection = self.pool.acquire().await.map_err(|error| {
            usage_error(
                "failed to acquire in-flight usage recovery connection",
                error,
            )
        })?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to start in-flight usage recovery", error))?;
        let rows = sqlx::query(
            r#"
            SELECT owner_user_id, COUNT(*) AS request_count
            FROM usage_logical_requests
            WHERE logical_status = 'in_progress'
            GROUP BY owner_user_id
            "#,
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| usage_error("failed to group in-flight usage requests", error))?;
        let mut recovered = 0u64;
        for row in rows {
            let owner_user_id: String = row.get("owner_user_id");
            let count: i64 = row.get("request_count");
            let count = u64::try_from(count)
                .map_err(|_| UsageRepositoryError::new("invalid in-flight usage count"))?;
            recovered = recovered
                .checked_add(count)
                .ok_or_else(|| UsageRepositoryError::new("in-flight usage count overflowed"))?;
            sqlx::query(
                r#"
                INSERT INTO usage_tracking_gaps (owner_user_id, reason, bucket_start_ms, count)
                VALUES (?, 'recovered_in_flight', ?, ?)
                ON CONFLICT (owner_user_id, reason, bucket_start_ms) DO UPDATE SET
                    count = count + excluded.count
                "#,
            )
            .bind(owner_user_id)
            .bind(gap_bucket(now_ms))
            .bind(i64::try_from(count).expect("SQLite count already fits i64"))
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to record recovered usage gap", error))?;
        }
        sqlx::query("DELETE FROM usage_logical_requests WHERE logical_status = 'in_progress'")
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to discard in-flight usage requests", error))?;
        sqlx::query("COMMIT")
            .execute(&mut *connection)
            .await
            .map_err(|error| usage_error("failed to commit in-flight usage recovery", error))?;
        Ok(recovered)
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

    async fn delete_resolved_quota_ledger_entries_before(
        &self,
        cutoff_ms: i64,
        batch: u32,
    ) -> Result<u64, UsageRepositoryError> {
        let result = sqlx::query(
            r#"
            DELETE FROM api_key_quota_ledger
            WHERE entry_id IN (
                SELECT entry_id FROM api_key_quota_ledger
                WHERE state IN ('settled', 'released')
                  AND resolved_at_ms < ?
                ORDER BY resolved_at_ms, entry_id
                LIMIT ?
            )
            "#,
        )
        .bind(cutoff_ms)
        .bind(i64::from(batch))
        .execute(&self.pool)
        .await
        .map_err(|error| usage_error("failed to delete resolved quota ledger entries", error))?;
        Ok(result.rows_affected())
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

const fn attempt_outcome_str(outcome: AttemptOutcome) -> &'static str {
    match outcome {
        AttemptOutcome::Succeeded => "succeeded",
        AttemptOutcome::Failed => "failed",
        AttemptOutcome::Cancelled => "cancelled",
    }
}

fn attempt_outcome_from(value: &str) -> Result<AttemptOutcome, UsageRepositoryError> {
    match value {
        "succeeded" => Ok(AttemptOutcome::Succeeded),
        "failed" => Ok(AttemptOutcome::Failed),
        "cancelled" => Ok(AttemptOutcome::Cancelled),
        other => Err(unknown_value("attempt outcome", other)),
    }
}

const fn attempt_failover_reason_str(reason: AttemptFailoverReason) -> &'static str {
    match reason {
        AttemptFailoverReason::AuthenticationExhausted => "authentication_exhausted",
        AttemptFailoverReason::QuotaExhausted => "quota_exhausted",
        AttemptFailoverReason::RateLimited => "rate_limited",
        AttemptFailoverReason::PreconnectFailure => "preconnect_failure",
    }
}

fn attempt_failover_reason_from(
    value: &str,
) -> Result<AttemptFailoverReason, UsageRepositoryError> {
    match value {
        "authentication_exhausted" => Ok(AttemptFailoverReason::AuthenticationExhausted),
        "quota_exhausted" => Ok(AttemptFailoverReason::QuotaExhausted),
        "rate_limited" => Ok(AttemptFailoverReason::RateLimited),
        "preconnect_failure" => Ok(AttemptFailoverReason::PreconnectFailure),
        other => Err(unknown_value("attempt failover reason", other)),
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
    let outcome: Option<String> = row.get("attempt_outcome");
    let failover_reason: Option<String> = row.get("failover_reason");
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
        outcome: outcome.as_deref().map(attempt_outcome_from).transpose()?,
        failover_reason: failover_reason
            .as_deref()
            .map(attempt_failover_reason_from)
            .transpose()?,
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
    use std::sync::Arc;

    use provider_auth::{ApiKeyId, AuthRepository, QuotaAdmissionOutcome};
    use provider_usage::{
        CatalogInlinePriceRecordV1, ComponentPrices, PRICE_SCALE, QuotaLedgerWriter, UnitPrice,
    };

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
                missing_cache_read_means_zero: false,
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

    fn zero_observation() -> ProviderUsageObservation {
        ProviderUsageObservation {
            uncached_input_tokens: TokenMetric::ProviderReported { value: 0 },
            cache_read_input_tokens: TokenMetric::ProviderReported { value: 0 },
            cache_write_input_tokens: TokenMetric::NotApplicable,
            effective_input_tokens: TokenMetric::ProviderReported { value: 0 },
            output_tokens: TokenMetric::ProviderReported { value: 0 },
            reasoning_tokens: TokenMetric::ProviderReported { value: 0 },
            input_audio_tokens: TokenMetric::NotApplicable,
            output_audio_tokens: TokenMetric::NotApplicable,
            total_tokens: TokenMetric::ProviderReported { value: 0 },
            pricing_context_tokens: TokenMetric::ProviderReported { value: 0 },
            billable: Vec::new(),
            warnings: Vec::new(),
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
            outcome: None,
            failover_reason: None,
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

    async fn insert_api_key(
        repository: &SqliteUsageRepository,
        key_id: &str,
        quota_limit_atoms: Option<&str>,
    ) {
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
                id, owner_user_id, group_label, label, key,
                enabled, quota_limit_atoms, spent_atoms, created_at, updated_at
            )
            VALUES (?, 'user-1', 'default', 'quota', 'pode-usage-test-key', 1,
                    ?, '0', 1, 1)
            "#,
        )
        .bind(key_id)
        .bind(quota_limit_atoms)
        .execute(&repository.pool)
        .await
        .expect("insert API key");
    }

    async fn insert_reservation(
        repository: &SqliteUsageRepository,
        entry_id: &str,
        api_key_id: &str,
        reserved_atoms: &str,
    ) {
        sqlx::query(
            r#"
            INSERT INTO api_key_quota_ledger (
                entry_id, api_key_id, reserved_atoms, state, reserved_at_ms
            )
            VALUES (?, ?, ?, 'reserved', 1)
            "#,
        )
        .bind(entry_id)
        .bind(api_key_id)
        .bind(reserved_atoms)
        .execute(&repository.pool)
        .await
        .expect("insert quota reservation");
    }

    async fn mark_dispatched(repository: &SqliteUsageRepository, entry_id: &str) {
        repository
            .mark_quota_request_dispatched(entry_id, 2)
            .await
            .expect("mark quota request dispatched");
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
    async fn unlimited_key_spend_records_complete_attempts_once() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", None).await;
        repository
            .begin_logical_request(&start("req-unlimited"))
            .await
            .expect("begin unlimited request");

        let mut first = attempt("req-unlimited", "att-1", 1);
        first.cost = ObservedCatalogCost {
            total_known: UsdAtoms::from_atoms(40),
            status: CostStatus::CompleteForObservedCatalogComponents,
            reasons: Vec::new(),
            calculator_version: 1,
        };
        repository
            .record_attempt(&first)
            .await
            .expect("record first attempt");
        repository
            .record_attempt(&first)
            .await
            .expect("redeliver first attempt");

        let mut second = attempt("req-unlimited", "att-2", 2);
        second.cost = ObservedCatalogCost {
            total_known: UsdAtoms::from_atoms(60),
            status: CostStatus::CompleteForObservedCatalogComponents,
            reasons: Vec::new(),
            calculator_version: 1,
        };
        repository
            .record_attempt(&second)
            .await
            .expect("record second attempt");

        repository
            .record_attempt(&attempt("req-unlimited", "att-partial", 3))
            .await
            .expect("record partial attempt");

        let spent: String =
            sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
                .fetch_one(&repository.pool)
                .await
                .expect("load unlimited key spend");
        assert_eq!(spent, "100");
    }

    #[tokio::test]
    async fn finite_quota_attempt_spend_is_owned_by_the_ledger() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", Some("100")).await;
        repository
            .begin_quota_request(&start("req-quota"))
            .await
            .expect("begin quota request");

        let mut facts = attempt("req-quota", "att-quota", 1);
        facts.cost = ObservedCatalogCost {
            total_known: UsdAtoms::from_atoms(40),
            status: CostStatus::CompleteForObservedCatalogComponents,
            reasons: Vec::new(),
            calculator_version: 1,
        };
        repository
            .record_attempt(&facts)
            .await
            .expect("record quota attempt");
        mark_dispatched(&repository, "req-quota").await;

        let before_settlement: String =
            sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
                .fetch_one(&repository.pool)
                .await
                .expect("load spend before settlement");
        assert_eq!(before_settlement, "0");

        repository
            .record_quota_ledger_entry(&provider_usage::QuotaLedgerEntry {
                entry_id: "req-quota".to_owned(),
                api_key_id: "key-1".to_owned(),
                dispatched: true,
                cost_atoms: Some("40".to_owned()),
                resolved_at_ms: 10,
                attempts: Vec::new(),
            })
            .await
            .expect("settle quota request");

        let after_settlement: String =
            sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
                .fetch_one(&repository.pool)
                .await
                .expect("load spend after settlement");
        assert_eq!(after_settlement, "40");
    }

    #[tokio::test]
    async fn quota_request_start_creates_logical_row_and_claim_atomically() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", Some("100")).await;
        let request = start("req-claim");

        assert_eq!(
            repository
                .begin_quota_request(&request)
                .await
                .expect("begin quota request"),
            LogicalWriteOutcome::Written
        );
        assert_eq!(
            repository
                .begin_quota_request(&request)
                .await
                .expect("replay quota request"),
            LogicalWriteOutcome::AlreadyKnown
        );

        let logical_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM usage_logical_requests WHERE request_id = ?")
                .bind(&request.request_id)
                .fetch_one(&repository.pool)
                .await
                .expect("count logical request");
        let claim: (String, String, String) = sqlx::query_as(
            "SELECT api_key_id, reserved_atoms, state FROM api_key_quota_ledger WHERE entry_id = ?",
        )
        .bind(&request.request_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load quota claim");

        assert_eq!(logical_rows, 1);
        assert_eq!(
            claim,
            ("key-1".to_owned(), "0".to_owned(), "reserved".to_owned())
        );
    }

    #[tokio::test]
    async fn failed_quota_claim_rolls_back_the_logical_start() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", Some("100")).await;
        sqlx::query(
            r#"
            INSERT INTO api_keys (
                id, owner_user_id, group_label, label, key,
                enabled, quota_limit_atoms, spent_atoms, created_at, updated_at
            )
            VALUES ('key-2', 'user-1', 'default', 'quota-2',
                    'pode-usage-test-key-2', 1, '100', '0', 2, 2)
            "#,
        )
        .execute(&repository.pool)
        .await
        .expect("insert conflicting claim key");
        insert_reservation(&repository, "req-conflict", "key-2", "0").await;

        let request = start("req-conflict");
        assert!(repository.begin_quota_request(&request).await.is_err());

        let logical_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM usage_logical_requests WHERE request_id = ?")
                .bind(&request.request_id)
                .fetch_one(&repository.pool)
                .await
                .expect("count rolled-back logical request");
        assert_eq!(logical_rows, 0);

        repository
            .begin_quota_request(&start("req-after-rollback"))
            .await
            .expect("connection remains usable after rollback");
    }

    #[tokio::test]
    async fn quota_ledger_records_observed_cost_above_reservation_and_keeps_writer_ready() {
        let account_repository = SqliteAccountRepository::in_memory()
            .await
            .expect("test database");
        let repository = Arc::new(account_repository.usage_repository());
        insert_api_key(&repository, "key-1", Some("100")).await;
        insert_reservation(&repository, "req-over-reservation", "key-1", "50").await;
        mark_dispatched(&repository, "req-over-reservation").await;

        let writer = QuotaLedgerWriter::spawn(repository.clone(), 1);
        let receipt = writer.reserve().await.expect("quota writer permit").submit(
            provider_usage::QuotaLedgerEntry {
                entry_id: "req-over-reservation".to_owned(),
                api_key_id: "key-1".to_owned(),
                dispatched: true,
                cost_atoms: Some("140".to_owned()),
                resolved_at_ms: 10,
                attempts: Vec::new(),
            },
        );

        assert!(receipt.persisted().await);
        assert!(writer.drain().await);
        assert!(writer.is_ready());
        assert_eq!(writer.pending(), 0);

        let ledger: (String, Option<String>) = sqlx::query_as(
            "SELECT state, settled_atoms FROM api_key_quota_ledger WHERE entry_id = ?",
        )
        .bind("req-over-reservation")
        .fetch_one(&repository.pool)
        .await
        .expect("load settled quota entry");
        assert_eq!(ledger, ("settled".to_owned(), Some("140".to_owned())));

        let spent: String = sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = ?")
            .bind("key-1")
            .fetch_one(&repository.pool)
            .await
            .expect("load actual spend");
        assert_eq!(spent, "140");

        assert_eq!(
            account_repository
                .admit_api_key_quota(&ApiKeyId::new("key-1").expect("API key ID"))
                .await
                .expect("check admission after overrun"),
            QuotaAdmissionOutcome::Exceeded
        );
    }

    #[tokio::test]
    async fn quota_ledger_settles_exact_keeps_dispatched_unknown_and_releases_undispatched() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", Some("9999999999999999")).await;
        insert_reservation(&repository, "req-unknown", "key-1", "100").await;
        insert_reservation(&repository, "req-complete", "key-1", "50").await;
        insert_reservation(&repository, "req-release", "key-1", "70").await;
        mark_dispatched(&repository, "req-unknown").await;
        mark_dispatched(&repository, "req-complete").await;

        repository
            .record_quota_ledger_entry(&provider_usage::QuotaLedgerEntry {
                entry_id: "req-unknown".to_owned(),
                api_key_id: "key-1".to_owned(),
                dispatched: true,
                cost_atoms: None,
                resolved_at_ms: 10,
                attempts: Vec::new(),
            })
            .await
            .expect("release unknown cost");

        let complete = provider_usage::QuotaLedgerEntry {
            entry_id: "req-complete".to_owned(),
            api_key_id: "key-1".to_owned(),
            dispatched: true,
            cost_atoms: Some("40".to_owned()),
            resolved_at_ms: 11,
            attempts: Vec::new(),
        };
        repository
            .record_quota_ledger_entry(&complete)
            .await
            .expect("settle exact cost");
        repository
            .record_quota_ledger_entry(&complete)
            .await
            .expect("redeliver exact settlement");
        repository
            .record_quota_ledger_entry(&provider_usage::QuotaLedgerEntry {
                entry_id: "req-release".to_owned(),
                api_key_id: "key-1".to_owned(),
                dispatched: false,
                cost_atoms: None,
                resolved_at_ms: 12,
                attempts: Vec::new(),
            })
            .await
            .expect("release undispatched request");
        let spent: String =
            sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
                .fetch_one(&repository.pool)
                .await
                .expect("load settled spend");
        assert_eq!(spent, "40");
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT state, settled_atoms FROM api_key_quota_ledger ORDER BY entry_id",
        )
        .fetch_all(&repository.pool)
        .await
        .expect("load quota outcomes");
        assert_eq!(
            rows,
            vec![
                ("settled".to_owned(), Some("40".to_owned())),
                ("released".to_owned(), None),
                ("reserved".to_owned(), None),
            ]
        );
    }

    #[tokio::test]
    async fn failed_quota_settlement_rolls_back_for_the_next_write() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", Some("100")).await;
        insert_reservation(&repository, "req-rollback", "key-1", "0").await;
        mark_dispatched(&repository, "req-rollback").await;

        let wrong_key = provider_usage::QuotaLedgerEntry {
            entry_id: "req-rollback".to_owned(),
            api_key_id: "wrong-key".to_owned(),
            dispatched: true,
            cost_atoms: Some("40".to_owned()),
            resolved_at_ms: 10,
            attempts: Vec::new(),
        };
        assert!(
            repository
                .record_quota_ledger_entry(&wrong_key)
                .await
                .is_err()
        );

        repository
            .record_quota_ledger_entry(&provider_usage::QuotaLedgerEntry {
                api_key_id: "key-1".to_owned(),
                ..wrong_key
            })
            .await
            .expect("settlement after rollback");
        let spent: String =
            sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
                .fetch_one(&repository.pool)
                .await
                .expect("load spend");
        assert_eq!(spent, "40");
    }

    #[tokio::test]
    async fn quota_ledger_survives_api_key_deletion_after_dispatch() {
        let repository = repository().await;
        insert_api_key(&repository, "key-deleted", Some("9999999999999999")).await;
        insert_reservation(&repository, "req-after-key-delete", "key-deleted", "200").await;
        mark_dispatched(&repository, "req-after-key-delete").await;
        sqlx::query("DELETE FROM api_keys WHERE id = 'key-deleted'")
            .execute(&repository.pool)
            .await
            .expect("delete API key after dispatch");

        repository
            .record_quota_ledger_entry(&provider_usage::QuotaLedgerEntry {
                entry_id: "req-after-key-delete".to_owned(),
                api_key_id: "key-deleted".to_owned(),
                dispatched: true,
                cost_atoms: Some("100".to_owned()),
                resolved_at_ms: 10,
                attempts: Vec::new(),
            })
            .await
            .expect("record terminal ledger entry");

        let stored: (String, String) = sqlx::query_as(
            "SELECT api_key_id, settled_atoms FROM api_key_quota_ledger WHERE entry_id = ?",
        )
        .bind("req-after-key-delete")
        .fetch_one(&repository.pool)
        .await
        .expect("load terminal ledger entry");
        assert_eq!(stored, ("key-deleted".to_owned(), "100".to_owned()));
    }

    #[tokio::test]
    async fn quota_ledger_retention_deletes_only_expired_resolved_entries_in_batches() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", Some("9999999999999999")).await;
        for entry_id in [
            "old-settled",
            "old-released",
            "cutoff-settled",
            "active-reservation",
        ] {
            insert_reservation(&repository, entry_id, "key-1", "100").await;
        }
        mark_dispatched(&repository, "old-settled").await;
        mark_dispatched(&repository, "cutoff-settled").await;

        for entry in [
            provider_usage::QuotaLedgerEntry {
                entry_id: "old-settled".to_owned(),
                api_key_id: "key-1".to_owned(),
                dispatched: true,
                cost_atoms: Some("40".to_owned()),
                resolved_at_ms: 10,
                attempts: Vec::new(),
            },
            provider_usage::QuotaLedgerEntry {
                entry_id: "old-released".to_owned(),
                api_key_id: "key-1".to_owned(),
                dispatched: false,
                cost_atoms: None,
                resolved_at_ms: 20,
                attempts: Vec::new(),
            },
            provider_usage::QuotaLedgerEntry {
                entry_id: "cutoff-settled".to_owned(),
                api_key_id: "key-1".to_owned(),
                dispatched: true,
                cost_atoms: Some("30".to_owned()),
                resolved_at_ms: 50,
                attempts: Vec::new(),
            },
        ] {
            repository
                .record_quota_ledger_entry(&entry)
                .await
                .expect("resolve quota ledger entry");
        }

        assert_eq!(
            repository
                .delete_resolved_quota_ledger_entries_before(50, 1)
                .await
                .expect("delete first expired entry"),
            1
        );
        assert_eq!(
            repository
                .delete_resolved_quota_ledger_entries_before(50, 1)
                .await
                .expect("delete second expired entry"),
            1
        );
        assert_eq!(
            repository
                .delete_resolved_quota_ledger_entries_before(50, 1)
                .await
                .expect("reach retention tail"),
            0
        );

        let remaining: Vec<(String, String)> =
            sqlx::query_as("SELECT entry_id, state FROM api_key_quota_ledger ORDER BY entry_id")
                .fetch_all(&repository.pool)
                .await
                .expect("load remaining quota ledger entries");
        assert_eq!(
            remaining,
            vec![
                ("active-reservation".to_owned(), "reserved".to_owned()),
                ("cutoff-settled".to_owned(), "settled".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn startup_recovery_releases_unresolved_reservations_without_spend() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", Some("9999999999999999")).await;
        insert_reservation(&repository, "req-1", "key-1", "30").await;
        insert_reservation(&repository, "req-2", "key-1", "40").await;

        assert_eq!(
            repository
                .recover_quota_reservations(100)
                .await
                .expect("recover outstanding reservations"),
            2
        );
        assert_eq!(
            repository
                .recover_quota_reservations(200)
                .await
                .expect("no reservations remain"),
            0
        );
        let spent: String =
            sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
                .fetch_one(&repository.pool)
                .await
                .expect("load recovered spend");
        assert_eq!(spent, "0");
        let unresolved: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_key_quota_ledger WHERE state = 'reserved'",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("count unresolved reservations");
        assert_eq!(unresolved, 0);
    }

    #[tokio::test]
    async fn startup_recovery_settles_complete_dispatched_attempts() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", Some("9999999999999999")).await;
        repository
            .begin_quota_request(&start("req-recover-cost"))
            .await
            .expect("begin quota request");
        mark_dispatched(&repository, "req-recover-cost").await;

        let mut facts = attempt("req-recover-cost", "att-recover-cost", 1);
        facts.cost = ObservedCatalogCost {
            total_known: UsdAtoms::from_atoms(40),
            status: CostStatus::CompleteForObservedCatalogComponents,
            reasons: Vec::new(),
            calculator_version: 1,
        };
        repository
            .record_attempt(&facts)
            .await
            .expect("record attempt");

        assert_eq!(repository.recover_quota_reservations(100).await.unwrap(), 1);
        let ledger: (String, Option<String>) = sqlx::query_as(
            "SELECT state, settled_atoms FROM api_key_quota_ledger WHERE entry_id = ?",
        )
        .bind("req-recover-cost")
        .fetch_one(&repository.pool)
        .await
        .expect("load recovered ledger");
        assert_eq!(ledger, ("settled".to_owned(), Some("40".to_owned())));
        let spent: String =
            sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
                .fetch_one(&repository.pool)
                .await
                .expect("load recovered spend");
        assert_eq!(spent, "40");
    }

    #[tokio::test]
    async fn startup_recovery_keeps_dispatched_claim_without_complete_cost_reserved() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", Some("9999999999999999")).await;
        repository
            .begin_quota_request(&start("req-recover-unknown"))
            .await
            .expect("begin quota request");
        mark_dispatched(&repository, "req-recover-unknown").await;

        assert_eq!(repository.recover_quota_reservations(100).await.unwrap(), 0);
        let state: String = sqlx::query_scalar(
            "SELECT state FROM api_key_quota_ledger WHERE entry_id = 'req-recover-unknown'",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("load unresolved ledger");
        assert_eq!(state, "reserved");
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
            .record_attempt(&attempt("req-1", "att-2", 2))
            .await
            .expect("record final attempt");
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
    async fn recovery_discards_in_flight_requests_and_keeps_a_gap() {
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
            .record_attempt(&attempt("req-done", "att-1", 1))
            .await
            .expect("record completed request attempt");
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

        assert!(
            repository
                .load_logical_request("req-live")
                .await
                .expect("load")
                .is_none(),
            "an unknowable request is not retained as Usage"
        );
        let recovered_gaps: i64 = sqlx::query_scalar(
            "SELECT count FROM usage_tracking_gaps WHERE owner_user_id = 'user-1' AND reason = 'recovered_in_flight'",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("load recovered tracking gap");
        assert_eq!(recovered_gaps, 1, "recovery still admits the tracking gap");

        let untouched = repository
            .load_logical_request("req-done")
            .await
            .expect("load")
            .expect("present");
        assert_eq!(untouched.status, LogicalStatus::Succeeded);
    }

    #[tokio::test]
    async fn failed_request_and_attempt_gap_are_retained_without_changing_exact_spend() {
        let repository = repository().await;
        insert_api_key(&repository, "key-1", None).await;
        repository
            .begin_logical_request(&start("req-failed"))
            .await
            .expect("begin");
        let mut facts = attempt("req-failed", "att-failed", 1);
        facts.tracking = TrackingState::Gap {
            reason: TrackingGapReason::ObservationLost,
        };
        facts.cost = ObservedCatalogCost {
            total_known: UsdAtoms::from_atoms(40),
            status: CostStatus::CompleteForObservedCatalogComponents,
            reasons: Vec::new(),
            calculator_version: 1,
        };
        repository
            .record_attempt(&facts)
            .await
            .expect("record attempt");
        let mut failed = terminal("req-failed", "att-failed", 1);
        failed.status = LogicalStatus::Failed;
        failed.execution = Some(ExecutionOutcome::StableFailure);
        assert_eq!(
            repository
                .complete_logical_request(&failed)
                .await
                .expect("complete failed request"),
            LogicalWriteOutcome::Written
        );

        let logicals: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_logical_requests")
            .fetch_one(&repository.pool)
            .await
            .expect("count logical requests");
        let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_attempts")
            .fetch_one(&repository.pool)
            .await
            .expect("count attempts");
        let spent: String =
            sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
                .fetch_one(&repository.pool)
                .await
                .expect("load exact spend");
        let attempt_gap: String = sqlx::query_scalar(
            "SELECT tracking_gap_reason FROM usage_attempts WHERE id = 'att-failed'",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("load attempt gap");
        assert_eq!((logicals, attempts), (1, 1));
        assert_eq!(attempt_gap, "observation_lost");
        assert_eq!(spent, "40", "retention must not change exact spend");
    }

    #[tokio::test]
    async fn succeeded_request_with_only_zero_tokens_is_retained_as_an_outcome() {
        let repository = repository().await;
        repository
            .begin_logical_request(&start("req-zero"))
            .await
            .expect("begin");
        let mut facts = attempt("req-zero", "att-zero", 1);
        facts.observation = zero_observation();
        repository
            .record_attempt(&facts)
            .await
            .expect("record attempt");
        assert_eq!(
            repository
                .complete_logical_request(&terminal("req-zero", "att-zero", 1))
                .await
                .expect("complete zero-token request"),
            LogicalWriteOutcome::Written
        );
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_logical_requests")
            .fetch_one(&repository.pool)
            .await
            .expect("count logical requests");
        assert_eq!(rows, 1);
    }

    #[tokio::test]
    async fn succeeded_request_without_a_final_attempt_is_retained_as_an_outcome() {
        let repository = repository().await;
        repository
            .begin_logical_request(&start("req-no-attempt"))
            .await
            .expect("begin");
        let terminal = LogicalRequestTerminal {
            final_attempt_id: None,
            ..terminal("req-no-attempt", "unused", 1)
        };
        assert_eq!(
            repository
                .complete_logical_request(&terminal)
                .await
                .expect("complete request without attempt"),
            LogicalWriteOutcome::Written
        );
        let stored = repository
            .load_logical_request("req-no-attempt")
            .await
            .expect("load")
            .expect("operational outcome remains stored");
        assert_eq!(stored.status, LogicalStatus::Succeeded);
        assert!(stored.final_attempt_id.is_none());
    }

    #[tokio::test]
    async fn succeeded_request_with_positive_final_tokens_is_retained() {
        let repository = repository().await;
        repository
            .begin_logical_request(&start("req-valid"))
            .await
            .expect("begin");
        repository
            .record_attempt(&attempt("req-valid", "att-valid", 1))
            .await
            .expect("record attempt");
        assert_eq!(
            repository
                .complete_logical_request(&terminal("req-valid", "att-valid", 1))
                .await
                .expect("complete valid request"),
            LogicalWriteOutcome::Written
        );
        let stored = repository
            .load_logical_request("req-valid")
            .await
            .expect("load")
            .expect("valid Usage must remain");
        assert_eq!(stored.status, LogicalStatus::Succeeded);
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
