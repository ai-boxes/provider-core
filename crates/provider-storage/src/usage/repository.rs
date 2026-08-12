use async_trait::async_trait;
use provider_auth::add_atoms;
use provider_core::usage::BillableObservation;
use provider_usage::{
    AttemptFacts, AttemptOutcome, CostStatus, DispatchEvidence, LogicalRequestStart,
    LogicalRequestTerminal, LogicalWriteOutcome, PriceResolution, StoredCatalog,
    StoredLogicalRequest, TrackingGapReason, UsageRepository, UsageRepositoryError, gap_bucket,
};
use sqlx::{Row, SqliteConnection};

use super::{
    SqliteUsageRepository,
    codec::{
        attempt_facts, attempt_failover_reason_str, attempt_outcome_str, billable_code_from,
        billable_code_str, billable_unit_from, billable_unit_str, cache_capability_str,
        cache_eligibility_str, cache_reporting_str, cost_reason_str, cost_status_str,
        delivery_outcome_str, dispatch_evidence_str, execution_outcome_str, gap_reason_str,
        logical_status_str, price_resolution_str, pricing_basis_str, pricing_mode_str,
        split_observation, storable_cost, storable_quantity, stored_logical_request,
        tracking_columns, usage_error, warning_str,
    },
};

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
            } else {
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
                SELECT entry_id, api_key_id
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
                let entry_id: String = row.try_get("entry_id").map_err(|error| {
                    usage_error("failed to decode recovered quota entry", error)
                })?;
                let api_key_id: String = row.try_get("api_key_id").map_err(|error| {
                    usage_error("failed to decode recovered quota key", error)
                })?;
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
                    sqlx::query(
                        "UPDATE api_key_quota_ledger SET state = 'released', settled_atoms = NULL, resolved_at_ms = ? WHERE entry_id = ? AND state = 'reserved'",
                    )
                    .bind(now_ms)
                    .bind(&entry_id)
                    .execute(&mut *connection)
                    .await
                    .map_err(|error| usage_error("failed to release recovered quota claim", error))?;
                } else {
                    let mut settled_atoms = "0".to_owned();
                    for cost in costs {
                        settled_atoms = add_atoms(&settled_atoms, &cost.to_string()).map_err(|_| {
                            UsageRepositoryError::new("recovered quota spend overflowed")
                        })?;
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
                }
                recovered = recovered.checked_add(1).ok_or_else(|| {
                    UsageRepositoryError::new("too many quota claims to recover")
                })?;
            }
            Ok(recovered)
        }
        .await;
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
