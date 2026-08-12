use std::sync::Arc;

use provider_auth::{ApiKeyId, AuthRepository, QuotaAdmissionOutcome};
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
    AttemptFacts, AttemptSequence, CatalogInlinePriceRecordV1, ComponentPrices, CostReason,
    CostStatus, DeliveryOutcome, DispatchEvidence, ExecutionOutcome, InlinePriceRecord,
    LogicalRequestStart, LogicalRequestTerminal, LogicalStatus, LogicalWriteOutcome,
    ObservedCatalogCost, PRICE_SCALE, PriceResolution, QuotaLedgerWriter, TrackingGapReason,
    TrackingState, UnitPrice, UsageRepository, UsdAtoms,
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
                uncached_input_per_million: Some(UnitPrice::from_scaled(125 * PER_MILLION / 100)),
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

    let spent: String = sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
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

    let ledger: (String, Option<String>) =
        sqlx::query_as("SELECT state, settled_atoms FROM api_key_quota_ledger WHERE entry_id = ?")
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
async fn quota_ledger_settles_exact_and_releases_unknown_costs() {
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
    let spent: String = sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
        .fetch_one(&repository.pool)
        .await
        .expect("load settled spend");
    assert_eq!(spent, "40");
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT state, settled_atoms FROM api_key_quota_ledger ORDER BY entry_id")
            .fetch_all(&repository.pool)
            .await
            .expect("load quota outcomes");
    assert_eq!(
        rows,
        vec![
            ("settled".to_owned(), Some("40".to_owned())),
            ("released".to_owned(), None),
            ("released".to_owned(), None),
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
    let spent: String = sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
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
    let spent: String = sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
        .fetch_one(&repository.pool)
        .await
        .expect("load recovered spend");
    assert_eq!(spent, "0");
    let unresolved: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM api_key_quota_ledger WHERE state = 'reserved'")
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

    assert_eq!(
        repository
            .recover_quota_reservations(100)
            .await
            .expect("recover completed dispatched reservation"),
        1
    );
    let ledger: (String, Option<String>) =
        sqlx::query_as("SELECT state, settled_atoms FROM api_key_quota_ledger WHERE entry_id = ?")
            .bind("req-recover-cost")
            .fetch_one(&repository.pool)
            .await
            .expect("load recovered ledger");
    assert_eq!(ledger, ("settled".to_owned(), Some("40".to_owned())));
    let spent: String = sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
        .fetch_one(&repository.pool)
        .await
        .expect("load recovered spend");
    assert_eq!(spent, "40");
}

#[tokio::test]
async fn startup_recovery_sums_complete_attempts_ignores_partial_and_is_idempotent() {
    let repository = repository().await;
    insert_api_key(&repository, "key-1", Some("9999999999999999")).await;
    repository
        .begin_quota_request(&start("req-recover-mixed"))
        .await
        .expect("begin quota request");
    mark_dispatched(&repository, "req-recover-mixed").await;

    for (attempt_id, sequence, atoms, status) in [
        (
            "att-complete-1",
            1,
            40,
            CostStatus::CompleteForObservedCatalogComponents,
        ),
        ("att-partial", 2, 500, CostStatus::Partial),
        (
            "att-complete-2",
            3,
            30,
            CostStatus::CompleteForObservedCatalogComponents,
        ),
    ] {
        let mut facts = attempt("req-recover-mixed", attempt_id, sequence);
        facts.cost = ObservedCatalogCost {
            total_known: UsdAtoms::from_atoms(atoms),
            status,
            reasons: if status == CostStatus::Partial {
                vec![CostReason::UnmodeledBillableComponent]
            } else {
                Vec::new()
            },
            calculator_version: 1,
        };
        repository
            .record_attempt(&facts)
            .await
            .expect("record mixed recovery attempt");
    }

    assert_eq!(
        repository
            .recover_quota_reservations(100)
            .await
            .expect("recover mixed attempts"),
        1
    );
    assert_eq!(
        repository
            .recover_quota_reservations(200)
            .await
            .expect("repeat mixed recovery"),
        0
    );
    let ledger: (String, Option<String>) =
        sqlx::query_as("SELECT state, settled_atoms FROM api_key_quota_ledger WHERE entry_id = ?")
            .bind("req-recover-mixed")
            .fetch_one(&repository.pool)
            .await
            .expect("load recovered mixed ledger");
    assert_eq!(ledger, ("settled".to_owned(), Some("70".to_owned())));
    let spent: String = sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
        .fetch_one(&repository.pool)
        .await
        .expect("load recovered mixed spend");
    assert_eq!(spent, "70");
}

#[tokio::test]
async fn startup_recovery_exhausts_key_for_dispatched_claim_without_complete_cost() {
    let repository = repository().await;
    insert_api_key(&repository, "key-1", Some("9999999999999999")).await;
    sqlx::query("UPDATE api_keys SET spent_atoms = '99' WHERE id = 'key-1'")
        .execute(&repository.pool)
        .await
        .expect("seed existing spend");
    repository
        .begin_quota_request(&start("req-recover-unknown"))
        .await
        .expect("begin quota request");
    mark_dispatched(&repository, "req-recover-unknown").await;

    assert_eq!(
        repository
            .recover_quota_reservations(100)
            .await
            .expect("settle incomplete dispatched reservation conservatively"),
        1
    );
    let ledger: (String, Option<String>) = sqlx::query_as(
        "SELECT state, settled_atoms FROM api_key_quota_ledger WHERE entry_id = 'req-recover-unknown'",
    )
    .fetch_one(&repository.pool)
    .await
    .expect("load recovered ledger");
    assert_eq!(
        ledger,
        ("settled".to_owned(), Some("9999999999999900".to_owned()))
    );
    let spent: String = sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
        .fetch_one(&repository.pool)
        .await
        .expect("load conservatively recovered spend");
    assert_eq!(spent, "9999999999999999");
}

#[tokio::test]
async fn startup_recovery_keeps_a_complete_zero_cost_exact() {
    let repository = repository().await;
    insert_api_key(&repository, "key-1", Some("9999999999999999")).await;
    repository
        .begin_quota_request(&start("req-recover-zero"))
        .await
        .expect("begin quota request");
    mark_dispatched(&repository, "req-recover-zero").await;

    let mut facts = attempt("req-recover-zero", "att-recover-zero", 1);
    facts.cost = ObservedCatalogCost {
        total_known: UsdAtoms::ZERO,
        status: CostStatus::CompleteForObservedCatalogComponents,
        reasons: Vec::new(),
        calculator_version: 1,
    };
    repository
        .record_attempt(&facts)
        .await
        .expect("record zero-cost attempt");

    assert_eq!(
        repository
            .recover_quota_reservations(100)
            .await
            .expect("recover exact zero cost"),
        1
    );
    let ledger: (String, Option<String>) = sqlx::query_as(
        "SELECT state, settled_atoms FROM api_key_quota_ledger WHERE entry_id = 'req-recover-zero'",
    )
    .fetch_one(&repository.pool)
    .await
    .expect("load zero-cost ledger");
    assert_eq!(ledger, ("settled".to_owned(), Some("0".to_owned())));
}

#[tokio::test]
async fn startup_recovery_settles_missing_key_dispatch_without_blocking_startup() {
    let repository = repository().await;
    insert_api_key(&repository, "key-1", Some("100")).await;
    repository
        .begin_quota_request(&start("req-deleted-key"))
        .await
        .expect("begin quota request");
    mark_dispatched(&repository, "req-deleted-key").await;
    sqlx::query("DELETE FROM api_keys WHERE id = 'key-1'")
        .execute(&repository.pool)
        .await
        .expect("delete API key after dispatch");

    assert_eq!(
        repository
            .recover_quota_reservations(100)
            .await
            .expect("recover deleted key claim"),
        1
    );
    let ledger: (String, Option<String>) = sqlx::query_as(
        "SELECT state, settled_atoms FROM api_key_quota_ledger WHERE entry_id = 'req-deleted-key'",
    )
    .fetch_one(&repository.pool)
    .await
    .expect("load deleted key ledger");
    assert_eq!(ledger, ("settled".to_owned(), Some("0".to_owned())));
}

#[tokio::test]
async fn startup_recovery_settles_now_unlimited_key_without_blocking_startup() {
    let repository = repository().await;
    insert_api_key(&repository, "key-1", Some("100")).await;
    repository
        .begin_quota_request(&start("req-unlimited-key"))
        .await
        .expect("begin quota request");
    mark_dispatched(&repository, "req-unlimited-key").await;
    sqlx::query("UPDATE api_keys SET quota_limit_atoms = NULL WHERE id = 'key-1'")
        .execute(&repository.pool)
        .await
        .expect("remove quota after dispatch");

    assert_eq!(
        repository
            .recover_quota_reservations(100)
            .await
            .expect("recover unlimited key claim"),
        1
    );
    let ledger: (String, Option<String>) = sqlx::query_as(
        "SELECT state, settled_atoms FROM api_key_quota_ledger WHERE entry_id = 'req-unlimited-key'",
    )
    .fetch_one(&repository.pool)
    .await
    .expect("load unlimited key ledger");
    assert_eq!(ledger, ("settled".to_owned(), Some("0".to_owned())));
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
    let spent: String = sqlx::query_scalar("SELECT spent_atoms FROM api_keys WHERE id = 'key-1'")
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
