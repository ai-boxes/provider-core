/// A token metric split into what the column holds and what the sidecar JSON
/// holds. `kind` is `None` exactly when the metric is a plain provider-reported
/// number, which is the common case and stores nothing extra.
use provider_core::{
    ProviderKind,
    usage::{
        BillableComponentCode, BillableUnit, CacheCapability, CacheEligibility,
        CacheReportingExpectation, NormalizationWarning, PricingContextBasis, PricingMode,
        ProviderUsageObservation, TokenInclusionRules, TokenMetric, TokenUnknownReason,
        UsageContractSnapshot,
    },
};
use provider_usage::{
    AttemptFacts, AttemptFailoverReason, AttemptOutcome, AttemptSequence, CostReason, CostStatus,
    DeliveryOutcome, DispatchEvidence, ExecutionOutcome, InlinePriceRecord, LogicalRequestStart,
    LogicalStatus, ObservedCatalogCost, PriceResolution, StoredLogicalRequest, TrackingGapReason,
    TrackingState, UsageRepositoryError, UsdAtoms,
};
use serde::{Deserialize, Serialize};
use sqlx::{Row, sqlite::SqliteRow};

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
pub(super) struct StoredKinds {
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
pub(super) struct StoredValues {
    pub(super) uncached_input: Option<i64>,
    pub(super) cache_read_input: Option<i64>,
    pub(super) cache_write_input: Option<i64>,
    pub(super) effective_input: Option<i64>,
    pub(super) output: Option<i64>,
    pub(super) reasoning: Option<i64>,
    pub(super) input_audio: Option<i64>,
    pub(super) output_audio: Option<i64>,
    pub(super) total: Option<i64>,
    pub(super) pricing_context: Option<i64>,
}

pub(super) fn split_observation(
    observation: &ProviderUsageObservation,
) -> (StoredValues, StoredKinds) {
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
pub(super) struct StorableCost {
    pub(super) status: CostStatus,
    pub(super) atoms: Option<i64>,
    pub(super) reasons: Vec<CostReason>,
    pub(super) calculator_version: u16,
}

pub(super) fn storable_cost(cost: &ObservedCatalogCost) -> StorableCost {
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
pub(super) fn storable_quantity(value: u64) -> Result<i64, UsageRepositoryError> {
    i64::try_from(value)
        .map_err(|_| UsageRepositoryError::new("billable quantity is too large to store"))
}

pub(super) fn tracking_columns(tracking: TrackingState) -> (&'static str, Option<&'static str>) {
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

pub(super) const fn gap_reason_str(reason: TrackingGapReason) -> &'static str {
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

pub(super) const fn logical_status_str(status: LogicalStatus) -> &'static str {
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

pub(super) const fn execution_outcome_str(outcome: ExecutionOutcome) -> &'static str {
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

pub(super) const fn delivery_outcome_str(outcome: DeliveryOutcome) -> &'static str {
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

pub(super) const fn attempt_outcome_str(outcome: AttemptOutcome) -> &'static str {
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

pub(super) const fn attempt_failover_reason_str(reason: AttemptFailoverReason) -> &'static str {
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

pub(super) const fn dispatch_evidence_str(evidence: DispatchEvidence) -> &'static str {
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

pub(super) const fn cache_capability_str(capability: CacheCapability) -> &'static str {
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

pub(super) const fn cache_eligibility_str(eligibility: CacheEligibility) -> &'static str {
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

pub(super) const fn cache_reporting_str(expectation: CacheReportingExpectation) -> &'static str {
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

pub(super) const fn pricing_basis_str(basis: PricingContextBasis) -> &'static str {
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

pub(super) const fn pricing_mode_str(mode: PricingMode) -> &'static str {
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

pub(super) const fn price_resolution_str(resolution: &PriceResolution) -> &'static str {
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

pub(super) const fn cost_status_str(status: CostStatus) -> &'static str {
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

pub(super) const fn cost_reason_str(reason: CostReason) -> &'static str {
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

pub(super) const fn warning_str(warning: NormalizationWarning) -> &'static str {
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

pub(super) const fn billable_code_str(code: BillableComponentCode) -> &'static str {
    match code {
        BillableComponentCode::CacheWrite5m => "cache_write_5m",
        BillableComponentCode::CacheWrite1h => "cache_write_1h",
        BillableComponentCode::ServerToolCall => "server_tool_call",
        BillableComponentCode::ImageInputTokens => "image_input_tokens",
        BillableComponentCode::ImageOutputTokens => "image_output_tokens",
    }
}

pub(super) fn billable_code_from(
    value: &str,
) -> Result<BillableComponentCode, UsageRepositoryError> {
    match value {
        "cache_write_5m" => Ok(BillableComponentCode::CacheWrite5m),
        "cache_write_1h" => Ok(BillableComponentCode::CacheWrite1h),
        "server_tool_call" => Ok(BillableComponentCode::ServerToolCall),
        "image_input_tokens" => Ok(BillableComponentCode::ImageInputTokens),
        "image_output_tokens" => Ok(BillableComponentCode::ImageOutputTokens),
        other => Err(unknown_value("billable component code", other)),
    }
}

pub(super) const fn billable_unit_str(unit: BillableUnit) -> &'static str {
    match unit {
        BillableUnit::Tokens => "tokens",
        BillableUnit::Calls => "calls",
    }
}

pub(super) fn billable_unit_from(value: &str) -> Result<BillableUnit, UsageRepositoryError> {
    match value {
        "tokens" => Ok(BillableUnit::Tokens),
        "calls" => Ok(BillableUnit::Calls),
        other => Err(unknown_value("billable unit", other)),
    }
}

pub(super) fn stored_logical_request(
    row: SqliteRow,
) -> Result<StoredLogicalRequest, UsageRepositoryError> {
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
