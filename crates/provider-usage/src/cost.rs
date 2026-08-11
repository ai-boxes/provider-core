//! Observed catalog cost: reported/derived quantities priced by the attempt's
//! locked rule, with checked integer arithmetic.
//!
//! A missing mapping, price, or usage never yields `$0`. It yields `Partial`
//! (some amount known, with a stable reason) or `Unavailable` (nothing
//! computable), so a zero is only ever a genuine, priced zero.

use serde::{Deserialize, Serialize};

use provider_core::{
    ProviderModelPricing,
    usage::{
        CacheCapability, CacheEligibility, NormalizationWarning, PricingMode,
        ProviderUsageObservation, TokenMetric, UsageContractSnapshot,
    },
};

use crate::catalog::{component_prices_from_model_pricing, context_price_tiers_from_model_pricing};
use crate::money::{UnitPrice, UsdAtoms, component_cost_atoms};
use crate::price::{ComponentPrices, PriceResolution};

/// Version of the cost calculator; stored with each attempt so a historical cost
/// is reproducible under the same rules.
pub const CALCULATOR_VERSION: u16 = 2;

/// Why a finite-quota request cannot be assigned a safe pre-dispatch maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaximumCostError {
    InvalidPricing,
    MissingComponentPrice,
    UnsupportedPricingMode,
    ArithmeticOverflow,
    InvalidAttemptLimit,
}

/// Compute the maximum catalog cost of a text-only request before dispatch.
///
/// The caller supplies a locally counted input bound, the client-declared output
/// bound, and the route's maximum number of real upstream attempts. Every
/// context tier is evaluated and the largest total wins. Requests containing
/// image or audio input must be rejected by the caller because their billable
/// quantities are not bounded by these two token counts.
pub fn compute_maximum_text_request_cost(
    pricing: &ProviderModelPricing,
    contract: &UsageContractSnapshot,
    input_tokens: u64,
    max_output_tokens: u64,
    maximum_attempts: u32,
) -> Result<UsdAtoms, MaximumCostError> {
    if maximum_attempts == 0 {
        return Err(MaximumCostError::InvalidAttemptLimit);
    }
    if matches!(contract.pricing_mode, PricingMode::Unknown) {
        return Err(MaximumCostError::UnsupportedPricingMode);
    }

    let base =
        component_prices_from_model_pricing(pricing).ok_or(MaximumCostError::InvalidPricing)?;
    let tiers =
        context_price_tiers_from_model_pricing(pricing).ok_or(MaximumCostError::InvalidPricing)?;
    let mut maximum = maximum_cost_for_prices(base, contract, input_tokens, max_output_tokens)?;
    for tier in tiers {
        let candidate =
            maximum_cost_for_prices(tier.prices, contract, input_tokens, max_output_tokens)?;
        maximum = maximum.max(candidate);
    }

    maximum
        .as_atoms()
        .checked_mul(i128::from(maximum_attempts))
        .map(UsdAtoms::from_atoms)
        .ok_or(MaximumCostError::ArithmeticOverflow)
}

fn maximum_cost_for_prices(
    prices: ComponentPrices,
    contract: &UsageContractSnapshot,
    input_tokens: u64,
    max_output_tokens: u64,
) -> Result<UsdAtoms, MaximumCostError> {
    let mut total = UsdAtoms::ZERO;
    if input_tokens > 0 {
        let mut input_rate = required_price(prices.uncached_input_per_million)?;
        if cache_read_can_apply(contract) {
            input_rate = input_rate.max(required_price(prices.cache_read_per_million)?);
        }
        if contract.inclusion.cache_write_applicable {
            input_rate = input_rate.max(required_price(prices.cache_write_per_million)?);
        }
        total = checked_add_component(total, input_tokens, input_rate)?;
    }

    if max_output_tokens > 0 {
        total = checked_add_component(
            total,
            max_output_tokens,
            required_price(prices.output_per_million)?,
        )?;
        if contract.inclusion.reasoning_applicable
            && !contract.inclusion.reasoning_included_in_output
        {
            total = checked_add_component(
                total,
                max_output_tokens,
                required_price(prices.reasoning_per_million)?,
            )?;
        }
    }
    Ok(total)
}

fn cache_read_can_apply(contract: &UsageContractSnapshot) -> bool {
    !matches!(contract.cache_capability, CacheCapability::Unsupported)
        && !matches!(
            contract.cache_eligibility,
            CacheEligibility::NotRequested | CacheEligibility::NotApplicable
        )
}

fn required_price(price: Option<UnitPrice>) -> Result<UnitPrice, MaximumCostError> {
    price.ok_or(MaximumCostError::MissingComponentPrice)
}

fn checked_add_component(
    current: UsdAtoms,
    quantity: u64,
    price: UnitPrice,
) -> Result<UsdAtoms, MaximumCostError> {
    let component =
        component_cost_atoms(quantity, price).ok_or(MaximumCostError::ArithmeticOverflow)?;
    current
        .checked_add(component)
        .ok_or(MaximumCostError::ArithmeticOverflow)
}

/// Completeness of a catalog cost estimate. Never implies a provider invoice.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostStatus {
    /// Every applicable quantity is known and every positive component priced.
    CompleteForObservedCatalogComponents,
    /// A partial amount is known; see the reasons.
    Partial,
    /// Nothing computable.
    Unavailable,
}

/// A stable reason a cost is not complete. `example`-level in the spec; this is
/// the closed set the calculator emits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostReason {
    CatalogUnavailable,
    ProviderMappingMissing,
    ModelMappingMissing,
    CostMissing,
    CatalogEntryInvalid,
    PricingRuleUnsupported,
    PricingRuleConflict,
    TierBasisUnavailable,
    PriceModeUnknown,
    UnmodeledBillableComponent,
    /// A positive metered component has no catalog price.
    ComponentPriceMissing,
    /// A billable component's quantity was not reported or is unknown.
    UsageComponentMissing,
    InputCategorySplitUnavailable,
    /// The provider's reported numbers contradict each other under the locked
    /// contract, so the priced components may not cover what was metered.
    UsageFieldConflict,
    ModelMismatch,
    ArithmeticOverflow,
    /// No upstream call was made, so there is nothing to price. Distinct from a
    /// pricing failure: the absence here is the correct answer, not a shortfall.
    NotDispatched,
}

/// The catalog cost of one attempt. Basis is always `observed_catalog`; it is an
/// estimate, not a bill.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedCatalogCost {
    pub total_known: UsdAtoms,
    pub status: CostStatus,
    pub reasons: Vec<CostReason>,
    pub calculator_version: u16,
}

impl ObservedCatalogCost {
    /// The cost of an attempt that never reached the upstream. It is unavailable
    /// rather than zero: no call was made, so no amount was determined.
    #[must_use]
    pub fn not_dispatched() -> Self {
        Self::unavailable(CostReason::NotDispatched)
    }

    fn unavailable(reason: CostReason) -> Self {
        Self {
            total_known: UsdAtoms::ZERO,
            status: CostStatus::Unavailable,
            reasons: vec![reason],
            calculator_version: CALCULATOR_VERSION,
        }
    }
}

/// What pricing a single component produced.
enum ComponentOutcome {
    /// Priced (possibly a genuine zero for an explicit-zero quantity).
    Priced(UsdAtoms),
    /// Not applicable to cost (not applicable, or unknown-but-unpriced).
    Skip,
    /// A partial reason, no amount added.
    Partial(CostReason),
    /// Arithmetic overflowed.
    Overflow,
}

/// Price one token component: an explicit zero needs no price; a positive
/// quantity needs one; a not-reported/unknown quantity is incomplete only when
/// the component is actually priced (i.e. billable).
fn price_component(quantity: TokenMetric, price: Option<UnitPrice>) -> ComponentOutcome {
    match quantity.known_value() {
        Some(0) => ComponentOutcome::Priced(UsdAtoms::ZERO),
        Some(count) => match price {
            Some(unit) => match component_cost_atoms(count, unit) {
                Some(atoms) => ComponentOutcome::Priced(atoms),
                None => ComponentOutcome::Overflow,
            },
            None => ComponentOutcome::Partial(CostReason::ComponentPriceMissing),
        },
        None => match quantity {
            TokenMetric::NotApplicable => ComponentOutcome::Skip,
            _ if price.is_some() => ComponentOutcome::Partial(CostReason::UsageComponentMissing),
            _ => ComponentOutcome::Skip,
        },
    }
}

fn push_unique(reasons: &mut Vec<CostReason>, reason: CostReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

/// Compute the observed catalog cost for one attempt from its normalized usage,
/// locked contract, and price resolution.
#[must_use]
pub fn compute_observed_catalog_cost(
    observation: &ProviderUsageObservation,
    contract: &UsageContractSnapshot,
    resolution: &PriceResolution,
) -> ObservedCatalogCost {
    let record = match resolution {
        PriceResolution::Resolved(record) => record,
        PriceResolution::CatalogUnavailable => {
            return ObservedCatalogCost::unavailable(CostReason::CatalogUnavailable);
        }
        PriceResolution::ProviderMappingMissing => {
            return ObservedCatalogCost::unavailable(CostReason::ProviderMappingMissing);
        }
        PriceResolution::ModelMappingMissing => {
            return ObservedCatalogCost::unavailable(CostReason::ModelMappingMissing);
        }
        PriceResolution::CostMissing => {
            return ObservedCatalogCost::unavailable(CostReason::CostMissing);
        }
        PriceResolution::CatalogEntryInvalid => {
            return ObservedCatalogCost::unavailable(CostReason::CatalogEntryInvalid);
        }
        PriceResolution::PricingRuleUnsupported => {
            return ObservedCatalogCost::unavailable(CostReason::PricingRuleUnsupported);
        }
        PriceResolution::PricingRuleConflict => {
            return ObservedCatalogCost::unavailable(CostReason::PricingRuleConflict);
        }
    };

    let prices = record.prices_for_context(observation.pricing_context_tokens.known_value());
    // Reasoning that the contract says is already inside `output_tokens` must not
    // be priced again, even when the catalog carries a separate reasoning price.
    let reasoning_tokens = if contract.inclusion.reasoning_included_in_output {
        TokenMetric::NotApplicable
    } else {
        observation.reasoning_tokens
    };
    let components = [
        price_component(
            observation.uncached_input_tokens,
            prices.uncached_input_per_million,
        ),
        price_component(
            observation.cache_read_input_tokens,
            prices.cache_read_per_million,
        ),
        price_component(
            observation.cache_write_input_tokens,
            prices.cache_write_per_million,
        ),
        price_component(observation.output_tokens, prices.output_per_million),
        price_component(reasoning_tokens, prices.reasoning_per_million),
        price_component(
            observation.input_audio_tokens,
            prices.input_audio_per_million,
        ),
        price_component(
            observation.output_audio_tokens,
            prices.output_audio_per_million,
        ),
    ];

    let mut total = UsdAtoms::ZERO;
    let mut reasons: Vec<CostReason> = Vec::new();
    for outcome in components {
        match outcome {
            ComponentOutcome::Priced(atoms) => match total.checked_add(atoms) {
                Some(sum) => total = sum,
                None => return ObservedCatalogCost::unavailable(CostReason::ArithmeticOverflow),
            },
            ComponentOutcome::Skip => {}
            ComponentOutcome::Partial(reason) => push_unique(&mut reasons, reason),
            ComponentOutcome::Overflow => {
                return ObservedCatalogCost::unavailable(CostReason::ArithmeticOverflow);
            }
        }
    }

    if matches!(contract.pricing_mode, PricingMode::Unknown) {
        push_unique(&mut reasons, CostReason::PriceModeUnknown);
    }
    if record.unmodeled_billable_component() || !observation.billable.is_empty() {
        push_unique(&mut reasons, CostReason::UnmodeledBillableComponent);
    }
    if record.unmodeled_pricing_rule() {
        // The base rates are exact for a request under the rule's threshold and
        // too low above it, and nothing observed says which side this request fell
        // on. Partial is the only honest status: the amount is real but it is a
        // floor, not the answer.
        push_unique(&mut reasons, CostReason::PricingRuleUnsupported);
    }
    if record.has_context_tiers() && observation.pricing_context_tokens.known_value().is_none() {
        push_unique(&mut reasons, CostReason::TierBasisUnavailable);
    }
    if observation
        .warnings
        .contains(&NormalizationWarning::ProviderModelMismatch)
    {
        push_unique(&mut reasons, CostReason::ModelMismatch);
    }
    if observation
        .warnings
        .contains(&NormalizationWarning::FieldConflict)
    {
        // The components below each priced correctly, so nothing here reports a
        // shortfall on its own — but the reported numbers do not reconcile, which
        // means the set of components may be the wrong set. Complete is a claim
        // this cost cannot support.
        push_unique(&mut reasons, CostReason::UsageFieldConflict);
    }

    let status = if reasons.is_empty() {
        CostStatus::CompleteForObservedCatalogComponents
    } else {
        CostStatus::Partial
    };

    ObservedCatalogCost {
        total_known: total,
        status,
        reasons,
        calculator_version: CALCULATOR_VERSION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provider_core::usage::{
        CacheCapability, CacheEligibility, CacheReportingExpectation, PricingContextBasis,
        RawUsageFields, TokenInclusionRules, TokenUnknownReason, TotalSource, normalize_usage,
    };
    use provider_core::{ProviderModelPricingSource, ProviderModelPricingTier};

    use crate::price::{
        CatalogInlinePriceRecordV1, ComponentPrices, ContextPriceTier, InlinePriceRecord,
        ModelInlinePriceRecordV2,
    };

    const PER_MILLION: i128 = 10i128.pow(crate::money::PRICE_SCALE);

    fn contract(mode: PricingMode) -> UsageContractSnapshot {
        UsageContractSnapshot {
            contract_version: 1,
            normalization_version: 1,
            inclusion: TokenInclusionRules {
                input_includes_cache: false,
                input_categories_mutually_exclusive: true,
                reasoning_included_in_output: true,
                reasoning_applicable: true,
                audio_applicable: false,
                cache_write_applicable: true,
                missing_cache_read_means_zero: false,
                total_source: TotalSource::Reported,
            },
            cache_capability: CacheCapability::Supported,
            cache_eligibility: CacheEligibility::Eligible,
            cache_reporting_expectation: CacheReportingExpectation::Expected,
            pricing_context_basis: PricingContextBasis::EffectiveInput,
            pricing_mode: mode,
        }
    }

    fn record(prices: ComponentPrices) -> PriceResolution {
        PriceResolution::Resolved(Box::new(InlinePriceRecord::CatalogV1(
            CatalogInlinePriceRecordV1 {
                format_version: 1,
                parser_version: 1,
                catalog_revision: "test".to_owned(),
                catalog_provider_id: "openai".to_owned(),
                catalog_model_id: "gpt-x".to_owned(),
                mapping_revision: 1,
                prices,
                context_tier: None,
                selected_tier: None,
                unmodeled_billable_component: false,
                unmodeled_pricing_rule: false,
            },
        )))
    }

    fn reported(value: u64) -> TokenMetric {
        TokenMetric::ProviderReported { value }
    }

    fn observation(input: TokenMetric, output: TokenMetric) -> ProviderUsageObservation {
        ProviderUsageObservation {
            uncached_input_tokens: input,
            cache_read_input_tokens: TokenMetric::NotApplicable,
            cache_write_input_tokens: TokenMetric::NotApplicable,
            effective_input_tokens: input,
            output_tokens: output,
            reasoning_tokens: TokenMetric::NotApplicable,
            input_audio_tokens: TokenMetric::NotApplicable,
            output_audio_tokens: TokenMetric::NotApplicable,
            total_tokens: TokenMetric::NotReported,
            pricing_context_tokens: TokenMetric::NotReported,
            billable: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn omitted_cache_read_can_be_zero_by_contract_and_cost_completely() {
        let usage_contract = UsageContractSnapshot {
            contract_version: 2,
            normalization_version: 2,
            inclusion: TokenInclusionRules {
                input_includes_cache: true,
                input_categories_mutually_exclusive: false,
                reasoning_included_in_output: true,
                reasoning_applicable: true,
                audio_applicable: true,
                cache_write_applicable: false,
                missing_cache_read_means_zero: true,
                total_source: TotalSource::Reported,
            },
            cache_capability: CacheCapability::Unknown,
            cache_eligibility: CacheEligibility::Unknown,
            cache_reporting_expectation: CacheReportingExpectation::Unknown,
            pricing_context_basis: PricingContextBasis::EffectiveInput,
            pricing_mode: PricingMode::Default,
        };
        let observation = normalize_usage(
            Some(RawUsageFields {
                input: Some(2_534),
                output: Some(768),
                total: Some(3_302),
                ..RawUsageFields::default()
            }),
            &usage_contract,
        );
        assert_eq!(
            observation.uncached_input_tokens,
            TokenMetric::DerivedFromReported {
                value: 2_534,
                rule_version: 2,
            }
        );
        assert_eq!(
            observation.cache_read_input_tokens,
            TokenMetric::DerivedFromReported {
                value: 0,
                rule_version: 2,
            }
        );

        let cost = compute_observed_catalog_cost(
            &observation,
            &usage_contract,
            &record(ComponentPrices {
                uncached_input_per_million: Some(UnitPrice::from_scaled(PER_MILLION)),
                cache_read_per_million: Some(UnitPrice::from_scaled(PER_MILLION / 10)),
                output_per_million: Some(UnitPrice::from_scaled(10 * PER_MILLION)),
                ..ComponentPrices::default()
            }),
        );

        assert_eq!(
            cost.status,
            CostStatus::CompleteForObservedCatalogComponents
        );
        assert!(cost.reasons.is_empty());
        assert_eq!(cost.total_known.to_decimal_string(), "0.01021400000000");
    }

    #[test]
    fn maximum_text_cost_uses_the_most_expensive_tier_and_attempt_count() {
        let pricing = ProviderModelPricing {
            input: Some("2".to_owned()),
            output: Some("10".to_owned()),
            cache_read: Some("1".to_owned()),
            cache_write: None,
            reasoning: None,
            input_audio: None,
            output_audio: None,
            tiers: vec![ProviderModelPricingTier {
                threshold_tokens: 100,
                input: Some("4".to_owned()),
                output: Some("20".to_owned()),
                cache_read: Some("6".to_owned()),
                cache_write: None,
                reasoning: None,
                input_audio: None,
                output_audio: None,
            }],
        };
        let mut usage_contract = contract(PricingMode::Default);
        usage_contract.inclusion.cache_write_applicable = false;

        let maximum = compute_maximum_text_request_cost(&pricing, &usage_contract, 100, 10, 2)
            .expect("maximum cost");

        assert_eq!(maximum.as_atoms(), 1_600 * PER_MILLION);
    }

    #[test]
    fn maximum_text_cost_rejects_a_missing_applicable_cache_price() {
        let pricing = ProviderModelPricing {
            input: Some("2".to_owned()),
            output: Some("10".to_owned()),
            cache_read: None,
            cache_write: None,
            reasoning: None,
            input_audio: None,
            output_audio: None,
            tiers: Vec::new(),
        };
        let mut usage_contract = contract(PricingMode::Default);
        usage_contract.inclusion.cache_write_applicable = false;

        assert_eq!(
            compute_maximum_text_request_cost(&pricing, &usage_contract, 1, 1, 1),
            Err(MaximumCostError::MissingComponentPrice)
        );
    }

    #[test]
    fn maximum_text_cost_prices_separate_reasoning_conservatively() {
        let pricing = ProviderModelPricing {
            input: Some("2".to_owned()),
            output: Some("10".to_owned()),
            cache_read: None,
            cache_write: None,
            reasoning: Some("4".to_owned()),
            input_audio: None,
            output_audio: None,
            tiers: Vec::new(),
        };
        let mut usage_contract = contract(PricingMode::Default);
        usage_contract.cache_capability = CacheCapability::Unsupported;
        usage_contract.inclusion.cache_write_applicable = false;
        usage_contract.inclusion.reasoning_included_in_output = false;

        let maximum = compute_maximum_text_request_cost(&pricing, &usage_contract, 5, 7, 1)
            .expect("maximum cost");
        assert_eq!(maximum.as_atoms(), 108 * PER_MILLION);
    }

    #[test]
    fn model_price_uses_the_highest_matching_context_tier() {
        let resolution = PriceResolution::Resolved(Box::new(InlinePriceRecord::ModelV2(
            ModelInlinePriceRecordV2 {
                format_version: 2,
                source: ProviderModelPricingSource::Catalog,
                prices: ComponentPrices {
                    uncached_input_per_million: Some(UnitPrice::from_scaled(PER_MILLION)),
                    output_per_million: Some(UnitPrice::from_scaled(10 * PER_MILLION)),
                    ..ComponentPrices::default()
                },
                tiers: vec![
                    ContextPriceTier {
                        threshold_tokens: 100,
                        prices: ComponentPrices {
                            uncached_input_per_million: Some(UnitPrice::from_scaled(
                                2 * PER_MILLION,
                            )),
                            output_per_million: Some(UnitPrice::from_scaled(20 * PER_MILLION)),
                            ..ComponentPrices::default()
                        },
                    },
                    ContextPriceTier {
                        threshold_tokens: 200,
                        prices: ComponentPrices {
                            uncached_input_per_million: Some(UnitPrice::from_scaled(
                                3 * PER_MILLION,
                            )),
                            output_per_million: Some(UnitPrice::from_scaled(30 * PER_MILLION)),
                            ..ComponentPrices::default()
                        },
                    },
                ],
            },
        )));
        let mut usage = observation(reported(201), reported(1));
        usage.pricing_context_tokens = reported(201);
        let cost =
            compute_observed_catalog_cost(&usage, &contract(PricingMode::Default), &resolution);
        assert_eq!(
            cost.status,
            CostStatus::CompleteForObservedCatalogComponents
        );
        assert_eq!(cost.total_known.as_atoms(), (201 * 3 + 30) * PER_MILLION);

        usage.pricing_context_tokens = reported(200);
        let boundary =
            compute_observed_catalog_cost(&usage, &contract(PricingMode::Default), &resolution);
        assert_eq!(
            boundary.total_known.as_atoms(),
            (201 * 2 + 20) * PER_MILLION
        );
    }

    #[test]
    fn missing_price_for_positive_component_is_partial_not_zero() {
        let prices = ComponentPrices {
            uncached_input_per_million: Some(UnitPrice::from_scaled(3 * PER_MILLION)),
            output_per_million: None, // no output price
            ..ComponentPrices::default()
        };
        let cost = compute_observed_catalog_cost(
            &observation(reported(1000), reported(500)),
            &contract(PricingMode::Default),
            &record(prices),
        );
        assert_eq!(cost.status, CostStatus::Partial);
        assert_eq!(cost.total_known.as_atoms(), 1000 * 3 * PER_MILLION);
        assert!(cost.reasons.contains(&CostReason::ComponentPriceMissing));
    }

    #[test]
    fn unknown_quantity_on_priced_component_is_partial() {
        let prices = ComponentPrices {
            uncached_input_per_million: Some(UnitPrice::from_scaled(3 * PER_MILLION)),
            output_per_million: Some(UnitPrice::from_scaled(15 * PER_MILLION)),
            ..ComponentPrices::default()
        };
        let unknown_output = TokenMetric::Unknown {
            reason: TokenUnknownReason::NoUsageTerminal,
        };
        let cost = compute_observed_catalog_cost(
            &observation(reported(1000), unknown_output),
            &contract(PricingMode::Default),
            &record(prices),
        );
        assert_eq!(cost.status, CostStatus::Partial);
        assert!(cost.reasons.contains(&CostReason::UsageComponentMissing));
    }

    #[test]
    fn a_reported_total_that_does_not_add_up_stops_the_cost_reading_as_complete() {
        // The exact risk taken when Grok's contract was inferred rather than
        // measured: it declares reasoning to sit inside `output`. Here it does not
        // — the provider's own total is input + output + reasoning — so 40 metered
        // tokens fall outside every priced component. Nothing errors and no metric
        // is unknown; only the arithmetic disagrees, and that has to be enough.
        let grok_like = UsageContractSnapshot {
            inclusion: TokenInclusionRules {
                input_includes_cache: true,
                input_categories_mutually_exclusive: false,
                reasoning_included_in_output: true,
                ..contract(PricingMode::Default).inclusion
            },
            ..contract(PricingMode::Default)
        };
        let prices = ComponentPrices {
            uncached_input_per_million: Some(UnitPrice::from_scaled(3 * PER_MILLION)),
            cache_read_per_million: Some(UnitPrice::from_scaled(PER_MILLION)),
            output_per_million: Some(UnitPrice::from_scaled(15 * PER_MILLION)),
            ..ComponentPrices::default()
        };
        let fields = |total| RawUsageFields {
            input: Some(1000),
            cache_read: Some(0),
            output: Some(100),
            reasoning: Some(40),
            total: Some(total),
            ..RawUsageFields::default()
        };

        let conflicting = normalize_usage(Some(fields(1140)), &grok_like);
        assert!(
            conflicting
                .warnings
                .contains(&NormalizationWarning::FieldConflict),
            "a total that exceeds input + output contradicts the inclusion rules"
        );
        let cost = compute_observed_catalog_cost(&conflicting, &grok_like, &record(prices));
        assert_eq!(cost.status, CostStatus::Partial);
        assert!(cost.reasons.contains(&CostReason::UsageFieldConflict));

        // And it must stay quiet when the numbers do reconcile, or every attempt
        // would be partial and the signal would mean nothing.
        let agreeing = normalize_usage(Some(fields(1100)), &grok_like);
        assert!(
            !agreeing
                .warnings
                .contains(&NormalizationWarning::FieldConflict)
        );
        assert_eq!(
            compute_observed_catalog_cost(&agreeing, &grok_like, &record(prices)).status,
            CostStatus::CompleteForObservedCatalogComponents
        );
    }

    #[test]
    fn reasoning_inside_output_is_not_priced_twice() {
        // The catalog carries a reasoning price, but the contract says reasoning
        // is already counted inside `output_tokens`.
        let prices = ComponentPrices {
            uncached_input_per_million: Some(UnitPrice::from_scaled(3 * PER_MILLION)),
            output_per_million: Some(UnitPrice::from_scaled(15 * PER_MILLION)),
            reasoning_per_million: Some(UnitPrice::from_scaled(15 * PER_MILLION)),
            ..ComponentPrices::default()
        };
        let mut observed = observation(reported(1000), reported(500));
        observed.reasoning_tokens = reported(400);

        let mut contract_included = contract(PricingMode::Default);
        contract_included.inclusion.reasoning_included_in_output = true;
        let cost = compute_observed_catalog_cost(&observed, &contract_included, &record(prices));
        // Only input + output are billed; the 400 reasoning tokens are already in output.
        assert_eq!(
            cost.status,
            CostStatus::CompleteForObservedCatalogComponents
        );
        assert_eq!(cost.total_known.as_atoms(), 10_500 * PER_MILLION);

        // When the contract says reasoning is billed separately, it is added.
        let mut contract_separate = contract(PricingMode::Default);
        contract_separate.inclusion.reasoning_included_in_output = false;
        let cost_separate =
            compute_observed_catalog_cost(&observed, &contract_separate, &record(prices));
        assert_eq!(
            cost_separate.total_known.as_atoms(),
            (10_500 + 400 * 15) * PER_MILLION
        );
    }
}
