//! Observed catalog cost: reported/derived quantities priced by the attempt's
//! locked rule, with checked integer arithmetic.
//!
//! A missing mapping, price, or usage never yields `$0`. It yields `Partial`
//! (some amount known, with a stable reason) or `Unavailable` (nothing
//! computable), so a zero is only ever a genuine, priced zero.

use serde::{Deserialize, Serialize};

use provider_core::usage::{
    NormalizationWarning, PricingMode, ProviderUsageObservation, TokenMetric, UsageContractSnapshot,
};

use crate::money::{UnitPrice, UsdAtoms, component_cost_atoms};
use crate::price::PriceResolution;

/// Version of the cost calculator; stored with each attempt so a historical cost
/// is reproducible under the same rules.
pub const CALCULATOR_VERSION: u16 = 2;

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

    let prices = match record.context_tier {
        Some(tier) => match observation.pricing_context_tokens.known_value() {
            Some(tokens) if tokens > tier.threshold_tokens => tier.prices,
            Some(_) | None => record.prices,
        },
        None => record.prices,
    };
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
    if record.unmodeled_billable_component || !observation.billable.is_empty() {
        push_unique(&mut reasons, CostReason::UnmodeledBillableComponent);
    }
    if record.unmodeled_pricing_rule {
        // The base rates are exact for a request under the rule's threshold and
        // too low above it, and nothing observed says which side this request fell
        // on. Partial is the only honest status: the amount is real but it is a
        // floor, not the answer.
        push_unique(&mut reasons, CostReason::PricingRuleUnsupported);
    }
    if record.context_tier.is_some() && observation.pricing_context_tokens.known_value().is_none() {
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

    use crate::price::{ComponentPrices, InlinePriceRecord};

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
        PriceResolution::Resolved(Box::new(InlinePriceRecord {
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
        }))
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
