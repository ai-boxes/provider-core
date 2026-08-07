//! The models.dev price catalog: parsing, and resolving a price for an attempt.
//!
//! Source: `https://models.dev/api.json`, shaped as
//! `{provider_id: {models: {model_id: {cost: {...}}}}}` with every cost in USD
//! per million tokens — the same unit as [`UnitPrice`].
//!
//! Two rules make this honest rather than merely convenient:
//!
//! 1. **No `f64` ever touches a price.** `serde_json` would parse `1.25` into a
//!    float before this code saw it, so cost numbers are captured as raw JSON
//!    text and converted to a scaled integer directly. A value that cannot be
//!    represented exactly is rejected, not rounded.
//! 2. **Mapping is exact, never guessed.** A provider or model with no entry
//!    resolves to a stable "missing" reason, so an attempt records why it has no
//!    price instead of appearing to be free.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use provider_core::ProviderKind;
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::{
    money::{PRICE_SCALE, UnitPrice},
    price::{ComponentPrices, ContextPriceTier, InlinePriceRecord, PriceResolution},
    tracking::PriceResolver,
};

/// The document layout this parser understands.
pub const CATALOG_FORMAT_VERSION: u16 = 1;

/// This parser's own version, bumped when its interpretation changes.
pub const CATALOG_PARSER_VERSION: u16 = 2;

/// The provider-to-catalog mapping's version, bumped when the mapping changes.
pub const CATALOG_MAPPING_REVISION: u32 = 1;

/// Largest catalog body accepted, before parsing. The real document is a couple
/// of megabytes; this bounds what an unexpected response can cost us.
pub const MAX_CATALOG_BYTES: usize = 16 * 1024 * 1024;

/// The catalog provider id for one of our provider kinds.
///
/// Only Codex is claimed, and only because its models are OpenAI's. The others
/// are deliberately unmapped: guessing an id would attach confident prices to a
/// provider whose catalog entry nobody has checked.
#[must_use]
pub const fn catalog_provider_id(kind: ProviderKind) -> Option<&'static str> {
    match kind {
        ProviderKind::Codex => Some("openai"),
        // Verified against the real document: `xai` exists with 10 models and
        // `grok-4.3` carries input, output and cache_read prices.
        ProviderKind::Grok => Some("xai"),
        // A "compatible" account points at whatever the operator configured and its
        // model ids are user-chosen, so there is no mapping to infer. These resolve
        // to `provider_mapping_missing` — token counts without a cost.
        ProviderKind::OpenAiCompatible | ProviderKind::AnthropicCompatible => None,
    }
}

/// What the catalog says about one model.
///
/// The prices are boxed because there is one entry per model in the whole
/// document and most carry no price: sizing every entry for the largest variant
/// would waste most of the map.
#[derive(Clone, Debug, Eq, PartialEq)]
enum CatalogEntry {
    Priced {
        prices: Box<ComponentPrices>,
        context_tier: Option<ContextPriceTier>,
        unmodeled_pricing_rule: bool,
    },
    /// The entry exists but carries no `cost` at all.
    NoCost,
    /// The entry has a cost that could not be read exactly.
    Invalid,
}

/// An immutable view of the catalog. Swapped as a whole, so a refresh can never
/// be observed half-applied and an attempt always prices against one revision.
#[derive(Debug)]
pub struct CatalogSnapshot {
    revision: String,
    entries: HashMap<(String, String), CatalogEntry>,
}

impl CatalogSnapshot {
    /// Parse a catalog body. `revision` is the content hash the caller stored it
    /// under, and is inlined onto every attempt priced from this snapshot.
    pub fn parse(body: &str, revision: impl Into<String>) -> Result<Self, CatalogParseError> {
        if body.len() > MAX_CATALOG_BYTES {
            return Err(CatalogParseError::TooLarge);
        }
        let raw: HashMap<String, RawProvider> =
            serde_json::from_str(body).map_err(|_| CatalogParseError::Malformed)?;

        let mut entries = HashMap::new();
        for (provider_id, provider) in raw {
            for (model_id, model) in provider.models {
                let entry = match model.cost {
                    None => CatalogEntry::NoCost,
                    Some(cost) => match component_prices(&cost) {
                        Some(prices) => {
                            let (context_tier, unmodeled_pricing_rule) = parse_context_tier(&cost);
                            CatalogEntry::Priced {
                                prices: Box::new(prices),
                                context_tier,
                                unmodeled_pricing_rule,
                            }
                        }
                        None => CatalogEntry::Invalid,
                    },
                };
                entries.insert((provider_id.clone(), model_id), entry);
            }
        }
        Ok(Self {
            revision: revision.into(),
            entries,
        })
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// How many models this snapshot can price. Useful for health, and for
    /// noticing a body that parsed but carries nothing.
    #[must_use]
    pub fn priced_model_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| matches!(entry, CatalogEntry::Priced { .. }))
            .count()
    }

    /// Resolve the price for one attempt.
    ///
    /// Every failure is a distinct, stable reason. None of them is zero.
    #[must_use]
    pub fn resolve(
        &self,
        provider: ProviderKind,
        configured_model: Option<&str>,
    ) -> PriceResolution {
        let Some(catalog_provider) = catalog_provider_id(provider) else {
            return PriceResolution::ProviderMappingMissing;
        };
        // No model means nothing to look up; that is a missing mapping, not a
        // reason to fall back to some default price.
        let Some(model) = configured_model else {
            return PriceResolution::ModelMappingMissing;
        };
        let Some(entry) = self
            .entries
            .get(&(catalog_provider.to_owned(), model.to_owned()))
        else {
            return PriceResolution::ModelMappingMissing;
        };

        match entry {
            CatalogEntry::NoCost => PriceResolution::CostMissing,
            CatalogEntry::Invalid => PriceResolution::CatalogEntryInvalid,
            CatalogEntry::Priced {
                prices,
                context_tier,
                unmodeled_pricing_rule,
            } => {
                PriceResolution::Resolved(Box::new(InlinePriceRecord {
                    format_version: CATALOG_FORMAT_VERSION,
                    parser_version: CATALOG_PARSER_VERSION,
                    catalog_revision: self.revision.clone(),
                    catalog_provider_id: catalog_provider.to_owned(),
                    catalog_model_id: model.to_owned(),
                    mapping_revision: CATALOG_MAPPING_REVISION,
                    prices: **prices,
                    context_tier: *context_tier,
                    // No tier is ever *selected*: the document states two
                    // thresholds for the same model and they disagree, so picking
                    // one would be a guess. `unmodeled_pricing_rule` is what
                    // carries that forward, and it makes the cost partial.
                    selected_tier: None,
                    unmodeled_billable_component: false,
                    unmodeled_pricing_rule: *unmodeled_pricing_rule,
                }))
            }
        }
    }
}

/// Why a catalog body was rejected outright.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogParseError {
    TooLarge,
    Malformed,
}

/// Holds the current snapshot, if any, and prices attempts from it.
///
/// Before the first successful load there is no snapshot, and every attempt
/// resolves to `catalog_unavailable` — visibly missing rather than free.
#[derive(Default)]
pub struct CatalogPrices {
    snapshot: RwLock<Option<Arc<CatalogSnapshot>>>,
}

impl CatalogPrices {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the snapshot atomically.
    pub fn install(&self, snapshot: Arc<CatalogSnapshot>) {
        if let Ok(mut current) = self.snapshot.write() {
            *current = Some(snapshot);
        }
    }

    #[must_use]
    pub fn current(&self) -> Option<Arc<CatalogSnapshot>> {
        self.snapshot
            .read()
            .ok()
            .and_then(|current| current.clone())
    }
}

impl PriceResolver for CatalogPrices {
    fn resolve(&self, provider: ProviderKind, configured_model: Option<&str>) -> PriceResolution {
        match self.current() {
            Some(snapshot) => snapshot.resolve(provider, configured_model),
            None => PriceResolution::CatalogUnavailable,
        }
    }
}

#[derive(Deserialize)]
struct RawProvider {
    #[serde(default)]
    models: HashMap<String, RawModel>,
}

#[derive(Deserialize)]
struct RawModel {
    cost: Option<RawCost>,
}

/// Cost numbers are kept as raw JSON so their digits survive to
/// [`parse_unit_price`]. Unknown sibling fields are ignored: models.dev adds
/// fields over time and that must not invalidate a price.
///
/// The two tier encodings are read only to detect that a tier *exists*. They are
/// deliberately not interpreted: for `gpt-5.5` the document states
/// `tiers[].tier.size = 272000` and `context_over_200k` at the same time, so the
/// threshold itself is ambiguous and any single reading would be a guess.
#[derive(Deserialize)]
struct RawCost {
    input: Option<Box<RawValue>>,
    output: Option<Box<RawValue>>,
    reasoning: Option<Box<RawValue>>,
    cache_read: Option<Box<RawValue>>,
    cache_write: Option<Box<RawValue>>,
    input_audio: Option<Box<RawValue>>,
    output_audio: Option<Box<RawValue>>,
    tiers: Option<Box<RawValue>>,
    context_over_200k: Option<Box<RawValue>>,
}

impl RawCost {
    fn has_tier_rule(&self) -> bool {
        [self.tiers.as_deref(), self.context_over_200k.as_deref()]
            .into_iter()
            .flatten()
            .any(|raw| raw.get().trim() != "null")
    }
}

#[derive(Deserialize)]
struct RawTierCost {
    input: Option<Box<RawValue>>,
    output: Option<Box<RawValue>>,
    reasoning: Option<Box<RawValue>>,
    cache_read: Option<Box<RawValue>>,
    cache_write: Option<Box<RawValue>>,
    input_audio: Option<Box<RawValue>>,
    output_audio: Option<Box<RawValue>>,
    tier: RawTierSelector,
}

#[derive(Deserialize)]
struct RawTierSelector {
    #[serde(rename = "type")]
    kind: String,
    size: u64,
}

#[derive(Deserialize)]
struct RawContextCost {
    input: Option<Box<RawValue>>,
    output: Option<Box<RawValue>>,
    reasoning: Option<Box<RawValue>>,
    cache_read: Option<Box<RawValue>>,
    cache_write: Option<Box<RawValue>>,
    input_audio: Option<Box<RawValue>>,
    output_audio: Option<Box<RawValue>>,
}

fn parse_context_tier(cost: &RawCost) -> (Option<ContextPriceTier>, bool) {
    if !cost.has_tier_rule() {
        return (None, false);
    }

    let tier = cost.tiers.as_deref().and_then(|raw| {
        let tiers: Vec<RawTierCost> = serde_json::from_str(raw.get()).ok()?;
        let [tier] = tiers.as_slice() else {
            return None;
        };
        if tier.tier.kind != "context" {
            return None;
        }
        Some(ContextPriceTier {
            threshold_tokens: tier.tier.size,
            prices: component_prices_from_tier(tier)?,
        })
    });
    let legacy = cost.context_over_200k.as_deref().and_then(|raw| {
        let value: RawContextCost = serde_json::from_str(raw.get()).ok()?;
        Some(ContextPriceTier {
            threshold_tokens: 200_000,
            prices: component_prices_from_context(&value)?,
        })
    });

    match (tier, legacy) {
        (Some(tier), Some(legacy)) if tier == legacy => (Some(tier), false),
        (Some(tier), None) if cost.context_over_200k.is_none() => (Some(tier), false),
        (None, Some(legacy)) if cost.tiers.is_none() => (Some(legacy), false),
        _ => (None, true),
    }
}

fn component_prices_from_tier(cost: &RawTierCost) -> Option<ComponentPrices> {
    component_prices_from_fields(
        cost.input.as_deref(),
        cost.output.as_deref(),
        cost.reasoning.as_deref(),
        cost.cache_read.as_deref(),
        cost.cache_write.as_deref(),
        cost.input_audio.as_deref(),
        cost.output_audio.as_deref(),
    )
}

fn component_prices_from_context(cost: &RawContextCost) -> Option<ComponentPrices> {
    component_prices_from_fields(
        cost.input.as_deref(),
        cost.output.as_deref(),
        cost.reasoning.as_deref(),
        cost.cache_read.as_deref(),
        cost.cache_write.as_deref(),
        cost.input_audio.as_deref(),
        cost.output_audio.as_deref(),
    )
}

/// Convert a cost block, or `None` if any present value is unreadable.
///
/// An absent component is simply not priced; a *present but unreadable* one makes
/// the whole entry invalid, because silently ignoring it would under-report cost
/// while still looking complete.
fn component_prices(cost: &RawCost) -> Option<ComponentPrices> {
    component_prices_from_fields(
        cost.input.as_deref(),
        cost.output.as_deref(),
        cost.reasoning.as_deref(),
        cost.cache_read.as_deref(),
        cost.cache_write.as_deref(),
        cost.input_audio.as_deref(),
        cost.output_audio.as_deref(),
    )
}

fn component_prices_from_fields(
    input: Option<&RawValue>,
    output: Option<&RawValue>,
    reasoning: Option<&RawValue>,
    cache_read: Option<&RawValue>,
    cache_write: Option<&RawValue>,
    input_audio: Option<&RawValue>,
    output_audio: Option<&RawValue>,
) -> Option<ComponentPrices> {
    Some(ComponentPrices {
        // models.dev `input` is the standard, uncached input rate; `cache_read`
        // is the discounted rate for the cached portion.
        uncached_input_per_million: optional_price(input)?,
        cache_read_per_million: optional_price(cache_read)?,
        cache_write_per_million: optional_price(cache_write)?,
        output_per_million: optional_price(output)?,
        reasoning_per_million: optional_price(reasoning)?,
        input_audio_per_million: optional_price(input_audio)?,
        output_audio_per_million: optional_price(output_audio)?,
    })
}

/// `Some(None)` for an absent component, `None` for one that is present but
/// unreadable.
fn optional_price(raw: Option<&RawValue>) -> Option<Option<UnitPrice>> {
    match raw {
        None => Some(None),
        Some(raw) => {
            let text = raw.get();
            // An explicit JSON null is the same as absent.
            if text == "null" {
                return Some(None);
            }
            parse_unit_price(text).map(Some)
        }
    }
}

/// Largest accepted length of a price literal, so a pathological number cannot
/// drive the digit loop.
const MAX_PRICE_LITERAL: usize = 32;

/// Parse a decimal price in USD per million tokens into an exact scaled integer.
///
/// Deliberately strict, because the alternative to rejecting a value is silently
/// charging a different one:
///
/// * plain decimal notation only — exponents are refused rather than guessed at;
/// * at most [`PRICE_SCALE`] fractional digits, so nothing is rounded away;
/// * no negative prices.
#[must_use]
pub fn parse_unit_price(text: &str) -> Option<UnitPrice> {
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_PRICE_LITERAL {
        return None;
    }
    let (integer, fraction) = match text.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (text, ""),
    };
    if integer.is_empty() && fraction.is_empty() {
        return None;
    }
    // A digits-only check also rules out `-`, `+`, `e`, `E`, `NaN` and whitespace.
    if !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let scale = PRICE_SCALE as usize;
    if fraction.len() > scale {
        // More precision than the fixed point can hold. Truncating here would
        // quietly change every cost computed from this price.
        return None;
    }

    let mut scaled: i128 = 0;
    for byte in integer.bytes().chain(fraction.bytes()) {
        scaled = scaled
            .checked_mul(10)?
            .checked_add(i128::from(byte - b'0'))?;
    }
    // Left-align the fraction to the fixed scale.
    for _ in 0..(scale - fraction.len()) {
        scaled = scaled.checked_mul(10)?;
    }
    Some(UnitPrice::from_scaled(scaled))
}

#[cfg(test)]
mod tests {
    use provider_core::usage::{
        CacheCapability, CacheEligibility, CacheReportingExpectation, PricingContextBasis,
        PricingMode, RawUsageFields, TokenInclusionRules, TotalSource, UsageContractSnapshot,
        normalize_usage,
    };

    use super::*;
    use crate::cost::{CostReason, CostStatus, compute_observed_catalog_cost};

    const PER_MILLION: i128 = 10i128.pow(PRICE_SCALE);

    /// Shaped like the real `https://models.dev/api.json`: a provider map, each
    /// with a model map, each model optionally carrying a `cost` block in USD per
    /// million tokens. Prices here are illustrative, not a price source.
    const CATALOG: &str = r#"{
      "openai": {
        "id": "openai",
        "name": "OpenAI",
        "models": {
          "gpt-5-codex": {
            "id": "gpt-5-codex",
            "name": "GPT-5 Codex",
            "cost": {
              "input": 1.25,
              "output": 10,
              "cache_read": 0.125,
              "reasoning": 0.075
            },
            "limit": { "context": 400000 }
          },
          "listed-without-cost": {
            "id": "listed-without-cost",
            "name": "No Cost"
          },
          "unreadable-cost": {
            "id": "unreadable-cost",
            "cost": { "input": 1.2e-3, "output": 1 }
          },
          "tiered": {
            "id": "tiered",
            "cost": {
              "input": 5,
              "output": 30,
              "cache_read": 0.5,
              "tiers": [
                { "input": 10, "output": 45, "cache_read": 1,
                  "tier": { "type": "context", "size": 272000 } }
              ],
              "context_over_200k": { "input": 10, "output": 45, "cache_read": 1 }
            }
          },
          "consistent-tier": {
            "id": "consistent-tier",
            "cost": {
              "input": 2,
              "output": 6,
              "cache_read": 0.3,
              "tiers": [
                { "input": 4, "output": 12, "cache_read": 0.6,
                  "tier": { "type": "context", "size": 200000 } }
              ],
              "context_over_200k": { "input": 4, "output": 12, "cache_read": 0.6 }
            }
          }
        }
      },
      "anthropic": {
        "id": "anthropic",
        "models": {
          "claude-4": { "id": "claude-4", "cost": { "input": 3, "output": 15 } }
        }
      }
    }"#;

    fn snapshot() -> CatalogSnapshot {
        CatalogSnapshot::parse(CATALOG, "r".repeat(64)).expect("catalog parses")
    }

    /// Enough of a contract to run the cost calculator: input already includes
    /// cache, reasoning sits inside output, no audio.
    fn codex_like_contract() -> UsageContractSnapshot {
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

    #[test]
    fn plain_decimals_become_exact_scaled_integers() {
        // The whole point: no value here may pass through a float.
        assert_eq!(
            parse_unit_price("1.25"),
            Some(UnitPrice::from_scaled(125 * PER_MILLION / 100))
        );
        assert_eq!(
            parse_unit_price("10"),
            Some(UnitPrice::from_scaled(10 * PER_MILLION))
        );
        assert_eq!(parse_unit_price("0"), Some(UnitPrice::from_scaled(0)));
        // 0.075 is not representable in binary floating point, so a float route
        // would land a tick off; the exact answer is 7_500_000 at scale 8.
        assert_eq!(
            parse_unit_price("0.075"),
            Some(UnitPrice::from_scaled(7_500_000))
        );
        assert_eq!(
            parse_unit_price("0.1"),
            Some(UnitPrice::from_scaled(10_000_000))
        );
        // Exactly at the representable precision.
        assert_eq!(
            parse_unit_price("0.00000001"),
            Some(UnitPrice::from_scaled(1))
        );
    }

    #[test]
    fn a_tiered_model_keeps_its_base_price_but_never_reads_as_complete() {
        // The real document does this for `gpt-5.5`, which is a default Codex
        // model: base rates plus a higher tier above some context threshold. The
        // base rates are exact below it, so they are kept — but a cost computed
        // from them is a floor, and presenting it as complete under-reports every
        // long-context request by roughly half.
        let record = snapshot()
            .resolve(ProviderKind::Codex, Some("tiered"))
            .resolved()
            .expect("the base rates are still usable")
            .clone();
        assert_eq!(
            record.prices.uncached_input_per_million,
            Some(UnitPrice::from_scaled(5 * PER_MILLION)),
            "the base rate is what the document states, unrounded"
        );
        assert!(record.unmodeled_pricing_rule);
        assert_eq!(
            record.selected_tier, None,
            "the document states two disagreeing thresholds, so no tier is chosen"
        );

        // What a caller actually sees: the amount is there, and its status says it
        // cannot be trusted as the whole bill.
        let contract = codex_like_contract();
        let observation = normalize_usage(
            // One million uncached input tokens, nothing else, so the amount below
            // is the input rate itself and any drift is visible in one digit.
            Some(RawUsageFields {
                input: Some(1_000_000),
                cache_read: Some(0),
                output: Some(0),
                ..RawUsageFields::default()
            }),
            &contract,
        );
        let cost = compute_observed_catalog_cost(
            &observation,
            &contract,
            &snapshot().resolve(ProviderKind::Codex, Some("tiered")),
        );
        assert_eq!(cost.total_known.to_decimal_string(), "5.00000000000000");
        assert_eq!(cost.status, CostStatus::Partial);
        assert!(cost.reasons.contains(&CostReason::PricingRuleUnsupported));

        // The same path on an untiered model must still read as complete, or the
        // marker would be worthless noise on every model.
        let untiered = compute_observed_catalog_cost(
            &observation,
            &contract,
            &snapshot().resolve(ProviderKind::Codex, Some("gpt-5-codex")),
        );
        assert_eq!(
            untiered.status,
            CostStatus::CompleteForObservedCatalogComponents
        );
    }

    #[test]
    fn an_explicit_consistent_context_tier_is_selected_from_observed_tokens() {
        let resolution = snapshot().resolve(ProviderKind::Codex, Some("consistent-tier"));
        let record = resolution.resolved().expect("tiered price resolves");
        assert_eq!(
            record.context_tier,
            Some(ContextPriceTier {
                threshold_tokens: 200_000,
                prices: ComponentPrices {
                    uncached_input_per_million: Some(UnitPrice::from_scaled(4 * PER_MILLION)),
                    cache_read_per_million: Some(UnitPrice::from_scaled(6 * PER_MILLION / 10)),
                    output_per_million: Some(UnitPrice::from_scaled(12 * PER_MILLION)),
                    ..ComponentPrices::default()
                },
            })
        );
        assert!(!record.unmodeled_pricing_rule);

        let contract = codex_like_contract();
        let below = normalize_usage(
            Some(RawUsageFields {
                input: Some(200_000),
                cache_read: Some(0),
                output: Some(0),
                ..RawUsageFields::default()
            }),
            &contract,
        );
        let above = normalize_usage(
            Some(RawUsageFields {
                input: Some(200_001),
                cache_read: Some(0),
                output: Some(0),
                ..RawUsageFields::default()
            }),
            &contract,
        );
        let below_cost = compute_observed_catalog_cost(&below, &contract, &resolution);
        let above_cost = compute_observed_catalog_cost(&above, &contract, &resolution);
        assert_eq!(
            below_cost.status,
            CostStatus::CompleteForObservedCatalogComponents
        );
        assert_eq!(
            above_cost.status,
            CostStatus::CompleteForObservedCatalogComponents
        );
        assert_eq!(
            below_cost.total_known.to_decimal_string(),
            "0.40000000000000"
        );
        assert_eq!(
            above_cost.total_known.to_decimal_string(),
            "0.80000400000000"
        );
    }

    #[test]
    fn a_price_that_cannot_be_held_exactly_is_refused_not_rounded() {
        // Nine fractional digits would have to be truncated, changing every cost
        // computed from it.
        assert_eq!(parse_unit_price("0.000000001"), None);
        // Exponent notation is legal JSON but its intent is not guessed at.
        assert_eq!(parse_unit_price("1.2e-3"), None);
        assert_eq!(parse_unit_price("1E6"), None);
        // A negative price is not a price.
        assert_eq!(parse_unit_price("-1.0"), None);
        assert_eq!(parse_unit_price("+1.0"), None);
        assert_eq!(parse_unit_price("NaN"), None);
        assert_eq!(parse_unit_price("Infinity"), None);
        assert_eq!(parse_unit_price(""), None);
        assert_eq!(parse_unit_price("."), None);
        assert_eq!(parse_unit_price("1.2.3"), None);
        assert_eq!(parse_unit_price("\"1.25\""), None);
        // Absurdly long input never reaches the digit loop.
        assert_eq!(parse_unit_price(&"9".repeat(64)), None);
    }

    #[test]
    fn model_ids_are_not_shared_across_providers() {
        // `claude-4` exists in the document, but under anthropic. Codex must not
        // reach it, or a mapping mistake would silently price against the wrong
        // provider's rates.
        let snapshot = snapshot();
        assert_eq!(
            snapshot.resolve(ProviderKind::Codex, Some("claude-4")),
            PriceResolution::ModelMappingMissing
        );
        // Six models are listed; `listed-without-cost` and `unreadable-cost`
        // carry no price the parser accepted.
        assert_eq!(snapshot.priced_model_count(), 4);
    }
}
