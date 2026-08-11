//! The models.dev price catalog: parsing and exact model-price lookup.
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
//! 2. **Mapping is exact, never guessed.** A model with no accepted exact-ID
//!    entry remains unpriced when provider models are refreshed.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use provider_core::{
    ProviderModelInputModality, ProviderModelPricing, ProviderModelPricingCatalog,
    ProviderModelPricingTier,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::{
    money::{PRICE_SCALE, UnitPrice},
    price::{ComponentPrices, ContextPriceTier},
};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Largest catalog body accepted, before parsing. The real document is a couple
/// of megabytes; this bounds what an unexpected response can cost us.
pub const MAX_CATALOG_BYTES: usize = 16 * 1024 * 1024;

/// What the catalog says about one model.
///
/// The prices are boxed because there is one entry per model in the whole
/// document and most carry no price: sizing every entry for the largest variant
/// would waste most of the map.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogEntry {
    pricing: CatalogPricing,
    input_modalities: Option<Vec<ProviderModelInputModality>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CatalogPricing {
    Priced {
        prices: Box<ComponentPrices>,
        model_tiers: Vec<ProviderModelPricingTier>,
    },
    /// The entry exists but carries no `cost` at all.
    NoCost,
    /// The entry has a cost that could not be read exactly.
    Invalid,
}

/// An immutable view of the catalog. Swapped as a whole, so provider model
/// refreshes can never observe a half-applied catalog revision.
#[derive(Debug)]
pub struct CatalogSnapshot {
    revision: String,
    entries: HashMap<(String, String), CatalogEntry>,
}

impl CatalogSnapshot {
    /// Parse a catalog body. `revision` is the content hash stored alongside it.
    pub fn parse(body: &str, revision: impl Into<String>) -> Result<Self, CatalogParseError> {
        if body.len() > MAX_CATALOG_BYTES {
            return Err(CatalogParseError::TooLarge);
        }
        let raw: HashMap<String, RawProvider> =
            serde_json::from_str(body).map_err(|_| CatalogParseError::Malformed)?;

        let mut entries = HashMap::new();
        for (provider_id, provider) in raw {
            for (model_id, model) in provider.models {
                let pricing = match model.cost {
                    None => CatalogPricing::NoCost,
                    Some(cost) => match (component_prices(&cost), parse_model_pricing_tiers(&cost))
                    {
                        (Some(prices), Some(model_tiers)) => CatalogPricing::Priced {
                            prices: Box::new(prices),
                            model_tiers,
                        },
                        _ => CatalogPricing::Invalid,
                    },
                };
                let entry = CatalogEntry {
                    pricing,
                    input_modalities: input_modalities(model.modalities),
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
            .filter(|entry| matches!(&entry.pricing, CatalogPricing::Priced { .. }))
            .count()
    }

    #[must_use]
    pub fn exact_model_pricing(&self, model: &str) -> Option<ProviderModelPricing> {
        if let Some(provider) = official_catalog_provider(model)
            && let Some(entry) = self.entries.get(&(provider.to_owned(), model.to_owned()))
        {
            return model_pricing_from_entry(entry);
        }

        let mut candidate: Option<ProviderModelPricing> = None;
        for ((_, model_id), entry) in &self.entries {
            if model_id != model {
                continue;
            }
            let pricing = model_pricing_from_entry(entry)?;
            match candidate.as_ref() {
                Some(current) if current != &pricing => return None,
                Some(_) => {}
                None => candidate = Some(pricing),
            }
        }
        candidate
    }

    #[must_use]
    pub fn exact_model_input_modalities(
        &self,
        model: &str,
    ) -> Option<Vec<ProviderModelInputModality>> {
        if let Some(provider) = official_catalog_provider(model)
            && let Some(entry) = self.entries.get(&(provider.to_owned(), model.to_owned()))
        {
            return entry.input_modalities.clone();
        }

        let mut candidate: Option<Option<Vec<ProviderModelInputModality>>> = None;
        for ((_, model_id), entry) in &self.entries {
            if model_id != model {
                continue;
            }
            match candidate.as_ref() {
                Some(current) if current != &entry.input_modalities => return None,
                Some(_) => {}
                None => candidate = Some(entry.input_modalities.clone()),
            }
        }
        candidate.flatten()
    }
}

fn model_pricing_from_entry(entry: &CatalogEntry) -> Option<ProviderModelPricing> {
    match &entry.pricing {
        CatalogPricing::Priced {
            prices,
            model_tiers,
            ..
        } => {
            let mut pricing = model_pricing_from_components(**prices);
            pricing.tiers = model_tiers.clone();
            Some(pricing)
        }
        CatalogPricing::NoCost | CatalogPricing::Invalid => None,
    }
}

fn input_modalities(modalities: Option<Box<RawValue>>) -> Option<Vec<ProviderModelInputModality>> {
    let input = serde_json::from_str::<RawModalities>(modalities?.get())
        .ok()?
        .input;
    provider_core::validate_input_modalities(Some(&input)).ok()?;
    Some(input)
}

fn official_catalog_provider(model: &str) -> Option<&'static str> {
    if model.starts_with("grok-") {
        Some("xai")
    } else if model.starts_with("qwen") {
        Some("alibaba")
    } else if model.starts_with("gpt-")
        || model.starts_with("chatgpt-")
        || model.starts_with("codex-")
        || matches!(model, "o1" | "o3" | "o4-mini")
        || model.starts_with("o1-")
        || model.starts_with("o3-")
        || model.starts_with("o4-")
    {
        Some("openai")
    } else if model.starts_with("claude-") {
        Some("anthropic")
    } else if model.starts_with("gemini-") || model.starts_with("gemma-") {
        Some("google")
    } else if model.starts_with("deepseek-") {
        Some("deepseek")
    } else if model.starts_with("kimi-") {
        Some("moonshotai")
    } else if model.starts_with("minimax-") || model.starts_with("MiniMax-") {
        Some("minimax")
    } else if model.starts_with("glm-") {
        Some("zhipuai")
    } else if model.starts_with("mistral-")
        || model.starts_with("codestral-")
        || model.starts_with("devstral-")
        || model.starts_with("magistral-")
        || model.starts_with("ministral-")
        || model.starts_with("pixtral-")
        || model.starts_with("open-mistral-")
        || model.starts_with("open-mixtral-")
    {
        Some("mistral")
    } else if model.starts_with("command-") || model.starts_with("c4ai-aya-") {
        Some("cohere")
    } else if model.starts_with("amazon.") {
        Some("amazon-bedrock")
    } else {
        None
    }
}

/// Why a catalog body was rejected outright.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogParseError {
    TooLarge,
    Malformed,
}

/// Holds the current snapshot used when provider models are refreshed.
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

impl ProviderModelPricingCatalog for CatalogPrices {
    fn exact_pricing(&self, upstream_model: &str) -> Option<ProviderModelPricing> {
        self.current()?.exact_model_pricing(upstream_model)
    }

    fn exact_input_modalities(
        &self,
        upstream_model: &str,
    ) -> Option<Vec<ProviderModelInputModality>> {
        self.current()?.exact_model_input_modalities(upstream_model)
    }
}

#[must_use]
pub fn component_prices_from_model_pricing(
    pricing: &ProviderModelPricing,
) -> Option<ComponentPrices> {
    if pricing.is_empty() {
        return None;
    }
    Some(ComponentPrices {
        uncached_input_per_million: parse_optional_price(pricing.input.as_deref())?,
        output_per_million: parse_optional_price(pricing.output.as_deref())?,
        cache_read_per_million: parse_optional_price(pricing.cache_read.as_deref())?,
        cache_write_per_million: parse_optional_price(pricing.cache_write.as_deref())?,
        reasoning_per_million: parse_optional_price(pricing.reasoning.as_deref())?,
        input_audio_per_million: parse_optional_price(pricing.input_audio.as_deref())?,
        output_audio_per_million: parse_optional_price(pricing.output_audio.as_deref())?,
    })
}

#[must_use]
pub fn context_price_tiers_from_model_pricing(
    pricing: &ProviderModelPricing,
) -> Option<Vec<ContextPriceTier>> {
    let mut previous_threshold = None;
    let mut tiers = Vec::with_capacity(pricing.tiers.len());
    for tier in &pricing.tiers {
        if tier.threshold_tokens > MAX_SAFE_INTEGER {
            return None;
        }
        if previous_threshold.is_some_and(|previous| tier.threshold_tokens <= previous) {
            return None;
        }
        let prices = component_prices_from_model_tier(tier)?;
        tiers.push(ContextPriceTier {
            threshold_tokens: tier.threshold_tokens,
            prices,
        });
        previous_threshold = Some(tier.threshold_tokens);
    }
    Some(tiers)
}

fn component_prices_from_model_tier(tier: &ProviderModelPricingTier) -> Option<ComponentPrices> {
    let pricing = ProviderModelPricing {
        input: tier.input.clone(),
        output: tier.output.clone(),
        cache_read: tier.cache_read.clone(),
        cache_write: tier.cache_write.clone(),
        reasoning: tier.reasoning.clone(),
        input_audio: tier.input_audio.clone(),
        output_audio: tier.output_audio.clone(),
        tiers: Vec::new(),
    };
    component_prices_from_model_pricing(&pricing)
}

#[must_use]
pub fn canonical_model_pricing(pricing: &ProviderModelPricing) -> Option<ProviderModelPricing> {
    let prices = component_prices_from_model_pricing(pricing)?;
    let tiers = context_price_tiers_from_model_pricing(pricing)?;
    let mut canonical = model_pricing_from_components(prices);
    canonical.tiers = tiers
        .into_iter()
        .map(|tier| ProviderModelPricingTier {
            threshold_tokens: tier.threshold_tokens,
            input: decimal_price(tier.prices.uncached_input_per_million),
            output: decimal_price(tier.prices.output_per_million),
            cache_read: decimal_price(tier.prices.cache_read_per_million),
            cache_write: decimal_price(tier.prices.cache_write_per_million),
            reasoning: decimal_price(tier.prices.reasoning_per_million),
            input_audio: decimal_price(tier.prices.input_audio_per_million),
            output_audio: decimal_price(tier.prices.output_audio_per_million),
        })
        .collect();
    Some(canonical)
}

fn parse_optional_price(value: Option<&str>) -> Option<Option<UnitPrice>> {
    match value {
        None => Some(None),
        Some(value) => parse_unit_price(value).map(Some),
    }
}

fn model_pricing_from_components(prices: ComponentPrices) -> ProviderModelPricing {
    ProviderModelPricing {
        input: decimal_price(prices.uncached_input_per_million),
        output: decimal_price(prices.output_per_million),
        cache_read: decimal_price(prices.cache_read_per_million),
        cache_write: decimal_price(prices.cache_write_per_million),
        reasoning: decimal_price(prices.reasoning_per_million),
        input_audio: decimal_price(prices.input_audio_per_million),
        output_audio: decimal_price(prices.output_audio_per_million),
        tiers: Vec::new(),
    }
}

fn decimal_price(price: Option<UnitPrice>) -> Option<String> {
    price.map(UnitPrice::to_decimal_string)
}

#[derive(Deserialize)]
struct RawProvider {
    #[serde(default)]
    models: HashMap<String, RawModel>,
}

#[derive(Deserialize)]
struct RawModel {
    cost: Option<RawCost>,
    modalities: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
struct RawModalities {
    input: Vec<ProviderModelInputModality>,
}

/// Cost numbers are kept as raw JSON so their digits survive to
/// [`parse_unit_price`]. Unknown sibling fields are ignored: models.dev adds
/// fields over time and that must not invalidate a price.
///
/// Both supported context-tier encodings are parsed strictly for saved model
/// pricing. The explicit `tiers` encoding wins over the legacy
/// `context_over_200k` block when they differ.
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

fn parse_model_pricing_tiers(cost: &RawCost) -> Option<Vec<ProviderModelPricingTier>> {
    let tiers = match cost.tiers.as_deref() {
        None => None,
        Some(raw) if raw.get().trim() == "null" => None,
        Some(raw) => {
            let raw_tiers = serde_json::from_str::<Vec<RawTierCost>>(raw.get()).ok()?;
            let mut tiers = Vec::with_capacity(raw_tiers.len());
            for tier in &raw_tiers {
                if tier.tier.kind != "context" {
                    return None;
                }
                let prices = component_prices_from_tier(tier)?;
                if prices == ComponentPrices::default() {
                    return None;
                }
                tiers.push(model_pricing_tier(tier.tier.size, prices));
            }
            tiers.sort_by_key(|tier| tier.threshold_tokens);
            if tiers
                .windows(2)
                .any(|pair| pair[0].threshold_tokens == pair[1].threshold_tokens)
            {
                return None;
            }
            Some(tiers)
        }
    };

    if let Some(tiers) = tiers {
        return Some(tiers);
    }

    let legacy = match cost.context_over_200k.as_deref() {
        None => None,
        Some(raw) if raw.get().trim() == "null" => None,
        Some(raw) => {
            let tier = serde_json::from_str::<RawContextCost>(raw.get()).ok()?;
            let prices = component_prices_from_context(&tier)?;
            if prices == ComponentPrices::default() {
                return None;
            }
            Some(vec![model_pricing_tier(200_000, prices)])
        }
    };

    // The explicit `tiers` encoding is authoritative whenever it is present;
    // `context_over_200k` is the legacy form models.dev keeps alongside it. A
    // difference between the two (for example a 272k tier next to the old 200k
    // block) must not drop a real price, so the explicit encoding wins instead
    // of invalidating the entry.
    Some(legacy.unwrap_or_default())
}

fn model_pricing_tier(threshold_tokens: u64, prices: ComponentPrices) -> ProviderModelPricingTier {
    ProviderModelPricingTier {
        threshold_tokens,
        input: decimal_price(prices.uncached_input_per_million),
        output: decimal_price(prices.output_per_million),
        cache_read: decimal_price(prices.cache_read_per_million),
        cache_write: decimal_price(prices.cache_write_per_million),
        reasoning: decimal_price(prices.reasoning_per_million),
        input_audio: decimal_price(prices.input_audio_per_million),
        output_audio: decimal_price(prices.output_audio_per_million),
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
    use super::*;

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

    #[test]
    fn input_modalities_are_preserved_independently_from_pricing() {
        let snapshot = CatalogSnapshot::parse(
            r#"{
              "openai": {
                "models": {
                  "gpt-image": {
                    "modalities": {"input": ["video", "text", "pdf", "image", "audio"]},
                    "cost": {"input": "invalid"}
                  },
                  "gpt-audio": {
                    "modalities": {"input": ["audio"]}
                  },
                  "gpt-empty": {
                    "modalities": {"input": []},
                    "cost": {"input": 1, "output": 2}
                  },
                  "gpt-duplicate": {
                    "modalities": {"input": ["text", "text"]},
                    "cost": {"input": 1, "output": 2}
                  },
                  "gpt-unknown": {
                    "modalities": {"input": ["text", "future"]},
                    "cost": {"input": 1, "output": 2}
                  },
                  "gpt-invalid-modalities": {
                    "modalities": {"input": "text"},
                    "cost": {"input": 1, "output": 2}
                  }
                }
              }
            }"#,
            "modalities",
        )
        .expect("invalid modality data does not invalidate prices");

        assert_eq!(
            snapshot.exact_model_input_modalities("gpt-image"),
            Some(vec![
                ProviderModelInputModality::Video,
                ProviderModelInputModality::Text,
                ProviderModelInputModality::Pdf,
                ProviderModelInputModality::Image,
                ProviderModelInputModality::Audio,
            ])
        );
        assert_eq!(snapshot.exact_model_pricing("gpt-image"), None);
        assert_eq!(
            snapshot.exact_model_input_modalities("gpt-audio"),
            Some(vec![ProviderModelInputModality::Audio])
        );
        assert_eq!(snapshot.exact_model_input_modalities("gpt-empty"), None);
        assert!(snapshot.exact_model_pricing("gpt-empty").is_some());
        assert_eq!(snapshot.exact_model_input_modalities("gpt-duplicate"), None);
        assert!(snapshot.exact_model_pricing("gpt-duplicate").is_some());
        assert_eq!(snapshot.exact_model_input_modalities("gpt-unknown"), None);
        assert!(snapshot.exact_model_pricing("gpt-unknown").is_some());
        assert_eq!(
            snapshot.exact_model_input_modalities("gpt-invalid-modalities"),
            None
        );
        assert!(
            snapshot
                .exact_model_pricing("gpt-invalid-modalities")
                .is_some()
        );
    }

    #[test]
    fn modality_lookup_uses_the_same_exact_match_rules_as_pricing() {
        let snapshot = CatalogSnapshot::parse(
            r#"{
              "openai": {"models": {
                "gpt-shared": {"modalities": {"input": ["text", "image"]}},
                "shared": {"modalities": {"input": ["text"]}}
              }},
              "gateway": {"models": {
                "gpt-shared": {"modalities": {"input": ["text"]}},
                "shared": {"modalities": {"input": ["text"]}},
                "conflict": {"modalities": {"input": ["text"]}}
              }},
              "other": {"models": {
                "conflict": {"modalities": {"input": ["text", "image"]}}
              }}
            }"#,
            "matching",
        )
        .expect("catalog parses");

        assert_eq!(
            snapshot.exact_model_input_modalities("gpt-shared"),
            Some(vec![
                ProviderModelInputModality::Text,
                ProviderModelInputModality::Image,
            ]),
            "the official provider wins for an official model ID"
        );
        assert_eq!(
            snapshot.exact_model_input_modalities("shared"),
            Some(vec![ProviderModelInputModality::Text]),
            "identical cross-provider entries are unambiguous"
        );
        assert_eq!(
            snapshot.exact_model_input_modalities("conflict"),
            None,
            "conflicting cross-provider entries are not guessed"
        );
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
    fn explicit_tiers_win_over_the_legacy_context_tier() {
        let snapshot = snapshot();
        let model_pricing = snapshot
            .exact_model_pricing("tiered")
            .expect("explicit tiers are used even when the legacy context tier differs");
        assert_eq!(model_pricing.tiers.len(), 1);
        assert_eq!(model_pricing.tiers[0].threshold_tokens, 272_000);
    }

    #[test]
    fn explicit_tiers_ignore_an_unreadable_legacy_context_tier() {
        let snapshot = CatalogSnapshot::parse(
            r#"{
              "openai": {
                "models": {
                  "explicit-tier": {
                    "cost": {
                      "input": 2,
                      "output": 6,
                      "tiers": [
                        { "input": 4, "output": 12, "tier": { "type": "context", "size": 272000 } }
                      ],
                      "context_over_200k": { "input": "unreadable" }
                    }
                  }
                }
              }
            }"#,
            "explicit",
        )
        .expect("catalog parses");
        let model_pricing = snapshot
            .exact_model_pricing("explicit-tier")
            .expect("valid explicit tiers do not depend on the legacy encoding");
        assert_eq!(model_pricing.tiers.len(), 1);
        assert_eq!(model_pricing.tiers[0].threshold_tokens, 272_000);
    }

    #[test]
    fn legacy_context_tier_is_kept_when_there_are_no_explicit_tiers() {
        let snapshot = CatalogSnapshot::parse(
            r#"{
              "openai": {
                "models": {
                  "legacy-tier": {
                    "cost": {
                      "input": 2,
                      "output": 6,
                      "context_over_200k": { "input": 4, "output": 12, "cache_read": 0.6 }
                    }
                  }
                }
              }
            }"#,
            "legacy",
        )
        .expect("legacy-only catalog parses");
        let model_pricing = snapshot
            .exact_model_pricing("legacy-tier")
            .expect("legacy context tier is used without explicit tiers");
        assert_eq!(model_pricing.tiers.len(), 1);
        assert_eq!(model_pricing.tiers[0].threshold_tokens, 200_000);
    }

    #[test]
    fn consistent_context_tier_is_saved_with_model_pricing() {
        let model_pricing = snapshot()
            .exact_model_pricing("consistent-tier")
            .expect("consistent tier is saved with model pricing");
        assert_eq!(model_pricing.tiers.len(), 1);
        assert_eq!(model_pricing.tiers[0].threshold_tokens, 200_000);
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
    fn exact_model_ids_remain_case_sensitive() {
        let snapshot = snapshot();
        assert!(snapshot.exact_model_pricing("claude-4").is_some());
        assert_eq!(snapshot.exact_model_pricing("Claude-4"), None);
        // Six models are listed; missing and unreadable costs carry no price the
        // parser accepted. The tiered model is priced from its explicit tiers.
        assert_eq!(snapshot.priced_model_count(), 4);
    }

    #[test]
    fn exact_model_pricing_accepts_identical_candidates_and_rejects_conflicts() {
        let identical = CatalogSnapshot::parse(
            r#"{
              "one":{"models":{"shared/model":{"cost":{"input":1,"output":2,
                "tiers":[{"input":2,"output":4,"tier":{"type":"context","size":200000}}]}}}},
              "two":{"models":{"shared/model":{"cost":{"input":1,"output":2,
                "tiers":[{"input":2,"output":4,"tier":{"type":"context","size":200000}}]}}}}
            }"#,
            "identical",
        )
        .expect("identical catalog parses")
        .exact_model_pricing("shared/model")
        .expect("identical complete prices are usable");
        assert_eq!(identical.input.as_deref(), Some("1.00000000"));
        assert_eq!(identical.output.as_deref(), Some("2.00000000"));
        assert_eq!(identical.tiers.len(), 1);

        let conflicting = CatalogSnapshot::parse(
            r#"{
              "one":{"models":{"shared/model":{"cost":{"input":1,"output":2}}}},
              "two":{"models":{"shared/model":{"cost":{"input":1,"output":3}}}}
            }"#,
            "conflicting",
        )
        .expect("conflicting catalog parses");
        assert_eq!(conflicting.exact_model_pricing("shared/model"), None);
        assert_eq!(conflicting.exact_model_pricing("Shared/model"), None);

        let conflicting_tiers = CatalogSnapshot::parse(
            r#"{
              "one":{"models":{"shared/model":{"cost":{"input":1,"output":2}}}},
              "two":{"models":{"shared/model":{"cost":{"input":1,"output":2,
                "tiers":[{"input":2,"output":4,"tier":{"type":"context","size":200000}}]}}}}
            }"#,
            "conflicting-tiers",
        )
        .expect("catalog parses");
        assert_eq!(conflicting_tiers.exact_model_pricing("shared/model"), None);

        let official = CatalogSnapshot::parse(
            r#"{
              "reseller":{"models":{"grok-4.5":{"cost":{"input":2,"output":6,"cache_read":0.5}}}},
              "xai":{"models":{"grok-4.5":{"cost":{"input":2,"output":6,"cache_read":0.3,
                "tiers":[{"input":4,"output":12,"cache_read":0.6,"tier":{"type":"context","size":200000}}]}}}}
            }"#,
            "official",
        )
        .expect("official catalog parses")
        .exact_model_pricing("grok-4.5")
        .expect("official provider wins conflicting exact-id prices");
        assert_eq!(official.cache_read.as_deref(), Some("0.30000000"));
        assert_eq!(official.tiers.len(), 1);
        assert_eq!(official.tiers[0].threshold_tokens, 200_000);
        assert_eq!(official.tiers[0].cache_read.as_deref(), Some("0.60000000"));

        let mistral = CatalogSnapshot::parse(
            r#"{
              "reseller":{"models":{"mistral-large-latest":{"cost":{"input":9,"output":18}}}},
              "mistral":{"models":{"mistral-large-latest":{"cost":{"input":2,"output":6}}}}
            }"#,
            "mistral-official",
        )
        .expect("Mistral catalog parses")
        .exact_model_pricing("mistral-large-latest")
        .expect("verified Mistral provider wins conflicting exact-id prices");
        assert_eq!(mistral.input.as_deref(), Some("2.00000000"));
        assert_eq!(mistral.output.as_deref(), Some("6.00000000"));

        let duplicate_tier = CatalogSnapshot::parse(
            r#"{
              "xai":{"models":{"grok-4.5":{"cost":{"input":2,"output":6,
                "tiers":[
                  {"input":4,"output":12,"tier":{"type":"context","size":200000}},
                  {"input":5,"output":15,"tier":{"type":"context","size":200000}}
                ]}}}}
            }"#,
            "duplicate-tier",
        )
        .expect("catalog document parses");
        assert_eq!(duplicate_tier.exact_model_pricing("grok-4.5"), None);
    }

    #[test]
    fn canonical_manual_pricing_preserves_and_validates_context_tiers() {
        let pricing = ProviderModelPricing {
            input: Some("1.5".to_owned()),
            output: Some("2".to_owned()),
            cache_read: None,
            cache_write: None,
            reasoning: None,
            input_audio: None,
            output_audio: None,
            tiers: vec![ProviderModelPricingTier {
                threshold_tokens: 200_000,
                input: Some("3".to_owned()),
                output: Some("4.25".to_owned()),
                cache_read: None,
                cache_write: None,
                reasoning: None,
                input_audio: None,
                output_audio: None,
            }],
        };

        let canonical = canonical_model_pricing(&pricing).expect("valid pricing");
        assert_eq!(canonical.input.as_deref(), Some("1.50000000"));
        assert_eq!(canonical.tiers.len(), 1);
        assert_eq!(canonical.tiers[0].threshold_tokens, 200_000);
        assert_eq!(canonical.tiers[0].output.as_deref(), Some("4.25000000"));

        let mut invalid = pricing;
        invalid.tiers.push(invalid.tiers[0].clone());
        assert_eq!(canonical_model_pricing(&invalid), None);

        invalid.tiers = vec![ProviderModelPricingTier {
            threshold_tokens: MAX_SAFE_INTEGER + 1,
            ..invalid.tiers[0].clone()
        }];
        assert_eq!(canonical_model_pricing(&invalid), None);
    }
}
