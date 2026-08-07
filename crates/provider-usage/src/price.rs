//! Price resolution locked at attempt start from the in-memory catalog.
//!
//! A resolved price is inlined onto the attempt as the exact per-component unit
//! prices actually used plus the catalog revision, so historical cost is
//! reproducible from the attempt alone — without keeping old catalog revisions
//! and without a separate deduplicated rule table. Every non-resolved outcome is
//! a distinct, stable reason; a missing price is never silently treated as free.

use serde::{Deserialize, Serialize};

use crate::money::UnitPrice;

/// The per-component unit prices selected for an attempt (already reflecting the
/// chosen context tier and mode). `None` means the catalog has no price for that
/// component, which makes any positive quantity in it partial rather than free.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComponentPrices {
    pub uncached_input_per_million: Option<UnitPrice>,
    pub cache_read_per_million: Option<UnitPrice>,
    pub cache_write_per_million: Option<UnitPrice>,
    pub output_per_million: Option<UnitPrice>,
    pub reasoning_per_million: Option<UnitPrice>,
    pub input_audio_per_million: Option<UnitPrice>,
    pub output_audio_per_million: Option<UnitPrice>,
}

/// A catalog context tier whose threshold and component prices are explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextPriceTier {
    pub threshold_tokens: u64,
    pub prices: ComponentPrices,
}

/// The price facts inlined onto an attempt. Enough to recompute and explain the
/// cost on its own; it does not carry the whole catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InlinePriceRecord {
    pub format_version: u16,
    pub parser_version: u16,
    /// Content SHA-256 of the catalog the prices came from.
    pub catalog_revision: String,
    pub catalog_provider_id: String,
    pub catalog_model_id: String,
    pub mapping_revision: u32,
    pub prices: ComponentPrices,
    /// Optional higher context tier selected from the observed pricing basis.
    #[serde(default)]
    pub context_tier: Option<ContextPriceTier>,
    /// Human-readable label of the selected context tier; `None` means base.
    pub selected_tier: Option<String>,
    /// A billable component was observed that the catalog cannot price.
    pub unmodeled_billable_component: bool,
    /// The catalog entry carries a pricing rule this parser does not model, so
    /// `prices` may not be the complete answer.
    ///
    /// Defaults to `false` so attempts stored before this field existed keep
    /// meaning exactly what they meant when written.
    #[serde(default)]
    pub unmodeled_pricing_rule: bool,
}

/// The price outcome fixed for an attempt before dispatch. Only `Resolved`
/// carries prices; every other variant is a stable failure reason that keeps the
/// cost honest instead of defaulting to zero.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PriceResolution {
    Resolved(Box<InlinePriceRecord>),
    /// No catalog is available (no last-known-good and no seed).
    CatalogUnavailable,
    /// The account is not mapped to a catalog provider id.
    ProviderMappingMissing,
    /// The upstream model has no exact catalog model id.
    ModelMappingMissing,
    /// The catalog entry exists but carries no cost subtree.
    CostMissing,
    /// The catalog entry's cost is malformed.
    CatalogEntryInvalid,
    /// A tier/mode rule exists but has no tested evidence for its semantics.
    PricingRuleUnsupported,
    /// Two price representations disagree and cannot be normalized.
    PricingRuleConflict,
}

impl PriceResolution {
    /// The inlined prices when resolved, else `None`.
    #[must_use]
    pub fn resolved(&self) -> Option<&InlinePriceRecord> {
        match self {
            Self::Resolved(record) => Some(record.as_ref()),
            _ => None,
        }
    }
}
