//! Price resolution locked at attempt start from the routed provider model.
//!
//! A resolved price is inlined onto the attempt as the exact per-component unit
//! prices and context tiers actually used, so historical cost is reproducible
//! from the attempt alone. The v1 catalog record remains only for strict reading
//! of historical attempts; new attempts write the v2 provider-model record.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use provider_core::ProviderModelPricingSource;

use crate::money::UnitPrice;

/// The per-component unit prices selected for an attempt (already reflecting the
/// chosen context tier and mode). `None` means the saved model price has no rate
/// for that component, which makes any positive quantity partial rather than free.
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
#[serde(deny_unknown_fields)]
pub struct CatalogInlinePriceRecordV1 {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelInlinePriceRecordV2 {
    pub format_version: u16,
    pub source: ProviderModelPricingSource,
    pub prices: ComponentPrices,
    pub tiers: Vec<ContextPriceTier>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
// `PriceResolution` already boxes this enum; boxing one variant would add a
// second allocation without shrinking the stored resolution.
#[allow(clippy::large_enum_variant)]
pub enum InlinePriceRecord {
    CatalogV1(CatalogInlinePriceRecordV1),
    ModelV2(ModelInlinePriceRecordV2),
}

impl InlinePriceRecord {
    #[must_use]
    pub const fn prices(&self) -> ComponentPrices {
        match self {
            Self::CatalogV1(record) => record.prices,
            Self::ModelV2(record) => record.prices,
        }
    }

    #[must_use]
    pub const fn context_tier(&self) -> Option<ContextPriceTier> {
        match self {
            Self::CatalogV1(record) => record.context_tier,
            Self::ModelV2(_) => None,
        }
    }

    #[must_use]
    pub fn has_context_tiers(&self) -> bool {
        match self {
            Self::CatalogV1(record) => record.context_tier.is_some(),
            Self::ModelV2(record) => !record.tiers.is_empty(),
        }
    }

    #[must_use]
    pub fn prices_for_context(&self, context_tokens: Option<u64>) -> ComponentPrices {
        let Some(context_tokens) = context_tokens else {
            return self.prices();
        };
        match self {
            Self::CatalogV1(record) => record.context_tier.map_or(record.prices, |tier| {
                if context_tokens > tier.threshold_tokens {
                    tier.prices
                } else {
                    record.prices
                }
            }),
            Self::ModelV2(record) => record
                .tiers
                .iter()
                .take_while(|tier| context_tokens > tier.threshold_tokens)
                .last()
                .map_or(record.prices, |tier| tier.prices),
        }
    }

    #[must_use]
    pub fn selected_tier(&self) -> Option<&str> {
        match self {
            Self::CatalogV1(record) => record.selected_tier.as_deref(),
            Self::ModelV2(_) => None,
        }
    }

    #[must_use]
    pub fn catalog_revision(&self) -> Option<&str> {
        match self {
            Self::CatalogV1(record) => Some(&record.catalog_revision),
            Self::ModelV2(_) => None,
        }
    }

    #[must_use]
    pub fn catalog_model_id(&self) -> Option<&str> {
        match self {
            Self::CatalogV1(record) => Some(&record.catalog_model_id),
            Self::ModelV2(_) => None,
        }
    }

    #[must_use]
    pub const fn source(&self) -> Option<ProviderModelPricingSource> {
        match self {
            Self::CatalogV1(_) => None,
            Self::ModelV2(record) => Some(record.source),
        }
    }

    #[must_use]
    pub const fn unmodeled_billable_component(&self) -> bool {
        match self {
            Self::CatalogV1(record) => record.unmodeled_billable_component,
            Self::ModelV2(_) => false,
        }
    }

    #[must_use]
    pub const fn unmodeled_pricing_rule(&self) -> bool {
        match self {
            Self::CatalogV1(record) => record.unmodeled_pricing_rule,
            Self::ModelV2(_) => false,
        }
    }
}

impl Serialize for InlinePriceRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::CatalogV1(record) => record.serialize(serializer),
            Self::ModelV2(record) => record.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for InlinePriceRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let version = value
            .get("format_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| serde::de::Error::custom("inline price format_version is required"))?;
        match version {
            1 => serde_json::from_value::<CatalogInlinePriceRecordV1>(value)
                .map(Self::CatalogV1)
                .map_err(serde::de::Error::custom),
            2 => serde_json::from_value::<ModelInlinePriceRecordV2>(value)
                .map(Self::ModelV2)
                .map_err(serde::de::Error::custom),
            _ => Err(serde::de::Error::custom(
                "unsupported inline price format_version",
            )),
        }
    }
}

/// The price outcome fixed for an attempt before dispatch. Only `Resolved`
/// carries prices; every other variant is a stable failure reason that keeps the
/// cost honest instead of defaulting to zero.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PriceResolution {
    Resolved(Box<InlinePriceRecord>),
    /// Historical v1 outcome: no catalog was available.
    CatalogUnavailable,
    /// Historical v1 outcome: the account had no catalog provider mapping.
    ProviderMappingMissing,
    /// The routed provider model has no saved exact-ID price.
    ModelMappingMissing,
    /// Historical v1 outcome: the catalog entry carried no cost subtree.
    CostMissing,
    /// The frozen model price is malformed.
    CatalogEntryInvalid,
    /// Historical v1 outcome: a pricing rule had unsupported semantics.
    PricingRuleUnsupported,
    /// Historical v1 outcome: two price representations conflicted.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_price_v2_round_trips_and_rejects_unknown_shapes() {
        let record = InlinePriceRecord::ModelV2(ModelInlinePriceRecordV2 {
            format_version: 2,
            source: ProviderModelPricingSource::Manual,
            prices: ComponentPrices {
                uncached_input_per_million: Some(UnitPrice::from_scaled(125_000_000)),
                output_per_million: Some(UnitPrice::from_scaled(1_000_000_000)),
                ..ComponentPrices::default()
            },
            tiers: vec![ContextPriceTier {
                threshold_tokens: 200_000,
                prices: ComponentPrices {
                    uncached_input_per_million: Some(UnitPrice::from_scaled(250_000_000)),
                    output_per_million: Some(UnitPrice::from_scaled(2_000_000_000)),
                    ..ComponentPrices::default()
                },
            }],
        });
        let json = serde_json::to_string(&record).expect("serialize v2 price");
        assert_eq!(
            serde_json::from_str::<InlinePriceRecord>(&json).expect("deserialize v2 price"),
            record
        );
        assert_eq!(
            record.prices_for_context(Some(200_000)),
            ComponentPrices {
                uncached_input_per_million: Some(UnitPrice::from_scaled(125_000_000)),
                output_per_million: Some(UnitPrice::from_scaled(1_000_000_000)),
                ..ComponentPrices::default()
            }
        );
        assert_eq!(
            record.prices_for_context(Some(200_001)),
            ComponentPrices {
                uncached_input_per_million: Some(UnitPrice::from_scaled(250_000_000)),
                output_per_million: Some(UnitPrice::from_scaled(2_000_000_000)),
                ..ComponentPrices::default()
            }
        );
        assert!(serde_json::from_str::<InlinePriceRecord>(r#"{"source":"manual"}"#).is_err());
        assert!(
            serde_json::from_str::<InlinePriceRecord>(
                r#"{"format_version":2,"source":"manual","prices":{}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<InlinePriceRecord>(
                r#"{"format_version":3,"source":"manual","prices":{}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<InlinePriceRecord>(
                r#"{"format_version":2,"source":"manual","prices":{},"extra":true}"#
            )
            .is_err()
        );
    }
}
