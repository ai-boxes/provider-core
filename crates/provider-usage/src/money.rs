//! Exact fixed-point money. No `f64` ever touches a price or an amount.
//!
//! A unit price is a USD-per-million-tokens value scaled by `10^PRICE_SCALE`.
//! An amount is an integer count of `10^-AMOUNT_SCALE` USD atoms, chosen so that
//!
//! ```text
//! cost_usd = quantity * price_per_million / 1_000_000
//! ```
//!
//! reduces to the exact integer `quantity * price_numerator` with no division
//! and no intermediate rounding. Amounts are summed as integers and rounded
//! only at a display boundary — never rounded per-component and then added.

use serde::{Deserialize, Serialize};

/// Fractional decimal digits kept for a unit price (USD per million tokens).
///
/// Provisional: pinned with measurement in a later phase. It must exceed the
/// precision of any catalog price; `8` covers models.dev's per-token costs with
/// headroom.
pub const PRICE_SCALE: u32 = 8;

/// Fractional decimal digits of a USD amount atom (`PRICE_SCALE + 6`, the `+6`
/// absorbing the per-million divisor).
pub const AMOUNT_SCALE: u32 = PRICE_SCALE + 6;

/// A unit price in USD per million tokens, stored as an integer numerator scaled
/// by `10^PRICE_SCALE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct UnitPrice(i128);

impl UnitPrice {
    /// Build from an already-scaled numerator (`price_per_million * 10^PRICE_SCALE`).
    #[must_use]
    pub const fn from_scaled(numerator: i128) -> Self {
        Self(numerator)
    }

    /// The scaled numerator.
    #[must_use]
    pub const fn as_scaled(self) -> i128 {
        self.0
    }

    /// Canonical USD-per-million decimal string at the catalog price scale.
    #[must_use]
    pub fn to_decimal_string(self) -> String {
        let magnitude = self.0.unsigned_abs();
        let divisor = 10u128.pow(PRICE_SCALE);
        let integer = magnitude / divisor;
        let fraction = magnitude % divisor;
        let sign = if self.0 < 0 { "-" } else { "" };
        format!(
            "{sign}{integer}.{fraction:0width$}",
            width = PRICE_SCALE as usize
        )
    }
}

/// A USD amount as an integer count of `10^-AMOUNT_SCALE` USD atoms.
///
/// `Default` is zero, which is the correct starting point for a *sum*. It is not
/// a stand-in for a missing amount: an absent cost is expressed by
/// [`crate::CostStatus::Unavailable`], never by this being zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct UsdAtoms(i128);

impl UsdAtoms {
    pub const ZERO: Self = Self(0);

    /// Rebuild an amount from a raw atom count, as stored.
    #[must_use]
    pub const fn from_atoms(atoms: i128) -> Self {
        Self(atoms)
    }

    /// The raw atom count.
    #[must_use]
    pub const fn as_atoms(self) -> i128 {
        self.0
    }

    /// Sum two amounts, returning `None` on overflow so a caller can mark the
    /// cost unavailable rather than wrap.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(sum) => Some(Self(sum)),
            None => None,
        }
    }

    /// The canonical, full-precision decimal string (`AMOUNT_SCALE` fractional
    /// digits). Display-level rounding is a separate, later step.
    #[must_use]
    pub fn to_decimal_string(self) -> String {
        let magnitude = self.0.unsigned_abs();
        let divisor = 10u128.pow(AMOUNT_SCALE);
        let integer = magnitude / divisor;
        let fraction = magnitude % divisor;
        let sign = if self.0 < 0 { "-" } else { "" };
        format!(
            "{sign}{integer}.{fraction:0width$}",
            width = AMOUNT_SCALE as usize
        )
    }
}

/// The exact cost of one component: `quantity * price_numerator` atoms. Returns
/// `None` on overflow.
#[must_use]
pub fn component_cost_atoms(quantity: u64, price: UnitPrice) -> Option<UsdAtoms> {
    i128::from(quantity)
        .checked_mul(price.as_scaled())
        .map(UsdAtoms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_is_exact_integer_product() {
        // 1000 tokens at 3 USD / million = 0.003 USD.
        let price = UnitPrice::from_scaled(3 * 10i128.pow(PRICE_SCALE));
        let cost = component_cost_atoms(1000, price).expect("no overflow");
        assert_eq!(cost.as_atoms(), 1000 * 3 * 10i128.pow(PRICE_SCALE));
        assert_eq!(cost.to_decimal_string(), "0.00300000000000");
    }

    #[test]
    fn unit_price_has_a_canonical_decimal_representation() {
        let price = UnitPrice::from_scaled(5 * 10i128.pow(PRICE_SCALE));
        assert_eq!(price.to_decimal_string(), "5.00000000");
    }

    #[test]
    fn overflow_is_reported_not_wrapped() {
        let price = UnitPrice::from_scaled(i128::MAX);
        assert_eq!(component_cost_atoms(u64::MAX, price), None);
        assert_eq!(UsdAtoms(i128::MAX).checked_add(UsdAtoms(1)), None);
    }
}
