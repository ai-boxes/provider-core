use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::{ProviderKind, StoredProviderAccount};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQuotaSupport {
    Supported,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQuotaFreshness {
    Fresh,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaGroupAudience {
    Shared,
    OwnerOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaGroupScope {
    Aggregate,
    Product,
    Billing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaMetricKind {
    Usage,
    Balance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaUnit {
    Percent,
    UsdCents,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaPeriodKind {
    Weekly,
    Monthly,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum QuotaAmount {
    Integer(i64),
    Decimal(f64),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuotaPeriod {
    pub kind: QuotaPeriodKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starts_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct QuotaBreakdown {
    pub key: String,
    pub label: String,
    pub used: QuotaAmount,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct QuotaMetric {
    pub key: String,
    pub kind: QuotaMetricKind,
    pub unit: QuotaUnit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<QuotaAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining: Option<QuotaAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<QuotaAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<QuotaPeriod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub breakdown: Vec<QuotaBreakdown>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct QuotaGroup {
    pub key: String,
    pub scope: QuotaGroupScope,
    #[serde(skip)]
    pub audience: QuotaGroupAudience,
    pub metrics: Vec<QuotaMetric>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProviderQuotaSnapshot {
    pub account_id: String,
    pub provider: ProviderKind,
    pub fetched_at: i64,
    pub groups: Vec<QuotaGroup>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProviderQuotaView {
    pub support: ProviderQuotaSupport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness: Option<ProviderQuotaFreshness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<ProviderQuotaSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<ProviderQuotaErrorKind>,
}

impl ProviderQuotaView {
    #[must_use]
    pub const fn supported_without_snapshot() -> Self {
        Self {
            support: ProviderQuotaSupport::Supported,
            freshness: None,
            snapshot: None,
            last_error: None,
        }
    }

    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            support: ProviderQuotaSupport::Unsupported,
            freshness: None,
            snapshot: None,
            last_error: None,
        }
    }

    #[must_use]
    pub const fn failed(kind: ProviderQuotaErrorKind) -> Self {
        Self {
            support: ProviderQuotaSupport::Supported,
            freshness: None,
            snapshot: None,
            last_error: Some(kind),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProviderQuotaFetch {
    pub snapshot: ProviderQuotaSnapshot,
    pub credential_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQuotaErrorKind {
    Unsupported,
    Authentication,
    RateLimited,
    Upstream,
    InvalidResponse,
    Internal,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct ProviderQuotaError {
    kind: ProviderQuotaErrorKind,
    message: String,
    upstream_status: Option<u16>,
}

impl ProviderQuotaError {
    #[must_use]
    pub fn new(kind: ProviderQuotaErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            upstream_status: None,
        }
    }

    #[must_use]
    pub const fn with_upstream_status(mut self, status: u16) -> Self {
        self.upstream_status = Some(status);
        self
    }

    #[must_use]
    pub const fn kind(&self) -> ProviderQuotaErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub const fn upstream_status(&self) -> Option<u16> {
        self.upstream_status
    }
}

#[async_trait]
pub trait ProviderQuotaSource: Send + Sync {
    async fn fetch_quota(&self) -> Result<ProviderQuotaSnapshot, ProviderQuotaError>;
}

#[async_trait]
pub trait ProviderQuotaControl: Send + Sync {
    fn supports_quota(&self, provider: ProviderKind) -> bool;

    async fn fetch_account_quota(
        &self,
        account: StoredProviderAccount,
    ) -> Result<ProviderQuotaFetch, ProviderQuotaError>;
}
