use std::{collections::HashSet, pin::Pin, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use thiserror::Error;

use crate::{AccountId, ProviderModel, ProviderRequest, WireFormat};

/// Byte stream crossing the provider and protocol boundaries.
pub type ProviderStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, ProviderError>> + Send + 'static>>;

/// Stable error categories used by the HTTP layer for protocol-specific mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    InvalidRequest,
    Authentication,
    RateLimited,
    Upstream,
    Internal,
}

/// A reviewed reason why replaying the request on another account is safe.
///
/// Errors are non-replayable by default. Drivers and the account runtime must
/// opt in only when they can prove the request falls into one of these cases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailoverReason {
    AuthenticationExhausted,
    QuotaExhausted,
    RateLimited,
    PreconnectFailure,
}

/// A safe provider error that may cross crate boundaries.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ProviderError {
    kind: ProviderErrorKind,
    message: String,
    upstream_status: Option<u16>,
    failover_reason: Option<ProviderFailoverReason>,
}

impl ProviderError {
    #[must_use]
    pub fn new(kind: ProviderErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            upstream_status: None,
            failover_reason: None,
        }
    }

    #[must_use]
    pub const fn with_upstream_status(mut self, status: u16) -> Self {
        self.upstream_status = Some(status);
        self
    }

    #[must_use]
    pub const fn with_failover_reason(mut self, reason: ProviderFailoverReason) -> Self {
        self.failover_reason = Some(reason);
        self
    }

    #[must_use]
    pub const fn kind(&self) -> ProviderErrorKind {
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

    #[must_use]
    pub const fn failover_reason(&self) -> Option<ProviderFailoverReason> {
        self.failover_reason
    }
}

/// Runtime provider boundary used by the proxy service.
#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;

    fn native_format(&self) -> WireFormat;

    fn models(&self) -> &[ProviderModel];

    async fn execute_stream(
        &self,
        request: ProviderRequest,
    ) -> Result<ProviderStream, ProviderError>;

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError>;
}

/// One concrete provider account selected for a request.
#[async_trait]
pub trait ProviderRoute: Send + Sync {
    fn provider_name(&self) -> &'static str;

    fn native_format(&self) -> WireFormat;

    /// Whether response IDs from this account may be reused by a later request.
    fn supports_previous_response_id(&self) -> bool {
        false
    }

    fn usage_profile(&self) -> Option<crate::usage::ProviderUsageProfile> {
        None
    }

    /// Maximum number of real upstream attempts one execution can make.
    fn maximum_attempts(&self) -> u32 {
        1
    }

    /// Execute the request, opening one tracked attempt per real upstream call.
    ///
    /// `tracking` is threaded down here rather than handled by the caller because
    /// a refresh-and-retry happens inside this call: only the code that decides
    /// to make a second upstream call can report it as a second attempt.
    async fn execute_stream(
        &self,
        request: ProviderRequest,
        pricing: Option<&crate::ProviderModelPricingRecord>,
        tracking: Option<&Arc<dyn crate::usage::RequestTracking>>,
    ) -> Result<ProviderStream, ProviderError>;

    async fn count_tokens(&self, request: ProviderRequest) -> Result<u64, ProviderError>;
}

#[derive(Clone)]
pub struct ProviderRouteCandidate {
    pub account_id: Option<AccountId>,
    pub priority: u32,
    pub upstream_model: String,
    pub input_modalities: Option<Vec<crate::ProviderModelInputModality>>,
    pub responses_lite: bool,
    pub pricing: Option<crate::ProviderModelPricingRecord>,
    pub route: Arc<dyn ProviderRoute>,
}

#[derive(Clone, Debug)]
pub struct RoutableProviderModel {
    pub model: ProviderModel,
    pub native_formats: Vec<WireFormat>,
}

pub struct ProviderRouteQuery<'a> {
    pub user_id: &'a str,
    pub routing_scope: &'a str,
    pub model: &'a str,
    pub native_formats: &'a [WireFormat],
    pub session_id: Option<&'a str>,
    pub previous_response_id: Option<&'a str>,
    pub account_ids: Option<&'a HashSet<AccountId>>,
}

/// In-memory model index used before protocol conversion and provider execution.
pub trait ProviderRouter: Send + Sync {
    fn models(
        &self,
        user_id: &str,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Vec<RoutableProviderModel>;

    fn routes(&self, query: &ProviderRouteQuery<'_>) -> Vec<ProviderRouteCandidate>;

    fn commit_session_affinity(
        &self,
        _routing_scope: &str,
        _model: &str,
        _session_id: Option<&str>,
        _account_id: &AccountId,
    ) {
    }

    fn record_route_failure(
        &self,
        _account_id: &AccountId,
        _model: &str,
        _reason: ProviderFailoverReason,
    ) {
    }

    fn record_route_success(&self, _account_id: &AccountId, _model: &str) {}

    fn bind_response_id(&self, _routing_scope: &str, _response_id: &str, _account_id: &AccountId) {}
}

/// Shared metadata and native protocol implemented by one upstream driver.
pub trait ProviderDriver: Send + Sync {
    fn name(&self) -> &'static str;

    fn native_format(&self) -> WireFormat;

    fn models(&self) -> &[ProviderModel];
}
