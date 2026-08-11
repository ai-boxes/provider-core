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

/// A safe provider error that may cross crate boundaries.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ProviderError {
    kind: ProviderErrorKind,
    message: String,
    upstream_status: Option<u16>,
}

impl ProviderError {
    #[must_use]
    pub fn new(kind: ProviderErrorKind, message: impl Into<String>) -> Self {
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
    pub upstream_model: String,
    pub input_modalities: Option<Vec<crate::ProviderModelInputModality>>,
    pub pricing: Option<crate::ProviderModelPricingRecord>,
    pub route: Arc<dyn ProviderRoute>,
}

#[derive(Clone, Debug)]
pub struct RoutableProviderModel {
    pub model: ProviderModel,
    pub native_formats: Vec<WireFormat>,
}

/// In-memory model index used before protocol conversion and provider execution.
pub trait ProviderRouter: Send + Sync {
    fn models(
        &self,
        user_id: &str,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Vec<RoutableProviderModel>;

    fn routes(
        &self,
        user_id: &str,
        model: &str,
        native_formats: &[WireFormat],
        session_id: Option<&str>,
        account_ids: Option<&HashSet<AccountId>>,
    ) -> Vec<ProviderRouteCandidate>;
}

/// Shared metadata and native protocol implemented by one upstream driver.
pub trait ProviderDriver: Send + Sync {
    fn name(&self) -> &'static str;

    fn native_format(&self) -> WireFormat;

    fn models(&self) -> &[ProviderModel];
}
