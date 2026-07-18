use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use thiserror::Error;

use crate::{ProviderModel, ProxyRequest};

/// Stream returned by a provider after adapting events to the source protocol.
pub type ProviderStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, ProviderError>> + Send + 'static>>;

/// Stable error categories used by the HTTP layer for protocol-specific mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    InvalidRequest,
    Authentication,
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

    fn models(&self) -> &[ProviderModel];

    async fn execute_stream(&self, request: ProxyRequest) -> Result<ProviderStream, ProviderError>;

    async fn count_tokens(&self, request: ProxyRequest) -> Result<u64, ProviderError>;
}
