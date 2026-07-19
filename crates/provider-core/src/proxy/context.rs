use bytes::Bytes;
use thiserror::Error;

use crate::WireFormat;

/// Sanitized request metadata allowed to cross into provider adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequestMetadata {
    pub session_id: Option<String>,
}

/// Provider-neutral request envelope that preserves the source JSON payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyRequest {
    pub format: WireFormat,
    pub model: String,
    pub payload: Bytes,
    pub metadata: RequestMetadata,
}

impl ProxyRequest {
    pub fn new(
        format: WireFormat,
        model: impl Into<String>,
        payload: Bytes,
    ) -> Result<Self, ProxyRequestError> {
        let model = model.into().trim().to_owned();
        if model.is_empty() {
            return Err(ProxyRequestError::EmptyModel);
        }

        Ok(Self {
            format,
            model,
            payload,
            metadata: RequestMetadata::default(),
        })
    }

    #[must_use]
    pub fn with_metadata(mut self, metadata: RequestMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Request encoded in the native wire format expected by a provider driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRequest {
    pub format: WireFormat,
    pub model: String,
    pub payload: Bytes,
    pub metadata: RequestMetadata,
}

impl ProviderRequest {
    #[must_use]
    pub fn from_proxy(request: ProxyRequest, format: WireFormat) -> Self {
        Self {
            format,
            model: request.model,
            payload: request.payload,
            metadata: request.metadata,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProxyRequestError {
    #[error("model must not be empty")]
    EmptyModel,
}
