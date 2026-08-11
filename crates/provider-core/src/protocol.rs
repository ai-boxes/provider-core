use serde::{Deserialize, Serialize};

use crate::{
    ProviderError, ProviderModelInputModality, ProviderRequest, ProviderStream, ProxyRequest,
};

/// Request and response schema used on one side of the proxy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireFormat {
    OpenAiResponses,
    OpenAiChatCompletions,
    ClaudeMessages,
}

/// Prepared native provider request and its per-request response translator.
pub struct PreparedProviderRequest {
    request: ProviderRequest,
    response: Box<dyn ResponseTranslator>,
}

impl PreparedProviderRequest {
    #[must_use]
    pub fn new(request: ProviderRequest, response: Box<dyn ResponseTranslator>) -> Self {
        Self { request, response }
    }

    #[must_use]
    pub fn into_parts(self) -> (ProviderRequest, Box<dyn ResponseTranslator>) {
        (self.request, self.response)
    }
}

/// Converts an inbound request into the native format of a selected provider.
pub trait ProtocolBridge: Send + Sync {
    fn supports(&self, source: WireFormat, target: WireFormat) -> bool;

    fn prepare(
        &self,
        request: ProxyRequest,
        target: WireFormat,
        input_modalities: Option<&[ProviderModelInputModality]>,
    ) -> Result<PreparedProviderRequest, ProviderError>;
}

/// Stateful response conversion created for one request.
pub trait ResponseTranslator: Send {
    fn translate_stream(self: Box<Self>, stream: ProviderStream) -> ProviderStream;
}
