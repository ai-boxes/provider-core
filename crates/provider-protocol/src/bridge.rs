use provider_core::{
    PreparedProviderRequest, ProtocolBridge, ProviderError, ProviderErrorKind, ProviderRequest,
    ProviderStream, ProxyRequest, ResponseTranslator, WireFormat,
};

use crate::claude;

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultProtocolBridge;

impl ProtocolBridge for DefaultProtocolBridge {
    fn prepare(
        &self,
        request: ProxyRequest,
        target: WireFormat,
    ) -> Result<PreparedProviderRequest, ProviderError> {
        if request.format == target {
            return Ok(PreparedProviderRequest::new(
                ProviderRequest::from_proxy(request, target),
                Box::new(IdentityResponseTranslator),
            ));
        }

        match (request.format, target) {
            (WireFormat::ClaudeMessages, WireFormat::OpenAiResponses) => {
                let (request, response) = claude::prepare_responses_request(request)?;
                Ok(PreparedProviderRequest::new(request, Box::new(response)))
            }
            _ => Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "the selected provider does not support this protocol conversion",
            )),
        }
    }
}

struct IdentityResponseTranslator;

impl ResponseTranslator for IdentityResponseTranslator {
    fn translate_stream(self: Box<Self>, stream: ProviderStream) -> ProviderStream {
        stream
    }
}
