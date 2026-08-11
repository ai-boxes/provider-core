use provider_core::{
    PreparedProviderRequest, ProtocolBridge, ProviderError, ProviderErrorKind,
    ProviderModelInputModality, ProviderRequest, ProviderStream, ProxyRequest, ResponseTranslator,
    WireFormat,
};

use crate::{anthropic, claude, openai_chat};

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultProtocolBridge;

impl ProtocolBridge for DefaultProtocolBridge {
    fn supports(&self, source: WireFormat, target: WireFormat) -> bool {
        source == target
            || matches!(
                source,
                WireFormat::OpenAiResponses | WireFormat::ClaudeMessages
            ) && matches!(
                target,
                WireFormat::OpenAiResponses
                    | WireFormat::OpenAiChatCompletions
                    | WireFormat::ClaudeMessages
            )
    }

    fn prepare(
        &self,
        request: ProxyRequest,
        target: WireFormat,
        input_modalities: Option<&[ProviderModelInputModality]>,
    ) -> Result<PreparedProviderRequest, ProviderError> {
        let explicitly_text_only = input_modalities == Some(&[ProviderModelInputModality::Text]);
        if request.format == target {
            let mut request = ProviderRequest::from_proxy(request, target);
            if target == WireFormat::OpenAiChatCompletions && explicitly_text_only {
                openai_chat::omit_tool_images(&mut request)?;
            }
            return Ok(PreparedProviderRequest::new(
                request,
                Box::new(IdentityResponseTranslator),
            ));
        }

        let (responses_request, responses_to_source): (
            ProviderRequest,
            Box<dyn ResponseTranslator>,
        ) = match request.format {
            WireFormat::OpenAiResponses => (
                ProviderRequest::from_proxy(request, WireFormat::OpenAiResponses),
                Box::new(IdentityResponseTranslator),
            ),
            WireFormat::ClaudeMessages => {
                let (request, response) = claude::prepare_responses_request(request)?;
                (request, Box::new(response))
            }
            WireFormat::OpenAiChatCompletions => return Err(unsupported_conversion()),
        };

        let (provider_request, target_to_responses): (
            ProviderRequest,
            Box<dyn ResponseTranslator>,
        ) = match target {
            WireFormat::OpenAiResponses => {
                return Ok(PreparedProviderRequest::new(
                    responses_request,
                    responses_to_source,
                ));
            }
            WireFormat::OpenAiChatCompletions => {
                let (request, response) =
                    openai_chat::prepare_request(responses_request, explicitly_text_only)?;
                (request, Box::new(response))
            }
            WireFormat::ClaudeMessages => {
                let (request, response) = anthropic::prepare_request(responses_request)?;
                (request, Box::new(response))
            }
        };

        Ok(PreparedProviderRequest::new(
            provider_request,
            Box::new(ComposedResponseTranslator {
                inner: target_to_responses,
                outer: responses_to_source,
            }),
        ))
    }
}

fn unsupported_conversion() -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::InvalidRequest,
        "the selected provider does not support this protocol conversion",
    )
}

struct IdentityResponseTranslator;

impl ResponseTranslator for IdentityResponseTranslator {
    fn translate_stream(self: Box<Self>, stream: ProviderStream) -> ProviderStream {
        stream
    }
}

struct ComposedResponseTranslator {
    inner: Box<dyn ResponseTranslator>,
    outer: Box<dyn ResponseTranslator>,
}

impl ResponseTranslator for ComposedResponseTranslator {
    fn translate_stream(self: Box<Self>, stream: ProviderStream) -> ProviderStream {
        self.outer
            .translate_stream(self.inner.translate_stream(stream))
    }
}
