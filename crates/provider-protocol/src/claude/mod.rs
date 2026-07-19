mod request;
mod response;

use provider_core::{ProviderError, ProviderRequest, ProxyRequest};

pub(crate) use response::ClaudeResponseTranslator;

pub(crate) fn prepare_responses_request(
    request: ProxyRequest,
) -> Result<(ProviderRequest, ClaudeResponseTranslator), ProviderError> {
    request::prepare_responses_request(request)
}
