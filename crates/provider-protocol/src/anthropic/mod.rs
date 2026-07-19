mod request;
mod response;

use provider_core::{ProviderError, ProviderRequest};

pub(crate) use response::AnthropicResponseTranslator;

pub(crate) fn prepare_request(
    request: ProviderRequest,
) -> Result<(ProviderRequest, AnthropicResponseTranslator), ProviderError> {
    request::prepare_request(request)
}
