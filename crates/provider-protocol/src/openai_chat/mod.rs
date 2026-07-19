mod request;
mod response;

use provider_core::{ProviderError, ProviderRequest};

pub(crate) use response::ChatResponseTranslator;

pub(crate) fn prepare_request(
    request: ProviderRequest,
) -> Result<(ProviderRequest, ChatResponseTranslator), ProviderError> {
    request::prepare_request(request)
}
