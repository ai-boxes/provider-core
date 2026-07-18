use async_trait::async_trait;
use provider_core::{
    Protocol, Provider, ProviderError, ProviderErrorKind, ProviderModel, ProviderStream,
    ProxyRequest, TokenCounter,
};

use crate::{
    Cl100kTokenCounter, GrokClient, GrokCredentials, grok_models,
    request::{prepare_claude_request, prepare_codex_request},
    response::adapt_grok_stream_to_claude,
};

/// Grok upstream adapter implementing the provider-core contract.
#[derive(Clone)]
pub struct GrokProvider {
    client: GrokClient,
    token_counter: Cl100kTokenCounter,
}

impl GrokProvider {
    #[must_use]
    pub fn new(credentials: GrokCredentials) -> Self {
        Self {
            client: GrokClient::new(credentials),
            token_counter: Cl100kTokenCounter,
        }
    }

    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    pub fn for_test(access_token: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self {
            client: GrokClient::with_base_url(
                GrokCredentials::from_access_token(access_token),
                base_url,
            ),
            token_counter: Cl100kTokenCounter,
        }
    }
}

#[async_trait]
impl Provider for GrokProvider {
    fn name(&self) -> &'static str {
        "grok"
    }

    fn models(&self) -> &[ProviderModel] {
        grok_models()
    }

    async fn execute_stream(&self, request: ProxyRequest) -> Result<ProviderStream, ProviderError> {
        match request.protocol {
            Protocol::CodexResponses => {
                let prepared = prepare_codex_request(request)?;
                self.client
                    .execute_stream(prepared.payload, &prepared.metadata)
                    .await
            }
            Protocol::ClaudeMessages => {
                let prepared = prepare_claude_request(request)?;
                let stream = self
                    .client
                    .execute_stream(prepared.upstream.payload, &prepared.upstream.metadata)
                    .await?;
                Ok(adapt_grok_stream_to_claude(stream, prepared.response))
            }
        }
    }

    async fn count_tokens(&self, request: ProxyRequest) -> Result<u64, ProviderError> {
        let prepared = match request.protocol {
            Protocol::CodexResponses => prepare_codex_request(request)?,
            Protocol::ClaudeMessages => prepare_claude_request(request)?.upstream,
        };
        let input = std::str::from_utf8(&prepared.payload).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "normalized Grok request was not valid UTF-8",
            )
        })?;

        self.token_counter.count(input).map_err(|error| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                format!("failed to count Grok request tokens: {error}"),
            )
        })
    }
}
