use provider_core::{TokenCountError, TokenCounter};
use tiktoken_rs::cl100k_base_singleton;

/// Approximate Grok input token counter backed by cl100k_base.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cl100kTokenCounter;

impl TokenCounter for Cl100kTokenCounter {
    fn count(&self, input: &str) -> Result<u64, TokenCountError> {
        let count = cl100k_base_singleton().count_with_special_tokens(input);
        u64::try_from(count)
            .map_err(|error| TokenCountError::Tokenizer(format!("token count overflow: {error}")))
    }
}
