use thiserror::Error;

/// Replaceable input token counting boundary.
pub trait TokenCounter: Send + Sync {
    fn count(&self, input: &str) -> Result<u64, TokenCountError>;
}

#[derive(Debug, Error)]
pub enum TokenCountError {
    #[error("tokenizer failed: {0}")]
    Tokenizer(String),
}
