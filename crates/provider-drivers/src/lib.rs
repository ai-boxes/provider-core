//! Built-in upstream provider drivers.

#![forbid(unsafe_code)]

use provider_core::{CredentialKind, ProviderConfigurationError};
use secrecy::SecretString;

pub mod anthropic_compatible;
pub mod codex;
mod compatibility;
pub mod grok;
pub mod openai_compatible;
mod token_count;

pub fn compatible_api_key_credential(
    api_key: SecretString,
) -> Result<(CredentialKind, u32, SecretString), ProviderConfigurationError> {
    let (kind, credential_json) = compatibility::CompatibleCredentials::from_input(api_key)?;
    Ok((kind, 1, credential_json))
}
