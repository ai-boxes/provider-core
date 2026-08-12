use provider_core::{ProviderError, ProviderErrorKind};
use reqwest::RequestBuilder;
use secrecy::{ExposeSecret, SecretString};

use super::credentials::CodexCredentials;

pub(crate) const DEFAULT_BACKEND_ROOT: &str = "https://chatgpt.com/backend-api";
pub(crate) const DEFAULT_AUTH_ISSUER: &str = "https://auth.openai.com";
pub(crate) const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub(crate) const ORIGINATOR: &str = "codex_cli_rs";
pub(crate) const CODEX_CLI_VERSION: &str = "0.144.5";
const LUNA_MODEL: &str = "gpt-5.6-luna";
const LUNA_ORIGINATOR: &str = "codex-tui";
const LUNA_USER_AGENT: &str =
    "codex-tui/0.144.0 (Mac OS 26.5.1; arm64) iTerm.app/3.6.11 (codex-tui; 0.144.0)";

pub(crate) fn user_agent() -> String {
    let os = os_info::get();
    format!(
        "{ORIGINATOR}/{CODEX_CLI_VERSION} ({} {}; {}) {}",
        os.os_type(),
        os.version(),
        os.architecture().unwrap_or("unknown"),
        terminal_identity()
    )
}

fn terminal_identity() -> String {
    let value = std::env::var("TERM_PROGRAM")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|program| match std::env::var("TERM_PROGRAM_VERSION") {
            Ok(version) if !version.trim().is_empty() => format!("{program}/{version}"),
            _ => program,
        })
        .or_else(|| std::env::var("TERM").ok())
        .unwrap_or_else(|| "unknown".to_owned());
    value
        .chars()
        .map(|character| {
            if matches!(character, ' '..='~') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn oauth_headers(request: RequestBuilder) -> RequestBuilder {
    request
        .header("originator", ORIGINATOR)
        .header(reqwest::header::USER_AGENT, user_agent())
}

pub(crate) fn responses_headers(
    request: RequestBuilder,
    credentials: &CodexCredentials,
) -> Result<RequestBuilder, ProviderError> {
    Ok(auth_headers(request, credentials)?
        .header("originator", ORIGINATOR)
        .header(reqwest::header::USER_AGENT, user_agent()))
}

pub(crate) fn responses_model_headers(
    request: RequestBuilder,
    credentials: &CodexCredentials,
    model: &str,
) -> Result<RequestBuilder, ProviderError> {
    let request = auth_headers(request, credentials)?;
    if model == LUNA_MODEL {
        Ok(request
            .header("originator", LUNA_ORIGINATOR)
            .header(reqwest::header::USER_AGENT, LUNA_USER_AGENT))
    } else {
        Ok(request
            .header("originator", ORIGINATOR)
            .header(reqwest::header::USER_AGENT, user_agent()))
    }
}

pub(crate) fn quota_headers(
    request: RequestBuilder,
    credentials: &CodexCredentials,
) -> Result<RequestBuilder, ProviderError> {
    Ok(auth_headers(request, credentials)?.header(reqwest::header::USER_AGENT, user_agent()))
}

fn auth_headers(
    mut request: RequestBuilder,
    credentials: &CodexCredentials,
) -> Result<RequestBuilder, ProviderError> {
    request = request.bearer_auth(credentials.access_token().expose_secret());
    if let Some(account_id) = credentials.account_id() {
        let value = reqwest::header::HeaderValue::from_str(account_id).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "Codex credential has an invalid account ID",
            )
        })?;
        request = request.header("ChatGPT-Account-ID", value);
    }
    if credentials.is_fedramp() {
        request = request.header("X-OpenAI-Fedramp", "true");
    }
    Ok(request)
}

pub(crate) fn secret(value: String) -> Option<SecretString> {
    let value = value.trim().to_owned();
    (!value.is_empty()).then(|| SecretString::from(value))
}
