use std::{fs::File, io::Read, path::Path};

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use thiserror::Error;

/// Validated credentials loaded from a CLIProxyAPI xAI auth file.
#[derive(Clone, Debug)]
pub struct GrokCredentials {
    access_token: SecretString,
}

impl GrokCredentials {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, GrokAuthError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| GrokAuthError::Open {
            path: path.to_path_buf(),
            source,
        })?;

        Self::from_reader(file)
    }

    #[must_use]
    pub(crate) const fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn from_access_token(access_token: impl Into<String>) -> Self {
        Self {
            access_token: SecretString::from(access_token.into()),
        }
    }

    fn from_reader(reader: impl Read) -> Result<Self, GrokAuthError> {
        let stored: StoredGrokCredentials = serde_json::from_reader(reader)?;

        if !stored.provider_type.trim().eq_ignore_ascii_case("xai") {
            return Err(GrokAuthError::InvalidProviderType);
        }
        if !stored.auth_kind.trim().eq_ignore_ascii_case("oauth") {
            return Err(GrokAuthError::InvalidAuthKind);
        }
        if stored.disabled {
            return Err(GrokAuthError::Disabled);
        }
        if stored.access_token.expose_secret().trim().is_empty() {
            return Err(GrokAuthError::MissingAccessToken);
        }

        Ok(Self {
            access_token: stored.access_token,
        })
    }
}

#[derive(Deserialize)]
struct StoredGrokCredentials {
    #[serde(rename = "type")]
    provider_type: String,
    auth_kind: String,
    #[serde(default)]
    access_token: SecretString,
    #[serde(default)]
    disabled: bool,
}

#[derive(Debug, Error)]
pub enum GrokAuthError {
    #[error("failed to open Grok auth file {path}: {source}")]
    Open {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse Grok auth JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Grok auth JSON must have type xai")]
    InvalidProviderType,
    #[error("Grok auth JSON must have auth_kind oauth")]
    InvalidAuthKind,
    #[error("Grok credential is disabled")]
    Disabled,
    #[error("Grok auth JSON is missing access_token")]
    MissingAccessToken,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const VALID_AUTH: &str = r#"{
        "type": "xai",
        "auth_kind": "oauth",
        "access_token": "secret-token",
        "disabled": false
    }"#;

    #[test]
    fn parses_valid_auth_without_exposing_token_in_debug() {
        let credentials =
            GrokCredentials::from_reader(Cursor::new(VALID_AUTH)).expect("valid credentials");
        let debug = format!("{credentials:?}");

        assert_eq!(credentials.access_token().expose_secret(), "secret-token");
        assert!(!debug.contains("secret-token"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn rejects_disabled_credential() {
        let auth = VALID_AUTH.replace("false", "true");
        let result = GrokCredentials::from_reader(Cursor::new(auth));

        assert!(matches!(result, Err(GrokAuthError::Disabled)));
    }

    #[test]
    fn rejects_empty_access_token() {
        let auth = VALID_AUTH.replace("secret-token", "   ");
        let result = GrokCredentials::from_reader(Cursor::new(auth));

        assert!(matches!(result, Err(GrokAuthError::MissingAccessToken)));
    }

    #[test]
    fn parse_error_does_not_echo_secret_value() {
        let error = GrokCredentials::from_reader(Cursor::new(
            r#"{"type":"xai","auth_kind":"oauth","access_token":"do-not-log""#,
        ))
        .expect_err("invalid JSON");

        assert!(!error.to_string().contains("do-not-log"));
    }
}
