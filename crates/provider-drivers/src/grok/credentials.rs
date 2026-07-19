use std::fmt;

#[cfg(test)]
use std::io::Read;

use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::refresh::RefreshedGrokTokens;

/// Validated credentials for one Grok provider account.
#[derive(Clone)]
pub struct GrokCredentials {
    document: Map<String, Value>,
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    token_endpoint: Option<String>,
    base_url: Option<String>,
}

impl GrokCredentials {
    pub fn from_json(credential_json: &SecretString) -> Result<Self, GrokAuthError> {
        let document: Value = serde_json::from_str(credential_json.expose_secret())?;
        let document = document
            .as_object()
            .cloned()
            .ok_or(GrokAuthError::NotObject)?;
        Self::from_document(document)
    }

    #[must_use]
    pub(crate) const fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    #[must_use]
    pub(crate) fn refresh_token(&self) -> Option<&SecretString> {
        self.refresh_token.as_ref()
    }

    #[must_use]
    pub(crate) fn token_endpoint(&self) -> Option<&str> {
        self.token_endpoint.as_deref()
    }

    #[must_use]
    pub(crate) fn base_url(&self) -> Option<&str> {
        self.base_url.as_deref()
    }

    pub(crate) fn expires_at(&self) -> Result<Option<i64>, GrokAuthError> {
        timestamp_field(&self.document, "expired")
    }

    pub(crate) fn last_refreshed_at(&self) -> Result<Option<i64>, GrokAuthError> {
        timestamp_field(&self.document, "last_refresh")
    }

    pub(crate) fn refreshed(
        &self,
        tokens: &RefreshedGrokTokens,
        refreshed_at: i64,
    ) -> Result<(Self, i64), GrokAuthError> {
        let expires_in = i64::from(tokens.expires_in);
        let expires_at = refreshed_at
            .checked_add(expires_in)
            .ok_or(GrokAuthError::TimestampOutOfRange)?;
        let expired = timestamp_rfc3339(expires_at)?;
        let last_refresh = timestamp_rfc3339(refreshed_at)?;
        let mut document = self.document.clone();

        document.insert("type".to_owned(), Value::String("xai".to_owned()));
        document.insert("auth_kind".to_owned(), Value::String("oauth".to_owned()));
        document.insert(
            "access_token".to_owned(),
            Value::String(tokens.access_token.expose_secret().to_owned()),
        );
        if let Some(refresh_token) = tokens.refresh_token.as_ref() {
            document.insert(
                "refresh_token".to_owned(),
                Value::String(refresh_token.expose_secret().to_owned()),
            );
        }
        if let Some(id_token) = tokens.id_token.as_ref() {
            document.insert(
                "id_token".to_owned(),
                Value::String(id_token.expose_secret().to_owned()),
            );
        }
        if let Some(token_type) = tokens.token_type.as_ref() {
            document.insert("token_type".to_owned(), Value::String(token_type.clone()));
        }
        document.insert("expires_in".to_owned(), Value::from(tokens.expires_in));
        document.insert("expired".to_owned(), Value::String(expired));
        document.insert("last_refresh".to_owned(), Value::String(last_refresh));
        document.insert("disabled".to_owned(), Value::Bool(false));

        Ok((Self::from_document(document)?, expires_at))
    }

    pub(crate) fn to_json(&self) -> Result<SecretString, GrokAuthError> {
        serde_json::to_string(&Value::Object(self.document.clone()))
            .map(SecretString::from)
            .map_err(GrokAuthError::Json)
    }

    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn from_access_token(access_token: impl Into<String>) -> Self {
        let access_token = access_token.into();
        let mut document = Map::new();
        document.insert("type".to_owned(), Value::String("xai".to_owned()));
        document.insert("auth_kind".to_owned(), Value::String("oauth".to_owned()));
        document.insert("access_token".to_owned(), Value::String(access_token));
        document.insert("disabled".to_owned(), Value::Bool(false));
        match Self::from_document(document) {
            Ok(credentials) => credentials,
            Err(_) => unreachable!("test credential must be valid"),
        }
    }

    #[cfg(test)]
    fn from_reader(mut reader: impl Read) -> Result<Self, GrokAuthError> {
        let mut credential_json = String::new();
        reader.read_to_string(&mut credential_json)?;
        Self::from_json(&SecretString::from(credential_json))
    }

    fn from_document(document: Map<String, Value>) -> Result<Self, GrokAuthError> {
        if !string_field(&document, "type")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("xai"))
        {
            return Err(GrokAuthError::InvalidProviderType);
        }
        if !string_field(&document, "auth_kind")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("oauth"))
        {
            return Err(GrokAuthError::InvalidAuthKind);
        }
        if document
            .get("disabled")
            .and_then(Value::as_bool)
            .unwrap_or_default()
        {
            return Err(GrokAuthError::Disabled);
        }
        let access_token =
            required_secret(&document, "access_token").ok_or(GrokAuthError::MissingAccessToken)?;
        let refresh_token = optional_secret(&document, "refresh_token");
        let token_endpoint = string_field(&document, "token_endpoint")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let base_url = string_field(&document, "base_url")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);

        Ok(Self {
            document,
            access_token,
            refresh_token,
            token_endpoint,
            base_url,
        })
    }
}

impl fmt::Debug for GrokCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrokCredentials")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_endpoint", &self.token_endpoint)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

fn string_field<'a>(document: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    document.get(field).and_then(Value::as_str)
}

fn required_secret(document: &Map<String, Value>, field: &str) -> Option<SecretString> {
    optional_secret(document, field).filter(|value| !value.expose_secret().trim().is_empty())
}

fn optional_secret(document: &Map<String, Value>, field: &str) -> Option<SecretString> {
    string_field(document, field)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| SecretString::from(value.to_owned()))
}

fn timestamp_rfc3339(timestamp: i64) -> Result<String, GrokAuthError> {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| GrokAuthError::TimestampOutOfRange)?
        .format(&Rfc3339)
        .map_err(|_| GrokAuthError::TimestampOutOfRange)
}

fn timestamp_field(
    document: &Map<String, Value>,
    field: &str,
) -> Result<Option<i64>, GrokAuthError> {
    let Some(value) = string_field(document, field)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|timestamp| Some(timestamp.unix_timestamp()))
        .map_err(|_| GrokAuthError::InvalidTimestamp(field.to_owned()))
}

#[derive(Debug, Error)]
pub enum GrokAuthError {
    #[error("failed to read Grok auth JSON: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse Grok auth JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Grok auth JSON must be an object")]
    NotObject,
    #[error("Grok auth JSON must have type xai")]
    InvalidProviderType,
    #[error("Grok auth JSON must have auth_kind oauth")]
    InvalidAuthKind,
    #[error("Grok credential is disabled")]
    Disabled,
    #[error("Grok auth JSON is missing access_token")]
    MissingAccessToken,
    #[error("stored provider account is not a Grok account")]
    InvalidStoredProvider,
    #[error("unsupported Grok credential format version {0}")]
    UnsupportedCredentialFormat(u32),
    #[error("Grok credential timestamp is out of range")]
    TimestampOutOfRange,
    #[error("Grok auth JSON has invalid {0} timestamp")]
    InvalidTimestamp(String),
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
