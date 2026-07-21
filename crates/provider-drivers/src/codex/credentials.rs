use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use thiserror::Error;

use super::refresh::RefreshedCodexTokens;

#[derive(Clone)]
pub(crate) struct CodexCredentials {
    access_token: SecretString,
    refresh_token: SecretString,
    id_token: SecretString,
    account_id: Option<String>,
    is_fedramp: bool,
    plan_type: Option<String>,
    expires_at: Option<i64>,
    last_refreshed_at: i64,
}

impl CodexCredentials {
    pub(crate) fn from_json(credential_json: &SecretString) -> Result<Self, CodexAuthError> {
        let value: Value = serde_json::from_str(credential_json.expose_secret())
            .map_err(|_| CodexAuthError::InvalidJson)?;
        let document = value.as_object().ok_or(CodexAuthError::NotObject)?;
        if string_field(document, "type") != Some("codex") {
            return Err(CodexAuthError::InvalidProviderType);
        }
        if string_field(document, "auth_kind") != Some("oauth") {
            return Err(CodexAuthError::InvalidAuthKind);
        }
        let access_token =
            required_secret(document, "access_token").ok_or(CodexAuthError::MissingAccessToken)?;
        let refresh_token = required_secret(document, "refresh_token")
            .ok_or(CodexAuthError::MissingRefreshToken)?;
        let id_token =
            required_secret(document, "id_token").ok_or(CodexAuthError::MissingIdToken)?;
        let stored_account_id = optional_string(document, "account_id");
        let stored_fedramp = document.get("is_fedramp").and_then(Value::as_bool);
        let stored_plan = optional_string(document, "plan_type");
        let stored_expires_at = optional_i64(document, "expires_at")?;
        let last_refreshed_at = optional_i64(document, "last_refreshed_at")?
            .ok_or(CodexAuthError::MissingLastRefreshedAt)?;

        let claims = identity_claims(id_token.expose_secret())?;
        let account_id = reconcile_optional("account_id", stored_account_id, claims.account_id)?;
        let is_fedramp =
            reconcile_optional_bool(stored_fedramp, Some(claims.is_fedramp))?.unwrap_or(false);
        let plan_type = reconcile_optional("plan_type", stored_plan, claims.plan_type)?;
        let access_expires_at = access_expiration(access_token.expose_secret());
        let expires_at = match (stored_expires_at, access_expires_at) {
            (Some(stored), Some(claim)) if stored != claim => {
                return Err(CodexAuthError::ClaimMismatch("expires_at"));
            }
            (stored, claim) => stored.or(claim),
        };
        validate_account_id(account_id.as_deref())?;

        Ok(Self {
            access_token,
            refresh_token,
            id_token,
            account_id,
            is_fedramp,
            plan_type,
            expires_at,
            last_refreshed_at,
        })
    }

    pub(crate) fn from_tokens(
        access_token: String,
        refresh_token: String,
        id_token: String,
        refreshed_at: i64,
    ) -> Result<Self, CodexAuthError> {
        let access_token =
            non_empty_secret(access_token).ok_or(CodexAuthError::MissingAccessToken)?;
        let refresh_token =
            non_empty_secret(refresh_token).ok_or(CodexAuthError::MissingRefreshToken)?;
        let id_token = non_empty_secret(id_token).ok_or(CodexAuthError::MissingIdToken)?;
        let claims = identity_claims(id_token.expose_secret())?;
        validate_account_id(claims.account_id.as_deref())?;
        let expires_at = access_expiration(access_token.expose_secret());
        Ok(Self {
            access_token,
            refresh_token,
            id_token,
            account_id: claims.account_id,
            is_fedramp: claims.is_fedramp,
            plan_type: claims.plan_type,
            expires_at,
            last_refreshed_at: refreshed_at,
        })
    }

    pub(crate) fn refreshed(
        &self,
        tokens: RefreshedCodexTokens,
        refreshed_at: i64,
    ) -> Result<Self, CodexAuthError> {
        let access_rotated = tokens.access_token.is_some();
        let id_rotated = tokens.id_token.is_some();
        if !access_rotated && tokens.refresh_token.is_none() && !id_rotated {
            return Err(CodexAuthError::EmptyRefreshResponse);
        }
        let access_token = tokens
            .access_token
            .unwrap_or_else(|| self.access_token.clone());
        let refresh_token = tokens
            .refresh_token
            .unwrap_or_else(|| self.refresh_token.clone());
        let id_token = tokens.id_token.unwrap_or_else(|| self.id_token.clone());
        let expires_at = if access_rotated {
            access_expiration(access_token.expose_secret())
        } else {
            self.expires_at
        };
        let (account_id, is_fedramp, plan_type) = if id_rotated {
            let claims = identity_claims(id_token.expose_secret())?;
            let account_id =
                reconcile_optional("account_id", self.account_id.clone(), claims.account_id)?;
            (account_id, claims.is_fedramp, claims.plan_type)
        } else {
            (
                self.account_id.clone(),
                self.is_fedramp,
                self.plan_type.clone(),
            )
        };
        validate_account_id(account_id.as_deref())?;
        Ok(Self {
            access_token,
            refresh_token,
            id_token,
            account_id,
            is_fedramp,
            plan_type,
            expires_at,
            last_refreshed_at: refreshed_at,
        })
    }

    pub(crate) fn to_json(&self) -> Result<SecretString, CodexAuthError> {
        let value = serde_json::json!({
            "type": "codex",
            "auth_kind": "oauth",
            "access_token": self.access_token.expose_secret(),
            "refresh_token": self.refresh_token.expose_secret(),
            "id_token": self.id_token.expose_secret(),
            "account_id": self.account_id,
            "is_fedramp": self.is_fedramp,
            "plan_type": self.plan_type,
            "expires_at": self.expires_at,
            "last_refreshed_at": self.last_refreshed_at,
        });
        serde_json::to_string(&value)
            .map(SecretString::from)
            .map_err(|_| CodexAuthError::InvalidJson)
    }

    pub(crate) const fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    pub(crate) const fn refresh_token(&self) -> &SecretString {
        &self.refresh_token
    }

    pub(crate) fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    pub(crate) const fn is_fedramp(&self) -> bool {
        self.is_fedramp
    }

    pub(crate) const fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    pub(crate) const fn last_refreshed_at(&self) -> i64 {
        self.last_refreshed_at
    }
}

impl fmt::Debug for CodexCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexCredentials")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("id_token", &"[REDACTED]")
            .field(
                "account_id",
                &self.account_id.as_ref().map(|_| "[REDACTED]"),
            )
            .field("is_fedramp", &self.is_fedramp)
            .field("plan_type", &self.plan_type.as_ref().map(|_| "[REDACTED]"))
            .field("expires_at", &self.expires_at)
            .field("last_refreshed_at", &self.last_refreshed_at)
            .finish()
    }
}

#[derive(Default)]
struct IdentityClaims {
    account_id: Option<String>,
    is_fedramp: bool,
    plan_type: Option<String>,
}

#[derive(Deserialize)]
struct AccessClaims {
    #[serde(default)]
    exp: Option<i64>,
}

#[derive(Deserialize)]
struct IdClaims {
    #[serde(rename = "https://api.openai.com/auth", default)]
    auth: Option<AuthClaims>,
}

#[derive(Deserialize)]
struct AuthClaims {
    #[serde(default)]
    chatgpt_account_id: Option<String>,
    #[serde(default)]
    chatgpt_account_is_fedramp: Option<bool>,
    #[serde(default)]
    chatgpt_plan_type: Option<String>,
}

fn access_expiration(token: &str) -> Option<i64> {
    decode_jwt_payload::<AccessClaims>(token)
        .ok()
        .and_then(|claims| claims.exp)
}

fn identity_claims(token: &str) -> Result<IdentityClaims, CodexAuthError> {
    let claims = decode_jwt_payload::<IdClaims>(token)?;
    let Some(auth) = claims.auth else {
        return Ok(IdentityClaims::default());
    };
    Ok(IdentityClaims {
        account_id: normalized(auth.chatgpt_account_id),
        is_fedramp: auth.chatgpt_account_is_fedramp.unwrap_or(false),
        plan_type: normalized(auth.chatgpt_plan_type),
    })
}

fn decode_jwt_payload<T: DeserializeOwned>(token: &str) -> Result<T, CodexAuthError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(CodexAuthError::InvalidJwt);
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() || payload.len() > 64 * 1024
    {
        return Err(CodexAuthError::InvalidJwt);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| CodexAuthError::InvalidJwt)?;
    serde_json::from_slice(&bytes).map_err(|_| CodexAuthError::InvalidJwt)
}

fn reconcile_optional(
    field: &'static str,
    left: Option<String>,
    right: Option<String>,
) -> Result<Option<String>, CodexAuthError> {
    match (left, right) {
        (Some(left), Some(right)) if left != right => Err(CodexAuthError::ClaimMismatch(field)),
        (left, right) => Ok(left.or(right)),
    }
}

fn reconcile_optional_bool(
    left: Option<bool>,
    right: Option<bool>,
) -> Result<Option<bool>, CodexAuthError> {
    match (left, right) {
        (Some(left), Some(right)) if left != right => {
            Err(CodexAuthError::ClaimMismatch("is_fedramp"))
        }
        (left, right) => Ok(left.or(right)),
    }
}

fn validate_account_id(account_id: Option<&str>) -> Result<(), CodexAuthError> {
    if let Some(account_id) = account_id
        && reqwest::header::HeaderValue::from_str(account_id).is_err()
    {
        return Err(CodexAuthError::InvalidAccountId);
    }
    Ok(())
}

fn string_field<'a>(document: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    document.get(field).and_then(Value::as_str)
}

fn optional_string(document: &Map<String, Value>, field: &str) -> Option<String> {
    normalized(string_field(document, field).map(str::to_owned))
}

fn optional_i64(
    document: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<i64>, CodexAuthError> {
    match document.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or(CodexAuthError::InvalidField(field)),
    }
}

fn required_secret(document: &Map<String, Value>, field: &str) -> Option<SecretString> {
    string_field(document, field)
        .map(str::to_owned)
        .and_then(non_empty_secret)
}

fn non_empty_secret(value: String) -> Option<SecretString> {
    normalized(Some(value)).map(SecretString::from)
}

fn normalized(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Error)]
pub enum CodexAuthError {
    #[error("Codex credential JSON is invalid")]
    InvalidJson,
    #[error("Codex credential JSON must be an object")]
    NotObject,
    #[error("Codex credential must have type codex")]
    InvalidProviderType,
    #[error("Codex credential must have auth_kind oauth")]
    InvalidAuthKind,
    #[error("Codex credential is missing access_token")]
    MissingAccessToken,
    #[error("Codex credential is missing refresh_token")]
    MissingRefreshToken,
    #[error("Codex credential is missing id_token")]
    MissingIdToken,
    #[error("Codex credential is missing last_refreshed_at")]
    MissingLastRefreshedAt,
    #[error("Codex credential has invalid field {0}")]
    InvalidField(&'static str),
    #[error("Codex token is not a valid JWT")]
    InvalidJwt,
    #[error("Codex token claims disagree on {0}")]
    ClaimMismatch(&'static str),
    #[error("Codex account ID cannot be used as an HTTP header")]
    InvalidAccountId,
    #[error("Codex token refresh did not rotate any token")]
    EmptyRefreshResponse,
    #[error("stored provider account is not a Codex account")]
    InvalidStoredProvider,
    #[error("Codex account credential kind must be oauth")]
    InvalidCredentialKind,
    #[error("unsupported Codex credential format version {0}")]
    UnsupportedCredentialFormat(u32),
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use secrecy::ExposeSecret;

    use super::*;
    use crate::codex::identity::secret;

    #[test]
    fn accepts_opaque_access_tokens_and_redacts_debug_output() {
        let id_token = jwt(serde_json::json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "workspace-1",
                "chatgpt_account_is_fedramp": false,
                "chatgpt_plan_type": "plus"
            }
        }));
        let credentials = CodexCredentials::from_tokens(
            "opaque-access-token".to_owned(),
            "refresh-secret".to_owned(),
            id_token,
            10,
        )
        .expect("credentials");

        assert_eq!(credentials.account_id(), Some("workspace-1"));
        assert_eq!(credentials.expires_at(), None);
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("opaque-access-token"));
        assert!(!debug.contains("refresh-secret"));
        assert!(!debug.contains("workspace-1"));
        assert!(!debug.contains("plus"));
    }

    #[test]
    fn rejects_stored_workspace_mismatch() {
        let credential_json = SecretString::from(
            serde_json::json!({
                "type": "codex",
                "auth_kind": "oauth",
                "access_token": "opaque-access-token",
                "refresh_token": "refresh-secret",
                "id_token": jwt(serde_json::json!({
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "workspace-1"
                    }
                })),
                "account_id": "workspace-2",
                "is_fedramp": false,
                "last_refreshed_at": 10
            })
            .to_string(),
        );

        assert!(matches!(
            CodexCredentials::from_json(&credential_json),
            Err(CodexAuthError::ClaimMismatch("account_id"))
        ));
    }

    #[test]
    fn refresh_allows_plan_and_fedramp_changes_but_not_workspace_changes() {
        let current = CodexCredentials::from_tokens(
            jwt(serde_json::json!({ "exp": 100 })),
            "refresh-1".to_owned(),
            jwt(serde_json::json!({
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "workspace-1",
                    "chatgpt_account_is_fedramp": false,
                    "chatgpt_plan_type": "plus"
                }
            })),
            10,
        )
        .expect("current credentials");
        let refreshed = current
            .refreshed(
                RefreshedCodexTokens {
                    access_token: secret(jwt(serde_json::json!({ "exp": 200 }))),
                    refresh_token: None,
                    id_token: secret(jwt(serde_json::json!({
                        "https://api.openai.com/auth": {
                            "chatgpt_account_id": "workspace-1",
                            "chatgpt_account_is_fedramp": true,
                            "chatgpt_plan_type": "pro"
                        }
                    }))),
                },
                20,
            )
            .expect("refreshed credentials");
        let refreshed_json: Value = serde_json::from_str(
            refreshed
                .to_json()
                .expect("credential JSON")
                .expose_secret(),
        )
        .expect("credential document");

        assert_eq!(refreshed.expires_at(), Some(200));
        assert!(refreshed.is_fedramp());
        assert_eq!(refreshed_json["plan_type"], "pro");

        let mismatch = current.refreshed(
            RefreshedCodexTokens {
                access_token: None,
                refresh_token: secret("refresh-2".to_owned()),
                id_token: secret(jwt(serde_json::json!({
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "workspace-2"
                    }
                }))),
            },
            20,
        );
        assert!(matches!(
            mismatch,
            Err(CodexAuthError::ClaimMismatch("account_id"))
        ));
    }

    fn jwt(payload: Value) -> String {
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("encode JWT payload"));
        format!("e30.{payload}.sig")
    }
}
