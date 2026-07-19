use provider_core::{CredentialKind, ProviderConfigurationError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct CompatibleConfig {
    pub base_url: String,
}

impl CompatibleConfig {
    pub(crate) fn parse(
        provider: &str,
        config_json: &str,
    ) -> Result<Self, ProviderConfigurationError> {
        let mut config: Self = serde_json::from_str(config_json).map_err(|_| {
            ProviderConfigurationError::new(format!("{provider} configuration must be valid JSON"))
        })?;
        config.base_url = normalize_base_url(provider, &config.base_url)?;
        Ok(config)
    }

    pub(crate) fn to_json(&self) -> Result<String, ProviderConfigurationError> {
        serde_json::to_string(self).map_err(|_| {
            ProviderConfigurationError::new("failed to serialize provider configuration")
        })
    }
}

#[derive(Clone)]
pub(crate) struct CompatibleCredentials {
    pub api_key: Option<SecretString>,
}

impl CompatibleCredentials {
    pub(crate) fn from_input(
        api_key: Option<SecretString>,
    ) -> Result<(CredentialKind, SecretString), ProviderConfigurationError> {
        let api_key = api_key
            .map(|value| value.expose_secret().trim().to_owned())
            .filter(|value| !value.is_empty());
        let kind = if api_key.is_some() {
            CredentialKind::ApiKey
        } else {
            CredentialKind::None
        };
        let credential_json = serde_json::to_string(&CredentialDocument {
            auth_kind: kind.as_str(),
            api_key: api_key.as_deref(),
        })
        .map(SecretString::from)
        .map_err(|_| ProviderConfigurationError::new("failed to serialize provider credential"))?;
        Ok((kind, credential_json))
    }

    pub(crate) fn parse(
        provider: &str,
        kind: CredentialKind,
        credential_json: &SecretString,
    ) -> Result<Self, ProviderConfigurationError> {
        let document: CredentialDocumentOwned =
            serde_json::from_str(credential_json.expose_secret()).map_err(|_| {
                ProviderConfigurationError::new(format!("{provider} credential must be valid JSON"))
            })?;
        if document.auth_kind.trim() != kind.as_str() {
            return Err(ProviderConfigurationError::new(format!(
                "{provider} credential type does not match credential_kind"
            )));
        }
        let api_key = document
            .api_key
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(SecretString::from);
        match kind {
            CredentialKind::ApiKey if api_key.is_none() => Err(ProviderConfigurationError::new(
                format!("{provider} credential is missing api_key"),
            )),
            CredentialKind::None if api_key.is_some() => Err(ProviderConfigurationError::new(
                format!("{provider} credential_kind none must not contain api_key"),
            )),
            CredentialKind::Oauth => Err(ProviderConfigurationError::new(format!(
                "{provider} does not support OAuth credentials"
            ))),
            _ => Ok(Self { api_key }),
        }
    }
}

pub(crate) fn normalize_label(
    provider: &str,
    label: &str,
) -> Result<String, ProviderConfigurationError> {
    let label = label.trim().to_owned();
    if label.is_empty() {
        return Err(ProviderConfigurationError::new(format!(
            "{provider} account label must not be empty"
        )));
    }
    Ok(label)
}

fn normalize_base_url(
    provider: &str,
    base_url: &str,
) -> Result<String, ProviderConfigurationError> {
    let base_url = base_url.trim().trim_end_matches('/').to_owned();
    let url = reqwest::Url::parse(&base_url).map_err(|_| {
        ProviderConfigurationError::new(format!("{provider} base_url must be an absolute URL"))
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ProviderConfigurationError::new(format!(
            "{provider} base_url must use HTTP or HTTPS and include a host"
        )));
    }
    Ok(base_url)
}

#[derive(Serialize)]
struct CredentialDocument<'a> {
    auth_kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key: Option<&'a str>,
}

#[derive(Deserialize)]
struct CredentialDocumentOwned {
    auth_kind: String,
    api_key: Option<String>,
}
