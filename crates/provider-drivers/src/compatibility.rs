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
    pub api_key: SecretString,
}

impl CompatibleCredentials {
    pub(crate) fn from_input(
        api_key: SecretString,
    ) -> Result<(CredentialKind, SecretString), ProviderConfigurationError> {
        let api_key = api_key.expose_secret().trim().to_owned();
        if api_key.is_empty() {
            return Err(ProviderConfigurationError::new(
                "compatible provider api_key must not be empty",
            ));
        }
        let credential_json = serde_json::to_string(&CredentialDocument {
            auth_kind: CredentialKind::ApiKey.as_str(),
            api_key: &api_key,
        })
        .map(SecretString::from)
        .map_err(|_| ProviderConfigurationError::new("failed to serialize provider credential"))?;
        Ok((CredentialKind::ApiKey, credential_json))
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
        if kind != CredentialKind::ApiKey {
            return Err(ProviderConfigurationError::new(format!(
                "{provider} requires API key credentials"
            )));
        }
        let api_key = document.api_key.trim().to_owned();
        if api_key.is_empty() {
            return Err(ProviderConfigurationError::new(format!(
                "{provider} credential is missing api_key"
            )));
        }
        Ok(Self {
            api_key: SecretString::from(api_key),
        })
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
    api_key: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialDocumentOwned {
    auth_kind: String,
    api_key: String,
}
