use provider_core::{CredentialKind, ProviderConfigurationError, ProviderError, ProviderErrorKind};
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

    pub(crate) fn build_client(&self) -> Result<reqwest::Client, ProviderError> {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| {
                ProviderError::new(
                    ProviderErrorKind::Internal,
                    "failed to build compatible upstream client",
                )
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
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(ProviderConfigurationError::new(format!(
            "{provider} base_url must use HTTPS and include a host"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ProviderConfigurationError::new(format!(
            "{provider} base_url must not contain userinfo"
        )));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ProviderConfigurationError::new(format!(
            "{provider} base_url must not contain a query or fragment"
        )));
    }
    Ok(base_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatible_base_url_requires_https_without_userinfo() {
        for rejected in [
            "http://api.example.com/v1",
            "https://user:secret@api.example.com/v1",
        ] {
            assert!(
                normalize_base_url("Compatible", rejected).is_err(),
                "{rejected}"
            );
        }
        assert_eq!(
            normalize_base_url("Compatible", " https://api.example.com/v1/ ")
                .expect("valid HTTPS URL"),
            "https://api.example.com/v1"
        );

        for accepted in [
            "https://127.0.0.1/v1",
            "https://127.1/v1",
            "https://2130706433/v1",
            "https://0x7f000001/v1",
            "https://10.0.0.1/v1",
            "https://[::1]/v1",
            "https://localhost/v1",
            "https://models.internal/v1",
        ] {
            assert!(
                normalize_base_url("Compatible", accepted).is_ok(),
                "{accepted}"
            );
        }
    }
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
