use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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

    pub(crate) async fn pinned_client(&self) -> Result<reqwest::Client, ProviderError> {
        let url = reqwest::Url::parse(&self.base_url).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "compatible base URL is invalid",
            )
        })?;
        let host = url.host_str().ok_or_else(|| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "compatible base URL has no host",
            )
        })?;
        let port = url.port_or_known_default().ok_or_else(|| {
            ProviderError::new(
                ProviderErrorKind::Internal,
                "compatible base URL has no port",
            )
        })?;
        let parsed_host = host.trim_start_matches('[').trim_end_matches(']');
        let (addresses, resolve_host) = match parsed_host.parse::<IpAddr>() {
            Ok(address) => (vec![SocketAddr::new(address, port)], None),
            Err(_) => {
                let addresses = tokio::net::lookup_host((host, port)).await.map_err(|_| {
                    ProviderError::new(
                        ProviderErrorKind::Upstream,
                        "compatible upstream DNS resolution failed",
                    )
                })?;
                let mut addresses = addresses.collect::<Vec<_>>();
                addresses.sort_unstable();
                addresses.dedup();
                if addresses.is_empty() {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Upstream,
                        "compatible upstream DNS returned no addresses",
                    ));
                }
                (addresses, Some(host.to_owned()))
            }
        };
        if addresses.iter().any(|address| !is_public_ip(address.ip())) {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "compatible upstream DNS resolved to a non-public address",
            ));
        }
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
        if let Some(resolve_host) = resolve_host {
            builder = builder.resolve_to_addrs(&resolve_host, &addresses);
        }
        builder.build().map_err(|_| {
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
    let literal_address = url
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok());
    if literal_address.is_some_and(|address| !is_public_ip(address)) {
        return Err(ProviderConfigurationError::new(format!(
            "{provider} base_url must use a public address"
        )));
    }
    Ok(base_url)
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    const NON_PUBLIC: &[(u32, u32)] = &[
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc058_6300, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 3),
    ];
    let address = u32::from(address);
    !NON_PUBLIC
        .iter()
        .any(|(network, prefix)| matches_prefix_v4(address, *network, *prefix))
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    const GLOBAL_UNICAST: (u128, u32) = (0x2000_0000_0000_0000_0000_0000_0000_0000, 3);
    const NON_PUBLIC_GLOBAL_UNICAST: &[(u128, u32)] = &[
        (0x2001_0000_0000_0000_0000_0000_0000_0000, 23),
        (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),
        (0x2002_0000_0000_0000_0000_0000_0000_0000, 16),
        (0x3ffe_0000_0000_0000_0000_0000_0000_0000, 16),
        (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20),
    ];
    let address = u128::from(address);
    matches_prefix_v6(address, GLOBAL_UNICAST.0, GLOBAL_UNICAST.1)
        && !NON_PUBLIC_GLOBAL_UNICAST
            .iter()
            .any(|(network, prefix)| matches_prefix_v6(address, *network, *prefix))
}

fn matches_prefix_v4(address: u32, network: u32, prefix: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    address & mask == network & mask
}

fn matches_prefix_v6(address: u128, network: u128, prefix: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
    address & mask == network & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatible_base_url_requires_https_without_userinfo_or_private_literals() {
        for rejected in [
            "http://api.example.com/v1",
            "https://user:secret@api.example.com/v1",
            "https://127.0.0.1/v1",
            "https://127.1/v1",
            "https://2130706433/v1",
            "https://0x7f000001/v1",
            "https://10.0.0.1/v1",
            "https://[::1]/v1",
        ] {
            assert!(
                normalize_base_url("Compatible", rejected).is_err(),
                "{rejected}"
            );
        }
        assert_eq!(
            normalize_base_url("Compatible", " https://api.example.com/v1/ ")
                .expect("public HTTPS URL"),
            "https://api.example.com/v1"
        );
    }

    #[test]
    fn public_address_classification_rejects_special_purpose_ranges() {
        for rejected in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "3ffe::1",
            "3fff::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
        ] {
            let address = rejected.parse().expect("test IP address");
            assert!(!is_public_ip(address), "{rejected}");
        }

        for accepted in [
            "1.1.1.1",
            "8.8.8.8",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ] {
            let address = accepted.parse().expect("test IP address");
            assert!(is_public_ip(address), "{accepted}");
        }
    }

    #[tokio::test]
    async fn compatible_dns_rejects_private_results() {
        let config = CompatibleConfig {
            base_url: "https://localhost/v1".to_owned(),
        };
        let error = config
            .pinned_client()
            .await
            .expect_err("private DNS result");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
        assert_eq!(
            error.message(),
            "compatible upstream DNS resolved to a non-public address"
        );
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
