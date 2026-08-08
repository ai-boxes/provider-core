use std::{io, net::IpAddr};

/// Default bind address for local (non-container) runs.
pub(crate) const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:8317";

/// Override with host:port, e.g. `0.0.0.0:8317` inside Docker.
pub(crate) const LISTEN_ADDRESS_ENV: &str = "PODE_LISTEN_ADDRESS";

pub(crate) const DATABASE_PATH: &str = "data/provider-core.db";

/// Set to `0`, `false` or `off` to stop fetching the models.dev price catalog.
pub(crate) const CATALOG_SYNC_ENV: &str = "PODE_CATALOG_SYNC";

/// Exact reverse-proxy peer allowed to supply the client IP header.
pub(crate) const TRUSTED_PROXY_IP_ENV: &str = "PODE_TRUSTED_PROXY_IP";

/// Resolved listen address. Docker sets `PODE_LISTEN_ADDRESS=0.0.0.0:8317`.
pub(crate) fn listen_address() -> String {
    std::env::var(LISTEN_ADDRESS_ENV).unwrap_or_else(|_| DEFAULT_LISTEN_ADDRESS.to_owned())
}

/// Whether to keep the price catalog up to date over the network.
///
/// On by default: without a catalog every cost is `unavailable`, which reads like
/// a bug rather than a choice. The switch exists so an operator who does not want
/// the outbound request can turn it off and still get token counts.
pub(crate) fn catalog_sync_enabled() -> bool {
    match std::env::var(CATALOG_SYNC_ENV) {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

pub(crate) fn trusted_proxy_ip() -> Result<Option<IpAddr>, io::Error> {
    match std::env::var(TRUSTED_PROXY_IP_ENV) {
        Ok(value) => value.trim().parse().map(Some).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{TRUSTED_PROXY_IP_ENV} must be one IP address: {error}"),
            )
        }),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{TRUSTED_PROXY_IP_ENV} is invalid: {error}"),
        )),
    }
}
