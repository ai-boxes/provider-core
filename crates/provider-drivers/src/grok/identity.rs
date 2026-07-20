pub(crate) const DEFAULT_PROXY_BASE_URL: &str = "https://cli-chat-proxy.grok.com/v1";
pub(crate) const CLIENT_VERSION: &str = "0.2.105";
pub(crate) const CLIENT_MODE: &str = "headless";
pub(crate) const CLIENT_IDENTIFIER: &str = "grok-shell";
pub(crate) const TOKEN_AUTH_HEADER: &str = "X-XAI-Token-Auth";
pub(crate) const TOKEN_AUTH_VALUE: &str = "xai-grok-cli";

pub(crate) fn user_agent() -> String {
    format!(
        "grok-shell/{CLIENT_VERSION} ({}; {})",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}
