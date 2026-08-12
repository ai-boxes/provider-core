use reqwest::RequestBuilder;

pub(crate) const DEFAULT_PROXY_BASE_URL: &str = "https://cli-chat-proxy.grok.com/v1";
pub(crate) const CLIENT_VERSION: &str = "1.0.0";
pub(crate) const CLIENT_MODE: &str = "headless";
pub(crate) const CLIENT_IDENTIFIER: &str = "grok-shell";
const TOKEN_AUTH_HEADER: &str = "X-XAI-Token-Auth";
const TOKEN_AUTH_VALUE: &str = "xai-grok-cli";

pub(crate) fn user_agent() -> String {
    format!(
        "grok-shell/{CLIENT_VERSION} ({}; {})",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

pub(crate) fn session_headers(request: RequestBuilder) -> RequestBuilder {
    client_headers(request).header(TOKEN_AUTH_HEADER, TOKEN_AUTH_VALUE)
}

pub(crate) fn inference_headers(request: RequestBuilder) -> RequestBuilder {
    session_headers(request)
        .header("x-authenticateresponse", "authenticate-response")
        .header("x-grok-client-identifier", CLIENT_IDENTIFIER)
}

fn client_headers(request: RequestBuilder) -> RequestBuilder {
    request
        .header("x-grok-client-version", CLIENT_VERSION)
        .header("x-grok-client-mode", CLIENT_MODE)
        .header(reqwest::header::USER_AGENT, user_agent())
}
