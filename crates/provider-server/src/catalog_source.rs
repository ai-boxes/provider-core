//! Fetching the models.dev catalog over HTTP.
//!
//! Lives here rather than in `provider-usage` so the crate that owns pricing has
//! no HTTP client and no network behaviour to reason about.
//!
//! Everything crossing this boundary is treated as untrusted: the body is read
//! with a hard cap rather than into an unbounded buffer, validators are length-
//! and charset-checked before being stored or echoed back, and every failure
//! becomes one of a fixed set of reason codes so an upstream message can never
//! reach the database or an API response.

use std::time::Duration;

use async_trait::async_trait;
use provider_core::{BoundedBodyError, collect_bounded_body};
use provider_usage::{
    CatalogFetch, CatalogFetchError, CatalogSource, MAX_CATALOG_BYTES, MODELS_DEV_URL, reason,
};
use reqwest::{
    StatusCode,
    header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED},
};

/// A whole refresh, including connecting, must not outlive this.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest validator we will store or send back. Real ones are tens of bytes.
const MAX_VALIDATOR_LEN: usize = 256;

const REQUEST_FAILED: &str = "request_failed";
const HTTP_STATUS: &str = "http_status";
const BODY_READ_FAILED: &str = "body_read_failed";
const BODY_NOT_UTF8: &str = "body_not_utf8";

pub struct HttpCatalogSource {
    client: reqwest::Client,
    url: String,
}

impl HttpCatalogSource {
    /// A source for the published models.dev catalog.
    pub fn models_dev() -> Result<Self, reqwest::Error> {
        Self::new(MODELS_DEV_URL)
    }

    pub fn new(url: impl Into<String>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder().timeout(FETCH_TIMEOUT).build()?,
            url: url.into(),
        })
    }
}

#[async_trait]
impl CatalogSource for HttpCatalogSource {
    async fn fetch(
        &self,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<CatalogFetch, CatalogFetchError> {
        let mut request = self.client.get(&self.url);
        // Conditional when we hold validators, so an unchanged catalog costs a
        // 304 rather than a few megabytes.
        if let Some(etag) = etag.and_then(safe_validator) {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = last_modified.and_then(safe_validator) {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }

        let response = request
            .send()
            .await
            .map_err(|_| CatalogFetchError(REQUEST_FAILED))?;

        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(CatalogFetch::Unchanged);
        }
        if !response.status().is_success() {
            // The status code itself is not recorded: a stable code is enough to
            // act on, and keeps unbounded upstream detail out of storage.
            return Err(CatalogFetchError(HTTP_STATUS));
        }

        let etag = header_validator(&response, &ETAG);
        let last_modified = header_validator(&response, &LAST_MODIFIED);

        let body = collect_bounded_body(response.bytes_stream(), MAX_CATALOG_BYTES)
            .await
            .map_err(|error| match error {
                BoundedBodyError::Read(_) => CatalogFetchError(BODY_READ_FAILED),
                BoundedBodyError::TooLarge => CatalogFetchError(reason::BODY_TOO_LARGE),
            })?;

        Ok(CatalogFetch::Fresh {
            body: String::from_utf8(body.to_vec()).map_err(|_| CatalogFetchError(BODY_NOT_UTF8))?,
            etag,
            last_modified,
        })
    }
}

fn header_validator(
    response: &reqwest::Response,
    name: &reqwest::header::HeaderName,
) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(safe_validator)
        .map(ToOwned::to_owned)
}

/// Accept a validator only if it is short and printable ASCII.
///
/// These are stored and sent back out as request headers, so anything with
/// control characters or unbounded length is dropped rather than carried around.
fn safe_validator(value: &str) -> Option<&str> {
    let usable = !value.is_empty()
        && value.len() <= MAX_VALIDATOR_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ');
    usable.then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_validator_that_could_not_be_sent_back_safely_is_dropped() {
        // A newline in a stored validator would be re-sent as a request header.
        assert_eq!(safe_validator("\"abc\"\r\nX-Injected: 1"), None);
        assert_eq!(safe_validator("\t"), None);
        assert_eq!(safe_validator(""), None);
        assert_eq!(safe_validator(&"x".repeat(MAX_VALIDATOR_LEN + 1)), None);
        // Exactly at the limit is still fine.
        assert_eq!(
            safe_validator(&"x".repeat(MAX_VALIDATOR_LEN)).map(str::len),
            Some(MAX_VALIDATOR_LEN)
        );
    }
}
