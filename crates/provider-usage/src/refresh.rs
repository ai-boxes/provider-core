//! Keeping the models.dev model catalog current without blocking requests.
//!
//! The fetch itself is behind [`CatalogSource`] so this crate needs no HTTP
//! client: the wiring layer supplies one, and tests supply a fake.
//!
//! What a refresh may never do:
//!
//! * Replace a working catalog with a broken one. A body that does not parse
//!   leaves the last known good snapshot in place and records why.
//! * Touch the request path. Only provider model refresh reads the installed
//!   snapshot; requests use catalog data already saved with their routed model.
//! * Fail startup. With no catalog at all, model prices remain unconfigured and
//!   model prices and capabilities remain unknown and the proxy is unaffected.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::{
    catalog::{CatalogParseError, CatalogPrices, CatalogSnapshot},
    repository::{StoredCatalog, UsageRepository},
    tracking::ClockMs,
};

/// How often the catalog is checked. Prices change on the order of months, so
/// this is about eventually noticing, not about being current to the minute.
pub const DEFAULT_REFRESH_PERIOD: Duration = Duration::from_secs(2 * 60 * 60);

/// The published catalog document.
pub const MODELS_DEV_URL: &str = "https://models.dev/api.json";

/// One catalog fetch attempt's result.
pub enum CatalogFetch {
    /// A body to consider installing.
    Fresh {
        body: String,
        etag: Option<String>,
        last_modified: Option<String>,
    },
    /// The upstream confirmed what we already hold is current.
    Unchanged,
}

/// Why a fetch did not produce a body. Carries a stable code, never an upstream
/// message: those end up in a database and an API response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogFetchError(pub &'static str);

#[async_trait]
pub trait CatalogSource: Send + Sync {
    /// Fetch the catalog, conditionally when validators are available.
    async fn fetch(
        &self,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<CatalogFetch, CatalogFetchError>;
}

/// What one refresh cycle did. Every variant is a safe, stable value suitable for
/// a health endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshOutcome {
    /// A new revision was stored and installed.
    Installed,
    /// The body was byte-identical to what is already held.
    AlreadyCurrent,
    /// The upstream answered `304`.
    Unchanged,
    /// Nothing was replaced; the reason code says why.
    Failed(&'static str),
}

/// Reason codes recorded against the stored catalog. Kept as constants so the
/// same string is never spelled two ways.
pub mod reason {
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    pub const BODY_MALFORMED: &str = "body_malformed";
    pub const BODY_EMPTY: &str = "body_empty";
    pub const STORE_FAILED: &str = "store_failed";
}

pub struct CatalogRefresher {
    repository: Arc<dyn UsageRepository>,
    source: Arc<dyn CatalogSource>,
    prices: Arc<CatalogPrices>,
    now_ms: ClockMs,
}

impl CatalogRefresher {
    #[must_use]
    pub fn new(
        repository: Arc<dyn UsageRepository>,
        source: Arc<dyn CatalogSource>,
        prices: Arc<CatalogPrices>,
        now_ms: ClockMs,
    ) -> Self {
        Self {
            repository,
            source,
            prices,
            now_ms,
        }
    }

    /// Install whatever catalog is already stored.
    ///
    /// Called at startup so a restart prices requests from the last known good
    /// catalog immediately, without waiting for a fetch. Returns the revision
    /// installed, if any.
    pub async fn install_stored(&self) -> Option<String> {
        let stored = self.repository.load_catalog().await.ok()??;
        match CatalogSnapshot::parse(&stored.body, stored.revision.clone()) {
            Ok(snapshot) => {
                let revision = snapshot.revision().to_owned();
                self.prices.install(Arc::new(snapshot));
                Some(revision)
            }
            // A stored body that no longer parses is left alone rather than
            // deleted: a future parser version may understand it, and deleting it
            // would remove the only fallback we have.
            Err(_) => None,
        }
    }

    /// Run one refresh cycle.
    pub async fn refresh_once(&self) -> RefreshOutcome {
        let held = self.repository.load_catalog().await.ok().flatten();
        let (etag, last_modified) = held.as_ref().map_or((None, None), |stored| {
            (stored.etag.clone(), stored.last_modified.clone())
        });

        let fetched = self
            .source
            .fetch(etag.as_deref(), last_modified.as_deref())
            .await;
        let now = (self.now_ms)();

        let fresh = match fetched {
            Ok(CatalogFetch::Fresh {
                body,
                etag,
                last_modified,
            }) => (body, etag, last_modified),
            Ok(CatalogFetch::Unchanged) => {
                self.note_check(now, None).await;
                return RefreshOutcome::Unchanged;
            }
            Err(CatalogFetchError(code)) => {
                self.note_check(now, Some(code)).await;
                return RefreshOutcome::Failed(code);
            }
        };
        let (body, etag, last_modified) = fresh;

        let revision = content_revision(&body);
        if held
            .as_ref()
            .is_some_and(|stored| stored.revision == revision)
        {
            // Same content under a changed validator: nothing to install, but the
            // validators are worth keeping so the next fetch can still be
            // conditional.
            self.note_check(now, None).await;
            return RefreshOutcome::AlreadyCurrent;
        }

        // Parsed before storing, so a body that cannot be used never displaces a
        // working one.
        let snapshot = match CatalogSnapshot::parse(&body, revision.clone()) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let code = match error {
                    CatalogParseError::TooLarge => reason::BODY_TOO_LARGE,
                    CatalogParseError::Malformed => reason::BODY_MALFORMED,
                };
                self.note_check(now, Some(code)).await;
                return RefreshOutcome::Failed(code);
            }
        };
        if snapshot.priced_model_count() == 0 {
            // Valid JSON that prices nothing is not an improvement on what we
            // hold, and installing it would silently stop pricing everything.
            self.note_check(now, Some(reason::BODY_EMPTY)).await;
            return RefreshOutcome::Failed(reason::BODY_EMPTY);
        }

        if self
            .repository
            .store_catalog(&StoredCatalog {
                revision,
                body,
                etag,
                last_modified,
                content_fetched_at_ms: now,
                last_checked_at_ms: now,
                last_error_code: None,
            })
            .await
            .is_err()
        {
            // The snapshot is deliberately not installed: memory and storage must
            // agree, or a restart would silently change historical pricing.
            return RefreshOutcome::Failed(reason::STORE_FAILED);
        }

        self.prices.install(Arc::new(snapshot));
        RefreshOutcome::Installed
    }

    /// Refresh forever, on `period`. Failures are recorded and retried on the
    /// next tick rather than escalating.
    pub async fn run(self: Arc<Self>, period: Duration) {
        let mut ticker = tokio::time::interval(period);
        // The immediate first tick is the startup refresh.
        loop {
            ticker.tick().await;
            self.refresh_once().await;
        }
    }

    async fn note_check(&self, now_ms: i64, error_code: Option<&str>) {
        // A no-op when nothing is stored yet: "never fetched" is already visible
        // from the absent row.
        let _ = self
            .repository
            .record_catalog_check(now_ms, error_code)
            .await;
    }
}

/// The catalog revision: SHA-256 of the exact bytes, hex encoded.
///
/// Content-addressed rather than validator-addressed, so storage and the
/// installed snapshot refer to the exact same document bytes.
#[must_use]
pub fn content_revision(body: &str) -> String {
    let digest = Sha256::digest(body.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::{component_prices_from_model_pricing, tests_support::TestRepository};

    const GOOD: &str = r#"{"openai":{"models":{"gpt-5-codex":{"modalities":{"input":["text","image","pdf"]},"cost":{"input":1,"output":2}}}}}"#;

    /// Serves whatever a test queues.
    struct FakeSource {
        answers: Mutex<Vec<Result<CatalogFetch, CatalogFetchError>>>,
    }

    impl FakeSource {
        fn new(answers: Vec<Result<CatalogFetch, CatalogFetchError>>) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers),
            })
        }
    }

    #[async_trait]
    impl CatalogSource for FakeSource {
        async fn fetch(
            &self,
            _etag: Option<&str>,
            _last_modified: Option<&str>,
        ) -> Result<CatalogFetch, CatalogFetchError> {
            let mut answers = self.answers.lock().expect("answers");
            if answers.is_empty() {
                return Ok(CatalogFetch::Unchanged);
            }
            answers.remove(0)
        }
    }

    fn fresh(body: &str, etag: &str) -> Result<CatalogFetch, CatalogFetchError> {
        Ok(CatalogFetch::Fresh {
            body: body.to_owned(),
            etag: Some(etag.to_owned()),
            last_modified: None,
        })
    }

    fn fixed_clock() -> i64 {
        1_700_000_000_000
    }

    struct Harness {
        refresher: CatalogRefresher,
        repository: Arc<TestRepository>,
        prices: Arc<CatalogPrices>,
    }

    fn harness(answers: Vec<Result<CatalogFetch, CatalogFetchError>>) -> Harness {
        let repository = Arc::new(TestRepository::default());
        let prices = Arc::new(CatalogPrices::new());
        let refresher = CatalogRefresher::new(
            repository.clone(),
            FakeSource::new(answers),
            prices.clone(),
            fixed_clock,
        );
        Harness {
            refresher,
            repository,
            prices,
        }
    }

    fn priced(prices: &CatalogPrices) -> Option<i128> {
        prices
            .current()?
            .exact_model_pricing("gpt-5-codex")
            .and_then(|pricing| component_prices_from_model_pricing(&pricing))
            .and_then(|prices| prices.uncached_input_per_million)
            .map(|price| price.as_scaled())
    }

    #[tokio::test]
    async fn refresh_installs_model_modalities_with_prices() {
        let harness = harness(vec![fresh(GOOD, "\"v1\"")]);

        assert_eq!(
            harness.refresher.refresh_once().await,
            RefreshOutcome::Installed
        );
        assert_eq!(
            harness
                .prices
                .current()
                .expect("installed catalog")
                .exact_model_input_modalities("gpt-5-codex"),
            Some(vec![
                provider_core::ProviderModelInputModality::Text,
                provider_core::ProviderModelInputModality::Image,
                provider_core::ProviderModelInputModality::Pdf,
            ])
        );
    }

    #[tokio::test]
    async fn a_malformed_body_never_displaces_working_prices() {
        let harness = harness(vec![fresh(GOOD, "\"v1\""), fresh("{not json", "\"v2\"")]);
        assert_eq!(
            harness.refresher.refresh_once().await,
            RefreshOutcome::Installed
        );
        let good_revision = harness.repository.catalog().expect("stored").revision;

        assert_eq!(
            harness.refresher.refresh_once().await,
            RefreshOutcome::Failed(reason::BODY_MALFORMED)
        );

        let stored = harness.repository.catalog().expect("stored");
        assert_eq!(
            stored.revision, good_revision,
            "the last known good catalog is still stored"
        );
        assert_eq!(
            stored.last_error_code,
            Some(reason::BODY_MALFORMED.to_owned())
        );
        assert!(
            priced(&harness.prices).is_some(),
            "and it is still pricing requests"
        );
    }

    #[tokio::test]
    async fn a_store_failure_leaves_memory_and_storage_agreeing() {
        // Installing in memory without storing would change pricing until the
        // next restart, then change it back.
        let repository = Arc::new(TestRepository {
            fail_catalog_store: true,
            ..TestRepository::default()
        });
        let prices = Arc::new(CatalogPrices::new());
        let refresher = CatalogRefresher::new(
            repository.clone(),
            FakeSource::new(vec![fresh(GOOD, "\"v1\"")]),
            prices.clone(),
            fixed_clock,
        );

        assert_eq!(
            refresher.refresh_once().await,
            RefreshOutcome::Failed(reason::STORE_FAILED)
        );
        assert_eq!(
            priced(&prices),
            None,
            "no model pricing is exposed from a revision that was never stored"
        );
    }
}
