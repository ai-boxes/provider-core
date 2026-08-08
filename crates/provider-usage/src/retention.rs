//! Deleting raw usage facts once they are older than the retention window.
//!
//! Three rules, each of which exists because breaking it corrupts history rather
//! than merely inconveniencing someone:
//!
//! 1. **Delete by logical unit, never by attempt.** The cutoff is the logical
//!    request's terminal time. Filtering on an attempt's own time would delete a
//!    retry while keeping the request that owned it, leaving totals that no longer
//!    add up.
//! 2. **Never touch a request that has not finished.** An in-flight request has no
//!    terminal time to compare, and deleting it would erase a fact still being
//!    written.
//! 3. **Small batches.** Retention shares a database with the proxy's own writes,
//!    so it takes many short transactions rather than one long one.

use std::{sync::Arc, time::Duration};

use crate::{repository::UsageRepository, tracking::ClockMs};

/// How long raw facts are kept. Also the widest range a query may ask for: a
/// wider one would read as empty rather than as unavailable.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Logical requests removed per transaction.
pub const DEFAULT_RETENTION_BATCH: u32 = 500;

/// How often retention runs. Facts expire continuously, so there is nothing to
/// gain from checking more often than this.
pub const DEFAULT_RETENTION_PERIOD: Duration = Duration::from_secs(60 * 60);

/// What one retention cycle removed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetentionReport {
    pub logical_requests_deleted: u64,
    pub gap_buckets_deleted: u64,
}

pub struct RetentionWorker {
    repository: Arc<dyn UsageRepository>,
    retention: Duration,
    batch: u32,
    now_ms: ClockMs,
}

impl RetentionWorker {
    #[must_use]
    pub fn new(repository: Arc<dyn UsageRepository>, now_ms: ClockMs) -> Self {
        Self {
            repository,
            retention: DEFAULT_RETENTION,
            batch: DEFAULT_RETENTION_BATCH,
            now_ms,
        }
    }

    #[must_use]
    pub const fn with_window(mut self, retention: Duration, batch: u32) -> Self {
        self.retention = retention;
        self.batch = batch;
        self
    }

    /// The instant before which facts are no longer kept.
    #[must_use]
    pub fn cutoff_ms(&self) -> i64 {
        let window = i64::try_from(self.retention.as_millis())
            .expect("usage retention window must fit i64 milliseconds");
        (self.now_ms)().saturating_sub(window)
    }

    /// Run one cycle. Errors end the cycle rather than being retried in a tight
    /// loop; whatever is left is picked up next time.
    pub async fn run_once(&self) -> RetentionReport {
        let cutoff = self.cutoff_ms();
        let mut report = RetentionReport::default();

        loop {
            match self
                .repository
                .delete_logical_requests_before(cutoff, self.batch)
                .await
            {
                Ok(deleted) => {
                    report.logical_requests_deleted += deleted;
                    // A short batch means the tail was reached.
                    if deleted < u64::from(self.batch) {
                        break;
                    }
                }
                Err(_) => return report,
            }
        }

        // Gap buckets use the same bounded statements and must also catch up.
        loop {
            match self
                .repository
                .delete_tracking_gaps_before(cutoff, self.batch)
                .await
            {
                Ok(deleted) => {
                    report.gap_buckets_deleted += deleted;
                    if deleted < u64::from(self.batch) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        report
    }

    /// Run forever, on `period`.
    pub async fn run(self: Arc<Self>, period: Duration) {
        let mut ticker = tokio::time::interval(period);
        loop {
            ticker.tick().await;
            self.run_once().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::TestRepository;

    const NOW: i64 = 1_700_000_000_000;
    const DAY: i64 = 24 * 60 * 60 * 1000;

    fn fixed_clock() -> i64 {
        NOW
    }

    fn worker(repository: Arc<TestRepository>, batch: u32) -> RetentionWorker {
        RetentionWorker::new(repository, fixed_clock)
            .with_window(Duration::from_millis(30 * DAY as u64), batch)
    }

    #[tokio::test]
    async fn only_facts_older_than_the_window_are_deleted() {
        let repository = Arc::new(TestRepository::default());
        *repository.expired_requests.lock().expect("lock") = vec![
            NOW - 60 * DAY, // expired
            NOW - 31 * DAY, // expired
            NOW - 29 * DAY, // inside the window
            NOW - DAY,      // recent
        ];

        let report = worker(repository.clone(), 100).run_once().await;
        assert_eq!(report.logical_requests_deleted, 2);
        assert_eq!(
            *repository.expired_requests.lock().expect("lock"),
            vec![NOW - 29 * DAY, NOW - DAY],
            "anything still inside the window stays"
        );
    }

    #[tokio::test]
    async fn one_cycle_drains_backlog_beyond_the_old_fixed_cap_in_small_batches() {
        let repository = Arc::new(TestRepository::default());
        *repository.expired_requests.lock().expect("lock") = vec![NOW - 60 * DAY; 20_501];
        *repository.expired_gap_buckets.lock().expect("lock") = vec![NOW - 60 * DAY; 1_201];

        let report = worker(repository.clone(), 500).run_once().await;

        assert_eq!(report.logical_requests_deleted, 20_501);
        assert_eq!(report.gap_buckets_deleted, 1_201);
        assert!(repository.expired_requests.lock().expect("lock").is_empty());
        assert!(
            repository
                .expired_gap_buckets
                .lock()
                .expect("lock")
                .is_empty()
        );
        assert!(
            repository
                .retention_batches
                .lock()
                .expect("lock")
                .iter()
                .all(|batch| *batch == 500),
            "every delete remains a bounded batch statement"
        );
    }
}
