//! A recording [`UsageRepository`] double shared by the writer and tracker tests.
//!
//! It records what was written and can be told to fail, so tests can assert both
//! the happy path and the fail-open behaviour without a database.

use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;

use crate::{
    attempt::TrackingGapReason,
    repository::{
        AttemptFacts, LogicalRequestStart, LogicalRequestTerminal, LogicalWriteOutcome,
        QuotaLedgerEntry, StoredCatalog, StoredLogicalRequest, UsageRepository,
        UsageRepositoryError,
    },
};

#[derive(Default)]
pub(crate) struct TestRepository {
    // Public so tests can use struct-update syntax to flip only the switch they
    // care about; read them through the accessors below.
    pub attempts: Mutex<Vec<AttemptFacts>>,
    pub terminals: Mutex<Vec<LogicalRequestTerminal>>,
    pub gaps: Mutex<Vec<(String, TrackingGapReason, i64, u64)>>,
    pub quota_entries: Mutex<Vec<QuotaLedgerEntry>>,
    pub catalog: Mutex<Option<StoredCatalog>>,
    /// The logical start write fails, as a full or read-only database would.
    pub fail_start: bool,
    /// Attempt and terminal writes fail.
    pub fail_facts: bool,
    /// Quota persistence panics so tests can verify worker-loss readiness.
    pub panic_quota: bool,
    /// Even the gap write fails, leaving nothing but an in-memory count.
    pub fail_gaps: bool,
    /// Report a terminal whose logical start never landed.
    pub terminal_is_orphaned: bool,
    /// Held for the duration of each fact write, to stall the writer on demand.
    pub stall: Option<Arc<tokio::sync::Mutex<()>>>,
    /// Storing a catalog fails, as a full or read-only database would.
    pub fail_catalog_store: bool,
    /// Retention deletes fail.
    pub fail_deletes: bool,
    /// Terminal times of requests retention may remove.
    pub expired_requests: Mutex<Vec<i64>>,
    /// Resolution times of quota-ledger entries retention may remove.
    pub expired_quota_entries: Mutex<Vec<i64>>,
    /// Bucket times of tracking gaps retention may remove.
    pub expired_gap_buckets: Mutex<Vec<i64>>,
    /// Batch sizes passed to retention delete calls.
    pub retention_batches: Mutex<Vec<u32>>,
}

impl TestRepository {
    pub(crate) fn attempts(&self) -> Vec<AttemptFacts> {
        guard(&self.attempts).clone()
    }

    pub(crate) fn terminals(&self) -> Vec<LogicalRequestTerminal> {
        guard(&self.terminals).clone()
    }

    pub(crate) fn gaps(&self) -> Vec<(String, TrackingGapReason, i64, u64)> {
        guard(&self.gaps).clone()
    }

    pub(crate) fn quota_entries(&self) -> Vec<QuotaLedgerEntry> {
        guard(&self.quota_entries).clone()
    }

    pub(crate) fn gap_count(&self, reason: TrackingGapReason) -> u64 {
        guard(&self.gaps)
            .iter()
            .filter(|(_, stored, _, _)| *stored == reason)
            .map(|(_, _, _, count)| *count)
            .sum()
    }

    pub(crate) fn catalog(&self) -> Option<StoredCatalog> {
        guard(&self.catalog).clone()
    }

    async fn hold(&self) {
        if let Some(stall) = &self.stall {
            let _guard = stall.lock().await;
        }
    }
}

fn guard<T>(slot: &Mutex<T>) -> MutexGuard<'_, T> {
    slot.lock().unwrap_or_else(|error| error.into_inner())
}

fn unavailable() -> UsageRepositoryError {
    UsageRepositoryError::new("database is unavailable")
}

#[async_trait]
impl UsageRepository for TestRepository {
    async fn begin_logical_request(
        &self,
        _start: &LogicalRequestStart,
    ) -> Result<LogicalWriteOutcome, UsageRepositoryError> {
        if self.fail_start {
            return Err(unavailable());
        }
        Ok(LogicalWriteOutcome::Written)
    }

    async fn complete_logical_request(
        &self,
        terminal: &LogicalRequestTerminal,
    ) -> Result<LogicalWriteOutcome, UsageRepositoryError> {
        self.hold().await;
        if self.fail_facts {
            return Err(unavailable());
        }
        guard(&self.terminals).push(terminal.clone());
        Ok(if self.terminal_is_orphaned {
            LogicalWriteOutcome::MissingRequest
        } else {
            LogicalWriteOutcome::Written
        })
    }

    async fn record_attempt(&self, facts: &AttemptFacts) -> Result<(), UsageRepositoryError> {
        self.hold().await;
        if self.fail_facts {
            return Err(unavailable());
        }
        guard(&self.attempts).push(facts.clone());
        Ok(())
    }

    async fn record_quota_ledger_entry(
        &self,
        entry: &crate::repository::QuotaLedgerEntry,
    ) -> Result<(), UsageRepositoryError> {
        assert!(!self.panic_quota, "quota worker test panic");
        self.hold().await;
        if self.fail_facts {
            return Err(unavailable());
        }
        guard(&self.quota_entries).push(entry.clone());
        Ok(())
    }

    async fn recover_quota_reservations(&self, _now_ms: i64) -> Result<u64, UsageRepositoryError> {
        Ok(0)
    }

    async fn record_tracking_gap(
        &self,
        owner_user_id: &str,
        reason: TrackingGapReason,
        bucket_start_ms: i64,
        count: u64,
    ) -> Result<(), UsageRepositoryError> {
        if self.fail_gaps {
            return Err(unavailable());
        }
        guard(&self.gaps).push((owner_user_id.to_owned(), reason, bucket_start_ms, count));
        Ok(())
    }

    async fn recover_in_flight_requests(&self, _now_ms: i64) -> Result<u64, UsageRepositoryError> {
        Ok(0)
    }

    async fn load_logical_request(
        &self,
        _request_id: &str,
    ) -> Result<Option<StoredLogicalRequest>, UsageRepositoryError> {
        Ok(None)
    }

    async fn load_attempts(
        &self,
        _request_id: &str,
    ) -> Result<Vec<AttemptFacts>, UsageRepositoryError> {
        Ok(Vec::new())
    }

    async fn delete_resolved_quota_ledger_entries_before(
        &self,
        cutoff_ms: i64,
        batch: u32,
    ) -> Result<u64, UsageRepositoryError> {
        if self.fail_deletes {
            return Err(unavailable());
        }
        guard(&self.retention_batches).push(batch);
        let mut expired = guard(&self.expired_quota_entries);
        let deletable = expired
            .iter()
            .filter(|resolved_at_ms| **resolved_at_ms < cutoff_ms)
            .count()
            .min(batch as usize);
        let mut deleted = 0;
        expired.retain(|resolved_at_ms| {
            if *resolved_at_ms < cutoff_ms && deleted < deletable {
                deleted += 1;
                false
            } else {
                true
            }
        });
        Ok(deleted as u64)
    }

    async fn delete_logical_requests_before(
        &self,
        cutoff_ms: i64,
        batch: u32,
    ) -> Result<u64, UsageRepositoryError> {
        if self.fail_deletes {
            return Err(unavailable());
        }
        guard(&self.retention_batches).push(batch);
        let mut expired = guard(&self.expired_requests);
        let deletable = expired
            .iter()
            .filter(|completed_at_ms| **completed_at_ms < cutoff_ms)
            .count()
            .min(batch as usize);
        let mut deleted = 0;
        expired.retain(|completed_at_ms| {
            if *completed_at_ms < cutoff_ms && deleted < deletable {
                deleted += 1;
                false
            } else {
                true
            }
        });
        Ok(deleted as u64)
    }

    async fn delete_tracking_gaps_before(
        &self,
        cutoff_ms: i64,
        batch: u32,
    ) -> Result<u64, UsageRepositoryError> {
        if self.fail_deletes {
            return Err(unavailable());
        }
        guard(&self.retention_batches).push(batch);
        let mut expired = guard(&self.expired_gap_buckets);
        let last_expired_bucket = cutoff_ms.saturating_sub(crate::GAP_BUCKET_MS);
        let deletable = expired
            .iter()
            .filter(|bucket_start_ms| **bucket_start_ms <= last_expired_bucket)
            .count()
            .min(batch as usize);
        let mut deleted = 0;
        expired.retain(|bucket_start_ms| {
            if *bucket_start_ms <= last_expired_bucket && deleted < deletable {
                deleted += 1;
                false
            } else {
                true
            }
        });
        Ok(deleted as u64)
    }

    async fn load_catalog(&self) -> Result<Option<StoredCatalog>, UsageRepositoryError> {
        Ok(self.catalog())
    }

    async fn store_catalog(&self, catalog: &StoredCatalog) -> Result<(), UsageRepositoryError> {
        if self.fail_catalog_store {
            return Err(unavailable());
        }
        *guard(&self.catalog) = Some(catalog.clone());
        Ok(())
    }

    async fn record_catalog_check(
        &self,
        checked_at_ms: i64,
        error_code: Option<&str>,
    ) -> Result<(), UsageRepositoryError> {
        // Mirrors the real repository: a check never replaces the body.
        if let Some(catalog) = guard(&self.catalog).as_mut() {
            catalog.last_checked_at_ms = checked_at_ms;
            catalog.last_error_code = error_code.map(ToOwned::to_owned);
        }
        Ok(())
    }
}
