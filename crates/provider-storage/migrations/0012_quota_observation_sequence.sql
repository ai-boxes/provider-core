ALTER TABLE provider_quota_window_observations RENAME TO old_quota_observations;
DROP INDEX provider_quota_observations_history_idx;

CREATE TABLE provider_quota_window_observations (
    observation_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL REFERENCES provider_accounts(id) ON DELETE CASCADE,
    credential_revision INTEGER NOT NULL CHECK (credential_revision >= 0),
    credential_identity_revision INTEGER NOT NULL CHECK (credential_identity_revision >= 0),
    observed_at_ms INTEGER NOT NULL,
    group_key TEXT NOT NULL CHECK (length(group_key) > 0),
    metric_key TEXT NOT NULL CHECK (length(metric_key) > 0),
    metric_position INTEGER NOT NULL CHECK (metric_position >= 0),
    used_hundredths INTEGER NOT NULL CHECK (used_hundredths BETWEEN 0 AND 10000),
    period_kind TEXT NOT NULL CHECK (period_kind IN ('weekly', 'monthly', 'rolling')),
    starts_at_ms INTEGER NOT NULL,
    ends_at_ms INTEGER NOT NULL,
    duration_seconds INTEGER,
    CHECK (ends_at_ms > starts_at_ms),
    CHECK (observed_at_ms >= starts_at_ms AND observed_at_ms <= ends_at_ms),
    CHECK (duration_seconds IS NULL OR duration_seconds > 0)
);

INSERT INTO provider_quota_window_observations
SELECT rowid, account_id, credential_revision, credential_identity_revision,
    observed_at_ms, group_key, metric_key, metric_position, used_hundredths,
    period_kind, starts_at_ms, ends_at_ms, duration_seconds
FROM old_quota_observations ORDER BY rowid;
DROP TABLE old_quota_observations;

CREATE INDEX provider_quota_observations_history_idx
ON provider_quota_window_observations (
    account_id, credential_identity_revision, ends_at_ms DESC, group_key, metric_position
);
CREATE INDEX provider_quota_observations_sequence_idx
ON provider_quota_window_observations (
    account_id, credential_identity_revision, group_key, metric_key, observation_sequence DESC
);
