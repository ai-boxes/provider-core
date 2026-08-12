ALTER TABLE provider_accounts
    ADD COLUMN priority INTEGER NOT NULL DEFAULT 0 CHECK (priority >= 0);

ALTER TABLE usage_attempts
    ADD COLUMN attempt_outcome TEXT CHECK (
        attempt_outcome IS NULL OR attempt_outcome IN ('succeeded', 'failed', 'cancelled')
    );

ALTER TABLE usage_attempts
    ADD COLUMN failover_reason TEXT CHECK (
        failover_reason IS NULL OR failover_reason IN (
            'authentication_exhausted',
            'quota_exhausted',
            'rate_limited',
            'preconnect_failure'
        )
    );

CREATE TRIGGER usage_attempts_failover_reason_check_insert
BEFORE INSERT ON usage_attempts
WHEN NEW.failover_reason IS NOT NULL AND NEW.attempt_outcome != 'failed'
BEGIN
    SELECT RAISE(ABORT, 'an attempt failover reason requires a failed attempt outcome');
END;

CREATE TRIGGER usage_attempts_failover_reason_check_update
BEFORE UPDATE OF attempt_outcome, failover_reason ON usage_attempts
WHEN NEW.failover_reason IS NOT NULL AND NEW.attempt_outcome != 'failed'
BEGIN
    SELECT RAISE(ABORT, 'an attempt failover reason requires a failed attempt outcome');
END;
