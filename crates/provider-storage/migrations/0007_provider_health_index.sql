CREATE INDEX usage_attempts_account_completed_idx
    ON usage_attempts (account_id, completed_at_ms);
