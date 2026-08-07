ALTER TABLE usage_logical_requests
ADD COLUMN reasoning_effort TEXT
    CHECK (
        reasoning_effort IS NULL
        OR (
            length(trim(reasoning_effort)) > 0
            AND length(reasoning_effort) <= 32
        )
    );

ALTER TABLE usage_attempts
ADD COLUMN first_token_at_ms INTEGER
    CHECK (
        first_token_at_ms IS NULL
        OR (
            first_token_at_ms >= started_at_ms
            AND first_token_at_ms <= completed_at_ms
        )
    );
