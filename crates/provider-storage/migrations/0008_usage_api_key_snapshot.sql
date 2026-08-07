ALTER TABLE usage_logical_requests
ADD COLUMN api_key_label TEXT;

ALTER TABLE usage_logical_requests
ADD COLUMN api_key_group_label TEXT
    CHECK (
        api_key_group_label IS NULL
        OR (
            length(trim(api_key_group_label)) > 0
            AND length(api_key_group_label) <= 64
        )
    );

CREATE INDEX usage_logical_requests_group_idx
    ON usage_logical_requests (owner_user_id, api_key_group_label, completed_at_ms DESC, request_id DESC);
