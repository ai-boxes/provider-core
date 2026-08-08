ALTER TABLE api_key_quota_ledger RENAME TO api_key_quota_ledger_with_key_fk;

CREATE TABLE api_key_quota_ledger (
    entry_id TEXT PRIMARY KEY NOT NULL,
    api_key_id TEXT NOT NULL,
    cost_atoms TEXT,
    accounting_state TEXT NOT NULL CHECK (accounting_state IN ('charged', 'indeterminate')),
    recorded_at_ms INTEGER NOT NULL,
    CHECK (
        (accounting_state = 'charged' AND cost_atoms IS NOT NULL)
        OR (accounting_state = 'indeterminate' AND cost_atoms IS NULL)
    ),
    CHECK (
        cost_atoms IS NULL OR (
            length(cost_atoms) > 0 AND length(cost_atoms) <= 64
            AND cost_atoms GLOB '[0-9]*' AND cost_atoms NOT GLOB '*[^0-9]*'
        )
    )
);

INSERT INTO api_key_quota_ledger (
    entry_id, api_key_id, cost_atoms, accounting_state, recorded_at_ms
)
SELECT entry_id, api_key_id, cost_atoms, accounting_state, recorded_at_ms
FROM api_key_quota_ledger_with_key_fk;

DROP TABLE api_key_quota_ledger_with_key_fk;

CREATE INDEX api_key_quota_ledger_key_idx
ON api_key_quota_ledger (api_key_id, recorded_at_ms, entry_id);
