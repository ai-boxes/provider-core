CREATE TABLE IF NOT EXISTS api_key_plaintext_recovery (
    id TEXT PRIMARY KEY NOT NULL,
    key TEXT NOT NULL UNIQUE
);

CREATE TABLE api_keys_with_plaintext (
    id TEXT PRIMARY KEY NOT NULL,
    owner_user_id TEXT NOT NULL,
    group_label TEXT NOT NULL CHECK (length(trim(group_label)) > 0 AND length(group_label) <= 64),
    label TEXT NOT NULL,
    key TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    expires_at INTEGER,
    quota_limit_atoms TEXT CHECK (
        quota_limit_atoms IS NULL OR (
            length(quota_limit_atoms) > 0 AND length(quota_limit_atoms) <= 64
            AND quota_limit_atoms GLOB '[1-9]*' AND quota_limit_atoms NOT GLOB '*[^0-9]*'
        )
    ),
    spent_atoms TEXT NOT NULL DEFAULT '0' CHECK (
        length(spent_atoms) > 0 AND length(spent_atoms) <= 64
        AND spent_atoms GLOB '[0-9]*' AND spent_atoms NOT GLOB '*[^0-9]*'
    ),
    quota_accounting_state TEXT NOT NULL DEFAULT 'ready'
        CHECK (quota_accounting_state IN ('ready', 'indeterminate')),
    last_used_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO api_keys_with_plaintext (
    id, owner_user_id, group_label, label, key, enabled, expires_at,
    quota_limit_atoms, spent_atoms, quota_accounting_state, last_used_at, created_at, updated_at
)
SELECT
    k.id, k.owner_user_id, k.group_label, k.label, r.key, k.enabled, k.expires_at,
    k.quota_limit_atoms, k.spent_atoms, k.quota_accounting_state, k.last_used_at,
    k.created_at, k.updated_at
FROM api_keys AS k
INNER JOIN api_key_plaintext_recovery AS r ON r.id = k.id;

CREATE TABLE api_key_plaintext_migration_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
);

INSERT INTO api_key_plaintext_migration_guard (valid)
SELECT CASE
    WHEN (SELECT COUNT(*) FROM api_keys) = (SELECT COUNT(*) FROM api_keys_with_plaintext)
    THEN 1
    ELSE 0
END;

DROP TABLE api_keys;
ALTER TABLE api_keys_with_plaintext RENAME TO api_keys;

CREATE INDEX api_keys_owner_idx ON api_keys (owner_user_id, created_at);
CREATE INDEX api_keys_active_idx ON api_keys (enabled, expires_at);

DROP TABLE api_key_plaintext_migration_guard;
DROP TABLE api_key_plaintext_recovery;
