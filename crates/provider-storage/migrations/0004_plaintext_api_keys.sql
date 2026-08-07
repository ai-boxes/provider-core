DROP TABLE api_keys;

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    owner_user_id TEXT NOT NULL,
    group_label TEXT NOT NULL CHECK (
        length(trim(group_label)) > 0
        AND length(group_label) <= 64
    ),
    label TEXT NOT NULL,
    key TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    expires_at INTEGER,
    quota_limit_atoms TEXT CHECK (
        quota_limit_atoms IS NULL
        OR (
            length(quota_limit_atoms) > 0
            AND length(quota_limit_atoms) <= 64
            AND quota_limit_atoms GLOB '[1-9]*'
            AND quota_limit_atoms NOT GLOB '*[^0-9]*'
        )
    ),
    spent_atoms TEXT NOT NULL DEFAULT '0' CHECK (
        length(spent_atoms) > 0
        AND length(spent_atoms) <= 64
        AND spent_atoms GLOB '[0-9]*'
        AND spent_atoms NOT GLOB '*[^0-9]*'
    ),
    last_used_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX api_keys_owner_idx ON api_keys (owner_user_id, created_at);
CREATE INDEX api_keys_active_idx ON api_keys (enabled, expires_at);
