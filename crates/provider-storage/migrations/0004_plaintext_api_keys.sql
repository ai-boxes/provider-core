DROP TABLE api_keys;

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    owner_user_id TEXT NOT NULL,
    label TEXT NOT NULL,
    key TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    expires_at INTEGER,
    last_used_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX api_keys_owner_idx ON api_keys (owner_user_id, created_at);
CREATE INDEX api_keys_active_idx ON api_keys (enabled, expires_at);
