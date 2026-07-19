ALTER TABLE provider_accounts
ADD COLUMN config_json TEXT NOT NULL DEFAULT '{}'
CHECK (json_valid(config_json));

ALTER TABLE provider_credentials
ADD COLUMN credential_kind TEXT NOT NULL DEFAULT 'oauth'
CHECK (credential_kind IN ('oauth', 'api_key', 'none'));

CREATE TABLE provider_models (
    account_id TEXT NOT NULL,
    upstream_model TEXT NOT NULL,
    alias TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    available INTEGER NOT NULL DEFAULT 1 CHECK (available IN (0, 1)),
    routable INTEGER NOT NULL DEFAULT 1 CHECK (routable IN (0, 1)),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    last_seen_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (account_id, upstream_model),
    FOREIGN KEY (account_id) REFERENCES provider_accounts(id) ON DELETE CASCADE
);

CREATE INDEX provider_models_effective_lookup_idx
ON provider_models (enabled, available, routable, upstream_model, alias);
