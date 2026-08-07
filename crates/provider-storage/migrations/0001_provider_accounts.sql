CREATE TABLE provider_accounts (
    id TEXT PRIMARY KEY NOT NULL,
    provider TEXT NOT NULL,
    label TEXT NOT NULL,
    group_label TEXT NOT NULL CHECK (
        length(trim(group_label)) > 0
        AND length(group_label) <= 64
    ),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    auth_state TEXT NOT NULL DEFAULT 'active',
    safe_error_code TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE provider_credentials (
    account_id TEXT PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    format_version INTEGER NOT NULL CHECK (format_version > 0),
    credential_json TEXT NOT NULL,
    expires_at INTEGER,
    last_refreshed_at INTEGER,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    FOREIGN KEY (account_id) REFERENCES provider_accounts(id) ON DELETE CASCADE
);

CREATE INDEX provider_accounts_enabled_provider_idx
    ON provider_accounts (enabled, provider);

CREATE INDEX provider_accounts_group_label_idx
    ON provider_accounts (group_label);
