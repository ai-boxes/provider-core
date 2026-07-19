CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('super_admin', 'user')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE auth_setup (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    initial_user_id TEXT UNIQUE,
    FOREIGN KEY (initial_user_id) REFERENCES users(id) ON DELETE RESTRICT
);

INSERT INTO auth_setup (singleton, initial_user_id) VALUES (1, NULL);

CREATE TABLE user_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    access_token_hash BLOB NOT NULL UNIQUE CHECK (length(access_token_hash) = 32),
    refresh_token_hash BLOB NOT NULL UNIQUE CHECK (length(refresh_token_hash) = 32),
    access_expires_at INTEGER NOT NULL,
    refresh_expires_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX user_sessions_user_idx ON user_sessions (user_id, revoked_at);

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    owner_user_id TEXT NOT NULL,
    label TEXT NOT NULL,
    key_hash BLOB NOT NULL UNIQUE CHECK (length(key_hash) = 32),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    expires_at INTEGER,
    last_used_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX api_keys_owner_idx ON api_keys (owner_user_id, created_at);
CREATE INDEX api_keys_active_idx ON api_keys (enabled, expires_at);

ALTER TABLE provider_accounts
ADD COLUMN owner_user_id TEXT REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE provider_accounts
ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'
CHECK (visibility IN ('private', 'shared'));

CREATE INDEX provider_accounts_owner_visibility_idx
ON provider_accounts (owner_user_id, visibility, enabled);
