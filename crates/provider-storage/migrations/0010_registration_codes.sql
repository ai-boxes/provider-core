CREATE TABLE registration_codes (
    code_hash BLOB PRIMARY KEY NOT NULL CHECK (length(code_hash) = 32),
    expires_at INTEGER NOT NULL
);
