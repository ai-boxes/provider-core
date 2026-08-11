CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (
        length(trim(username)) > 0 AND length(username) <= 128
    ),
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
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX user_sessions_user_idx ON user_sessions (user_id, revoked_at);

CREATE TABLE registration_codes (
    code_hash BLOB PRIMARY KEY NOT NULL CHECK (length(code_hash) = 32),
    expires_at INTEGER NOT NULL
);

CREATE TABLE provider_accounts (
    id TEXT PRIMARY KEY NOT NULL,
    owner_user_id TEXT,
    visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'shared')),
    provider TEXT NOT NULL CHECK (
        provider IN ('grok', 'codex', 'openai_compatible', 'anthropic_compatible')
    ),
    label TEXT NOT NULL CHECK (length(trim(label)) > 0 AND length(label) <= 128),
    group_label TEXT NOT NULL CHECK (
        length(trim(group_label)) > 0 AND length(group_label) <= 64
    ),
    config_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(config_json)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    auth_state TEXT NOT NULL DEFAULT 'active'
        CHECK (auth_state IN ('active', 'reauth_required')),
    safe_error_code TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX provider_accounts_enabled_provider_idx
    ON provider_accounts (enabled, provider);
CREATE INDEX provider_accounts_group_label_idx
    ON provider_accounts (group_label);
CREATE INDEX provider_accounts_owner_visibility_idx
    ON provider_accounts (owner_user_id, visibility, enabled);

CREATE TABLE provider_credentials (
    account_id TEXT PRIMARY KEY NOT NULL,
    credential_kind TEXT NOT NULL CHECK (credential_kind IN ('oauth', 'api_key')),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    format_version INTEGER NOT NULL CHECK (format_version > 0),
    credential_json TEXT NOT NULL CHECK (
        length(credential_json) > 3 AND credential_json GLOB 'v1:*'
    ),
    expires_at INTEGER,
    last_refreshed_at INTEGER,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    FOREIGN KEY (account_id) REFERENCES provider_accounts(id) ON DELETE CASCADE
);

CREATE TABLE provider_models (
    account_id TEXT NOT NULL,
    upstream_model TEXT NOT NULL,
    alias TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    available INTEGER NOT NULL DEFAULT 1 CHECK (available IN (0, 1)),
    routable INTEGER NOT NULL DEFAULT 1 CHECK (routable IN (0, 1)),
    input_modalities_json TEXT CHECK (
        input_modalities_json IS NULL
        OR input_modalities_json IN ('["text"]', '["text","image"]')
    ),
    input_modalities_source TEXT NOT NULL DEFAULT 'discovery'
        CHECK (input_modalities_source IN ('discovery', 'manual')),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    pricing_source TEXT CHECK (pricing_source IS NULL OR pricing_source IN ('catalog', 'manual')),
    pricing_json TEXT CHECK (pricing_json IS NULL OR json_valid(pricing_json)),
    last_seen_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (account_id, upstream_model),
    FOREIGN KEY (account_id) REFERENCES provider_accounts(id) ON DELETE CASCADE
);

CREATE INDEX provider_models_effective_lookup_idx
    ON provider_models (enabled, available, routable, upstream_model, alias);

CREATE TRIGGER provider_models_pricing_insert_check
BEFORE INSERT ON provider_models
WHEN (NEW.pricing_source IS NULL) != (NEW.pricing_json IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'provider model pricing source and json must be set together');
END;

CREATE TRIGGER provider_models_pricing_update_check
BEFORE UPDATE OF pricing_source, pricing_json ON provider_models
WHEN (NEW.pricing_source IS NULL) != (NEW.pricing_json IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'provider model pricing source and json must be set together');
END;

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    owner_user_id TEXT NOT NULL,
    group_label TEXT NOT NULL CHECK (
        length(trim(group_label)) > 0 AND length(group_label) <= 64
    ),
    label TEXT NOT NULL CHECK (length(trim(label)) > 0 AND length(label) <= 128),
    key TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    expires_at INTEGER,
    quota_limit_atoms TEXT CHECK (
        quota_limit_atoms IS NULL OR (
            length(quota_limit_atoms) > 0 AND length(quota_limit_atoms) <= 64
            AND quota_limit_atoms GLOB '[1-9]*'
            AND quota_limit_atoms NOT GLOB '*[^0-9]*'
        )
    ),
    spent_atoms TEXT NOT NULL DEFAULT '0' CHECK (
        length(spent_atoms) > 0 AND length(spent_atoms) <= 64
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

CREATE TABLE api_key_quota_ledger (
    entry_id TEXT PRIMARY KEY NOT NULL,
    api_key_id TEXT NOT NULL,
    reserved_atoms TEXT NOT NULL CHECK (
        length(reserved_atoms) > 0 AND length(reserved_atoms) <= 64
        AND reserved_atoms GLOB '[0-9]*'
        AND reserved_atoms NOT GLOB '*[^0-9]*'
    ),
    settled_atoms TEXT CHECK (
        settled_atoms IS NULL OR (
            length(settled_atoms) > 0 AND length(settled_atoms) <= 64
            AND settled_atoms GLOB '[0-9]*'
            AND settled_atoms NOT GLOB '*[^0-9]*'
        )
    ),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'settled', 'released')),
    reserved_at_ms INTEGER NOT NULL,
    resolved_at_ms INTEGER,
    CHECK (
        (state = 'reserved' AND settled_atoms IS NULL AND resolved_at_ms IS NULL)
        OR (state = 'settled' AND settled_atoms IS NOT NULL AND resolved_at_ms IS NOT NULL)
        OR (state = 'released' AND settled_atoms IS NULL AND resolved_at_ms IS NOT NULL)
    )
);

CREATE INDEX api_key_quota_ledger_key_state_idx
    ON api_key_quota_ledger (api_key_id, state, entry_id);

CREATE INDEX api_key_quota_ledger_resolved_idx
    ON api_key_quota_ledger (resolved_at_ms, entry_id);

CREATE TABLE usage_logical_requests (
    request_id TEXT PRIMARY KEY NOT NULL,
    owner_user_id TEXT NOT NULL,
    api_key_id TEXT,
    api_key_label TEXT,
    api_key_group_label TEXT CHECK (
        api_key_group_label IS NULL OR (
            length(trim(api_key_group_label)) > 0 AND length(api_key_group_label) <= 64
        )
    ),
    client_model_raw TEXT,
    routing_model TEXT,
    reasoning_effort TEXT CHECK (
        reasoning_effort IS NULL OR (
            length(trim(reasoning_effort)) > 0 AND length(reasoning_effort) <= 32
        )
    ),
    started_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    logical_status TEXT NOT NULL CHECK (
        logical_status IN ('in_progress', 'succeeded', 'failed', 'canceled', 'incomplete')
    ),
    execution_outcome TEXT CHECK (
        execution_outcome IS NULL OR execution_outcome IN (
            'stable_success_terminal',
            'stable_failure',
            'translator_or_stream_error',
            'eof_without_success_terminal',
            'recovered_old_run_active'
        )
    ),
    delivery_outcome TEXT CHECK (
        delivery_outcome IS NULL OR delivery_outcome IN (
            'clean_eof', 'client_drop', 'error_before_bytes', 'error_after_bytes', 'unknown'
        )
    ),
    final_attempt_id TEXT,
    tracking_state TEXT NOT NULL DEFAULT 'complete'
        CHECK (tracking_state IN ('complete', 'gap')),
    tracking_gap_reason TEXT CHECK (
        tracking_gap_reason IS NULL OR tracking_gap_reason IN (
            'write_failed',
            'writer_saturated',
            'recovered_in_flight',
            'ambiguous_cancel',
            'observation_lost'
        )
    ),
    state_version INTEGER NOT NULL DEFAULT 0 CHECK (state_version >= 0),
    CHECK ((logical_status = 'in_progress') = (completed_at_ms IS NULL)),
    CHECK ((tracking_state = 'gap') = (tracking_gap_reason IS NOT NULL))
);

CREATE INDEX usage_logical_requests_owner_idx
    ON usage_logical_requests (owner_user_id, completed_at_ms DESC, request_id DESC);
CREATE INDEX usage_logical_requests_key_idx
    ON usage_logical_requests (api_key_id, completed_at_ms DESC, request_id DESC);
CREATE INDEX usage_logical_requests_group_idx
    ON usage_logical_requests (
        owner_user_id, api_key_group_label, completed_at_ms DESC, request_id DESC
    );
CREATE INDEX usage_logical_requests_in_flight_idx
    ON usage_logical_requests (started_at_ms)
    WHERE logical_status = 'in_progress';

CREATE TABLE usage_attempts (
    id TEXT PRIMARY KEY NOT NULL,
    logical_request_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    provider TEXT NOT NULL,
    account_id TEXT NOT NULL,
    configured_model TEXT,
    provider_reported_model TEXT,
    started_at_ms INTEGER NOT NULL,
    first_token_at_ms INTEGER CHECK (
        first_token_at_ms IS NULL OR (
            first_token_at_ms >= started_at_ms AND first_token_at_ms <= completed_at_ms
        )
    ),
    completed_at_ms INTEGER NOT NULL,
    dispatch_evidence TEXT NOT NULL CHECK (
        dispatch_evidence IN ('not_invoked', 'dispatch_invoked', 'response_observed')
    ),
    tracking_state TEXT NOT NULL DEFAULT 'complete'
        CHECK (tracking_state IN ('complete', 'gap')),
    tracking_gap_reason TEXT CHECK (
        tracking_gap_reason IS NULL OR tracking_gap_reason IN (
            'write_failed',
            'writer_saturated',
            'recovered_in_flight',
            'ambiguous_cancel',
            'observation_lost'
        )
    ),
    contract_version INTEGER NOT NULL CHECK (contract_version >= 1),
    normalization_version INTEGER NOT NULL CHECK (normalization_version >= 1),
    inclusion_json TEXT NOT NULL CHECK (json_valid(inclusion_json)),
    cache_capability TEXT NOT NULL
        CHECK (cache_capability IN ('supported', 'unsupported', 'unknown')),
    cache_eligibility TEXT NOT NULL
        CHECK (cache_eligibility IN ('eligible', 'not_requested', 'not_applicable', 'unknown')),
    cache_reporting_expectation TEXT NOT NULL
        CHECK (cache_reporting_expectation IN ('expected', 'not_expected', 'unknown')),
    pricing_context_basis TEXT NOT NULL
        CHECK (pricing_context_basis IN ('effective_input', 'unknown')),
    pricing_mode TEXT NOT NULL CHECK (pricing_mode IN ('default', 'unknown')),
    uncached_input_tokens INTEGER CHECK (uncached_input_tokens >= 0),
    cache_read_input_tokens INTEGER CHECK (cache_read_input_tokens >= 0),
    cache_write_input_tokens INTEGER CHECK (cache_write_input_tokens >= 0),
    effective_input_tokens INTEGER CHECK (effective_input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens >= 0),
    reasoning_tokens INTEGER CHECK (reasoning_tokens >= 0),
    input_audio_tokens INTEGER CHECK (input_audio_tokens >= 0),
    output_audio_tokens INTEGER CHECK (output_audio_tokens >= 0),
    total_tokens INTEGER CHECK (total_tokens >= 0),
    pricing_context_tokens INTEGER CHECK (pricing_context_tokens >= 0),
    token_kinds_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(token_kinds_json)),
    normalization_warnings_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(normalization_warnings_json)),
    price_resolution TEXT NOT NULL CHECK (
        price_resolution IN (
            'resolved',
            'catalog_unavailable',
            'provider_mapping_missing',
            'model_mapping_missing',
            'cost_missing',
            'catalog_entry_invalid',
            'pricing_rule_unsupported',
            'pricing_rule_conflict'
        )
    ),
    catalog_revision TEXT,
    selected_tier TEXT,
    price_json TEXT CHECK (price_json IS NULL OR json_valid(price_json)),
    calculator_version INTEGER NOT NULL CHECK (calculator_version >= 1),
    cost_status TEXT NOT NULL CHECK (
        cost_status IN ('complete_for_observed_catalog_components', 'partial', 'unavailable')
    ),
    cost_atoms INTEGER,
    cost_reasons_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(cost_reasons_json)),
    UNIQUE (logical_request_id, sequence),
    CHECK ((tracking_state = 'gap') = (tracking_gap_reason IS NOT NULL)),
    CHECK ((price_resolution = 'resolved') = (price_json IS NOT NULL)),
    CHECK ((cost_status = 'unavailable') = (cost_atoms IS NULL)),
    CHECK (
        dispatch_evidence <> 'not_invoked' OR (
            cost_status = 'unavailable'
            AND effective_input_tokens IS NULL
            AND output_tokens IS NULL
            AND total_tokens IS NULL
        )
    ),
    FOREIGN KEY (logical_request_id)
        REFERENCES usage_logical_requests(request_id) ON DELETE CASCADE
);

CREATE INDEX usage_attempts_account_completed_idx
    ON usage_attempts (account_id, completed_at_ms);

CREATE TABLE usage_billable_observations (
    attempt_id TEXT NOT NULL,
    component_code TEXT NOT NULL CHECK (
        component_code IN (
            'cache_write_5m',
            'cache_write_1h',
            'server_tool_call',
            'image_input_tokens',
            'image_output_tokens'
        )
    ),
    unit TEXT NOT NULL CHECK (unit IN ('tokens', 'calls')),
    quantity INTEGER NOT NULL CHECK (quantity >= 0),
    PRIMARY KEY (attempt_id, component_code),
    FOREIGN KEY (attempt_id) REFERENCES usage_attempts(id) ON DELETE CASCADE
);

CREATE TABLE usage_tracking_gaps (
    owner_user_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (
        reason IN (
            'write_failed',
            'writer_saturated',
            'recovered_in_flight',
            'ambiguous_cancel',
            'observation_lost'
        )
    ),
    bucket_start_ms INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
    PRIMARY KEY (owner_user_id, reason, bucket_start_ms)
);

CREATE TABLE usage_catalog (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    revision TEXT NOT NULL CHECK (length(revision) = 64),
    body TEXT NOT NULL CHECK (json_valid(body)),
    etag TEXT,
    last_modified TEXT,
    content_fetched_at_ms INTEGER NOT NULL,
    last_checked_at_ms INTEGER NOT NULL,
    last_error_code TEXT
);
