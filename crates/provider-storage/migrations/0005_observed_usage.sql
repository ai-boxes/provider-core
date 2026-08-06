-- Observed usage facts: fail-open estimates, never billing records.
--
-- Two honesty rules are enforced by the schema itself:
--   * A token count that is not a known number is NULL, never 0. `SUM` skips it
--     and `COUNT(*) - COUNT(col)` gives the unknown count.
--   * An attempt that never reached the transport cannot carry usage or a cost.
--
-- Timestamps in these tables are unix **milliseconds** (`_at_ms`), unlike the
-- second-granularity columns in earlier migrations. The suffix is what keeps the
-- two units from being confused inside the same database.

CREATE TABLE usage_logical_requests (
    request_id TEXT PRIMARY KEY NOT NULL,

    -- Identity snapshot. Deliberately no foreign key: deleting a user or an API
    -- key must not cascade away, or silently rewrite, past usage.
    owner_user_id TEXT NOT NULL,
    api_key_id TEXT,

    client_model_raw TEXT,
    routing_model TEXT,

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

    -- Snapshot pointer used by the user-observed scope. No foreign key on
    -- purpose: it would be circular with usage_attempts.logical_request_id.
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

    -- Monotonic per-request version so an out-of-order writer event cannot
    -- overwrite newer state.
    state_version INTEGER NOT NULL DEFAULT 0 CHECK (state_version >= 0),

    CHECK ((logical_status = 'in_progress') = (completed_at_ms IS NULL)),
    CHECK ((tracking_state = 'gap') = (tracking_gap_reason IS NOT NULL))
);

-- Stable keyset cursors: (completed_at_ms DESC, request_id DESC).
CREATE INDEX usage_logical_requests_owner_idx
    ON usage_logical_requests (owner_user_id, completed_at_ms DESC, request_id DESC);
CREATE INDEX usage_logical_requests_key_idx
    ON usage_logical_requests (api_key_id, completed_at_ms DESC, request_id DESC);

-- Startup recovery scans only what a previous run left running, so keep the
-- index partial rather than covering every historical row.
CREATE INDEX usage_logical_requests_in_flight_idx
    ON usage_logical_requests (started_at_ms)
    WHERE logical_status = 'in_progress';

CREATE TABLE usage_attempts (
    id TEXT PRIMARY KEY NOT NULL,
    logical_request_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),

    -- Resource snapshot, again without foreign keys so deleting an account or a
    -- model keeps history readable.
    provider TEXT NOT NULL,
    account_id TEXT NOT NULL,
    configured_model TEXT,
    provider_reported_model TEXT,

    started_at_ms INTEGER NOT NULL,
    -- Attempts are written once, after the response reaches a terminal state.
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

    -- Usage contract. The inclusion rules are stored, not derived from
    -- (provider, contract_version), because recomputing a historical cost needs
    -- them: whether reasoning sat inside output decides whether it may be priced
    -- separately. The rest of the snapshot is kept in columns below.
    contract_version INTEGER NOT NULL CHECK (contract_version >= 1),
    normalization_version INTEGER NOT NULL CHECK (normalization_version >= 1),
    inclusion_json TEXT NOT NULL CHECK (json_valid(inclusion_json)),

    -- Cache dimensions are columns because hit rate and reporting coverage
    -- aggregate over them.
    cache_capability TEXT NOT NULL
        CHECK (cache_capability IN ('supported', 'unsupported', 'unknown')),
    cache_eligibility TEXT NOT NULL
        CHECK (cache_eligibility IN ('eligible', 'not_requested', 'not_applicable', 'unknown')),
    cache_reporting_expectation TEXT NOT NULL
        CHECK (cache_reporting_expectation IN ('expected', 'not_expected', 'unknown')),
    pricing_context_basis TEXT NOT NULL
        CHECK (pricing_context_basis IN ('effective_input', 'unknown')),
    pricing_mode TEXT NOT NULL CHECK (pricing_mode IN ('default', 'unknown')),

    -- Token metrics. NULL is "not a known number"; 0 is a known zero.
    uncached_input_tokens INTEGER CHECK (uncached_input_tokens >= 0),
    cache_read_input_tokens INTEGER CHECK (cache_read_input_tokens >= 0),
    cache_write_input_tokens INTEGER CHECK (cache_write_input_tokens >= 0),
    effective_input_tokens INTEGER CHECK (effective_input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens >= 0),
    reasoning_tokens INTEGER CHECK (reasoning_tokens >= 0),
    input_audio_tokens INTEGER CHECK (input_audio_tokens >= 0),
    output_audio_tokens INTEGER CHECK (output_audio_tokens >= 0),
    total_tokens INTEGER CHECK (total_tokens >= 0),
    -- Selects a context price tier and is never billed on its own. Kept so an
    -- attempt read back is exactly what was written, and so a tier choice can be
    -- explained after the fact.
    pricing_context_tokens INTEGER CHECK (pricing_context_tokens >= 0),

    -- Why a metric is not a plain provider-reported number, keyed by category.
    -- Only entries that are NOT `provider_reported` appear, so a fully reported
    -- attempt stores `{}`.
    token_kinds_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(token_kinds_json)),
    normalization_warnings_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(normalization_warnings_json)),

    -- Price resolution, inlined so historical cost is recomputable without
    -- reading the current catalog.
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
    -- The full InlinePriceRecord, including the exact per-component unit prices
    -- actually used. Present exactly when price_resolution = 'resolved'.
    price_json TEXT CHECK (price_json IS NULL OR json_valid(price_json)),

    -- Cost estimate. cost_atoms counts 10^-14 USD, so one attempt tops out far
    -- above any real response; calculator_version pins that scale and the
    -- formula. An amount that cannot be represented is 'unavailable' with an
    -- 'arithmetic_overflow' reason, never a truncated number.
    calculator_version INTEGER NOT NULL CHECK (calculator_version >= 1),
    cost_status TEXT NOT NULL CHECK (
        cost_status IN ('complete_for_observed_catalog_components', 'partial', 'unavailable')
    ),
    cost_atoms INTEGER,
    cost_reasons_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(cost_reasons_json)),

    UNIQUE (logical_request_id, sequence),

    CHECK ((tracking_state = 'gap') = (tracking_gap_reason IS NOT NULL)),
    CHECK ((price_resolution = 'resolved') = (price_json IS NOT NULL)),
    -- A missing price must never read as $0, and an amount is either storable
    -- exactly or not stored at all.
    CHECK ((cost_status = 'unavailable') = (cost_atoms IS NULL)),
    -- Nothing was sent, so there is nothing to have observed or to bill.
    CHECK (
        dispatch_evidence <> 'not_invoked' OR (
            cost_status = 'unavailable'
            AND effective_input_tokens IS NULL
            AND output_tokens IS NULL
            AND total_tokens IS NULL
        )
    ),

    FOREIGN KEY (logical_request_id)
        REFERENCES usage_logical_requests (request_id) ON DELETE CASCADE
);

-- Billable quantities that do not fold into a single token category. Sparse: the
-- primary key bounds this to the known component vocabulary, so an unrecognised
-- upstream field can never grow it into a high-cardinality table.
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
    FOREIGN KEY (attempt_id) REFERENCES usage_attempts (id) ON DELETE CASCADE
);

-- Known bookkeeping gaps, bucketed so a saturated writer records a count instead
-- of one row per lost fact. This is an admission of missing data, not a
-- substitute for it.
CREATE TABLE usage_tracking_gaps (
    owner_user_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (
        reason IN ('write_failed',
            'writer_saturated',
            'recovered_in_flight',
            'ambiguous_cancel',
            'observation_lost')
    ),
    bucket_start_ms INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
    PRIMARY KEY (owner_user_id, reason, bucket_start_ms)
);

-- The current models.dev catalog, one row. History is not kept: an attempt
-- inlines the prices it actually used, so no past revision needs to be re-read.
-- An empty table means the vendored seed is in effect.
CREATE TABLE usage_catalog (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    -- SHA-256 of `body`, hex encoded.
    revision TEXT NOT NULL CHECK (length(revision) = 64),
    body TEXT NOT NULL CHECK (json_valid(body)),
    etag TEXT,
    last_modified TEXT,
    content_fetched_at_ms INTEGER NOT NULL,
    last_checked_at_ms INTEGER NOT NULL,
    -- A stable reason code, never an upstream message.
    last_error_code TEXT
);
