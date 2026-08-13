CREATE TABLE route_generations (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    generation INTEGER NOT NULL CHECK (generation > 0),
    provider TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'shadow', 'active', 'draining', 'disabled')),
    provider_config TEXT NOT NULL,
    qualified_policy_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (domain, direction, generation)
);

CREATE UNIQUE INDEX one_active_route_per_domain_direction
    ON route_generations (domain, direction)
    WHERE state = 'active';

CREATE INDEX route_generation_lookup
    ON route_generations (domain, direction, state, generation);

CREATE TABLE capability_evidence (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    domain_scope TEXT NOT NULL,
    capability TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
    artifact_sha256 TEXT NOT NULL,
    evidence_uri TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX capability_evidence_lookup
    ON capability_evidence (
        provider, domain_scope, capability, policy_version, passed, expires_at
    );

CREATE TABLE replay_tokens (
    token_sha256 TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    purpose TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX replay_token_expiry ON replay_tokens (expires_at);

CREATE TABLE ingress_messages (
    id TEXT PRIMARY KEY,
    notice_id TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    provider_event_id TEXT NOT NULL,
    provider_message_id TEXT,
    domain TEXT NOT NULL,
    binding_id TEXT NOT NULL REFERENCES route_generations(id),
    binding_generation INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'empty', 'notice_only', 'raw_only', 'ready', 'delivering',
        'retry_wait', 'handed_off', 'quarantined', 'deleted'
    )),
    envelope_blob_key TEXT,
    raw_blob_key TEXT,
    raw_sha256 TEXT,
    raw_size INTEGER,
    notice_json TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    lease_until TEXT,
    last_diagnostic TEXT,
    retention_until TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    handed_off_at TEXT,
    deleted_at TEXT,
    UNIQUE (provider, provider_event_id)
);

CREATE INDEX ingress_work_queue
    ON ingress_messages (state, next_attempt_at, lease_until, created_at);

CREATE INDEX ingress_binding_drain
    ON ingress_messages (binding_id, state);

CREATE TABLE outbound_messages (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    binding_id TEXT NOT NULL REFERENCES route_generations(id),
    binding_generation INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'queued', 'submitting', 'retry_wait', 'accepted', 'rejected',
        'unknown', 'quarantined', 'deleted'
    )),
    envelope_blob_key TEXT NOT NULL,
    raw_blob_key TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    raw_size INTEGER NOT NULL,
    provider_receipt_id TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    lease_until TEXT,
    last_diagnostic TEXT,
    retention_until TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    terminal_at TEXT,
    deleted_at TEXT
);

CREATE INDEX outbound_work_queue
    ON outbound_messages (state, next_attempt_at, lease_until, created_at);

CREATE INDEX outbound_binding_drain
    ON outbound_messages (binding_id, state);

CREATE INDEX outbound_provider_receipt
    ON outbound_messages (provider_receipt_id);

CREATE TABLE feedback_events (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_event_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    recipient_hash TEXT NOT NULL,
    submission_id TEXT REFERENCES outbound_messages(id),
    provider_receipt_id TEXT,
    diagnostic_code TEXT NOT NULL,
    correlation_state TEXT NOT NULL CHECK (
        correlation_state IN ('correlated', 'quarantined')
    ),
    created_at TEXT NOT NULL,
    UNIQUE (provider, provider_event_id)
);

CREATE INDEX feedback_submission_lookup
    ON feedback_events (submission_id, occurred_at);

CREATE TABLE quarantine (
    id TEXT PRIMARY KEY,
    object_type TEXT NOT NULL CHECK (
        object_type IN ('ingress', 'outbound', 'feedback')
    ),
    object_id TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    resolution TEXT,
    UNIQUE (object_type, object_id, reason_code)
);

CREATE INDEX quarantine_open ON quarantine (resolved_at, created_at);

CREATE TABLE operational_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX operational_event_retention ON operational_events (created_at);

