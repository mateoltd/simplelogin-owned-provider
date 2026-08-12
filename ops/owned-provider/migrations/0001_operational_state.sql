CREATE TABLE owned_provider.probe_result (
    id bigserial PRIMARY KEY,
    probe_name text NOT NULL,
    success boolean NOT NULL,
    latency_ms double precision NOT NULL CHECK (latency_ms >= 0),
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX probe_result_name_checked_at_idx
    ON owned_provider.probe_result (probe_name, checked_at DESC);

CREATE TABLE owned_provider.restore_marker (
    marker text PRIMARY KEY,
    phase text NOT NULL CHECK (phase IN ('checkpoint', 'after-checkpoint')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE owned_provider.operation (
    idempotency_key text PRIMARY KEY,
    operation text NOT NULL,
    result jsonb NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
