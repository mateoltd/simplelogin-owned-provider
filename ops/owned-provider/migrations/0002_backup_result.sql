CREATE TABLE owned_provider.backup_result (
    id bigserial PRIMARY KEY,
    success boolean NOT NULL,
    size_bytes bigint CHECK (size_bytes IS NULL OR size_bytes >= 0),
    sha256 text CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX backup_result_completed_at_idx
    ON owned_provider.backup_result (completed_at DESC);
