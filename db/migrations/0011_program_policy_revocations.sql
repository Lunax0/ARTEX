-- Immutable revocation markers for approved ProgramPolicy source snapshots.
CREATE TABLE IF NOT EXISTS program_policy_revocations (
    program_id      TEXT NOT NULL,
    source_sha256   TEXT NOT NULL CHECK (source_sha256 ~ '^[0-9a-fA-F]{64}$'),
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_by      TEXT NOT NULL,
    reason          TEXT NOT NULL,
    PRIMARY KEY (program_id, source_sha256)
);
CREATE INDEX IF NOT EXISTS idx_program_policy_revocations_time
    ON program_policy_revocations (revoked_at DESC);
