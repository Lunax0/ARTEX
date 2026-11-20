-- Shared ProgramPolicy request budgets across ARTEX replicas.
CREATE TABLE IF NOT EXISTS program_policy_budget_state (
    budget_key          TEXT PRIMARY KEY,
    requests_per_second DOUBLE PRECISION NOT NULL CHECK (requests_per_second > 0),
    burst               INTEGER NOT NULL CHECK (burst > 0),
    max_concurrency     INTEGER NOT NULL CHECK (max_concurrency > 0),
    request_timeout_seconds INTEGER NOT NULL CHECK (request_timeout_seconds BETWEEN 1 AND 600),
    max_retries         INTEGER NOT NULL CHECK (max_retries BETWEEN 0 AND 10),
    tokens              DOUBLE PRECISION NOT NULL,
    refilled_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS program_policy_budget_leases (
    id          BIGSERIAL PRIMARY KEY,
    budget_key  TEXT NOT NULL REFERENCES program_policy_budget_state(budget_key) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_program_policy_budget_leases_key_expiry
    ON program_policy_budget_leases (budget_key, expires_at);
