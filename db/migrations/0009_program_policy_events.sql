-- Sanitized event stream for mandatory ProgramPolicy decisions.
-- Raw request inputs, credentials, cookies and query strings are intentionally excluded.
CREATE TABLE IF NOT EXISTS program_policy_events (
    id                  BIGSERIAL PRIMARY KEY,
    task_id             TEXT NOT NULL,
    conversation_id     BIGINT,
    agent_name          TEXT NOT NULL DEFAULT '',
    tool_name           TEXT NOT NULL,
    decision_code       TEXT NOT NULL,
    action              TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
    target_authority    TEXT NOT NULL DEFAULT '',
    policy_digest       TEXT NOT NULL DEFAULT '',
    execution_status    TEXT NOT NULL CHECK (execution_status IN ('unknown', 'not_executed')),
    reason              TEXT NOT NULL DEFAULT '',
    actor               TEXT NOT NULL DEFAULT 'system' CHECK (actor = 'system'),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_program_policy_events_task_created
    ON program_policy_events (task_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_program_policy_events_digest_created
    ON program_policy_events (policy_digest, created_at DESC);
