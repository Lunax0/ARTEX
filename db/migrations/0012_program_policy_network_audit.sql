-- Extend the sanitized ProgramPolicy ledger with per-hop and resolved-IP evidence.
ALTER TABLE program_policy_events
    ADD COLUMN IF NOT EXISTS event_phase TEXT NOT NULL DEFAULT 'decision'
        CHECK (event_phase IN ('decision', 'redirect', 'dial'));
ALTER TABLE program_policy_events
    ADD COLUMN IF NOT EXISTS resolved_ips JSONB NOT NULL DEFAULT '[]'::jsonb;
CREATE INDEX IF NOT EXISTS idx_program_policy_events_phase_created
    ON program_policy_events (event_phase, created_at DESC);
