-- Reviewed Bug Bounty program policy snapshot. NULL preserves legacy task behavior;
-- policy-bound tasks are enforced by the server runtime, not by Target Gate.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS program_policy JSONB;
