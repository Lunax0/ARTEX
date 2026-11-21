-- Keep the policy audit ledger self-validating even when writes bypass the Go API.
-- Empty digests are permitted for legacy/system events; populated values must be SHA-256 hex.
ALTER TABLE program_policy_events
    ADD CONSTRAINT program_policy_events_policy_digest_check
    CHECK (policy_digest = '' OR policy_digest ~ '^[0-9a-fA-F]{64}$');
