-- Record bounded, budget-charged HTTP 429/503 retry attempts in the policy audit ledger.
ALTER TABLE program_policy_events
    DROP CONSTRAINT IF EXISTS program_policy_events_event_phase_check;
ALTER TABLE program_policy_events
    ADD CONSTRAINT program_policy_events_event_phase_check
    CHECK (event_phase IN ('decision', 'redirect', 'dial', 'retry'));
