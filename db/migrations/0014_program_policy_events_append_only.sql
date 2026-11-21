-- Prevent accidental or application-level mutation of the policy audit ledger.
-- A database owner/superuser can still disable or remove these guards; this is
-- append-only protection, not cryptographic tamper evidence.
CREATE OR REPLACE FUNCTION reject_program_policy_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'program_policy_events is append-only; % is forbidden', TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS program_policy_events_no_update_delete ON program_policy_events;
CREATE TRIGGER program_policy_events_no_update_delete
    BEFORE UPDATE OR DELETE ON program_policy_events
    FOR EACH ROW EXECUTE FUNCTION reject_program_policy_event_mutation();

DROP TRIGGER IF EXISTS program_policy_events_no_truncate ON program_policy_events;
CREATE TRIGGER program_policy_events_no_truncate
    BEFORE TRUNCATE ON program_policy_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_program_policy_event_mutation();
