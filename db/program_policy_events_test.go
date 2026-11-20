package db

import (
	"strings"
	"testing"
	"time"
)

func TestCreateProgramPolicyEventValidatesBeforeDatabase(t *testing.T) {
	d := &DB{}
	cases := []ProgramPolicyEvent{
		{TaskID: "task", ToolName: "WebFetch", DecisionCode: "POLICY_ALLOWED", Action: "ask", ExecutionStatus: "unknown"},
		{TaskID: "", ToolName: "WebFetch", DecisionCode: "POLICY_ALLOWED", Action: "allow", ExecutionStatus: "unknown"},
		{TaskID: "task", ToolName: "", DecisionCode: "POLICY_ALLOWED", Action: "allow", ExecutionStatus: "unknown"},
		{TaskID: "task", ToolName: "WebFetch", DecisionCode: "", Action: "allow", ExecutionStatus: "unknown"},
		{TaskID: "task", ToolName: "WebFetch", DecisionCode: "POLICY_ALLOWED", Action: "allow", ExecutionStatus: "completed"},
		{TaskID: "task", ToolName: "WebFetch", DecisionCode: "POLICY_ALLOWED", Action: "allow", ExecutionStatus: "unknown", PolicyDigest: "not-a-digest"},
	}
	for n, event := range cases {
		if _, err := d.CreateProgramPolicyEvent(event); err == nil {
			t.Errorf("case %d: invalid event accepted", n)
		}
	}
}

func TestProgramPolicyEventRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	taskID := "policy-event-test-" + time.Now().UTC().Format("20060102150405.000000000")
	digest := strings.Repeat("a", 64)
	convID := int64(42)
	input := ProgramPolicyEvent{
		TaskID: taskID, ConversationID: &convID, AgentName: "worker",
		ToolName: "WebFetch", DecisionCode: "POLICY_ALLOWED", Action: "allow",
		TargetAuthority: "api.example.test:443", PolicyDigest: digest,
		ExecutionStatus: "unknown", Reason: "read-only target is in scope",
	}
	id, err := d.CreateProgramPolicyEvent(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.GetProgramPolicyEvent(id)
	if err != nil || got == nil {
		t.Fatalf("get event: %+v err=%v", got, err)
	}
	if got.TaskID != taskID || got.ToolName != input.ToolName ||
		got.DecisionCode != input.DecisionCode || got.Action != "allow" ||
		got.TargetAuthority != input.TargetAuthority || got.PolicyDigest != digest ||
		got.ExecutionStatus != "unknown" || got.Actor != "system" {
		t.Fatalf("event round trip mismatch: %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("created_at was not populated by the database")
	}
	rows, err := d.ListTaskProgramPolicyEvents(taskID, 1)
	if err != nil || len(rows) != 1 || rows[0].ID != id {
		t.Fatalf("list events: %+v err=%v", rows, err)
	}
	if _, err := d.ListTaskProgramPolicyEvents(" ", 10); err == nil {
		t.Fatal("empty task id accepted")
	}
	if _, err := d.Exec("UPDATE program_policy_events SET reason='tampered' WHERE id=$1", id); err == nil {
		t.Fatal("policy event update was not rejected")
	}
	if _, err := d.Exec("DELETE FROM program_policy_events WHERE id=$1", id); err == nil {
		t.Fatal("policy event deletion was not rejected")
	}
	if _, err := d.Exec("TRUNCATE TABLE program_policy_events"); err == nil {
		t.Fatal("policy event truncation was not rejected")
	}
}
