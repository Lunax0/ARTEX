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
		{TaskID: "task", ToolName: "WebFetch", DecisionCode: "POLICY_ALLOWED", Action: "allow", ExecutionStatus: "unknown", TargetAuthority: "https://example.test/path"},
		{TaskID: "task", ToolName: "WebFetch", DecisionCode: "POLICY_ALLOWED", Action: "allow", ExecutionStatus: "unknown", TargetAuthority: "example.test:99999"},
		{TaskID: "task", ToolName: "WebFetch", DecisionCode: "POLICY_ALLOWED", Action: "allow", ExecutionStatus: "unknown", EventPhase: "other"},
		{TaskID: "task", ToolName: "WebFetch", DecisionCode: "POLICY_ALLOWED", Action: "allow", ExecutionStatus: "unknown", ResolvedIPs: []string{"not-an-ip"}},
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
		got.DecisionCode != input.DecisionCode || got.Action != "allow" || got.EventPhase != "decision" ||
		got.TargetAuthority != input.TargetAuthority || got.PolicyDigest != digest || len(got.ResolvedIPs) != 0 ||
		got.ExecutionStatus != "unknown" || got.Actor != "system" {
		t.Fatalf("event round trip mismatch: %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("created_at was not populated by the database")
	}
	dialID, err := d.CreateProgramPolicyEvent(ProgramPolicyEvent{
		TaskID: taskID, ToolName: "WebFetch.Dial", DecisionCode: "POLICY_ALLOWED",
		Action: "allow", EventPhase: "dial", TargetAuthority: "api.example.test:443",
		ResolvedIPs: []string{"203.0.113.8"}, PolicyDigest: digest,
		ExecutionStatus: "unknown", Reason: "resolved address passed policy",
	})
	if err != nil {
		t.Fatal(err)
	}
	dialEvent, err := d.GetProgramPolicyEvent(dialID)
	if err != nil || dialEvent == nil || dialEvent.EventPhase != "dial" ||
		len(dialEvent.ResolvedIPs) != 1 || dialEvent.ResolvedIPs[0] != "203.0.113.8" {
		t.Fatalf("dial event round trip: %+v err=%v", dialEvent, err)
	}
	retryID, err := d.CreateProgramPolicyEvent(ProgramPolicyEvent{
		TaskID: taskID, ToolName: "WebFetch.Retry", DecisionCode: "POLICY_ALLOWED",
		Action: "allow", EventPhase: "retry", TargetAuthority: "api.example.test:443",
		PolicyDigest: digest, ExecutionStatus: "unknown", Reason: "bounded retry after HTTP 503",
	})
	if err != nil {
		t.Fatal(err)
	}
	retryEvent, err := d.GetProgramPolicyEvent(retryID)
	if err != nil || retryEvent == nil || retryEvent.EventPhase != "retry" {
		t.Fatalf("retry event round trip: %+v err=%v", retryEvent, err)
	}
	rows, err := d.ListTaskProgramPolicyEvents(taskID, 3)
	if err != nil || len(rows) != 3 {
		t.Fatalf("list events: %+v err=%v", rows, err)
	}
	if _, err := d.ListTaskProgramPolicyEvents(" ", 10); err == nil {
		t.Fatal("empty task id accepted")
	}
	if _, err := d.Exec("UPDATE program_policy_events SET reason='tampered' WHERE id=$1", id); err == nil {
		t.Fatal("policy event UPDATE was not rejected")
	}
	if _, err := d.Exec("DELETE FROM program_policy_events WHERE id=$1", id); err == nil {
		t.Fatal("policy event DELETE was not rejected")
	}
	if _, err := d.Exec("TRUNCATE program_policy_events"); err == nil {
		t.Fatal("policy event TRUNCATE was not rejected")
	}
}
