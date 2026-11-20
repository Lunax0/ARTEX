package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/policy"
)

func TestCreateTaskApprovesAndPersistsProgramPolicy(t *testing.T) {
	g := newGateServer(t)
	now := time.Now().UTC()
	source := sha256.Sum256([]byte("captured bug bounty policy"))
	expires := now.Add(24 * time.Hour)
	request := map[string]any{
		"description":    "Program policy persistence test",
		"goal":           "Review the authorized web application for reproducible security issues without accessing other users' data.",
		"program_policy": map[string]any{
			"schema_version": 1,
			"program_id":     "policy-persistence-test",
			"policy_url":     "https://bugcrowd.com/engagements/policy-persistence-test",
			"source_sha256":  hex.EncodeToString(source[:]),
			"retrieved_at":   now.Add(-365 * 24 * time.Hour).Format(time.RFC3339Nano),
			"approved_at":    now.Add(-365 * 24 * time.Hour).Format(time.RFC3339Nano),
			"approved_by":    "spoofed-client",
			"expires_at":     expires.Format(time.RFC3339Nano),
			"in_scope":       []any{
				map[string]any{"pattern": "app.example.com"},
				map[string]any{"pattern": "*.api.example.net"},
			},
			"out_of_scope":   []any{
				map[string]any{"pattern": "admin.app.example.com"},
			},
			"limits":         map[string]any{
				"requests_per_second":      1,
				"burst":                    1,
				"max_concurrency":          1,
				"request_timeout_seconds":  30,
				"max_retries":              0,
			},
			"permissions":    map[string]any{
				"allow_passive_recon":      true,
				"allow_authenticated_read": true,
			},
		},
	}
	raw, _ := json.Marshal(request)
	code, response := g.do(t, "POST", "/api/tasks", string(raw))
	if code != 201 {
		t.Fatalf("create task: %d %v", code, response)
	}
	id, _ := response["id"].(string)
	if id == "" {
		t.Fatalf("create response has no task id: %v", response)
	}
	g.cleanupTask(t, id)
	if response["program_policy_bound"] != true || response["program_policy_valid"] != true ||
		response["program_policy_digest"] == "" {
		t.Fatalf("policy metadata missing from response: %v", response)
	}

	taskID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := g.m.pg.GetTask(taskID)
	if err != nil || stored == nil {
		t.Fatalf("GetTask = %+v, %v", stored, err)
	}
	var snapshot policy.ProgramPolicy
	if err := json.Unmarshal(stored.ProgramPolicyJSON, &snapshot); err != nil {
		t.Fatalf("stored policy JSON: %v", err)
	}
	wantApprover := jwtSubject(g.token, g.s.jwtKey)
	if wantApprover == "" || snapshot.ApprovedBy != wantApprover {
		t.Fatalf("approved_by = %q, want authenticated JWT subject %q", snapshot.ApprovedBy, wantApprover)
	}
	if snapshot.ApprovedAt.Before(now.Add(-time.Minute)) || snapshot.RetrievedAt.Before(now.Add(-time.Minute)) {
		t.Fatalf("client-controlled approval timestamps were not replaced: approved=%s retrieved=%s", snapshot.ApprovedAt, snapshot.RetrievedAt)
	}
	if snapshot.SourceSHA256 != hex.EncodeToString(source[:]) || snapshot.ProgramID != "policy-persistence-test" {
		t.Fatalf("stored policy source/program metadata changed: %+v", snapshot)
	}

	task, ok := g.m.Task(id)
	if !ok || !task.ProgramPolicyBound || task.ProgramPolicy == nil || task.ProgramPolicyError != "" {
		t.Fatalf("runtime task policy not compiled: ok=%v task=%+v", ok, task)
	}
	ctx := intercept.WithTargetScope(context.Background(), task.targetScope(time.Second))
	block, message, _ := task.Guard.Hooks().PreToolUse(ctx, "WebFetch", []byte(`{"url":"https://admin.app.example.com/"}`))
	if !block || !strings.Contains(message, policy.CodeExcluded) {
		t.Fatalf("explicit exclusion not enforced by created task: block=%v message=%q", block, message)
	}
}

func TestCreateTaskRejectsInvalidProgramPolicy(t *testing.T) {
	g := newGateServer(t)
	request := map[string]any{
		"description":    "Invalid policy test",
		"goal":           "Review the authorized web application for reproducible security issues without accessing other users' data.",
		"program_policy": map[string]any{
			"schema_version": 1,
			"program_id":     "invalid-policy-test",
			"policy_url":     "https://bugcrowd.com/engagements/invalid-policy-test",
			"source_sha256":  "not-a-sha256",
			"expires_at":     time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
			"in_scope":       []any{map[string]any{"pattern": "*.com"}},
			"limits":         map[string]any{
				"requests_per_second":      1,
				"burst":                    1,
				"max_concurrency":          1,
				"request_timeout_seconds":  30,
				"max_retries":              0,
			},
		},
	}
	raw, _ := json.Marshal(request)
	code, response := g.do(t, "POST", "/api/tasks", string(raw))
	if code != 400 || !strings.Contains(response["error"].(string), "invalid Bug Bounty program policy") {
		t.Fatalf("invalid policy accepted: %d %v", code, response)
	}
}
