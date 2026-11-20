package guard

import (
	"context"
	"errors"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/policy"
)

func compiledGuardPolicy(t *testing.T) *policy.CompiledPolicy {
	t.Helper()
	now := time.Now().UTC()
	sum := sha256.Sum256([]byte("reviewed policy source"))
	compiled, err := policy.CompileAt(policy.ProgramPolicy{
		SchemaVersion: policy.SchemaVersion,
		ProgramID:     "guard-test",
		PolicyURL:     "https://bugcrowd.com/engagements/guard-test",
		SourceSHA256:  hex.EncodeToString(sum[:]),
		RetrievedAt:   now,
		ApprovedAt:    now,
		ApprovedBy:    "operator",
		ExpiresAt:     now.Add(time.Hour),
		InScope: []policy.AssetRule{
			{Pattern: "example.com"},
			{Pattern: "*.example.net"},
		},
		Limits: policy.Limits{
			RequestsPerSecond: 1, Burst: 1, MaxConcurrency: 1,
			RequestTimeoutSecond: 30, MaxRetries: 0,
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func policyGuardContext(compiled *policy.CompiledPolicy, enabled func() bool) context.Context {
	return intercept.WithTargetScope(context.Background(), intercept.TargetScope{
		TaskID: "77", Enabled: enabled,
		ProgramPolicyRequired: true, ProgramPolicy: compiled,
		ProgramPolicyCheck: func(context.Context) error { return nil },
	})
}

func callPolicyGuard(g *Guard, ctx context.Context, tool, input string) (bool, string) {
	block, message, _ := g.Hooks().PreToolUse(ctx, tool, []byte(input))
	return block, message
}

func TestProgramPolicyAppliesWhenTargetGateIsOff(t *testing.T) {
	compiled := compiledGuardPolicy(t)
	g := NewTargetOnly(nil)
	g.SetProgramPolicy(compiled, true, "")
	ctx := policyGuardContext(compiled, nil) // no Target Gate opt-in

	if block, msg := callPolicyGuard(g, ctx, "WebFetch", `{"url":"https://api.example.net/v1"}`); !block ||
		!strings.Contains(msg, policy.CodeUnavailable) {
		t.Fatalf("in-scope WebFetch without a durable audit store must fail closed: block=%v msg=%q", block, msg)
	}
	if block, msg := callPolicyGuard(g, ctx, "WebFetch", `{"url":"https://outside.example.org/"}`); !block ||
		!strings.Contains(msg, policy.CodeOutOfScope) {
		t.Fatalf("out-of-scope WebFetch block=%v msg=%q", block, msg)
	}
}

func TestProgramPolicyRunsBeforeUserAllowRules(t *testing.T) {
	compiled := compiledGuardPolicy(t)
	ic := intercept.New(nil)
	ic.SetRulesForTest([]db.InterceptRule{{
		ID: 1, Name: "allow WebFetch", Enabled: true, Priority: 100,
		MatchTarget: "tool_name", MatchType: "string", Action: "allow", Pattern: "WebFetch",
	}})
	g := NewWithInterceptor(ic)
	g.SetProgramPolicy(compiled, true, "")
	ctx := policyGuardContext(compiled, func() bool { return true })

	if block, msg := callPolicyGuard(g, ctx, "WebFetch", `{"url":"https://outside.example.org/"}`); !block ||
		!strings.Contains(msg, policy.CodeOutOfScope) {
		t.Fatalf("user allow rule bypassed ProgramPolicy: block=%v msg=%q", block, msg)
	}
}

func TestProgramPolicyBlocksUncontrolledNetworkTools(t *testing.T) {
	compiled := compiledGuardPolicy(t)
	g := NewTargetOnly(nil)
	g.SetProgramPolicy(compiled, true, "")
	ctx := policyGuardContext(compiled, nil)

	for _, tool := range []string{"Bash", "shell_open", "shell_send", "Monitor", "ExecuteExtraTool", "mcp__browser__navigate", "custom_http", "spawn_task", "create_skill", "delete_assets_by_host"} {
		if block, msg := callPolicyGuard(g, ctx, tool, `{"url":"https://api.example.net/"}`); !block ||
			!strings.Contains(msg, policy.CodeOperationDenied) {
			t.Errorf("%s: block=%v msg=%q, want policy operation denial", tool, block, msg)
		}
	}
	for _, tool := range []string{"list_assets", "web_search", "Read"} {
		if block, msg := callPolicyGuard(g, ctx, tool, `{"query":"api.example.net"}`); block {
			t.Errorf("%s: known internal/no-target tool unexpectedly blocked: %s", tool, msg)
		}
	}
}

func TestProgramPolicyFailsClosedWithoutContextOrValidSnapshot(t *testing.T) {
	compiled := compiledGuardPolicy(t)
	g := NewTargetOnly(nil)
	g.SetProgramPolicy(compiled, true, "")
	if block, msg := callPolicyGuard(g, context.Background(), "WebFetch", `{"url":"https://api.example.net/"}`); !block ||
		!strings.Contains(msg, policy.CodeUnavailable) {
		t.Fatalf("missing policy context block=%v msg=%q", block, msg)
	}

	g.SetProgramPolicy(nil, true, "stored snapshot failed validation")
	if block, msg := callPolicyGuard(g, context.Background(), "WebFetch", `{"url":"https://api.example.net/"}`); !block ||
		!strings.Contains(msg, policy.CodeUnavailable) {
		t.Fatalf("invalid stored policy block=%v msg=%q", block, msg)
	}
}

func TestProgramPolicyRequiresExactlyOneValidWebFetchTarget(t *testing.T) {
	compiled := compiledGuardPolicy(t)
	g := NewTargetOnly(nil)
	g.SetProgramPolicy(compiled, true, "")
	ctx := policyGuardContext(compiled, nil)
	for _, input := range []string{
		`{"url":"not a URL"}`,
		`{"url":"ftp://api.example.net/file"}`,
	} {
		if block, msg := callPolicyGuard(g, ctx, "WebFetch", input); !block ||
			!strings.Contains(msg, policy.CodeInvalidTarget) {
			t.Errorf("input %s: block=%v msg=%q", input, block, msg)
		}
	}
}

func TestProgramPolicyRevocationBlocksTargetAndInternalTools(t *testing.T) {
	compiled := compiledGuardPolicy(t)
	g := NewTargetOnly(nil)
	g.SetProgramPolicy(compiled, true, "")
	scope, _ := intercept.TargetScopeFromContext(policyGuardContext(compiled, nil))
	scope.ProgramPolicyCheck = func(context.Context) error {
		return errors.New("approved policy source has been revoked")
	}
	ctx := intercept.WithTargetScope(context.Background(), scope)
	for _, tool := range []string{"WebFetch", "list_assets"} {
		if block, msg := callPolicyGuard(g, ctx, tool, `{"url":"https://api.example.net/"}`); !block ||
			!strings.Contains(msg, policy.CodeUnavailable) {
			t.Errorf("%s: revoked policy block=%v msg=%q", tool, block, msg)
		}
	}
}
