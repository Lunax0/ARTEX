package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

var policyNow = time.Now().UTC()

func testPolicy() ProgramPolicy {
	source := sha256.Sum256([]byte("reviewed program policy"))
	return ProgramPolicy{
		SchemaVersion: SchemaVersion,
		ProgramID:     "example-program",
		PolicyURL:     "https://bugcrowd.com/engagements/example-program",
		SourceSHA256:  hex.EncodeToString(source[:]),
		RetrievedAt:   policyNow.Add(-48 * time.Hour),
		ApprovedAt:    policyNow.Add(-24 * time.Hour),
		ExpiresAt:     policyNow.Add(30 * 24 * time.Hour),
		ApprovedBy:    "operator",
		InScope: []AssetRule{
			{Pattern: "example.com"},
			{Pattern: "*.example.net"},
		},
		Limits: Limits{
			RequestsPerSecond:    1,
			Burst:                1,
			MaxConcurrency:       1,
			RequestTimeoutSecond: 30,
			MaxRetries:           0,
		},
	}
}

func mustCompile(t *testing.T, input ProgramPolicy) *CompiledPolicy {
	t.Helper()
	p, err := CompileAt(input, policyNow)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExactAndWildcardDomainSemantics(t *testing.T) {
	p := mustCompile(t, testPolicy())
	for _, tc := range []struct {
		host string
		port int
		want bool
	}{
		{"example.com", 443, true},
		{"www.example.com", 443, false},
		{"api.example.net", 443, true},
		{"a.b.example.net", 443, true},
		{"example.net", 443, false},
		{"notexample.net", 443, false},
	} {
		got := p.CheckTarget(tc.host, tc.port)
		if got.Allowed != tc.want {
			t.Errorf("%s:%d: allowed=%v code=%s, want %v", tc.host, tc.port, got.Allowed, got.Code, tc.want)
		}
	}
}

func TestOutOfScopeAlwaysOverridesInScope(t *testing.T) {
	input := testPolicy()
	input.InScope = []AssetRule{{Pattern: "*.example.com"}}
	input.OutOfScope = []AssetRule{{Pattern: "admin.example.com"}}
	p := mustCompile(t, input)

	if got := p.CheckTarget("www.example.com", 443); !got.Allowed {
		t.Fatalf("in-scope child denied: %+v", got)
	}
	if got := p.CheckTarget("admin.example.com", 443); got.Allowed || got.Code != CodeExcluded {
		t.Fatalf("explicit exclusion did not win: %+v", got)
	}
}

func TestDefaultInScopePortsAreHTTPOnlyAndExclusionsCoverAllPorts(t *testing.T) {
	input := testPolicy()
	input.InScope = []AssetRule{{Pattern: "*.example.com"}}
	input.OutOfScope = []AssetRule{{Pattern: "admin.example.com"}}
	p := mustCompile(t, input)

	for _, port := range []int{80, 443} {
		if got := p.CheckTarget("api.example.com", port); !got.Allowed {
			t.Errorf("default web port %d denied: %+v", port, got)
		}
	}
	if got := p.CheckTarget("api.example.com", 8443); got.Allowed {
		t.Fatalf("unlisted non-web port unexpectedly allowed: %+v", got)
	}
	if got := p.CheckTarget("admin.example.com", 22); got.Allowed || got.Code != CodeExcluded {
		t.Fatalf("portless out-of-scope rule did not exclude SSH port: %+v", got)
	}
}

func TestPortRestrictionsAndUnknownPort(t *testing.T) {
	input := testPolicy()
	input.InScope = []AssetRule{{Pattern: "api.example.com", Ports: []uint16{443}}}
	p := mustCompile(t, input)

	if got := p.CheckTarget("api.example.com", 443); !got.Allowed {
		t.Fatalf("443 denied: %+v", got)
	}
	if got := p.CheckTarget("api.example.com", 8443); got.Allowed || got.Code != CodeOutOfScope {
		t.Fatalf("8443 should be out of scope: %+v", got)
	}
	if got := p.CheckTarget("api.example.com", 0); got.Allowed || got.Code != CodePortNotAllowed {
		t.Fatalf("unknown port should fail closed for a port-restricted rule: %+v", got)
	}
}

func TestCIDRAndExactIP(t *testing.T) {
	input := testPolicy()
	input.InScope = []AssetRule{
		{Pattern: "203.0.113.0/24"},
		{Pattern: "198.51.100.7"},
	}
	p := mustCompile(t, input)

	for _, tc := range []struct {
		host string
		want bool
	}{
		{"203.0.113.9", true},
		{"203.0.114.9", false},
		{"198.51.100.7", true},
		{"198.51.100.8", false},
	} {
		if got := p.CheckTarget(tc.host, 443); got.Allowed != tc.want {
			t.Errorf("%s: %+v, want allowed=%v", tc.host, got, tc.want)
		}
	}
}

func TestCheckURLRequiresAbsoluteHTTPWithoutUserinfo(t *testing.T) {
	p := mustCompile(t, testPolicy())
	for _, raw := range []string{
		"https://example.com/path",
		"http://example.com/",
	} {
		if got := p.CheckURL(raw); !got.Allowed {
			t.Errorf("%q denied: %+v", raw, got)
		}
	}
	for _, raw := range []string{
		"ftp://example.com/file",
		"//example.com/path",
		"https://user:pass@example.com/",
		"https://example.com:bad/",
		"javascript://example.com/",
	} {
		if got := p.CheckURL(raw); got.Allowed || got.Code != CodeInvalidTarget {
			t.Errorf("%q should be invalid: %+v", raw, got)
		}
	}
}

func TestIDNAAndTrailingDotNormalization(t *testing.T) {
	input := testPolicy()
	input.InScope = []AssetRule{{Pattern: "BÜCHER.example."}}
	p := mustCompile(t, input)

	got := p.CheckURL("https://xn--bcher-kva.example./")
	if !got.Allowed {
		t.Fatalf("IDNA/trailing-dot target denied: %+v", got)
	}
}

func TestNestedWildcardScopeIsAllowedWithoutIncludingItsApex(t *testing.T) {
	input := testPolicy()
	input.InScope = []AssetRule{{Pattern: "*.staging.example.com"}}
	p := mustCompile(t, input)
	if got := p.CheckTarget("api.staging.example.com", 443); !got.Allowed {
		t.Fatalf("nested wildcard child denied: %+v", got)
	}
	if got := p.CheckTarget("staging.example.com", 443); got.Allowed {
		t.Fatalf("nested wildcard unexpectedly included its apex: %+v", got)
	}
}

func TestWildcardMustNotCoverPublicSuffix(t *testing.T) {
	for _, pattern := range []string{"*.com", "*.co.uk", "*.*.example.com", "api.*.example.com"} {
		input := testPolicy()
		input.InScope = []AssetRule{{Pattern: pattern}}
		if _, err := CompileAt(input, policyNow); err == nil {
			t.Errorf("wildcard %q unexpectedly compiled", pattern)
		}
	}
}

func TestCompileRequiresFreshApprovedSnapshot(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ProgramPolicy)
	}{
		{"unsupported schema", func(p *ProgramPolicy) { p.SchemaVersion++ }},
		{"missing approver", func(p *ProgramPolicy) { p.ApprovedBy = "" }},
		{"bad source digest", func(p *ProgramPolicy) { p.SourceSHA256 = "abc" }},
		{"expired", func(p *ProgramPolicy) { p.ExpiresAt = policyNow }},
		{"approval before retrieval", func(p *ProgramPolicy) { p.ApprovedAt = p.RetrievedAt.Add(-time.Second) }},
		{"future retrieval", func(p *ProgramPolicy) { p.RetrievedAt = policyNow.Add(time.Hour) }},
		{"empty scope", func(p *ProgramPolicy) { p.InScope = nil }},
		{"zero rate", func(p *ProgramPolicy) { p.Limits.RequestsPerSecond = 0 }},
		{"excessive concurrency", func(p *ProgramPolicy) { p.Limits.MaxConcurrency = 129 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := testPolicy()
			tc.edit(&input)
			if _, err := CompileAt(input, policyNow); err == nil {
				t.Fatal("invalid policy unexpectedly compiled")
			}
		})
	}
}

func TestExpiredPolicyFailsAtUseTime(t *testing.T) {
	input := testPolicy()
	input.ExpiresAt = policyNow.Add(time.Hour)
	p := mustCompile(t, input)
	got := p.CheckTargetAt("example.com", 443, policyNow.Add(2*time.Hour))
	if got.Allowed || got.Code != CodeExpired {
		t.Fatalf("expired policy was not rejected: %+v", got)
	}
}

func TestOperationPermissionsDefaultToReadOnly(t *testing.T) {
	p := mustCompile(t, testPolicy())
	for _, tc := range []struct {
		op   Operation
		want bool
	}{
		{OperationReadOnly, true},
		{OperationPassiveRecon, false},
		{OperationAuthenticatedRead, false},
		{OperationActiveRecon, false},
		{OperationStateChange, false},
		{OperationDestructive, false},
		{Operation("unknown"), false},
	} {
		if got := p.AllowsOperation(tc.op); got.Allowed != tc.want {
			t.Errorf("%s: %+v, want allowed=%v", tc.op, got, tc.want)
		}
	}
}

func TestResolvedPrivateAddressNeedsExplicitIPScope(t *testing.T) {
	input := testPolicy()
	input.InScope = []AssetRule{{Pattern: "app.example.com"}}
	p := mustCompile(t, input)
	got := p.CheckResolvedIP("app.example.com", 443, "10.20.30.40")
	if got.Allowed || got.Code != CodeNonPublicAddress {
		t.Fatalf("private DNS answer was not blocked: %+v", got)
	}

	input.InScope = []AssetRule{
		{Pattern: "app.example.com"},
		{Pattern: "10.0.0.0/8"},
	}
	p = mustCompile(t, input)
	if got := p.CheckResolvedIP("app.example.com", 443, "10.20.30.40"); !got.Allowed {
		t.Fatalf("explicitly scoped private address denied: %+v", got)
	}

	input.OutOfScope = []AssetRule{{Pattern: "10.20.30.0/24"}}
	p = mustCompile(t, input)
	if got := p.CheckResolvedIP("app.example.com", 443, "10.20.30.40"); got.Allowed || got.Code != CodeExcluded {
		t.Fatalf("resolved-IP exclusion did not win: %+v", got)
	}
}

func TestNumericNonCanonicalHostIsRejected(t *testing.T) {
	input := testPolicy()
	input.InScope = []AssetRule{{Pattern: "127.1"}}
	if _, err := CompileAt(input, policyNow); err == nil {
		t.Fatal("non-canonical numeric host unexpectedly compiled")
	}
	p := mustCompile(t, testPolicy())
	for _, host := range []string{"127.1", "2130706433", "0x7f000001"} {
		got := p.CheckTarget(host, 443)
		if got.Allowed || got.Code != CodeInvalidTarget {
			t.Errorf("%q should be rejected as ambiguous: %+v", host, got)
		}
	}
}

func TestPolicyDigestStableAndSnapshotDetached(t *testing.T) {
	input := testPolicy()
	p1 := mustCompile(t, input)
	p2 := mustCompile(t, input)
	if p1.Digest() == "" || p1.Digest() != p2.Digest() {
		t.Fatalf("digest not stable: %q / %q", p1.Digest(), p2.Digest())
	}
	snapshot := p1.Snapshot()
	snapshot.InScope[0].Pattern = "attacker.example"
	snapshot.InScope[0].Ports = []uint16{1}
	if p1.Snapshot().InScope[0].Pattern == "attacker.example" {
		t.Fatal("snapshot mutation changed compiled policy")
	}
}

func TestInvalidHostPatternsFailClosed(t *testing.T) {
	for _, pattern := range []string{
		"", "https://example.com", "example.com/path", "user@example.com",
		"example.com?x=1", "example..com", "-bad.example.com", "bad-.example.com",
		"127.0.0.1%lo0", "api.example.com:443",
	} {
		input := testPolicy()
		input.InScope = []AssetRule{{Pattern: pattern}}
		if _, err := CompileAt(input, policyNow); err == nil {
			t.Errorf("invalid pattern %q unexpectedly compiled", pattern)
		}
	}
}

func TestReasonCodesAreStable(t *testing.T) {
	p := mustCompile(t, testPolicy())
	got := p.CheckTarget("outside.example.org", 443)
	if got.Code != CodeOutOfScope || !strings.Contains(got.Reason, "not listed") {
		t.Fatalf("unexpected out-of-scope result: %+v", got)
	}
}
