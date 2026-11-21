package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/egress"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/policy"
	actool "github.com/Autumn-27/norma/tool"
)

// pinNoiseOff runs t with the off noise profile, whatever ARTEX_NOISE_PROFILE says.
func pinNoiseOff(t *testing.T) {
	old := egressGovernor
	egressGovernor = func() *egress.Governor { return egress.New(egress.Profile{Name: "off"}) }
	t.Cleanup(func() { egressGovernor = old })
}

// Under a profile, two WebFetch calls on the same URL in one task both run the
// tool and its redirect gate: WebFetch results are never cached.
func TestWebFetchProfileDoesNotCache(t *testing.T) {
	pair := newRedirectPair(t)
	var checks atomic.Int64
	inner := actool.NewWebFetch(actool.WebFetchConfig{CheckRedirect: func(*http.Request, []*http.Request) error {
		checks.Add(1)
		return nil
	}})
	balanced := egress.New(egress.Profiles["balanced"])
	old := egressGovernor
	egressGovernor = func() *egress.Governor { return balanced }
	t.Cleanup(func() { egressGovernor = old })
	tool := governedFetch{inner}
	ctx := intercept.WithTargetScope(t.Context(), intercept.TargetScope{TaskID: "7"})
	for range 2 {
		res, err := tool.Call(ctx, json.RawMessage(fetchInputJSON(pair.start)), &actool.ToolContext{})
		if err != nil || res.IsError {
			t.Fatalf("WebFetch: err=%v result=%q", err, res.Flatten())
		}
	}
	if checks.Load() != 2 || pair.startHits.Load() != 2 || pair.finalHits.Load() != 2 {
		t.Fatalf("redirect checks %d, start hits %d, final hits %d; want 2 each (no cache hit)",
			checks.Load(), pair.startHits.Load(), pair.finalHits.Load())
	}
}

// TestPolicyBoundWebFetchChargesRedirect verifies the complete wrapper path:
// the initial request consumes the first token and the redirect callback
// consumes a second token before net/http follows the hop.
func TestPolicyBoundWebFetchChargesRedirect(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "")
	}
	finalHits := atomic.Int64{}
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		finalHits.Add(1)
		_, _ = w.Write([]byte("final"))
	}))
	t.Cleanup(final.Close)
	startHits := atomic.Int64{}
	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startHits.Add(1)
		http.Redirect(w, r, final.URL+"/final", http.StatusFound)
	}))
	t.Cleanup(start.Close)

	ports := make([]uint16, 0, 2)
	for _, raw := range []string{start.URL, final.URL} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, uint16(port))
	}
	now := time.Now().UTC()
	source := sha256.Sum256([]byte("policy-bound webfetch redirect budget test " + now.Format(time.RFC3339Nano)))
	compiled, err := policy.CompileAt(policy.ProgramPolicy{
		SchemaVersion: policy.SchemaVersion,
		ProgramID:     "webfetch-redirect-budget-test",
		PolicyURL:     "https://bugcrowd.com/engagements/webfetch-redirect-budget-test",
		SourceSHA256:  hex.EncodeToString(source[:]),
		RetrievedAt:   now,
		ApprovedAt:    now,
		ExpiresAt:     now.Add(time.Hour),
		ApprovedBy:    "test",
		InScope:       []policy.AssetRule{{Pattern: "127.0.0.1", Ports: ports}},
		Limits: policy.Limits{
			RequestsPerSecond:    2,
			Burst:                1,
			MaxConcurrency:       1,
			RequestTimeoutSecond: 5,
			MaxRetries:           0,
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	// A unique policy source keeps this test's process-wide budget isolated.
	ctx := intercept.WithTargetScope(t.Context(), intercept.TargetScope{
		TaskID: "webfetch-redirect-budget-test", ProgramPolicyRequired: true, ProgramPolicy: compiled,
		ProgramPolicyCheck: func(context.Context) error { return nil },
		ProgramPolicyAudit: func(context.Context, string, string, string, string, string, string, []string) error { return nil },
		ProgramPolicyAcquire: func(ctx context.Context, key string, limits policy.Limits) (func(), error) {
			if err := egress.PolicyWait(ctx, key, limits); err != nil {
				return nil, err
			}
			return func() {}, nil
		},
		ProgramPolicyWait: func(ctx context.Context, key string, limits policy.Limits) error {
			return egress.PolicyWait(ctx, key, limits)
		},
	})
	inner := actool.NewWebFetch(actool.WebFetchConfig{CheckRedirect: intercept.RedirectCheck("WebFetch")})
	tool := governedFetch{inner}

	began := time.Now()
	result, err := tool.Call(ctx, json.RawMessage(fetchInputJSON(start.URL+"/start")), &actool.ToolContext{})
	if err != nil || result.IsError {
		t.Fatalf("policy-bound WebFetch: err=%v result=%q", err, result.Flatten())
	}
	if elapsed := time.Since(began); elapsed < 400*time.Millisecond {
		t.Fatalf("redirect was followed without its additional budget wait: %s", elapsed)
	}
	if startHits.Load() != 1 || finalHits.Load() != 1 {
		t.Fatalf("request hits: start=%d final=%d, want one each", startHits.Load(), finalHits.Load())
	}
}

func TestPolicyBoundWebFetchRetries429And503WithBudgetAndAudit(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "")
	}
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch hits.Add(1) {
		case 1:
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("rate limited"))
			return
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("temporary unavailable"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port64, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	source := sha256.Sum256([]byte("policy-bound webfetch retry test " + now.Format(time.RFC3339Nano)))
	compiled, err := policy.CompileAt(policy.ProgramPolicy{
		SchemaVersion: policy.SchemaVersion,
		ProgramID: "webfetch-retry-test",
		PolicyURL: "https://bugcrowd.com/engagements/webfetch-retry-test",
		SourceSHA256: hex.EncodeToString(source[:]),
		RetrievedAt: now, ApprovedAt: now, ExpiresAt: now.Add(time.Hour), ApprovedBy: "test",
		InScope: []policy.AssetRule{{Pattern: "127.0.0.1", Ports: []uint16{uint16(port64)}}},
		Limits: policy.Limits{
			RequestsPerSecond: 100, Burst: 3, MaxConcurrency: 1,
			RequestTimeoutSecond: 10, MaxRetries: 2,
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var checks, waits, audits atomic.Int64
	ctx := intercept.WithTargetScope(t.Context(), intercept.TargetScope{
		TaskID: "webfetch-retry-test", ProgramPolicyRequired: true, ProgramPolicy: compiled,
		ProgramPolicyCheck: func(context.Context) error { checks.Add(1); return nil },
		ProgramPolicyAcquire: func(context.Context, string, policy.Limits) (func(), error) {
			return func() {}, nil
		},
		ProgramPolicyWait: func(context.Context, string, policy.Limits) error {
			waits.Add(1)
			return nil
		},
		ProgramPolicyAudit: func(_ context.Context, phase, tool, authority, action, code, reason string, ips []string) error {
			if phase != "retry" || tool != "WebFetch.Retry" ||
				authority != net.JoinHostPort("127.0.0.1", u.Port()) ||
				action != "allow" || code != policy.CodeAllowed ||
				(!strings.Contains(reason, "HTTP 429") && !strings.Contains(reason, "HTTP 503")) || len(ips) != 0 {
				t.Errorf("unexpected retry audit: phase=%q tool=%q authority=%q action=%q code=%q reason=%q IPs=%v",
					phase, tool, authority, action, code, reason, ips)
			}
			audits.Add(1)
			return nil
		},
	})
	tool := governedFetch{actool.NewWebFetch(actool.WebFetchConfig{
		CheckRedirect: intercept.RedirectCheck("WebFetch"),
	})}
	result, err := tool.Call(ctx, json.RawMessage(fetchInputJSON(server.URL)), &actool.ToolContext{})
	if err != nil || result.IsError {
		t.Fatalf("WebFetch retry: err=%v result=%q", err, result.Flatten())
	}
	if hits.Load() != 3 || waits.Load() != 2 || audits.Load() != 2 || checks.Load() < 4 {
		t.Fatalf("hits=%d waits=%d audits=%d revocation checks=%d; want 3,2,2,and >=4",
			hits.Load(), waits.Load(), audits.Load(), checks.Load())
	}
	if !strings.Contains(result.Flatten(), "[200 OK]") {
		t.Fatalf("final response was not returned: %q", result.Flatten())
	}
}

func TestPolicyBoundWebFetchRetryCapIsAudited(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "")
	}
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("temporarily unavailable"))
	}))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port64, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	source := sha256.Sum256([]byte("policy-bound webfetch retry-cap test " + now.Format(time.RFC3339Nano)))
	compiled, err := policy.CompileAt(policy.ProgramPolicy{
		SchemaVersion: policy.SchemaVersion, ProgramID: "webfetch-retry-cap-test",
		PolicyURL: "https://bugcrowd.com/engagements/webfetch-retry-cap-test",
		SourceSHA256: hex.EncodeToString(source[:]), RetrievedAt: now, ApprovedAt: now,
		ExpiresAt: now.Add(time.Hour), ApprovedBy: "test",
		InScope: []policy.AssetRule{{Pattern: "127.0.0.1", Ports: []uint16{uint16(port64)}}},
		Limits: policy.Limits{RequestsPerSecond: 100, Burst: 2, MaxConcurrency: 1,
			RequestTimeoutSecond: 10, MaxRetries: 1},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var waits atomic.Int64
	var actions []string
	ctx := intercept.WithTargetScope(t.Context(), intercept.TargetScope{
		TaskID: "webfetch-retry-cap-test", ProgramPolicyRequired: true, ProgramPolicy: compiled,
		ProgramPolicyCheck: func(context.Context) error { return nil },
		ProgramPolicyAcquire: func(context.Context, string, policy.Limits) (func(), error) {
			return func() {}, nil
		},
		ProgramPolicyWait: func(context.Context, string, policy.Limits) error {
			waits.Add(1)
			return nil
		},
		ProgramPolicyAudit: func(_ context.Context, phase, tool, authority, action, code, reason string, _ []string) error {
			if phase != "retry" || tool != "WebFetch.Retry" || authority != net.JoinHostPort("127.0.0.1", u.Port()) {
				t.Errorf("unexpected retry audit identity: phase=%q tool=%q authority=%q", phase, tool, authority)
			}
			actions = append(actions, action)
			if action == "deny" && (!strings.Contains(reason, "retry limit exhausted") || code != policy.CodeOperationDenied) {
				t.Errorf("unexpected retry-cap denial: code=%q reason=%q", code, reason)
			}
			return nil
		},
	})
	tool := governedFetch{actool.NewWebFetch(actool.WebFetchConfig{CheckRedirect: intercept.RedirectCheck("WebFetch")})}
	result, err := tool.Call(ctx, json.RawMessage(fetchInputJSON(server.URL)), &actool.ToolContext{})
	if err != nil || result.IsError {
		t.Fatalf("WebFetch retry cap: err=%v result=%q", err, result.Flatten())
	}
	if hits.Load() != 2 || waits.Load() != 1 || len(actions) != 2 || actions[0] != "allow" || actions[1] != "deny" {
		t.Fatalf("hits=%d waits=%d audit actions=%v; want 2,1,[allow deny]", hits.Load(), waits.Load(), actions)
	}
	if !strings.HasPrefix(result.Flatten(), "[503 Service Unavailable]") {
		t.Fatalf("retry cap did not return final 503 response: %q", result.Flatten())
	}
}

func TestPolicyBoundWebFetchRechecksRevocationAfterRetryBackoff(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "")
	}
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("temporarily unavailable"))
	}))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port64, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	source := sha256.Sum256([]byte("policy-bound webfetch retry revocation test " + now.Format(time.RFC3339Nano)))
	compiled, err := policy.CompileAt(policy.ProgramPolicy{
		SchemaVersion: policy.SchemaVersion, ProgramID: "webfetch-retry-revocation-test",
		PolicyURL: "https://bugcrowd.com/engagements/webfetch-retry-revocation-test",
		SourceSHA256: hex.EncodeToString(source[:]), RetrievedAt: now, ApprovedAt: now,
		ExpiresAt: now.Add(time.Hour), ApprovedBy: "test",
		InScope: []policy.AssetRule{{Pattern: "127.0.0.1", Ports: []uint16{uint16(port64)}}},
		Limits: policy.Limits{RequestsPerSecond: 100, Burst: 2, MaxConcurrency: 1,
			RequestTimeoutSecond: 10, MaxRetries: 1},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var checks, waits atomic.Int64
	var actions []string
	ctx := intercept.WithTargetScope(t.Context(), intercept.TargetScope{
		TaskID: "webfetch-retry-revocation-test", ProgramPolicyRequired: true, ProgramPolicy: compiled,
		ProgramPolicyCheck: func(context.Context) error {
			if checks.Add(1) == 4 {
				return fmt.Errorf("policy source revoked during retry backoff")
			}
			return nil
		},
		ProgramPolicyAcquire: func(context.Context, string, policy.Limits) (func(), error) {
			return func() {}, nil
		},
		ProgramPolicyWait: func(context.Context, string, policy.Limits) error {
			waits.Add(1)
			return nil
		},
		ProgramPolicyAudit: func(_ context.Context, phase, tool, authority, action, code, reason string, _ []string) error {
			if phase != "retry" || tool != "WebFetch.Retry" || authority != net.JoinHostPort("127.0.0.1", u.Port()) {
				t.Errorf("unexpected retry audit identity: phase=%q tool=%q authority=%q", phase, tool, authority)
			}
			actions = append(actions, action)
			if action == "deny" && !strings.Contains(reason, "revocation check failed after retry backoff") {
				t.Errorf("unexpected retry revocation denial: %q", reason)
			}
			return nil
		},
	})
	tool := governedFetch{actool.NewWebFetch(actool.WebFetchConfig{CheckRedirect: intercept.RedirectCheck("WebFetch")})}
	result, err := tool.Call(ctx, json.RawMessage(fetchInputJSON(server.URL)), &actool.ToolContext{})
	if err != nil || !result.IsError {
		t.Fatalf("revoked retry should stop with a policy error: err=%v result=%q", err, result.Flatten())
	}
	if hits.Load() != 1 || waits.Load() != 1 || checks.Load() != 4 || len(actions) != 1 || actions[0] != "deny" {
		t.Fatalf("hits=%d waits=%d checks=%d audit actions=%v; want 1,1,4,[deny]",
			hits.Load(), waits.Load(), checks.Load(), actions)
	}
}
