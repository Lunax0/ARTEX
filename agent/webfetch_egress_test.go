package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
		ProgramID: "webfetch-redirect-budget-test",
		PolicyURL: "https://bugcrowd.com/engagements/webfetch-redirect-budget-test",
		SourceSHA256: hex.EncodeToString(source[:]),
		RetrievedAt: now, ApprovedAt: now, ExpiresAt: now.Add(time.Hour),
		ApprovedBy: "test",
		InScope: []policy.AssetRule{{Pattern: "127.0.0.1", Ports: ports}},
		Limits: policy.Limits{
			RequestsPerSecond: 2, Burst: 1, MaxConcurrency: 1,
			RequestTimeoutSecond: 5, MaxRetries: 0,
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	// A unique policy source keeps this test's process-wide budget isolated.
	ctx := intercept.WithTargetScope(t.Context(), intercept.TargetScope{
		TaskID: "webfetch-redirect-budget-test", ProgramPolicyRequired: true, ProgramPolicy: compiled,
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
