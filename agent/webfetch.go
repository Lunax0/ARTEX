package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/egress"
	"github.com/Autumn-27/artex/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

// withWebFetch returns tools plus the WebFetch tool of an agent session. Every
// agent kind builds WebFetch here, one tool per run, so that its configuration
// can depend on the run: every redirect hop goes through the target gate
// (intercept.RedirectCheck), and every connection through the pinned dialer
// (intercept.PinnedDialer), on the client that uses proxy and on the direct
// retry client alike. ctx is the context of the run: when it carries a target
// scope the dialer never connects without one, and when that scope's gate is
// on the direct retry is turned off for the run, since it would leave without
// the proxy. The tool is added after the session's own tools, where agentcore
// adds it, so the tool list keeps its order. caCert is the recording proxy's
// CA, trusted to verify the HTTPS it re-signs. Each call goes through the shared
// egress governor (see governedFetch). tools is not modified.
func withWebFetch(ctx context.Context, tools []actool.CoreTool, proxy, caCert string) []actool.CoreTool {
	scope, scoped := intercept.TargetScopeFromContext(ctx)
	gated := scoped && scope.Enabled != nil && scope.Enabled()
	policyBound := scoped && scope.ProgramPolicyRequired
	webFetch := actool.NewWebFetch(actool.WebFetchConfig{Proxy: proxy, CACert: caCert, CheckRedirect: intercept.RedirectCheck("WebFetch"),
		DialContext: intercept.PinnedDialer("WebFetch", scoped), DisableDirectRetry: gated || policyBound})
	return append(tools[:len(tools):len(tools)], governedFetch{webFetch})
}

// egressGovernor resolves the governor of a WebFetch call, once per call so a
// changed noise profile applies to the next call; a test may pin it.
var egressGovernor = egress.Current

func retryablePolicyHTTPStatus(result actool.Result) (int, bool) {
	if result.IsError {
		return 0, false
	}
	line := strings.TrimSpace(strings.SplitN(result.Flatten(), "\n", 2)[0])
	if strings.HasPrefix(line, "[429 ") {
		return http.StatusTooManyRequests, true
	}
	if strings.HasPrefix(line, "[503 ") {
		return http.StatusServiceUnavailable, true
	}
	return 0, false
}

func policyAuditAuthority(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = strconv.Itoa(443)
		} else {
			port = strconv.Itoa(80)
		}
	}
	return net.JoinHostPort(host, port)
}

func (f governedFetch) callWithPolicyRetries(ctx, budgetCtx context.Context, input json.RawMessage, tc *actool.ToolContext, scope intercept.TargetScope, budgetKey string, limits policy.Limits, targetURL *url.URL) (actool.Result, error) {
	result, err := f.CoreTool.Call(budgetCtx, input, tc)
	if err != nil {
		return result, err
	}
	for attempt := 1; attempt <= limits.MaxRetries; attempt++ {
		status, retry := retryablePolicyHTTPStatus(result)
		if !retry {
			break
		}
		if scope.ProgramPolicyCheck == nil {
			return actool.Errorf("ARTEX policy control: policy revocation check is unavailable; retry blocked"), nil
		}
		if err := scope.ProgramPolicyCheck(ctx); err != nil {
			return actool.Errorf("ARTEX policy control: %v; retry blocked", err), nil
		}
		if scope.ProgramPolicyWait == nil {
			return actool.Errorf("ARTEX policy control: shared request budget is unavailable; retry blocked"), nil
		}
		if err := scope.ProgramPolicyWait(ctx, budgetKey, limits); err != nil {
			return actool.Errorf("ARTEX policy control: retry budget unavailable: " + err.Error()), nil
		}
		shift := min(attempt-1, 3)
		delay := time.Duration(1<<shift) * 250 * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return actool.Errorf("ARTEX policy control: request cancelled during retry backoff"), nil
		case <-timer.C:
		}
		if err := scope.ProgramPolicyCheck(ctx); err != nil {
			return actool.Errorf("ARTEX policy control: %v; retry blocked", err), nil
		}
		if scope.ProgramPolicyAudit == nil {
			return actool.Errorf("ARTEX policy control: retry audit writer is unavailable; retry blocked"), nil
		}
		reason := fmt.Sprintf("retrying HTTP %d response after bounded backoff (attempt %d of %d)", status, attempt, limits.MaxRetries)
		if err := scope.ProgramPolicyAudit(ctx, "retry", "WebFetch.Retry", policyAuditAuthority(targetURL), "allow", policy.CodeAllowed, reason, nil); err != nil {
			return actool.Errorf("ARTEX policy control: retry audit could not be persisted; retry blocked"), nil
		}
		result, err = f.CoreTool.Call(budgetCtx, input, tc)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

// governedFetch runs each WebFetch call as one send under the egress governor
// (off by default; then the call runs unchanged). Under a noise profile it
// paces the call by the rate, jitter and concurrency of the URL's host, and
// nothing else: WebFetch calls are neither coalesced nor cached, since each
// tool carries its own proxy and redirect and dial gate (see egress.Do).
// Norma owns the HTTP client, so redirect hops are not paced separately and a
// 429/503 is not retried.
type governedFetch struct {
	actool.CoreTool
}

func (f governedFetch) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var in struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(input, &in) != nil {
		return f.CoreTool.Call(ctx, input, tc)
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Host == "" {
		return f.CoreTool.Call(ctx, input, tc) // the tool reports the bad URL
	}
	if scope, ok := intercept.TargetScopeFromContext(ctx); ok && scope.ProgramPolicyRequired {
		if scope.ProgramPolicy == nil || scope.ProgramPolicyError != "" {
			return actool.Errorf("ARTEX policy control: the required Bug Bounty policy is unavailable; request blocked"), nil
		}
		snapshot := scope.ProgramPolicy.Snapshot()
		limits := snapshot.Limits
		bounded, cancel := context.WithTimeout(ctx, time.Duration(limits.RequestTimeoutSecond)*time.Second)
		defer cancel()
		// Approval timestamps differ between tasks. Key the shared budget by
		// program identity and the exact reviewed source, not the compiled
		// snapshot digest, so parallel tasks for one program share one budget.
		budgetKey := snapshot.ProgramID + ":" + snapshot.SourceSHA256
		if scope.ProgramPolicyAcquire == nil || scope.ProgramPolicyWait == nil {
			return actool.Errorf("ARTEX policy control: shared ProgramPolicy request budget is unavailable; request blocked"), nil
		}
		budgetCtx := intercept.WithRequestBudget(bounded, func(waitCtx context.Context, _ string) error {
			return scope.ProgramPolicyWait(waitCtx, budgetKey, limits)
		})
		return egress.PolicyDo(bounded, u, budgetKey, limits, func() (actool.Result, error) {
			return f.callWithPolicyRetries(bounded, budgetCtx, input, tc, scope, budgetKey, limits, u)
		})
	}
	return egress.Do(egressGovernor(), ctx, u, func() (actool.Result, error) {
		return f.CoreTool.Call(ctx, input, tc)
	})
}
