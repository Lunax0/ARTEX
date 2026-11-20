package intercept

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Autumn-27/artex/policy"
)

// The HTTP clients the platform owns (WebFetch and the custom http tool)
// follow redirects. The hook and the rendered-URL gate decide on the URL a call
// names; a redirect sends the client to a URL nobody checked. RedirectCheck is
// the redirect policy of those clients: the client asks it before it follows
// each hop, and the hop goes through the same target decision as the call, on
// the URL the client is about to request: the asset block rules on that URL and
// on its target, before any lookup, then exemptions, resolution and pins.

// maxRedirects is the limit net/http applies to a client without a redirect
// policy. Setting a policy replaces it, so RedirectCheck restates it, with the
// same error text.
const maxRedirects = 10

// RedirectCheck returns the redirect policy (http.Client.CheckRedirect) of a
// platform-owned client run by the tool toolName. Everything it needs comes
// from the context of the request, which net/http keeps on every hop: the
// target scope of the session and the Interceptor that owns its gate.
//
// With a policy-bound scope, every hop is checked against the program scope
// and charged to its mandatory request budget, even when the optional gate is
// off. With only a legacy gate-off scope, it applies the default 10-hop limit
// and otherwise leaves redirect behavior unchanged.
func RedirectCheck(toolName string) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("stopped after 10 redirects")
		}
		ctx := req.Context()
		scope, scoped := TargetScopeFromContext(ctx)
		from := ""
		if len(via) > 0 && via[len(via)-1] != nil && via[len(via)-1].URL != nil {
			from = via[len(via)-1].URL.String()
		}
		if scoped && scope.ProgramPolicyRequired {
			decision := checkProgramPolicyURL(scope, req.URL.String())
			if decision.Code != "" {
				return &redirectError{res: decision, from: from, hop: req.URL.String(), scope: scope.scopeName()}
			}
		}
		// The optional Target Gate runs before charging the request budget: a
		// redirect that is denied or awaiting approval is not sent and consumes
		// no request token.
		if scoped && scope.Enabled != nil && scope.Enabled() {
			if from == "" {
				return errors.New("redirect origin is unavailable")
			}
			if err := checkRedirectHop(ctx, scope, toolName, req.URL.String(), from); err != nil {
				return err
			}
		}
		// Every policy-bound redirect that will actually be followed consumes
		// another token. Missing budget wiring is a fail-closed condition; this
		// prevents a future HTTP client from accidentally bypassing accounting.
		if scoped && scope.ProgramPolicyRequired {
			budget, ok := RequestBudgetFromContext(ctx)
			if !ok {
				res := TargetResult{Code: policy.CodeUnavailable, Reason: "the mandatory per-program request budget is unavailable"}
				return &redirectError{res: res, from: from, hop: req.URL.String(), scope: scope.scopeName()}
			}
			if err := budget(ctx, req.URL.String()); err != nil {
				res := TargetResult{Code: policy.CodeUnavailable, Reason: "the per-program request budget could not be acquired: " + err.Error()}
				return &redirectError{res: res, from: from, hop: req.URL.String(), scope: scope.scopeName()}
			}
		}
		return nil
	}
}

// checkProgramPolicyURL applies the mandatory program scope to a redirect
// hop independently of the optional Target Gate.
func checkProgramPolicyURL(scope TargetScope, raw string) TargetResult {
	if scope.ProgramPolicyError != "" || scope.ProgramPolicy == nil {
		reason := scope.ProgramPolicyError
		if reason == "" {
			reason = "the required program policy snapshot is unavailable"
		}
		return TargetResult{Code: policy.CodeUnavailable, Reason: reason}
	}
	decision := scope.ProgramPolicy.CheckURL(raw)
	if decision.Allowed {
		return TargetResult{}
	}
	t, _ := urlTarget(raw)
	return TargetResult{Code: decision.Code, Host: t.Host, Port: t.Port, Reason: decision.Reason}
}

// checkRedirectHop runs the gate decision on one hop, from the URL that
// redirected (from) to the URL the client will request (hop).
func checkRedirectHop(ctx context.Context, scope TargetScope, toolName, hop, from string) error {
	input, _ := json.Marshal(map[string]string{"url": hop, "redirect_from": from})
	blocked := func(res TargetResult) error {
		return &redirectError{res: res, from: from, hop: hop, scope: scope.scopeName()}
	}
	t, err := urlTarget(hop)
	if err != nil {
		return blocked(undeterminedTarget(ctx, scope, toolName, input, "the target of the redirect could not be read ("+err.Error()+")"))
	}
	i := scope.Interceptor
	if i == nil {
		return blocked(TargetResult{Code: TargetGateUnavailable, Host: t.Host, Port: t.Port, Reason: "the session's target scope carries no gate"})
	}
	var origin string
	if o, err := urlTarget(from); err == nil {
		origin = o.String()
	}
	ctx = WithCall(ctx, toolName, input)
	c := &targetCheck{i: i, ctx: ctx, scope: scope, tool: toolName, input: input, urls: []string{hop}, redirectFrom: origin}
	unpinned, res := c.run([]Target{t})
	if res.Code == "" && len(unpinned) > 0 {
		// Wait bound 0: the request is found or created, and the call does not wait.
		scope.WaitBound = 0
		for n := range unpinned {
			unpinned[n].RedirectFrom = origin
		}
		res = i.RequestTargets(ctx, scope, toolName, input, unpinned, nil)
	}
	if res.Code == "" {
		return nil
	}
	return blocked(res)
}

// redirectError is what the client returns when a hop is not followed. Both
// tools hand the client error to the model as the tool result.
type redirectError struct {
	res              TargetResult
	from, hop, scope string
}

func (e *redirectError) Error() string {
	target := e.hop
	if e.res.Host != "" {
		target = targetName(TargetRequest{Host: e.res.Host, Port: e.res.Port})
	}
	msg := "[ARTEX platform control, not target defense] " + e.res.Code + ": " + e.from + " redirects to " + target
	if e.res.Code == TargetApprovalPending {
		return msg + ", which is not approved for " + e.scope + ". The redirect was not followed and an approval was requested. " +
			"Retry the same call after the approval. Do not fetch the redirect target directly or with another tool."
	}
	return msg + ": " + e.res.Reason + ". The redirect was not followed. Do not fetch the redirect target directly or with another tool."
}
