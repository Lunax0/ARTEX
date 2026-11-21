package intercept

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/policy"
)

// The HTTP clients the platform owns (WebFetch and the custom http tool)
// connect through PinnedDialer. The hook, the rendered-URL gate and the
// redirect policy decide on a URL, and the client then resolves the name again
// on its own when it connects: a name can answer differently in between. In a
// gated scope the dialer takes a second, independent decision on the address
// it is asked to connect to (the target of the call, of a redirect hop, or a
// proxy). It resolves the name afresh, compares the answer with the pins, and
// connects only to the addresses it compared, never to the name. It never
// waits: an address no pin covers finds or opens the approval request and
// fails the connection at once with TARGET_APPROVAL_PENDING.

// baseDial opens a connection with the dialer settings of http.DefaultTransport.
var baseDial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext

// PinnedDialer returns the DialContext of a platform-owned HTTP client run by
// the tool toolName. The scope is read from the context net/http passes to the
// dial, which carries the values of the request's context: the scope the hook,
// the rendered-URL gate and the redirect policy read.
//
// scoped is whether the client was built for a session with a target scope.
// Such a client never dials without one. Policy-bound scopes are always
// checked, whether or not the optional Target Gate is enabled; legacy scopes
// retain the previous direct-dial behavior when the gate is off.
func PinnedDialer(toolName string, scoped bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		scope, ok := TargetScopeFromContext(ctx)
		switch {
		case !ok && scoped:
			return nil, &dialError{code: TargetGateUnavailable, target: addr, reason: "the target scope of the session did not reach the connection"}
		case !ok:
			return baseDial(ctx, network, addr)
		case scope.ProgramPolicyRequired:
			if scope.ProgramPolicy == nil || scope.ProgramPolicyError != "" {
				reason := scope.ProgramPolicyError
				if reason == "" {
					reason = "the required program policy snapshot is unavailable"
				}
				return nil, &dialError{code: policy.CodeUnavailable, target: addr, reason: reason}
			}
			if scope.Interceptor == nil {
				return nil, &dialError{code: policy.CodeUnavailable, target: addr, reason: "the policy-bound session has no controlled resolver or dialer"}
			}
			if scope.ProgramPolicyCheck == nil {
				return nil, &dialError{code: policy.CodeUnavailable, target: addr, reason: "the ProgramPolicy revocation check is unavailable"}
			}
			if err := scope.ProgramPolicyCheck(ctx); err != nil {
				return nil, &dialError{code: policy.CodeUnavailable, target: addr, reason: err.Error()}
			}
			if scope.ProgramPolicyAudit == nil {
				return nil, &dialError{code: policy.CodeUnavailable, target: addr, reason: "the ProgramPolicy network audit writer is unavailable"}
			}
			if scope.Interceptor.policyProxyConfigured(toolName) {
				return nil, &dialError{code: policy.CodeProxyUnsupported, target: addr, reason: "proxy egress is not yet policy-aware; disable proxies or wait for policy-enforcing proxy support"}
			}
			if scope.Enabled != nil && scope.Enabled() {
				return scope.Interceptor.dialTarget(ctx, scope, toolName, network, addr)
			}
			return scope.Interceptor.dialPolicyTarget(ctx, scope, toolName, network, addr)
		case scope.Enabled == nil || !scope.Enabled():
			if scope.Interceptor != nil {
				return scope.Interceptor.baseDialer()(ctx, network, addr)
			}
			return baseDial(ctx, network, addr)
		case scope.Interceptor == nil:
			return nil, &dialError{code: TargetGateUnavailable, target: addr, reason: "the session's target scope carries no gate"}
		}
		return scope.Interceptor.dialTarget(ctx, scope, toolName, network, addr)
	}
}

// GateOn reports whether ctx carries a target scope whose gate is on.
func GateOn(ctx context.Context) bool {
	_, on := renderedScope(ctx)
	return on
}

func (i *Interceptor) baseDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.dial
}

// policyProxyConfigured reports whether this tool's target connection may
// be routed through a proxy whose ultimate destination ARTEX cannot verify.
// Policy-bound requests fail closed until the proxy itself enforces ProgramPolicy.
func (i *Interceptor) policyProxyConfigured(toolName string) bool {
	i.mu.RLock()
	upstream, toolProxy := i.upstreamProxy, i.toolProxy
	i.mu.RUnlock()
	if upstream != nil && upstream() || toolProxy != nil && toolProxy(toolName) {
		return true
	}
	// Go's default HTTP transport may honor environment proxy variables even
	// when no explicit ARTEX proxy is configured. We cannot infer the proxy's
	// ultimate CONNECT destination from DialContext, so policy-bound requests
	// fail closed whenever an environment proxy is present.
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			return true
		}
	}
	return false
}

func (i *Interceptor) isDerivedEndpoint(host string, port int) bool {
	for _, exemption := range i.DerivedExemptions() {
		if exemption.Host == host && exemption.Port == port {
			return true
		}
	}
	return false
}

func checkPolicyRevocation(ctx context.Context, scope TargetScope) error {
	if !scope.ProgramPolicyRequired {
		return nil
	}
	if scope.ProgramPolicyCheck == nil {
		return errors.New("the ProgramPolicy revocation check is unavailable")
	}
	return scope.ProgramPolicyCheck(ctx)
}

// dialPolicyTarget resolves the hostname once, checks every answer against the
// immutable program scope, and dials only those exact checked IP addresses.
// This path is used when the optional Target Gate is off.
func (i *Interceptor) dialPolicyTarget(ctx context.Context, scope TargetScope, toolName, network, addr string) (net.Conn, error) {
	t, err := addrTarget(network, addr)
	if err != nil {
		return nil, &dialError{code: policy.CodeInvalidTarget, target: addr, reason: "the connection address could not be parsed: " + err.Error()}
	}
	if scope.ProgramPolicy == nil || scope.ProgramPolicyError != "" {
		reason := scope.ProgramPolicyError
		if reason == "" {
			reason = "the required program policy snapshot is unavailable"
		}
		return nil, &dialError{code: policy.CodeUnavailable, target: t.String(), reason: reason}
	}
	if decision := scope.ProgramPolicy.CheckTarget(t.Host, t.Port); !decision.Allowed {
		_ = auditPolicyDial(ctx, scope, toolName, t, "deny", decision.Code, decision.Reason, nil)
		return nil, &dialError{code: decision.Code, target: t.String(), reason: decision.Reason}
	}
	if i.isDerivedEndpoint(t.Host, t.Port) {
		reason := "this connection is routed to a platform-derived service/proxy endpoint whose ultimate egress destination is not controlled by ProgramPolicy"
		_ = auditPolicyDial(ctx, scope, toolName, t, "deny", policy.CodeProxyUnsupported, reason, nil)
		return nil, &dialError{code: policy.CodeProxyUnsupported, target: t.String(), reason: reason}
	}

	var ips []string
	if t.Kind == TargetDomain {
		resolved, lookupErr := i.resolve.lookup(ctx, t.Host, true)
		if lookupErr != nil {
			reason := "the platform could not resolve the in-scope hostname: " + lookupErr.Error()
			_ = auditPolicyDial(ctx, scope, toolName, t, "deny", policy.CodeResolveFailed, reason, nil)
			return nil, &dialError{code: policy.CodeResolveFailed, target: t.String(), reason: reason}
		}
		ips = resolved.ips
	} else {
		ips = []string{t.Host}
	}
	if len(ips) == 0 {
		reason := "the platform resolver returned no addresses"
		_ = auditPolicyDial(ctx, scope, toolName, t, "deny", policy.CodeResolveFailed, reason, nil)
		return nil, &dialError{code: policy.CodeResolveFailed, target: t.String(), reason: reason}
	}
	for _, ip := range ips {
		decision := scope.ProgramPolicy.CheckResolvedIP(t.Host, t.Port, ip)
		if !decision.Allowed {
			reason := decision.Reason + " (resolved address " + ip + ")"
			_ = auditPolicyDial(ctx, scope, toolName, t, "deny", decision.Code, reason, ips)
			return nil, &dialError{code: decision.Code, target: t.String(), reason: reason}
		}
	}
	if err := checkPolicyRevocation(ctx, scope); err != nil {
		_ = auditPolicyDial(ctx, scope, toolName, t, "deny", policy.CodeUnavailable, err.Error(), ips)
		return nil, &dialError{code: policy.CodeUnavailable, target: t.String(), reason: err.Error()}
	}
	if err := auditPolicyDial(ctx, scope, toolName, t, "allow", policy.CodeAllowed, "resolved addresses passed ProgramPolicy checks", ips); err != nil {
		return nil, &dialError{code: policy.CodeUnavailable, target: t.String(), reason: "the dial audit event could not be persisted: " + err.Error()}
	}
	return i.dialAddrs(ctx, toolName, network, ips, t.Port, t)
}

// dialTarget decides one connection of a gated scope and opens it. The asset
// block rules, exemptions and pins are those of the hook, on the target the
// address names, with a fresh lookup. URL rules are not matched: they ran on
// the URL at the hook and on each hop in RedirectCheck.
//
// A derived exemption, and a pin that is name-only for this connection, dial
// the address as received. A stored exemption that holds, and a pin that
// holds every address of the lookup, dial those addresses and nothing else.
func auditPolicyDial(ctx context.Context, scope TargetScope, toolName string, target Target, action, code, reason string, ips []string) error {
	if scope.ProgramPolicyAudit == nil {
		return errors.New("the ProgramPolicy dial audit writer is unavailable")
	}
	authority := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	return scope.ProgramPolicyAudit(ctx, "dial", toolName+".Dial", authority, action, code, reason, ips)
}

func (i *Interceptor) dialTarget(ctx context.Context, scope TargetScope, toolName, network, addr string) (net.Conn, error) {
	input, _ := json.Marshal(map[string]string{"dial": addr})
	ctx = WithCall(ctx, toolName, input)
	t, err := addrTarget(network, addr)
	if err != nil {
		res := undeterminedTarget(ctx, scope, toolName, input, "the address of the connection could not be read ("+err.Error()+")")
		return nil, &dialError{code: res.Code, target: addr, reason: res.Reason}
	}
	blocked := func(res TargetResult) error {
		return &dialError{code: res.Code, target: t.String(), reason: res.Reason}
	}
	if scope.ProgramPolicyRequired {
		decision := scope.ProgramPolicy.CheckTarget(t.Host, t.Port)
		if !decision.Allowed {
			_ = auditPolicyDial(ctx, scope, toolName, t, "deny", decision.Code, decision.Reason, nil)
			return nil, blocked(TargetResult{Code: decision.Code, Reason: decision.Reason})
		}
	}
	c := &targetCheck{i: i, ctx: ctx, scope: scope, tool: toolName, input: input, fresh: true}
	unpinned, res := c.run([]Target{t})
	if res.Code != "" {
		return nil, blocked(res)
	}
	if len(unpinned) > 0 {
		if scope.ProgramPolicyRequired {
			for _, request := range unpinned {
				for _, ip := range request.ResolvedIPs {
					decision := scope.ProgramPolicy.CheckResolvedIP(t.Host, t.Port, ip)
					if !decision.Allowed {
						_ = auditPolicyDial(ctx, scope, toolName, t, "deny", decision.Code, decision.Reason, request.ResolvedIPs)
						return nil, &dialError{code: decision.Code, target: t.String(), reason: decision.Reason + " (resolved address " + ip + ")"}
					}
				}
			}
		}
		// Wait bound 0: the request is found or created, and the dial does not wait.
		scope.WaitBound = 0
		res = i.RequestTargets(ctx, scope, toolName, input, unpinned, nil)
		if res.Code == TargetApprovalPending {
			res.Reason = notCovered(unpinned[0], scope)
		}
		return nil, blocked(res)
	}
	if scope.ProgramPolicyRequired {
		if len(c.checked[0].ips) == 0 {
			reason := "the target gate did not provide resolved addresses for a policy-bound connection"
			_ = auditPolicyDial(ctx, scope, toolName, t, "deny", policy.CodeResolveFailed, reason, nil)
			return nil, &dialError{code: policy.CodeResolveFailed, target: t.String(), reason: reason}
		}
		for _, ip := range c.checked[0].ips {
			decision := scope.ProgramPolicy.CheckResolvedIP(t.Host, t.Port, ip)
			if !decision.Allowed {
				_ = auditPolicyDial(ctx, scope, toolName, t, "deny", decision.Code, decision.Reason, c.checked[0].ips)
				return nil, &dialError{code: decision.Code, target: t.String(), reason: decision.Reason + " (resolved address " + ip + ")"}
			}
		}
		if err := checkPolicyRevocation(ctx, scope); err != nil {
			_ = auditPolicyDial(ctx, scope, toolName, t, "deny", policy.CodeUnavailable, err.Error(), c.checked[0].ips)
			return nil, &dialError{code: policy.CodeUnavailable, target: t.String(), reason: err.Error()}
		}
		if err := auditPolicyDial(ctx, scope, toolName, t, "allow", policy.CodeAllowed, "resolved addresses passed ProgramPolicy and Target Gate checks", c.checked[0].ips); err != nil {
			return nil, &dialError{code: policy.CodeUnavailable, target: t.String(), reason: "the dial audit event could not be persisted: " + err.Error()}
		}
	}
	switch ct := c.checked[0]; ct.cover {
	case coverDerived, coverNameOnly:
		if scope.ProgramPolicyRequired {
			// Policy-bound calls must connect to the exact addresses checked above;
			// never hand the hostname back to the OS resolver.
			return i.dialAddrs(ctx, toolName, network, ct.ips, t.Port, t)
		}
		return i.baseDialer()(ctx, network, addr)
	default:
		return i.dialAddrs(ctx, toolName, network, ct.ips, t.Port, t)
	}
}

// addrTarget reads the address net/http dials, host:port with the host in
// ASCII form and the port always written, as the target urlTarget reads from
// the URL.
func addrTarget(network, addr string) (Target, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return Target{}, fmt.Errorf("network %q is not tcp", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return Target{}, err
	}
	kind, h, ok := normalizeHost(host, true)
	if !ok || kind == TargetCIDR {
		return Target{}, fmt.Errorf("host %q", host)
	}
	t := Target{Kind: kind, Host: h, Port: validPort(port)}
	if t.Port == 0 {
		return Target{}, fmt.Errorf("port %q", port)
	}
	return t, nil
}

// dialAddrs connects to the addresses the decision compared, in their canonical
// order: the first that accepts wins. An address of the wrong family for tcp4
// or tcp6 is skipped. When every attempt fails, the last error is returned.
func (i *Interceptor) dialAddrs(ctx context.Context, toolName, network string, ips []string, port int, policyTarget Target) (net.Conn, error) {
	dial := i.baseDialer()
	var last error = &net.AddrError{Err: "no suitable address found", Addr: strings.Join(ips, ", ")}
	for _, ip := range ips {
		a, err := netip.ParseAddr(ip)
		if err != nil || network == "tcp4" && !a.Is4() || network == "tcp6" && !a.Is6() {
			continue
		}
		if scope, ok := TargetScopeFromContext(ctx); ok && scope.ProgramPolicyRequired {
			if err := checkPolicyRevocation(ctx, scope); err != nil {
				_ = auditPolicyDial(ctx, scope, toolName, policyTarget, "deny", policy.CodeUnavailable, err.Error(), []string{ip})
				return nil, &dialError{code: policy.CodeUnavailable, target: net.JoinHostPort(ip, strconv.Itoa(port)), reason: err.Error()}
			}
		}
		conn, err := dial(ctx, network, net.JoinHostPort(ip, strconv.Itoa(port)))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

// notCovered says why a connection needs an approval: the addresses the dial
// resolved, and the pin they fall outside of.
func notCovered(r TargetRequest, scope TargetScope) string {
	if r.Pin != nil {
		return fmt.Sprintf("%s now resolves to %s, outside pin v%d (%s) of %s",
			r.Host, strings.Join(r.ResolvedIPs, ", "), r.Pin.Version, strings.Join(r.Pin.PinnedIPs, ", "), scope.scopeName())
	}
	if r.Kind != TargetDomain {
		return fmt.Sprintf("%s is not approved for %s", r.Host, scope.scopeName())
	}
	return fmt.Sprintf("%s resolves to %s and is not approved for %s", r.Host, strings.Join(r.ResolvedIPs, ", "), scope.scopeName())
}

// dialError is what PinnedDialer returns for a connection it does not open.
// Both clients hand the error to the model as the tool result.
type dialError struct {
	code, target, reason string
}

func (e *dialError) Error() string {
	msg := "[ARTEX platform control, not target defense] " + e.code + ": the connection to " + e.target + " was not opened: " + e.reason + "."
	if e.code == TargetApprovalPending {
		msg += " An approval was requested. Retry the same call after the approval."
	}
	return msg + " Do not fetch the target with another tool or by its address."
}
