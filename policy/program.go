// Package policy compiles an operator-reviewed Bug Bounty program policy into
// an immutable, fail-closed authorization snapshot. It deliberately does not
// fetch policy pages or infer scope from discovered assets.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const SchemaVersion = 1

const (
	CodeAllowed          = "POLICY_ALLOWED"
	CodeUnavailable      = "POLICY_UNAVAILABLE"
	CodeOutOfScope       = "POLICY_OUT_OF_SCOPE"
	CodeExcluded         = "POLICY_EXCLUDED"
	CodeInvalidTarget    = "POLICY_INVALID_TARGET"
	CodePortNotAllowed   = "POLICY_PORT_NOT_ALLOWED"
	CodeExpired          = "POLICY_EXPIRED"
	CodeOperationDenied  = "POLICY_OPERATION_DENIED"
	CodeNonPublicAddress = "POLICY_NON_PUBLIC_ADDRESS"
)

type Operation string

const (
	OperationReadOnly          Operation = "read_only"
	OperationPassiveRecon      Operation = "passive_recon"
	OperationAuthenticatedRead Operation = "authenticated_read"
	OperationActiveRecon       Operation = "active_recon"
	OperationStateChange       Operation = "state_change"
	OperationDestructive       Operation = "destructive"
)

// ProgramPolicy is the reviewed, versioned input to the compiler. Scope is
// intentionally explicit: discovering an asset never adds it to InScope.
type ProgramPolicy struct {
	SchemaVersion int          `json:"schema_version"`
	ProgramID     string       `json:"program_id"`
	PolicyURL     string       `json:"policy_url"`
	SourceSHA256  string       `json:"source_sha256"`
	RetrievedAt   time.Time    `json:"retrieved_at"`
	ExpiresAt     time.Time    `json:"expires_at"`
	ApprovedAt    time.Time    `json:"approved_at"`
	ApprovedBy    string       `json:"approved_by"`
	InScope       []AssetRule  `json:"in_scope"`
	OutOfScope    []AssetRule  `json:"out_of_scope,omitempty"`
	Limits        Limits       `json:"limits"`
	Permissions   Permissions  `json:"permissions"`
}

// AssetRule is a host, wildcard domain, IP literal, or CIDR. A wildcard
// "*.example.com" covers subdomains only, not the apex "example.com".
// Empty Ports means the policy did not constrain ports; a non-empty list is
// an explicit allow-list. Path-based scope is not supported by schema v1.
type AssetRule struct {
	Pattern string   `json:"pattern"`
	Ports   []uint16 `json:"ports,omitempty"`
}

type Limits struct {
	RequestsPerSecond    float64 `json:"requests_per_second"`
	Burst                int     `json:"burst"`
	MaxConcurrency       int     `json:"max_concurrency"`
	RequestTimeoutSecond int     `json:"request_timeout_seconds"`
	MaxRetries           int     `json:"max_retries"`
}

// Permissions are opt-in capabilities. Read-only requests to in-scope assets
// are the baseline; authentication, active recon and state changes require an
// explicit permission. Destructive testing is separately gated.
type Permissions struct {
	AllowPassiveRecon      bool `json:"allow_passive_recon"`
	AllowAuthenticatedRead bool `json:"allow_authenticated_read"`
	AllowActiveRecon       bool `json:"allow_active_recon"`
	AllowStateChanges      bool `json:"allow_state_changes"`
	AllowDestructive       bool `json:"allow_destructive"`
}

type Decision struct {
	Allowed         bool   `json:"allowed"`
	Code            string `json:"code"`
	Reason          string `json:"reason"`
	MatchedPattern  string `json:"matched_pattern,omitempty"`
}

type compiledRule struct {
	pattern string
	kind    ruleKind
	domain  string
	prefix  netip.Prefix
	ip      netip.Addr
	ports   map[uint16]struct{}
}

type ruleKind uint8

const (
	ruleExactDomain ruleKind = iota + 1
	ruleWildcardDomain
	ruleIP
	ruleCIDR
)

// CompiledPolicy is immutable after construction. Its fields are private so
// callers cannot widen scope after approval.
type CompiledPolicy struct {
	snapshot ProgramPolicy
	inScope  []compiledRule
	excluded []compiledRule
	digest   string
}

func Compile(input ProgramPolicy) (*CompiledPolicy, error) {
	return CompileAt(input, time.Now())
}

// CompileAt is Compile with an explicit clock, useful for deterministic tests
// and offline policy validation.
func CompileAt(input ProgramPolicy, now time.Time) (*CompiledPolicy, error) {
	if input.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported policy schema version %d", input.SchemaVersion)
	}
	input.ProgramID = strings.TrimSpace(input.ProgramID)
	input.ApprovedBy = strings.TrimSpace(input.ApprovedBy)
	if input.ProgramID == "" {
		return nil, errors.New("program_id is required")
	}
	if input.ApprovedBy == "" {
		return nil, errors.New("approved_by is required")
	}
	if err := validatePolicyURL(input.PolicyURL); err != nil {
		return nil, fmt.Errorf("policy_url: %w", err)
	}
	sum, err := hex.DecodeString(strings.TrimSpace(input.SourceSHA256))
	if err != nil || len(sum) != sha256.Size {
		return nil, errors.New("source_sha256 must be a 64-character SHA-256 hex digest")
	}
	input.SourceSHA256 = strings.ToLower(strings.TrimSpace(input.SourceSHA256))
	if input.RetrievedAt.IsZero() || input.ApprovedAt.IsZero() || input.ExpiresAt.IsZero() {
		return nil, errors.New("retrieved_at, approved_at and expires_at are required")
	}
	if input.RetrievedAt.After(now) || input.ApprovedAt.After(now) {
		return nil, errors.New("retrieved_at and approved_at must not be in the future")
	}
	if input.ApprovedAt.Before(input.RetrievedAt) {
		return nil, errors.New("approved_at must not precede retrieved_at")
	}
	if !input.ExpiresAt.After(input.ApprovedAt) || !input.ExpiresAt.After(now) {
		return nil, errors.New("policy is expired or expires before approval")
	}
	if err := validateLimits(input.Limits); err != nil {
		return nil, err
	}
	if len(input.InScope) == 0 {
		return nil, errors.New("at least one explicit in_scope asset is required")
	}

	compiled := &CompiledPolicy{snapshot: input}
	var compileErr error
	compiled.inScope, compileErr = compileRules(input.InScope)
	if compileErr != nil {
		return nil, fmt.Errorf("in_scope: %w", compileErr)
	}
	compiled.excluded, compileErr = compileRules(input.OutOfScope)
	if compileErr != nil {
		return nil, fmt.Errorf("out_of_scope: %w", compileErr)
	}
	compiled.snapshot.InScope = snapshotRules(compiled.inScope)
	compiled.snapshot.OutOfScope = snapshotRules(compiled.excluded)

	canonical, err := json.Marshal(compiled.snapshot)
	if err != nil {
		return nil, fmt.Errorf("encode compiled policy: %w", err)
	}
	digest := sha256.Sum256(canonical)
	compiled.digest = hex.EncodeToString(digest[:])
	return compiled, nil
}

func validatePolicyURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if !u.IsAbs() || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil {
		return errors.New("must be an absolute HTTPS URL without userinfo")
	}
	if _, err := normalizeHost(u.Hostname()); err != nil {
		return fmt.Errorf("invalid host: %w", err)
	}
	return nil
}

func validateLimits(l Limits) error {
	if math.IsNaN(l.RequestsPerSecond) || math.IsInf(l.RequestsPerSecond, 0) ||
		l.RequestsPerSecond <= 0 || l.RequestsPerSecond > 1000 {
		return errors.New("requests_per_second must be finite and in (0, 1000]")
	}
	if l.Burst < 1 || l.Burst > 1000 {
		return errors.New("burst must be in [1, 1000]")
	}
	if l.MaxConcurrency < 1 || l.MaxConcurrency > 128 {
		return errors.New("max_concurrency must be in [1, 128]")
	}
	if l.RequestTimeoutSecond < 1 || l.RequestTimeoutSecond > 600 {
		return errors.New("request_timeout_seconds must be in [1, 600]")
	}
	if l.MaxRetries < 0 || l.MaxRetries > 5 {
		return errors.New("max_retries must be in [0, 5]")
	}
	return nil
}

func compileRules(rules []AssetRule) ([]compiledRule, error) {
	out := make([]compiledRule, 0, len(rules))
	for i, rule := range rules {
		cr, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%q): %w", i, rule.Pattern, err)
		}
		out = append(out, cr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].pattern != out[j].pattern {
			return out[i].pattern < out[j].pattern
		}
		return portsKey(out[i].ports) < portsKey(out[j].ports)
	})
	return out, nil
}

func compileRule(rule AssetRule) (compiledRule, error) {
	raw := strings.TrimSpace(rule.Pattern)
	if raw == "" {
		return compiledRule{}, errors.New("asset pattern is empty")
	}
	if strings.Contains(raw, "://") || strings.ContainsAny(raw, " \t\r\n?#@") {
		return compiledRule{}, errors.New("asset pattern must be a host, wildcard, IP or CIDR, not a URL or command")
	}
	cr := compiledRule{pattern: raw}
	if len(rule.Ports) > 0 {
		cr.ports = make(map[uint16]struct{}, len(rule.Ports))
		for _, port := range rule.Ports {
			if port == 0 {
				return compiledRule{}, errors.New("port 0 is not valid")
			}
			if _, exists := cr.ports[port]; exists {
				return compiledRule{}, fmt.Errorf("duplicate port %d", port)
			}
			cr.ports[port] = struct{}{}
		}
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		if prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return compiledRule{}, errors.New("CIDR must not contain an IPv6 zone or IPv4-mapped IPv6 address")
		}
		cr.kind, cr.prefix = ruleCIDR, prefix.Masked()
		cr.pattern = cr.prefix.String()
		return cr, nil
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		if ip.Zone() != "" {
			return compiledRule{}, errors.New("IP literals with zones are not supported")
		}
		cr.kind, cr.ip = ruleIP, ip.Unmap()
		cr.pattern = cr.ip.String()
		return cr, nil
	}
	if strings.HasPrefix(raw, "*.") {
		suffix, err := normalizeHost(strings.TrimPrefix(raw, "*."))
		if err != nil {
			return compiledRule{}, err
		}
		registrable, err := publicsuffix.EffectiveTLDPlusOne(suffix)
		if err != nil || registrable != suffix {
			return compiledRule{}, errors.New("wildcard must be rooted at a registrable domain, not a public suffix")
		}
		cr.kind, cr.domain = ruleWildcardDomain, suffix
		cr.pattern = "*." + suffix
		return cr, nil
	}
	if strings.Contains(raw, "*") {
		return compiledRule{}, errors.New("only a leading *.<registrable-domain> wildcard is supported")
	}
	host, err := normalizeHost(raw)
	if err != nil {
		return compiledRule{}, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		cr.kind, cr.ip = ruleIP, ip.Unmap()
	} else {
		cr.kind, cr.domain = ruleExactDomain, host
	}
	cr.pattern = host
	return cr, nil
}

func normalizeHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.ContainsAny(host, "/?#@%") {
		return "", errors.New("invalid host syntax")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", errors.New("IP zones are not supported")
		}
		return ip.Unmap().String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid internationalized domain: %w", err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", errors.New("host length is invalid")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", errors.New("domain must contain at least two labels")
	}
	allNumeric := true
	for _, label := range labels {
		if !numericAddressLabel(label) {
			allNumeric = false
		}
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("domain label is invalid")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("domain label contains an unsupported character")
			}
		}
	}
	if allNumeric {
		return "", errors.New("ambiguous numeric host notation is not supported; use a canonical IP literal")
	}
	return ascii, nil
}

func numericAddressLabel(label string) bool {
	if label == "" {
		return false
	}
	if strings.HasPrefix(label, "0x") && len(label) > 2 {
		for _, c := range label[2:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	for _, c := range label {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func snapshotRules(compiled []compiledRule) []AssetRule {
	out := make([]AssetRule, 0, len(compiled))
	for _, rule := range compiled {
		ports := make([]uint16, 0, len(rule.ports))
		for port := range rule.ports {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		out = append(out, AssetRule{Pattern: rule.pattern, Ports: ports})
	}
	return out
}

func portsKey(ports map[uint16]struct{}) string {
	if len(ports) == 0 {
		return "*"
	}
	values := make([]int, 0, len(ports))
	for p := range ports {
		values = append(values, int(p))
	}
	sort.Ints(values)
	var b strings.Builder
	for _, p := range values {
		b.WriteString(strconv.Itoa(p))
		b.WriteByte(',')
	}
	return b.String()
}

func (p *CompiledPolicy) Digest() string {
	if p == nil {
		return ""
	}
	return p.digest
}

// Snapshot returns a copy of the normalized policy snapshot used to compile p.
func (p *CompiledPolicy) Snapshot() ProgramPolicy {
	if p == nil {
		return ProgramPolicy{}
	}
	out := p.snapshot
	out.InScope = cloneRules(p.snapshot.InScope)
	out.OutOfScope = cloneRules(p.snapshot.OutOfScope)
	return out
}

func cloneRules(in []AssetRule) []AssetRule {
	out := make([]AssetRule, len(in))
	for i, r := range in {
		out[i] = AssetRule{Pattern: r.Pattern, Ports: append([]uint16(nil), r.Ports...)}
	}
	return out
}

func (p *CompiledPolicy) CheckURL(raw string) Decision {
	if p == nil {
		return denied(CodeUnavailable, "no compiled program policy is attached")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.User != nil {
		return denied(CodeInvalidTarget, "target must be an absolute URL without userinfo")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return denied(CodeInvalidTarget, "only HTTP and HTTPS targets are supported by policy schema v1")
	}
	host := u.Hostname()
	if host == "" {
		return denied(CodeInvalidTarget, "target URL has no host")
	}
	port := 80
	if scheme == "https" {
		port = 443
	}
	if rawPort := u.Port(); rawPort != "" {
		n, err := strconv.Atoi(rawPort)
		if err != nil || n < 1 || n > 65535 {
			return denied(CodeInvalidTarget, "target URL has an invalid port")
		}
		port = n
	}
	return p.CheckTarget(host, port)
}

// CheckTarget checks a normalized or raw host/IP and port. port 0 means the
// tool disclosed the host but not its port; it is accepted only by a host rule
// with no explicit port restriction. The network dial layer must always check
// the concrete non-zero port again before connecting.
func (p *CompiledPolicy) CheckTarget(host string, port int) Decision {
	return p.CheckTargetAt(host, port, time.Now())
}

func (p *CompiledPolicy) CheckTargetAt(host string, port int, now time.Time) Decision {
	if p == nil {
		return denied(CodeUnavailable, "no compiled program policy is attached")
	}
	if !p.snapshot.ExpiresAt.After(now) {
		return denied(CodeExpired, "the program policy snapshot has expired; refresh and approve it before continuing")
	}
	if port < 0 || port > 65535 {
		return denied(CodeInvalidTarget, "target port is invalid")
	}
	normalized, err := normalizeHost(host)
	if err != nil {
		return denied(CodeInvalidTarget, "target host is invalid: "+err.Error())
	}
	if rule := firstMatch(p.excluded, normalized, port); rule != nil {
		return Decision{Code: CodeExcluded, Reason: "target matches an explicit out-of-scope rule", MatchedPattern: rule.pattern}
	}
	if rule := firstMatch(p.inScope, normalized, port); rule != nil {
		return Decision{Allowed: true, Code: CodeAllowed, Reason: "target matches the approved program scope", MatchedPattern: rule.pattern}
	}
	if port == 0 {
		return denied(CodePortNotAllowed, "the tool did not disclose a port and no unrestricted host rule matched")
	}
	return denied(CodeOutOfScope, "target is not listed in the approved program scope")
}

func firstMatch(rules []compiledRule, host string, port int) *compiledRule {
	for i := range rules {
		r := &rules[i]
		if len(r.ports) > 0 {
			if port == 0 {
				continue
			}
			if _, ok := r.ports[uint16(port)]; !ok {
				continue
			}
		}
		if r.matchesHost(host) {
			return r
		}
	}
	return nil
}

func (r compiledRule) matchesHost(host string) bool {
	switch r.kind {
	case ruleExactDomain:
		return host == r.domain
	case ruleWildcardDomain:
		return host != r.domain && strings.HasSuffix(host, "."+r.domain)
	case ruleIP:
		ip, err := netip.ParseAddr(host)
		return err == nil && ip.Unmap() == r.ip
	case ruleCIDR:
		ip, err := netip.ParseAddr(host)
		return err == nil && r.prefix.Contains(ip.Unmap())
	default:
		return false
	}
}

// CheckResolvedIP validates the address a hostname resolved to after the host
// itself passed scope matching. Private, loopback, link-local, multicast,
// unspecified and special-purpose addresses require an explicit IP/CIDR
// allow-rule; an out-of-scope IP/CIDR rule always wins.
func (p *CompiledPolicy) CheckResolvedIP(host string, port int, rawIP string) Decision {
	if p == nil {
		return denied(CodeUnavailable, "no compiled program policy is attached")
	}
	base := p.CheckTarget(host, port)
	if !base.Allowed {
		return base
	}
	ip, err := netip.ParseAddr(strings.Trim(rawIP, "[]"))
	if err != nil || ip.Zone() != "" {
		return denied(CodeInvalidTarget, "resolved address is not a valid unzoned IP literal")
	}
	ip = ip.Unmap()
	for i := range p.excluded {
		r := &p.excluded[i]
		if len(r.ports) > 0 {
			if _, ok := r.ports[uint16(port)]; !ok {
				continue
			}
		}
		if r.matchesIP(ip) {
			return Decision{Code: CodeExcluded, Reason: "resolved address matches an explicit out-of-scope rule", MatchedPattern: r.pattern}
		}
	}
	if isSpecialAddress(ip) && !p.explicitlyAllowsIP(ip, port) {
		return denied(CodeNonPublicAddress, "resolved address is private, local, or special-purpose and is not explicitly authorized")
	}
	return Decision{Allowed: true, Code: CodeAllowed, Reason: "hostname is in scope and resolved address passed the address policy", MatchedPattern: base.MatchedPattern}
}

func (r compiledRule) matchesIP(ip netip.Addr) bool {
	switch r.kind {
	case ruleIP:
		return ip.Unmap() == r.ip
	case ruleCIDR:
		return r.prefix.Contains(ip.Unmap())
	default:
		return false
	}
}

func (p *CompiledPolicy) explicitlyAllowsIP(ip netip.Addr, port int) bool {
	for i := range p.inScope {
		r := &p.inScope[i]
		if len(r.ports) > 0 {
			if _, ok := r.ports[uint16(port)]; !ok {
				continue
			}
		}
		if r.matchesIP(ip) {
			return true
		}
	}
	return false
}

func isSpecialAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || !ip.IsGlobalUnicast() {
		return true
	}
	special := []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4", "2001:db8::/32", "2001::/23",
	}
	for _, raw := range special {
		prefix, _ := netip.ParsePrefix(raw)
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *CompiledPolicy) AllowsOperation(op Operation) Decision {
	if p == nil {
		return denied(CodeUnavailable, "no compiled program policy is attached")
	}
	if !p.snapshot.ExpiresAt.After(time.Now()) {
		return denied(CodeExpired, "the program policy snapshot has expired; refresh and approve it before continuing")
	}
	allowed := false
	switch op {
	case OperationReadOnly:
		allowed = true
	case OperationPassiveRecon:
		allowed = p.snapshot.Permissions.AllowPassiveRecon
	case OperationAuthenticatedRead:
		allowed = p.snapshot.Permissions.AllowAuthenticatedRead
	case OperationActiveRecon:
		allowed = p.snapshot.Permissions.AllowActiveRecon
	case OperationStateChange:
		allowed = p.snapshot.Permissions.AllowStateChanges
	case OperationDestructive:
		allowed = p.snapshot.Permissions.AllowStateChanges && p.snapshot.Permissions.AllowDestructive
	default:
		return denied(CodeOperationDenied, "unknown operation class is denied by default")
	}
	if !allowed {
		return denied(CodeOperationDenied, "the program policy does not explicitly authorize this operation class")
	}
	return Decision{Allowed: true, Code: CodeAllowed, Reason: "operation class is authorized by the approved program policy"}
}

func denied(code, reason string) Decision {
	return Decision{Code: code, Reason: reason}
}
