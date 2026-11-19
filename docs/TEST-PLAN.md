# ARTEX Test Plan

Status: planned; M0 source review only. No local test result is claimed.  
Baseline: `8e6acb0638b033d6c6d93eca1cf5d79853b6803b`

## 1. Baseline reproduction

Run from a clean checkout of `dev/m0-baseline-audit` with the pinned Go toolchain and a disposable PostgreSQL database. Do not use a live bounty target.

Record OS/architecture, Go version, Docker version, PostgreSQL version, commit SHA, environment (redact secrets), elapsed time, exit code, and logs.

Suggested sequence:

```bash
git status --short
git rev-parse HEAD
go version
go build ./...
go vet ./...
go test -p 1 ./...
go test -race -p 1 ./agent ./archivestore ./cmd/artex ./config ./db ./evidence ./guard
```

The repository CI also runs frontend checks, shell checks, posture checks, and online SQL index scripts. Reproduce these in CI or a disposable environment; do not silently omit a failed job.

## 2. P0 policy and scope tests (must pass before live-target use)

### ProgramPolicy package tests

The initial suite in `policy/program_test.go` covers exact and wildcard semantics, exclusions, ports, CIDR/IP matching, HTTP URL parsing, IDNA/trailing-dot normalization, public-suffix wildcard rejection, metadata/expiry, read-only defaults, resolved private addresses, ambiguous numeric hosts, digest stability and detached snapshots. These tests have been authored but have **not yet been executed**; run `go test ./policy` when a supported Go toolchain and dependencies are available.

### Policy compilation
- Reject missing/empty policy, malformed URL/domain/CIDR, wildcard overreach, contradictory allow/deny rules, invalid rate/concurrency, and unknown policy versions.
- Preserve exact source policy text, retrieval time, program/version identifier, hash, parser version, and operator approval.
- Fail closed if policy fetch/parse/cache is stale, incomplete, ambiguous or unavailable.
- Distinguish explicit in-scope assets, wildcard semantics, exclusions, third-party infrastructure, account requirements, and prohibited test classes.
- Never promote discovered assets, redirect destinations, DNS neighbors, certificates, CDN origins or linked domains into authorized scope without explicit policy logic.

### Scope enforcement
- Test all supported URL, host, port, IP, IPv6, CIDR, IDNA, trailing-dot, userinfo, percent-encoding, alternate IPv4 notation, redirects, DNS rebinding and mixed-answer cases.
- A redirect to an excluded or unknown host must be blocked before the second request.
- Re-resolve at connect time and verify the connected IP against the approved policy/pin.
- Test direct dial, HTTP(S), SOCKS, upstream proxy, recording proxy, custom HTTP tools, browser, MCP, WebFetch, Bash, shell sessions, background jobs and subprocesses.
- Unknown network-capable tools must fail closed until classified.
- If OS/container egress enforcement is unavailable, disable arbitrary network-capable shell tools for live tasks rather than claiming complete coverage.

### Rate and side effects
- Enforce per-program global and per-host RPS, burst, concurrency, timeout, retry, and backoff across every network execution path.
- Confirm retries honor Retry-After and never exceed the policy cap.
- GET/HEAD/OPTIONS are not automatically safe; operation semantics and policy still apply.
- Block destructive/write operations unless an explicit policy capability and an owned test resource are recorded.
- Prove cancellation, task pause, policy revocation and budget exhaustion stop in-flight and queued work.

### Account/data boundaries
- Use only researcher-owned accounts and objects.
- Verify authorization differences with two researcher-controlled accounts where required.
- Stop immediately if a response contains non-owned personal data; do not enumerate or copy it.
- Store minimum evidence, redact credentials/tokens, and prevent secrets from entering prompts, logs, screenshots or reports.

## 3. P1 workflow tests

- ReconFTW passive/active mode selected only from the policy; passive mode makes no target requests.
- ReconFTW output is typed, size-limited, provenance-tagged and treated as untrusted data.
- Out-of-scope discoveries are recorded as intel only, never auto-scoped or probed.
- Every operation is recorded as `confirmed`, `refuted`, `blocked`, `untested`, `not_applicable`, or `needs_follow_up`, with evidence and reason.
- Coverage denominator is based on eligible operation × vulnerability-class pairs, not merely asset count.
- Planner does not schedule duplicate intents or concurrent conflicting state-changing tests.
- A worker cannot report a confirmed finding without a replayable artifact and required preconditions.
- Independent verifier is a separate run/model context and attempts to falsify the claim.
- Root-cause duplicate detection groups the same underlying flaw, not merely matching titles or URLs.
- VRT mapping uses a pinned catalog version and never fabricates categories or severity.
- Report generator separates observed facts, inference, impact, scope basis and unverified assumptions.
- Human approval required before any submission.

## 4. Regression suites

- Existing guard, intercept, target gate, redirect, DNS resolution, pinned dial, egress, BBOT ingestion, coverage ledger, finding evidence, retest, RSI, task budget, LLM rotation, skill loader and path-confinement tests.
- Go race detector for concurrency-sensitive policy, scheduler, account lock and egress code.
- Fuzz tests for URL/host parsing, policy parsing, scope matching, JSONL ingestion, redirect chains and report evidence binding.
- Integration tests with a local mock HTTP target and controlled DNS resolver. Never use public bounty infrastructure for negative tests.

## 5. Release gates

- P0 negative tests: 100% pass, zero known bypasses.
- Build, vet, full tests and race suites: pass.
- Migration upgrade and rollback: pass on a copy of production-shaped data.
- Benchmark: repeatable pinned corpus; independent judge passes its own falsification battery.
- Canary: isolated, explicitly authorized test target with low request budget and human observation.
- Rollback: documented prior image/commit, DB backup, migration compatibility and feature flags.
