# ARTEX Test Plan

Status: Verify the latest PR #1 CI run for the current branch head before release. Local reproduction, fuzz/security review, migration rollback testing and benchmark reproduction remain outstanding.
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

### ProgramPolicy package, DB and API tests

- `policy/program_test.go`: exact/wildcard semantics, exclusions, ports, CIDR/IP matching, URL parsing, IDNA/trailing-dot normalization, public-suffix wildcard rejection, metadata/expiry, read-only defaults, resolved private addresses, ambiguous numeric hosts, digest stability and detached snapshots.
- `db/tasks_test.go`: JSONB policy round-trip, legacy NULL behavior and invalid JSON rejection.
- `db/migrate_test.go`: migration sequence includes `0008_task_program_policy.sql`, `0009_program_policy_events.sql`, `0010_program_policy_shared_budget.sql` and `0011_program_policy_revocations.sql`, `0012_program_policy_network_audit.sql`, `0013_program_policy_retry_audit.sql` and `0014_program_policy_events_append_only.sql`.
- `server/program_policy_test.go`: server-stamped approver/timestamps, task persistence, runtime compilation and invalid policy rejection.
- These tests passed in PR #1 workflow run 44707635509. Reproduce locally with `go test ./policy ./db ./server` in the pinned Go toolchain and a disposable PostgreSQL database before release.


### ProgramPolicy audit tests

- `db/intercept_decided_by_test.go`: verify ProgramPolicy decisions persist with `decision_source=program_policy`, `decided_by=system`, sanitized target-only input, policy digest metadata, history detail retrieval and combined filters.
- `db/program_policy_events_test.go`: verify dedicated event persistence, bounded retrieval, validation, redirect/dial event phases, resolved-IP round trip and rejection of malformed target authorities. The event table exposes application-level insert/list/get APIs; migration `0014` also rejects UPDATE, DELETE and TRUNCATE through database triggers. Tests must verify all three mutations fail.
- `db/program_policy_revocations_test.go`: verify immutable first revocation attestation, exact-source lookup, idempotency and validation.
- `server/program_policy_test.go`: verify authenticated revoke/status APIs, reject creation from an already revoked source, and ensure revoking one source disables every task sharing the same program ID + source digest.
- Guard, redirect and dial paths recheck revocation state; missing or unavailable revocation checks fail closed.
- `db/program_policy_budget_test.go`: verify PostgreSQL-backed rate/concurrency sharing across independent DB handles, redirect token charging and cancellation.
- Guard policy-denial tests verify the mandatory block path remains ahead of user rules and Target Gate; allowed requests fail closed if the durable event ledger is unavailable. `web_search` must be denied without `allow_passive_recon` and must fail closed if its allow decision cannot be audited.
- `intercept/target_redirect_test.go` and `intercept/target_dial_test.go`: verify sanitized redirect-hop and resolved-IP dial audit events; allowed network events fail closed if the audit writer is unavailable. Target Gate pins must not widen ProgramPolicy.
- Latest current-head CI results are tracked in GitHub Actions; no earlier passing run substitutes for the current head.

### Policy compilation and task binding
- Reject malformed policy URL/domain/CIDR, wildcard overreach, invalid rate/concurrency, empty scope, malformed source digest and unknown policy versions.
- Verify client-supplied approval identity/timestamps are ignored and server stamps authenticated operator identity/time.
- Verify invalid or expired snapshots remain policy-bound and fail closed on task reload.
- Verify legacy tasks with NULL policy preserve existing behavior.
- The source digest is caller-supplied; the API does not fetch or independently hash the remote policy page.
- Never promote discovered assets, redirect destinations, DNS neighbors, certificates, CDN origins or linked domains into authorized scope.

### Guard, redirect and egress tests
- `guard/program_policy_test.go`: policy applies with Target Gate off, precedes user allow rules, blocks Bash/shell/MCP/deferred/custom/unknown tools, and fails closed without context/snapshot.
- `intercept/target_dial_test.go`: policy-only direct dial, private DNS answer rejection, out-of-scope host rejection, proxy denial, and combined ProgramPolicy + Target Gate pinning.
- `intercept/target_redirect_test.go`: redirect host/scheme policy checks independent of Target Gate.
- Test all supported URL, host, port, IP, IPv6, CIDR, IDNA, trailing-dot, userinfo, alternate IPv4 notation, redirect, DNS rebinding and mixed-answer cases.
- A redirect to an excluded or unknown host must be blocked before the second request.
- Re-resolve at connect time and verify the connected IP against the approved policy; dial only that exact checked IP.
- Configured proxy egress must fail closed until the proxy enforces the same policy.
- Browser, MCP, custom HTTP, Bash, shell sessions, arbitrary subprocesses and unknown tools are blocked in policy-bound tasks; they are not considered policy-enabled.
- If OS/container egress enforcement is unavailable, do not enable arbitrary network-capable shell tools for live tasks.

### Rate and side effects
- Enforce per-program RPS, burst, concurrency and timeout across the supported WebFetch initial request and redirect path using PostgreSQL shared state.
- `agent/webfetch_egress_test.go`: verify HTTP 429 and 503 retries obey `max_retries`, charge the shared per-program request budget, recheck revocation, write retry audit events and return the final response. Retry-After support remains unavailable because the underlying Norma WebFetch result does not expose that response header.
- Extend the same policy budget contract to any future network-capable tool before enabling it.
- GET/HEAD/OPTIONS are not automatically safe; operation semantics and policy still apply.
- Block destructive/write operations unless an explicit policy capability and an owned test resource are recorded.
- Prove cancellation and task pause stop in-flight and queued work. Shared-budget cancellation and exact-source policy revocation have DB/Guard/API tests; add adversarial race tests for revocation during DNS resolution and long-running requests.

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
