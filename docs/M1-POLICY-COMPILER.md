# M1 ProgramPolicy — Schema v1 and Runtime Status

Status: **runtime integrated; not yet certified for live bounty use**  
Package: `policy`  
Branch: `dev/m0-baseline-audit`  
Implementation PR: https://github.com/Lunax0/ARTEX/pull/1

## Purpose

Convert an operator-reviewed Bug Bounty program scope into an immutable authorization snapshot. The compiler is deterministic and fail-closed. It does not scrape policy pages, infer authorization from discovered assets, or approve a program on the operator's behalf.

## Input contract

`policy.ProgramPolicy` requires:

- `schema_version = 1`
- stable `program_id` and absolute HTTPS `policy_url`
- SHA-256 digest of the exact policy source captured by the operator
- `expires_at`
- at least one explicit `in_scope` rule
- bounded request limits: RPS, burst, concurrency, timeout and retries

The compiler also requires `retrieved_at`, `approved_at`, and `approved_by`. When a policy is attached through `POST /api/tasks`, the server overwrites those three fields with server time and the authenticated JWT subject. Client-supplied approval identity/timestamps are ignored.

The source digest is an operator attestation supplied by the caller; schema v1 does not fetch or independently hash the remote policy page. The operator must hash the exact saved policy text before creating the task. The URL and digest are retained in the immutable snapshot.

## Task binding and persistence

- `POST /api/tasks` accepts an optional `program_policy` object.
- The server compiles and validates the policy before creating the task.
- The normalized snapshot is stored in `tasks.program_policy` (JSONB) in migration `0008_task_program_policy.sql`. Migrations `0009` and `0011` add sanitized decision events and exact-source revocation markers; migration `0010` adds shared per-program request-budget state; migration `0012` adds redirect/dial phases and resolved-IP evidence; migration `0013` adds the retry audit phase.
- Legacy tasks with a NULL policy column preserve existing behavior.
- When a task is loaded or restored, the server recompiles the stored snapshot. Invalid, unsupported or expired snapshots remain policy-bound but fail closed.
- The snapshot is immutable for the lifetime of the task. Exact-source revocation is available through the authenticated `POST /api/program-policy/task/{taskID}/revoke` endpoint; `GET /api/program-policy/task/{taskID}/status` reports active, expired or revoked state. Revocation disables every task sharing that program ID and source digest. Revocation is irreversible. There is no in-place refresh endpoint; expiration stops policy-authorized target requests. A changed policy requires a new task and fresh operator approval.

A bounty task must be created with an explicit `program_policy`. The field is optional for ARTEX's non-bounty/legacy task workflows; omission does not create a policy boundary.

## Asset rule semantics

Supported patterns:

- Exact DNS name: `api.example.com`
- Leading wildcard: `*.example.com`
- Exact IPv4/IPv6 literal
- IPv4/IPv6 CIDR

Normalization:

- DNS names are IDNA Lookup-normalized, lowercased and stripped of a trailing dot.
- IP literals are canonicalized; IPv4-mapped IPv6 literals are unmapped.
- Ambiguous numeric host notation, zone-scoped IPs, URLs, paths, userinfo, commands and unsupported wildcard forms are rejected.
- Wildcards match subdomains only, not their apex. A wildcard cannot target a public suffix (for example `*.com` or `*.co.uk`), but a wildcard below a registrable domain (for example `*.staging.example.com`) is valid.
- In-scope rules with omitted `ports` default to HTTP/HTTPS ports 80 and 443; other ports must be explicitly listed. Out-of-scope rules with omitted `ports` exclude every port. A non-empty `ports` list is an explicit allow-list/exclusion list. Unknown port (0) cannot pass a port-restricted rule.
- Every explicit out-of-scope rule takes precedence over every in-scope rule.

Schema v1 is host/IP/CIDR based. It does not yet model path-level inclusions/exclusions, scheme-specific asset rules, account ownership, data classes, or program-specific test categories.

## Operation semantics

Read-only is the baseline. The compiler defines:

- `read_only`: allowed after the target itself passes scope.
- `passive_recon`: requires `allow_passive_recon`.
- `authenticated_read`: requires `allow_authenticated_read`.
- `active_recon`: requires `allow_active_recon`.
- `state_change`: requires `allow_state_changes`.
- `destructive`: requires both `allow_state_changes` and `allow_destructive`.

Runtime mapping is deliberately conservative in this milestone: only built-in `WebFetch` is currently classified as a target-network tool, and it is read-only. Other network-capable tools are blocked rather than assuming a permission flag makes them safe.

## Runtime enforcement implemented

For tasks with a valid ProgramPolicy:

1. Both worker Guard and planner/main-agent TargetGuard receive the immutable snapshot through the task scope.
2. Guard checks ProgramPolicy before user intercept rules and before the optional Target Gate. A user `allow` rule or human pin cannot widen scope.
3. `WebFetch` must declare exactly one valid HTTP(S) URL. The host and port are checked before the tool runs.
4. Every redirect hop is checked independently, even when Target Gate is off.
5. The pinned dialer resolves the hostname freshly, checks every returned address, and dials only the exact IPs it checked. A private, local, excluded or special-purpose answer requires an explicit IP/CIDR rule; out-of-scope IP rules win.
6. When Target Gate is also enabled, its pin/approval requirement remains an additional control. It does not replace ProgramPolicy.
7. Configured proxy egress and platform-derived proxy/service endpoints are blocked for policy-bound target requests until the proxy can enforce the same destination policy.
8. Bash, shell sessions, Monitor, MCP/deferred tools, custom tools and unknown tools are blocked for policy-bound tasks. Known internal/no-target tools remain available; child-task creation and selected global mutation tools are excluded from that allowlist.

This deliberately means ReconFTW and other subprocess-based recon are not available to policy-bound tasks yet. They must not be re-enabled until ARTEX has a real OS/container/network egress sandbox that enforces the same policy.

## Remaining blockers before live bounty use

- PostgreSQL-backed per-program token buckets and concurrency leases enforce the initial WebFetch request, each followed redirect hop and each bounded HTTP 429/503 retry across ARTEX instances sharing the same database. Retries honor max_retries (0–5), recheck revocation, use bounded exponential backoff and write a sanitized retry event before repeating the request. Other network execution paths remain blocked.
- Sanitized policy decision events are persisted in a dedicated table. The application exposes insert/list/get only; it does not provide update/delete APIs. This is not database-enforced append-only protection or cryptographic tamper evidence. Allowed initial WebFetch requests, redirects and dials fail closed if their required event cannot be persisted. Token-bucket usage and request-completion correlation are not yet recorded.
- Exact-source revocation is implemented and checked at Guard, shared-budget acquisition, redirect and final dial boundaries. There is still no in-place policy review/refresh or expiry-notification UI. Expired snapshots fail closed; changed scope requires a newly reviewed task snapshot.
- There is no policy-aware custom HTTP, browser, MCP or subprocess sandbox. These tools are blocked, not policy-enabled.
- Schema v1 has no path/method/account/data-class permissions.
- CI must be checked against the latest branch head before release. Local reproduction, independent adversarial review, migration rollback testing and benchmark reproduction remain outstanding.

Do not use this milestone alone to authorize live bounty execution. The supported WebFetch enforcement path still requires independent security review; policy refresh UI, Retry-After support, token-bucket/request-completion audit and OS/container egress isolation remain incomplete.


## M1.4 request-budget integration

Policy-bound WebFetch calls use a mandatory egress governor keyed by `program_id + source_sha256`, not by the compiled snapshot digest. Separate tasks using the same reviewed program-policy revision therefore share one budget even though their server-stamped approval timestamps differ.

- `requests_per_second` and `burst` share one token bucket across all target hosts for that program revision.
- `max_concurrency` limits concurrent top-level WebFetch invocations for that program revision. A redirect chain retains the same invocation slot.
- `request_timeout_seconds` bounds the complete WebFetch invocation, including time spent waiting for redirect tokens.
- The initial WebFetch request consumes one token in `PolicyDo`.
- Every redirect that is allowed by ProgramPolicy (and by Target Gate, when enabled) consumes another token in `PolicyWait` before net/http follows it.
- A redirect denied by scope, awaiting human approval, or missing its budget callback is not followed. It does not consume a request token.
- Reusing one policy revision key with any different request limits (including timeout) fails closed rather than silently retaining stale limits.
- The current implementation uses PostgreSQL-backed token buckets and concurrency leases keyed by `program_id + source_sha256`. Independent ARTEX instances sharing the same PostgreSQL database share the same budget. Lease expiry recovers slots after process crashes; a deployment using a different database or bypassing the callback would not share the budget.
- WebFetch exposes its HTTP status in the result prefix. Policy-bound requests retry HTTP 429/503 up to `max_retries` (maximum 5), with bounded exponential backoff, a fresh revocation check, a shared PostgreSQL budget charge and a durable retry audit event before each retry. The current Norma WebFetch result does not expose the `Retry-After` header, so the wrapper cannot honor server-provided retry timing; it uses its own bounded backoff.

The budget covers the initial request and each followed redirect hop for the supported WebFetch path across instances sharing the same PostgreSQL database. It is not a complete network sandbox: other network-capable tools remain blocked for policy-bound tasks and must not be enabled until they use the same authorization and budget contract.


## M1.5 ProgramPolicy decision audit

The mandatory Guard now records sanitized policy decisions in a dedicated `program_policy_events` ledger and also mirrors them into the existing `intercept_pending` history store for UI visibility.

- New rows use `decision_source=program_policy` and `decided_by=system`; this is distinct from human, rule and model decisions.
- The persisted request input is deliberately sanitized to the target authority (host:port) only. Raw WebFetch arguments are not copied because they may contain cookies, authorization headers or sensitive query parameters.
- The policy snapshot digest, decision code, task/conversation, agent/tool, action, event phase, target authority, resolved IPs (for dial events), execution status, system actor and timestamp are stored in the dedicated ledger.
- Raw tool input, URL path/query, headers, cookies, credentials and model conversation content are excluded.
- The application exposes no update/delete methods for policy events. This is an application-level write-path convention only, not database-enforced append-only protection or cryptographic tamper evidence; a database role with write privileges can alter rows.
- The approval/history UI displays a dedicated Program policy source badge and filter.
- Allowed initial WebFetch calls fail closed if the dedicated event cannot be inserted. Denials remain denied even if audit persistence fails.

The ledger now records allowed/denied redirect hops and the resolved IPs checked before each policy-bound socket dial. It still does not record token-bucket usage or request completion. Exact-source revocation is recorded separately in `program_policy_revocations` with operator identity, reason and timestamp; the secondary `intercept_pending` mirror remains best-effort.
