# M1 ProgramPolicy — Schema v1 and Runtime Status

Status: **partially integrated; not yet certified for live bounty use**  
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
- The normalized snapshot is stored in `tasks.program_policy` (JSONB) in migration `0008_task_program_policy.sql`.
- Legacy tasks with a NULL policy column preserve existing behavior.
- When a task is loaded or restored, the server recompiles the stored snapshot. Invalid, unsupported or expired snapshots remain policy-bound but fail closed.
- The snapshot is immutable for the lifetime of the task. There is no in-place refresh/revocation endpoint yet; expiration stops policy-authorized target requests. Use a new task for a changed policy until an audited reapproval workflow exists.

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

- Per-program/per-host RPS, burst, concurrency, timeout, retry and cancellation budgets are validated but not yet enforced as one shared governor across all execution paths.
- Policy decisions are not yet written to a durable policy audit ledger with digest, rule, resolved IP and decision provenance.
- There is no UI for policy review, source capture, approval, refresh, revocation or expiry notification.
- There is no policy-aware custom HTTP, browser, MCP or subprocess sandbox. These tools are blocked, not policy-enabled.
- Schema v1 has no path/method/account/data-class permissions.
- The added unit/integration tests have not yet been executed in the pinned Go toolchain/CI.

Do not use this milestone alone to authorize live bounty execution until the P0 tests pass, CI is green, the per-program request governor is implemented, and the remaining network escape paths have been independently reviewed.
