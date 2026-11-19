# M1 ProgramPolicy Compiler — Schema v1

Status: implemented as an isolated compiler/matcher; runtime integration is not complete.  
Package: `policy`  
Branch: `dev/m0-baseline-audit`

## Purpose

Convert an operator-reviewed, versioned program scope into an immutable authorization snapshot. The compiler is deliberately deterministic and fail-closed. It does not scrape a program page, infer authorization from discovered assets, or approve a program on the operator's behalf.

## Input contract

`policy.ProgramPolicy` requires:

- `schema_version = 1`
- stable `program_id` and HTTPS `policy_url`
- SHA-256 digest of the exact policy source captured by the operator
- `retrieved_at`, `approved_at`, `expires_at`, and non-empty `approved_by`
- at least one explicit `in_scope` rule
- explicit bounded request limits: RPS, burst, concurrency, timeout and retries

The compiler rejects an expired snapshot, future retrieval/approval timestamps, malformed source digest, empty scope, unsupported schema version, and out-of-bounds limits.

The source digest is an attestation supplied by the caller; schema v1 does not fetch or independently hash a remote policy document. The caller must hash the exact saved source before approval.

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
- Empty `ports` means the reviewed policy did not constrain ports. A non-empty `ports` list is an explicit allow-list. Unknown port (0) cannot pass a port-restricted rule.
- Every explicit out-of-scope rule takes precedence over every in-scope rule.

Schema v1 is host/IP/CIDR based. It does not yet model path-level inclusions/exclusions, scheme-specific asset rules, account ownership, data classes, or program-specific test categories.

## Operation semantics

Read-only is the baseline. These operation classes are separate:

- `read_only`: allowed after the target itself passes scope.
- `passive_recon`: requires `allow_passive_recon`.
- `authenticated_read`: requires `allow_authenticated_read`.
- `active_recon`: requires `allow_active_recon`.
- `state_change`: requires `allow_state_changes`.
- `destructive`: requires both `allow_state_changes` and `allow_destructive`.

Unknown operation classes are denied. These are policy labels only until the runtime maps each concrete tool/action to a class; do not treat the compiler package alone as enforcement.

## URL and resolved-address checks

- `CheckURL` accepts absolute HTTP/HTTPS URLs only, rejects userinfo, invalid hosts and invalid/empty ports, then checks the canonical host and effective port.
- `CheckTarget` checks an extracted host/IP and optional port.
- `CheckResolvedIP` first checks the hostname scope, then checks each resolved IP. Private, loopback, link-local, multicast, unspecified and selected special-purpose ranges require an explicit in-scope IP/CIDR rule. An out-of-scope IP/CIDR rule wins.

The network dialer must call the resolved-address check on the exact addresses it will connect to, after a fresh resolution. A check performed earlier on the URL alone is not sufficient against DNS rebinding.

## Runtime integration still required

This package is **not yet wired into**:

1. Task creation, PostgreSQL persistence, task reload, or policy revocation.
2. `guard.Guard` and every worker/planner/main-agent tool hook.
3. WebFetch/custom HTTP URL rendering, redirects, pinned dialing and DNS resolution.
4. MCP/custom tools and browser/network transports.
5. Bash, interactive shells, ReconFTW and arbitrary subprocess network traffic.
6. Global per-program/per-host RPS, burst, concurrency, retries and cancellation.
7. A policy review UI, audit history and expiry/re-approval workflow.

Until these paths are integrated and negative tests prove there is no bypass, do not use this package as the sole authorization boundary for a live bounty task. The current target approval gate remains a separate optional control and must never override ProgramPolicy.
