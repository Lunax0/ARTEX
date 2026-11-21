# M2 — Policy-Enforced Execution Sandbox

Status: DESIGN DECISION; not implemented. Policy-bound Bash, shell, subprocess, browser/MCP and custom network tools must remain blocked until the acceptance criteria below are met.

## 1. Objective

Enable useful automation tools (including selected ReconFTW modules) without relying on environment proxy variables as a security boundary.

A policy-bound task must not be able to reach an unauthorized destination by:
- ignoring HTTP_PROXY/HTTPS_PROXY/ALL_PROXY;
- using a direct IP, alternate DNS resolver, IPv6, UDP, raw sockets or a custom client;
- spawning child processes or background jobs;
- following redirects to another host;
- changing proxy settings or using a second network interface;
- reusing a stale approval after policy expiry or revocation.

The enforcement boundary must sit below the shell process. A prompt, Guard rule, wrapper script or proxy environment variable alone is insufficient.

## 2. Architecture decision

Use a separate, ephemeral execution environment per policy-bound task/run, plus a policy-aware egress gateway.

ARTEX remains the control plane:
- validates and stamps the immutable ProgramPolicy snapshot;
- creates a short-lived execution grant bound to task ID, program ID, source digest and expiry;
- starts/stops the sandbox and supplies only the task workspace;
- exposes tool output and structured audit events;
- revokes the grant when the source is revoked or expires.

The executor is a separate service/runtime boundary:
- launches an ephemeral OCI container or equivalent isolated workload;
- does not mount the Docker/container runtime socket into ARTEX;
- does not share host PID, IPC or network namespaces;
- runs as an unprivileged identity with no-new-privileges, dropped capabilities, seccomp/AppArmor (or stronger runtime profile), read-only root filesystem, bounded writable workspace/tmpfs, PID/memory/CPU/file-size limits and a hard wall-clock deadline;
- mounts only the task's own workspace and explicitly approved input/output directories;
- never injects platform credentials, JWT keys, database credentials, proxy admin secrets or other tasks' data.

The sandbox network has no direct Internet route. Its only permitted egress is to the policy-aware gateway on a private network. Direct DNS, arbitrary UDP, ICMP, raw sockets and alternate interfaces are denied by the network boundary unless a separately reviewed adapter is added.

## 3. Egress enforcement model

### 3.1 HTTP and HTTPS

The first supported adapter is an explicit forward proxy:
- HTTP requests are checked by scheme, authority, port and current policy revision.
- HTTPS CONNECT is checked by hostname/IP and port before the tunnel is opened.
- The gateway resolves hostnames itself, rejects loopback/private/link-local/reserved/metadata destinations, and pins the checked IP for the upstream socket.
- Redirects to a new authority require a new policy check. Same-authority redirects remain within the already-authorized host/port boundary.
- Proxy authentication is a short-lived task grant, not a shared static credential. It cannot be reused by another task.
- The gateway checks expiry/revocation and shared request budgets before each new request/CONNECT and can terminate active flows on revocation.

Do not claim path/method-level enforcement for HTTPS CONNECT unless TLS is deliberately terminated and the privacy/security implications are separately reviewed. Schema v1 currently authorizes host/port, not path or HTTP method.

### 3.2 DNS

Use a controlled resolver:
- the sandbox cannot contact public DNS resolvers directly;
- queries are checked against the task's explicit in-scope suffixes/IP/CIDR rules;
- DNS answers are recorded and checked for forbidden address classes;
- CNAME chains are followed and checked; an in-scope name resolving to a forbidden or out-of-scope address fails closed;
- cache entries are scoped to the exact policy source digest and have short TTLs;
- DNS rebinding and answer changes are rechecked at connection time.

Do not treat a DNS answer as permanent authorization. The egress gateway must validate the exact IP again at the socket boundary.

### 3.3 Raw TCP and non-HTTP protocols

Do not expose general raw network access in the first release.

- Raw TCP to a literal IP/CIDR may be enabled only when that exact IP/CIDR is explicitly in scope and the port is allowed.
- Domain wildcard authorization does not automatically authorize arbitrary raw TCP to every resolved address; hostname/SNI/vhost ambiguity must be handled by a protocol-aware adapter.
- UDP, ICMP, raw sockets, packet crafting, port scanning and arbitrary SOCKS tunnels remain blocked until each protocol has a reviewed policy adapter, budget enforcement and audit coverage.
- A tool that cannot be proven to use an approved adapter is unavailable in policy-bound tasks.

This is intentionally conservative. Do not advertise full ReconFTW compatibility until every enabled module's network behavior is tested against the sandbox.

## 4. Tool enablement tiers

1. **Tier 0 — internal tools:** graph, task metadata, evidence, report drafting and file operations inside the isolated workspace.
2. **Tier 1 — WebFetch:** current in-process ProgramPolicy enforcement; remains available with the M1 controls.
3. **Tier 2 — HTTP proxy-aware tools:** enable only after integration tests prove the tool uses the task proxy for every request, redirect and retry. Candidate tools include curl/httpx/nuclei/ffuf, but each binary/version/module needs a compatibility record.
4. **Tier 3 — DNS tools:** enable only through the controlled resolver and policy-aware answer logging.
5. **Tier 4 — raw TCP/UDP/ICMP and browser/MCP:** disabled until protocol-specific enforcement and independent review are complete.

ReconFTW is an orchestrator, not a security boundary. Its module list must be filtered to approved tiers; unsupported modules must be disabled rather than silently allowed.

## 5. Revocation, expiry and lifecycle

- Every sandbox receives a short-lived grant bound to task ID + program ID + source SHA-256.
- The gateway rechecks the grant and revocation state before each new flow.
- Revocation prevents new flows immediately and closes existing tracked flows within a bounded interval.
- Expiry terminates the sandbox and invalidates the grant.
- The executor kills the entire process tree/container on cancellation, timeout, policy revocation, task stop or resource-limit breach.
- A failed control-plane/gateway connection means no new network activity; no offline grace period.
- Child tasks/workers must inherit the exact same approved snapshot or receive a new explicit operator approval. They must never inherit broader scope.

## 6. Audit and budgets

The gateway must write durable, sanitized events for:
- task/program/source digest and tool/module identity;
- requested hostname/IP, port and protocol;
- DNS/CNAME chain and resolved IPs;
- allow/deny decision and stable policy code;
- redirect/CONNECT/dial/retry phase;
- token-bucket charge, concurrency lease, start/end time, byte counts and outcome;
- revocation/expiry cancellation.

Never log raw Authorization/Cookie headers, tokens, passwords, request bodies, full URL paths or query strings by default. Payload capture remains a separate opt-in traffic-evidence feature with its own retention and redaction policy.

Budgets are shared across all sandboxes for the same program ID + exact source digest. Retries, redirects and parallel modules consume the same request budget; concurrency is enforced centrally, not per container.

## 7. Required adversarial acceptance tests

The sandbox cannot be marked enabled until all of these pass in a disposable integration environment:

- Direct IPv4/IPv6 TCP, UDP, ICMP, raw sockets and alternate DNS attempts cannot bypass the gateway.
- HTTP_PROXY removal, uppercase/lowercase proxy changes, custom clients and child-process environment changes do not create direct egress.
- In-scope exact host, wildcard host, explicit IP/CIDR and allowed ports work as expected.
- Out-of-scope host, excluded host, disallowed port, private/loopback/link-local/multicast/metadata IP, IPv4-mapped IPv6 and mixed public/private DNS answers are denied.
- CNAME chains, DNS rebinding, TTL expiry, concurrent DNS changes and IPv6 answers are checked at the final socket boundary.
- HTTP and HTTPS redirects to in-scope, excluded, out-of-scope, private and alternate-port destinations are denied or allowed exactly as policy requires.
- Proxy authentication cannot be reused across tasks; one task cannot request another task's policy grant.
- Expiry/revocation during DNS resolution, budget wait, backoff, CONNECT, active transfer and child-process execution stops new activity and terminates tracked flows.
- Rate, burst, concurrency, timeout, retry and cancellation limits are shared across multiple executor instances.
- Container escape surfaces, host mounts, Docker socket access, privileged mode, capabilities, procfs, symlinks, workspace traversal and resource exhaustion are tested.
- Audit database failure blocks new allowed flows; denied events are durably retried or surfaced as an explicit audit degradation.
- Every enabled ReconFTW module/tool binary has a compatibility test and a documented network capability classification.

## 8. Release gates

Do not enable policy-bound Bash or ReconFTW until:
1. executor and gateway are implemented;
2. direct egress is blocked by the network namespace/firewall, not just proxy configuration;
3. all Tier 2/3 tools pass the adversarial suite;
4. revocation and shared budgets are enforced at the gateway;
5. migration/rollback and resource cleanup tests pass;
6. an independent security review signs off;
7. the current branch-head CI and a disposable end-to-end canary pass.

Until then, the correct behavior is to keep shell/subprocess/MCP/custom network tools blocked for policy-bound tasks.