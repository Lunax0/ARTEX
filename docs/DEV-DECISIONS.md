# ARTEX Development Decisions

Status: M0 audit complete; M1 ProgramPolicy runtime slice implemented; latest CI run #59 has Go stable, Web, Shell and Python jobs passed, with Go race tests still running; release certification remains blocked  
Date: 2026-11-20  
Repository: `Lunax0/ARTEX`  
Upstream: `BaaRai/ARTEX`

## 1. Frozen baseline

- Upstream repository: https://github.com/BaaRai/ARTEX
- Fork repository: https://github.com/Lunax0/ARTEX
- Base branch: `main`
- Frozen commit: `8e6acb0638b033d6c6d93eca1cf5d79853b6803b`
- Historical audit reference: `90ca982c5ede13b14ee9a9d94c4abe6ed68fd1a4`
- The fork's `main` was verified to point to the frozen commit before this audit branch was created.
- Upstream CI for the frozen commit: successful run https://github.com/BaaRai/ARTEX/actions/runs/44555779396
- This is a source baseline, not a claim that the code has been built or tested in the current working environment.

## 2. Product objective

Optimize for the number and value of **policy-compliant, real-impact, independently reproducible findings that are ultimately accepted by bounty programs**. Do not optimize raw scan volume, number of agents, number of reports, or token spend.

Track technical verification separately from platform outcomes:
`Verified`, `Submitted/Pending`, `Accepted`, `Duplicate`, `Rejected`, and `Reward` are distinct states. Unknown platform outcomes remain unknown.

## 3. Fixed architecture decisions

1. Keep the existing Go + PostgreSQL + web UI, Planner/Worker/MainAgent, asset graph, exploration graph, evidence, and retest systems. No rewrite and no replacement with another platform.
2. Audit existing code before changing it. Prefer small, test-led, reversible changes.
3. ReconFTW (`six2dez/reconftw`) is the planned default Recon entry point. ARTEX remains focused on authorized vulnerability research. Existing BBOT/ScopeSentry integrations remain compatibility/import paths, not competing default schedulers.
4. Adapt useful workflow contracts from `mdpsec/bug-bounty-hunting-prompts` (phase handoffs, applicability, failure records, two-account checks, chains, independent verification, root-cause deduplication). Do not copy private helper dependencies or instructions that conflict with a program's policy.
5. Add one versioned `bug-bounty-hunting` workflow Skill; reuse existing `api-security`, `api-recon`, and other relevant skills. Keep `artex-bugcrowd-vrt-skill` responsible for versioned VRT mapping/report checks. The first unified phase-handoff Skill now exists at `skills/bug-bounty-hunting/SKILL.md`; loader/runtime discovery and offline handoff validation remain.
6. Reuse existing LLM profiles and role bindings initially. Strong models are candidates for Main/Planner/independent verification; lower-cost models for routine worker tasks. No dynamic reward-driven model router until measured evidence exists.
7. Generate reports for human review only. No automatic bounty submission.
8. Default to read-only. Use only explicitly authorized targets and researcher-controlled accounts/objects. No access to other users' real data. Stop if non-owned PII appears. Respect program rate, concurrency, identification, and tool restrictions.
9. Never infer an asset is in scope because it was discovered, linked, referenced, or loaded by a browser. Third-party systems and sibling domains require explicit authorization.
10. Do not develop against upstream `main`. Use this fork and isolated development branches.

## 4. Current branch and change policy

- Current development branch: `dev/m0-baseline-audit` (contains the frozen audit artifacts plus the initial M1 ProgramPolicy work).
- Frozen parent: `8e6acb0638b033d6c6d93eca1cf5d79853b6803b`
- The fork's `main` remains untouched; all changes are isolated in Draft PR #1.
- Each subsequent change must remain narrowly scoped, include negative tests, pass CI, and have a rollback path.
- PR #1 CI run 44707635509 passed the initial M1 slice. Latest run #59 (44777060032) has Go stable serial tests, Web, Shell and Python jobs passed; Go race tests are still running. Do not merge the Draft PR until current-head CI is fully green, independent security review, remaining P0 gaps and release checks pass.
- Upstream synchronization is a separate change, never mixed with feature work.

## 5. M0 findings that affect sequencing

- `db/task_scope.go` explicitly describes TaskScope as a coverage/query scope, not an execution boundary.
- `target_gate` remains opt-in and new tasks default to it being off.
- `intercept/target_extract.go` documents that target extraction inspects declared tool input; it cannot prevent undeclared connections by itself.
- ProgramPolicy now binds reviewed snapshots to tasks, enforces WebFetch host/port scope, redirects and DNS-resolved dial IPs, blocks unclassified network tools for policy-bound tasks, and fails closed when an allowed initial decision cannot be written to the dedicated audit ledger.
- The Target Gate and pins remain additional approval controls, not substitutes for ProgramPolicy.
- `egress` pacing applies to platform-owned HTTP clients; `.env.example` explicitly states Bash-launched tools are not throttled.
- Coverage ledger, finding evidence checks, retesting, BBOT ingestion, skills, and L3 benchmark infrastructure already exist and should be extended rather than replaced.
- M1 PR #1 workflow run 44707635509 passed all five jobs on 2026-11-20, including Go unit/integration tests and race tests, Go stable serial tests, Web checks/build, ShellCheck/shell tests and Python posture tests. This is CI evidence, not a locally reproduced baseline or independent security review. No benchmark result artifact was found; benchmark reproduction remains pending.

## 6. Priority order

1. D00: complete source audit, baseline and gap matrix.
2. D01: define and persist a machine-readable `ProgramPolicy`.
   - Compiler/matcher: `policy/program.go`, `policy/program_test.go`.
   - Task JSONB persistence, server-stamped approval, task reload compilation and Guard binding now exist.
   - Runtime enforcement currently covers WebFetch, redirects and direct DNS/socket egress; policy-bound Bash/shell/MCP/custom/unknown tools are blocked.
   - Contract and limitations: `docs/M1-POLICY-COMPILER.md`.
3. D02: complete the shared request budget, audit and lifecycle contract, and establish a reviewed OS/container egress boundary before enabling ReconFTW or other subprocess tools.
   - PostgreSQL-backed per-program token buckets and concurrency leases are implemented and tested across independent DB handles.
   - A dedicated sanitized `program_policy_events` ledger exposes only insert/list/get application methods; allowed initial WebFetch decisions fail closed if ledger insertion fails. It is not database-enforced append-only or cryptographically tamper-evident; database owners can still alter rows.
   - Exact-source policy revocation is now supported through an authenticated task-scoped API and checked at Guard, budget acquisition, redirect and final dial boundaries. A revoked source cannot be reactivated; a new reviewed source snapshot is required. In-place refresh/expiry-notification UI, token-bucket usage and request-completion audit, 429/503 retries, and OS/container egress enforcement remain outstanding.
   - CI status must be evaluated on the latest branch-head run; earlier passing runs are not evidence for later commits. Passing CI does not certify the policy boundary against adversarial bypasses.
4. D03: validate the new `bug-bounty-hunting` Skill in the ARTEX loader, add offline handoff fixtures, and ensure it composes existing skills without duplicating their specialist content.
5. D04: ReconFTW adapter with provenance and no scope expansion.
6. D05: operation/resource graph and eligibility-aware coverage.
7. D06: planner intent deduplication, scheduling, and account/session conflict control.
8. D07: prerequisites, attack-chain analysis, independent verification, VRT, and root-cause deduplication.
9. D08: platform feedback, RSI, model-role and cost measurement.
10. D09: controlled benchmarks, canary, rollback, and release.

## 7. Acceptance and release principles

- P0 safety tests must have zero bypasses before any live bounty target experiment.
- New schemas and migrations must be backward compatible and tested.
- Findings must not become submission-ready without evidence and independently verified prerequisites/impact.
- Reports remain human-reviewed.
- Benchmarks must pin corpus version/image digest, prompts, models, budgets, seeds, and independent judge. Report denominators and uncertainty.
- Never claim improvement in accepted findings or reward until actual platform outcomes establish it.

   - ProgramPolicy audit rows intentionally omit conversational/model context and persist only the sanitized target authority plus policy digest. Allowed decisions use `execution_status=unknown` until the tool result can be correlated; the audit does not claim that an allowed request actually completed.
