# ARTEX Development Decisions

Status: M0 baseline audit in progress  
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
5. Add one versioned `bug-bounty-hunting` workflow Skill; reuse existing `api-security`, `api-recon`, and other relevant skills. Keep `artex-bugcrowd-vrt-skill` responsible for versioned VRT mapping/report checks.
6. Reuse existing LLM profiles and role bindings initially. Strong models are candidates for Main/Planner/independent verification; lower-cost models for routine worker tasks. No dynamic reward-driven model router until measured evidence exists.
7. Generate reports for human review only. No automatic bounty submission.
8. Default to read-only. Use only explicitly authorized targets and researcher-controlled accounts/objects. No access to other users' real data. Stop if non-owned PII appears. Respect program rate, concurrency, identification, and tool restrictions.
9. Never infer an asset is in scope because it was discovered, linked, referenced, or loaded by a browser. Third-party systems and sibling domains require explicit authorization.
10. Do not develop against upstream `main`. Use this fork and isolated development branches.

## 4. Current branch and change policy

- M0 branch: `dev/m0-baseline-audit`
- Frozen parent: `8e6acb0638b033d6c6d93eca1cf5d79853b6803b`
- No production behavior changes are authorized in M0.
- Each subsequent change must have a narrowly scoped issue/PR, a failing test or baseline first, implementation, CI, regression checks, and a rollback path.
- Upstream synchronization is a separate change, never mixed with feature work.

## 5. M0 findings that affect sequencing

- `db/task_scope.go` explicitly describes TaskScope as a coverage/query scope, not an execution boundary.
- `target_gate` is opt-in and new tasks default to it being off.
- `intercept/target_extract.go` documents that target extraction inspects declared tool input; it cannot prevent undeclared connections.
- The target gate and target pins are useful approval controls, but are not equivalent to a machine-compiled program allow/deny policy enforced at every network egress.
- `egress` pacing applies to platform-owned HTTP clients; `.env.example` explicitly states Bash-launched tools are not throttled.
- Coverage ledger, finding evidence checks, retesting, BBOT ingestion, skills, and L3 benchmark infrastructure already exist and should be extended rather than replaced.
- The current CI run on the frozen upstream commit succeeded, but no benchmark result artifact was found in the repository. Local baseline execution remains pending.

## 6. Priority order

1. D00: complete source audit, baseline and gap matrix.
2. D01: define a machine-readable `ProgramPolicy` and negative test fixtures.
   - Initial implementation exists in `policy/program.go` and `policy/program_test.go`.
   - It is an isolated compiler/matcher only; task persistence, runtime enforcement and test execution remain outstanding.
   - Contract and limitations: `docs/M1-POLICY-COMPILER.md`.
3. D02: enforce Scope/Network/Side-effect policy at all egress paths, fail closed.
4. D03: version and offline-test `bug-bounty-hunting` Skill handoffs.
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
