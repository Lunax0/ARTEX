# ARTEX Gap Matrix

Status: M0 source review plus initial M1 ProgramPolicy runtime integration; items marked `PARTIAL` are not certified as safe for live bounty use.  
Baseline: `8e6acb0638b033d6c6d93eca1cf5d79853b6803b`

Legend: `EXISTS` = implementation found in source; `PARTIAL` = useful implementation exists but a material gap remains; `MISSING` = no sufficient implementation identified in this review; `UNTESTED` = source suggests a capability but behavior has not been reproduced in the local baseline.

| Area | Existing implementation/evidence | Status | Gap / risk | Next action |
|---|---|---:|---|---|
| Planner / Worker / MainAgent | `agent/planner.go`, `agent/worker.go`, `server/engine.go` | EXISTS | Existing orchestration should be preserved; role/session constraints need audit | D00/D06 |
| Asset graph / exploration graph | `db/exploration.go`, asset stores and graph tools | EXISTS | Asset existence, authorization, and test coverage must remain distinct | D01/D05 |
| ProgramPolicy compiler + task binding | `policy/program.go`, `db/migrations/0008_task_program_policy.sql`, `server/server.go`, `server/manager.go` | PARTIAL | Immutable snapshot, server-stamped approval, JSONB persistence, reload validation and task Guard binding exist. Policy is optional for legacy tasks; no refresh/revocation UI or durable policy audit yet; tests not yet executed | D01/D02 |
| TaskScope | `db/task_scope.go` | PARTIAL | Source comment explicitly says this is coverage/query scope, not enforced; it does not block out-of-scope calls | D01/D02 |
| Target Gate | `intercept/target_gate.go`, `guard/guard.go` | PARTIAL | Remains opt-in and additional to ProgramPolicy. Policy-bound WebFetch is checked even with Target Gate off; pins/approvals cannot widen scope | D02 |
| Target extraction | `intercept/target_extract.go` | PARTIAL | Declared-input inspection cannot prevent undeclared network connections; unknown/custom tools require explicit review | D02 |
| Network egress | `intercept/target_dial.go`, `intercept/target_redirect.go`, `agent/webfetch.go` | PARTIAL | Policy-bound WebFetch checks redirects, fresh DNS answers and exact dial IPs; proxy paths fail closed. Bash/shell/MCP/custom/unknown tools are blocked for policy-bound tasks. No OS/container egress sandbox exists yet | D02 |
| Rate/concurrency | `egress/egress.go`, `egress/pace.go`, `agent/webfetch.go` | PARTIAL | Policy-bound WebFetch invocations now share a per-program RPS/concurrency budget keyed by program ID + policy source digest and honor the policy timeout. This accounts for one top-level WebFetch call, not each internal redirect hop; non-WebFetch network tools remain blocked. Bash-launched tools remain unthrottled but are disabled for policy-bound tasks | D02 |
| Redirect / DNS / pinning | `intercept/target_resolve.go`, `target_redirect.go`, `target_dial.go` | PARTIAL / UNTESTED | Policy-bound WebFetch checks each redirect and dials only fresh checked addresses; proxy/service exemptions are rejected. Other HTTP transports are blocked pending integration | D02 |
| Side-effect policy | `intercept/alwaysallow_denylist.go`, built-in intercept rules | PARTIAL | Built-in deny rules are not a typed, immutable policy contract; database rules can be configured and tool coverage varies | D01/D02 |
| Browser / MCP / custom tools | `server/assembly.go`, MCP and custom tool wiring, guard hooks | PARTIAL | These tools are denied in policy-bound tasks unless explicitly classified as known internal/no-target. They are not yet policy-enabled or sandboxed | D02 |
| Recon integration | BBOT parser/import in `agent/bbot_ingest.go`; ScopeSentry sync in `server/sync_scopesentry.go` | PARTIAL | BBOT is present; no ReconFTW adapter found. BBOT/ScopeSentry should remain compatibility inputs, not competing schedulers | D04 |
| BBOT ingestion provenance | `agent/bbot_ingest.go`, `agent/bbot_ingest_tool.go`, `skills/bbot-recon/SKILL.md` | EXISTS | Good scope-distance separation and inert treatment of free text; generalize schema/provenance for ReconFTW | D04 |
| Coverage ledger | `agent/coverage_ledger.go`, `db/coverage_ledger.go` | EXISTS | Current ledger is surface × risk area, agent-reported; planned operation × vulnerability-class eligibility needs machine-observed provenance and states | D05 |
| API recon | `skills/api-recon/SKILL.md` and scripts | EXISTS | Skill is detailed but has target-specific procedure assumptions; needs common workflow contract and policy-aware adapter | D03/D05 |
| API security | `skills/api-security/SKILL.md` | EXISTS | Some checklist items imply enumeration or mutation; must be gated by ProgramPolicy, owned accounts and explicit permissions | D03 |
| Bug bounty hunting Skill | User-provided workflow requirements; existing individual skills | MISSING | No unified versioned phase-handoff Skill was found in the shipped skills directory | D03 |
| Findings / evidence | `agent/finding_workflow.go`, `db/finding_verification.go`, traffic binding and evidence quotes | EXISTS | Technical proof and actual impact must remain separate; verifier independence needs test coverage | D07 |
| Retesting | `agent/retester.go`, server retest context/result flow | EXISTS | Ensure retest reuses original policy snapshot and only tests the bound finding | D07 |
| VRT / report quality | Existing report workflow; separate `artex-bugcrowd-vrt-skill` planned by user | PARTIAL | Formal catalog version/provenance and category-null behavior need integration tests | D07 |
| Duplicate detection | Finding dedup seeds and workflow logic | PARTIAL | Need same-program root-cause/repair-equivalence checks; titles or endpoint overlap alone are insufficient | D07 |
| RSI | `docs/rsi-lessons.md`, lesson DB and selection code | EXISTS | Shadow/inject modes exist; bounty acceptance/rejection/reward feedback is not fully integrated | D08 |
| LLM profile routing | `server/task_llm.go`, `agent/budget.go`, llmpool | EXISTS | Static profile chains/rotation exist; no evidence-based role/category reward router yet | D08 |
| Benchmark | `scripts/benchmark/run_bench.py`, Juice Shop ground truth, Drost harness | EXISTS | Infrastructure exists; no checked-in run result found; real bounty acceptance/reward cannot be inferred from lab score | D09 |
| Local baseline | Upstream CI run succeeded on frozen commit | UNTESTED | Current local environment has not run build/tests/bench; upstream CI is not a substitute for our reproducible baseline | D00 |

## Highest-risk blockers

1. **P0 — TaskScope is still not an authorization boundary.** Only tasks created with a valid ProgramPolicy are policy-bound; legacy tasks remain unchanged. A bounty task must include an explicit reviewed policy snapshot.
2. **P0 — ProgramPolicy is not a complete egress sandbox.** WebFetch is policy-checked; Bash/shell/MCP/custom/unknown tools are blocked in policy-bound tasks. Do not re-enable subprocess recon until OS/container egress enforcement exists.
3. **P0 — request budgets are only partially enforced.** Policy-bound WebFetch calls share a per-program token bucket/concurrency budget and timeout. Redirect hops are checked for scope and DNS but are not separately charged as individual requests; any future permitted network tool must use the same governor.
4. **P0 — proxy-aware enforcement is intentionally fail-closed.** Policy-bound WebFetch cannot use a configured proxy until the proxy enforces the same destination policy.
5. **P1 — no unified hunting Skill or ReconFTW adapter.** These follow after the safety execution contract.
6. **P1 — operation-level coverage and independent verification need stronger machine-checkable contracts.**

## M0 exit criteria

- All critical source paths inventoried with file references and current behavior.
- Baseline build, unit tests, race tests and benchmark command/result recorded, or blockers explicitly documented.
- Each P0 gap has a testable requirement and negative test fixture.
- No production behavior changed in M0.
