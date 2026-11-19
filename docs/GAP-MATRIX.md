# ARTEX Gap Matrix

Status: M0 source review; items marked `PARTIAL` are not certified as safe for live bounty use.  
Baseline: `8e6acb0638b033d6c6d93eca1cf5d79853b6803b`

Legend: `EXISTS` = implementation found in source; `PARTIAL` = useful implementation exists but a material gap remains; `MISSING` = no sufficient implementation identified in this review; `UNTESTED` = source suggests a capability but behavior has not been reproduced in the local baseline.

| Area | Existing implementation/evidence | Status | Gap / risk | Next action |
|---|---|---:|---|---|
| Planner / Worker / MainAgent | `agent/planner.go`, `agent/worker.go`, `server/engine.go` | EXISTS | Existing orchestration should be preserved; role/session constraints need audit | D00/D06 |
| Asset graph / exploration graph | `db/exploration.go`, asset stores and graph tools | EXISTS | Asset existence, authorization, and test coverage must remain distinct | D01/D05 |
| TaskScope | `db/task_scope.go` | PARTIAL | Source comment explicitly says this is coverage/query scope, not enforced; it does not block out-of-scope calls | D01/D02 |
| Target Gate | `intercept/target_gate.go`, `guard/guard.go` | PARTIAL | Opt-in; new tasks default off. Approval pins are not a program policy compiler | D02 |
| Target extraction | `intercept/target_extract.go` | PARTIAL | Declared-input inspection cannot prevent undeclared network connections; unknown/custom tools require explicit review | D02 |
| Network egress | `intercept/target_dial.go`, redirect checks, `egress/egress.go` | PARTIAL | Platform-owned HTTP paths are governed, but Bash-launched tools and arbitrary subprocess traffic are not proven to share one enforceable choke point | D02 |
| Rate/concurrency | `egress/egress.go`, `egress/pace.go` | PARTIAL | Egress profiles govern selected HTTP paths; `.env.example` says Bash-launched tools are not throttled. Per-program RPS and concurrency need central enforcement | D02 |
| Redirect / DNS / pinning | `intercept/target_resolve.go`, `target_redirect.go`, `target_dial.go` | EXISTS / UNTESTED | Source includes fresh resolution, redirect checks and pinned dialing; full integration across every client/proxy/subprocess is not yet proven | D00/D02 |
| Side-effect policy | `intercept/alwaysallow_denylist.go`, built-in intercept rules | PARTIAL | Built-in deny rules are not a typed, immutable policy contract; database rules can be configured and tool coverage varies | D01/D02 |
| Browser / MCP / custom tools | `server/assembly.go`, MCP and custom tool wiring, guard hooks | PARTIAL | Need an inventory of every network-capable tool, deferred tool, browser path, MCP transport, custom tool and subprocess escape route | D02 |
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

1. **P0 — authorization is not enforced by TaskScope.** Do not use TaskScope coverage rows as a security boundary.
2. **P0 — Target Gate defaults off.** A bounty task must not be runnable without a compiled, validated policy.
3. **P0 — declared-target extraction is not complete egress enforcement.** A command can create an undeclared connection; arbitrary subprocesses require OS/container/network enforcement or must be disabled.
4. **P0 — rate limiting is incomplete across execution paths.** A per-host governor on selected HTTP clients does not cap all subprocess traffic.
5. **P1 — no unified hunting Skill or ReconFTW adapter.** These follow after the safety execution contract.
6. **P1 — operation-level coverage and independent verification need stronger machine-checkable contracts.**

## M0 exit criteria

- All critical source paths inventoried with file references and current behavior.
- Baseline build, unit tests, race tests and benchmark command/result recorded, or blockers explicitly documented.
- Each P0 gap has a testable requirement and negative test fixture.
- No production behavior changed in M0.
