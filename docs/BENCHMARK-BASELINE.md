# ARTEX Benchmark Baseline

Status: baseline metadata recorded; no local benchmark has been executed.  
Date: 2026-11-20  
Commit: `8e6acb0638b033d6c6d93eca1cf5d79853b6803b`

## Existing harness

- Runner: `scripts/benchmark/run_bench.py`
- Method: `scripts/benchmark/README.md`
- Initial corpus: OWASP Juice Shop, ground truth `scripts/benchmark/ground_truth/juice-shop.json`
- Ground truth version: `v1`
- Ground-truth entries: 8
- Extended corpus option: DrostBench v1 (100 docker-compose applications; run harness documentation for setup).
- The runner uses an independent judge and includes a judge falsification battery. Do not use the subject model as judge except as an explicitly marked diagnostic.
- Current repository tree contains no `scripts/benchmark/benchmark-results/` run artifact.

## Upstream CI reference

- Frozen commit: `8e6acb0638b033d6c6d93eca1cf5d79853b6803b`
- Upstream CI run: https://github.com/BaaRai/ARTEX/actions/runs/44555779396
- Observed conclusion: `success`
- This confirms upstream CI reported success for the frozen commit. It does not provide a local baseline runtime, benchmark score, or evidence of bounty acceptance.

## Baseline run record

| Field | Value |
|---|---|
| Commit | `8e6acb0638b033d6c6d93eca1cf5d79853b6803b` |
| OS / architecture | Not run |
| Go toolchain | `go.mod` declares Go 1.26.10; local toolchain not recorded |
| Docker / PostgreSQL | Not run |
| Subject model / provider | Not run |
| Independent judge | Not run |
| Task timeout / turn / token budget | Not run |
| Corpus image digest | Not pinned in this record |
| Random seed | Not run |
| Terminal task status | Not run |
| Ground-truth recall | Not measured |
| Per-gate component / class / mechanism / proof | Not measured |
| Discovery candidates | Not measured |
| False-positive / duplicate bounds | Not measured |
| Tokens and tool calls per verified finding | Not measured |
| Wall-clock time | Not measured |
| Result artifact | None |

## Required benchmark protocol

1. Pin the exact subject commit, Docker image digest, corpus version, policy/task prompt, Skill versions, model identifiers, provider settings, temperature, timeout, turn/token budgets and seed.
2. Pin a judge model different from the subject model. Run the judge falsification battery first.
3. Run each corpus/model/configuration at least three times; rotate order to reduce time/provider bias.
4. Record all findings, not only matches to the ground truth. Extra findings remain candidates until independently verified.
5. Report each gate with numerator/denominator and confidence intervals. Report zero-findings runs; never omit failed or timed-out runs.
6. Measure cost and tool calls per independently verified finding, not per raw report.
7. Run a separate human-labelled bounty-like corpus with known authorization and impact constraints before claiming generalization beyond training labs.
8. Do not use lab benchmark score as a proxy for accepted submissions or monetary rewards.

## Success metric

Primary technical metric: independently verified, in-scope findings per fixed budget, stratified by severity and root cause, with false-positive and duplicate rates reported.

Ultimate product metric: accepted bounty findings and realized reward per researcher-hour / compute cost, tracked only from actual platform dispositions. Pending, rejected, duplicate and accepted outcomes must remain distinct.

No improvement claim is valid until baseline and candidate runs use the same pinned protocol and enough repetitions to make the difference meaningful.
