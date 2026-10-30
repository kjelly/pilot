# Severity and finding rubric (P0–P4)

The project-local `issue-to-pr`, `pr-ready`, `pr-review-merge` and `pilot-code-review` workflows use this shared rubric. Reviewers, SAs and Root classify findings against the same PR base and acceptance contract. This does not change separately installed workflows.

## Severity

| Level | Definition | Blocking |
|---|---|---|
| **P0** | Exploitable security hole, data loss/corruption, leaked secret, or a change that breaks build/startup for everyone. | yes |
| **P1** | A stated acceptance criterion is not met, or the changed behaviour is wrong on its main path with no reasonable workaround. | yes |
| **P2** | A defect or regression **introduced or aggravated by this change**, reachable under the change's intended and supported use, and demonstrable: wrong result, silent failure or false "success", a race with a concrete interleaving, a security weakness under a supported configuration, an acceptance criterion with no test, a test that still passes when the fix is reverted, or a PR description/evidence that materially contradicts the code. | yes |
| **P3** | Edge case outside intended use, hardening, maintainability, inaccurate-but-not-misleading docs, and **any pre-existing defect** (see Origin). | no |
| **P4** | Style, naming, nits. | no |

## Origin (mandatory on every finding)

Compare against the base branch and state one of:

- `introduced` — the change creates the defect. Keeps its severity.
- `aggravated` — the defect existed on base, but this change makes it reachable, worse, or defeats the change's own purpose. Keeps its severity.
- `pre-existing` — the same behaviour is already on base and the change neither touches nor depends on it. **Cap at P3.** Do not block on it; record it for the PR description ("Not in this PR") or a follow-up issue.

A reviewer who cannot say whether the defect exists on base must check it (read `git show BASE:path`, or run the failing case on the base commit) before rating it P2 or higher.

## Evidence for blocking findings

A P0–P2 finding must carry a reproduction: a failing command/test, or a concrete call path with `file:line` that shows how the bad state is reached. A suspicion without either is reported as `needs_evidence` (non-blocking until demonstrated). Before dispatching a Coder for a P2, the Root Agent reproduces or traces it once itself; a finding that does not reproduce is returned to the reviewer, not fixed.

Finding fields: `{id, severity, origin, class, file, line, evidence, impact, remediation}`. `class` is a short root-cause label (e.g. `unvalidated-input`, `error-swallowed`) used for the class rule below.

## Re-review rounds

Round 1 is a full review of the diff against base. For round N ≥ 2, give the reviewer the ledger of earlier findings (id, class, status, fix commit) and the last reviewed SHA, and require:

1. **Verify each closed finding**, ideally by reverting the fix (or mutating it) and confirming the regression test fails.
2. **Review the delta** since the last reviewed SHA in full.
3. **Focus re-review on the delta and its interactions**, while verifying previous closures. Origin is always relative to the PR base, **not** the previous reviewed SHA. An introduced defect missed in an earlier review remains introduced and may block once demonstrated; it does not become P3 because the author has not touched that line since the last round.
4. **Keep severity evidence-based.** A new blocker needs a concrete trigger, impact and base comparison; do not re-rate identical evidence just because a fresh reviewer has different preferences. Missing required validation is a gate/evidence gap; without a reproduction or a concrete causal trace, do not label it a demonstrated runtime bug.

Run one fresh, full-diff review as the last gate before Ready/approval. It may uncover a previously missed introduced/aggravated blocker, which must be resolved. These three skills do not merge PRs.

## Class rule (stop point-fixing)

If a finding has the same `class` as an earlier closed finding, or two findings in one round share a class, do not send the Coder another isolated point fix. Dispatch SA to assess all relevant sites in the affected execution family, including shared helpers, callers/includes and sibling backends; use a repository search to check the scope without expanding into an unrelated audit. Prefer a shared choke-point fix when architecture supports it; otherwise justify consistent multi-site fixes and a matrix covering the affected invariant. Then Coder implements that plan. This applies from the **second** occurrence of a class, not only after three failed rounds.

## Scope

Fix cheap P3s only when this change introduced them and the fix does not touch new behaviour. Everything else goes to "Not in this PR". Never widen the diff just to pre-empt a future reviewer: every extra commit invalidates SHA-bound receipts and starts another review round.
