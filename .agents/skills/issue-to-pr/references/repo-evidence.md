# Repository evidence rules

Some facts about "valid evidence" belong to the repository, not to these skills: which files are evidence rather than behaviour, and which evidence every change must carry (for example a real-VM run mandated by `AGENTS.md`). The skills provide the mechanism; the repository declares the content in `.github/pr-evidence.json`.

## The manifest

```json
{
  "schema_version": 1,
  "evidence_only_paths": ["qa/evidence/**"],
  "required_evidence": [
    {"id": "e2e-run", "source": "CONTRIBUTING.md#verification",
     "artifact_glob": "qa/evidence/**/*.md",
     "description": "Fresh-VM run of the changed playbooks: base fails, candidate passes."}
  ]
}
```

- **Read from the base branch** (`origin/<base>`), never from the PR head. A change cannot grant itself an exemption. If the manifest is itself part of the change, it takes effect only after it is merged.
- `evidence_only_paths`: globs (`*`, `**`, `?`) for files that hold evidence only. Default is none, meaning strict SHA binding. A glob that would cover all code of a language or all build files (`**`, `**/*.go`, `*`) is rejected. Only list paths no test, build step or runtime reads. If a test reads `AGENTS.md` or a docs file, that file is behaviour, not evidence.
- `required_evidence[].artifact_glob`: where the committed artifact for that item must live. These paths are also treated as evidence-only.
- `required_evidence[].required_paths` (optional): repository-relative globs whose change always needs that evidence. When the change (from the merge base with the base branch to HEAD, both names of a rename) touches one, `not-applicable` is refused and only a `pass` entry satisfies the gate. A broad glob only makes the rule stricter, so the whole-tree check above does not apply. pr-review-merge refuses `not-needed` for the same paths, so an Issue PR does not reach Ready only to wait at the merge gate.
- Check the manifest the way the gate sees it: `python3 scripts/repo_evidence.py --worktree WT --base-ref origin/main`.

## Evidence-only delta

A check receipt, an independent review, or a required-evidence run taken at commit `R` is still accepted for HEAD when `R` is an ancestor of HEAD and **every file changed between `R` and HEAD matches** `evidence_only_paths`. The gate computes this itself with `git diff`; no agent attestation is involved. Accepted deltas are listed in the gate output under `repo_evidence.delta_accepted`. The top-level `evidence.head_sha` must still equal HEAD, and the remote branch must still equal the validated HEAD.

The Root Agent still reads the evidence commit. The rule saves a 30-minute rerun when only a run record was added; it does not make the record honest.

## Required evidence entries

For every `required_evidence` id (and any extra requirement you list from `AGENTS.md`), add to the evidence JSON:

```json
"repo_required_evidence": [
  {"id": "e2e-run", "status": "pass", "head_sha": "<commit the run used>",
   "artifact": "qa/evidence/foo/2026-10-28-ab12cd3.md",
   "summary": "Staging deploy of the candidate: base fails the smoke suite, candidate passes."},
  {"id": "other-id", "status": "not-applicable",
   "reason": "Docs-only change; no runtime behaviour touched.", "reviewer_confirmed": true}
]
```

The gate requires one entry per declared id, `status` `pass` or `not-applicable`; for `pass`: `head_sha` covers HEAD (same commit or evidence-only delta), a `summary` of what was observed, and where the evidence lives:

- a repository-relative `artifact` that is **committed at HEAD** (and inside `artifact_glob` when the manifest declares one), or
- an `https://` `url`, only when the manifest item declares no `artifact_glob`: for evidence kept outside the repository such as a CI run, a test-management record or a wiki page. `not-applicable` needs a specific reason (30+ chars) and `reviewer_confirmed: true`, and is refused when the change touches the item's `required_paths`.

## No manifest

The gate cannot check what it was not told, and prints a warning (`repo_evidence.warnings`). Before the first worker is dispatched, read `AGENTS.md`, `CONTRIBUTING`, the PR template and CI config; write mandated tests, live runs, docs and changelog into the checkpoint as acceptance items, and tell the user the material requirements. Proceed under existing authorization; only clarify genuinely unresolved intent, target or destructive boundaries. Add what applies to `repo_required_evidence`. Do not infer an `evidence_only_paths` list yourself; leave it empty unless declared by the base manifest.

## Order of work

Long checks are expensive, and any commit invalidates SHA-bound receipts unless the delta is evidence-only. Work in this order:

1. Freeze code/tests as a clean candidate commit. Obtain an independent preliminary code review that identifies unresolved findings and required target runs. This is not final PASS while mandatory evidence is missing.
2. Gather repository-required evidence (live runs and relevant failure paths) against that exact candidate.
3. Have the independent Reviewer inspect the candidate-bound artifacts and full diff, then issue final PASS only when all required verification is complete and blockers are resolved.
4. Commit sanitized evidence separately. A record being evidence-only for repo publication does not automatically make its delta accepted by the Python gate: without base-manifest allowances, checks/review remain strictly SHA-bound and must cover the new HEAD. Never let the PR declare its own exemption.
5. Run long receipts (`run_check.py`) on the final HEAD, or reuse candidate receipts only when the gate accepts the evidence-only delta. Refresh the final review on the actual HEAD when required; do not claim the earlier PASS covers an unaccepted delta.
6. Run the gate.

If a live run or review changes executable content, go back to step 1; affected later artifacts are stale. An accepted evidence-only delta needs content inspection, not another VM run with identical execution inputs.

## Examples for other kinds of repositories

The mechanism is the same everywhere; only the manifest differs. `evidence_only_paths` and `artifact_glob` can be any layout, and both are optional.

| Repository | Manifest |
|---|---|
| Python library; coverage and compatibility report kept in CI | `{"schema_version":1,"required_evidence":[{"id":"compat-matrix","source":"CONTRIBUTING.md#testing"}]}`, entry gives the CI run as `url` |
| Web app; Playwright run on staging, report committed | `{"schema_version":1,"evidence_only_paths":["test-reports/**"],"required_evidence":[{"id":"staging-e2e","source":"docs/release.md","artifact_glob":"test-reports/staging/**"}]}` |
| Infrastructure repo; apply on a throwaway environment | `{"schema_version":1,"evidence_only_paths":["runs/**"],"required_evidence":[{"id":"plan-apply","source":"RUNBOOK.md","artifact_glob":"runs/**/*.md"}]}` |
| Repo with no extra mandates | no manifest: record the gate warning and inspect AGENTS.md/CONTRIBUTING; proceed within existing authorization |

## Ownership

| Belongs to the skills | Belongs to the repository |
|---|---|
| Manifest schema, validation, base-branch loading | `evidence_only_paths` and `required_evidence` content |
| Delta calculation, evidence entry checks | What a live run is and how to perform it (runbook, `AGENTS.md`, or a repo skill) |
| Ordering guidance, dispatching a worker for the run | Where artifacts live and what they must contain |
