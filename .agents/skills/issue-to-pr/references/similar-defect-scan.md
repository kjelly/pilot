# Similar-defect scan and related Issues (stage 0)

`AGENTS.md` §5.10 asks every bug fix to look for the same mistake elsewhere before it lands. This
reference turns that into a fixed step of every valid **bug** Issue, at its **first** occurrence (the
[class rule](severity.md#class-rule-stop-point-fixing) still adds a class-level reassessment when a
finding class repeats during review). It is the single definition of the scan, the
`similar_defect_scan` evidence field and the related-Issue rules; other files link here.

## 1. SA: before any code change

For every valid bug Issue, SA returns `similar_scan` with:

1. `class` (short kebab-case, `^[a-z0-9]+(-[a-z0-9]+)*$`, the same label vocabulary as the
   [severity rubric](severity.md)), the violated `invariant`, trigger, observable failure and negative
   control. Before inventing a label, check `../../pilot-code-review/references/pilot-history-checks.md`
   for an existing one.
2. **Repository-wide candidate search**: at least one `git grep` on the base commit,
   `git grep -n -e <pattern> <BASE_SHA> -- <pathspec>`, covering the different spellings of the
   pattern, not only one function name. Record pattern, pathspec and hit count. `git grep` exit 1 is
   zero hits; any exit above 1 is an error and is never reported as zero hits.
3. **Execution-family trace**: at least one search along callers, shared helpers/includes, sibling
   backends or history (`git log -S/-G`), to find sites with the same cause but different spelling.
   A repository-wide search with zero hits still needs this step.
4. **Related open Issues** (section 5, step 1).
5. Every hit becomes a classified candidate (section 2) with evidence.
6. `limitations`: what was not searched and why. A failed, truncated or unfinished search, or a caller
   that could not be located, is reported as such and never as `complete`.
7. `recurrence_risk = yes | no` with a reason; for `yes`, the repository-wide lint or regression test
   that would stop new code from repeating the defect.

Deep analysis stays inside the execution families the evidence points to; this is not an unbounded
repository audit, and it never starts another Issue workstream.

## 2. Candidate classification

| Classification | Disposition |
|---|---|
| `same-invariant-in-scope` | Fixed in the same PR, each with its own regression test. |
| `shared-choke-point` | Fixed once at the shared entry; every caller/backend verified. |
| `false-positive` | Concrete exclusion evidence; the Reviewer re-checks it. |
| `separate-defect` | Not added to this PR; tracked by a follow-up Issue (`issue-filing`). |
| `dependent-or-overlapping` | Handled by the existing dependency / stacked-PR rules. |
| `unconfirmed` | Not finished: keep investigating. Never counted as cleared. |

Origin stays as defined in the [severity rubric](severity.md): an unrelated defect already on base is
`pre-existing` and capped at P3, never raised to pass the scan; a same-class site inside the approved
scope cannot be waved off as `pre-existing`.

## 3. Coder and Reviewer

Coder:

- Fixes every `same-invariant-in-scope` and `shared-choke-point` site, keeping the backends consistent,
  with a regression per trigger and backend that checks external or effective state.
- For `recurrence_risk = yes`, adds or extends a repository-wide guard. It parses structure where the
  defect lives in structure (`pre_tasks`, `include_tasks` and the like, `AGENTS.md` §4.4). It runs the
  guard on a read-only scratch copy of the base (`git archive <BASE_SHA> | tar -x -C <scratch>`, the
  rule in `.agents/skills/_shared/single-item-checkout.md`) and records why it fails there in
  `guard.negative_control`. A missing tool, a compile error or another gate refusing first is not a
  valid failure.
- Records the scan range, candidate count, fixed sites and follow-ups in the commit message. The PR body
  carries a short scan table, never raw search output.

Reviewer (independent, not repeating SA):

- Re-runs SA's repository-wide queries and at least one query of its own.
- Checks that every in-scope candidate is fixed, every `false-positive` has exclusion evidence and every
  `separate-defect` has a follow-up Issue.
- Reads the guard and the base code to judge `guard.negative_control`.
- Returns `similar_scan: {confirmed, missed_sites, notes}`; any missed site makes `confirmed` false.

## 4. `similar_defect_scan` in `evidence.json`

An additive field; `schema_version` stays 1. Example:

```json
{
  "similar_defect_scan": {
    "status": "complete",
    "issue_kind": "bug",
    "class": "error-swallowed",
    "invariant": "A failed query must never read as an absent resource",
    "base_sha": "<40 hex: the base SA searched; must be an ancestor of HEAD>",
    "queries": [
      {"id": "q1", "kind": "git-grep", "scope": "repo", "pattern": "failed_when: false", "pathspec": ["playbooks"], "hits": 3},
      {"id": "q2", "kind": "family", "scope": "playbooks/apply/tasks", "description": "callers of the same include", "hits": 1}
    ],
    "candidates": [
      {"location": "playbooks/apply/x.yml:120", "query_ids": ["q1"], "hits": 1,
       "classification": "same-invariant-in-scope", "resolved": true,
       "related_issue_url": "https://github.com/OWNER/REPO/issues/151",
       "evidence": "Same rc != 0 treated as absent; fixed in <commit>"},
      {"location": "playbooks/apply/y.yml", "query_ids": ["q1"], "hits": 2,
       "classification": "false-positive",
       "evidence": "Both are check-mode debug tasks followed by an rc check"},
      {"location": "playbooks/apply/tasks/z.yml:40", "query_ids": ["q2"], "hits": 1,
       "classification": "separate-defect",
       "follow_up_issue_url": "https://github.com/OWNER/REPO/issues/200",
       "evidence": "Different invariant: only affects check-mode output"}
    ],
    "limitations": ["docs/** not searched; internal/ grep only, not read site by site"],
    "recurrence_risk": "yes",
    "guard": {
      "status": "added",
      "path": "internal/spec/example_regression_test.go",
      "negative_control": "Added to a scratch copy of BASE it fails because <invariant>: <summary>"
    },
    "reviewer": {"confirmed": true, "head_sha": "<HEAD, or an ancestor differing only by evidence-only paths>"}
  }
}
```

Rules:

- A candidate may stand for several hits in one file (`location` is a path, `hits` the count) and may
  belong to several queries (`query_ids`, a non-empty list of the queries' `id` strings). **Each
  query's `hits` equals the sum of `hits` of the candidates that list it**, so a hit nobody classified
  cannot pass. Narrow a query that returns too many hits instead of listing them blindly.
- `kind` is `git-grep` or `family`; at least one `git-grep` query has `scope: "repo"`, and at least one
  query is `family`.
- `classification` is one of section 2; `same-invariant-in-scope` and `shared-choke-point` need
  `resolved: true`; `separate-defect` needs `follow_up_issue_url`. `follow_up_issue_url` and
  `related_issue_url` are `https://github.com/OWNER/REPO/issues/N` of this repository, never this Issue.
- `related_issue_url` (optional) marks a site that another open Issue reports (section 5). It does not
  make this PR close that Issue.
- `recurrence_risk` is `yes` or `no`. For `yes`, `guard.status` is `added` or `existing`, `guard.path`
  exists at HEAD, an `added` guard is changed on the branch, and `guard.negative_control` says why it
  fails on base. The text is the Reviewer-confirmed account; nothing re-runs it.
- `reviewer.confirmed` is the independent Reviewer's verdict for `reviewer.head_sha`.
- A non-bug Issue uses `status: "not-applicable"`, `issue_kind: "non-bug"` and a specific `reason`,
  confirmed by the Reviewer. A bug Issue never uses `not-applicable`. Whether an Issue is a bug is a
  human judgment; the gate cannot tell.
- No raw Issue text, comment text or matched line goes into this field: locations, numbers and
  summaries only (`.agents/skills/_shared/committed-secrets.md`).

`issue_gate.py` checks this field **in advisory mode** (`SIMILAR_SCAN_ENFORCED = False`): its output
carries `similar_defect_scan: {enforced, status: pass | warn | missing, problems}`, which
`create_pr.py` and `mark_ready.py` repeat in their results, and no problem blocks the gate. Making the
problems blocking is a separate change decided by the repository's owner, not part of an Issue fix. The
gate checks structure and provenance only (the rules above, `base_sha` ancestry, the guard file at HEAD
and on the branch, the Reviewer's HEAD); it does not prove that the search was sufficient, that the guard
fails on base, or that the fix is correct. Root and the independent Reviewer own those judgments, and a
`warn` or `missing` status is reported, not ignored.

## 5. Related open Issues (stage 0)

A PR still closes only the selected Issue. Open Issues with the same invariant join the fix as
candidates; after the PR merges, each is closed by its own later `issue-to-pr` invocation. Claims, the gate's Issue checks and the
`Fixes` checks of `create_pr.py`/`mark_ready.py` do not change.

When the related Issues are already sub-issues of one `issue-batch-planner` umbrella, use
[umbrella mode](workflow.md#umbrella-mode) instead: the umbrella and its open sub-issues are one item
and the PR closes each fixed sub-issue with its own `Fixes`. This section covers every other related
Issue, including Issues outside the umbrella in umbrella mode. The scan itself runs once for the
umbrella, and the sites its sub-issues report are `same-invariant-in-scope`.

1. **Find** (read-only): during the scan, SA searches open Issues (`gh issue list --search`) by class,
   invariant and the files or components involved. A recent `issue-batch-planner` report, when the user
   provides one, is a further input: its batches name Issues that share files, tests or references, but
   they are leads to verify, not conclusions. A confirmed same-invariant Issue becomes a candidate with
   `related_issue_url`; an uncertain one is `unconfirmed`.
2. **Eligibility** (read-only, per related Issue): no open PR; no claim by another session
   (`claim.py check`); still open; its claims and acceptance criteria do not conflict with this fix
   (judged per [Issue claims](issue-claims.md), without commenting on it). An ineligible Issue is
   classified `separate-defect` or `dependent-or-overlapping` and stays out of the fix.
3. **Regression**: each related Issue's symptom has a distinguishing regression test, or the PR body
   names the test that covers it. One shared test alone does not support closing it later.
4. **PR body**: the selected Issue gets `Fixes #N`; related Issues appear only as `Refs #M` under a
   "Related Issues" heading, **never** with a closing keyword (`Fixes`, `Closes`, `Resolves`). A closing
   keyword would let GitHub close them on merge without verification, and a later gate run for #M would
   count this PR as an existing closing PR.
5. **Before merge**, do not comment on, relabel or close related Issues; the `Refs` cross-link is enough.
6. **After merge**, run `issue-to-pr` once per related Issue. It takes the
   [existing-PR disposition](workflow.md#existing-pr-disposition): confirm the fix is on the default
   branch and meets that Issue's valid acceptance criteria, comment with the PR and revision, and close
   it as `completed`. A symptom the fix does not cover goes through the normal fix workflow instead.
7. The selected Issue's final report lists the related Issues that wait for this post-merge step.

Known residual risk: stage 0 takes no claim on related Issues. Between SA's check and the merge,
another session can open a PR for #M, and the gate's duplicate check only sees closing keywords. The
`Refs #M` cross-link and a second check of #M's open PRs and claim right before PR creation reduce it;
on a collision, follow the `EXISTING_PR` rules. Do not describe the risk as eliminated.
