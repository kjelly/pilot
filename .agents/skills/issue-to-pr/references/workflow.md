# Workflow, dependencies, and recovery

## Inputs

Accept:
- Absolute Issue URL, e.g. `https://github.com/OWNER/REPO/issues/123`.
- `OWNER/REPO#123` or `#123` in an unambiguous Git repository.
- Exactly one Issue per invocation. For multiple/all targets, ask which one to handle; never queue or fan out. Read the checkout contract, `.agents/skills/_shared/single-item-checkout.md` (repo-root path), before analysis. The one exception is [umbrella mode](#umbrella-mode): a planner umbrella and its open sub-issues are one item.

Missing Issue IDs are not permission to process every open Issue.

## Claims across sessions

`scripts/claim.py` keeps one claim per Issue in `$GH_WORKFLOW_CLAIM_DIR` (default `~/.cache/gh-workflow-claims/OWNER__REPO/issue-N.json`), outside every clone, so any session on the machine sees it. A claim lasts 240 minutes unless renewed; a dead session's claim expires by itself. Acquire it at `DISCOVERED`, before creating a branch. `acquire` also refuses when the remote or the scanned clone already has a branch whose name contains the Issue number (whole number: `157` matches `fix/157-x`, not `1570`) unless it is your own `--branch`. Record `token` in `checkpoint.json` next to the Issue state; a resumed run passes it back with `--token`, which works only while the Issue claim is live: an Issue claim that has expired is not renewed (`renew` answers `EXPIRED`, `acquire --token` makes a new claim with a new token after the branch scan), because another session may have taken a number it covered meanwhile. On `EXPIRED` stop writing, `acquire` again with `--branch`, save the new token and re-validate. At most one live claim covers an Issue number, so any write that would overlap another live claim is refused and writes nothing (`CONFLICT`; `check` reports an existing overlap as `OVERLAP`). A claim for a PR (`pr-ready`) has no members and still revives after expiry as before. Keep (and `renew`) the claim while the PR is a Draft waiting for CI or follow-ups; release on `READY_FOR_REVIEW`, `DRAFT_CI_BLOCKED`/`DRAFT_PENDING` (when you stop and hand the Draft back), `EXISTING_PR`, `BLOCKED`, `INVALID` or `NEEDS_DECISION`. Limits: claims only bind sessions that use this script, and the branch scan covers one clone plus the remote, so a session that never claims and never pushed is invisible; the user remains the arbiter.

## Issue-oriented state machine

```
DISCOVERED -> CLAIMED -> BRANCH_CHECKED_OUT -> ANALYZED -> IMPLEMENTING
         -> COMMITTED -> CHECKED -> REVIEWED -> GATE_PASS
         -> PUSHED -> DRAFT_PR_CREATED -> (CI green + follow-ups done) -> READY_FOR_REVIEW
           \-> BLOCKED  (any stage; preserve evidence)
           \-> EXISTING_PR / INVALID / NEEDS_DECISION  (no PR; Issue answered, see issue-claims.md)
```

- A P0–P2 review finding returns `REVIEWED -> IMPLEMENTING`. A new commit invalidates `CHECKED` and `REVIEWED` receipts.
- `GATE_PASS` is not a permanent certificate. Repeat checks if HEAD or Issue/PR state changes.
- `PUSHED` is not a completed task. Confirm PR exists and references the intended issue/HEAD.
- `INVALID` and `NEEDS_DECISION` need the reviewer's independent verdict and a reply on the Issue first ([Issue claims](issue-claims.md)). A claim raised again without new evidence after a confirmed dispute is `NEEDS_DECISION`, not another implementation or reply round.
- If a post-PR CI check fails, repair on the same Draft PR branch; if unresolved report DRAFT_CI_BLOCKED and leave it Draft. Do not claim CI success. Only `mark_ready.py` moves a PR to Ready, and only after CI_PASSED on the exact HEAD with all follow-ups done; it also signs the PR (the Ready signal `pr-review-merge` and `scripts/pr_loop.py` require).

## Existing-PR disposition

Handle the selected Issue only; do not create a duplicate PR or a new branch merely to confirm an existing fix.

- Open PR: report `EXISTING_PR` and leave the Issue open. A closed-unmerged PR is not proof of resolution.
- Merged PR: verify its merge status, read the current default-branch code and relevant Issue comments, and check that the fix remains present and satisfies the valid acceptance criteria. A PR title or Issue reference alone is insufficient. If resolution is partial, uncertain, or contradicted by newer reproduction evidence, leave the Issue open and explain the remaining gap.
- Confirmed resolution: post a concise comment linking the merged PR and fixing revision, explain how it resolves the reported behavior, and state validation limits accurately. Do not claim new tests, runtime evidence, or CI results that were not obtained. Then close the Issue with reason `completed` and read it back to verify `CLOSED` / `COMPLETED`. The skill invocation authorizes this comment and closure; no additional confirmation is needed.
- On retry, inspect the existing comments and state first; reuse an equivalent resolution comment rather than posting it again. Save its URL and the verified Issue state in the checkpoint and final report. Release any held claim. An API failure leaves the disposition incomplete and must be reported explicitly.

This is an `EXISTING_PR` terminal path before implementation; it does not authorize creating a PR without the quality gate or treating a partial fix as complete.

The same path closes a related Issue after the PR that referenced it with `Refs #M` has merged (stage 0 below).

## Related Issues (stage 0)

Open Issues with the same invariant as the selected Issue are found during the [similar-defect scan](similar-defect-scan.md) and handled by its section 5: they join the fix only as `Refs #M` (never a closing keyword), nobody comments on or closes them before the merge, and after the merge each one gets its own `issue-to-pr` invocation that takes the existing-PR disposition above. This invocation still handles exactly one Issue; stage 0 takes no claim on related Issues, so re-check their open PRs and claims right before PR creation.

## Umbrella mode

An umbrella is an Issue that `issue-batch-planner` filed with `file_umbrella.py` for a batch the user approved. Its body has exactly one line `issue-batch-planner batch: <12 hex>` and one line `issue-batch-planner issues: <n> <n> ...`, and its GitHub sub-issues are those members. When the user names the umbrella U or one of its sub-issues, U with its open sub-issues is the one work item of this invocation: one branch, one claim, one PR, which closes each sub-issue it fixes with its own `Fixes`. An Issue whose GitHub parent is an ordinary Issue, or is in another repository, resolves to `mode: single`. An umbrella with a sub-issue in another repository, or with no open sub-issue or more than four, is refused: `resolve` exits 2 and the invocation stops. The exception is part of the checkout contract (`.agents/skills/_shared/single-item-checkout.md`) and adds no other Issue.

1. **Resolve** right after reading the Issue: `python3 "$SNAP/.agents/skills/issue-to-pr/scripts/umbrella.py" resolve --repo OWNER/REPO --issue N` (read-only). `mode: single` leaves the rest of this skill unchanged. `mode: umbrella` makes U the work item; `redirected: true` means the user named a sub-issue, so tell them. Exit 2 means stop and report the reason: most often U's linking stopped part-way (its sub-issues are not its member line; finish it with `file_umbrella.py` until exit 0) or someone changed its sub-issues by hand.
2. **Claim and branch**: `claim.py acquire --issue U --member C` (repeat `--member` for every open sub-issue) on the branch `issue/<U>-<c1>-<c2>-<slug>`, so the member numbers stay in the branch name after the claim expires. One claim file covers the group, a conflict on any number writes nothing, and `renew`/`release` take U. Resuming with `--token` keeps the members (give no `--member`, or the same set); a changed set is refused (exit 2, release and acquire again), and `--takeover` replaces only U's own claim, never a number another live claim holds.
3. **Analysis**: SA triages the claims and acceptance criteria of every open sub-issue separately, with a regression that tells that sub-issue apart from the others. One similar-defect scan covers the umbrella, and the sites the sub-issues report are in scope. A sub-issue that is `INVALID`, `NEEDS_DECISION`, or that this PR cannot fix becomes `partial`: Root replies on that sub-issue per [Issue claims](issue-claims.md) and records the reply in its own `disputed_issue_claims`. The other sub-issues are fixed as usual; one stuck sub-issue does not hold up the PR.
4. **Coder and Reviewer**: each `fixes` sub-issue needs at least one distinguishing regression; a single shared test is not enough. The Reviewer gives a verdict per sub-issue (`reviewer_confirmed`) and checks the umbrella's own resolution (next point).
5. **Evidence**: `issue` is U and `umbrella` records each open sub-issue ([evidence contract](evidence-contract.md)). U's `issue_resolution` is `fixes` exactly when every sub-issue is `fixes`, otherwise `partial`; U's own `disputed_issue_claims` stays empty. The gate fails closed on this field.
6. **PR body**: `Fixes #c` for each `fixes` sub-issue and `Refs #c` for each `partial` one, one keyword per number (a keyword in front of two numbers closes only the first, so the check fails); `Fixes #U` when U is `fixes`, otherwise `Refs #U`. `create_pr.py` and `mark_ready.py` check each of them.
7. **After the merge**, GitHub closes the Issues behind `Fixes`. A `partial` sub-issue and a `partial` U stay open with the reply that says what is left; this PR closes nothing else.

Related open Issues that are already sub-issues of the same umbrella are handled here, not through stage 0; stage 0 still applies to related Issues outside it.

## Dependency decisions

- Use explicit `blocked by`, acceptance dependencies, related PR branches, and actual source prerequisites; mentions alone do not imply a hard dependency.
- Issue A requiring code introduced by Issue B: block A until B is merged, **unless user explicitly requests stacked PRs**.
- For authorized stacked PRs: A's PR base must be the predecessor's branch. Document `Depends on #...`, ensure only A's incremental diff is reviewed, and require retarget + revalidation after B merges.
- Dependencies are read-only context. This invocation never starts another Issue, even when the selected one is blocked.
- Exactly one source-writing Issue workstream; retain separate SA/Coder/Reviewer roles for that item.

## Git and write isolation

- Fetch remote base; record `base_sha` in checkpoint.
- Create branch from verified remote base, not from the current checkout's potentially dirty HEAD.
- Land it with the contract (steps 4-5): `--new` on the fetched base SHA creates `issue/123-short-slug` without tracking the base branch. Do not create per-Issue worktrees.
- Keep one writer in the checkout. SA/Reviewer are read-only; never let two subagents write to it at the same time.
- For check receipts: commit, confirm `git status --porcelain` empty, then run checks. Never run check receipts on a dirty/uncommitted tree.
- On resume, land again with the contract's resume rule, and check the branch mapping and open PR list before any commit/PR operation. Never force-delete or force-switch away from an existing branch, another checkout or user work.
- Stage intentional files explicitly; no blanket `git add -A` if it may include user files, state, secrets, or platform configs.

## Long-running execution

Keep an Issue→status→branch→commit→gate timestamp→PR URL ledger outside source control. Suggested `checkpoint.json` for the selected Issue:

```json
{
  "repo": "OWNER/REPO",
  "issue": 123,
  "phase": "CHECKED",
  "branch": "issue/123-short-slug",
  "checkout": "/absolute/path/of/the/current/checkout",
  "head_sha": "<40-hex-digit commit>",
  "start_branch": "main",
  "start_sha": "<40-hex-digit commit>",
  "role_drift": [],
  "dependents": [],
  "blockers": [],
  "pr_url": null
}
```

`start_branch`/`start_sha` (or only `start_sha` when HEAD started detached) feed the restore step; `role_drift` lists each role the contract's role check reported as DRIFT (role, both sha256 hashes, `header_changes`). An agent may update the checkpoint atomically using temp-write/rename. Keep it separate from PR source files. A checkpoint is a hint, not the source of truth: re-verify with git/GitHub when resuming.

## Three unsuccessful revisions

Keep a findings ledger (`id, class, severity, origin, status, fix commit`); rounds after the first review the delta against it, and the second finding of one `class` goes to SA for a class-level fix (see `severity.md`). After 3 substantive, nonconverging review/fix attempts on the same Issue, hand the evidence and alternate hypotheses to a fresh SA. If resolution still cannot be proven, mark `BLOCKED` with minimal reproducible symptom, relevant artifact paths, suggested next action. Stop this invocation; do not start another Issue or manufacture a success.

## PR creation and idempotency

1. `gh issue view` confirms Issue is open.
2. Inspect existing linked PRs and a `gh pr list --state all` snapshot to look for same head/Issue-closing references; do not trust this list alone as exhaustive.
3. Gate passes for committed local SHA; verify push permission and push only own branch.
4. `git ls-remote --heads origin BRANCH` matches SHA (for same-repo pushes).
5. Re-run gate; create a **Draft** PR (`gh pr create --draft`, via `create_pr.py`) only if no duplicate.
6. `gh pr view` confirms PR is a **Draft** and HEAD is expected. Preserve URL in checkpoint.
7. If an API call times out, **query PRs before retrying create** to prevent duplicate PRs.

PR creation should be safe to rerun: it must detect and report an existing PR rather than creating a second one.

## Post-creation verification

- A Draft PR is work in progress: it is **not** yet claimed to be merge-quality. Run `pr_ci.py` on the confirmed remote HEAD and capture the result.
- If CI fails: Coder changes current Issue branch, commits; Root invalidates old evidence, reads the added lines, runs the secret scan and pushes; checks and review on the new SHA run while its CI runs; verify same PR head, then re-check CI on it.
- If CI never starts or cannot be observed: report `DRAFT_PENDING` / CI unknown, not `CI_PASSED`, and keep the PR Draft.
- Before any retry, query the existing PR using branch and Issue refs to prevent duplicates.
- When CI is `CI_PASSED` on the exact HEAD and every follow-up is done (final independent review of the whole head diff, every review comment answered, accurate PR body, evidence/doc follow-ups, no conflicts), run `mark_ready.py --confirm-complete`; checkpoint `phase: READY_FOR_REVIEW` only when it reports `READY_FOR_REVIEW`. It also writes the Ready signal (marker comment, then the `pr-ready-verified` label, read back as valid); a signal it cannot confirm, or a PR that is already Ready without one, is `READY_UNVERIFIED`: report it, and the recovery is a person converting the PR to Draft and running `mark_ready.py` again. A new commit afterwards invalidates the Ready claim and the signal (it names the HEAD and the Ready transition it signed), and so does a later Draft/Ready cycle: re-verify immediately.
- Never auto-merge, request auto-merge, or bypass branch protection.
