# Workflow, dependencies, and recovery

## Inputs

Accept:
- Absolute Issue URL, e.g. `https://github.com/OWNER/REPO/issues/123`.
- `OWNER/REPO#123` or `#123` in an unambiguous Git repository.
- Multiple Issues separated by commas/spaces. Resolve each URL to its real repository; **never blindly assume all have the same owner/repo**.

Missing Issue IDs are not permission to process every open Issue.

## Claims across sessions

`scripts/claim.py` keeps one claim per Issue in `$GH_WORKFLOW_CLAIM_DIR` (default `~/.cache/gh-workflow-claims/OWNER__REPO/issue-N.json`), outside every clone, so any session on the machine sees it. A claim lasts 240 minutes unless renewed; a dead session's claim expires by itself. Acquire it at `DISCOVERED`, before creating a branch. `acquire` also refuses when the remote or the scanned clone already has a branch whose name contains the Issue number (whole number: `157` matches `fix/157-x`, not `1570`) unless it is your own `--branch`. Record `token` in `checkpoint.json` next to the Issue state; a resumed run passes it back with `--token`. Keep (and `renew`) the claim while the PR is a Draft waiting for CI or follow-ups; release on `READY_FOR_REVIEW`, `DRAFT_CI_BLOCKED`/`DRAFT_PENDING` (when you stop and hand the Draft back), `EXISTING_PR`, `BLOCKED`, `INVALID` or `NEEDS_DECISION`. Limits: claims only bind sessions that use this script, and the branch scan covers one clone plus the remote, so a session that never claims and never pushed is invisible; the user remains the arbiter.

## Issue-oriented state machine

```
DISCOVERED -> ANALYZED -> QUEUED -> WORKTREE_READY -> IMPLEMENTING
         -> COMMITTED -> CHECKED -> REVIEWED -> GATE_PASS
         -> PUSHED -> DRAFT_PR_CREATED -> (CI green + follow-ups done) -> READY_FOR_REVIEW
           \-> BLOCKED  (any stage; preserve evidence)
           \-> EXISTING_PR / INVALID / NEEDS_DECISION  (no PR; Issue answered, see issue-claims.md)
```

- A P0–P2 review finding returns `REVIEWED -> IMPLEMENTING`. A new commit invalidates `CHECKED` and `REVIEWED` receipts.
- `GATE_PASS` is not a permanent certificate. Repeat checks if HEAD or Issue/PR state changes.
- `PUSHED` is not a completed task. Confirm PR exists and references the intended issue/HEAD.
- `INVALID` and `NEEDS_DECISION` need the reviewer's independent verdict and a reply on the Issue first ([Issue claims](issue-claims.md)). A claim raised again without new evidence after a confirmed dispute is `NEEDS_DECISION`, not another implementation or reply round.
- If a post-PR CI check fails, repair on the same Draft PR branch; if unresolved report DRAFT_CI_BLOCKED and leave it Draft. Do not claim CI success. Only `mark_ready.py` moves a PR to Ready, and only after CI_PASSED on the exact HEAD with all follow-ups done.

## Dependency decisions

- Use explicit `blocked by`, acceptance dependencies, related PR branches, and actual source prerequisites; mentions alone do not imply a hard dependency.
- Issue A requiring code introduced by Issue B: block A until B is merged, **unless user explicitly requests stacked PRs**.
- For authorized stacked PRs: A's PR base must be the predecessor's branch. Document `Depends on #...`, ensure only A's incremental diff is reviewed, and require retarget + revalidation after B merges.
- Independent Issues editing shared core files, DB migrations, global code generation, or shared integration test deployments should be serialized, despite worktree isolation.
- At most 2 active source-writing Issue workstreams (and preferably 2 simultaneous analysis workers); this is a scheduler instruction, not a host-global concurrency control. A host with fewer worker slots must serialize.

## Git and write isolation

- Fetch remote base; record `base_sha` in checkpoint.
- Create branch from verified remote base, not from the current checkout's potentially dirty HEAD.
- Example: `git worktree add -b issue/123-short-slug ../repo-issue-123 origin/main` after checking branch/path absence.
- Keep one writer per worktree. SA/Reviewer are read-only. Avoid using the same worktree for two concurrent subagents with write access.
- For check receipts: commit, confirm `git status --porcelain` empty, then run checks. Never run check receipts on a dirty/uncommitted tree.
- On resume, examine `git worktree list --porcelain`, branch mapping, open PR list, and `git status` before issuing new worktree/commit/PR operations. Never force-delete an existing worktree or existing user's branch.
- Stage intentional files explicitly; no blanket `git add -A` if it may include user files, state, secrets, or platform configs.

## Long-running execution

Keep an Issue→status→worktree→branch→commit→gate timestamp→PR URL ledger outside source control. Suggested per Issue `checkpoint.json`:

```json
{
  "repo": "OWNER/REPO",
  "issue": 123,
  "phase": "CHECKED",
  "branch": "issue/123-short-slug",
  "worktree": "/absolute/path/repo-issue-123",
  "head_sha": "<40-hex-digit commit>",
  "dependents": [],
  "blockers": [],
  "pr_url": null
}
```

An agent may update the checkpoint atomically using temp-write/rename. Keep it separate from PR source files. A checkpoint is a hint, not the source of truth: re-verify with git/GitHub when resuming.

## Three unsuccessful revisions

Keep a findings ledger (`id, class, severity, origin, status, fix commit`); rounds after the first review the delta against it, and the second finding of one `class` goes to SA for a class-level fix (see `severity.md`). After 3 substantive, nonconverging review/fix attempts on the same Issue, hand the evidence and alternate hypotheses to a fresh SA. If resolution still cannot be proven, mark `BLOCKED` with minimal reproducible symptom, relevant artifact paths, suggested next action. Proceed with other independent Issues; do not manufacture a success.

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
- If CI fails: Coder changes current Issue branch, commits; Root invalidates old evidence; checks/review on new SHA; push; verify same PR head and rerun CI.
- If CI never starts or cannot be observed: report `DRAFT_PENDING` / CI unknown, not `CI_PASSED`, and keep the PR Draft.
- Before any retry, query the existing PR using branch and Issue refs to prevent duplicates.
- When CI is `CI_PASSED` on the exact HEAD and every follow-up is done (final independent review of the whole head diff, accurate PR body, evidence/doc follow-ups, no conflicts), run `mark_ready.py --confirm-complete`; checkpoint `phase: READY_FOR_REVIEW`. A new commit afterwards invalidates the Ready claim: re-verify immediately.
- Never auto-merge, request auto-merge, or bypass branch protection.
