# Orchestration / checkpoint playbook

## Initialization

1. Resolve exactly one Draft PR. For multiple/all targets, list candidates and ask which one to handle. Follow the checkout contract, `.agents/skills/_shared/single-item-checkout.md` (repo-root path), before analysis.
2. Fetch the selected PR's current head/base, title, body, linked Issues, diff, CI, reviews/comments, and history (`gh pr view`, `gh pr diff`, `gh api`, `gh pr checks`). Treat failures to fetch metadata as blockers, not missing data.
3. Model PR dependencies: explicit base/head stacking, shared feature assumptions, cross-PR changes to the same symbol/API/schema or shared integration fixture; an ambiguous dependency blocks this PR until resolved; the other PR is read-only context, never started here.
4. Run one PR workflow only. SA → Coder → Reviewer are sequential for dependent steps on this item. A reviewer never reviews its own diff.

## Checkout lifecycle

- Work in the current clean checkout of the correct repository, after the contract's preflight (clean tree, no ignored-file collision, branch not checked out elsewhere) and snapshot. `gh pr checkout N --repo OWNER/REPO` (no `--force`) is the normal way to check out the PR head.
- Confirm `headRepository`, `headRefName`, `headRefOid`, and writable remote. Fetch the branch/ref explicitly. Reuse an existing local branch only when its upstream matches the target PR; otherwise stop and ask.
- Example **same-origin branch** sequence when not using `gh pr checkout`, to adapt after verifying refs and remote:

  ```bash
  git fetch origin refs/heads/BRANCH:refs/remotes/origin/BRANCH
  # Stop first if the preflight did not PASS (dirty, ignored-file collision, owned by another writer, or checked out elsewhere).
  if git show-ref --verify --quiet refs/heads/BRANCH; then
    git switch BRANCH
  else
    git switch --track -c BRANCH origin/BRANCH
  fi
  # Verify HEAD equals remote PR headRefOid before making any edits.
  ```

  Use the current clean checkout; do not create per-PR worktrees. A tracking or temporary branch is for reading only; **the implementation must push back to the original PR head branch/ref**, with a verified repository/remote.

- If branch is already checked out elsewhere, stop and identify that checkout; do not silently switch directories. Never use `--force`, `git reset --hard`, or discard user's work.
- Set the per-PR checkpoint under `.pr-ready/<N>/` in the checkout (N = PR number; ensure ignored locally and not committed). Never reuse another PR's directory. Add `.pr-ready/` to `$(git rev-parse --git-path info/exclude)` if needed; avoid changing project `.gitignore` solely for this workflow. The final gate rejects committed `.pr-ready/` artifacts. A checkpoint should contain PR URL, repo, head SHA, the starting branch/HEAD (for the restore step), any role DRIFT reported by the contract's role check (role, both hashes, pin change), iteration count, acceptance criteria, findings, dependency status, test receipts, current blocker, and next action.
- After new commit/push or remote movement, invalidate prior receipts and reviews. Do not treat older check results as reusable, even if the test command is unchanged.

## Delegation contract

Task envelope for each subagent: `{repo, pr, url, base_sha, head_sha, checkout_path, role, acceptance_criteria, explicit_scope, known_findings}`. Supply paths to diff/log artifacts instead of flooding parent context.

For pilot, also supply `pilot_history_checks` (absolute path to the shared history
reference), relevant fix/review links, finding ledger and the `target_validation`
decision with invariant, reason, target ownership, snapshot/fault boundaries and
evidence plan. SA proposes target runs; Root/Coder executes within authorization.
Reviewer reads artifacts and independently revisits the decision before PASS.
Use the ready-to-copy prompts in
[the shared reference](../../pilot-code-review/references/pilot-history-checks.md).

Expected concise result: `{role, head_sha, status, root_causes, changed_files, commits, findings:[{severity,file,line,evidence,remediation}], validation:[{command,result,head_sha,log_path}], blockers, next_action}`.

- SA/Reviewer: analytical roles; no code edits, commit, push or Ready transition.
- Coder: can edit/test/commit only in the assigned verified checkout (no worktrees, no branch switching). Parent owns Github mutations (push/Ready) after verification.
- Reviewer must inspect the actual current diff, not just Coder's claims, and independently assess whether the stated acceptance criteria are met.

## Loop and interruption

- Make an effective round count when Coder changed a causal hypothesis or implementation and ran impacted checks; a no-op transient CI retry is not a fix round.
- Whatever the end state (READY, DRAFT-BLOCKED, pending CI), finish with the contract's restore step: switch back to the starting branch only if the checkout is clean, the PR head branch has no unpushed commits and the way back passes the preflight; otherwise stay on the PR head branch and report why.
- After 3 failed rounds invoke SA again with new evidence. If no sound alternative, mark Draft-blocked and end this invocation without starting another PR.
- Permission errors, rate limiting, pending CI, no true independent agent, unknown check requirements, and push conflicts are **external blockers**. Never mark Ready by inference.
- Do not poll indefinitely. When CI does not settle within the interactive execution or runtime is ending, persist checkpoint, leave Draft and report the specific pending checks; on future invocation resume after requerying current HEAD. This is not a quality relaxation.
