# Orchestration / checkpoint playbook

## Initialization

1. Resolve explicit PR targets; if user requests all Drafts, enumerate open PRs and select only `isDraft=true`.
2. Fetch each PR's current head/base, title, body, linked Issues, diff, CI, reviews/comments, and history (`gh pr view`, `gh pr diff`, `gh api`, `gh pr checks`). Treat failures to fetch metadata as blockers, not missing data.
3. Model PR dependencies: explicit base/head stacking, shared feature assumptions, cross-PR changes to the same symbol/API/schema or shared integration fixture; ambiguous dependencies must be serialized until resolved.
4. Cap active PR workflows at 2. Within a PR, SA → Coder → Reviewer are sequential for dependent steps. Independent read-only analysis may run concurrently. A reviewer never reviews its own diff.

## Worktree lifecycle

- Start from a clean clone of the correct repository. Do not run `gh pr checkout` blindly in the user's active worktree.
- Confirm `headRepository`, `headRefName`, `headRefOid`, and writable remote. Fetch the branch/ref explicitly. Reuse an existing local branch/worktree only when its ownership and upstream match the target PR.
- Example **same-origin branch** sequence, to adapt after verifying refs and remote:

  ```bash
  git fetch origin refs/heads/BRANCH:refs/remotes/origin/BRANCH
  # If local PR branch is not already checked out in another worktree:
  if git show-ref --verify --quiet refs/heads/BRANCH; then
    git worktree add ../pr-ready-NUMBER BRANCH
  else
    git worktree add -b BRANCH ../pr-ready-NUMBER origin/BRANCH
  fi
  # Verify HEAD equals remote PR headRefOid before making any edits.
  ```

  Prefer `git worktree add ../path BRANCH` when BRANCH already exists locally and is free. A tracking or temporary branch is for reading only; **the implementation must push back to the original PR head branch/ref**, with a verified repository/remote.

- If branch is already checked out elsewhere, reuse that isolated worktree if safe, or serialize. Never use `--force`, `git reset --hard`, or discard user's work.
- Set per-PR checkpoint under the *worktree* `.pr-ready/` (ensure ignored locally and not committed). Add `.pr-ready/` to `$(git rev-parse --git-path info/exclude)` if needed; avoid changing project `.gitignore` solely for this workflow. The final gate rejects committed `.pr-ready/` artifacts. A checkpoint should contain PR URL, repo, head SHA, iteration count, acceptance criteria, findings, dependency status, test receipts, current blocker, and next action.
- After new commit/push or remote movement, invalidate prior receipts and reviews. Do not treat older check results as reusable, even if the test command is unchanged.

## Delegation contract

Task envelope for each subagent: `{repo, pr, url, base_sha, head_sha, worktree_path, role, acceptance_criteria, explicit_scope, known_findings}`. Supply paths to diff/log artifacts instead of flooding parent context.

For pilot, also supply `pilot_history_checks` (absolute path to the shared history
reference), relevant fix/review links, finding ledger and the `target_validation`
decision with invariant, reason, target ownership, snapshot/fault boundaries and
evidence plan. SA proposes target runs; Root/Coder executes within authorization.
Reviewer reads artifacts and independently revisits the decision before PASS.
Use the ready-to-copy prompts in
[the shared reference](../../pilot-code-review/references/pilot-history-checks.md).

Expected concise result: `{role, head_sha, status, root_causes, changed_files, commits, findings:[{severity,file,line,evidence,remediation}], validation:[{command,result,head_sha,log_path}], blockers, next_action}`.

- SA/Reviewer: analytical roles; no code edits, commit, push or Ready transition.
- Coder: can edit/test/commit only its assigned worktree. Parent owns Github mutations (push/Ready) after verification.
- Reviewer must inspect the actual current diff, not just Coder's claims, and independently assess whether the stated acceptance criteria are met.
- Review comments Root would dispute go to the reviewer as `{url, text, path/line}` without Root's disposition or counter-evidence; compare its verdict with Root's afterwards ([review comments](review-comments.md)).

## Loop and interruption

- Make an effective round count when Coder changed a causal hypothesis or implementation and ran impacted checks; a no-op transient CI retry is not a fix round.
- After 3 failed rounds invoke SA again with new evidence. If no sound alternative, mark Draft-blocked and move on to independent PRs.
- Permission errors, rate limiting, pending CI, no true independent agent, unknown check requirements, and push conflicts are **external blockers**. Never mark Ready by inference.
- A review claim raised again without new evidence after a reviewer-confirmed dispute, or a Root/reviewer disagreement that a fresh SA diagnosis does not settle, is a **human decision**: leave Draft and report both comment URLs.
- Do not poll indefinitely. When CI does not settle within the interactive execution or runtime is ending, persist checkpoint, leave Draft and report the specific pending checks; on future invocation resume after requerying current HEAD. This is not a quality relaxation.
