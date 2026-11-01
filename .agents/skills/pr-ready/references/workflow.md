# Orchestration / checkpoint playbook

## Initialization

1. Resolve exactly one Draft PR. For multiple/all targets, list candidates and ask which one to handle. Follow the checkout contract, `.agents/skills/_shared/single-item-checkout.md` (repo-root path), before analysis.
2. Fetch the selected PR's current head/base, title, body, linked Issues, diff, CI, reviews/comments, and history (`gh pr view`, `gh pr diff`, `gh api`, `gh pr checks`). Treat failures to fetch metadata as blockers, not missing data.
3. Model PR dependencies: explicit base/head stacking, shared feature assumptions, cross-PR changes to the same symbol/API/schema or shared integration fixture; an ambiguous dependency blocks this PR until resolved; the other PR is read-only context, never started here.
4. Run one PR workflow only. SA → Coder → Reviewer are sequential for dependent steps on this item. A reviewer never reviews its own diff.

## Checkout lifecycle

- Land the PR head with the contract (steps 4-5): fetch `refs/pull/N/head`, check the SHA against `headRepository`/`headRefName`/`headRefOid`, then land that exact SHA on `headRefName` with `checkout_preflight.py`. Never land by name; do not create per-PR worktrees. The implementation pushes back only to the original head ref (`git push origin HEAD:refs/heads/HEAD_NAME`, no force; a fork pushes to its head repository after the permission check). Never use `git reset --hard` or discard user's work.
- Set the per-PR checkpoint under `.pr-ready/<N>/` in the checkout (N = PR number; ensure ignored locally and not committed). Never reuse another PR's directory. Add `.pr-ready/` to `$(git rev-parse --git-path info/exclude)` if needed; avoid changing project `.gitignore` solely for this workflow. The final gate rejects committed `.pr-ready/` artifacts. A checkpoint should contain PR URL, repo, head SHA, the starting branch/HEAD (for the restore step), any role DRIFT reported by the contract's role check (role, both hashes, `header_changes`), iteration count, acceptance criteria, findings, dependency status, test receipts, current blocker, and next action.
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
- Review comments Root would dispute go to the reviewer as `{url, text, path/line}` without Root's disposition or counter-evidence; compare its verdict with Root's afterwards ([review comments](review-comments.md)).

## Loop and interruption

- Make an effective round count when Coder changed a causal hypothesis or implementation and ran impacted checks; a no-op transient CI retry is not a fix round.
- After 3 failed rounds invoke SA again with new evidence. If no sound alternative, mark Draft-blocked and end this invocation without starting another PR.
- Permission errors, rate limiting, pending CI, no true independent agent, unknown check requirements, and push conflicts are **external blockers**. Never mark Ready by inference.
- A review claim raised again without new evidence after a reviewer-confirmed dispute, or a Root/reviewer disagreement that a fresh SA diagnosis does not settle, is a **human decision**: leave Draft and report both comment URLs.
- Do not poll indefinitely. When CI does not settle within the interactive execution or runtime is ending, persist checkpoint, leave Draft and report the specific pending checks; on future invocation resume after requerying current HEAD. This is not a quality relaxation.
