# Single-item scope and branch checkout

This contract applies to `issue-to-pr`, `pr-ready`, and `pr-review-merge`.

## Select exactly one item

- Each invocation handles exactly one Issue or PR. Never start another item after
  success, failure, or a blocker. Dependencies are read-only context, not extra work.
- An explicit single URL/number selects that item. For multiple items or “all”,
  list candidates and ask which one to handle; do not silently choose, fan out,
  or drain a queue. An unambiguous current-branch PR may supply a missing PR target;
  `issue-to-pr` always requires an explicit Issue.
- SA, Coder, and independent Reviewer still collaborate on this one item. Only
  one writer owns its checkout. Finish dependent roles before the next handoff;
  preserve a fresh review context rather than simulating independent review.

## Checkout before analysis, edits, review, tests or delegation

1. Resolve repository identity and the selected item's remote metadata first.
   Record starting directory, branch, HEAD, target branch and base/head SHAs.
   Before switching, preserve the invoked skill bundle in a stable directory
   outside the checkout, including scripts, native role definitions and transitive
   references (`_shared`, `pilot-code-review`, and referenced Issue/PR skills).
   Record its source repository/revision and verify the snapshot contents. Use
   absolute snapshot paths for every later child prompt, reference and gate run;
   absolute paths into this checkout alone are insufficient because switching to
   an older PR branch can replace or remove those files. Do not install or change
   native role configuration silently; report a missing native role as blocked.
2. Check `git status --porcelain`, including untracked files, and
   `git worktree list --porcelain`. If dirty or owned by another writer, stop and
   ask. Never stash, discard, reset, force-checkout, or overwrite user work
   automatically. Do not create per-item worktrees as a workaround.
3. For an existing PR, verify head repository, head branch and head SHA, fetch
   that exact remote branch, then checkout the original head branch in the current
   checkout (`gh pr checkout N --repo OWNER/REPO`, without force, or a verified
   `git switch BRANCH`). A fork requires verifying its source remote and write
   permission before repair; read-only review does not require write permission.
   If the branch is checked out elsewhere, stop and identify that checkout; do not
   force it or silently switch directories.
4. For an Issue with no existing PR, acquire the Issue claim first, fetch the
   verified base, then create and checkout its dedicated branch with
   `git switch -c issue/N-short-slug VERIFIED_REMOTE_BASE`. For an authorized
   resume, verify the Issue-to-branch mapping before `git switch EXISTING_BRANCH`.
   Existing PRs remain with `pr-ready`; never create a duplicate.
5. Verify `git branch --show-current` and `git rev-parse HEAD` against the selected
   branch and captured remote SHA (or fetched base for a new Issue branch).
   Stop on detached HEAD, mismatched branch, divergence or remote movement. Do not
   reset a local branch to make this check pass. Only then dispatch the first role.
6. Give every child the same verified checkout and target identity. In existing
   script flags and evidence schemas, `worktree` means this checkout directory;
   it does not require `git worktree add`. Recheck branch/HEAD before each handoff,
   check receipt and push; invalidate evidence when the relevant SHA changes.

## Finish only the selected item

`issue-to-pr` creates one PR from its dedicated branch. `pr-ready` pushes only to
the existing PR's original head and never creates a replacement. `pr-review-merge`
does not edit or publish a new PR; retain its gated merge/Draft/WAITING behavior.
Preserve all existing claim, independent review, evidence, CI and permission gates.
Checkpoint and report the selected item, checked-out branch and exact SHA. Leave
the checkout on that branch and report it; do not switch to or process another item.
