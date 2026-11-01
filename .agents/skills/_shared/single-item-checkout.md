# Single-item scope and branch checkout

This contract applies to `issue-to-pr`, `pr-ready`, and `pr-review-merge`. Skills
refer to it by the repo-root path `.agents/skills/_shared/single-item-checkout.md`,
never by a relative link: Claude Code presents a skill as the symlink
`.claude/skills/<name>`, `../_shared` does not exist beside it, and `_shared` is
not a skill, so it cannot be linked there.

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

Helpers live in `.agents/skills/_shared/scripts/` and are stdlib-only; each prints
one JSON object and exits 0 only on PASS. Any other exit is a stop, except that
`verify-role` exits 3 for DRIFT (step 7).

1. Resolve `SKILL_DIR=$(realpath <directory of the invoked SKILL.md>)` (never the
   `.claude/skills/<name>` path) and `REPO_ROOT=$(git -C "$SKILL_DIR" rev-parse
   --show-toplevel)`; it must be the repository being worked on. Record the
   starting directory, the starting branch (or the detached SHA), HEAD, and the
   item's remote metadata (target branch, base/head SHAs, head repository).
2. Snapshot: `python3 "$REPO_ROOT/.agents/skills/_shared/scripts/skill_snapshot.py"
   create --repo "$REPO_ROOT"`, the only script run from the checkout. It refuses
   uncommitted or untracked files under `BUNDLE_PATHS` (listed in the script),
   copies the committed bundle (`git archive HEAD`) outside the checkout and
   records the source revision and a sha256 manifest. `SNAP` = its `snapshot_dir`.
   Every later script, reference and child prompt uses absolute `$SNAP` paths,
   because switching to another branch can replace the checkout's copy;
   `skill_snapshot.py verify --snapshot "$SNAP"` re-checks it and counts any added
   file, bytecode included: the bundle scripts do not write `__pycache__`, so run any
   other Python from `$SNAP` with `-B`. Do not install or
   change native role configuration silently; a missing role is blocked. agy loads a
   copy `.agents/agents/NAME.md`: list `/.agents/agents/` in
   `$(git rev-parse --git-path info/exclude)` next to `.pr-ready/` (not `.gitignore`:
   older branches lack it), or the untracked copy makes the checkout dirty. Whether
   agy loads `NAME.md` or `NAME/agent.md` is unverified without an authenticated agy
   session; `verify-role` fails closed on a missing file.
3. Select and claim from `$SNAP`: `list_ready.py` candidates, the Issue claim
   (`claim.py`), `repo_evidence.py`. Nothing yet touches the working tree.
4. Resolve one full commit SHA and verify it. **Never land by name** with `git pull`,
   `git checkout`, `git switch BRANCH`, `gh pr checkout` or `--track -c origin/X`:
   they re-resolve their target at run time (a stale local branch, a stale
   remote-tracking ref, a fork head named like the user's `main`, a ref named like a
   SHA) and can put an unchecked tree on disk. `$HEAD_NAME` below is the PR's
   `headRefName`. Pass every ref, branch name and URL quoted (`--branch="$B"`,
   `"HEAD:refs/heads/$HEAD_NAME"`): `git check-ref-format` accepts names such as `x$(id)`.
   - PR in this repository: `git fetch origin refs/pull/N/head`; SHA =
     `git rev-parse FETCH_HEAD`, which must equal `headRefOid`; upstream
     `--remote origin --merge "refs/heads/$HEAD_NAME"`. Push with
     `git push origin "HEAD:refs/heads/$HEAD_NAME"` (no force).
   - PR from a fork: the same fetch and checks; upstream `--remote "$HEAD_REPO_URL"
     --merge "refs/heads/$HEAD_NAME" --merge refs/pull/N/head` (the second accepts a
     branch an earlier checkout created). `$HEAD_REPO_URL` is
     `https://github.com/OWNER/NAME` from `gh pr view N --json
     headRepository,headRepositoryOwner`; URLs are compared literally after a trailing
     `/` and `.git` are stripped, so ssh and https forms of one repository differ: use
     one form every time. The local name is always `$HEAD_NAME`; a clash stops and
     asks the user. Push with `git push "$HEAD_REPO_URL" "HEAD:refs/heads/$HEAD_NAME"`
     after verifying write permission; read-only review needs none.
   - New Issue branch: acquire the claim first; `git fetch origin refs/heads/BASE`;
     SHA = FETCH_HEAD, cross-checked with `git ls-remote origin refs/heads/BASE`;
     branch `issue/N-short-slug` with `--new`. Push later with `git push -u origin`.
   - Issue resume: if the local branch exists its tip is the SHA (local work is the
     truth) with upstream `--remote origin --merge "refs/heads/$B"`. A branch with no
     upstream yet (made by `--new`, never pushed) is attached as it is; one tracking
     something else is a clash. If the remote is ahead, fetch it and use its SHA,
     which fast-forwards the branch when the local tip is an ancestor and the upstream
     matches. A missing local branch is fetched (`refs/heads/$B`) and created.
5. Land: `python3 "$SNAP/.agents/skills/_shared/scripts/checkout_preflight.py" --repo
   "$REPO_ROOT" --target "$SHA" --branch="$B" [--remote "$R" --merge "$REF" ...] [--new]`
   prints the plan and changes nothing; add `--execute` to re-run every check and run
   exactly the planned commands. It stops (`invalid_branch_name`, `unresolvable_target`,
   `dirty`, `operation_in_progress`, `detached_head_unreachable`,
   `checked_out_elsewhere`, `ignored_collision`, `branch_clash`, `unverifiable`) when
   the name is invalid, the SHA is not a commit here, the checkout is dirty or has
   untracked files (a dirty submodule counts), a git operation is in progress, a
   detached HEAD would be orphaned, the branch is checked out in another worktree, an
   **ignored** path collides with the SHA's tree (the same path, a file/directory
   prefix of it, or any path below an ignored nested repository: `git status` cannot
   see ignored files and git overwrites them without warning), the existing local
   branch is at the SHA but tracks another upstream, or is not at the SHA and not a
   fast-forwardable branch with the same upstream (or `--new` and it exists), or a
   check cannot be run. Landing
   detaches at the SHA (the only tree change), then creates the branch, attaches it, or
   fast-forwards it by compare-and-swap, never reset or forced. On any non-zero exit
   stop and ask. Never stash, discard, reset, force-checkout, or overwrite user work
   automatically, and do not create per-item worktrees as a workaround.
6. Verify `git branch --show-current` and `git rev-parse HEAD` against the selected
   branch and SHA (`--execute` already did); stop on mismatch or remote movement. Only
   then dispatch the first role. A Coder that merges, rebases or pulls an incoming
   commit first runs the dry run on that full SHA (`--target "$SHA"`, no `--branch`; a
   bare target is a dry run only, `--execute` needs `--branch` or a restore's
   `--safe-sha`) and merges exactly that SHA, never a branch or remote-tracking name.
7. Give every child the same verified checkout and target identity. Before each dispatch
   run `python3 "$SNAP/.agents/skills/_shared/scripts/skill_snapshot.py" verify-role
   --snapshot "$SNAP" --repo "$REPO_ROOT" --platform claude|codex|agy --role NAME`.
   Exit 0 (PASS): identical; dispatch. Exit 3 (DRIFT): the role file differs, as on a
   branch cut before this workflow; the snapshot is the binding contract, so dispatch
   the native role anyway and start the task envelope with the output's
   `binding_statement` ("Your native role definition on disk differs from the invoking
   workflow's. Read `<absolute $SNAP role path>` now and follow it as your role
   contract; where they conflict, the snapshot wins."). Record the role, both sha256
   hashes, `header_changes` and `pins_differ` in the checkpoint and in the review
   report or evidence rationale; a pin difference is reported, never silent. Exit 1
   (STOP) is `BLOCKED`: the role file is missing, the name is invalid, the snapshot
   fails `verify`, or the role resolves outside the checkout. In script flags and
   evidence schemas, `worktree` means this checkout directory. Recheck branch/HEAD
   before each handoff, check receipt and push; invalidate evidence when the relevant
   SHA changes.

Known limitation: nothing holds a lock for the whole invocation. Two invocations must
not share a checkout; the branch/HEAD recheck before each handoff detects one
switching the branch under the other.

## Read-only scratch copies are not item worktrees

Never create per-item writer worktrees or checkouts. A read-only scratch copy (for
example `git archive SHA | tar -x -C SCRATCH`, outside the checkout, no branch, never
pushed from) is how AGENTS.md §1.5's "clean, isolated checkout" is met for a
candidate evidence run, and the only place revert or mutation negative controls go.

## Finish only the selected item

`issue-to-pr` creates one PR from its dedicated branch. `pr-ready` pushes only to the
existing PR's original head and never creates a replacement. `pr-review-merge` does
not edit or publish a new PR; retain its gated merge/Draft/WAITING behavior. Preserve
all existing claim, independent review, evidence, CI and permission gates. Checkpoint
and report the selected item, the branch and the exact SHA it ended on. Do not switch
to or process another item; the only branch change after the item is the restore step.

## Finish: restore the starting branch

At the end, whatever the outcome (success, Draft-blocked, WAITING or BLOCKED), return
to the starting branch recorded in step 1 (or the detached starting SHA) with the same
landing: `checkout_preflight.py --target "$START_SHA" --branch="$START_BRANCH"
--safe-sha "$S" [--safe-sha "$S2"] --execute`, where START_SHA is `git rev-parse
refs/heads/START_BRANCH` (the branch is never recreated from a remote-tracking ref: a
start branch that no longer exists is a stop, `start_branch_missing`), or the recorded
detached SHA with no `--branch`. `--safe-sha` lists the commits HEAD may be at without
stranding local work: the commit the selected branch was checked out at (always the
case for `pr-review-merge`, even after a merge whose remote branch GitHub deleted) and
the remote head verified after the last push (a fork push included). HEAD at any other
commit has unpushed commits and is a stop (`unpushed_commits`). The switch also needs a
clean checkout and the same preflight for the way back, so ignored files are guarded
there too. Never use force, stash or reset. Verify the branch (or SHA) equals the
recorded start and report the final branch. If the script stops, stay on the selected
branch and report why, naming the branch and its unpushed commits or the stop.
