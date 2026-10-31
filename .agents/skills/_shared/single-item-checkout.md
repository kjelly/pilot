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

Helper scripts live in `.agents/skills/_shared/scripts/` and are stdlib-only;
each prints one JSON object and exits 0 only on PASS. Any other exit is a stop,
except that `verify-role` exits 3 for DRIFT (step 7).

1. Resolve the skill directory physically before reading any shared file:
   `SKILL_DIR=$(realpath <directory of the invoked SKILL.md>)` (never the
   `.claude/skills/<name>` path) and `REPO_ROOT=$(git -C "$SKILL_DIR" rev-parse
   --show-toplevel)`; it must be the repository being worked on. Resolve the
   repository identity and the selected item's remote metadata. Record the
   starting directory, starting branch (or the detached SHA when HEAD is
   detached), HEAD, target branch and base/head SHAs: the restore step at the
   end needs them.
2. Fetch the exact target commit; this does not touch the working tree. For an
   existing PR: `git fetch origin refs/pull/N/head` (same-repository and fork
   PRs) and compare the fetched SHA with `headRefOid`. For an Issue with no
   existing PR: acquire the Issue claim first, then fetch the verified remote base.
3. Preflight, read-only, **before any switch**:
   `python3 "$REPO_ROOT/.agents/skills/_shared/scripts/checkout_preflight.py"
   --repo "$REPO_ROOT" --target-ref TARGET_SHA --branch BRANCH`. It stops when the
   checkout is dirty or has untracked files (a dirty submodule counts, whatever
   `diff.ignoreSubmodules` says), when a git operation is in progress, when a
   detached HEAD would be orphaned, when BRANCH is checked out in another
   worktree, or when an **ignored** path collides with a path the target tracks:
   the same path, a file/directory prefix of it in either direction, or any path
   below an ignored nested git repository (`vendor/x/`). `git status --porcelain`
   cannot see ignored files and git overwrites or deletes them without warning, so
   this check is not optional. **Every commit that can land in the working tree
   is checked**: `--target-ref` is repeatable, and BRANCH's existing local tip is
   checked as well as TARGET_SHA, because `git switch BRANCH` and `gh pr checkout`
   check out that (possibly stale) tip first. Pass an extra `--target-ref` for any
   other commit you may check out. It also stops, failing closed, when a target
   cannot be resolved or a check cannot be run. On any non-zero exit stop and ask. Never
   stash, discard, reset, force-checkout, or overwrite user work automatically,
   and do not create per-item worktrees as a workaround.
4. Snapshot, **after** the clean check (the script refuses a dirty checkout):
   `python3 "$REPO_ROOT/.agents/skills/_shared/scripts/skill_snapshot.py" create
   --repo "$REPO_ROOT"`. It copies `.agents/skills/{_shared,pilot-code-review,issue-to-pr,
   pr-ready,pr-review-merge}`, `.codex/agents` and `.claude/agents` from the
   committed HEAD (`git archive`) to a new directory outside the checkout and
   records the source repository/revision (HEAD and tree ID) and a sha256 manifest.
   Run every later script, reference and child prompt from that snapshot (`SNAP` =
   `snapshot_dir` in its output) using absolute snapshot paths: switching to an
   older PR branch can replace or remove the files in the checkout.
   `python3 "$SNAP/.agents/skills/_shared/scripts/skill_snapshot.py" verify
   --snapshot "$SNAP"` re-checks it. Do not install or change native role
   configuration silently; report a missing native role as blocked.
5. For an existing PR, verify head repository, head branch and head SHA, then
   checkout the original head branch in the current checkout (`gh pr checkout N
   --repo OWNER/REPO`, without force, or a verified `git switch BRANCH`). A fork
   requires verifying its source remote and write permission before repair;
   read-only review does not require write permission. If the branch is checked out
   elsewhere, stop and identify that checkout; do not force it or silently switch
   directories.
   For an Issue with no existing PR, create and checkout its dedicated branch with
   `git switch --no-track -c issue/N-short-slug VERIFIED_REMOTE_BASE` (a
   dedicated branch must not track the base branch). For an authorized resume,
   verify the Issue-to-branch mapping before `git switch EXISTING_BRANCH`.
   Existing PRs remain with `pr-ready`; never create a duplicate.
6. Verify `git branch --show-current` and `git rev-parse HEAD` against the selected
   branch and captured remote SHA (or fetched base for a new Issue branch). For a
   fork PR (or a name clash) `gh pr checkout` may create a local branch named
   differently from the PR's head branch: record the actual name from
   `git branch --show-current` and verify it together with the SHA instead of
   assuming BRANCH. Stop on detached HEAD, mismatched branch, divergence or remote
   movement. Do not reset a local branch to make this check pass. Only then
   dispatch the first role.
7. Give every child the same verified checkout and target identity. Before each
   dispatch run `python3 "$SNAP/.agents/skills/_shared/scripts/skill_snapshot.py"
   verify-role --snapshot "$SNAP" --repo "$REPO_ROOT" --platform claude|codex|agy
   --role NAME` for the role file the runtime will load (`.claude/agents/NAME.md`,
   `.codex/agents/NAME.toml`, or for agy its copy `.agents/agents/NAME.md`).
   Exit 0 (PASS): the file is identical to the snapshot's; dispatch. Exit 3
   (DRIFT): the file exists in the checkout but differs, as on a branch cut
   before this workflow; the snapshot is the binding contract, so dispatch the
   native role anyway and start the task envelope with the output's
   `binding_statement`: "Your native role definition on disk comes from the
   checked-out target branch and differs from the invoking workflow. Read
   `<absolute $SNAP role path>` now and follow it as your role contract; where
   they conflict, the snapshot wins." Record the role, both sha256 hashes and
   any model/effort pin difference (`pins_differ`; Claude/agy frontmatter
   `model`/`effort`, Codex `model`/`model_reasoning_effort`) in the checkpoint and
   in the review report or evidence rationale: a pin difference is reported, never
   silent. Exit 1 (STOP) is `BLOCKED`: the role file is missing in the checkout,
   the role name is invalid, the snapshot fails `verify`, or the role resolves
   outside the checkout; nothing can be dispatched. In existing
   script flags and evidence schemas, `worktree` means this checkout directory; it
   does not require `git worktree add`. Recheck branch/HEAD before each handoff,
   check receipt and push; invalidate evidence when the relevant SHA changes.

Known limitation: nothing holds a lock for the whole invocation. Two invocations
must not share a checkout; the branch/HEAD recheck before each handoff is what
detects one switching the branch under the other.

## Read-only scratch copies are not item worktrees

Never create per-item writer worktrees or checkouts. A read-only scratch copy
(for example `git archive SHA | tar -x -C SCRATCH`, outside the checkout, no
branch, never pushed from) is allowed for revert or mutation negative controls and
for AGENTS.md §1.5 evidence runs. The clean current checkout at the committed
candidate SHA is the candidate checkout, and a read-only scratch copy of that same
SHA is an equally valid one for an evidence run; mutations and reverts go only into
scratch copies. Neither is an item workspace: do not give a candidate its own
writer worktree or branch.

## Finish only the selected item

`issue-to-pr` creates one PR from its dedicated branch. `pr-ready` pushes only to
the existing PR's original head and never creates a replacement. `pr-review-merge`
does not edit or publish a new PR; retain its gated merge/Draft/WAITING behavior.
Preserve all existing claim, independent review, evidence, CI and permission gates.
Checkpoint and report the selected item, the branch and the exact SHA it ended on.
Do not switch to or process another item; the only branch change after the item is
the restore step below.

## Finish: restore the starting branch

At the end of the invocation, whatever its outcome (success, Draft-blocked,
WAITING or BLOCKED), switch back to the starting branch recorded in step 1 (or to
the detached starting SHA) only when all three hold:

1. the checkout is clean (the preflight's dirty check);
2. the selected branch has no unpushed commits: its upstream exists and
   `git rev-list @{u}..HEAD` is empty, or nothing was ever written locally (HEAD is
   still the commit the branch was checked out at, which is always so for
   `pr-review-merge`, including after a merge whose remote branch GitHub deleted);
3. the preflight passes for the way back, so the ignored-file collision and
   stale-tip checks guard it too (a start branch that no longer exists is a stop
   as well).

`python3 "$SNAP/.agents/skills/_shared/scripts/checkout_preflight.py" --repo
"$REPO_ROOT" --restore-check --start-sha START_SHA [--start-branch START_BRANCH]
[--checked-out-sha CHECKED_OUT_SHA]` checks all three without changing anything
(`--checked-out-sha` is the nothing-written form of the second condition) and
prints the `switch_command`. Run it, then run `git switch START_BRANCH`, or
`git switch --detach START_SHA` if HEAD started detached. Never use force, stash
or reset. After switching, verify `git branch --show-current` (or
`git rev-parse HEAD` for a detached start) equals the recorded start and report
the final branch. If any condition fails, stay on the selected branch and report
why, naming the branch and its unpushed commits or the preflight stop.
