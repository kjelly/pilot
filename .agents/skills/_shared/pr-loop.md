# Process a batch of pull requests

Run the standalone PR loop in the checkout the agents should work in:

```bash
python3 scripts/pr_loop.py 371 372 --repo kjelly/pilot
```

The agents start in that checkout of yours, not in a clone the runner makes.
`--checkout DIR` names it and defaults to the root of the git work tree that
contains the current directory; `DIR` must be the root of its work tree, not a
subdirectory. The runner refuses to start, with `pr-loop: <reason>` on stderr and
exit status 1, before it reads a pull request or starts an agent (a dry run
reports it after the PR states, below), unless: `origin` has exactly one URL,
and that URL and every push URL name the `--repo` repository; no git operation
is in progress; nothing is uncommitted or untracked and not ignored; HEAD is on a
branch: the default branch that `origin` itself reports
(`git ls-remote --symref origin HEAD`), or another clean branch that the runner
leaves for it (the paragraph after the next); the default branch is at the tip of
`origin`'s or strictly behind it (the next paragraph); and the tip has the two
helpers named below. It also refuses while another runner holds the checkout's
lock (the file `git rev-parse --git-path pilot-pr-loop.lock` names) and while a
live agent pane of an earlier run is still in the checkout (see below).

A checkout that is strictly behind the tip of `origin` is fast-forwarded by the
runner, at startup only (never again while a batch runs, when the merge train
moves `origin`). It fetches exactly the commit `origin` reported, by its SHA, into
`refs/remotes/origin/<branch>` as `git pull` does (no tags, no submodules, no
pruning, no automatic maintenance, no `FETCH_HEAD`), so a push to `origin` a
moment later cannot change what lands; then it runs `git merge --ff-only` of that
SHA, with hooks and automatic maintenance switched off, and prints
`Fast-forwarded <branch> from <L12> to <T12>, origin's tip`. The branch's reflog and
`ORIG_HEAD` name the commit it was at. Before anything reaches the work tree it
checks that the local branch is an ancestor of the tip, that the tip has the two
helpers, that it does not move a submodule, and that it would not overwrite, delete
or write into an ignored path (git does that without a word, also inside an ignored
nested repository). It refuses, and leaves the branch at its old commit and the
work tree as it was, when any of these fails, when the checkout is ahead of the tip,
has diverged from it or has no commit yet, is a partial clone, or when the fetch or
the merge fails (the message then says where git left the checkout). Run
`git pull --ff-only` yourself, or move the branch to the tip, for the refusals that
say so.

A clean checkout on another branch `<x>` is switched to the default branch `<b>`,
at startup only, and is not switched back when the run ends. `<x>` and its commits
are not touched, whether it tracks something or has commits `origin` does not have.
The runner switches only to an existing local `<b>`; if `<b>` is strictly behind the
tip, it is first moved to it by `git fetch . <tip>:refs/heads/<b>` (local, never
forced: git itself checks the fast-forward and refuses a branch that another work
tree holds), and then `git switch --no-guess --no-recurse-submodules
--no-overwrite-ignore -- <b>` makes the one tree update, with hooks and automatic
maintenance switched off. Every check that reads the tip's tree (the two helpers, no
moved submodule between `<x>` and the tip, no ignored path overwritten) runs before
any ref of yours is written. It prints, in this order, `Fast-forwarded <b> from <L12>
to <T12>, origin's tip` when `<b>` moved, and `Switched <path> from <x> (at <X12>) to
<b>; to go back: git -C <path> switch <x>`; the end of the run repeats the way back.
It refuses, with the checkout left on `<x>`, when there is no local `<b>` (it is
never created), when another work tree has `<b>` checked out (also a prunable one),
when another work tree is in the middle of a git operation, when `<b>` is ahead of
the tip or has diverged from it, when HEAD is detached or `<x>` has no commit, and
for the partial clone, submodule, helper and ignored-path cases above. A failed
`git switch` after `<b>` moved leaves the checkout on `<x>` and says that `<b>` was
fast-forwarded.

The runner uses the Python 3 standard library. Install `git`, authenticated
`gh`, `tmux`, and the coding agents, with `claude` and `codex` as defaults.
The target repository's default branch must contain Pilot's PR skills, the
result helper (`.agents/skills/_shared/scripts/pr_loop_result.py`) and the Ready
signal module (`.agents/skills/_shared/scripts/ready_signal.py`); the runner checks
both and refuses a default branch that lacks either. The merge train consumer must
be running.

The runner starts agents automatically in the checkout, which it has verified to
be on the default branch of `origin` at its tip (fast-forwarded to it, when it was
behind). An agent process is reused for its role while the same PR moves between
Draft and Ready. Before every dispatch it checks that the checkout is back on the
branch and commit it started on, clean, with no git operation in progress, and
otherwise stops without dispatching. A gate that reports a blocker, a current-HEAD
`needs-person` hand-off, a Ready PR without a valid signal (below), or a timeout
stops the batch and keeps the agent windows open for inspection. The runner prints
where the task files are when it stops.

The agents run as windows of one tmux session that belongs to the checkout, never
in one of your own sessions. Its name is `pilot-pr-<directory name>-<8 hex>`: the
checkout's directory name with every run of characters other than letters,
digits, `_` and `-` replaced by `-`, leading and trailing `-` removed, cut to at
most 24 characters (`checkout` when nothing is left), then the first 8 hex
digits of the SHA-256 of the checkout's full path. The name is the same on every run in that checkout and
differs between checkouts, also between two with the same directory name. Each
agent has one window, named `<PR>-<phase>` (for example `371-draft`). At the
start the runner prints `Agents run as windows of tmux session <session>; watch
them read-only with: tmux attach -r -t <session>`, and for each agent `PR #N
<phase> agent: %<id> in window <PR>-<phase> of tmux session <session>`; a dry
run prints `would start the agents in tmux session <session>` and calls no tmux.

The first agent creates the session and every later agent adds a window to it.
Agents the runner is done with (those of a merged PR, or one that exited and was
replaced) are closed only after the next agent has been started, and the last
ones when the run ends, so the session lasts for the whole batch. It ends with its
last window, and a client attached to it is then detached (tmux's default). Watch
from another terminal with `tmux attach -r -t <session>`, which is read-only.
Inside tmux that command fails (`sessions should be nested with care`): use
`tmux switch-client -t <session>` or `prefix s` instead. These are not read-only:
what you type in an agent's window reaches the agent, so look and do not type.
Agents run with the environment of the tmux server, except that every agent gets
the runner's own value of each variable that tmux's `update-environment` list
(`tmux show-options -gv update-environment`) names, as tmux matches it: an entry
may be a glob pattern such as `FOO_*`, and `SSH_AUTH_SOCK` and `DISPLAY` are in
the default list. So the agents use the runner's agent socket and not one left by
an earlier run or by the last client to attach. Those values are socket paths and
display names, not secrets, and they appear for a moment in the arguments of the
tmux command: do not add a name that carries a secret, or a pattern that matches
one, to `update-environment`. The session handling was verified on tmux 3.8 only.

Apart from the fast-forward at startup, the runner never deletes, resets, cleans
or stashes anything in the checkout, and it never deletes the task files. It never
kills or renames a window or a session. It adds a window to the session named for
the checkout when that exists, also one an earlier run left, and it closes only
panes it started in this run, one pane at a time (`kill-pane`, so a pane you split
off in an agent's window survives), after checking that each is still that pane on
the same tmux server: pane IDs are only unique within one server, which exits with
its last session, so a later server can give the same ID to another pane. The dead
windows of an earlier run stay where they are. A stop keeps the agent windows open. Close one with `tmux kill-pane -t %N` (`%N` is the
pane ID the runner printed), or the whole session with
`tmux kill-session -t =<session>` when nothing in it still runs; the `=` is
required, because without it tmux may pick another session whose name starts the
same. A live pane in the checkout in any session whose name starts with
`pilot-pr-` refuses the next run with `pr-loop: agent pane %N (session <session>)
is still running in <checkout>; inspect and close it before starting the runner
again`, and so does a window you open in the runner's session with its working
directory in the checkout. Dead panes do not: after a stop that left only dead windows, the next run adds new
windows to the same session. An agent that was interrupted may leave the checkout
with uncommitted work, which the next run refuses until you have put it right, or
on a clean PR branch, which the next run leaves for the default branch (the branch
and its commits stay). Nothing else may use the checkout while the runner runs:
the agents switch it to PR branches, and your own agent sessions in that directory
are not protected by the lock. A second runner on the same checkout refuses. For a
long-lived setup, use a dedicated checkout that you trust once: a second clone,
or a linked worktree when your primary checkout is not on the default branch. The
runner no longer creates or uses the clones under
`$XDG_STATE_HOME/pilot/pr-loop/batch-*` (by default
`~/.local/state/pilot/pr-loop/batch-*`); delete old ones by hand.

Use `--draft-agent` and `--ready-agent` to choose executable paths. The prompts
default to `/pr-ready {pr}` and `$pr-review-merge {pr}`; you can set them with
`--draft-command` and `--ready-command`. Quote them in the shell to preserve the
native skill syntax. Add `--dry-run` to see PR states before starting any agent:
it prints `PR #N: <phase>` for each PR, then inspects the checkout the same way,
read-only (no lock, no write, no tmux), and prints `Checkout: <path> (<branch> at
<sha12>)` and the session name above, or `pr-loop: <reason>` and exit status 1 for
a refused checkout. For a checkout behind `origin` it fetches nothing and writes
nothing, and prints `would fetch origin's <branch> at <T12> and fast-forward
<branch> from <L12> to it`; for a checkout on another branch it prints `Checkout:
<path> (<x> at <X12>)` and `would switch <path> from <x> (at <X12>) to <b>`,
switching nothing; when that commit is already in the checkout it also runs the
checks above on it, and otherwise says that it did not check them (without the
commit a dry run cannot tell that the checkout has diverged from it; the real run
fetches it and says so). It does not check whether another runner holds the lock
or whether a pane from an earlier run is still open, and only a real run notices a
tracked `.gitignore` that overrides the exclude lines below. The phase timeout
defaults to 14400 seconds (4 hours): a Draft phase that fixes a review finding, runs
the checks and waits for CI can take more than two hours.

Each dispatch writes `<checkout>/.pr-loop/<nonce>/task.json` and pastes
`--pr-loop-task=<path>` after the prompt; the skill writes `result.json` beside
it. The runner keeps `/.pr-loop/` and `/.pr-ready/` out of `git status`: for a
path that git does not already ignore, it appends the line to the checkout's git
exclude file (found with `git rev-parse --git-path info/exclude`) and prints
`Added ... to <file>`, and it refuses to start when git still does not ignore
them.

Both agents must already trust the checkout: start each of them there once
yourself and answer its trust dialog. The runner stops at a trust dialog only
when its options are numbered; claude's are not, so it takes the selected option
for the input prompt, pastes its command and presses Enter in the same second,
and nobody can answer in time. In a directory an agent does not trust, `claude`
exits at once (its default answer is "No, exit") and the runner stops with an
`agent exited` message that does not mention trust; `codex` loses the command,
may record the directory as trusted, and the runner then waits silently until
`--phase-timeout` (14400 seconds by default).

The runner dispatches the Ready phase only for a PR that carries a valid Ready
signal at its current HEAD: the label `pr-ready-verified` and a comment that starts with
the producer's heading and ends with a marker line for that HEAD and for the PR's latest Ready transition, which `pr-ready` (or issue-to-pr's `mark_ready.py`)
writes after it verified the Draft and made it Ready. The signal counts only when
the account `gh` runs as wrote it, so the runner and the skills must run as the
same GitHub account, and the label must exist in the repository (a one-time
maintainer action; nothing here creates labels). A Ready PR without a valid
signal is `unverified`, for example because it was made Ready by hand or by a
script that skipped the gate, was created Ready, was pushed to after it was
signed, went through Draft and Ready again after it was signed, or was signed by
another account. The runner reads
the phase twice like any other, dispatches nothing for it, writes nothing to
GitHub and stops with `PR #N is Ready without a valid pr-ready-verified signal at
HEAD <h12>: <reason>; ...`; `--dry-run` prints `PR #N: unverified (<reason>)`.
Unlike the `pr-review-merge` actor, the runner does not carry a signal across any
change, a base import or an evidence-only commit included. While the Draft agent
is still working, a Ready PR that is not signed yet counts as the Draft phase,
because the gate marks the PR Ready before it verifies and signs it: a blocker
it reports afterwards stops the run instead of sending the Ready agent in. A
signal that never becomes valid (for example one written by another account)
ends that phase with `timed out in draft (Ready
without a valid pr-ready-verified signal: <reason>)`. To have an unverified PR processed, convert it to
Draft and run pr-ready on it, then start the runner again (a person can also sign
it by hand, see the "Ready signal" section of
[`.agents/skills/pr-ready/README.md`](../pr-ready/README.md)).

The runner acts on a state only after reading it twice in a row, and retries a
failed GitHub read twice before it stops, so one lagging or failing read neither
dispatches an agent nor ends the run. An agent that is still working when
GitHub shows the next phase is given the phase timeout to return to its prompt;
a PR can therefore take up to about twice `--phase-timeout` in one phase. Every
exhausted wait stops the runner without sending a command and keeps the
agent windows open. The runner reads the finished agent's result before it
moves on, and stops on a blocker even when GitHub already shows the next phase.
