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

Apart from the fast-forward at startup, a run never deletes, resets, cleans or
stashes anything in the checkout, and it deletes no task file (only `--clean
--remove-task-dirs --yes`, below, removes task directories). It never kills or
renames a window or a session. It adds a window to the session named for the
checkout when that exists, also one an earlier run left, and a run closes only
panes it started in this run, one pane at a time (`kill-pane`, so a pane you
split off in an agent's window survives), after checking that each is still that
pane on the same tmux server: pane IDs are only unique within one server, which
exits with its last session, so a later server can give the same ID to another
pane. The dead windows of an earlier run stay where they are until `--clean
--yes` closes them. A stop keeps the agent windows open. Close one by hand with
`tmux kill-pane -t %N` (`%N` is the pane ID the runner printed), or the whole
session with `tmux kill-session -t =<session>` when nothing in it still runs; the
`=` is required, because without it tmux may pick another session whose name
starts the same; or let `--clean` do it (the last section). A live pane in the
checkout in any session whose name starts with `pilot-pr-` refuses the next run
with `pr-loop: agent pane %N (session <session>) is still running in <checkout>;
inspect and close it before starting the runner again (python3 scripts/pr_loop.py
--clean lists what an earlier run left)`, and so does a window you open in the
runner's session with its working directory in the checkout. Dead panes do not:
after a stop that left only dead windows, the next run adds new windows to the
same session. An agent that was interrupted may leave the checkout with
uncommitted work, which the next run refuses until you have put it right, or on a
clean PR branch, which the next run leaves for the default branch (the branch and
its commits stay). Nothing else may use the checkout while the runner runs: the
agents switch it to PR branches, and your own agent sessions in that directory
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

## `--clean`: list and close what an earlier run left

A run that stops (a blocker, a timeout, a `WAITING` result, Ctrl-C) keeps its
agent windows and its task directories, and the next run refuses to start while a
live agent pane of the earlier one is in the checkout. `--clean` lists that
residue and, when told to, closes the part that is provably this runner's own. It
is not `git clean`: it never touches the git checkout.

```bash
python3 scripts/pr_loop.py --clean                         # list, change nothing
python3 scripts/pr_loop.py --clean --yes                   # close the dead and idle panes
python3 scripts/pr_loop.py --clean --yes --include-busy    # and the busy ones
python3 scripts/pr_loop.py --clean --yes --remove-task-dirs
```

`--clean` takes `--checkout DIR` and `--repo` like a run (`--repo` only names the
repository in the message for a directory that is not a git work tree; the
checkout's `origin` is not read), and no PR numbers. Without `--yes` it changes
nothing and exits 0: it reads no GitHub (no `gh` call), and asks tmux only
`list-panes` and `capture-pane`. It reads the checkout's lock with a shared,
non-blocking `flock` on a read-only descriptor, which never creates the lock
file, and reports a lock another runner holds. `--include-busy` and
`--remove-task-dirs` without `--yes` are still a listing: every line says what the
same command with `--yes` would do (`would close`, `would remove`). `--yes`,
`--include-busy` and `--remove-task-dirs` without `--clean` are errors, and so is
`--dry-run` with `--clean`. `--yes` is the confirmation: nothing asks again.

With `--yes` it takes the checkout's lock for the whole run, so that no runner
starts or runs meanwhile, and it refuses with `pr-loop: another pr_loop runner is
using the checkout ...` and exit status 1 when another runner holds it. It never
builds the checkout the way a run does (that refuses on exactly the panes this is
for, and may fast-forward or switch the checkout). It closes one pane at a time,
each with `kill-pane` on its ID and never a window or a session, and says
`closed`, `left open` or `removed` where a listing says `would`.

### Which panes are the runner's

A pane is listed as the runner's only when ALL of these hold on one row of
`tmux list-panes -a`:

1. its session is exactly the one named for the checkout (not one whose name
   starts with it, and not the grouped twin of it that has no windows of its own);
2. its window is named `<PR>-draft` or `<PR>-ready`;
3. it was started in the checkout itself: the real paths are equal (a
   subdirectory, or a sibling whose name starts the same, does not count);
4. its start command is `exec <absolute path>`, which is how the runner starts
   every agent and not how a window or a split you open is started;
5. the tmux server is the one that listed it: its PID and start time come from
   the same row, and are checked again right before the pane is closed.

Anything else that would stop the next run (the `-eink` twin of the session, a
session of the older `pilot-pr-<PR>-<phase>-<hex>` names, a checkout that was
moved, a window you renamed, a window or a split you opened) is listed as `not
the runner's` and left alone. Close it yourself with `tmux kill-pane -t %N`.

### Dead, idle, busy

A dead pane (`remain-on-exit` kept it after its agent exited) is closed with
`--yes`. An alive pane is **idle** only when ALL of these hold: its foreground
command is not a shell and not empty; it is not in copy mode; the agent's input
prompt is among the last six of the last 16 non-blank lines of its screen, with
no numbered choice and no `to interrupt` anywhere in those 16 (the runner's own
wait for a prompt looks for `esc to interrupt` only at the end of a line); and
two reads of its screen, at least a second apart, are the same. Anything else
is **busy** and the line says why (`copy-mode`, `unknown: ...`, `asking`,
`working`, `the screen is still changing`). Busy panes are closed only with
`--include-busy`, because that discards the agent's work.

What it cannot know: it reads the screen's text, and agents differ. An agent that
shows no `to interrupt` and prints nothing for a second while it works would be
read as idle. Read the listing before you pass `--yes`; the screen lines in it
(the last three non-blank lines of each pane, cut to 120 characters) are whatever
the agent displayed, so do not paste a listing into GitHub or a chat.

### Closing, one pane at a time

Right before each pane is closed it is listed and read again: it must still be on
the same tmux server and still satisfy the five conditions with the same session,
window, start directory and start command; its process must be the one that was
listed (a pane started again with `respawn-pane` is not closed), and a pane that
was dead must not have come alive; it is read again and must still be dead, idle,
or busy with `--include-busy`. The last read is the one that is sent with
`kill-pane`: it shows the pane's dead flag, copy mode, foreground command and
process, and they must be the ones the decision to close it rested on. A pane
that was started again (a new process), put in copy mode or given another
foreground command in the meantime is `left open: it changed right before it was
to be closed`, is not counted as closed, and still keeps the next run from
starting. `can't find pane` and a server that is gone count as closed; a pane ID
that another tmux server answers for is left open. It never closes the pane the
command runs in (`$TMUX_PANE` on the same server) nor a pane whose process is
above the command's own (read from `/proc`; where it cannot be read, only dead
panes are closed).

The listing says what goes with a pane: the window when it is the window's last
pane; the session when it is the session's last pane, which detaches a client
attached to it; and every session grouped with that one, which has no windows of
its own and ends with it. The last pane of a session that has a grouped twin is
closed with `--yes`, with that said on its line.

### Task directories

Every directory named like a nonce (32 hex digits) under the checkout's task
directory is listed, oldest first, with its PR and phase, its age (the time of its
`task.json`) and the result the skill published (`none` when there is none).
Task directories are evidence of what was dispatched and are kept unless
`--remove-task-dirs` is given with `--yes`. A directory is then removed only when
ALL of these hold: the lock is held by this run; after the pane step no live pane
of the runner's and no pane in the way is left (otherwise none is removed, and
the line says which pane); it is a real directory owned by you, reached without
following a symlink; its `task.json` parses and names the directory's own nonce;
and it holds nothing but `task.json` and `result.json`. The removal is the
unlinking of those two files and one `rmdir`, never a recursive delete. A stray
file (a `tmp*` left by an interrupted write of the result), any other name, the
evidence under `.pr-ready/`, and an older layout's directories are reported or
ignored and never removed.

### What it prints

The first line names the checkout, the session and the tmux socket. Next come
a line about the checkout's lock, when another runner holds it, and about
uncommitted work or a git operation in progress in the checkout (reported, never
touched); then a line for each pane of the runner's, with the last lines of its
screen after `  | `, a line for each pane in the way, a line for each task
directory, and a summary. With no tmux server running it prints tmux's own line
instead of panes. Exit status 0 for a finished listing or run (a pane left open
by a rule is not an error), 1 with `pr-loop: <reason>` on stderr when it cannot
go on (a held lock, a tmux failure, a listing it cannot read), 2 for a wrong
command line.

```text
Residue of earlier runs in <checkout> (tmux session <session> on <socket>):
pane %N window <PR>-<phase>: dead, <command>; would close: it is dead
pane %N window <PR>-<phase>: alive, idle (at its prompt), <command>; would close: it is idle
pane %N window <PR>-<phase>: alive, busy (<reason>), <command>; left open: it is busy; busy panes are closed only with --include-busy
pane %N window <PR>-<phase>: alive, idle (at its prompt), <command>; closed: it is idle; closing it ends window <PR>-<phase> and session <session>; an attached client is detached
not the runner's: pane %N (session <session>, window <window>) in <path>: left alone; the next run refuses because of it
task <nonce>: PR #<n> <phase>, <age> old, result <OUTCOME>; would remove: no pane of the runner is left and it holds only its task and result
task <nonce>: PR #<n> <phase>, <age> old, result <OUTCOME>; kept: task directories are removed only with --remove-task-dirs
would close <k> panes and remove <m> task directories; the next run would start
would close <k> panes and remove <m> task directories; the next run would still be refused (%N)
closed <k> panes and removed <m> task directories; the next run would start
```

The summary's last clause is about panes, uncommitted work and a git operation in
progress only: the next run can still refuse for another reason, such as an
`origin` that is not `--repo`. A second `--clean --yes` finds nothing more to do.

### Limits

`--clean` was verified on tmux 3.8 and on tmux 3.4. It closes a live pane only
where it can read `/proc` (Linux); elsewhere it closes dead panes. The read that
is sent with `kill-pane` and the `kill-pane` itself are two tmux commands (the
runner never sends `if-shell`, which could make them one): what happens to the
pane in the milliseconds between them is not covered, so a pane that is started
again or put in copy mode in that gap is still closed. tmux 3.4
records a `$` in a directory differently from 3.8, so a checkout whose path holds
one is not recognised there (its panes are listed as not the runner's), and it
does not quote a newline in a directory name, so a name made to look like a row
of the listing is read as one (3.8 quotes it). The start command of a split of
yours is told from the runner's by its text (`exec <absolute path>`), so a split
you started with exactly that command is taken for the runner's, and is closed
unless it is busy.
