#!/usr/bin/env python3
"""Run Pilot's Draft/Ready PR skills in order using managed tmux panes.

The agents start in YOUR checkout, not in a clone of their own: the root of the git work tree the runner is started
in, or the directory named by --checkout. Start the agents there once yourself, so that they already trust it: the
runner cannot answer a trust dialog. The checkout must be clean and its origin must be --repo, or the runner refuses
before it reads GitHub. It must be on the default branch of origin, at origin's tip or strictly behind it, or on
another branch, which the runner then leaves: it switches the checkout to origin's default branch (only an existing
local branch that no other work tree holds) and says how to go back, and never switches it back. At startup only, a
default branch strictly behind is fast-forwarded to exactly the tip origin reported: one `git fetch` of that commit,
one local `git fetch .` that moves the branch to it (git refuses anything but a fast-forward) and one `git switch`
(or, on the default branch itself, one `git merge --ff-only`), with hooks and automatic maintenance off; a checkout
that is ahead, diverged, detached, without a commit, a partial clone, or whose update would touch a submodule or an
ignored file is refused instead. Apart from that a run never deletes, resets, cleans or stashes anything in it, and the
branch it leaves keeps its commits; the task files it writes stay under the checkout's task directory (ignored by git),
and the agent windows it started stay open when it stops: `--clean` lists them, and closes them on request (below).

The agents run as windows (one per agent, named `<PR>-<phase>`) of ONE tmux session of the runner's own, never of one of
yours: `pilot-pr-<directory name>-<8 hex>`, where the directory name is the checkout's, cut down to letters, digits, `_`
and `-`, and the hex is a hash of its full path, so that the name is the same on every run in this checkout and differs
between checkouts. The first agent creates the session, every later one adds a window to it; the runner announces the
name once and you watch from another terminal, read-only, with `tmux attach -r -t <session>`. The runner never kills
or renames a window or a session. It adds a window to the session named for the checkout when that exists (also one an
earlier run left), and a run closes only the panes it started in this process, one pane at a time, after checking that
each is still that pane on the same tmux server: pane IDs are only unique within one server, and a tmux server exits
with its last session, so a later server can give the same ID to another pane. The dead windows of an earlier run
stay where they are until `--clean --yes` closes them. The session ends with its last window, and a client attached to
it is detached then (tmux's default).

`--clean` is for what a stopped or interrupted run left. It lists the panes that are provably the runner's (all of: the
session named for the checkout, a window named `<PR>-draft` or `<PR>-ready`, started in the checkout itself with the
command `exec <absolute path>`), each dead, idle or busy, and the task directories; a pane that is not provably the
runner's (another session, another window, a split of yours) is listed only when the next run would refuse because of
it, and is left alone. It changes nothing, reads no GitHub and starts no agent. `--clean --yes` takes the checkout's
lock and closes the dead and idle panes, one at a time with `kill-pane`, each after checking it again on the same tmux
server; it never closes the pane the command itself runs in, and `--include-busy` closes busy ones too (the agent's
work is lost). `--remove-task-dirs` removes the task directories of finished runs, and only when no pane of the runner
is left. It never touches the git checkout: uncommitted work is reported, and stays.

The runner dispatches the Ready skill (pr-review-merge) only for a PR that carries a valid Ready signal at its
current HEAD and for its latest Ready transition (`ready_signal.assess`): proof that pr-ready (or issue-to-pr's mark_ready.py) verified and signed it. A
Ready PR without one is `unverified` and is never acted on; the runner carries a signal across nothing (neither a
base import nor an evidence-only commit; the merge-train integration commit is the train's business) and writes
nothing to GitHub.
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import fnmatch
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit


sys.dont_write_bytecode = True
SKILLS = Path(__file__).resolve().parents[1] / ".agents/skills"
sys.path[:0] = [str(SKILLS / skill / "scripts") for skill in ("pr-review-merge", "_shared")]
import bounded_run  # the one way this runner starts a command (tests/test_bounded_run_lint.py)
from checkout_preflight import (HEX, GitError, check_checked_out_elsewhere, check_dirty, check_ignored_collisions,
                                check_in_progress)
from gh_runtime import GitHubError, Repo, issue_comments, pr_view, timeline_events, viewer_login
from list_ready import QUEUE_LABEL
from needs_person import LABEL as PERSON_LABEL, latest_marker
from pr_loop_result import NONCE, OUTCOMES, SHA, TASK_DIR
import ready_signal  # only LABEL, assess and SignalError: this runner reads the signal, it never writes one


# A phase must be read this many times in a row before the runner acts on it, and a failed GitHub read is
# retried up to READ_ATTEMPTS times in a row: one lagging or failing read must not dispatch an agent or stop
# the run. Module constants, not flags.
STABLE_POLLS = 2
READ_ATTEMPTS = 3
# What `--phase-timeout` defaults to, in seconds: the wait per phase. Four hours, because a Draft phase that fixes a review
# finding, runs the checks and waits for CI took about two and a half hours in a real run, and 7200 seconds gave up on an agent
# that was still working.
PHASE_TIMEOUT = 14400

# What `--checkout` defaults to, in the words of its help text and of `.agents/skills/_shared/pr-loop.md`.
CHECKOUT_DEFAULT = "the root of the git work tree that contains the current directory"
LOCK_NAME = "pilot-pr-loop.lock"
PANE_SESSION_PREFIX = "pilot-pr-"
# The longest directory name kept in a session name, and how many times starting an agent follows a session that
# somebody else created or killed meanwhile before it gives up. Module constants, not flags.
SESSION_LABEL_MAX = 24
CREATE_ROUNDS = 3
# What tmux prints for a new pane (`-P -F`): the pane ID, and the PID and start time of the tmux server that made it. A
# pane ID is only unique within one server; the pair identifies the server. And what the runner reads of a pane in ONE
# call, the server's identity beside the pane's fields.
PANE_FORMAT = "#{pane_id}|#{pid}|#{start_time}"
READ_FORMAT = "#{pane_dead}|#{pane_in_mode}|#{pane_current_command}|#{pid}|#{start_time}"
# The only git subcommands that change the checkout (the startup fast-forward and switch to origin's default branch), and
# how long each may run, in seconds. Every command this runner starts runs through `bounded_run.run` (see its docstring):
# one that outlives its limit gets SIGTERM to its whole process group and, KILL_AFTER seconds later, SIGKILL to whatever is
# still in that group (also when the command itself has already gone). What is then still in its pipes is read for at most
# DRAIN seconds and the pipes are closed, so that nothing the command started, in or out of its group, can hold the runner;
# POLL is the length of one wait for its output, after which a command that has exited is judged by its exit code. These
# three are what `run` and `git_change` pass, read at each call. Module constants.
GIT_CHANGES = {"fetch": 600, "merge": 120, "switch": 120}
KILL_AFTER = 30
DRAIN = 5
POLL = 1


class Stop(RuntimeError):
    pass


class ForwardInterrupted(KeyboardInterrupt):
    """Ctrl-C while the startup fast-forward was under way, or after it began: `text` says what to check."""

    def __init__(self, text):
        super().__init__(text)
        self.text = text


def tell(message):
    print(message, flush=True)


def run(args, *, cwd=None, data=None, env=None, timeout=120):
    """One command, whatever it exits with: its status is the caller's to judge, also when something it started still
    holds its output (a command that exited is not waited for beyond DRAIN). One that outlives `timeout` is ended with
    its whole process group (SIGTERM, then SIGKILL after KILL_AFTER) and is a Stop."""
    try:
        return bounded_run.run(args, limit=timeout, cwd=cwd, env=env, input=data, kill_after=KILL_AFTER, drain=DRAIN,
                               poll=POLL)
    except bounded_run.Timeout:
        raise Stop(f"{' '.join(args[:2])} timed out after {timeout} seconds") from None


def command(*args, cwd=None, data=None):
    proc = run(args, cwd=cwd, data=data)
    if proc.returncode != 0:
        raise Stop(f"{' '.join(args[:2])} failed ({proc.returncode}): {proc.stderr.strip()[:500]}")
    return proc.stdout


def git_change(cwd, sub, *args):
    """The ONLY git call of this runner that changes the checkout: `sub` is `fetch`, `merge` or `switch` (anything else is a
    Stop), run with hooks and automatic maintenance off, no credential prompt, no lazy fetch and one locale, in a
    process group of its own so that the terminal's Ctrl-C does not reach it half way. The result is the caller's to
    judge. The call has ONE deadline, GIT_CHANGES[sub] seconds from its start, and returns or raises within that plus
    KILL_AFTER and DRAIN (and one POLL), whatever git's descendants do with SIGTERM or with git's pipes: at the deadline
    `bounded_run` ends the group and the call raises a Stop. A git that exits is judged by its exit code and its output
    alone: what it left behind is not waited for beyond DRAIN and not signalled (it may be a daemon git started on
    purpose; every caller reads the state with git itself afterwards). A `merge` or `switch` that was interrupted is
    still waited for (it is short, and must finish or fail whole), but only until that same deadline, and the interrupt
    is raised afterwards, in place of the timeout Stop; a `fetch` that was interrupted is ended (SIGTERM, then SIGKILL)
    at once, and a second interrupt ends it with SIGKILL at once (`bounded_run.run`'s `on_interrupt`).
    tests/test_pr_loop.py::ImportsTests lists the call sites and the flags each must carry."""
    if sub not in GIT_CHANGES:
        raise Stop(f"git {sub} is not a command this runner changes a checkout with")
    argv = ["git", "-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=false", sub, *args]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", LC_ALL="C")
    try:
        return bounded_run.run(argv, limit=GIT_CHANGES[sub], cwd=cwd, env=env, kill_after=KILL_AFTER, drain=DRAIN,
                               poll=POLL, on_interrupt="end" if sub == "fetch" else "finish")
    except bounded_run.Timeout:
        raise Stop(f"git {sub} timed out after {GIT_CHANGES[sub]} seconds") from None


def git(cwd, *args, ok=(0,), env=None):
    """One READ-ONLY git call in `cwd`: no opportunistic index refresh, no credential prompt, one locale. A status
    outside `ok` is a Stop (`ok=None`: the caller judges the result). Every git call of this runner that only reads goes
    through here, the two that change the checkout through `git_change`, and tests/test_pr_loop.py::ImportsTests lists
    the subcommands each may name."""
    proc = run(["git", *args], cwd=cwd, env=dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
                                                  LC_ALL="C", **(env or {})))
    if ok is not None and proc.returncode not in ok:
        raise Stop(f"git {args[0]} failed ({proc.returncode}): {proc.stderr.strip()[:500]}")
    return proc


def state_of(view):
    if view.get("state") == "MERGED":
        return "merged"
    if view.get("state") != "OPEN":
        raise Stop(f"PR #{view['number']} is not open or merged")
    if view.get("isDraft") is True:
        return "draft"
    if view.get("isDraft") is not False:
        raise Stop(f"PR #{view['number']} has no Draft state")
    return "queued" if has_label(view, QUEUE_LABEL) else "ready"


def has_label(view, label):
    labels = view.get("labels")
    if not isinstance(labels, list) or any(not isinstance(entry, dict) for entry in labels):
        raise Stop(f"PR #{view['number']} returned invalid labels")
    return any(entry.get("name") == label for entry in labels)


def head_of(view):
    head = view.get("headRefOid")
    if not isinstance(head, str) or not SHA.fullmatch(head):
        raise Stop(f"PR #{view['number']} has no valid HEAD SHA")
    return head.lower()


def signal_phase(repo, number, view, account):
    """(phase, detail) of a PR `state_of` calls `ready`: `ready` only when its Ready signal is valid at this very
    HEAD, otherwise `unverified` with the reason. Strict: a signal that names an earlier HEAD does not count here,
    whatever changed since. The PR's timeline is read only when it carries the label; `account` is a callable that
    returns the login `gh` runs as (the signal is trusted only when that account wrote it)."""
    if not has_label(view, ready_signal.LABEL):
        return "unverified", f"the PR does not carry the {ready_signal.LABEL} label"
    head = head_of(view)
    try:
        found = ready_signal.assess(head, view["labels"], timeline_events(repo, number), account())
    except ready_signal.SignalError as exc:
        return "unverified", f"the signal cannot be read: {exc}"
    if found.valid and found.marker_head == head:
        return "ready", ""
    return "unverified", f"{found.state}: {found.reason}"


def phase_of(repo, number, view, account):
    """(phase, detail) of one PR view: `state_of`, with a Ready PR sorted into `ready` or `unverified`."""
    phase = state_of(view)
    if phase == "ready":
        return signal_phase(repo, number, view, account)
    return phase, ""


def observe(repo, number, account=None):
    """One observation of the PR: `(view, phase, detail)`. `account` returns the login `gh` runs as (a Batch passes a
    callable that reads it once); without one it is read on demand. A PR waiting for a person stops the run."""
    account = account or (lambda: viewer_login(repo))
    view = pr_view(repo, number)
    phase, detail = phase_of(repo, number, view, account)
    if phase == "ready" and has_label(view, PERSON_LABEL):
        head = head_of(view)
        marker = latest_marker(issue_comments(repo, number), account())
        if marker and marker["head"] == head:
            fresh = pr_view(repo, number)
            if state_of(fresh) == "ready" and has_label(fresh, PERSON_LABEL) and head_of(fresh) == head:
                raise Stop(f"PR #{number} needs a person at HEAD {head[:12]}; see the PR conversation")
            view = fresh
            phase, detail = phase_of(repo, number, fresh, account)
    return view, phase, detail


def repo_identity(repo):
    """`host/owner/name` of the repository the runner drives (the host defaults to github.com)."""
    return f"{repo.host or 'github.com'}/{repo.owner}/{repo.name}"


def check_pr_url(view, repo):
    """The PR a view describes must be this repository's pull request, on its host, by its number: the URL is read
    before every dispatch, whatever the checkout is."""
    url = urlsplit(view.get("url", ""))
    host = repo.host or "github.com"
    path = f"/{repo.owner}/{repo.name}"
    if url.scheme != "https" or url.netloc.casefold() != host.casefold() or \
       url.path.casefold() != f"{path}/pull/{view['number']}".casefold() or url.query or url.fragment:
        raise Stop("GitHub returned an unexpected PR URL")


def resolve_checkout(repo, directory=None):
    """The checkout, resolved once to one absolute path: the root of the work tree of the current directory, or
    `directory`, which must be that root itself (the agents start in it, literally)."""
    if directory is None:
        done = git(os.getcwd(), "rev-parse", "--show-toplevel", ok=None)
        if done.returncode != 0:
            raise Stop("the current directory is not inside a git work tree; start the runner in a checkout of "
                       f"{repo_identity(repo)} or pass --checkout DIR")
        return Path(done.stdout.strip()).resolve()
    given = Path(directory).expanduser()
    if not given.is_dir():
        raise Stop(f"--checkout {directory} is not a directory")
    done = git(given, "rev-parse", "--show-toplevel", ok=None)
    if done.returncode != 0:
        raise Stop(f"--checkout {directory} is not a git work tree")
    top = Path(done.stdout.strip()).resolve()
    if top != given.resolve():
        raise Stop(f"--checkout {directory} is not the root of its git work tree {top}; pass {top}")
    return top


_NAME = r"[A-Za-z0-9_.-]+"
_PATH = re.compile(rf"/(?P<owner>{_NAME})/(?P<name>{_NAME}?)(?:\.git)?/?")
_SCP = re.compile(rf"(?:[^@/:\s]+@)?(?P<host>[A-Za-z0-9.-]+):(?P<owner>{_NAME})/(?P<name>{_NAME}?)(?:\.git)?/?")
_HOST = re.compile(r"[A-Za-z0-9.-]+")


def origin_repo(url):
    """`(host, owner, name)` of a remote URL in one of the forms GitHub hands out (`https://[user@]host[:port]/o/n`,
    `ssh://[user@]host[:port]/o/n`, `[user@]host:o/n`, each with an optional `.git` and trailing `/`), else None. The
    userinfo, which may be a token, is never returned; neither is anything that is not a plain host or name."""
    if "://" in url:
        try:
            parts = urlsplit(url)
            host, _ = parts.hostname, parts.port
        except ValueError:
            return None
        if parts.scheme not in ("https", "ssh") or parts.query or parts.fragment or not host or \
           not _HOST.fullmatch(host):
            return None
        found = _PATH.fullmatch(parts.path)
        return (host, found["owner"], found["name"]) if found else None
    found = _SCP.fullmatch(url)
    return (found["host"].lower(), found["owner"], found["name"]) if found else None


def redact(text, urls):
    """`text` without any of the configured remote URLs and without the userinfo of any URL: a token may sit in a
    remote's URL, and git can quote a URL back."""
    for url in sorted(filter(None, urls), key=len, reverse=True):
        text = text.replace(url, "<origin>")
    return re.sub(r"(?<=://)[^/@\s]+@", "<redacted>@", text)


def lock_checkout(top, path):
    """Take the checkout's lock, for the life of the process: the descriptor of an exclusive `flock` on `path`, which
    is never deleted (the kernel drops the lock when the runner dies, however it dies) and is not inherited by the
    commands the runner starts. Anything but \"somebody else holds it\" is a refusal too: an unknown lock is no lock."""
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise Stop(f"cannot lock the checkout {top} ({path}): {exc.strerror or exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Stop(f"cannot lock the checkout {top} ({path}): not a regular file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            raise Stop(f"another pr_loop runner is using the checkout {top} (lock {path}); "
                       "wait for it to finish or stop it") from None
        raise Stop(f"cannot lock the checkout {top} ({path}): {exc.strerror or exc}") from exc
    except Stop:
        os.close(fd)
        raise
    return fd


def git_path(top, name):
    """Where git keeps `name` of the work tree at `top` (`git rev-parse --git-path`), as an absolute path."""
    raw = git(top, "rev-parse", "--git-path", name).stdout.strip()
    return Path(raw) if os.path.isabs(raw) else top / raw


def session_name(path):
    """The tmux session of the runner in the checkout at `path` (absolute and resolved: `resolve_checkout`):
    `pilot-pr-<label>-<8 hex>`. The label is the directory name cut down to what tmux keeps as typed and can target
    (letters, digits, `_` and `-`: a `:` in a name makes the session impossible to address, a `.` breaks some target
    forms such as `has-session -t =a.b`, a tab is refused) and the hex is a hash of the whole path, so the name is
    stable per checkout and two checkouts with the same directory name under different parents do not share a session."""
    label = re.sub(r"[^A-Za-z0-9_-]+", "-", Path(path).name).strip("-")[:SESSION_LABEL_MAX].rstrip("-") or "checkout"
    return f"{PANE_SESSION_PREFIX}{label}-{hashlib.sha256(os.fsencode(str(path))).hexdigest()[:8]}"


def no_tmux_server(stderr):
    """Whether what tmux said is that no server is running: the socket is left behind (`no server running on ...`) or there
    is none (`error connecting to ... (No such file or directory)`)."""
    return "no server running" in stderr or re.search(r"error connecting to .* \(No such file or directory\)",
                                                      stderr) is not None


# What `list-panes -a -F` prints for each pane, `|` between fields: the ones of a fixed shape first (the pane's and its window's
# ID, whether it is dead or in a mode, its process, and the PID and start time of the tmux server that answers), then the free
# text of the operator's world, each value in tmux's `q:` quoting (a backslash before every character that is special to a
# shell, and in tmux 3.8 before a newline too), so that no value ends its field or its row early. `pane_start_path` and
# `pane_start_command` are what the pane was started with, which a dead pane keeps (it has no current path; tmux 3.8 gives it
# no process, tmux 3.4 the one it had).
LIST_TEXT = ("socket_path", "session_name", "window_name", "pane_start_path", "pane_start_command", "pane_current_path",
             "pane_current_command")
LIST_FORMAT = "|".join(("#{pane_id}", "#{window_id}", "#{pane_dead}", "#{pane_in_mode}", "#{pane_pid}", "#{pid}",
                        "#{start_time}", *(f"#{{q:{name}}}" for name in LIST_TEXT)))
_SHAPES = (re.compile(r"%[0-9]+"), re.compile(r"@[0-9]+"), re.compile(r"[01]"), re.compile(r"[01]"), re.compile(r"[0-9]*"),
           re.compile(r"[0-9]+"), re.compile(r"[0-9]+"))
# The windows the runner names for its agents: `<PR>-draft` and `<PR>-ready`.
AGENT_WINDOW = re.compile(r"[1-9][0-9]*-(?:draft|ready)")


class Pane(NamedTuple):
    """One pane of the tmux server, as `list-panes -a` shows it (LIST_FORMAT), the free text unquoted. A pane of a grouped
    session is shown once for every session of the group."""
    pane: str
    window_id: str
    dead: bool
    in_mode: bool
    pid: str  # the pane's process; empty for a dead pane in tmux 3.8, the process it had in tmux 3.4
    server: tuple  # (PID, start time) of the tmux server that listed it: a pane ID means this pane only on that server
    socket: str
    session: str
    window: str
    start_path: str
    start_command: str
    path: str  # where the pane is now; empty for a dead pane
    command: str  # what runs in its foreground


def unquote(text):
    """`text` without the backslashes of tmux's `q:` quoting: a backslash makes the character after it a plain one."""
    return re.sub(r"\\(.)", r"\1", text, flags=re.DOTALL)


_ROW_START = re.compile(r"%[0-9]+\|@[0-9]+\|[01]\|[01]\|[0-9]*\|[0-9]+\|[0-9]+\|")


def split_listing(text):
    """The rows of a `list-panes` listing, each a list of fields, still quoted: a backslash makes the next character, a
    newline too, part of its field (tmux 3.8 puts one before a newline in a value); a `|` that is not quoted ends a field; a
    newline that is not quoted ends a row when what follows is the start of a row or the end of the text, and is otherwise part
    of the field (tmux 3.4 does not quote a newline in a value: a directory name may hold one). None when the text ends inside
    a row or inside a quoting: it cannot be read."""
    rows, row, field, at = [], [], [], 0
    while at < len(text):
        char = text[at]
        at += 1
        if char == "\\":
            if at == len(text):
                return None
            field += [char, text[at]]
            at += 1
        elif char == "|":
            row.append("".join(field))
            field = []
        elif char == "\n" and (at == len(text) or _ROW_START.match(text, at)):
            row.append("".join(field))
            rows.append(row)
            row, field = [], []
        else:
            field.append(char)
    return rows if not row and not field else None


def read_pane(fields):
    """The Pane of one row of `split_listing`; a row of another shape is a Stop."""
    if len(fields) != len(_SHAPES) + len(LIST_TEXT) or not all(shape.fullmatch(value) for shape, value in zip(_SHAPES, fields)):
        raise Stop("tmux list-panes returned a line that cannot be read")
    pane, window_id, dead, in_mode, pid, server_pid, start = fields[:7]
    socket, session, window, start_path, start_command, path, command = (unquote(field) for field in fields[7:])
    return Pane(pane, window_id, dead == "1", in_mode == "1", pid, (server_pid, start), socket, session, window, start_path,
                start_command, path, command)


def list_panes():
    """`(panes, said)`: every pane of the tmux server, in the order tmux lists them, and the text tmux printed when no
    server is running (`said`, with no panes). Any other failure, and a listing that cannot be read, is a Stop."""
    done = run(["tmux", "list-panes", "-a", "-F", LIST_FORMAT])
    if done.returncode != 0:
        if no_tmux_server(done.stderr):
            return [], done.stderr.strip()  # no tmux server, so no pane
        raise Stop(f"tmux list-panes failed ({done.returncode}): {done.stderr.strip()[:500]}")
    rows = split_listing(done.stdout)
    if rows is None:
        raise Stop("tmux list-panes returned a line that cannot be read")
    return [read_pane(row) for row in rows], ""


def distinct(panes, session):
    """One row for every pane: tmux repeats the panes of a session in each session grouped with it. The row of `session`
    wins, otherwise the first one does."""
    kept = {}
    for pane in panes:
        have = kept.get(pane.pane)
        if have is None or (pane.session == session and have.session != session):
            kept[pane.pane] = pane
    return list(kept.values())


# How tmux 3.8 writes the characters it escapes in a command it shows between double quotes (vis(3), C style): `\\`, `\"`, `\$`,
# the control characters with a name, and the others as three octal digits.
_VIS = {"\\": "\\", '"': '"', "$": "$", "n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "v": "\v", "f": "\f"}


def started_with(shown):
    """The absolute path in `exec <path>` when that is the start command of a pane as tmux shows it, else None. tmux shows the
    command it was given between double quotes when it holds a space (tmux 3.8), with the escapes of `_VIS`, or as it was given;
    the runner's own command is `exec ` and the path quoted for a shell (`shlex.quote`), and nothing else is read as it: the text
    must be exactly that, so a command that adds a word, a `;` or a second space is not the runner's."""
    if len(shown) >= 2 and shown[0] == shown[-1] == '"':
        shown = re.sub(r"\\(?:([\\\"$ntrabvf])|([0-7]{3}))", lambda found: _VIS[found[1]] if found[1] else chr(int(found[2], 8)),
                       shown[1:-1])
    try:
        words = shlex.split(shown)
    except ValueError:
        return None
    if len(words) == 2 and words[0] == "exec" and os.path.isabs(words[1]) and shown == "exec " + shlex.quote(words[1]):
        return words[1]
    return None


def runners_own(pane, top, session):
    """Whether `pane` is one this runner started for the checkout `top`: all of them on one row of the listing. Its session
    is exactly `session`, its window is named `<PR>-draft` or `<PR>-ready`, it was started in `top` itself (not below it, not
    a sibling whose name starts the same: the real paths are equal), and with the command `exec <absolute path>`, which is
    how the runner starts every agent and not how a pane you open is started. The tmux server comes from the same row."""
    return pane.session == session and AGENT_WINDOW.fullmatch(pane.window) is not None and \
        bool(pane.start_path) and os.path.realpath(pane.start_path) == os.path.realpath(top) and \
        started_with(pane.start_command) is not None


def blocking_panes(top, panes=None):
    """The panes that make the next run refuse to start in `top`, one for each: a live pane in a session whose name starts
    with `pilot-pr-` whose directory is `top` or below it. Whoever started it: the lock died with the run that did, the pane
    did not. `panes` are the rows of a listing already read; otherwise the server is asked. Dead panes, and panes elsewhere
    or in other sessions, are not the runner's business."""
    panes = list_panes()[0] if panes is None else panes
    inside, found = os.path.realpath(top), {}
    for pane in panes:
        where = os.path.realpath(pane.path) if pane.path else None
        if not pane.dead and pane.session.startswith(PANE_SESSION_PREFIX) and where and \
           (where == inside or where.startswith(inside + os.sep)):
            found.setdefault(pane.pane, pane)
    return list(found.values())


def check_panes(top):
    """A pane an earlier run kept (`pilot-pr-*`, still alive) in the checkout is a second user of it: the next run refuses,
    and says that `--clean` lists it."""
    blocking = blocking_panes(top)
    if blocking:
        raise Stop(f"agent pane {blocking[0].pane} (session {printable(blocking[0].session)}) is still running in {top}; "
                   "inspect and close it before starting the runner again "
                   "(python3 scripts/pr_loop.py --clean lists what an earlier run left)")


def printable(text):
    return "".join(char if char.isprintable() else "?" for char in text)


class Checkout:
    """The operator's own checkout, inspected once at startup and verified again before every dispatch. Everything
    here READS it, except three things: the lock file in its git directory; only when git does not ignore the task and
    evidence directories yet, two lines appended to its git exclude file; and, only when the checkout is strictly
    behind origin's tip or on another branch, the fast-forward and switch to exactly that tip: the objects and the remote-tracking ref
    `git fetch` writes, the default branch that `git merge --ff-only` (on it) or a local `git fetch .` (from another
    branch) moves, and the index, work tree and HEAD that the merge or `git switch` change. `dry_run` inspects without any
    of them (and without tmux); a refusal is a Stop."""

    def __init__(self, repo, directory=None, *, dry_run=False):
        self.repo, self.dry_run, self.lock_fd, self.would_add = repo, dry_run, None, []
        # What the fast-forward is doing or did: `forwarding` is set before the fetch starts, `forwarded` when the merge
        # has landed on the tip, `would_forward` is what a dry run found: `(local, tip, whether the tip is in the checkout)`.
        self.forwarding = self.forwarded = self.would_forward = None
        # The switch to origin's default branch, when the checkout was on another one: `switching` is `(x, b)`, set before
        # the first write; `switched` is `(x, X)` once HEAD is on `b`; `would_switch` is `(x, X, b)` in a dry run.
        self.switching = self.switched = self.would_switch = None
        self.path = resolve_checkout(repo, directory)
        self.session = session_name(self.path)
        self.lock_path = self.git_path(LOCK_NAME)
        if not dry_run:
            self.lock_fd = lock_checkout(self.path, self.lock_path)
        try:
            self.inspect()
        except BaseException as exc:
            self.release()  # a refusal does not keep the lock
            if isinstance(exc, KeyboardInterrupt) and not isinstance(exc, ForwardInterrupted) and self.switching:
                other, branch = self.switching
                raise ForwardInterrupted(f"Interrupted while switching {self.path} from {printable(other)} to {branch}; "
                                         "check it with git status before the next run.") from None
            if isinstance(exc, KeyboardInterrupt) and not isinstance(exc, ForwardInterrupted) and self.forwarding:
                branch, local, tip = self.forwarding
                raise ForwardInterrupted(f"Interrupted while fast-forwarding {branch} in {self.path} (from {local[:12]} "
                                         f"to {tip[:12]}); check it with git status before the next run.") from None
            raise

    def release(self):
        """Give the lock back (the lock file stays): only a refusal needs it, a run keeps the lock until it ends."""
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def inspect(self):
        if not self.dry_run:
            check_panes(self.path)
        self.check_origin()
        self.check_operation()
        self.check_clean()
        branch, tip = self.origin_head()
        ref, sha = self.current()
        if ref is None:
            raise Stop(f"checkout {self.path} has a detached HEAD at {(sha or '')[:12]}; check out {branch}, "
                       "the default branch of origin")
        if ref != f"refs/heads/{branch}":
            self.switch_to_default(branch, tip, ref, sha)
        else:
            self.check_tip(branch, tip)
        self.branch, self.head = ref, tip if self.forwarded else sha
        if self.switched:
            self.branch, self.head = f"refs/heads/{branch}", tip
        self.ignore_task_files()  # last: it judges the .gitignore of the tree the agents will see

    def git_path(self, name):
        return git_path(self.path, name)

    def config_values(self, key):
        done = git(self.path, "config", "--get-all", "-z", key, ok=(0, 1))
        return done.stdout.split("\0")[:-1]

    def check_origin(self):
        """origin is the repository the runner drives: one URL (git fetches from the first and pushes to all of them), and
        every push URL too. Only the host, owner and name are ever quoted, never a URL."""
        identity = repo_identity(self.repo)
        wanted = tuple(part.casefold() for part in identity.split("/"))
        urls = self.config_values("remote.origin.url")
        if not urls:
            raise Stop(f"checkout {self.path} has no origin remote")
        if len(urls) > 1:
            raise Stop(f"origin of {self.path} has {len(urls)} URLs; the runner needs exactly one, of {identity}")
        for fetch, values in ((True, urls), (False, self.config_values("remote.origin.pushurl"))):
            for value in values:
                found = origin_repo(value)
                if found is None:
                    raise Stop(f"origin of {self.path} is not a URL of {identity}" if fetch else
                               f"a push URL of origin of {self.path} is not a URL of {identity}")
                if tuple(part.casefold() for part in found) != wanted:
                    raise Stop(f"origin of {self.path} {'is' if fetch else 'pushes to'} {'/'.join(found)}, "
                               f"not {identity}")

    def check_operation(self, suffix=""):
        try:
            busy = check_in_progress(self.path)
        except GitError as exc:
            raise Stop(str(exc)) from exc
        if busy:
            raise Stop(f"a git operation is in progress in {self.path} ({', '.join(busy[0]['paths'])}); "
                       f"finish or abort it{suffix}")

    def check_clean(self, suffix=""):
        try:
            dirty = check_dirty(self.path)
        except GitError as exc:
            raise Stop(str(exc)) from exc
        if dirty:
            names = [re.sub(r"^[ MADRCUT?!]{2} ", "", entry) for entry in dirty[0]["paths"][:3]]
            raise Stop(f"checkout {self.path} has uncommitted changes or untracked files ({dirty[0]['count']} paths, "
                       f"e.g. {printable(', '.join(names))}); commit or remove them; the runner never stashes or "
                       f"discards work{suffix}")

    def current(self):
        """`(HEAD's branch ref or None when detached, HEAD's commit or None when unborn)`."""
        ref = git(self.path, "symbolic-ref", "--quiet", "HEAD", ok=(0, 1)).stdout.strip() or None
        sha = git(self.path, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", ok=(0, 1)).stdout.strip() or None
        return ref, sha

    def origin_head(self):
        """`(default branch, tip)` of origin, as origin says it NOW. `refs/remotes/origin/HEAD` is a cache that
        `git init` plus `git remote add` never sets and a rename leaves wrong."""
        done = git(self.path, "ls-remote", "--symref", "origin", "HEAD", ok=None)
        if done.returncode != 0:
            urls = self.config_values("remote.origin.url") + self.config_values("remote.origin.pushurl")
            raise Stop(f"cannot read the default branch of origin for {self.path}: git ls-remote failed "
                       f"({done.returncode}): {redact(done.stderr.strip(), urls)[:300]}")
        lines = done.stdout.splitlines()
        refused = Stop("origin did not report its default branch (git ls-remote --symref origin HEAD)")
        if len(lines) != 2:
            raise refused
        branch, tip = re.fullmatch(r"ref: refs/heads/([^\t]+)\tHEAD", lines[0]), re.fullmatch(rf"({HEX.pattern})\tHEAD", lines[1])
        if not branch or not tip or git(self.path, "check-ref-format", f"refs/heads/{branch[1]}",
                                        ok=(0, 1)).returncode != 0:
            raise refused
        return branch[1], tip[1]

    def relation(self, local, tip):
        """How the local branch (at `local`) stands to origin's `tip`: `ahead` (the tip is an ancestor of it), `behind`
        (it is an ancestor of the tip), `diverged`, or None when the tip is not in the checkout (or not with all its
        history): then nothing can be said without fetching it. Read-only, and it never fetches (no lazy fetch)."""
        quiet = {"GIT_NO_LAZY_FETCH": "1"}
        if git(self.path, "cat-file", "-e", f"{tip}^{{commit}}", ok=(0, 1, 128), env=quiet).returncode != 0:
            return None
        found = git(self.path, "merge-base", "--is-ancestor", tip, local, ok=(0, 1, 128), env=quiet).returncode
        if found == 0:
            return "ahead"
        if found != 1:
            return None
        found = git(self.path, "merge-base", "--is-ancestor", local, tip, ok=(0, 1, 128), env=quiet).returncode
        return "behind" if found == 0 else "diverged" if found == 1 else None

    def check_tip(self, branch, tip):
        """The skills run from this checkout, so it must be origin's default branch AT origin's tip, or strictly behind it:
        then (a real run) it is fast-forwarded to that tip, see `forward`. Ahead, diverged and without a commit are
        refused. Checked at startup only: the merge train moves origin during a batch, and that must not refuse the next
        PR, nor update the checkout between two of them."""
        local = git(self.path, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}",
                    ok=(0, 1)).stdout.strip()
        if local == tip:
            self.check_helpers(branch, tip)
            return
        if not local:
            raise Stop(f"local {branch} has no commit but origin's {branch} is at {tip[:12]}; run git pull --ff-only in "
                       f"{self.path} and start the runner again")
        relation = self.relation(local, tip)
        self.refuse_unless_behind(branch, local, tip, relation)
        if self.partial_clone():
            raise self.partial_refusal(branch, local, tip)
        if not self.dry_run:
            self.forward(branch, local, tip)
        else:
            if relation == "behind":
                self.check_forward(branch, local, tip)
            self.would_forward = (local, tip, relation == "behind")

    def partial_refusal(self, branch, local, tip):
        return Stop(f"local {branch} is at {local[:12]} but origin's {branch} is at {tip[:12]}; {self.path} is a partial "
                    f"clone, which the runner does not fast-forward: run git pull --ff-only in {self.path} and start "
                    "the runner again")

    def refuse_unless_behind(self, branch, local, tip, relation, left=""):
        """Refuse a local branch that is ahead of origin's tip or has diverged from it; `left` says where the checkout is."""
        if relation == "ahead":
            raise Stop(f"local {branch} at {local[:12]} has commits that origin's {branch} ({tip[:12]}) does not "
                       f"have; the skills must come from origin's default branch{left}")
        if relation == "diverged":
            raise Stop(f"local {branch} at {local[:12]} and origin's {branch} at {tip[:12]} have diverged (each has "
                       "commits the other does not have); the runner only fast-forwards: put "
                       f"{branch} at origin's tip yourself and start the runner again{left}")

    def partial_clone(self):
        """Whether the checkout is a partial clone: its missing objects would be fetched by git on its own."""
        promisor = git(self.path, "config", "--type=bool", "--get-all", "-z", "remote.origin.promisor", ok=(0, 1))
        configured = git(self.path, "config", "--get-all", "-z", "extensions.partialclone", ok=(0, 1))
        return "true" in promisor.stdout.split("\0") or configured.returncode == 0

    def check_helpers(self, branch, tip):
        """Both helpers are run from this checkout by the skills it hosts: a default branch that predates either would
        leave the agent unable to report or to sign, and the run would wait for its phase timeout. Judged on the tip
        itself, which is what the checkout is (or is about to be) at."""
        for helper in ("pr_loop_result.py", "ready_signal.py"):
            where = f".agents/skills/_shared/scripts/{helper}"
            if git(self.path, "cat-file", "-e", f"{tip}:{where}", ok=(0, 128), env={"GIT_NO_LAZY_FETCH": "1"}).returncode != 0:
                raise Stop(f"origin's default branch {branch} at {tip[:12]} lacks {where}; "
                           "the skills it hosts could not report or sign")

    def check_forward(self, branch, base, tip, doing=None):
        """What must hold before the work tree at commit `base` becomes `tip`'s (which is in the checkout): the two helpers
        are on the tip, it does not move a submodule (the runner does not update submodules), and it does not overwrite,
        delete or write into an ignored path (git does that without a word, even into an ignored nested repository).
        `doing` says what is about to happen, in the words of the refusal."""
        doing = doing or f"fast-forwarding {branch} to {tip[:12]}"
        self.check_helpers(branch, tip)
        moved = git(self.path, "diff-tree", "-r", "-z", "--raw", "--no-renames", base, tip,
                    env={"GIT_NO_LAZY_FETCH": "1"}).stdout.split("\0")[:-1]
        for header, name in zip(moved[::2], moved[1::2]):
            if "160000" in (mode.lstrip(":") for mode in header.split(" ")[:2]):
                raise Stop(f"origin's {branch} at {tip[:12]} moves the submodule {printable(name)}; the runner does not "
                           f"update submodules: run git pull --ff-only and git submodule update in {self.path} and start "
                           "the runner again")
        try:
            found = check_ignored_collisions(self.path, tip)
        except GitError as exc:
            raise Stop(str(exc)) from exc
        paths = sorted({path for problem in found for path in problem["paths"]})
        if found:
            count = sum(problem["count"] for problem in found)
            raise Stop(f"{doing} would overwrite, delete or write into ignored paths in "
                       f"{self.path} ({count} paths, e.g. {printable(', '.join(paths[:3]))}); move them out of the way "
                       "and start the runner again; the runner never deletes them")

    def remote_urls(self):
        """Every URL configured for origin: what git may quote back, and so what is taken out of what it says."""
        return self.config_values("remote.origin.url") + self.config_values("remote.origin.pushurl")

    def fetch_tip(self, branch, tip):
        """Fetch exactly `tip` from origin, by its SHA, into the remote-tracking ref (as `git pull` would; never by name, so
        that origin moving on cannot change what lands). Nothing else is written: no tag, no FETCH_HEAD, no pruning."""
        urls = self.remote_urls()
        done = git_change(self.path, "fetch", "--no-tags", "--no-recurse-submodules", "--no-auto-maintenance",
                          "--no-prune", "--no-write-fetch-head", "--atomic", "origin",
                          f"+{tip}:refs/remotes/origin/{branch}")
        if done.returncode != 0:
            raise Stop(f"cannot fetch origin's {branch} at {tip[:12]} into {self.path}: git fetch failed "
                       f"({done.returncode}): {redact(done.stderr.strip(), urls)[:300]}; {branch} was not changed")

    def forward(self, branch, local, tip):
        """Fast-forward the branch to exactly `tip`, the commit origin reported a moment ago: fetch that commit (by its
        SHA, into the remote-tracking ref, as `git pull` would; never by name, so that origin moving on cannot change
        what lands), check everything that can be checked before anything is written to the work tree, then
        `git merge --ff-only` that SHA. A failure leaves the branch where it was, and says so, or says what git changed."""
        self.forwarding = (branch, local, tip)  # from here on, an interrupt may have left something half way
        self.fetch_tip(branch, tip)
        relation = self.relation(local, tip)
        if relation is None:
            raise Stop(f"cannot read origin's {branch} at {tip[:12]} in {self.path} after fetching it; {branch} was "
                       "not changed")
        self.refuse_unless_behind(branch, local, tip, relation)
        self.check_forward(branch, local, tip)
        urls = self.remote_urls()
        done = git_change(self.path, "merge", "--ff-only", "--no-squash", "--no-overwrite-ignore", "--no-autostash",
                          "-q", tip)
        said = f"git merge --ff-only {tip[:12]} " + (f"failed ({done.returncode}): {redact(done.stderr.strip(), urls)[:300]}"
                                                     if done.returncode != 0 else "reported success but did not leave "
                                                     f"{branch} at {tip[:12]}, clean, with no git operation in progress")
        if done.returncode == 0 and self.landed(branch, tip):
            self.forwarded = (local, tip)
            self.say_forwarded(branch, local, tip)
            return
        raise Stop(f"{said}; {self.state_after(branch, local)}")

    def other_worktrees(self):
        """`(path, prunable, bare)` of every work tree of the repository but this one, from `git worktree list --porcelain`."""
        here, found, entry = os.path.realpath(self.path), [], None
        for line in git(self.path, "worktree", "list", "--porcelain").stdout.splitlines() + [""]:
            if line.startswith("worktree "):
                entry = [line[len("worktree "):], False, False]
            elif entry and line.startswith("prunable"):
                entry[1] = True
            elif entry and line == "bare":
                entry[2] = True
            elif not line and entry:
                if os.path.realpath(entry[0]) != here:
                    found.append(tuple(entry))
                entry = None
        return found

    def check_worktrees(self, other, branch):
        """The default branch is not checked out in another work tree (also one that is prunable), and no other work tree is
        in the middle of a git operation (a rebase holds its branch without showing it): `git fetch .` refuses the one, and
        the other is not something the runner may move a branch under."""
        try:
            held = check_checked_out_elsewhere(self.path, branch)
        except GitError as exc:
            raise Stop(str(exc)) from exc
        if held:
            raise Stop(f"checkout {self.path} is on {printable(other)}, and {branch}, the default branch of origin, is "
                       f"checked out in another work tree ({printable(held[0]['paths'][0])}); the runner does not switch to "
                       "it: start the runner in that work tree, or check out another branch there, and start the runner "
                       "again")
        for where, prunable, bare in self.other_worktrees():
            if prunable or bare:
                continue
            try:
                busy = check_in_progress(Path(where))
            except GitError as exc:
                raise Stop(str(exc)) from exc
            if busy:
                raise Stop(f"checkout {self.path} is on {printable(other)}, and the work tree {printable(where)} has a git "
                           f"operation in progress ({', '.join(busy[0]['paths'])}); the runner does not move or switch to "
                           f"{branch} while it may hold it: finish or abort it and start the runner again")

    @staticmethod
    def way_back(path, other):
        """The command that puts the checkout back on the branch it was on."""
        return f"git -C {shlex.quote(str(path))} switch {shlex.quote(printable(other))}"

    def switch_to_default(self, branch, tip, ref, sha):
        """The checkout is clean and on another branch `other` (at `sha`): put it on origin's default branch `branch`, at
        `tip`. Everything that can refuse is read before the first write: `branch` exists locally and is not held by another
        work tree, it is at the tip or strictly behind it, the tip has the helpers, moves no submodule and writes into no
        ignored path. Then (a real run) the tip is fetched, `branch` is moved to it by a local, unforced `git fetch .` (git
        itself checks the fast-forward and refuses a branch another work tree holds), and `git switch` makes the one tree
        update. `other` and its commits are never touched, and the checkout is not switched back at the end."""
        other, label = ref.removeprefix("refs/heads/"), printable(ref.removeprefix("refs/heads/"))
        if sha is None:
            raise Stop(f"checkout {self.path} is on {label}, which has no commit; check out {branch}, the default branch "
                       "of origin")
        local = git(self.path, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}",
                    ok=(0, 1)).stdout.strip()
        if not local:
            raise Stop(f"checkout {self.path} is on {label}, and it has no local {branch}, the default branch of origin; "
                       "the runner switches only to an existing local branch: create it at origin's tip yourself and "
                       "start the runner again")
        self.check_worktrees(other, branch)
        relation = "equal" if local == tip else self.relation(local, tip)
        self.refuse_unless_behind(branch, local, tip, relation, f"; the checkout was left on {label}")
        if self.partial_clone():
            if relation == "equal":
                raise Stop(f"checkout {self.path} is on {label}; {self.path} is a partial clone, which the runner does not "
                           f"switch: check out {branch}, the default branch of origin, yourself and start the runner again")
            raise self.partial_refusal(branch, local, tip)
        doing = f"switching {self.path} to {branch} at {tip[:12]}"
        if self.dry_run:
            known = relation in ("equal", "behind")
            if known:
                self.check_forward(branch, sha, tip, doing)
            self.would_switch = (other, sha, branch)
            if relation != "equal":
                self.would_forward = (local, tip, known)
            return
        self.switching = (other, branch)  # from here on, an interrupt may have left something half way
        if relation != "equal":
            self.fetch_tip(branch, tip)
            relation = self.relation(local, tip)
            if relation is None:
                raise Stop(f"cannot read origin's {branch} at {tip[:12]} in {self.path} after fetching it; {branch} was "
                           "not changed")
            self.refuse_unless_behind(branch, local, tip, relation, f"; the checkout was left on {label}")
        self.check_forward(branch, sha, tip, doing)
        urls = self.remote_urls()
        if local != tip:
            done = git_change(self.path, "fetch", "--no-tags", "--no-recurse-submodules", "--no-auto-maintenance",
                              "--no-prune", "--no-write-fetch-head", "--atomic", ".", f"{tip}:refs/heads/{branch}")
            if done.returncode != 0:
                raise Stop(f"cannot move {branch} to {tip[:12]} in {self.path}: git fetch . failed ({done.returncode}): "
                           f"{redact(done.stderr.strip(), urls)[:300]}; {branch} was not changed; "
                           f"{self.state_on(ref, sha, other)}")
            if git(self.path, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}",
                   ok=(0, 1)).stdout.strip() != tip:
                raise Stop(f"git fetch . reported success but {branch} is not at {tip[:12]} in {self.path}; "
                           f"{self.state_on(ref, sha, other)}")
            self.forwarded = (local, tip)
            self.say_forwarded(branch, local, tip)
        done = git_change(self.path, "switch", "--no-guess", "--no-recurse-submodules", "--no-overwrite-ignore", "-q",
                          "--", branch)
        moved = f"; {branch} was fast-forwarded to {tip[:12]}" * (local != tip)
        if done.returncode != 0 or not self.landed_switch(branch, tip, other, sha):
            said = (f"failed ({done.returncode}): {redact(done.stderr.strip(), urls)[:300]}" if done.returncode != 0 else
                    f"reported success but did not leave the checkout on {branch} at {tip[:12]}, clean, with no git "
                    "operation in progress")
            raise Stop(f"git switch to {branch} {said}; {self.state_on(ref, sha, other, moved)}")
        self.switched = (other, sha)
        self.say_switched(self.path, other, sha, branch)

    def landed_switch(self, branch, tip, other, sha):
        """The checkout is on the default branch at the tip, clean, with no git operation in progress, and the branch it
        left is where it was."""
        if not self.landed(branch, tip):
            return False
        return git(self.path, "rev-parse", "--verify", "--quiet", f"refs/heads/{other}^{{commit}}",
                   ok=(0, 1)).stdout.strip() == sha

    def state_on(self, ref, sha, other, moved=""):
        """Where a failed switch left the checkout, from git itself: still on `other` at `sha` and clean (what a refusal
        before the tree update leaves), or somewhere else."""
        now_ref, now_sha = self.current()
        try:
            dirty = bool(check_dirty(self.path))
        except GitError:
            dirty = True
        if (now_ref, now_sha) == (ref, sha) and not dirty:
            return f"the checkout is still on {printable(other)} at {sha[:12]} and clean{moved}"
        now = "a detached HEAD" if now_ref is None else printable(now_ref.removeprefix("refs/heads/"))
        return (f"the checkout is now on {now} at {(now_sha or '')[:12]}{' with uncommitted changes' if dirty else ''}: "
                "inspect it before starting the runner again")

    def landed(self, branch, tip):
        """The checkout is on the branch at the tip, clean, with no git operation in progress."""
        try:
            self.check_operation()
            self.check_clean()
        except Stop:
            return False
        return self.current() == (f"refs/heads/{branch}", tip)

    def state_after(self, branch, local):
        """Where a merge that did not land left the checkout, from git itself."""
        ref, sha = self.current()
        try:
            dirty = bool(check_dirty(self.path))
        except GitError:
            dirty = True
        if ref == f"refs/heads/{branch}" and sha == local and not dirty:
            return f"{branch} is still at {local[:12]} and clean"
        now = "a detached HEAD" if ref is None else ref.removeprefix("refs/heads/")
        return (f"the checkout is now on {now} at {(sha or '')[:12]}{' with uncommitted changes' if dirty else ''}: "
                "inspect it before starting the runner again")

    @staticmethod
    def say_forwarded(branch, local, tip):
        tell(f"Fast-forwarded {branch} from {local[:12]} to {tip[:12]}, origin's tip")

    @classmethod
    def say_switched(cls, path, other, sha, branch):
        tell(f"Switched {path} from {printable(other)} (at {sha[:12]}) to {branch}; to go back: {cls.way_back(path, other)}")

    def ignores(self, probe):
        return git(self.path, "check-ignore", "-q", "--", probe, ok=(0, 1)).returncode == 0

    def ignore_task_files(self):
        """The task and evidence directories must not count as uncommitted work: append them to the git exclude file
        when git does not ignore them yet (\"missing\" is judged by git, so an unanchored line of the operator's own
        counts), then ask git again, since a tracked .gitignore overrides the exclude file. Never removes a line."""
        # `git check-ignore -q` with several paths succeeds when ANY is ignored: ask for each path itself.
        probes = ((".pr-ready/probe", "/.pr-ready/"), (f"{TASK_DIR}/{'0' * 32}/task.json", f"/{TASK_DIR}/"))
        self.exclude = self.git_path("info/exclude")
        self.would_add = [line for probe, line in probes if not self.ignores(probe)]
        if self.dry_run or not self.would_add:
            return
        self.exclude.parent.mkdir(parents=True, exist_ok=True)
        existing = self.exclude.read_bytes() if self.exclude.exists() else b""
        with self.exclude.open("a", encoding="utf-8") as stream:
            stream.write("\n" * bool(existing and not existing.endswith(b"\n")) + "".join(f"{line}\n" for line in self.would_add))
        tell(f"Added {', '.join(self.would_add)} to {self.exclude}")
        if not all(self.ignores(probe) for probe, _ in probes):
            raise Stop(f"{self.path} does not ignore {TASK_DIR}/ and .pr-ready/ even after they were added to "
                       f"{self.exclude}: a tracked .gitignore overrides it, so the task files would count as "
                       "uncommitted work")
        self.would_add = []

    def announce(self):
        branch = self.branch.removeprefix("refs/heads/")
        tell(f"Checkout: {self.path} ({printable(branch)} at {self.head[:12]})")
        if self.dry_run:
            unchecked = ""
            if self.would_forward:
                local, tip, known = self.would_forward
                target = self.would_switch[2] if self.would_switch else branch
                tell(f"would fetch origin's {target} at {tip[:12]} and fast-forward {target} from {local[:12]} to it")
                if not known:
                    unchecked = (f"; whether origin's {target} at {tip[:12]} is a fast-forward of {target}, has the two "
                                 f"helpers{', moves no submodule' * bool(self.would_switch)} and leaves ignored files "
                                 f"alone, because {tip[:12]} is not in the checkout and a dry run does not fetch it")
            if self.would_switch:
                other, sha, target = self.would_switch
                tell(f"would switch {self.path} from {printable(other)} (at {sha[:12]}) to {target}")
            if self.would_add:
                tell(f"would add {', '.join(self.would_add)} to {self.exclude}")
            tell(f"would start the agents in tmux session {self.session}")
            tell(f"not checked in a dry run: whether another runner holds {self.lock_path}; whether an agent pane "
                 f"kept from an earlier run is still open in {self.path}{unchecked}")
        else:
            tell(f"Agents run as windows of tmux session {self.session}; watch them read-only with: "
                 f"tmux attach -r -t {self.session}")

    def verify(self):
        """Before every dispatch: back on the branch and commit the run started on (the default branch at the tip after the
        startup fast-forward or switch, when there was one), clean, no git operation in progress. The tip of origin is
        not read again, the checkout is not fast-forwarded again and not switched back: origin moves while a batch runs,
        and a skill that leaves another branch stops the run."""
        suffix = "; nothing was dispatched"
        self.check_operation(suffix)
        ref, sha = self.current()
        if ref != self.branch or sha != self.head:
            now = "detached" if ref is None else ref.removeprefix("refs/heads/")
            raise Stop(f"checkout {self.path} is no longer on {self.branch.removeprefix('refs/heads/')} at "
                       f"{self.head[:12]} (now {now} at {(sha or '')[:12]}): a skill did not restore it or something "
                       f"else changed it{suffix}")
        self.check_clean(suffix)

    def task(self, repo, number, phase, head):
        nonce = uuid.uuid4().hex
        base = self.path / TASK_DIR
        base.mkdir(mode=0o700, exist_ok=True)
        directory = base / nonce
        directory.mkdir(mode=0o700)
        task = dict(version=1, repo=f"{repo.owner}/{repo.name}", pr=number, phase=phase,
                    nonce=nonce, start_head=head)
        path = directory / "task.json"
        with path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(task))
        return path, task

    def finish(self):
        """The run is over: say what it left where. It deletes nothing; the lock goes with the process."""
        branch = self.branch.removeprefix("refs/heads/")
        changed = f"Nothing in {self.path} was deleted or reset."
        if self.switched:
            other, sha = self.switched
            moved = f" and fast-forwarded {branch} from {self.forwarded[0][:12]} to {self.forwarded[1][:12]}" \
                if self.forwarded else ""
            changed = (f"The runner switched {self.path} from {printable(other)} (at {sha[:12]}) to {branch}{moved} at the "
                       f"start; to go back: {self.way_back(self.path, other)}; nothing else in it was deleted or reset.")
        elif self.forwarded:
            changed = (f"The runner changed {self.path} only by fast-forwarding {branch} from "
                       f"{self.forwarded[0][:12]} to {self.forwarded[1][:12]} at the start; nothing else in it was deleted "
                       "or reset.")
        tell(f"Kept: the task files under {self.path / TASK_DIR} and any agent window still open in tmux session "
             f"{self.session}; close the agents still running in {self.path} before the next run. {changed}")


PROMPT = re.compile(r"^(?:[›❯](?:\s.*)?|>)$")
CHOICE = re.compile(r"^[›❯>]\s*\d+[.)]\s")
BUSY = re.compile(r"(?:esc|ctrl\+c) to interrupt(?:\))?$", re.IGNORECASE)
# `--clean` is stricter than BUSY, which wants the words at the end of a line: they are busy wherever they stand.
INTERRUPT = re.compile(r"to interrupt", re.IGNORECASE)
SHELLS = {"bash", "sh", "zsh", "fish", "dash", "ksh", "nu"}
SCREEN_LINES = 16


def screen_state(screen, *, strict=False):
    """What the last SCREEN_LINES non-blank lines of an agent's screen say: `working` (they end in `esc to interrupt`; with
    `strict`, they say `to interrupt` anywhere), `asking` (a numbered choice), `prompt` (the input prompt is among the
    last six) or `unknown`. The one place that reads a screen: `wait_for_prompt` waits for `prompt`, `--clean` also
    reads the other three."""
    recent = [line.strip() for line in screen.splitlines() if line.strip()][-SCREEN_LINES:]
    if any(BUSY.search(line) or (strict and INTERRUPT.search(line)) for line in recent):
        return "working"
    if any(CHOICE.match(line) for line in recent):
        return "asking"
    return "prompt" if any(PROMPT.fullmatch(line) for line in recent[-6:]) else "unknown"


def probe_pane(pane, server):
    """`(state, fields)` of the pane `pane` of the tmux server `server` (PID and start time): the one place that reads a
    pane in ONE `display-message` that also prints the identity of the tmux server answering. A pane ID is only unique
    within one tmux server, and a server exits with its last session: a later server can give the same ID to another
    pane (the replacement of an agent, or yours). `state` is `ours` (`fields` are the pane's dead and in-mode flags and its
    foreground command), `other server` (the server answering is not `server`), `gone` (that server has no such pane) or
    `no server`. Output that cannot be read, or any other failure of tmux, is a Stop. The commands that follow act on
    the pane by its ID: the milliseconds between this read and them are not covered."""
    done = run(["tmux", "display-message", "-p", "-t", pane, READ_FORMAT])
    if done.returncode != 0:
        if no_tmux_server(done.stderr):
            return "no server", None
        raise Stop(f"tmux display-message failed ({done.returncode}): {done.stderr.strip()[:500]}")
    parts = done.stdout.strip().split("|")
    if len(parts) != 5 or not (parts[3].isdigit() and parts[4].isdigit()):
        raise Stop(f"tmux could not read pane {pane}")
    if tuple(parts[3:]) != tuple(server):
        return "other server", None
    if parts[:3] == ["", "", ""]:
        return "gone", None  # tmux answers a pane it does not have with empty fields and exit status 0
    if parts[0] not in ("0", "1") or parts[1] not in ("0", "1"):
        raise Stop(f"tmux could not read pane {pane}")
    return "ours", (parts[0] == "1", parts[1] == "1", parts[2].lstrip("-"))


def close_pane(pane, server):
    """Close `pane`, and only the pane (`kill-pane` on its ID; never its window or its session, so that a pane you split off
    in the window survives), and only after `probe_pane` found it is still a pane of `server`. Returns `ours` when it was
    closed, which is what a pane that vanished meanwhile counts as, else why it was not: `gone` (already closed), `no
    server` (the server is gone, which closes everything) or `other server` (a server that did not make this pane: the ID
    may belong to another pane, and `kill-pane` is not sent). Any other failure is a Stop. The check and the `kill-pane`
    are two commands: what happens between them is not covered."""
    state = probe_pane(pane, server)[0]
    if state != "ours":
        return state
    done = run(["tmux", "kill-pane", "-t", pane])
    if done.returncode != 0 and (done.returncode, done.stderr.strip()) != (1, f"can't find pane: {pane}") and \
       not (done.returncode == 1 and no_tmux_server(done.stderr)):
        raise Stop(f"tmux kill-pane failed ({done.returncode}): {done.stderr.strip()[:500]}")
    return state


class Agent:
    def __init__(self, executable, checkout, number, phase):
        path = shutil.which(executable)
        if not path:
            raise Stop(f"agent executable not found: {executable}")
        self.session, self.window = checkout.session, f"{number}-{phase}"
        made = re.fullmatch(r"(%\d+)\|(\d+)\|(\d+)",
                            self.start(checkout.path, "exec " + shlex.quote(os.path.abspath(path))))
        if not made:
            raise Stop("tmux did not return a pane ID")
        # The pane, and the tmux server that made it: a pane ID means this pane only on that server.
        self.pane, self.server = made[1], (made[2], made[3])
        tell(f"PR #{number} {phase} agent: {self.pane} in window {self.window} of tmux session {self.session}")
        command("tmux", "set-option", "-w", "-t", self.pane, "remain-on-exit", "on")

    def start(self, directory, shell_command):
        """The pane of the new agent: the first one creates the runner's session, every later one adds a window to it.
        Somebody else may create the session between the two calls, or kill it (the operator may; tmux then makes it
        again): each answer is compared exactly, a `duplicate session` turns into a new window, a missing session into
        a new session, and anything else is a Stop. Every target is exact (`=S:`): an inexact `S:` falls back to a
        session whose name merely starts with S."""
        where, environment = ["-c", str(directory), "-P", "-F", PANE_FORMAT], None
        for _ in range(CREATE_ROUNDS):
            done = run(["tmux", "new-session", "-d", "-s", self.session, "-n", self.window, *where, "--", shell_command])
            if done.returncode == 0:
                return done.stdout.strip()
            if (done.returncode, done.stderr.strip()) != (1, f"duplicate session: {self.session}"):
                raise Stop(f"tmux new-session failed ({done.returncode}): {done.stderr.strip()[:500]}")
            environment = self.environment() if environment is None else environment
            done = run(["tmux", "new-window", "-d", "-t", f"={self.session}:", "-n", self.window, *where,
                        *environment, "--", shell_command])
            if done.returncode == 0:
                return done.stdout.strip()
            if (done.returncode, done.stderr.strip()) != (1, f"can't find session: {self.session}"):
                raise Stop(f"tmux new-window failed ({done.returncode}): {done.stderr.strip()[:500]}")
        raise Stop(f"tmux session {self.session} kept appearing and disappearing while an agent was started; "
                   "nothing was dispatched")

    @staticmethod
    def environment():
        """What a new window of an existing session must be given: a window takes the SESSION's value of each name in
        tmux's `update-environment` list (an earlier run's, or the last client's: the operator signs commits through
        SSH_AUTH_SOCK), a new session takes the runner's. `-e NAME=VALUE` for each variable the runner has itself that
        the list names, so that every agent sees the runner's environment; a name the runner does not have is not passed.
        An entry of the list is a glob pattern, as tmux matches it (`FOO_*` copies `FOO_X`; a plain name matches itself)."""
        entries = command("tmux", "show-options", "-gv", "update-environment").splitlines()
        names = {}
        for entry in entries:
            names.update((name, None) for name in sorted(os.environ) if fnmatch.fnmatchcase(name, entry))
        return [arg for name in names for arg in ("-e", f"{name}={os.environ[name]}")]

    def probe(self):
        """`(state, fields)` of this agent's pane, as `probe_pane` reads it against the tmux server that made it."""
        return probe_pane(self.pane, self.server)

    def status(self):
        """`(dead, in_mode, foreground command)` of the pane. A pane that is gone, or a tmux server that is not the one the
        agent was started on, is a Stop that names the pane: nothing is ever done to the pane that now has the ID."""
        state, fields = self.probe()
        if state != "ours":
            raise Stop(f"agent pane {self.pane} (window {self.window} of tmux session {self.session}) is not the pane "
                       "this agent was started in: the tmux server it was started on or the pane itself is gone or was "
                       "replaced; nothing was done to it")
        return fields

    def wait_for_prompt(self, timeout, *, allow_exit=False):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            dead, in_mode, process = self.status()
            if dead:
                if allow_exit:
                    return False
                raise Stop(f"agent exited during startup in {self.pane}")
            if process and process not in SHELLS and not in_mode:
                if screen_state(command("tmux", "capture-pane", "-p", "-J", "-t", self.pane)) == "prompt":
                    return True
            time.sleep(0.25)
        raise Stop(f"agent did not return to its input prompt in {self.pane}; inspect window {self.window} of tmux "
                   f"session {self.session}")

    def submit(self, text):
        self.status()  # still this pane, on the same tmux server, before anything is loaded or pasted
        buffer = "pilot-pr-" + uuid.uuid4().hex
        command("tmux", "load-buffer", "-b", buffer, "-", data=text)
        try:
            command("tmux", "paste-buffer", "-p", "-d", "-b", buffer, "-t", self.pane)
        except Stop:
            try:
                command("tmux", "delete-buffer", "-b", buffer)
            except Stop:
                pass
            raise
        time.sleep(0.25)
        dead, in_mode, foreground = self.status()
        if dead or in_mode or not foreground or foreground in SHELLS:
            raise Stop(f"pane {self.pane} changed while pasting; inspect before resuming")
        command("tmux", "send-keys", "-t", self.pane, "Enter")

    def close(self):
        """Close the agent's pane, and only its pane, and only when it is still this agent's pane on the tmux server that made
        it (`close_pane`). A pane that is already gone, a tmux server that is gone (you killed the session, and no other
        session kept the server alive) and a server that is not the one that made the pane are all closed, which is what this
        asks for, and `kill-pane` is not sent. Any other failure is a Stop."""
        close_pane(self.pane, self.server)


def check_result(path, task, head):
    result = path.with_name("result.json")
    if not result.exists():
        return
    with result.open("rb") as stream:
        data = stream.read(4097)
    if len(data) > 4096:
        raise Stop("skill result exceeded the size limit")
    report = json.loads(data)
    if not isinstance(report, dict) or any(report.get(key) != value for key, value in task.items()):
        raise Stop("skill result does not belong to this dispatch")
    judged, outcome, reason = report.get("head_sha"), report.get("outcome"), report.get("reason")
    if not isinstance(judged, str) or not SHA.fullmatch(judged) or \
       not isinstance(outcome, str) or outcome not in OUTCOMES[task["phase"]] or \
       not isinstance(reason, str) or (reason and not reason.isprintable()):
        raise Stop("invalid skill result")
    if judged.lower() == head and outcome not in ("READY", "DRAFT", "ENQUEUED", "MERGED"):
        kind = report.get("wait_kind")
        detail = f" ({kind})" if kind in ("person", "transient") else ""
        raise Stop(f"PR #{task['pr']} {outcome}{detail} at {head[:12]}: {reason}")


# ---- `--clean`: what a stopped or interrupted run left -----------------------------------------------------------------

# How long the screen of a pane must stay as it is before the pane counts as idle (seconds), and how much of it a listing
# shows. Module constants, not flags.
SETTLE = 1.0
SHOWN_LINES, SHOWN_WIDTH = 3, 120
TASK_FILES = ("task.json", "result.json")
READ_LIMIT = 4097  # a task or a result is at most 4096 bytes (pr_loop_result.py); one more byte tells that it is longer


class State(NamedTuple):
    """What a pane of the runner's is: `dead`, `idle` or `busy`, the reason, and the last read of its screen."""
    kind: str
    reason: str
    screen: str


class TaskDir(NamedTuple):
    """One directory of the task directory that holds an entry named like a nonce: what it says, how old it is, what the
    skill answered, why it must not be removed (None when it may be) and the names of what it holds."""
    nonce: str
    subject: str
    age: float
    result: str
    problem: str
    names: tuple


def header_line(top, session, socket):
    """The first line of the listing, with the tmux socket the panes were listed on (None when no server runs)."""
    return f"Residue of earlier runs in {top} (tmux session {session}" + (f" on {printable(socket)}" if socket else "") + "):"


def pane_line(pane, state, verdict, why, ends=""):
    """The line of a pane of the runner's: `verdict` is `would close`, `closed` or `left open`, `why` the reason, `ends` what
    closing it ends beyond the pane."""
    what = "dead" if state.kind == "dead" else f"alive, {state.kind} ({state.reason})"
    return (f"pane {pane.pane} window {printable(pane.window)}: {what}, {printable(pane.command) or '-'}; {verdict}: {why}"
            + (f"; closing it ends {ends}" if ends else ""))


def foreign_line(pane):
    """The line of a pane that is not provably the runner's and blocks the next run: it is left alone."""
    return (f"not the runner's: pane {pane.pane} (session {printable(pane.session)}, window {printable(pane.window)}) in "
            f"{printable(pane.path)}: left alone; the next run refuses because of it")


def task_line(task, verdict, why):
    """The line of a task directory: `verdict` is `would remove`, `removed` or `kept`."""
    return f"task {task.nonce}: {task.subject}, {age_text(task.age)} old, result {task.result}; {verdict}: {why}"


def summary_line(acting, closed, removed, refused):
    """The last line: what was (or would be) closed and removed, and whether the next run would start (`refused` says what
    would still stop it)."""
    done = f"closed {closed} panes and removed {removed} task directories" if acting else \
        f"would close {closed} panes and remove {removed} task directories"
    return f"{done}; " + (f"the next run would still be refused ({', '.join(refused)})" if refused else
                          "the next run would start")


def age_text(seconds):
    """`45s`, `12m`, `3h 20m` or `2d 4h`: how long ago something was."""
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    return f"{seconds // 86400}d {seconds % 86400 // 3600}h"


def excerpt(screen):
    """The last SHOWN_LINES non-blank lines of a screen, printable, each cut to SHOWN_WIDTH characters and shown after `  | `.
    They are whatever the agent displayed: they are not checked for anything but control characters."""
    lines = [line.strip() for line in screen.splitlines() if line.strip()][-SHOWN_LINES:]
    return [f"  | {printable(line)[:SHOWN_WIDTH]}" for line in lines]


def capture_pane(pane):
    """The screen of `pane` as text, or None when the pane (or the tmux server) is gone. Any other failure is a Stop."""
    done = run(["tmux", "capture-pane", "-p", "-J", "-t", pane])
    if done.returncode != 0:
        if no_tmux_server(done.stderr) or done.stderr.strip() == f"can't find pane: {pane}":
            return None
        raise Stop(f"tmux capture-pane failed ({done.returncode}): {done.stderr.strip()[:500]}")
    return done.stdout


def tmux_client():
    """`(pane, server PID or None)` of the pane this command runs in, from $TMUX_PANE and $TMUX (`socket,PID,index`), or None
    when it does not run in tmux."""
    pane, raw = os.environ.get("TMUX_PANE"), os.environ.get("TMUX")
    if not pane:
        return None
    parts = raw.rsplit(",", 2) if raw else []
    return pane, (parts[1] if len(parts) == 3 and re.fullmatch(r"[0-9]+", parts[1]) else None)


def ancestors():
    """The PIDs of this process and of every process above it, from /proc; None when /proc cannot be read (then nothing can be
    said about which process runs below which)."""
    found, pid = set(), os.getpid()
    while pid > 0 and pid not in found:
        found.add(pid)
        try:
            with open(f"/proc/{pid}/stat", "rb") as stream:
                pid = int(stream.read().rsplit(b")", 1)[1].split()[1])  # the field after the state: the parent
        except (OSError, IndexError, ValueError):
            return None
    return found


def lock_state(path):
    """None when nobody holds the checkout's lock `path`, else what the probe found. The probe is a shared, non-blocking
    `flock` on a read-only descriptor that does not create the file: a missing file is a lock nobody holds."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"cannot be probed ({exc.strerror or exc})"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return "cannot be probed (not a regular file)"
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError as exc:
        return "held by a running runner" if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN) else \
            f"cannot be probed ({exc.strerror or exc})"
    finally:
        os.close(fd)
    return None


def worktree_notes(top):
    """What in the checkout the next run refuses, as lines (read-only: nothing of the checkout is changed): uncommitted work
    or a git operation in progress. A state that cannot be read is said too."""
    try:
        busy, dirty = check_in_progress(top), check_dirty(top)
    except GitError as exc:
        return [f"the state of the checkout cannot be read ({printable(str(exc))}): left alone"]
    notes = []
    if busy:
        notes.append(f"a git operation is in progress in the checkout ({', '.join(busy[0]['paths'])}): left alone; the next "
                     "run refuses until you finish or abort it")
    if dirty:
        names = [re.sub(r"^[ MADRCUT?!]{2} ", "", entry) for entry in dirty[0]["paths"][:3]]
        notes.append(f"the checkout has uncommitted changes or untracked files ({dirty[0]['count']} paths, e.g. "
                     f"{printable(', '.join(names))}): left alone; the next run refuses until you commit or remove them")
    return notes


def read_small(dir_fd, name):
    """`(bytes, mtime)` of the regular file `name` of the directory `dir_fd`, at most READ_LIMIT bytes, never through a
    symlink. A file that is not there is a FileNotFoundError, anything else that is wrong an OSError."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        return os.read(fd, READ_LIMIT), info.st_mtime
    finally:
        os.close(fd)


def read_task_directory(fd, nonce):
    """The TaskDir of the directory `nonce`, opened as `fd` (read through descriptors: nothing here follows a symlink). `problem`
    is why it must not be removed, the first of: it is not the user's, `task.json` is missing, unreadable or another task's,
    it holds anything but `task.json` and `result.json`, one of those two is not a regular file."""
    info, problems = os.fstat(fd), []
    names = tuple(sorted(os.listdir(fd)))
    if info.st_uid != os.getuid():
        problems.append("it is not owned by this user")
    task, stamp, subject = None, info.st_mtime, ""
    try:
        data, stamp = read_small(fd, "task.json")
        task = json.loads(data) if len(data) < READ_LIMIT else None
        if not isinstance(task, dict) or task.get("nonce") != nonce or type(task.get("pr")) is not int or \
           task.get("phase") not in OUTCOMES:
            subject = "task.json is not this directory's task"
            problems.append("its task.json is not this directory's task")
        else:
            subject = f"PR #{task['pr']} {task['phase']}"
    except FileNotFoundError:
        subject = "no task.json"
        problems.append("it has no task.json")
    except (OSError, ValueError) as exc:
        subject = "task.json unreadable"
        problems.append(f"its task.json cannot be read ({getattr(exc, 'strerror', None) or exc})")
    result = "none"
    try:
        data, _ = read_small(fd, "result.json")
        report = json.loads(data) if len(data) < READ_LIMIT else None
        outcome = report.get("outcome") if isinstance(report, dict) else None
        result = outcome if isinstance(task, dict) and outcome in OUTCOMES.get(task.get("phase"), ()) else "unreadable"
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        result = "unreadable"
    others = [name for name in names if name not in TASK_FILES]
    if others:
        problems.append(f"it holds other files ({printable(', '.join(others[:3]))})")
    problems += [f"{name} is not a regular file" for name in names
                 if name in TASK_FILES and not stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode)]
    return TaskDir(nonce, subject, time.time() - stamp, result, problems[0] if problems else None, names)


def remove_task_directory(base_fd, nonce):
    """Remove the directory `nonce` of the task directory `base_fd` and what it holds, which is only `task.json` and
    `result.json`: each is unlinked through the descriptor of the directory and the empty directory is removed, never a
    tree. It is read again first. This is the ONE place that deletes anything (tests/test_pr_loop.py::ImportsTests). Returns
    None when it was removed, else why it was not."""
    try:
        fd = os.open(nonce, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base_fd)
    except OSError as exc:
        return f"it cannot be opened as a directory ({exc.strerror or exc})"
    try:
        found = read_task_directory(fd, nonce)
        if found.problem:
            return found.problem
        for name in reversed(TASK_FILES):  # the result first: an interrupted removal leaves a directory that is still a task
            if name in found.names:
                os.unlink(name, dir_fd=fd)
    except OSError as exc:
        return f"it could not be removed ({exc.strerror or exc})"
    finally:
        os.close(fd)
    try:
        os.rmdir(nonce, dir_fd=base_fd)
    except OSError as exc:
        return f"its files were removed but the directory could not be ({exc.strerror or exc})"
    return None


class Clean:
    """`--clean`: what earlier runs left in the checkout, listed, and with `--yes` closed and removed as far as it is provably
    the runner's own. The checkout is resolved and its lock found (`git rev-parse --git-path`) and that is all this reads of
    git, apart from the state it reports; it never builds a `Checkout`, which would refuse on the very panes this is for and
    could fast-forward or switch the checkout. Without `yes` it changes nothing (tmux is asked `list-panes` and
    `capture-pane` only, GitHub not at all) and every line says what the same command with `--yes` would do; with it the
    checkout's lock is held for the whole run, so that no runner starts or runs meanwhile."""

    def __init__(self, repo, args):
        self.args, self.acting = args, bool(args.yes)
        self.top = resolve_checkout(repo, args.checkout)
        self.session = session_name(self.top)
        self.lock_path = git_path(self.top, LOCK_NAME)
        self.held, self.worktree = None, []  # what `notes` found: the lock's state, and what is in the checkout's way
        self.above, self.above_us = False, None  # whether `ancestors` has been read, and what it said

    def run(self):
        """The whole command: the lock first when acting, then the report."""
        if not self.acting:
            return self.report()
        fd = lock_checkout(self.top, self.lock_path)
        try:
            return self.report()
        finally:
            os.close(fd)

    def report(self):
        """Read the tmux server and the task directory, say what is there, do what `--yes` asks, and say what is left."""
        panes, said = list_panes()
        tell(header_line(self.top, self.session, panes[0].socket if panes else None))
        if said:
            tell(printable(said))
        for note in self.notes():
            tell(note)
        ours = [pane for pane in distinct(panes, self.session) if runners_own(pane, self.top, self.session)]
        states = self.read_states(ours)
        closed = self.close_panes(ours, states, panes)
        listed = {pane.pane for pane in ours}
        for pane in blocking_panes(self.top, panes):
            if pane.pane not in listed:
                tell(foreign_line(pane))
        keeping, blocking = self.left(ours, closed, panes)
        removed = self.task_directories(keeping)
        tell(summary_line(self.acting, len(closed), removed, self.refused(blocking)))
        return 0

    def notes(self):
        """The lines about the checkout's lock (a preview only: an acting run holds it) and about its state."""
        self.held = None if self.acting else lock_state(self.lock_path)
        self.worktree = worktree_notes(self.top)
        return ([f"lock {self.lock_path}: {self.held}; --clean --yes would be refused"] if self.held else []) + self.worktree

    # ---- the panes -----------------------------------------------------------------------------------------------
    @staticmethod
    def look(pane, screen):
        """The State of an alive pane from ONE read of its screen (None: it could not be read): busy with the reason, or None
        when it may be idle, which takes a second read."""
        text = screen or ""
        if pane.in_mode:
            return State("busy", "copy-mode", text)
        if not pane.command or pane.command.lstrip("-") in SHELLS:
            return State("busy", "unknown: no agent in the foreground", text)
        if screen is None:
            return State("busy", "unknown: its screen could not be read", text)
        seen = screen_state(screen, strict=True)
        if seen == "unknown":
            return State("busy", "unknown: no input prompt on the screen", text)
        return None if seen == "prompt" else State("busy", seen, text)

    def read_states(self, ours):
        """`{pane ID: State}` of the panes of the runner's. A dead pane is dead. An alive one is read; one that is at its
        prompt is read again SETTLE seconds after the last first read, and is idle only when the second read is the first:
        an agent that is working changes its screen (a spinner, an elapsed time)."""
        states, first = {}, {}
        for pane in ours:
            if pane.dead:
                states[pane.pane] = State("dead", "", capture_pane(pane.pane) or "")  # what it showed last, for the listing
                continue
            first[pane.pane] = capture_pane(pane.pane)
            states[pane.pane] = self.look(pane, first[pane.pane])
        maybe = [pane for pane in ours if states[pane.pane] is None]
        if maybe:
            time.sleep(max(0.0, SETTLE))
        for pane in maybe:
            again = capture_pane(pane.pane)
            states[pane.pane] = State("idle", "at its prompt", again) if again == first[pane.pane] else \
                State("busy", "the screen is still changing", again or "")
        return states

    def holds_the_command(self, pane):
        """Why this command must not close `pane`, or None: it runs in it (its $TMUX_PANE, on the same tmux server), one of its
        processes is above this one, or that cannot be told (an alive pane whose process is unknown, /proc unreadable)."""
        mine = tmux_client()
        if mine and mine[0] == pane.pane and mine[1] in (None, pane.server[0]):
            return "the command runs in this pane"
        if pane.dead:
            return None
        if not pane.pid:
            return "its process is unknown, so it cannot be told whether the command runs in it"
        if not self.above:
            self.above, self.above_us = True, ancestors()
        if self.above_us is None:
            return "/proc cannot be read, so it cannot be told whether the command runs in it"
        return "the command runs below this pane's process" if int(pane.pid) in self.above_us else None

    def plan(self, pane, state):
        """`(close, why)`: whether the pane is to be closed, and the reason either way."""
        refusal = self.holds_the_command(pane)
        if refusal:
            return False, refusal
        if state.kind == "dead":
            return True, "it is dead"
        if state.kind == "idle":
            return True, "it is idle"
        if self.args.include_busy:
            return True, "it is busy, and --include-busy was given"
        return False, "it is busy; busy panes are closed only with --include-busy"

    def ends(self, pane, panes):
        """What closing `pane` ends beyond the pane, in words: its window when it is the window's last pane, then its session
        when it is the session's last, and the sessions grouped with it, which go with it. Empty when it ends only the pane."""
        if [other for other in distinct(panes, self.session) if other.window_id == pane.window_id and other.pane != pane.pane]:
            return ""
        what = f"window {printable(pane.window)}"
        if [other for other in panes if other.session == pane.session and other.pane != pane.pane]:
            return what
        grouped = sorted({other.session for other in panes if other.pane == pane.pane} - {pane.session})
        sessions = f"session {printable(pane.session)}" + \
            (f" and the sessions grouped with it ({', '.join(map(printable, grouped))})" if grouped else "")
        return f"{what} and {sessions}; an attached client is detached"

    def close_panes(self, ours, states, panes):
        """Say what is to be done with each pane of the runner's and, when acting, do it, one pane at a time. The IDs of the
        panes that are (would be) closed."""
        closed = []
        for pane in ours:
            state = states[pane.pane]
            closing, why = self.plan(pane, state)
            ends = ""
            if not closing:
                verdict = "left open"
            elif self.acting:
                verdict, why, ends, state = self.close(pane, state)
            else:
                verdict, ends = "would close", self.ends(pane, panes)
            if verdict in ("closed", "would close"):
                closed.append(pane.pane)
            tell(pane_line(pane, state, verdict, why, ends))
            for line in excerpt(state.screen):
                tell(line)
        return closed

    def close(self, listed, state):
        """Close the pane `listed`, after checking it again right before: the same tmux server, still a pane of the runner's
        with what it was listed with (not renamed, not started again: its process is the same, and a dead pane has not come
        alive), not the pane the command runs in, and read again: it must still be dead, or idle, or busy with
        `--include-busy`. `(verdict, why, what closing it ended, the State)`: `closed` or `left open`."""
        panes, said = list_panes()
        if said:
            return "closed", "it was already gone: no tmux server runs any more", "", state
        if panes and panes[0].server != listed.server:
            return "left open", "another tmux server answers now, and the pane ID may belong to another pane", "", state
        now = next((pane for pane in distinct(panes, self.session) if pane.pane == listed.pane), None)
        if now is None:
            return "closed", "it was already gone", "", state
        same = (now.session, now.window_id, now.window, now.start_path, now.start_command) == \
            (listed.session, listed.window_id, listed.window, listed.start_path, listed.start_command)
        if not same or not runners_own(now, self.top, self.session):
            return "left open", "it is not the pane that was listed any more", "", state
        if listed.dead and not now.dead:
            return "left open", "it was dead when it was listed and runs again", "", state
        if not listed.dead and not now.dead and now.pid != listed.pid:
            return "left open", "it was started again since it was listed", "", state
        if now.dead:
            state = State("dead", "", state.screen)
        else:
            screen = capture_pane(now.pane)
            gone = probe_pane(now.pane, listed.server)[0] if screen is None else "ours"
            if gone != "ours":
                return self.outcome(gone, "", "", state)  # it went while it was being read
            # Idle again only if it was idle when listed and has not changed since: a pane that was not at rest then is not
            # shown to be at rest by a second read that may follow the first at once (and is not reported as idle).
            state = self.look(now, screen) or (State("idle", "at its prompt", screen)
                                               if state.kind == "idle" and screen == state.screen else
                                               State("busy", "the screen is still changing", screen or ""))
        closing, why = self.plan(now, state)
        if not closing:
            return "left open", why, "", state
        return self.outcome(close_pane(now.pane, listed.server), why, self.ends(now, panes), state)

    @staticmethod
    def outcome(done, why, ends, state):
        """`(verdict, why, ends, state)` for what `close_pane` answered: `ours` is closed, a pane or a server that is gone counts as
        closed, and a server that is another one leaves the pane open."""
        if done == "other server":
            return "left open", "another tmux server answers now, and the pane ID may belong to another pane", "", state
        return "closed", why if done == "ours" else "it was already gone", ends, state

    def left(self, ours, closed, panes):
        """`(keeping, blocking)`: the IDs of the panes that are still there once the panes to be closed are, in the order of their
        IDs. `keeping` are those that must keep a task directory in place, an agent that may still write there: live panes of the
        runner's, and panes in its way. `blocking` are the panes in the way of the next run. (When acting the server is read again:
        this is what is there now.)"""
        if self.acting:
            panes = list_panes()[0]
            ours = [pane for pane in distinct(panes, self.session) if runners_own(pane, self.top, self.session)]
            closed = []
        blocking = {pane.pane for pane in blocking_panes(self.top, panes) if pane.pane not in closed}
        alive = {pane.pane for pane in ours if not pane.dead and pane.pane not in closed}
        order = lambda found: sorted(found, key=lambda name: int(name[1:]))
        return order(alive | blocking), order(blocking)

    def refused(self, blocking):
        """What would still make the next run refuse: panes, uncommitted work, a git operation in progress."""
        return [*blocking, *("a git operation in progress" if note.startswith("a git operation") else
                         "uncommitted work" if note.startswith("the checkout has") else "the state of the checkout"
                         for note in self.worktree)]

    # ---- the task directories ------------------------------------------------------------------------------------
    def keep_reason(self, task, left):
        """Why the task directory must stay, or None when it may be removed (it is only removed with `--remove-task-dirs`)."""
        if task.problem:
            return task.problem
        if not self.args.remove_task_dirs:
            return "task directories are removed only with --remove-task-dirs"
        if self.held:
            return f"the checkout's lock is not free: {self.held}"
        if left:
            return f"a pane of the runner is left ({', '.join(left)}) and its agent may still write there"
        return None

    def task_directories(self, left):
        """List the task directories, oldest first, and when acting with `--remove-task-dirs` remove the ones that may be. How
        many are (would be) removed."""
        where = self.top / TASK_DIR
        try:
            base = os.open(where, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return 0
        except OSError as exc:
            tell(f"task directory {where}: {exc.strerror or exc}: left alone; nothing in it is listed or removed")
            return 0
        removed = 0
        try:
            found = []
            for nonce in sorted(name for name in os.listdir(base) if NONCE.fullmatch(name)):
                try:
                    fd = os.open(nonce, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base)
                except OSError as exc:
                    found.append(TaskDir(nonce, "not a directory", 0.0, "none", f"it is not a real directory "
                                         f"({exc.strerror or exc})", ()))
                    continue
                try:
                    found.append(read_task_directory(fd, nonce))
                finally:
                    os.close(fd)
            for task in sorted(found, key=lambda entry: (-entry.age, entry.nonce)):
                why = self.keep_reason(task, left)
                if why is None and self.acting:
                    why = remove_task_directory(base, task.nonce)
                verdict = "kept" if why else "removed" if self.acting else "would remove"
                removed += verdict != "kept"
                tell(task_line(task, verdict, why or "no pane of the runner is left and it holds only its task and result"))
        finally:
            os.close(base)
        return removed


class Batch:
    def __init__(self, repo, args):
        self.repo, self.args = repo, args
        self.checkout = None
        self.login = None
        # Agents the runner is done with (merged PRs, agents that exited and were replaced), still open: they are
        # closed once the next agent exists, or when the run ends, so the session lives from the first dispatch to the
        # end of the batch instead of being torn down and made again between two PRs.
        self.finished = []

    def account(self):
        """The login `gh` runs as: asked once per Batch, a login does not change while the runner works."""
        if self.login is None:
            self.login = viewer_login(self.repo)
        return self.login

    def run(self):
        if self.args.dry_run:
            return self.dry_run()
        # The checkout is inspected before the first PR is read and before an agent is started: a refusal costs nothing.
        self.checkout = Checkout(self.repo, self.args.checkout)
        self.checkout.announce()
        interrupted = False
        try:
            for number in self.args.pr:
                self.drive(number)
        except KeyboardInterrupt:
            interrupted = True  # main says what was kept
            raise
        finally:
            self.release_finished()
            if not interrupted:
                self.checkout.finish()

    def close_finished(self):
        """Close the agents the runner is done with, each one once, in the order they finished. A failure is a Stop;
        the agents after it stay in `finished` for `release_finished`."""
        while self.finished:
            self.finished.pop(0).close()

    def release_finished(self):
        """The end of the run, however it ends: close what is left of `finished`, best effort. A pane that cannot be
        closed is said and never raised: this runs in a `finally`, and must not hide the Stop or the interrupt."""
        while self.finished:
            agent = self.finished.pop(0)
            try:
                agent.close()
            except (Stop, OSError, subprocess.SubprocessError) as exc:
                tell(f"could not close the agent pane {agent.pane}: {exc}")

    def dry_run(self):
        """The PR phases, then the same inspection of the checkout the real run starts with, read-only: no lock, no
        tmux, nothing written. A refusal is reported after the phases, so that one run shows both."""
        refusal, checkout = None, None
        try:
            checkout = Checkout(self.repo, self.args.checkout, dry_run=True)
        except Stop as exc:
            refusal = exc
        for number in self.args.pr:
            self.drive(number)
        if refusal is not None:
            raise refusal
        checkout.announce()

    def drive(self, number):
        try:
            self.run_pr(number)
        except (Stop, GitHubError, OSError, ValueError, subprocess.SubprocessError) as exc:
            raise Stop(f"PR #{number}: {exc}") from exc

    def read(self, number):
        """One observation of the PR, `(view, phase, detail)`. A failed GitHub read is retried; a Stop (a PR that
        cannot be driven) is a verdict, never retried."""
        for attempt in range(1, READ_ATTEMPTS + 1):
            try:
                return observe(self.repo, number, self.account)
            except GitHubError as exc:
                if attempt == READ_ATTEMPTS:
                    raise Stop(f"GitHub read failed {READ_ATTEMPTS} consecutive times; no command sent: {exc}") from exc
                tell(f"PR #{number}: GitHub read failed ({attempt}/{READ_ATTEMPTS}): {exc}")
                time.sleep(self.args.poll_interval)

    def run_pr(self, number):
        agents = {}
        active = None
        current, task_path, task = None, None, None
        candidate, seen = None, 0
        actions, exited = 0, 0
        deadline = time.monotonic() + self.args.phase_timeout
        while True:
            view, phase, detail = self.read(number)
            if self.args.dry_run:
                tell(f"PR #{number}: {phase}" + (f" ({detail})" if phase == "unverified" else ""))
                return
            # What a timeout says about a PR that was Ready without a signal when it ran out (the signal's author may be
            # another account than this runner's: the reason is in `detail`).
            unsigned = f" (Ready without a valid {ready_signal.LABEL} signal: {detail})" if phase == "unverified" else ""
            if phase == "unverified" and current == "draft":
                # The Draft agent is still working: the gate marks the PR Ready BEFORE it verifies and signs it, and a
                # blocker it reports afterwards leaves the PR Ready without a signal. Keep reading the Draft phase,
                # so that the result it publishes (DRAFT-BLOCKED) is the one the run stops on.
                phase = "draft"
            if phase == current:
                candidate, seen = None, 0
                if active is not None and phase != "queued":
                    check_result(task_path, task, head_of(view))
                    dead, _, foreground = active[1].status()
                    exited = exited + 1 if dead or foreground in SHELLS else 0
                    if exited >= 2:
                        raise Stop(f"{phase} agent exited before GitHub confirmed a state change{unsigned}")
            else:
                seen = seen + 1 if phase == candidate else 1
                candidate = phase
            if phase != current and seen >= STABLE_POLLS:
                candidate, seen = None, 0
                if current == "queued" and phase in ("ready", "unverified"):
                    raise Stop("left the merge train while still Ready; inspect the PR conversation")
                if phase != "queued" and active is not None:
                    role, agent = active
                    tell(f"PR #{number}: waiting for the {role} agent in {agent.pane} to return to its prompt")
                    if not agent.wait_for_prompt(self.args.phase_timeout, allow_exit=True):
                        self.finished.append(agents.pop(role))
                    # The agent publishes its result before it returns to its prompt, and GitHub may already show
                    # the next phase (a gate can mark the PR Ready and then report a blocker): read the result
                    # against a fresh HEAD before another role starts or the PR is reported done.
                    check_result(task_path, task, head_of(self.read(number)[0]))
                    active = None
                if phase == "unverified":
                    raise Stop(f"PR #{number} is Ready without a valid {ready_signal.LABEL} signal at HEAD "
                               f"{head_of(view)[:12]}: {detail}; nothing is dispatched for it: convert it to Draft and "
                               "run pr-ready on it, then start the runner again")
                if phase == "merged":
                    self.finished.extend(agents.values())
                    tell(f"PR #{number}: merged")
                    return
                deadline = time.monotonic() + self.args.phase_timeout
                current = phase
                if phase == "queued":
                    tell(f"PR #{number}: waiting for merge train")
                else:
                    if actions >= self.args.max_actions:
                        raise Stop("maximum agent dispatches reached")
                    check_pr_url(view, self.repo)
                    self.checkout.verify()
                    agent, replaced = agents.get(phase), None
                    if agent is not None and agent.status()[0]:
                        agent, replaced = None, agent
                    if agent is None:
                        agent = Agent(getattr(self.args, phase + "_agent"), self.checkout, number, phase)
                        agents[phase] = agent
                        # The new agent comes first: closing the dead one (or a merged PR's) while it was the last window
                        # would end the session and detach whoever watches it.
                        if replaced is not None:
                            self.finished.append(replaced)
                        self.close_finished()
                    agent.wait_for_prompt(self.args.startup_timeout)
                    # An approval prompt at startup can take long enough for GitHub to change.
                    view, now, _ = self.read(number)
                    if now != phase:
                        raise Stop("GitHub state changed before dispatch; retry against the current PR")
                    task_path, task = self.checkout.task(self.repo, number, phase, head_of(view))
                    prompt = getattr(self.args, phase + "_command").replace("{pr}", str(number))
                    actions += 1
                    agent.submit(prompt + " --pr-loop-task=" + json.dumps(str(task_path), ensure_ascii=False))
                    active, exited = (phase, agent), 0
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Stop(f"timed out in {phase}{unsigned}")
            time.sleep(min(self.args.poll_interval, remaining))


def seconds(value):
    duration = float(value)
    if not math.isfinite(duration) or duration <= 0:
        raise argparse.ArgumentTypeError("expected positive seconds")
    return duration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pr", metavar="PR", type=int, nargs="*")
    parser.add_argument("--repo", default="kjelly/pilot", help="GitHub repository (default: kjelly/pilot)")
    parser.add_argument("--draft-agent", default="claude")
    parser.add_argument("--ready-agent", default="codex")
    parser.add_argument("--draft-command", default="/pr-ready {pr}")
    parser.add_argument("--ready-command", default="$pr-review-merge {pr}")
    parser.add_argument("--phase-timeout", type=seconds, default=PHASE_TIMEOUT,
                        help=f"seconds waiting per phase (default: {PHASE_TIMEOUT})")
    parser.add_argument("--startup-timeout", type=seconds, default=60, help="seconds waiting for a newly started agent's prompt (default: 60)")
    parser.add_argument("--poll-interval", type=seconds, default=10, help="seconds between GitHub reads (default: 10)")
    parser.add_argument("--max-actions", type=int, default=20, help="maximum dispatches per PR (default: 20)")
    parser.add_argument("--checkout", metavar="DIR",
                        help="the checkout the agents start in: the ROOT of a git work tree that is clean, on origin's "
                             "default branch at or strictly behind origin's tip (the runner fast-forwards it), or on a "
                             "branch of it (the runner switches to origin's default branch and fast-forwards it to "
                             f"origin's tip), whose origin is --repo (default: {CHECKOUT_DEFAULT})")
    parser.add_argument("--dry-run", action="store_true", help="show current PR states and whether the checkout would be "
                                                              "accepted, without starting agents or writing anything")
    parser.add_argument("--clean", action="store_true",
                        help="list what earlier runs left in the checkout: the agent panes that are provably this runner's "
                             "(dead, idle or busy), the task directories, and the panes that would stop the next run; it "
                             "changes nothing, reads no GitHub and takes no PR numbers")
    parser.add_argument("--yes", action="store_true",
                        help="with --clean: close the dead and idle panes of the runner's, one at a time (the checkout's "
                             "lock is held meanwhile)")
    parser.add_argument("--include-busy", action="store_true",
                        help="with --clean: close busy panes too; the agent's work in them is lost (needs --yes to act)")
    parser.add_argument("--remove-task-dirs", action="store_true",
                        help="with --clean: remove the task directories of finished runs, when no pane of the runner is left "
                             "(needs --yes to act)")
    args = parser.parse_args()
    if args.clean:
        if args.pr or args.dry_run:
            parser.error("--clean takes no PR numbers and no --dry-run: without --yes it only lists")
    else:
        if not args.pr:
            parser.error("the following arguments are required: PR")
        if args.yes or args.include_busy or args.remove_task_dirs:
            parser.error("--yes, --include-busy and --remove-task-dirs go with --clean")
        if any(n <= 0 for n in args.pr) or len(set(args.pr)) != len(args.pr) or args.max_actions <= 0:
            parser.error("PR numbers must be positive and unique, and --max-actions must be positive")
        if any(not template.strip() or not template.isprintable() for template in (args.draft_command, args.ready_command)):
            parser.error("agent commands must be nonempty single lines")
    os.environ.setdefault("GH_PROMPT_DISABLED", "1")
    batch = None
    try:
        if args.clean:
            return Clean(Repo.parse(args.repo), args).run()
        batch = Batch(Repo.parse(args.repo), args)
        batch.run()
        return 0
    except KeyboardInterrupt as exc:
        if isinstance(exc, ForwardInterrupted):
            print(exc.text, file=sys.stderr)
        elif batch and batch.checkout:
            back = ""
            if batch.checkout.switched:
                other, sha = batch.checkout.switched
                back = (f" The checkout was switched from {printable(other)} (at {sha[:12]}) to "
                        f"{batch.checkout.branch.removeprefix('refs/heads/')} at the start; to go back: "
                        f"{batch.checkout.way_back(batch.checkout.path, other)}.")
            print(f"Interrupted; any agent window still open in tmux session {batch.checkout.session} and the task "
                  f"files under {batch.checkout.path / TASK_DIR}/ were kept.{back}", file=sys.stderr)
        elif args.clean:
            print("Interrupted; the lines above say what was closed or removed so far.", file=sys.stderr)
        else:
            print("Interrupted; nothing was written.", file=sys.stderr)
        return 130
    except (Stop, GitHubError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"pr-loop: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
