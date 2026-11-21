#!/usr/bin/env python3
"""Run Pilot's Draft/Ready PR skills in order using managed tmux panes.

The agents start in YOUR checkout, not in a clone of their own: the root of the git work tree the runner is started
in, or the directory named by --checkout. Start the agents there once yourself, so that they already trust it: the
runner cannot answer a trust dialog. The checkout must be clean, on the default branch of origin, at origin's tip, and
its origin must be --repo, or the runner refuses before it reads GitHub. The runner never deletes, resets, cleans or
stashes anything in it; the task files it writes stay under the checkout's task directory (ignored by git), and the
agent windows it started stay open when it stops.

The agents run as windows (one per agent, named `<PR>-<phase>`) of ONE tmux session of the runner's own, never of one of
yours: `pilot-pr-<directory name>-<8 hex>`, where the directory name is the checkout's, cut down to letters, digits, `_`
and `-`, and the hex is a hash of its full path, so that the name is the same on every run in this checkout and differs
between checkouts. The first agent creates the session, every later one adds a window to it; the runner announces the
name once and you watch from another terminal, read-only, with `tmux attach -r -t <session>`. The runner closes only
the panes it started in this process, one pane at a time: it never kills, renames or reuses a window or a session it
did not create in this process (the dead windows of an earlier run stay where they are). The session ends with its
last window, and a client attached to it is detached then (tmux's default).

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
from urllib.parse import urlsplit


sys.dont_write_bytecode = True
SKILLS = Path(__file__).resolve().parents[1] / ".agents/skills"
sys.path[:0] = [str(SKILLS / skill / "scripts") for skill in ("pr-review-merge", "_shared")]
from checkout_preflight import HEX, GitError, check_dirty, check_in_progress
from gh_runtime import GitHubError, Repo, issue_comments, pr_view, timeline_events, viewer_login
from list_ready import QUEUE_LABEL
from needs_person import LABEL as PERSON_LABEL, latest_marker
from pr_loop_result import OUTCOMES, SHA, TASK_DIR
import ready_signal  # only LABEL, assess and SignalError: this runner reads the signal, it never writes one


# A phase must be read this many times in a row before the runner acts on it, and a failed GitHub read is
# retried up to READ_ATTEMPTS times in a row: one lagging or failing read must not dispatch an agent or stop
# the run. Module constants, not flags.
STABLE_POLLS = 2
READ_ATTEMPTS = 3

# What `--checkout` defaults to, in the words of its help text and of the README.
CHECKOUT_DEFAULT = "the root of the git work tree that contains the current directory"
LOCK_NAME = "pilot-pr-loop.lock"
PANE_SESSION_PREFIX = "pilot-pr-"
# The longest directory name kept in a session name, and how many times starting an agent follows a session that
# somebody else created or killed meanwhile before it gives up. Module constants, not flags.
SESSION_LABEL_MAX = 24
CREATE_ROUNDS = 3


class Stop(RuntimeError):
    pass


def tell(message):
    print(message, flush=True)


def run(args, *, cwd=None, data=None, env=None, timeout=120):
    """One subprocess, whatever it exits with; a command that outlives `timeout` is a Stop."""
    options = {"input": data} if data is not None else {"stdin": subprocess.DEVNULL}
    try:
        return subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False, **options)
    except subprocess.TimeoutExpired:
        raise Stop(f"{' '.join(args[:2])} timed out after {timeout} seconds") from None


def command(*args, cwd=None, data=None):
    proc = run(args, cwd=cwd, data=data)
    if proc.returncode != 0:
        raise Stop(f"{' '.join(args[:2])} failed ({proc.returncode}): {proc.stderr.strip()[:500]}")
    return proc.stdout


def git(cwd, *args, ok=(0,), env=None):
    """One READ-ONLY git call in `cwd`: no opportunistic index refresh, no credential prompt, one locale. A status
    outside `ok` is a Stop (`ok=None`: the caller judges the result). Every git call of this runner goes through
    here, and tests/test_pr_loop.py::ImportsTests lists the subcommands it may name."""
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


def session_name(path):
    """The tmux session of the runner in the checkout at `path` (absolute and resolved: `resolve_checkout`):
    `pilot-pr-<label>-<8 hex>`. The label is the directory name cut down to what tmux keeps as typed and can target
    (letters, digits, `_` and `-`: a `:` or a `.` in a name makes the session impossible to address, a tab is
    refused) and the hex is a hash of the whole path, so the name is stable per checkout and two checkouts with the
    same directory name under different parents do not share a session."""
    label = re.sub(r"[^A-Za-z0-9_-]+", "-", Path(path).name).strip("-")[:SESSION_LABEL_MAX].rstrip("-") or "checkout"
    return f"{PANE_SESSION_PREFIX}{label}-{hashlib.sha256(os.fsencode(str(path))).hexdigest()[:8]}"


_PANE = re.compile(r"(?P<session>.*)\|(?P<pane>%\d+)\|(?P<dead>[01])\|(?P<path>.*)")


def check_panes(top):
    """A pane an earlier run kept (`pilot-pr-*`, still alive) in the checkout is a second user of it: the lock died with
    that run, the pane did not. Panes of other sessions, dead panes and panes elsewhere are not the runner's business."""
    done = run(["tmux", "list-panes", "-a", "-F", "#{session_name}|#{pane_id}|#{pane_dead}|#{pane_current_path}"])
    if done.returncode != 0:
        if "no server running" in done.stderr or re.search(r"error connecting to .* \(No such file or directory\)",
                                                           done.stderr):
            return  # no tmux server, so no pane
        raise Stop(f"tmux list-panes failed ({done.returncode}): {done.stderr.strip()[:500]}")
    inside = os.path.realpath(top)
    for line in done.stdout.splitlines():
        found = _PANE.fullmatch(line)
        if not found:
            raise Stop("tmux list-panes returned a line that cannot be read")
        where = os.path.realpath(found["path"]) if found["path"] else None
        if found["dead"] == "0" and found["session"].startswith(PANE_SESSION_PREFIX) and where and \
           (where == inside or where.startswith(inside + os.sep)):
            raise Stop(f"agent pane {found['pane']} (session {found['session']}) is still running in {top}; "
                       "inspect and close it before starting the runner again")


def printable(text):
    return "".join(char if char.isprintable() else "?" for char in text)


class Checkout:
    """The operator's own checkout, inspected once at startup and verified again before every dispatch. Everything
    here READS it, except two things: the lock file in its git directory and, only when git does not ignore the task
    and evidence directories yet, two lines appended to its git exclude file. `dry_run` inspects without either (and
    without tmux); a refusal is a Stop."""

    def __init__(self, repo, directory=None, *, dry_run=False):
        self.repo, self.dry_run, self.lock_fd, self.would_add = repo, dry_run, None, []
        self.path = resolve_checkout(repo, directory)
        self.session = session_name(self.path)
        self.lock_path = self.git_path(LOCK_NAME)
        if not dry_run:
            self.lock_fd = lock_checkout(self.path, self.lock_path)
        try:
            self.inspect()
        except BaseException:
            self.release()  # a refusal does not keep the lock
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
        if ref != f"refs/heads/{branch}":
            if ref is None:
                raise Stop(f"checkout {self.path} has a detached HEAD at {(sha or '')[:12]}; check out {branch}, "
                           "the default branch of origin")
            raise Stop(f"checkout {self.path} is on {ref.removeprefix('refs/heads/')}, not on {branch}, the default "
                       "branch of origin")
        self.check_tip(branch, tip)
        self.branch, self.head = ref, sha
        # Both helpers are run from this checkout by the skills it hosts: a default branch that predates either
        # would leave the agent unable to report or to sign, and the run would wait for its phase timeout.
        for helper in ("pr_loop_result.py", "ready_signal.py"):
            where = f".agents/skills/_shared/scripts/{helper}"
            if git(self.path, "cat-file", "-e", f"HEAD:{where}", ok=(0, 128)).returncode != 0:
                raise Stop(f"origin's default branch {branch} at {tip[:12]} lacks {where}; "
                           "the skills it hosts could not report or sign")
        self.ignore_task_files()

    def git_path(self, name):
        raw = git(self.path, "rev-parse", "--git-path", name).stdout.strip()
        return Path(raw) if os.path.isabs(raw) else self.path / raw

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

    def check_tip(self, branch, tip):
        """The skills run from this checkout, so it must be origin's default branch AT origin's tip. Checked at
        startup only: the merge train moves origin during a batch, and that must not refuse the next PR."""
        local = git(self.path, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}",
                    ok=(0, 1)).stdout.strip()
        if local == tip:
            return
        quiet = {"GIT_NO_LAZY_FETCH": "1"}
        if local and git(self.path, "cat-file", "-e", tip, ok=(0, 1), env=quiet).returncode == 0 and \
           git(self.path, "merge-base", "--is-ancestor", tip, local, ok=(0, 1), env=quiet).returncode == 0:
            raise Stop(f"local {branch} at {local[:12]} has commits that origin's {branch} ({tip[:12]}) does not "
                       "have; the skills must come from origin's default branch")
        what = f"is at {local[:12]} but" if local else "has no commit but"
        raise Stop(f"local {branch} {what} origin's {branch} is at {tip[:12]}; run git pull --ff-only in "
                   f"{self.path} and start the runner again")

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
        tell(f"Checkout: {self.path} ({self.branch.removeprefix('refs/heads/')} at {self.head[:12]})")
        if self.dry_run:
            if self.would_add:
                tell(f"would add {', '.join(self.would_add)} to {self.exclude}")
            tell(f"would start the agents in tmux session {self.session}")
            tell(f"not checked in a dry run: whether another runner holds {self.lock_path}; whether an agent pane "
                 f"kept from an earlier run is still open in {self.path}")
        else:
            tell(f"Agents run as windows of tmux session {self.session}; watch them read-only with: "
                 f"tmux attach -r -t {self.session}")

    def verify(self):
        """Before every dispatch: back on the branch and commit the run started on, clean, no git operation in
        progress. The tip of origin is not read again: it moves while a batch runs."""
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
        tell(f"Kept: the task files under {self.path / TASK_DIR} and any agent window still open in tmux session "
             f"{self.session}; close the agents still running in {self.path} before the next run. Nothing in "
             f"{self.path} was deleted or reset.")


PROMPT = re.compile(r"^(?:[›❯](?:\s.*)?|>)$")
CHOICE = re.compile(r"^[›❯>]\s*\d+[.)]\s")
BUSY = re.compile(r"(?:esc|ctrl\+c) to interrupt(?:\))?$", re.IGNORECASE)
SHELLS = {"bash", "sh", "zsh", "fish", "dash", "ksh", "nu"}


class Agent:
    def __init__(self, executable, checkout, number, phase):
        path = shutil.which(executable)
        if not path:
            raise Stop(f"agent executable not found: {executable}")
        self.session, self.window = checkout.session, f"{number}-{phase}"
        self.pane = self.start(checkout.path, "exec " + shlex.quote(os.path.abspath(path)))
        if not re.fullmatch(r"%\d+", self.pane):
            raise Stop("tmux did not return a pane ID")
        tell(f"PR #{number} {phase} agent: {self.pane} in window {self.window} of tmux session {self.session}")
        command("tmux", "set-option", "-w", "-t", self.pane, "remain-on-exit", "on")

    def start(self, directory, shell_command):
        """The pane of the new agent: the first one creates the runner's session, every later one adds a window to it.
        Somebody else may create the session between the two calls, or kill it (the operator may; tmux then makes it
        again): each answer is compared exactly, a `duplicate session` turns into a new window, a missing session into
        a new session, and anything else is a Stop. Every target is exact (`=S:`): an inexact `S:` falls back to a
        session whose name merely starts with S."""
        where, environment = ["-c", str(directory), "-P", "-F", "#{pane_id}"], None
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
        SSH_AUTH_SOCK), a new session takes the runner's. `-e NAME=VALUE` for each such name the runner has itself, so
        that every agent sees the runner's environment; a name the runner does not have is not passed."""
        names = command("tmux", "show-options", "-gv", "update-environment").splitlines()
        return [arg for name in names if name in os.environ for arg in ("-e", f"{name}={os.environ[name]}")]

    def status(self):
        raw = command("tmux", "display-message", "-p", "-t", self.pane,
                      "#{pane_dead}|#{pane_in_mode}|#{pane_current_command}").strip()
        parts = raw.split("|")
        if len(parts) != 3 or parts[0] not in ("0", "1") or parts[1] not in ("0", "1"):
            raise Stop(f"tmux could not read pane {self.pane}")
        return parts[0] == "1", parts[1] == "1", parts[2].lstrip("-")

    def wait_for_prompt(self, timeout, *, allow_exit=False):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            dead, in_mode, process = self.status()
            if dead:
                if allow_exit:
                    return False
                raise Stop(f"agent exited during startup in {self.pane}")
            if process and process not in SHELLS and not in_mode:
                screen = command("tmux", "capture-pane", "-p", "-J", "-t", self.pane)
                recent = [line.strip() for line in screen.splitlines() if line.strip()][-16:]
                if not any(BUSY.search(line) or CHOICE.match(line) for line in recent) and \
                   any(PROMPT.fullmatch(line) for line in recent[-6:]):
                    return True
            time.sleep(0.25)
        raise Stop(f"agent did not return to its input prompt in {self.pane}; inspect window {self.window} of tmux "
                   f"session {self.session}")

    def submit(self, text):
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
        """Close the agent's pane, and only its pane (`kill-pane` on its ID; never its window or its session, so that a
        pane the operator split off in the window survives). A pane that is already gone (the operator closed it, or
        killed the session) is closed, which is what this asks for; any other failure is a Stop."""
        done = run(["tmux", "kill-pane", "-t", self.pane])
        if done.returncode != 0 and (done.returncode, done.stderr.strip()) != (1, f"can't find pane: {self.pane}"):
            raise Stop(f"tmux kill-pane failed ({done.returncode}): {done.stderr.strip()[:500]}")


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
    parser.add_argument("pr", metavar="PR", type=int, nargs="+")
    parser.add_argument("--repo", default="kjelly/pilot", help="GitHub repository (default: kjelly/pilot)")
    parser.add_argument("--draft-agent", default="claude")
    parser.add_argument("--ready-agent", default="codex")
    parser.add_argument("--draft-command", default="/pr-ready {pr}")
    parser.add_argument("--ready-command", default="$pr-review-merge {pr}")
    parser.add_argument("--phase-timeout", type=seconds, default=7200, help="seconds waiting per phase (default: 7200)")
    parser.add_argument("--startup-timeout", type=seconds, default=60, help="seconds waiting for a newly started agent's prompt (default: 60)")
    parser.add_argument("--poll-interval", type=seconds, default=10, help="seconds between GitHub reads (default: 10)")
    parser.add_argument("--max-actions", type=int, default=20, help="maximum dispatches per PR (default: 20)")
    parser.add_argument("--checkout", metavar="DIR",
                        help="the checkout the agents start in: the ROOT of a git work tree that is clean, on origin's "
                             f"default branch at origin's tip, whose origin is --repo (default: {CHECKOUT_DEFAULT})")
    parser.add_argument("--dry-run", action="store_true", help="show current PR states and whether the checkout would be "
                                                              "accepted, without starting agents or writing anything")
    args = parser.parse_args()
    if any(n <= 0 for n in args.pr) or len(set(args.pr)) != len(args.pr) or args.max_actions <= 0:
        parser.error("PR numbers must be positive and unique, and --max-actions must be positive")
    if any(not template.strip() or not template.isprintable() for template in (args.draft_command, args.ready_command)):
        parser.error("agent commands must be nonempty single lines")
    os.environ.setdefault("GH_PROMPT_DISABLED", "1")
    batch = None
    try:
        batch = Batch(Repo.parse(args.repo), args)
        batch.run()
        return 0
    except KeyboardInterrupt:
        if batch and batch.checkout:
            print(f"Interrupted; any agent window still open in tmux session {batch.checkout.session} and the task "
                  f"files under {batch.checkout.path / TASK_DIR}/ were kept.", file=sys.stderr)
        else:
            print("Interrupted; nothing was written.", file=sys.stderr)
        return 130
    except (Stop, GitHubError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"pr-loop: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
