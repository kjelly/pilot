"""pr_gate.py's gh and git reads against REAL processes: bounded, their whole group ended, a finished command judged by its exit code.

kjelly/pilot#428 (first slice, class `unbounded-process-wait`): `cmd` and the five git reads of the gate used `subprocess.run`
with no limit (and `gh` with none either), so a `gh` or `git` that hangs, or one that finished and left a descendant holding
its pipes, kept the gate for as long as it liked. They go through `bounded_run.run` now, and a read that outlives its limit is a
GateError: the refusal a gh HTTP 503 already is (DRAFT-BLOCKED, exit 2), never an answer. The commands here are scripts in
front of PATH (the real `git` for everything a test does not hang): they hang, ignore SIGTERM, or print an answer and leave a
descendant; the processes they start carry an environment marker, and only those are ever killed by a test. The bounds are
injected small. `test_gh_bounded.py` of pr-review-merge is the model.
"""
import contextlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import test_cli_mock as cli_mock
import test_wait_cli as wait_cli

gate = cli_mock.gate  # the module `pr_gate.main()` of these tests runs in
bounded_run = gate.bounded_run
GateError = gate.GateError
REAL_GIT = shutil.which("git")

# What the fake `gh` does is named by $FAKE_MODE. "hang": a child process and then nothing, until a signal ends them;
# "stubborn": the same, but it and its child ignore SIGTERM; "leaked": print an answer, exit 0 at once and leave a descendant
# that holds the output; "no_required": write what `gh pr checks --required` writes on a branch with no required checks, and
# then hang; "answer_then_hang": write a complete answer, and then hang.
FAKE_GH = r'''#!/bin/sh
root="$BR_TEST_MARKER"
echo $$ > "$root/leader"
case "$FAKE_MODE" in
    hang)
        sleep 30 &
        echo $! > "$root/child"
        wait ;;
    stubborn)
        trap '' TERM
        sleep 30 &
        echo $! > "$root/child"
        wait ;;
    leaked)
        sleep 6 &
        echo $! > "$root/child"
        echo '{"leaked": true}'
        echo warning >&2
        exit 0 ;;
    no_required)
        echo "no required checks reported on the 'fix-one' branch" >&2
        sleep 30 &
        echo $! > "$root/child"
        wait ;;
    answer_then_hang)
        echo '[{"name": "go test", "bucket": "pass", "state": "SUCCESS"}]'
        sleep 30 &
        echo $! > "$root/child"
        wait ;;
esac
'''
# The fake `git` is the real one, except for a call whose arguments contain $FAKE_GIT_MATCH: that call hangs ("hang"), ignores
# SIGTERM ("stubborn"), runs the real git and leaves a descendant that holds its output ("leaked"), or fails with exit 128 at
# once ("fail"). Nothing else is touched,
# so the scratch repositories of a test are built by the real git, and the unbounded callers of git in the gate's process
# (the secret scanner) never meet a hang.
FAKE_GIT = r'''#!/bin/sh
if [ -z "$FAKE_GIT_MATCH" ]; then exec "$REAL_GIT" "$@"; fi
case "$*" in
    *"$FAKE_GIT_MATCH"*) ;;
    *) exec "$REAL_GIT" "$@" ;;
esac
root="$BR_TEST_MARKER"
echo $$ > "$root/leader"
case "$FAKE_GIT_MODE" in
    hang)
        sleep 30 &
        echo $! > "$root/child"
        wait ;;
    stubborn)
        trap '' TERM
        sleep 30 &
        echo $! > "$root/child"
        wait ;;
    leaked)
        sleep 6 &
        echo $! > "$root/child"
        "$REAL_GIT" "$@"
        exit $? ;;
    fail)
        echo "fatal: injected failure" >&2
        exit 128 ;;
esac
'''


def alive(pid):
    """Whether process `pid` runs: a killed process stays a zombie until its parent (init, for an orphan) reaps it."""
    try:
        with open(f"/proc/{pid}/stat") as stat_file:
            return stat_file.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X", "x")  # X: for an instant while init reaps it
    except OSError:
        return False


class Processes:
    """What the tests with real processes share: the marker, the clean-up, and a call that is cut off when it never returns."""

    root: Path

    def start_processes(self):
        self.addCleanup(self.kill_leftovers)
        watchdog = threading.Timer(25, self.kill_leftovers)
        watchdog.daemon = True
        watchdog.start()
        self.addCleanup(watchdog.cancel)

    def pid(self, name):
        return int((self.root / name).read_text())

    def owned(self, pid):
        try:
            return f"BR_TEST_MARKER={self.root}".encode() in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        except OSError:
            return False

    def kill_leftovers(self):
        for name in ("leader", "child"):
            with contextlib.suppress(OSError, ValueError):
                pid = self.pid(name)
                if alive(pid) and self.owned(pid):
                    group = os.getpgid(pid)
                    if group != os.getpgid(0):  # never the runner's own group (a command that was not given one of its own)
                        with contextlib.suppress(OSError):
                            os.killpg(group, signal.SIGKILL)
                    os.kill(pid, signal.SIGKILL)

    def assertGone(self, name, within=3.0):
        pid, end = self.pid(name), time.monotonic() + within
        while alive(pid) and time.monotonic() < end:
            time.sleep(0.05)
        self.assertFalse(alive(pid), f"{name} (pid {pid}) is still running")

    def bounded(self, fn, limit=8):
        """(what `fn` returned or raised, seconds it took); a call that is still waiting after `limit` seconds is cut off, its
        processes are killed, and the test fails (the code before kjelly/pilot#428 waited for the command or its descendant)."""
        box, began = {}, time.monotonic()

        def target():
            try:
                box["value"] = fn()
            except BaseException as exc:  # reported below, in the test's thread
                box["value"] = exc
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(limit)
        took = time.monotonic() - began
        if thread.is_alive():
            self.kill_leftovers()
            thread.join(10)
            self.fail(f"still waiting after {limit} s: the read has no bound, or its group is not ended")
        return box["value"], took

    @contextlib.contextmanager
    def fast(self, gh=0.4, git=0.4):
        """The limits, the grace before SIGKILL, the drain and the poll of every read, small."""
        with mock.patch.object(gate, "GH_TIMEOUT", gh), mock.patch.object(gate, "GIT_TIMEOUT", git), \
                mock.patch.object(gate.load_repo_evidence(), "GIT_TIMEOUT", git), mock.patch.object(gate, "KILL_AFTER", 0.3), \
                mock.patch.object(bounded_run, "KILL_AFTER", 0.3), mock.patch.object(bounded_run, "DRAIN", 0.3), \
                mock.patch.object(bounded_run, "POLL", 0.2):
            yield

    def timed_out(self, error, what, limit=0.4):
        self.assertIsInstance(error, gate.GateTimeout, error)
        self.assertIn(f"{what} timed out after {limit:g} s and its process group was ended", str(error))


class GateReadsAgainstRealProcesses(Processes, unittest.TestCase):
    """gh and git on PATH are scripts: `FAKE_MODE`/`FAKE_GIT_MODE` say what they do, `FAKE_GIT_MATCH` which git call."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="gate-bounded-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        (self.root / "bin").mkdir()
        for name, text in (("gh", FAKE_GH), ("git", FAKE_GIT)):
            (self.root / "bin" / name).write_text(text)
            (self.root / "bin" / name).chmod(0o755)
        patcher = mock.patch.dict(os.environ, {"PATH": f"{self.root / 'bin'}{os.pathsep}{os.environ['PATH']}",
                                               "BR_TEST_MARKER": str(self.root), "REAL_GIT": REAL_GIT, "FAKE_MODE": "",
                                               "FAKE_GIT_MATCH": "", "FAKE_GIT_MODE": ""})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.start_processes()
        self.repo = self.make_repo()

    def make_repo(self):
        """A PR worktree on `fix-one`: the base on `origin/main` (it carries the evidence manifest), a code commit, an
        evidence-only commit. `self.base`, `self.code`, `self.head` are the three commits."""
        home = self.root / "home"
        home.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(HOME=str(home), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_AUTHOR_NAME="t",
                   GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        repo = self.root / "repo"
        repo.mkdir()

        def git(*args):
            return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout.strip()

        def commit(name, text):
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(text)
            git("add", name)
            git("commit", "-q", "-m", name)
            return git("rev-parse", "HEAD")
        git("init", "-q", "-b", "main")
        commit(".github/pr-evidence.json", json.dumps({"schema_version": 1, "evidence_only_paths": ["docs/evidence/**"]}))
        self.base = commit("base-file", "the base\n")
        git("update-ref", "refs/remotes/origin/main", self.base)
        git("switch", "-q", "-c", "fix-one")
        self.code = commit("code.txt", "the change\n")
        self.head = commit("docs/evidence/run.md", "evidence\n")
        return repo

    def mode(self, gh=None, git=None, match=None):
        for name, value in (("FAKE_MODE", gh), ("FAKE_GIT_MODE", git), ("FAKE_GIT_MATCH", match)):
            if value is not None:
                os.environ[name] = value

    # --- cmd: every `gh` read of the gate -------------------------------------------------------------------------

    def test_a_gh_read_that_hangs_is_a_gate_error_and_its_whole_group_is_ended(self):
        self.mode(gh="hang")
        with self.fast():
            error, took = self.bounded(lambda: self.raised(gate.cmd, ["gh", "pr", "view", "7"]))
        self.timed_out(error, "gh pr view 7")
        self.assertLess(took, 4)
        self.assertGone("leader")
        self.assertGone("child")  # `subprocess.run(timeout=)` would end the leader only

    def test_a_gh_that_exited_returns_its_answer_although_a_descendant_holds_its_output(self):
        self.mode(gh="leaked")
        with self.fast():
            answer, took = self.bounded(lambda: gate.cmd(["gh", "pr", "view", "7"]))
        self.assertEqual({"leaked": True}, answer, "what gh printed, not a timeout")
        self.assertLess(took, 3, "poll + drain, not the descendant's 6 seconds")
        self.assertTrue(alive(self.pid("child")), "what a finished gh left behind is not signalled")

    def test_a_gh_that_ignores_sigterm_is_killed_after_the_grace(self):
        self.mode(gh="stubborn")
        with self.fast(gh=0.4):
            error, took = self.bounded(lambda: self.raised(gate.cmd, ["gh", "pr", "view", "7"]))
        self.timed_out(error, "gh pr view 7", limit=0.4)
        self.assertIn("(SIGTERM, then SIGKILL)", str(error))
        self.assertGreaterEqual(took, 0.7, "the limit, then the grace, before SIGKILL")
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_timed_out_gh_is_never_read_as_an_empty_list_or_a_check_answer(self):
        # `gh pr checks --required` on a branch with no required checks exits 1 with that stderr line and nothing on stdout,
        # and cmd reads exactly that as "no required checks": a command that wrote the line and then hung has no exit
        # code to say so, and one that wrote a whole answer and hung has not finished it (gh exits 8 for pending checks and
        # 1 for failed ones with JSON still printed, and allow_nonzero_json takes any of them).
        for mode, required, shape in (("no_required", True, "the no-required-checks line, then hangs"),
                                      ("answer_then_hang", True, "a complete required-check list, then hangs"),
                                      ("answer_then_hang", False, "a complete check list, then hangs")):
            with self.subTest(gh=shape):
                self.mode(gh=mode)
                with self.fast():
                    error, took = self.bounded(lambda: self.raised(gate.gh_checks, "acme/repo", 7, required=required))
                self.assertIsInstance(error, GateError, f"{error!r}: not [] and not a check list")
                self.assertIn("gh pr checks 7 timed out after 0.4 s", str(error))
                self.assertLess(took, 4)
                self.assertGone("leader")

    def raised(self, fn, *args, **kwargs):
        """What `fn` raises (the call must not return)."""
        try:
            value = fn(*args, **kwargs)
        except BaseException as exc:
            return exc
        self.fail(f"{fn.__name__} returned {value!r} instead of refusing")

    # --- the git reads ----------------------------------------------------------------------------------------------

    def test_check_local_with_a_git_that_hangs_is_a_gate_error(self):
        self.assertEqual((self.head, "fix-one", []), gate.check_local(self.repo), "control: the real git")
        self.mode(git="hang", match=" status ")
        with self.fast():
            error, took = self.bounded(lambda: self.raised(gate.check_local, self.repo))
        self.timed_out(error, "git status --porcelain --untracked-files=all")
        self.assertLess(took, 4)
        self.assertGone("leader")
        self.assertGone("child")

    def test_tracked_entry_with_a_git_that_hangs_is_a_gate_error_not_an_untracked_file(self):
        entry = gate.tracked_entry(self.repo, self.head, self.repo / "code.txt")
        self.assertEqual(("code.txt", "100644", "blob"), entry[:3], "control: the real git, a byte answer")
        self.mode(git="hang", match="ls-tree")
        with self.fast():
            error, _ = self.bounded(lambda: self.raised(gate.tracked_entry, self.repo, self.head, self.repo / "code.txt"))
        self.timed_out(error, f"git ls-tree {self.head[:12]} code.txt")
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_log_artifact_check_raises_a_git_that_timed_out_and_still_falls_back_on_one_that_failed(self):
        # log_artifact_problem asks tracked_entry whether the PR head tracks the log and, when git cannot say (a GateError
        # of rc != 0), lets the worktree check decide. A git that never answered is not "cannot say": swallowed there, the
        # timeout became the worktree rule's answer, here the text of a log that is missing from the checkout.
        log = "docs/evidence/run.md"  # tracked at the head
        (self.repo / log).unlink()  # the checkout no longer has it: only the head's tree proves it
        self.assertIsNone(gate.log_artifact_problem(self.repo, log, self.head), "control: the real git proves it at the head")
        self.mode(git="fail", match="ls-tree")
        self.assertEqual(f"log artifact missing/unreadable: {log}", gate.log_artifact_problem(self.repo, log, self.head),
                         "control: ls-tree fails (rc 128): the worktree check decides, as before")
        (self.repo / log).write_text("evidence\n")
        self.assertIsNone(gate.log_artifact_problem(self.repo, log, self.head), "control: and the file is in the worktree")
        (self.repo / log).unlink()
        self.mode(git="hang", match="ls-tree")
        with self.fast():
            error, took = self.bounded(lambda: self.raised(gate.log_artifact_problem, self.repo, log, self.head))
        self.timed_out(error, f"git ls-tree {self.head[:12]} {log}")
        self.assertLess(took, 4)
        self.assertGone("leader")
        self.assertGone("child")

    def test_the_checkout_head_that_timed_out_is_not_a_checkout_that_is_elsewhere(self):
        # tracked_pin compares the worktree file with the PR head's blob only while the checkout IS at the head. checkout_head
        # answers None for "git failed", which tracked_pin reads as "elsewhere": it would hand back a pin of a file the
        # worktree has changed. A timeout has to refuse, as the unchanged file's control and the edited file's one both do.
        entry = gate.tracked_entry(self.repo, self.head, self.repo / "code.txt")
        self.assertEqual(self.head, gate.checkout_head(self.repo), "control: the real git")
        self.assertEqual(("git:code.txt", f"100644 {entry[3]}"), gate.tracked_pin(self.repo, self.head, entry, self.repo / "code.txt"))
        (self.repo / "code.txt").write_text("edited in the worktree\n")
        with self.assertRaisesRegex(GateError, "differs from PR head"):
            gate.tracked_pin(self.repo, self.head, entry, self.repo / "code.txt")
        self.mode(git="hang", match="rev-parse HEAD")
        with self.fast():
            error, _ = self.bounded(lambda: self.raised(gate.tracked_pin, self.repo, self.head, entry, self.repo / "code.txt"))
        self.timed_out(error, "git rev-parse HEAD")
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_hash_object_that_hangs_is_a_gate_error_naming_it(self):
        entry = gate.tracked_entry(self.repo, self.head, self.repo / "code.txt")
        self.mode(git="hang", match="hash-object")
        with self.fast():
            error, _ = self.bounded(lambda: self.raised(gate.tracked_pin, self.repo, self.head, entry, self.repo / "code.txt"))
        self.timed_out(error, "git hash-object code.txt")
        self.assertGone("child")

    def test_the_fetched_base_that_timed_out_is_not_a_base_that_is_missing(self):
        # None is "the base ref is not fetched": the strict HEAD-only policy. A timeout must not select it.
        self.assertEqual(self.base, gate.fetched_base(self.repo, "origin", "main"), "control: the real git")
        self.assertIsNone(gate.fetched_base(self.repo, "origin", "nope"), "control: git answers rc 128, the old None")
        self.mode(git="hang", match="--verify")
        with self.fast():
            error, _ = self.bounded(lambda: self.raised(gate.fetched_base, self.repo, "origin", "main"))
        self.timed_out(error, "git rev-parse --verify refs/remotes/origin/main")
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_git_that_exited_returns_its_answer_although_a_descendant_holds_its_output(self):
        self.mode(git="leaked", match="--verify")
        with self.fast():
            answer, took = self.bounded(lambda: gate.fetched_base(self.repo, "origin", "main"))
        self.assertEqual(self.base, answer)
        self.assertLess(took, 3, "poll + drain, not the descendant's 6 seconds")
        self.assertTrue(alive(self.pid("child")))

    def test_a_git_that_ignores_sigterm_is_killed_after_the_grace(self):
        self.mode(git="stubborn", match="--verify")
        with self.fast(git=0.4):
            error, took = self.bounded(lambda: self.raised(gate.fetched_base, self.repo, "origin", "main"))
        self.timed_out(error, "git rev-parse --verify refs/remotes/origin/main", limit=0.4)
        self.assertIn("(SIGTERM, then SIGKILL)", str(error))
        self.assertGreaterEqual(took, 0.7)
        self.assertGone("child")

    # --- repo_evidence's git, as the gate meets it ----------------------------------------------------------------

    def test_a_repo_evidence_git_that_hangs_is_not_read_as_no_evidence_rules(self):
        # evidence_context answered None ("reuse cannot be checked": every receipt and the review must name HEAD itself),
        # review_covers_head False and stale_detail "" for any OSError; a timeout is an error of the gate instead.
        ctx = gate.evidence_context(self.repo, self.head, "main", "origin")
        self.assertIsNotNone(ctx, "control: the real git loads the manifest")
        self.assertTrue(gate.review_covers_head(ctx, self.code, self.head, "review"), "control: an evidence-only delta")
        self.assertIn("files outside evidence_only_paths changed", gate.stale_detail(ctx, self.base))
        self.mode(git="hang", match=":.github/pr-evidence.json")
        with self.fast():
            error, took = self.bounded(lambda: self.raised(gate.evidence_context, self.repo, self.head, "main", "origin"))
        self.assertIsInstance(error, GateError, error)
        self.assertIn(f"git show refs/remotes/origin/main:.github/pr-evidence.json timed out after 0.4 s", str(error))
        self.assertIn("the repository evidence rules cannot be read", str(error))
        self.assertLess(took, 4)
        self.assertGone("child")
        # The same git, late: the context loads, and the questions it answers with git meet the hang (a context of its own for
        # each: it remembers an answer it has had).
        self.mode(git="hang", match="merge-base")
        for label, call in (("review_covers_head", lambda ctx: gate.review_covers_head(ctx, self.code, self.head, "review")),
                            ("stale_detail", lambda ctx: gate.stale_detail(ctx, self.base)),
                            ("stale_detail of a review", lambda ctx: gate.stale_detail(ctx, self.base, review=True))):
            with self.subTest(call=label), self.fast():
                late = gate.evidence_context(self.repo, self.head, "main", "origin")
                self.assertIsNotNone(late)
                error, _ = self.bounded(lambda: self.raised(call, late))
                self.assertIsInstance(error, GateError, f"{error!r}: not False and not an empty detail")
                self.assertIn("timed out after 0.4 s", str(error))
                self.assertGone("child")


class EveryReadIsLimitedByItsConstant(unittest.TestCase):
    """No process: `bounded_run.run` is replaced, and what each read asks of it is the contract: the argv it always ran, a
    limit of 75 s for gh and 60 s for git with a 10 s grace, text or bytes as before, every constant read at each call."""

    SHA = "0123456789abcdef0123456789abcdef01234567"

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="gate-bounded-const-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def calls_of(self, site):
        """`(argv, kwargs)` of every `bounded_run.run` call `site()` makes; each is answered with exit 0 and a SHA."""
        def answer(argv, **kwargs):
            binary = kwargs.get("text") is False
            out = "{}" if argv[0] == "gh" else self.SHA + "\n"
            return subprocess.CompletedProcess(argv, 0, out.encode() if binary else out, b"" if binary else "")
        with mock.patch.object(bounded_run, "run", side_effect=answer) as run:
            site()
        return [(call.args[0], call.kwargs) for call in run.call_args_list]

    def test_the_limits_and_their_values(self):
        self.assertEqual((75, 60, 10), (gate.GH_TIMEOUT, gate.GIT_TIMEOUT, gate.KILL_AFTER))
        root, sha = self.root, self.SHA
        git = ["git", "-C", str(root)]
        reads = {  # name -> (the read, the argv of each of its commands, whether it reads text)
            "cmd": (lambda: gate.cmd(["gh", "pr", "view", "7"]), [["gh", "pr", "view", "7"]], True),
            "check_local": (lambda: gate.check_local(root), [[*git, "rev-parse", "HEAD"], [*git, "rev-parse", "--abbrev-ref", "HEAD"],
                                                             [*git, "status", "--porcelain", "--untracked-files=all"],
                                                             [*git, "ls-files", "--", ".pr-ready"]], True),
            "tracked_entry": (lambda: gate.tracked_entry(root, sha, root / "f"),
                              [["git", "--literal-pathspecs", "-C", str(root), "ls-tree", "-z", sha, "--", "f"]], False),
            "checkout_head": (lambda: gate.checkout_head(root), [[*git, "rev-parse", "HEAD"]], True),
            "tracked_pin": (lambda: gate.tracked_pin(root, sha, ("f", "100644", "blob", sha), root / "f"),
                            [[*git, "rev-parse", "HEAD"], [*git, "hash-object", "--path=f", "--", str(root / "f")]], True),
            "fetched_base": (lambda: gate.fetched_base(root, "origin", "main"),
                             [[*git, "rev-parse", "--verify", "refs/remotes/origin/main"]], True),
        }
        for limits in ((75, 60, 10), (3, 4, 5)):  # the shipped values, and others: nothing is frozen at import
            with mock.patch.object(gate, "GH_TIMEOUT", limits[0]), mock.patch.object(gate, "GIT_TIMEOUT", limits[1]), \
                    mock.patch.object(gate, "KILL_AFTER", limits[2]):
                for name, (read, argvs, text) in reads.items():
                    with self.subTest(read=name, limits=limits):
                        calls = self.calls_of(read)
                        self.assertEqual(argvs, [argv for argv, _ in calls])
                        for argv, kwargs in calls:
                            gh = argv[0] == "gh"
                            self.assertEqual((limits[0] if gh else limits[1], None if gh else limits[2], text),
                                             (kwargs["limit"], kwargs.get("kill_after"), kwargs["text"]), argv)


class WaitModeThroughMain(Processes, unittest.TestCase):
    """`pr_gate.main()` in this process, with the fake gh of test_wait_cli and a hook that hangs one of its `pr view` calls."""

    make_pr = cli_mock.CLIMockTests.make_pr
    evidence_only_pr = cli_mock.CLIMockTests.evidence_only_pr
    prepare = wait_cli.WaitCLITests.prepare
    # The hook runs as a child of the fake gh: it notes its own pid and its parent's, and sleeps.
    HANG = ("import os, pathlib, time\n"
            "root = pathlib.Path(os.environ['BR_TEST_MARKER'])\n"
            "(root / 'leader').write_text(str(os.getppid()))\n"
            "(root / 'child').write_text(str(os.getpid()))\n"
            "time.sleep(30)\n")

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="gate-bounded-main-")
        self.addCleanup(temp.cleanup)
        self.root = Path(os.path.realpath(temp.name))
        self.start_processes()

    def run_main(self, hang_poll, gh_limit, *, ready=False):
        """(exit code, JSON events, repo) of a `--wait` run whose `gh pr view` number `hang_poll` hangs (None: none does).
        Without `ready` the checks stay pending (no `--ready`); with it they pass and the gate makes the PR Ready."""
        checks = (wait_cli.PASS, wait_cli.LINT) if ready else (wait_cli.PENDING, wait_cli.LINT)
        repo, _, env, cli = self.prepare(self.root, [wait_cli.plan(*checks)])
        env["BR_TEST_MARKER"] = str(self.root)
        if hang_poll is not None:
            (self.root / f"hook-{hang_poll}.py").write_text(self.HANG)
        argv = ["pr_gate.py", *(a for a in cli[2:] if ready or a != "--ready")]
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(out), \
                cli_mock.signal_world.read_back_sleeps(), self.fast(gh=gh_limit):
            code = gate.main()
        return code, [json.loads(line) for line in out.getvalue().splitlines()], repo

    def test_a_gh_read_that_hangs_in_a_later_poll_blocks_the_draft_and_nothing_is_made_ready(self):
        started = time.monotonic()
        code, events, repo = self.run_main(hang_poll=1, gh_limit=1.2)
        took = time.monotonic() - started
        self.assertEqual((2, ["WAITING-CI", "DRAFT-BLOCKED"]), (code, [e["status"] for e in events]), events)
        (error,) = events[-1]["errors"]
        self.assertIn("gh pr view 7 timed out after 1.2 s and its process group was ended", error)
        self.assertLess(took, 20)
        self.assertEqual(1, json.loads((repo / ".pr-ready/7/wait-status.json").read_text())["polls"],
                         "one poll completed: the second read is the one that hung")
        self.assertFalse((self.root / "ready").exists(), "`gh pr ready` was never called")
        self.assertFalse((self.root / "ready.log").exists())
        self.assertFalse(events[-1]["ready_invoked"])
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_read_back_that_hangs_after_ready_was_invoked_is_blocked_and_says_so(self):
        # The same refusal as a 503 of that read: DRAFT-BLOCKED, with `ready_invoked` true, because `gh pr ready` ran.
        code, events, _ = self.run_main(None, 5, ready=True)
        self.assertEqual((0, "READY"), (code, events[-1]["status"]), "control: nothing hangs")
        read_back = int((self.root / "ready.log").read_text().split()[-1]) + 1  # the `pr view` right after `gh pr ready`
        second = tempfile.TemporaryDirectory(prefix="gate-bounded-main-")
        self.addCleanup(second.cleanup)
        self.root = Path(os.path.realpath(second.name))  # a state directory of its own; the clean-up follows `self.root`
        code, events, repo = self.run_main(read_back, 1.2, ready=True)
        self.assertEqual(2, code, events)
        self.assertEqual("DRAFT-BLOCKED", events[-1]["status"], events)
        self.assertNotIn("READY", [e["status"] for e in events])
        (error,) = events[-1]["errors"]
        self.assertIn("gh pr view 7 timed out after 1.2 s and its process group was ended", error)
        self.assertTrue(events[-1]["ready_invoked"], "`gh pr ready` had run")
        self.assertTrue((self.root / "ready").exists())
        self.assertTrue(json.loads((repo / ".pr-ready/7/wait-status.json").read_text())["ready_invoked"])
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_signal_during_a_hung_read_ends_gh_and_what_it_started(self):
        # `--wait` turns SIGTERM/SIGINT into WaitStopped, raised inside whatever the main thread is doing: a read of gh. The
        # leader alone used to be killed, and gh's own child stayed. A signal that comes before main() has installed its
        # handler must not end the test run, so this one has a handler of its own until then.
        previous = signal.signal(signal.SIGTERM, lambda *_: None)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)

        def send_when_gh_hangs():
            end = time.monotonic() + 15
            while not (self.root / "child").exists() and time.monotonic() < end:
                time.sleep(0.05)
            os.kill(os.getpid(), signal.SIGTERM)
        threading.Thread(target=send_when_gh_hangs, daemon=True).start()
        code, events, _ = self.run_main(hang_poll=0, gh_limit=60)
        self.assertEqual((2, ["WAIT-INTERRUPTED"]), (code, [e["status"] for e in events]), events)
        self.assertIn("Wait interrupted by SIGTERM", events[-1]["errors"][0])
        self.assertGone("leader")
        self.assertGone("child")


if __name__ == "__main__":
    unittest.main()
