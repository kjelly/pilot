"""issue_gate.py's and repo_evidence.py's gh and git reads against REAL processes: bounded, their whole group ended, a finished
command judged by its exit code.

kjelly/pilot#428 (first slice, class `unbounded-process-wait`): `issue_gate.command/git/git_answer/remote_head` and the two
git reads of `repo_evidence` used `subprocess.run` with no limit, so a `gh` or `git` that hangs, or one that finished and left a
descendant holding its pipes, kept the gate for as long as it liked. They go through `bounded_run.run` now. A read that outlives
its limit is a GateError in issue_gate (BLOCKED, exit 2), a TimeoutError in repo_evidence (an OSError: every caller already
refuses on one), and never an answer: not a made-up exit code that `allow_nonzero_json` or `empty_if` would parse, not a "no"
from `git_answer`, not an absent branch from `remote_head`, not "no manifest" (which would drop the repository's required
evidence). The commands here are scripts in front of PATH (the real `git` for everything a test does not hang): they hang,
ignore SIGTERM, or print an answer and leave a descendant; the processes they start carry an environment marker, and only
those are ever killed by a test. The bounds are injected small. `pr-review-merge/tests/test_gh_bounded.py` is the model.
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import create_pr  # noqa: E402
import issue_gate  # noqa: E402
import mark_ready  # noqa: E402
import pr_ci  # noqa: E402
import repo_evidence as re_  # noqa: E402

bounded_run = issue_gate.bounded_run
GateError = issue_gate.GateError
REAL_GIT = shutil.which("git")

# What the fake `gh` does is named by $FAKE_MODE. "hang": a child process and then nothing, until a signal ends them;
# "stubborn": the same, but it and its child ignore SIGTERM; "leaked": print an answer, exit 0 at once and leave a descendant
# that holds the output; "no_required": write what `gh pr checks --required` writes on a branch with no required checks, and
# then hang; "answer_then_hang": write a complete answer, and then hang; "view_then_hang": answer `pr view` like a PR that is
# open at $FAKE_SHA, and hang on any other call.
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
    view_then_hang)
        if [ "$1 $2" = "pr view" ]; then
            echo "{\"number\": 7, \"state\": \"OPEN\", \"isDraft\": true, \"headRefOid\": \"$FAKE_SHA\", \"url\": \"u\"}"
            exit 0
        fi
        sleep 30 &
        echo $! > "$root/child"
        wait ;;
esac
'''
# The fake `git` is the real one, except for a call whose arguments contain $FAKE_GIT_MATCH: that call hangs ("hang"), ignores
# SIGTERM ("stubborn"), or runs the real git and leaves a descendant that holds its output ("leaked"). Nothing else is touched,
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
esac
'''
MANIFEST = {"schema_version": 1, "evidence_only_paths": ["qa/evidence/**"],
            "required_evidence": [{"id": "e2e-run", "source": "CONTRIBUTING.md#verification",
                                   "artifact_glob": "qa/runs/**/*.md"}]}
SHA = "0123456789abcdef0123456789abcdef01234567"


def alive(pid):
    """Whether process `pid` runs: a killed process stays a zombie until its parent (init, for an orphan) reaps it."""
    try:
        with open(f"/proc/{pid}/stat") as stat_file:
            return stat_file.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X", "x")  # X: for an instant while init reaps it
    except OSError:
        return False


class GateReadsAgainstRealProcesses(unittest.TestCase):
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
                                               "BR_TEST_MARKER": str(self.root), "REAL_GIT": REAL_GIT, "FAKE_MODE": "", "FAKE_SHA": SHA,
                                               "FAKE_GIT_MATCH": "", "FAKE_GIT_MODE": ""})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.kill_leftovers)
        watchdog = threading.Timer(25, self.kill_leftovers)
        watchdog.daemon = True
        watchdog.start()
        self.addCleanup(watchdog.cancel)
        self.repo = self.make_repo()

    def make_repo(self):
        """A worktree on `issue/1-x` with a bare `origin` that holds `main` and the branch. The base carries the evidence
        manifest. `self.base`, `self.head` are the base commit and the branch's."""
        home = self.root / "home"
        home.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(HOME=str(home), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_AUTHOR_NAME="t",
                   GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        repo, remote = self.root / "repo", self.root / "remote.git"
        repo.mkdir()

        def git(*args, cwd=repo):
            return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env).stdout.strip()
        remote.mkdir()
        git("init", "-q", "--bare", "-b", "main", cwd=remote)
        git("init", "-q", "-b", "main")
        (repo / ".github").mkdir()
        (repo / ".github" / "pr-evidence.json").write_text(json.dumps(MANIFEST))
        (repo / "base-file").write_text("the base\n")
        git("add", "-A")
        git("commit", "-q", "-m", "base")
        self.base = git("rev-parse", "HEAD")
        git("remote", "add", "origin", str(remote))
        git("push", "-q", "origin", "main")
        git("switch", "-q", "-c", "issue/1-x")
        (repo / "code.txt").write_text("the change\n")
        git("add", "-A")
        git("commit", "-q", "-m", "code")
        self.head = git("rev-parse", "HEAD")
        git("push", "-q", "origin", "issue/1-x")
        return repo

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

    def raised(self, fn, *args, **kwargs):
        """What `fn` raises (the call must not return)."""
        try:
            value = fn(*args, **kwargs)
        except BaseException as exc:
            return exc
        self.fail(f"{fn.__name__} returned {value!r} instead of refusing")

    def mode(self, gh=None, git=None, match=None):
        for name, value in (("FAKE_MODE", gh), ("FAKE_GIT_MODE", git), ("FAKE_GIT_MATCH", match)):
            if value is not None:
                os.environ[name] = value

    @contextlib.contextmanager
    def fast(self, limit=0.4):
        """The limits, the grace before SIGKILL, the drain and the poll of every read, small."""
        with mock.patch.object(issue_gate, "GH_TIMEOUT", limit), mock.patch.object(issue_gate, "GIT_TIMEOUT", limit), \
                mock.patch.object(issue_gate, "REMOTE_TIMEOUT", limit), mock.patch.object(re_, "GIT_TIMEOUT", limit), \
                mock.patch.object(bounded_run, "KILL_AFTER", 0.3), mock.patch.object(bounded_run, "DRAIN", 0.3), \
                mock.patch.object(bounded_run, "POLL", 0.2):
            yield

    def timed_out(self, error, what, limit=0.4):
        self.assertIsInstance(error, GateError, error)
        self.assertIn(f"{what} timed out after {limit:g} s and its process group was ended", str(error))

    # --- issue_gate.command: every `gh` read of the three scripts that import it ----------------------------------

    def test_a_command_that_hangs_is_a_gate_error_and_its_whole_group_is_ended(self):
        self.mode(gh="hang")
        with self.fast():
            error, took = self.bounded(lambda: self.raised(issue_gate.command, ["gh", "issue", "view", "7", "-R", "a/b"]))
        self.timed_out(error, "gh issue view 7")
        self.assertLess(took, 4)
        self.assertGone("leader")
        self.assertGone("child")  # `subprocess.run(timeout=)` would end the leader only

    def test_a_command_that_exited_returns_its_answer_although_a_descendant_holds_its_output(self):
        self.mode(gh="leaked")
        with self.fast():
            answer, took = self.bounded(lambda: issue_gate.command(["gh", "issue", "view", "7"]))
        self.assertEqual({"leaked": True}, answer, "what gh printed, not a timeout")
        self.assertLess(took, 3, "poll + drain, not the descendant's 6 seconds")
        self.assertTrue(alive(self.pid("child")), "what a finished gh left behind is not signalled")

    def test_a_command_that_ignores_sigterm_is_killed_after_the_grace(self):
        self.mode(gh="stubborn")
        with self.fast(0.4):
            error, took = self.bounded(lambda: self.raised(issue_gate.command, ["gh", "issue", "view", "7"]))
        self.timed_out(error, "gh issue view 7", limit=0.4)
        self.assertIn("(SIGTERM, then SIGKILL)", str(error))
        self.assertGreaterEqual(took, 0.7, "the limit, then the grace, before SIGKILL")
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_timed_out_command_is_never_a_made_up_exit_code_with_json_or_an_empty_list(self):
        # `allow_nonzero_json` takes ANY non-zero exit with JSON on stdout, and `empty_if` turns exit 1 with that stderr line
        # into []: a command that timed out has no exit code, and what it had written is not an answer.
        self.mode(gh="answer_then_hang")
        with self.fast():
            error, _ = self.bounded(lambda: self.raised(issue_gate.command, ["gh", "pr", "checks", "7"], allow_nonzero_json=True))
        self.timed_out(error, "gh pr checks 7")
        self.mode(gh="no_required")
        with self.fast():
            error, _ = self.bounded(lambda: self.raised(pr_ci.checks, "acme/repo", 7, True))
        self.assertIsInstance(error, GateError, f"{error!r}: not [] and not a check list")
        self.assertIn("gh pr checks 7 timed out after 0.4 s", str(error))
        self.assertGone("leader")

    def test_the_ci_report_of_a_hung_gh_is_unknown_and_stops_the_watch(self):
        # CI_PENDING and NO_CI_OBSERVED are exit 3 and keep `--watch` polling; CI_UNKNOWN is exit 2. A timeout of the
        # check list must not read as "no checks yet" (NO_CI_OBSERVED), wherever in the report the hang is.
        argv = ["--repo", "acme/repo", "--pr", "7", "--head-sha", SHA, "--watch", "--timeout", "60", "--interval", "1"]
        for mode, hung in (("hang", "gh pr view 7"), ("view_then_hang", "gh pr checks 7")):
            with self.subTest(hangs=hung):
                self.mode(gh=mode)
                out = io.StringIO()
                with self.fast(), contextlib.redirect_stdout(out):
                    code, took = self.bounded(lambda: pr_ci.main(argv))
                self.assertEqual(2, code)
                report = json.loads(out.getvalue())
                self.assertEqual("CI_UNKNOWN", report["status"])
                self.assertIn(f"{hung} timed out after 0.4 s", report["blockers"][0])
                self.assertLess(took, 5, "one read, not a watch that polls on")
                self.assertGone("child")

    def test_the_readers_that_import_command_refuse_on_a_timeout_before_any_write(self):
        self.assertIs(issue_gate.command, mark_ready.command)
        self.assertIs(issue_gate.command, create_pr.command)
        self.mode(gh="hang")
        for name, call in (("mark_ready.unresolved_threads", lambda: mark_ready.unresolved_threads("acme/repo", 7)),
                           ("create_pr.check_pr", lambda: create_pr.check_pr("acme/repo", "issue/1-x", "main", SHA, draft=True,
                                                                              issue=1))):
            with self.subTest(read=name), self.fast():
                error, _ = self.bounded(lambda: self.raised(call))
                self.assertIsInstance(error, GateError, error)
                self.assertIn("timed out after 0.4 s", str(error))
                self.assertGone("child")

    # --- the git reads of issue_gate --------------------------------------------------------------------------------

    def test_git_with_a_hung_git_is_a_gate_error(self):
        self.assertEqual(self.head, issue_gate.git(self.repo, "rev-parse", "HEAD"), "control: the real git")
        self.mode(git="hang", match=" status ")
        with self.fast():
            error, took = self.bounded(lambda: self.raised(issue_gate.git, self.repo, "status", "--porcelain=v1"))
        self.timed_out(error, "git status --porcelain=v1")
        self.assertLess(took, 4)
        self.assertGone("leader")
        self.assertGone("child")

    def test_git_answer_that_timed_out_is_not_a_no(self):
        # exit 1 is False ("not an ancestor"), and a caller reports that as a defect of the evidence; a timeout is neither.
        ancestor = ("merge-base", "--is-ancestor")
        self.assertIs(True, issue_gate.git_answer(self.repo, *ancestor, self.base, self.head), "control: exit 0")
        self.assertIs(False, issue_gate.git_answer(self.repo, *ancestor, self.head, self.base), "control: exit 1")
        self.mode(git="hang", match="--is-ancestor")
        with self.fast():
            error, _ = self.bounded(lambda: self.raised(issue_gate.git_answer, self.repo, *ancestor, self.base, self.head))
        self.timed_out(error, f"git merge-base --is-ancestor {self.base} {self.head}")
        self.assertGone("leader")
        self.assertGone("child")

    def test_remote_head_that_timed_out_is_not_a_branch_that_is_absent(self):
        # None is exit 2: the branch is not on the remote. A `git ls-remote` that never answered says nothing about it.
        self.assertEqual(self.head, issue_gate.remote_head(self.repo, "origin", "issue/1-x"), "control: present")
        self.assertIsNone(issue_gate.remote_head(self.repo, "origin", "issue/2-y"), "control: absent, exit 2")
        self.mode(git="hang", match="ls-remote")
        with self.fast():
            error, took = self.bounded(lambda: self.raised(issue_gate.remote_head, self.repo, "origin", "issue/1-x"))
        self.timed_out(error, "git ls-remote refs/heads/issue/1-x")
        self.assertLess(took, 4)
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_pushed_stage_with_a_hung_ls_remote_blocks_and_does_not_report_a_missing_branch(self):
        self.mode(git="hang", match="ls-remote")
        evidence = self.root / "evidence.json"
        evidence.write_text(json.dumps({"base_branch": "main"}))
        with self.fast():
            (errors, _), _ = self.bounded(lambda: issue_gate.evaluate(repo="acme/repo", issue=1, worktree=self.repo,
                                                                      evidence_path=evidence, stage="pushed"))
        self.assertTrue([e for e in errors if "git ls-remote refs/heads/issue/1-x timed out after 0.4 s" in e], errors)
        self.assertFalse([e for e in errors if "differs from validated HEAD" in e], "None would have said the branch is absent")

    # --- repo_evidence: a TimeoutError, never an absent answer -----------------------------------------------------

    def context(self):
        return re_.Context.load(self.repo, self.head, "refs/remotes/origin/main")

    def test_a_manifest_read_that_times_out_does_not_drop_the_required_evidence(self):
        # A `git show` that fails (rc != 0) is "no manifest on the base": a warning, and `required` empty. The same for a
        # timeout would turn "the repository requires e2e-run" into "nothing is required", a false GATE-PASS.
        control = self.context()
        self.assertEqual((["e2e-run"], 1), (sorted(control.required), len(control.check_required([]))), "control: required")
        self.mode(git="hang", match=":.github/pr-evidence.json")
        with self.fast():
            error, took = self.bounded(lambda: self.raised(self.context))
        self.assertIsInstance(error, TimeoutError, error)
        self.assertIn("git show refs/remotes/origin/main:.github/pr-evidence.json timed out after 0.4 s and its process group "
                      "was ended", str(error))
        self.assertLess(took, 4)
        self.assertGone("leader")
        self.assertGone("child")

    def test_the_gate_blocks_when_the_manifest_cannot_be_read(self):
        self.mode(git="hang", match=":.github/pr-evidence.json")
        evidence = self.root / "evidence.json"
        evidence.write_text(json.dumps({"base_branch": "main"}))
        argv = ["--repo", "acme/repo", "--issue", "1", "--worktree", str(self.repo), "--evidence", str(evidence)]
        out = io.StringIO()
        with self.fast(), contextlib.redirect_stdout(out):
            code, _ = self.bounded(lambda: issue_gate.main(argv))
        report = json.loads(out.getvalue())
        self.assertEqual((2, "BLOCKED"), (code, report["status"]), report)
        self.assertIn("git show refs/remotes/origin/main:.github/pr-evidence.json timed out after 0.4 s", report["blockers"][0])
        self.assertNotIn("repo_evidence", report, "no report of rules that were never read")
        self.assertGone("child")

    def test_a_file_read_that_times_out_is_not_a_missing_file(self):
        ctx = self.context()
        self.assertEqual(b"the change\n", ctx.read_file(self.head, "code.txt"), "control: bytes")
        self.assertIsNone(ctx.read_file(self.head, "absent.txt"), "control: rc 128 is None, as it was")
        self.mode(git="hang", match=":code.txt")
        with self.fast():
            error, _ = self.bounded(lambda: self.raised(ctx.read_file, self.head, "code.txt"))
        self.assertIsInstance(error, TimeoutError, error)
        self.assertIn(f"git show {self.head}:code.txt timed out after 0.4 s", str(error))
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_git_that_timed_out_is_not_the_127_of_a_git_that_cannot_start(self):
        self.assertEqual((0, self.head + "\n"), re_.git(self.repo, "rev-parse", "HEAD"), "control")
        self.mode(git="hang", match="rev-parse HEAD")
        with self.fast():
            error, _ = self.bounded(lambda: self.raised(re_.git, self.repo, "rev-parse", "HEAD"))
        self.assertIsInstance(error, TimeoutError, error)
        self.assertIn("git rev-parse HEAD timed out after 0.4 s", str(error))
        self.assertGone("child")

    def test_a_git_that_exited_returns_its_answer_although_a_descendant_holds_its_output(self):
        self.mode(git="leaked", match="rev-parse HEAD")
        with self.fast():
            answer, took = self.bounded(lambda: re_.git(self.repo, "rev-parse", "HEAD"))
        self.assertEqual((0, self.head + "\n"), answer)
        self.assertLess(took, 3, "poll + drain, not the descendant's 6 seconds")
        self.assertTrue(alive(self.pid("child")))

    def test_a_git_that_ignores_sigterm_is_killed_after_the_grace(self):
        self.mode(git="stubborn", match="rev-parse HEAD")
        with self.fast(0.4):
            error, took = self.bounded(lambda: self.raised(re_.git, self.repo, "rev-parse", "HEAD"))
        self.assertIsInstance(error, TimeoutError, error)
        self.assertIn("git rev-parse HEAD timed out after 0.4 s and its process group was ended (SIGTERM, then SIGKILL)", str(error))
        self.assertGreaterEqual(took, 0.7)
        self.assertGone("child")


class EveryReadIsLimitedByItsConstant(unittest.TestCase):
    """No process: `bounded_run.run` is replaced, and what each read asks of it is the contract: the argv it always ran, a
    limit of 75 s for gh and `ls-remote` and 60 s for the other git reads, text or bytes as before, every constant read at
    each call."""

    def calls_of(self, site):
        """`(argv, kwargs)` of every `bounded_run.run` call `site()` makes; each is answered with exit 0."""
        def answer(argv, **kwargs):
            binary = kwargs.get("text") is False
            out = "{}" if argv[0] == "gh" else f"{SHA}\trefs/heads/b\n" if "ls-remote" in argv else SHA + "\n"
            return subprocess.CompletedProcess(argv, 0, out.encode() if binary else out, b"" if binary else "")
        with mock.patch.object(bounded_run, "run", side_effect=answer) as run:
            site()
        return [(call.args[0], call.kwargs) for call in run.call_args_list]

    def test_the_limits_and_their_values(self):
        self.assertEqual((75, 60, 75, 60), (issue_gate.GH_TIMEOUT, issue_gate.GIT_TIMEOUT, issue_gate.REMOTE_TIMEOUT, re_.GIT_TIMEOUT))
        root = Path("/work/tree")
        git = ["git", "-C", str(root)]
        ancestor = ("merge-base", "--is-ancestor", "a", "b")
        reads = {  # name -> (the read, the argv it runs, the limit it gets, whether it reads text)
            "command": (lambda: issue_gate.command(["gh", "issue", "view", "7"], cwd=root), ["gh", "issue", "view", "7"], "gh", True),
            "git": (lambda: issue_gate.git(root, "rev-parse", "HEAD"), [*git, "rev-parse", "HEAD"], "git", True),
            "git_answer": (lambda: issue_gate.git_answer(root, *ancestor), [*git, *ancestor], "git", True),
            "remote_head": (lambda: issue_gate.remote_head(root, "origin", "b"),
                            [*git, "ls-remote", "--exit-code", "origin", "refs/heads/b"], "remote", True),
            "repo_evidence.git": (lambda: re_.git(root, "rev-parse", "HEAD"), [*git, "rev-parse", "HEAD"], "evidence", True),
            "Context.read_file": (lambda: re_.Context(root, SHA, None, [], []).read_file("rev", "f.txt"),
                                  [*git, "show", "rev:f.txt"], "evidence", False),
        }
        for limits in ((75, 60, 75, 60), (3, 4, 5, 6)):  # the shipped values, and others: nothing is frozen at import
            with mock.patch.object(issue_gate, "GH_TIMEOUT", limits[0]), mock.patch.object(issue_gate, "GIT_TIMEOUT", limits[1]), \
                    mock.patch.object(issue_gate, "REMOTE_TIMEOUT", limits[2]), mock.patch.object(re_, "GIT_TIMEOUT", limits[3]):
                expected = {"gh": limits[0], "git": limits[1], "remote": limits[2], "evidence": limits[3]}
                for name, (read, argv, which, text) in reads.items():
                    with self.subTest(read=name, limits=limits):
                        ((got_argv, kwargs),) = self.calls_of(read)
                        self.assertEqual((argv, expected[which], text), (got_argv, kwargs["limit"], kwargs.get("text", True)))
                        self.assertNotIn("kill_after", kwargs, "the helper's own grace")
        self.assertEqual(root, self.calls_of(lambda: issue_gate.command(["gh", "x"], cwd=root))[0][1]["cwd"])


if __name__ == "__main__":
    unittest.main()
