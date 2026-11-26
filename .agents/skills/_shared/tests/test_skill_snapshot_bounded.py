"""skill_snapshot.py's git and tar calls against REAL processes: bounded, their whole group ended, a finished command judged
by its exit code.

kjelly/pilot#428 (first slice, class `unbounded-process-wait`): `git()` and the `tar -x` of `create` used `subprocess.run` with
no limit, so a git or tar that hangs, or one that finished and left a descendant holding its pipes, kept the snapshot for as
long as it liked. They go through `bounded_run.run` now, and a call that outlives its limit is a STOP (exit 1) that names the
command and the limit: not "the bundle path is missing" (`cat-file -e` has exit codes 1 and 128 in its `ok` set, and a timeout
must not become one of them), not a pass. The commands here are scripts in front of PATH (the real `git` for everything a test
does not hang): they hang, ignore SIGTERM, or print an answer and leave a descendant; the processes they start carry an
environment marker, and only those are ever killed by a test. The bounds are injected small. `test_skill_snapshot.py` keeps the
`python3 -I` and bytecode contracts of the script that now imports its sibling.
"""
import contextlib
import io
import json
import os
import shutil
import signal
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import test_skill_snapshot as snapshots
from gitrepo import load_module

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "skill_snapshot.py"
REAL_GIT, REAL_TAR = shutil.which("git"), shutil.which("tar")

# The fake `git` is the real one, except for a call whose arguments contain $FAKE_GIT_MATCH: that call hangs ("hang"), ignores
# SIGTERM ("stubborn"), or runs the real git and leaves a descendant that holds its output ("leaked"). The fake `tar` is the
# real one unless $FAKE_TAR_MODE says "hang" or "stubborn".
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
FAKE_TAR = r'''#!/bin/sh
if [ -z "$FAKE_TAR_MODE" ]; then exec "$REAL_TAR" "$@"; fi
root="$BR_TEST_MARKER"
echo $$ > "$root/leader"
[ "$FAKE_TAR_MODE" = stubborn ] && trap '' TERM
sleep 30 &
echo $! > "$root/child"
wait
'''


def alive(pid):
    """Whether process `pid` runs: a killed process stays a zombie until its parent (init, for an orphan) reaps it."""
    try:
        with open(f"/proc/{pid}/stat") as stat_file:
            return stat_file.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X", "x")  # X: for an instant while init reaps it
    except OSError:
        return False


class SnapshotCallsAgainstRealProcesses(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="snapshot-bounded-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        (self.root / "bin").mkdir()
        for name, text in (("git", FAKE_GIT), ("tar", FAKE_TAR)):
            (self.root / "bin" / name).write_text(text)
            (self.root / "bin" / name).chmod(0o755)
        patcher = mock.patch.dict(os.environ, {"PATH": f"{self.root / 'bin'}{os.pathsep}{os.environ['PATH']}",
                                               "BR_TEST_MARKER": str(self.root), "REAL_GIT": REAL_GIT, "REAL_TAR": REAL_TAR,
                                               "FAKE_GIT_MATCH": "",
                                               "FAKE_GIT_MODE": "", "FAKE_TAR_MODE": ""})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.kill_leftovers)
        watchdog = threading.Timer(25, self.kill_leftovers)
        watchdog.daemon = True
        watchdog.start()
        self.addCleanup(watchdog.cancel)
        self.module = load_module(SCRIPT)
        self.bounded_run = self.module.bounded_run
        self.checkout = snapshots.skill_repo(self)  # the real git builds it, before anything hangs

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
            self.fail(f"still waiting after {limit} s: the call has no bound, or its group is not ended")
        return box["value"], took

    def create(self):
        return self.module.create(self.checkout.path, self.checkout.base)

    def refused(self, fn=None):
        """The Stop that `create` raises (the call must not return)."""
        try:
            value = (fn or self.create)()
        except BaseException as exc:
            return exc
        self.fail(f"create returned {value!r} instead of stopping")

    def mode(self, git=None, match=None, tar=None):
        for name, value in (("FAKE_GIT_MODE", git), ("FAKE_GIT_MATCH", match), ("FAKE_TAR_MODE", tar)):
            if value is not None:
                os.environ[name] = value

    @contextlib.contextmanager
    def fast(self, limit=0.4):
        """The limits, the grace before SIGKILL, the drain and the poll of every call, small."""
        with mock.patch.object(self.module, "GIT_TIMEOUT", limit), mock.patch.object(self.module, "TAR_TIMEOUT", limit), \
                mock.patch.object(self.bounded_run, "KILL_AFTER", 0.3), mock.patch.object(self.bounded_run, "DRAIN", 0.3), \
                mock.patch.object(self.bounded_run, "POLL", 0.2):
            yield

    def test_a_cat_file_that_hangs_is_a_stop_that_names_the_timeout_and_not_a_missing_bundle_path(self):
        # `cat-file -e` answers 1 or 128 for an object that is not there, and `create` accepts both to say "HEAD does not
        # contain the skill bundle path": a hang must be neither.
        self.assertEqual("PASS", snapshots.create(self.checkout)[1]["status"], "control: the real git")
        self.mode(git="hang", match="cat-file")
        with self.fast():
            error, took = self.bounded(self.refused)
        self.assertIsInstance(error, self.module.Stop, error)
        self.assertEqual("git cat-file -e HEAD:.agents/skills/_shared timed out after 0.4 s and was ended (SIGTERM)", str(error))
        self.assertNotIn("does not contain", str(error))
        self.assertLess(took, 4)
        self.assertGone("leader")
        self.assertGone("child")  # `subprocess.run(timeout=)` would end the leader only

    def test_any_git_call_that_hangs_is_a_stop_and_the_command_line_says_exit_1(self):
        self.mode(git="hang", match="archive")  # the last call, after the snapshot directory exists
        with self.fast():
            error, _ = self.bounded(self.refused)
        self.assertIsInstance(error, self.module.Stop, error)
        self.assertIn("git archive --format=tar HEAD -- .agents/skills/_shared", str(error))
        self.assertIn("timed out after 0.4 s and was ended (SIGTERM)", str(error))
        self.assertGone("child")
        self.mode(git="hang", match=" status ")
        out = io.StringIO()
        argv = ["create", "--repo", str(self.checkout.path), "--out-parent", str(self.checkout.base)]
        with self.fast(), contextlib.redirect_stdout(out):
            code, _ = self.bounded(lambda: self.module.main(argv))
        report = json.loads(out.getvalue())
        self.assertEqual((1, "STOP"), (code, report["status"]), report)
        self.assertIn("git status --porcelain=v1 -z --untracked-files=all", report["error"])
        self.assertIn("timed out after 0.4 s", report["error"])

    def test_a_tar_that_hangs_is_a_stop_and_the_partly_extracted_snapshot_is_named(self):
        self.mode(tar="hang")
        with self.fast():
            error, took = self.bounded(self.refused)
        self.assertIsInstance(error, self.module.Stop, error)
        self.assertRegex(str(error), r"^tar extraction timed out after 0\.4 s and was ended \(SIGTERM\); "
                                     r".*single-item-skills-\w+ holds a partly extracted snapshot$")
        self.assertLess(took, 4)
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_tar_that_ignores_sigterm_is_killed_after_the_grace(self):
        self.mode(tar="stubborn")
        with self.fast(0.4):
            error, took = self.bounded(self.refused)
        self.assertIsInstance(error, self.module.Stop, error)
        self.assertIn("tar extraction timed out after 0.4 s and was ended (SIGTERM, then SIGKILL)", str(error))
        self.assertGreaterEqual(took, 0.7, "the limit, then the grace, before SIGKILL")
        self.assertGone("leader")
        self.assertGone("child")

    def test_a_git_that_exited_is_judged_by_its_result_although_a_descendant_holds_its_output(self):
        self.mode(git="leaked", match="HEAD^{tree}")
        with self.fast():
            made, took = self.bounded(self.create)
        self.assertEqual(self.checkout.out("rev-parse", "HEAD^{tree}"), made["tree_id"], "what git printed, not a timeout")
        self.assertLess(took, 5, "poll + drain, not the descendant's 6 seconds")
        self.assertTrue(alive(self.pid("child")), "what a finished git left behind is not signalled")

    def test_a_git_that_ignores_sigterm_is_killed_after_the_grace(self):
        self.mode(git="stubborn", match="HEAD^{tree}")
        with self.fast(0.4):
            error, took = self.bounded(self.refused)
        self.assertIsInstance(error, self.module.Stop, error)
        self.assertIn("timed out after 0.4 s and was ended (SIGTERM, then SIGKILL)", str(error))
        self.assertGreaterEqual(took, 0.7)
        self.assertGone("leader")
        self.assertGone("child")

    def test_every_call_runs_with_its_limit_read_at_each_call_and_the_bytes_it_always_read(self):
        self.assertEqual((60, 60), (self.module.GIT_TIMEOUT, self.module.TAR_TIMEOUT))
        for limits in ((60, 60), (3, 4)):  # the shipped values, and others: nothing is frozen at import
            real, seen = self.bounded_run.run, []

            def spy(argv, **kwargs):
                seen.append((argv[0], kwargs))
                return real(argv, **kwargs)
            with self.subTest(limits=limits), mock.patch.object(self.module, "GIT_TIMEOUT", limits[0]), \
                    mock.patch.object(self.module, "TAR_TIMEOUT", limits[1]), mock.patch.object(self.bounded_run, "run", spy):
                made = self.create()
                self.assertTrue(Path(made["snapshot_dir"]).name.startswith("single-item-skills-"), made)
                self.assertEqual({"git", "tar"}, {name for name, _ in seen})
                for name, kwargs in seen:
                    self.assertEqual((limits[0] if name == "git" else limits[1], False), (kwargs["limit"], kwargs["text"]), name)
                    self.assertNotIn("kill_after", kwargs, "the helper's own grace")
                (tar,) = [kwargs for name, kwargs in seen if name == "tar"]
                self.assertTrue(tar["input"], "the archive goes in on stdin")
                for name, kwargs in seen:
                    if name == "git":
                        self.assertEqual(("0", "C"), (kwargs["env"]["GIT_OPTIONAL_LOCKS"], kwargs["env"]["LC_ALL"]))


if __name__ == "__main__":
    unittest.main()
