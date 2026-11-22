"""`gh_runtime.run_gh` against a REAL process: bounded, its whole group ended, a finished `gh` judged by its exit code.

kjelly/pilot#427: `run_gh` used `subprocess.run(timeout=75)`, which ends the leader only and calls "gh exited 0, something it
started still holds its output" a timeout after 75 seconds. The `gh` here is a script in front of PATH; the processes it
starts carry an environment marker, and only those are ever killed by the test. `test_gh_reads.py` keeps `run_gh` honest
about what it does with recorded answers; this file is about processes.
"""
import contextlib
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import gh_runtime  # noqa: E402
from gh_runtime import GitHubError  # noqa: E402

bounded_run = gh_runtime.bounded_run  # importing gh_runtime is what makes the shared helper importable

# What the fake `gh` does is named by $FAKE_GH_MODE: "hang": a child process and then nothing, until a signal ends them;
# "stubborn": the same, but it and its child ignore SIGTERM; "leaked": print, exit 0 at once and leave a descendant that
# holds gh's stdout and stderr; "cat": print stdin.
FAKE_GH = r'''#!/bin/sh
root="$BR_TEST_MARKER"
echo $$ > "$root/leader"
case "$FAKE_GH_MODE" in
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
    cat)
        cat ;;
esac
'''


def alive(pid):
    """Whether process `pid` runs: a killed process stays a zombie until its parent (init, for an orphan) reaps it."""
    try:
        with open(f'/proc/{pid}/stat') as stat_file:
            return stat_file.read().rsplit(')', 1)[1].split()[0] != 'Z'
    except OSError:
        return False


class RunGhProcessTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='gh-bounded-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        (self.root / 'bin').mkdir()
        (self.root / 'bin' / 'gh').write_text(FAKE_GH)
        (self.root / 'bin' / 'gh').chmod(0o755)
        patcher = mock.patch.dict(os.environ, {'PATH': f"{self.root / 'bin'}{os.pathsep}{os.environ['PATH']}",
                                               'BR_TEST_MARKER': str(self.root), 'FAKE_GH_MODE': ''})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.kill_leftovers)
        watchdog = threading.Timer(15, self.kill_leftovers)
        watchdog.daemon = True
        watchdog.start()
        self.addCleanup(watchdog.cancel)

    def mode(self, name):
        os.environ['FAKE_GH_MODE'] = name

    def pid(self, name):
        return int((self.root / name).read_text())

    def owned(self, pid):
        try:
            return f'BR_TEST_MARKER={self.root}'.encode() in Path(f'/proc/{pid}/environ').read_bytes().split(b'\0')
        except OSError:
            return False

    def kill_leftovers(self):
        for name in ('leader', 'child'):
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
        self.assertFalse(alive(pid), f'{name} (pid {pid}) is still running')

    def bounded(self, fn, limit=8):
        """(what `fn` returned or raised, seconds it took); a call that is still waiting after `limit` seconds is cut off, its
        processes are killed, and the test fails (the code before kjelly/pilot#427 waited for the descendant or for 75 s)."""
        box, began = {}, time.monotonic()

        def target():
            try:
                box['value'] = fn()
            except BaseException as exc:  # reported below, in the test's thread
                box['value'] = exc
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(limit)
        took = time.monotonic() - began
        if thread.is_alive():
            self.kill_leftovers()
            thread.join(10)
            self.fail(f'still waiting after {limit} s: gh has no bound, or its group is not ended')
        return box['value'], took

    def test_a_gh_that_exited_returns_its_result_although_a_descendant_holds_its_output(self):
        self.mode('leaked')
        with mock.patch.object(bounded_run, 'POLL', 0.2), mock.patch.object(bounded_run, 'DRAIN', 0.5):
            done, took = self.bounded(lambda: gh_runtime.run_gh(['pr', 'view', '1']))
        self.assertEqual((0, '{"leaked": true}\n', 'warning\n'), (done.returncode, done.stdout, done.stderr),
                         'what gh returned, not "gh unavailable or timed out"')
        self.assertLess(took, 3, "poll + drain, not the descendant's 6 seconds")
        self.assertTrue(alive(self.pid('child')), 'what a finished gh left behind is not signalled')

    def test_a_gh_that_hangs_is_a_github_error_and_its_whole_group_is_ended(self):
        self.mode('hang')
        with mock.patch.object(gh_runtime, 'GH_TIMEOUT', 0.5, create=True), mock.patch.object(bounded_run, 'KILL_AFTER', 0.3), \
                mock.patch.object(bounded_run, 'DRAIN', 0.3):
            error, took = self.bounded(lambda: gh_runtime.run_gh(['pr', 'view', '1']))
        self.assertIsInstance(error, GitHubError)
        self.assertEqual("gh unavailable or timed out: Command '['gh', 'pr', 'view', '1']' timed out after 0.5 seconds", str(error))
        self.assertLess(took, 4)
        self.assertGone('leader')
        self.assertGone('child')  # `subprocess.run(timeout=)` ends the leader only

    def test_a_gh_that_ignores_sigterm_is_killed_after_the_grace(self):
        self.mode('stubborn')
        with mock.patch.object(gh_runtime, 'GH_TIMEOUT', 0.4, create=True), mock.patch.object(bounded_run, 'KILL_AFTER', 0.4), \
                mock.patch.object(bounded_run, 'DRAIN', 0.3):
            error, took = self.bounded(lambda: gh_runtime.run_gh(['pr', 'view', '1']))
        self.assertIsInstance(error, GitHubError)
        self.assertGreaterEqual(took, 0.8 - 0.2, 'the timeout, then the grace, before SIGKILL')
        self.assertLess(took, 5)
        self.assertGone('leader')
        self.assertGone('child')

    def test_input_text_is_gh_standard_input_and_without_it_the_input_is_closed(self):
        self.mode('cat')
        done, _ = self.bounded(lambda: gh_runtime.run_gh(['api', 'graphql', '--input', '-'], input_text='{"query": 1}'))
        self.assertEqual('{"query": 1}', done.stdout)
        done, took = self.bounded(lambda: gh_runtime.run_gh(['api', 'user']))
        self.assertEqual(('', 0), (done.stdout, done.returncode), '`cat` met end of input at once')
        self.assertLess(took, 3)

    def test_a_gh_call_is_limited_to_75_seconds_read_from_the_module_constant_at_each_call(self):
        answer = subprocess.CompletedProcess(['gh'], 0, '', '')
        for value in (75, 3):
            with self.subTest(limit=value), mock.patch.object(gh_runtime, 'GH_TIMEOUT', value), \
                    mock.patch.object(gh_runtime.bounded_run, 'run', return_value=answer) as run:
                gh_runtime.run_gh(['api', 'user'], input_text='x')
                self.assertEqual((['gh', 'api', 'user'], value, 'x'), (run.call_args.args[0], run.call_args.kwargs['limit'],
                                                                         run.call_args.kwargs['input']))
        self.assertEqual(75, gh_runtime.GH_TIMEOUT, 'the limit did not change when the call moved to bounded_run')


if __name__ == '__main__':
    unittest.main()
