"""scripts/bounded_run.py: a command returns within its bound, its whole group ends, and a finished command is judged by its exit code.

Class `unbounded-process-wait` (kjelly/pilot#427): completion and cleanup keyed on the leader and on pipe EOF instead of on
the process group and one deadline. Every test starts REAL processes (a shell leader, and Python members that ignore
SIGTERM, hold a pipe, leave the group), names the pids it starts in files, and asserts the outcome that an observer sees: the
time it took, the group's live members, the exact text, the marker a member wrote when it got SIGTERM. The numbers are small
(a fraction of a second) and the upper bounds are 5-8 times what the injected values need; a lower bound appears only where
it is the invariant (SIGKILL comes `kill_after` seconds after SIGTERM, not before). Whatever a test starts is killed when it
ends, and by a watchdog if the code under test waits for it: nothing outlives the test, also when the code is wrong.
"""
import contextlib
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
import warnings
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bounded_run  # noqa: E402

# Small limits for what the tests wait for; the module's own defaults are 30 / 5 / 1 seconds.
FAST = dict(kill_after=0.4, drain=0.3, poll=0.2)
LIMIT = 0.8  # for the tests that start a member: long enough for it to be ready, short enough not to be waited for

# A member that IGNORES SIGTERM: it leaves a marker when SIGTERM arrives and keeps running, so that only SIGKILL ends it.
# It says it is ready only after the handler is installed; the command waits for that, so that a slow start under load
# cannot let SIGTERM kill it first (which would make the test pass for the wrong reason).
MEMBER = """import os, signal, sys, time
root, name, _marker = sys.argv[1:4]
def on_term(*_):
    open(os.path.join(root, name + ".term"), "w").close()
signal.signal(signal.SIGTERM, on_term)
open(os.path.join(root, name + ".ready"), "w").close()
while True:
    time.sleep(0.1)
"""
# A writer that leaves the process group, ignores SIGTERM and keeps writing to its stderr: the pipe stays open for good.
ESCAPED = """import os, signal, sys, time
root, name, _marker = sys.argv[1:4]
os.setsid()
signal.signal(signal.SIGTERM, signal.SIG_IGN)
open(os.path.join(root, name + ".ready"), "w").close()
for _ in range(300):
    sys.stderr.write("x\\n")
    sys.stderr.flush()
    time.sleep(0.1)
"""
# Holds its inherited stdout and stderr and does nothing else, for a long time.
HOLDER = """import sys, time
time.sleep(30)
"""
# The leader ends on SIGTERM after ending its own child, so that no zombie of its own keeps the group "there".
LEADER_ENDS_ON_SIGTERM = "trap 'kill $!; wait $!; exit 143' TERM\nsleep 30 &\nwait\n"


# A killed process is a zombie (Z) until its parent (init, for an orphan) reaps it, and shows X (dead) for an instant while it is
# reaped: a check that counts X as running reads Z, then X, then nothing, and fails a test whose process was killed.
DEAD_STATES = ("Z", "X", "x")


def alive(pid):
    """Whether process `pid` runs: a killed process stays a zombie until its parent (init, for an orphan) reaps it."""
    try:
        with open(f"/proc/{pid}/stat") as stat_file:
            return stat_file.read().rsplit(")", 1)[1].split()[0] not in DEAD_STATES
    except OSError:
        return False


def group_members(pgid):
    """The pids of the live (not zombie) members of process group `pgid`."""
    found = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                with open(f"/proc/{name}/stat") as stat_file:
                    state, _, group = stat_file.read().rsplit(")", 1)[1].split()[:3]
            except OSError:
                continue
            if state not in DEAD_STATES and int(group) == pgid:
                found.append(int(name))
    return found


class Case(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="bounded-run-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.marker = uuid.uuid4().hex[:12]  # in the command line of everything the test starts: its pids are checked
        self.armed = False  # a SIGINT counts only while the call under test runs; a late one is dropped
        self.signal_problems = []  # a signal that was never sent, because the command never said it was running
        self.addCleanup(self.assertNoSignalProblems)

        def on_sigint(_signum, _frame):
            if self.armed:
                raise KeyboardInterrupt
        # A test run started in the background has SIGINT ignored: the interrupts these tests send would go nowhere.
        before = signal.signal(signal.SIGINT, on_sigint)
        self.addCleanup(signal.signal, signal.SIGINT, before)
        self.addCleanup(self.kill_leftovers)
        watchdog = threading.Timer(12, self.kill_leftovers)
        watchdog.daemon = True
        watchdog.start()
        self.addCleanup(watchdog.cancel)

    # -- what a test starts ------------------------------------------------------------------------------------------
    def script(self, name, text):
        path = self.root / name
        path.write_text(text)
        return f"{shlex.quote(sys.executable)} {path}"

    def member(self, name, source=MEMBER, holds_pipes=True, wait=True):
        """Shell lines that start a member in the background, record its pid in `<name>` and (`wait`) wait until the
        member says it is ready, by creating `<name>.ready`."""
        quiet = "" if holds_pipes else " >/dev/null 2>&1"
        lines = (f"{self.script(name + '.py', source)} {self.root} {name} {self.marker}{quiet} &\n"
                 f"echo $! > {self.root}/{name}\n")
        return lines + (f"while [ ! -e {self.root}/{name}.ready ]; do sleep 0.05; done\n" if wait else "")

    def sh(self, body, ids=False):
        """The leader: a shell that records its pid (and with `ids` its process group and session) in files, then runs
        `body`. The marker is in its command line."""
        return ["sh", "-c", f": {self.marker}\necho $$ > {self.root}/leader\n"
                            + (f"ps -o pgid=,sid= -p $$ > {self.root}/leader.ids 2>/dev/null\n" if ids else "") + body]

    def pid(self, name):
        return int((self.root / name).read_text())

    def owned(self, pid):
        try:
            return self.marker.encode() in Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return False

    def kill_leftovers(self):
        """Kill what the test started: only processes whose command line carries this test's marker."""
        for name in ("leader", "child", "helper", "member", "escaped"):
            with contextlib.suppress(OSError, ValueError):
                pid = self.pid(name)
                if alive(pid) and self.owned(pid):
                    group = os.getpgid(pid)
                    if group != os.getpgid(0):  # never the runner's own group (a command that was not given one of its own)
                        with contextlib.suppress(OSError):
                            os.killpg(group, signal.SIGKILL)
                    os.kill(pid, signal.SIGKILL)

    # -- how a test runs and watches it -----------------------------------------------------------------------------
    def run_bounded(self, argv, **kwargs):
        """(result or exception, seconds it took): `bounded_run.run` with the small test limits, SIGINT armed meanwhile."""
        kwargs = {**FAST, **kwargs}
        began, self.armed = time.monotonic(), True
        try:
            return bounded_run.run(argv, **kwargs), time.monotonic() - began
        finally:
            self.armed = False
            self.took = time.monotonic() - began

    def interrupts(self, *gaps, after="ready", sig=signal.SIGINT):
        """`sig` to this process `gaps[0]` seconds after file `after` appeared, then `gaps[1]` after that, and so on. The
        command writes `after` once it runs, so the signal never lands before `run()` has the process it started in hand
        (a timer started before the call could fire between the fork and the helper's `try:`, where an interrupt leaves the
        command running: a window the helper documents). The wait is bounded: a file that does not appear within 5 s sends
        nothing and fails the test when it ends."""
        def work():
            end = time.monotonic() + 5
            while not (self.root / after).exists():
                if time.monotonic() > end:
                    self.signal_problems.append(f"{after} did not appear within 5 s: no {sig.name} was sent")
                    return
                time.sleep(0.01)
            for gap in gaps:
                time.sleep(gap)
                if not self.armed:  # the call under test is over (it failed early): a late signal would reach the runner
                    return
                os.kill(os.getpid(), sig)
        threading.Thread(target=work, daemon=True).start()

    def assertNoSignalProblems(self):
        self.assertEqual([], self.signal_problems)

    def assertGone(self, name, within=3.0):
        pid, end = self.pid(name), time.monotonic() + within
        while alive(pid) and time.monotonic() < end:
            time.sleep(0.05)
        self.assertFalse(alive(pid), f"{name} (pid {pid}) is still running")

    def assertGroupGone(self, within=3.0):
        """No live member is left in the leader's group (killed members are zombies until init reaps them: not live)."""
        pgid, end = self.pid("leader"), time.monotonic() + within
        while group_members(pgid) and time.monotonic() < end:
            time.sleep(0.05)
        self.assertEqual([], group_members(pgid), "a process of the command's group is still running")


class FinishedCommandTests(Case):
    """What a command that exited returns, whatever its descendants do with its pipes."""

    def test_a_command_with_no_descendants_returns_its_result_unchanged(self):
        argv = self.sh("echo out; echo err >&2; exit 0\n")
        done, took = self.run_bounded(argv, limit=5)
        self.assertEqual((0, "out\n", "err\n", argv), (done.returncode, done.stdout, done.stderr, done.args))
        self.assertLess(took, 2)

    def test_it_returns_bytes_when_asked_and_passes_cwd_env_and_a_closed_stdin(self):
        body = "pwd; echo \"$BR_VALUE\"; cat; printf 'raw\\377' >&2\n"
        done, _ = self.run_bounded(self.sh(body), limit=5, text=False, cwd=self.root, env={**os.environ, "BR_VALUE": "v"})
        self.assertEqual((0, f"{self.root}\nv\n".encode(), b"raw\xff"), (done.returncode, done.stdout, done.stderr),
                         "bytes, undecoded; `cat` met end of input at once: stdin is closed when there is no `input`")

    def test_a_leaked_descendant_does_not_turn_a_finished_command_into_a_timeout(self):
        # H1. The command exited 3 and left a process that holds its stdout and stderr for 30 seconds.
        script = self.member("child", HOLDER, holds_pipes=True, wait=False)
        done, took = self.run_bounded(self.sh(script + "echo out; echo err >&2; exit 3\n"), limit=10)
        self.assertEqual((3, "out\n", "err\n"), (done.returncode, done.stdout, done.stderr),
                         "the command's own exit code and output, not a timeout")
        self.assertLess(took, 3, "poll + drain, not the 10 second limit and not the descendant's 30 seconds")
        self.assertTrue(alive(self.pid("child")), "what a finished command left behind is not signalled")

    def test_a_leaked_descendant_that_left_half_a_character_in_the_pipe_does_not_hide_the_result(self):
        # The command exited 3; what a descendant wrote before it stopped ends in the middle of a character. The result is
        # returned, the half character is a replacement character (strict decoding raised UnicodeDecodeError instead).
        body = f"( printf '\\344\\270'; sleep 5 ) &\necho $! > {self.root}/child\nexit 3\n"
        done, took = self.run_bounded(self.sh(body), limit=10)
        self.assertEqual((3, "\ufffd", ""), (done.returncode, done.stdout, done.stderr))
        self.assertLess(took, 3, "poll + drain, not the descendant's 5 seconds")

    def test_the_constants_are_read_at_each_call(self):
        script = self.member("child", HOLDER, holds_pipes=True, wait=False)
        with patch.object(bounded_run, "POLL", 0.1), patch.object(bounded_run, "DRAIN", 0.2):
            began = time.monotonic()
            done = bounded_run.run(self.sh(script + "exit 0\n"), limit=10)
        self.assertEqual(0, done.returncode)
        self.assertLess(time.monotonic() - began, 1.5, "POLL 0.1 and DRAIN 0.2 were used, not 1 and 5")
        self.kill_leftovers()
        with patch.object(bounded_run, "KILL_AFTER", 0.3), patch.object(bounded_run, "DRAIN", 0.3):
            began = time.monotonic()
            with self.assertRaises(bounded_run.Timeout):
                bounded_run.run(self.sh("trap '' TERM\nsleep 30\n"), limit=0.3, poll=0.1)
        self.assertLess(time.monotonic() - began, 3, "KILL_AFTER 0.3 was used, not 30")


class DeadlineTests(Case):
    """What happens at the deadline: the whole group ends, SIGTERM first, SIGKILL after `kill_after`."""

    def test_a_hung_command_and_its_child_end_on_sigterm_in_a_group_and_session_of_their_own(self):
        # H2.
        body = f"trap 'echo term > {self.root}/term' TERM\nsleep 30 &\necho $! > {self.root}/child\nwait\n"
        argv = self.sh(body, ids=True)
        with self.assertRaises(bounded_run.Timeout) as caught:
            self.run_bounded(argv, limit=0.5)
        error = caught.exception
        self.assertEqual("SIGTERM", error.ended)
        self.assertEqual(f"Command '{argv}' timed out after 0.5 seconds", str(error), "TimeoutExpired's own text")
        self.assertEqual((0.5, argv), (error.timeout, error.cmd))
        self.assertLess(self.took, 3)
        self.assertTrue((self.root / "term").exists(), "SIGTERM came first (the shell's trap ran)")
        leader = self.pid("leader")
        self.assertEqual(f"{leader} {leader}", " ".join((self.root / "leader.ids").read_text().split()),
                         "the command leads a process group and a session of its own")
        self.assertNotEqual(os.getpgid(0), leader)
        self.assertGone("leader")
        self.assertGone("child")
        self.assertGroupGone()

    def test_a_member_that_ignores_sigterm_and_holds_no_pipe_is_killed_after_kill_after_when_the_leader_is_gone(self):
        # H3: the leader ends on SIGTERM and is reaped; a member of its group that ignores SIGTERM stays.
        with self.assertRaises(bounded_run.Timeout) as caught:
            self.run_bounded(self.sh(self.member("member", holds_pipes=False) + LEADER_ENDS_ON_SIGTERM), limit=LIMIT)
        self.assertEqual("SIGTERM, then SIGKILL", caught.exception.ended)
        self.assertTrue((self.root / "member.term").exists(), "the member was asked first, and kept running")
        self.assertGreaterEqual(self.took, LIMIT + FAST["kill_after"] - 0.2, "SIGKILL comes kill_after seconds after SIGTERM, not sooner")
        self.assertLess(self.took, 5)
        self.assertGone("member")
        self.assertGroupGone()

    def test_a_member_that_is_still_cleaning_up_when_the_leader_is_gone_is_not_killed_within_kill_after(self):
        # H3, the other side: git's child removes its lock files on SIGTERM and then ends by itself.
        slow = ("import os, signal, sys, time\nroot, name, _marker = sys.argv[1:4]\n"
                "def on_term(*_):\n    time.sleep(0.4)\n    open(os.path.join(root, name + '.cleaned'), 'w').close()\n"
                "    os._exit(0)\nsignal.signal(signal.SIGTERM, on_term)\n"
                "open(os.path.join(root, name + '.ready'), 'w').close()\nwhile True:\n    time.sleep(0.1)\n")
        with self.assertRaises(bounded_run.Timeout) as caught:
            self.run_bounded(self.sh(self.member("member", slow, holds_pipes=False) + LEADER_ENDS_ON_SIGTERM),
                             limit=LIMIT, kill_after=3)
        self.assertEqual("SIGTERM", caught.exception.ended, "nothing needed SIGKILL")
        self.assertTrue((self.root / "member.cleaned").exists(), "the member finished what it does on SIGTERM")
        self.assertLess(self.took, 2.8, "it did not wait for kill_after once the group was empty")
        self.assertGroupGone()

    def test_a_member_that_ignores_sigterm_and_holds_the_pipe_is_bounded(self):
        # H4: waiting for the output of the group, after SIGTERM, would last as long as the member lives.
        with self.assertRaises(bounded_run.Timeout) as caught:
            self.run_bounded(self.sh(self.member("member", holds_pipes=True) + LEADER_ENDS_ON_SIGTERM), limit=LIMIT)
        self.assertEqual("SIGTERM, then SIGKILL", caught.exception.ended)
        self.assertTrue((self.root / "member.term").exists())
        self.assertLess(self.took, LIMIT + FAST["kill_after"] + FAST["drain"] + 3, "limit + kill_after + drain, not the member's life")
        self.assertGone("member")
        self.assertGroupGone()

    def test_a_process_that_left_the_group_while_holding_the_pipe_cannot_hold_the_caller(self):
        # H5.
        calls, real = [], os.killpg

        def recording_killpg(pgid, sig):
            try:
                real(pgid, sig)
            except ProcessLookupError:
                calls.append((sig, "ESRCH"))
                raise
            calls.append((sig, "ok"))
        made = []

        class Recording(subprocess.Popen):  # the test holds the Popen: only the helper can close its pipes (a collected
            def __init__(self, *args, **kwargs):  # Popen closes them by itself, and would hide a helper that does not)
                super().__init__(*args, **kwargs)
                made.append(self)
        body = self.member("escaped", ESCAPED, holds_pipes=True) + LEADER_ENDS_ON_SIGTERM
        with patch.object(bounded_run.os, "killpg", recording_killpg), patch.object(bounded_run.subprocess, "Popen", Recording):
            with self.assertRaises(bounded_run.Timeout) as caught:
                self.run_bounded(self.sh(body), limit=LIMIT)
        self.assertLess(self.took, 4, "limit + drain, not the writer's 30 seconds")
        self.assertEqual("SIGTERM", caught.exception.ended)
        empty = [i for i, (_, result) in enumerate(calls) if result == "ESRCH"]
        self.assertTrue(empty, f"the group was seen empty: {calls}")
        self.assertEqual(empty[0] + 1, len(calls), f"nothing is signalled after the group answered ESRCH: {calls}")
        self.assertTrue(made[0].stdout.closed and made[0].stderr.closed, "the helper closed the command's pipes")
        self.assertIsInstance(caught.exception.stderr, str)
        self.assertIn("x\n", caught.exception.stderr, "the output read so far is kept, decoded")
        self.assertGone("escaped", within=3.0)  # its next write meets a closed pipe

    def test_a_timeout_whose_partial_output_ends_in_the_middle_of_a_character_is_still_a_timeout(self):
        # What was read stops wherever the command was: here after two of the three bytes of a character. Decoded with the
        # pipe's strict errors that raised UnicodeDecodeError in place of the Timeout (kjelly/pilot#427, review F2).
        body = "printf 'out \\344\\270'\nprintf 'err \\344' >&2\nsleep 30\n"
        with self.assertRaises(bounded_run.Timeout) as caught:
            self.run_bounded(self.sh(body), limit=0.5)
        self.assertEqual(("out \ufffd", "err \ufffd"), (caught.exception.output, caught.exception.stderr))
        self.assertEqual("SIGTERM", caught.exception.ended)

    def test_a_timeout_in_binary_mode_keeps_what_was_read_as_bytes(self):
        body = "printf 'part\\377'\nsleep 30\n"
        with self.assertRaises(bounded_run.Timeout) as caught:
            self.run_bounded(self.sh(body), limit=0.5, text=False)
        self.assertEqual((b"part\xff", b""), (caught.exception.output, caught.exception.stderr))

    def test_a_group_that_cannot_be_signalled_does_not_turn_the_timeout_into_a_crash(self):
        # H10.
        def refused(pgid, sig):
            raise PermissionError(1, "Operation not permitted")
        with patch.object(bounded_run.os, "killpg", refused), warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)  # the command cannot be ended here, and is collected running
            with self.assertRaises(bounded_run.Timeout) as caught:
                self.run_bounded(self.sh("trap '' TERM\nsleep 30\n"), limit=0.3, kill_after=0.3, drain=0.2)
        self.assertEqual("not signalled (EPERM)", caught.exception.ended)
        self.assertLess(self.took, 4, "the pipes were still drained and closed within the bound")

    def test_an_exception_of_any_other_kind_ends_the_group_and_is_raised(self):
        def explode(_signum, _frame):
            if self.armed:
                raise SystemExit("from a signal handler")
        before = signal.signal(signal.SIGALRM, explode)
        self.addCleanup(signal.signal, signal.SIGALRM, before)
        body = f"sleep 30 &\necho $! > {self.root}/child\ntouch {self.root}/ready\nwait\n"
        self.interrupts(0.2, sig=signal.SIGALRM)  # once the command runs, as the interrupt tests do
        with self.assertRaises(SystemExit):
            self.run_bounded(self.sh(body), limit=10)
        self.assertLess(self.took, 3)
        self.assertGone("child")
        self.assertGroupGone()


class InterruptTests(Case):
    """A Ctrl-C reaches Python only (the command has a session of its own)."""

    def test_an_interrupt_ends_the_group_with_sigterm_first_and_is_raised(self):
        # H6, first half.
        body = (f"trap 'echo term > {self.root}/term; kill $!; wait $!; exit 143' TERM\nsleep 30 &\n"
                f"touch {self.root}/ready\nwait\n")
        self.interrupts(0.2)
        with self.assertRaises(KeyboardInterrupt):
            self.run_bounded(self.sh(body), limit=20)
        self.assertLess(self.took, 3)
        self.assertTrue((self.root / "term").exists(), "SIGTERM first")
        self.assertGroupGone()

    def test_a_second_interrupt_ends_the_group_at_once(self):
        # H6, second half: a command that ignores SIGTERM, and a kill_after of 20 seconds.
        self.interrupts(0.2, 0.6)
        with self.assertRaises(KeyboardInterrupt):
            self.run_bounded(self.sh(f"trap '' TERM\ntouch {self.root}/ready\nsleep 30\n"), limit=20, kill_after=20)
        self.assertLess(self.took, 3, "not kill_after (20 s)")
        self.assertGroupGone()

    def test_in_finish_mode_an_interrupted_command_is_waited_for_and_the_interrupt_raised_afterwards(self):
        # H7.
        self.interrupts(0.2)
        with self.assertRaises(KeyboardInterrupt):  # the result is not returned: the interrupt was not swallowed
            self.run_bounded(self.sh(f"touch {self.root}/ready\nsleep 0.7\necho finished > {self.root}/finished\n"),
                             limit=20, on_interrupt="finish")
        self.assertEqual("finished\n", (self.root / "finished").read_text(), "it ran to its end before the interrupt left")
        self.assertGreater(self.took, 0.6)

    def test_in_finish_mode_a_second_interrupt_is_absorbed_until_the_deadline(self):
        self.interrupts(0.2, 0.2)
        with self.assertRaises(KeyboardInterrupt):
            self.run_bounded(self.sh(f"touch {self.root}/ready\nsleep 0.8\necho finished > {self.root}/finished\n"),
                             limit=20, on_interrupt="finish")
        self.assertTrue((self.root / "finished").exists(), "the second interrupt did not end the command")

    def test_in_finish_mode_the_deadline_counts_from_the_start_and_the_interrupt_is_raised_not_the_timeout(self):
        # H7: a command that outlives its limit; the interrupt came at 1.0 s of 1.5.
        self.interrupts(1.0)
        with self.assertRaises(KeyboardInterrupt):  # a Timeout is no KeyboardInterrupt: it would be an error here
            self.run_bounded(self.sh(f"touch {self.root}/ready\n" + LEADER_ENDS_ON_SIGTERM), limit=1.5,
                             on_interrupt="finish")
        self.assertGreater(self.took, 1.4, "an interrupted command is still waited for, up to its limit")
        self.assertLess(self.took, 2.2, "the limit counts from the start of the call (a deadline from the interrupt: 2.5 s)")
        self.assertGroupGone()

    def test_in_finish_mode_an_interrupt_while_the_group_is_being_ended_kills_it_at_once(self):
        # The deadline is reached with the first interrupt saved; SIGTERM is ignored, kill_after is 20 s, and a second
        # interrupt arrives while the group is being ended.
        self.interrupts(0.1, 0.7)
        with self.assertRaises(KeyboardInterrupt):
            self.run_bounded(self.sh(f"trap '' TERM\ntouch {self.root}/ready\nsleep 30\n"), limit=0.5, kill_after=20,
                             on_interrupt="finish")
        self.assertLess(self.took, 4, "not kill_after (20 s)")
        self.assertGroupGone()


class InputAndArgumentTests(Case):
    def test_input_goes_to_the_first_read_only_also_when_the_command_is_slow(self):
        # H8: `cat` starts after 0.4 s, so the output read times out several times (poll 0.1) before it arrives.
        for text, data in ((True, "hello\n"), (False, b"bytes\n")):
            with self.subTest(text=text):
                done, took = self.run_bounded(self.sh("sleep 0.4\ncat\n"), limit=10, text=text, input=data, poll=0.1)
                self.assertEqual((0, data), (done.returncode, done.stdout))
                self.assertLess(took, 3)

    def test_an_empty_input_is_still_an_input(self):
        done, _ = self.run_bounded(self.sh("cat\n"), limit=5, input="")
        self.assertEqual((0, ""), (done.returncode, done.stdout))

    def test_a_limit_that_is_not_a_positive_finite_number_is_refused_before_anything_starts(self):
        # H9.
        with patch.object(bounded_run.subprocess, "Popen", side_effect=AssertionError("started")):
            for limit in (None, 0, -1, float("inf"), float("nan"), True, "5", [5]):
                with self.subTest(limit=limit), self.assertRaises(ValueError):
                    bounded_run.run(["true"], limit=limit)
            for name, value in (("kill_after", -1), ("kill_after", float("nan")), ("drain", float("inf")), ("poll", 0),
                                ("poll", -1)):
                with self.subTest(**{name: value}), self.assertRaises(ValueError):
                    bounded_run.run(["true"], limit=5, **{name: value})
            with self.assertRaises(ValueError):
                bounded_run.run(["true"], limit=5, on_interrupt="ignore")
            with self.assertRaises(TypeError):  # no default: the limit has to be named
                bounded_run.run(["true"])

    def test_a_program_that_does_not_exist_is_an_oserror(self):
        # H11.
        with self.assertRaises(FileNotFoundError):
            bounded_run.run([str(self.root / "no-such-program")], limit=5)


if __name__ == "__main__":
    unittest.main()
