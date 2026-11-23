"""scripts/pr_loop.py against a REAL tmux (kjelly/pilot#425): the sessions, windows and panes the runner makes and closes.

The fake tmux of the other tests is a model of what tmux does; this module checks the runner, and the facts that model
rests on, against the real thing. It runs on a tmux server of its own:

- the server lives in a private directory (`TMUX_TMPDIR`), and a keeper session started with `-f /dev/null` (no
  configuration file is read) holds it open; before anything of the runner is started, the test asks tmux for the
  `#{socket_path}` its plain `tmux` reaches and fails when that is not inside the private directory;
- `TMUX` and `TMUX_PANE` are removed from the environment (they would point a tmux at the developer's own server) and
  `HOME` is a temporary directory; the server is killed with an explicit `-S <its socket>`, never by name or by default.

No test here may reach the default server. Without tmux the tests are skipped, unless `PR_LOOP_REQUIRE_TMUX=1` (CI): then
a missing tmux fails them. The agent is a script that prints a prompt and sleeps.

`--clean` (kjelly/pilot#442) rests on facts about tmux that the fake of the other tests copies from tmux 3.8: what `list-panes` prints
for a dead pane, a pane that was started again, a split of yours, a grouped twin, a value with a `|` or a newline in it
(`#{q:...}`), and how a start command is shown. They are asserted here against the real thing, and a tmux that says them
differently (CI's is the one apt gives the runner image, probably older than 3.8) fails these tests and not the fake's.
"""
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "scripts"))
import pr_loop
import pr_loop_fakes
from pr_loop_fakes import LIST_FORMAT, UPDATE_ENVIRONMENT, FakeEnv

SOCKET_LIMIT = 100  # a Unix socket path is limited to 107 bytes; stay well inside


class RealTmuxCase(unittest.TestCase):
    """A real tmux server of its own, a dummy agent, and `agent()`, which starts one the way the runner does."""
    PROMPT_AGENT = "#!/bin/sh\nprintf '\\342\\235\\257\\n'\nexec sleep 600\n"  # prints the prompt character, then sleeps

    def setUp(self):
        if shutil.which("tmux") is None:
            if os.environ.get("PR_LOOP_REQUIRE_TMUX") == "1":
                self.fail("tmux is not installed and PR_LOOP_REQUIRE_TMUX=1: the real-tmux tests are required here")
            self.skipTest("tmux is not installed")
        temp = tempfile.TemporaryDirectory(prefix="prl-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.socket = self.root / f"tmux-{os.getuid()}" / "default"
        if len(os.fsencode(self.socket)) >= SOCKET_LIMIT:
            self.skipTest(f"the socket path {self.socket} would be {len(os.fsencode(self.socket))} bytes long")
        self.socket.parent.mkdir(mode=0o700)
        self.bin, self.home = self.root / "bin", self.root / "home"
        self.bin.mkdir()
        self.home.mkdir()
        env = {name: value for name, value in os.environ.items()
               if name not in ("TMUX", "TMUX_PANE", *UPDATE_ENVIRONMENT)}
        env.update(TMUX_TMPDIR=str(self.root), HOME=str(self.home), PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        patcher = patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        told = patch.object(pr_loop, "tell")
        told.start()
        self.addCleanup(told.stop)
        self.start_keeper()
        # Whatever is on the private socket at the end goes: explicitly that socket, never a name or the default.
        self.addCleanup(subprocess.run, ["tmux", "-S", str(self.socket), "kill-server"], capture_output=True, timeout=30)

    def start_keeper(self):
        """The keeper: a session of its own that keeps the server alive when the last session of a test goes (a server exits
        with its last session). Started on the private socket explicitly, so that nothing can reach any other server while the
        environment is not yet checked; then the check: what the runner's plain `tmux` reaches must be this server, it finds the
        keeper and its socket is in the private directory. Everything the runner does goes through that plain `tmux`. A test that
        lets the server exit calls this again for the next one, and the check is made again."""
        self.keeper = "pr-loop-keeper-" + uuid.uuid4().hex[:8]
        done = subprocess.run(["tmux", "-S", str(self.socket), "-f", "/dev/null", "new-session", "-d", "-s", self.keeper,
                               "exec sleep 600"], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        self.assertEqual(0, done.returncode, done.stderr)
        rc, out, err = self.tmux("display-message", "-p", "-t", f"={self.keeper}:", "#{socket_path}")
        self.assertEqual((0, str(self.socket)), (rc, out.strip()), f"plain tmux does not reach the private server: {err}")
        self.assertTrue(os.path.realpath(out.strip()).startswith(os.path.realpath(self.root) + os.sep))

    def server(self):
        """`(pid, start_time)` of the tmux server on the private socket, as tmux prints them."""
        return tuple(self.tmux_ok("display-message", "-p", "-t", f"={self.keeper}:", "#{pid}|#{start_time}").split("|"))

    def kill_server(self):
        """Every session and pane goes, the server with them: explicitly the private socket, and then the wait until it is
        not answering."""
        subprocess.run(["tmux", "-S", str(self.socket), "kill-server"], capture_output=True, timeout=30,
                       stdin=subprocess.DEVNULL)
        self.wait_for("the server to be gone", lambda: self.tmux("list-sessions")[0] != 0)

    # ---- the real tmux, as the operator uses it -------------------------------------------------------------------
    @staticmethod
    def tmux(*args):
        done = subprocess.run(["tmux", *args], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        return done.returncode, done.stdout, done.stderr.strip()

    def tmux_ok(self, *args):
        rc, out, err = self.tmux(*args)
        self.assertEqual(0, rc, f"tmux {' '.join(args)}: {err}")
        return out.strip()

    def sessions(self):
        """The sessions of the server but the keeper's, name -> window names (a twin shows its group's)."""
        names = [name for name in self.tmux_ok("list-sessions", "-F", "#{session_name}").splitlines() if name != self.keeper]
        return {name: self.tmux_ok("list-windows", "-t", f"={name}:", "-F", "#{window_name}").splitlines() for name in names}

    def panes(self, session):
        return self.tmux_ok("list-panes", "-t", f"={session}:", "-s", "-F", "#{window_name}|#{pane_id}|#{pane_dead}").splitlines()

    def wait_for(self, what, test, timeout=5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            found = test()
            if found:
                return found
            time.sleep(0.02)
        self.fail(f"timed out waiting for {what}")

    # ---- the runner's side ----------------------------------------------------------------------------------------
    def script(self, name, text=PROMPT_AGENT):
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)
        return name

    def checkout(self, name="checkout"):
        path = self.root / name
        path.mkdir()
        return SimpleNamespace(path=path, session=pr_loop.session_name(path))

    def agent(self, checkout, number=7, phase="draft", executable="agent"):
        if not (self.bin / executable).exists():
            self.script(executable)
        return pr_loop.Agent(executable, checkout, number, phase)


class RealTmuxSessionTests(RealTmuxCase):
    def test_agents_are_windows_of_one_session_that_keep_the_names_they_were_given(self):
        checkout = self.checkout()
        agents = [self.agent(checkout, 7, "draft"), self.agent(checkout, 7, "ready"), self.agent(checkout, 8, "draft")]
        self.assertEqual({checkout.session: ["7-draft", "7-ready", "8-draft"]}, self.sessions())
        self.assertEqual(3, len({agent.pane for agent in agents}))
        self.assertEqual({self.server()}, {agent.server for agent in agents}, "each agent has the PID and start time of the server")
        for agent in agents:
            self.assertEqual((False, False), agent.status()[:2])
        # `-n` turns automatic renaming off: the window is not renamed after the program in it (`sleep`, or `sh`)
        self.wait_for("the agents' script to reach sleep", lambda: all(
            self.tmux_ok("display-message", "-p", "-t", agent.pane, "#{pane_current_command}") == "sleep" for agent in agents))
        self.assertEqual({checkout.session: ["7-draft", "7-ready", "8-draft"]}, self.sessions())
        self.assertEqual("❯", self.tmux_ok("capture-pane", "-p", "-J", "-t", agents[0].pane).splitlines()[0])
        self.assertTrue(agents[0].wait_for_prompt(5), "the dummy agent is at an input prompt, as the runner reads it")

    def test_the_agent_starts_in_the_checkout_and_keeps_its_pane_when_it_exits(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        self.assertEqual(str(checkout.path), self.tmux_ok("display-message", "-p", "-t", agent.pane, "#{pane_current_path}"))
        self.assertEqual("on", self.tmux_ok("show-options", "-wv", "-t", agent.pane, "remain-on-exit"))
        pid = int(self.tmux_ok("display-message", "-p", "-t", agent.pane, "#{pane_pid}"))
        os.kill(pid, signal.SIGKILL)
        self.assertTrue(self.wait_for("the pane to be dead", lambda: agent.status()[0]))
        self.assertEqual({checkout.session: ["7-draft"]}, self.sessions(), "the dead pane is kept")

    def test_closing_an_agent_removes_its_window_only_and_a_pane_the_operator_split_off_survives(self):
        checkout = self.checkout()
        first, second = self.agent(checkout, 7, "draft"), self.agent(checkout, 7, "ready")
        split = self.tmux_ok("split-window", "-d", "-t", first.pane, "-P", "-F", "#{pane_id}", "exec sleep 600")
        first.close()
        self.assertEqual({checkout.session: ["7-draft", "7-ready"]}, self.sessions(), "the window stays: a pane is left in it")
        self.assertEqual([f"7-draft|{split}|0", f"7-ready|{second.pane}|0"], self.panes(checkout.session))
        second.close()
        self.assertEqual({checkout.session: ["7-draft"]}, self.sessions(), "only the closed agent's window went")
        self.tmux_ok("kill-pane", "-t", split)
        self.assertEqual({}, self.sessions(), "the session ended with its last window")

    def test_closing_the_last_agent_ends_the_session_and_its_grouped_twin(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        twin = checkout.session + "-eink"
        self.tmux_ok("new-session", "-d", "-t", checkout.session, "-s", twin)
        self.assertEqual({checkout.session: ["7-draft"], twin: ["7-draft"]}, self.sessions())
        agent.close()
        self.assertEqual({}, self.sessions())
        agent.close()  # and a pane that is gone is closed

    def test_a_session_the_operator_killed_is_made_again_and_the_twin_it_leaves_is_not_used(self):
        checkout = self.checkout()
        self.agent(checkout, 7, "draft")
        twin = checkout.session + "-eink"
        self.tmux_ok("new-session", "-d", "-t", checkout.session, "-s", twin)
        self.tmux_ok("kill-session", "-t", f"={checkout.session}")
        self.assertEqual({twin: ["7-draft"]}, self.sessions(), "the twin outlives the session and keeps the windows")
        agent = self.agent(checkout, 7, "ready")
        self.assertEqual({twin: ["7-draft"], checkout.session: ["7-ready"]}, self.sessions(),
                         "a session of its own, not a window in the operator's twin")
        self.assertEqual(checkout.session, self.tmux_ok("display-message", "-p", "-t", agent.pane, "#{session_name}"))

    def test_hostile_directory_names_make_sessions_tmux_can_address(self):
        for basename in ("my repo", "colon:name", "dotted.name", "tab\there", "x" * 40, "café", "-dash", "quo'te", "="):
            with self.subTest(basename=basename):
                checkout = self.checkout(basename)
                first, second = self.agent(checkout, 7, "draft"), self.agent(checkout, 7, "ready")
                self.assertEqual(checkout.session, self.tmux_ok("display-message", "-p", "-t", f"={checkout.session}:",
                                                                "#{session_name}"), "addressable, and not renamed")
                self.assertEqual(["7-draft", "7-ready"], self.sessions()[checkout.session])
                for agent in (first, second):
                    self.assertEqual(str(checkout.path), self.tmux_ok("display-message", "-p", "-t", agent.pane,
                                                                      "#{pane_current_path}"))
                    agent.close()
                self.assertNotIn(checkout.session, self.sessions())


class RealTmuxServerIdentityTests(RealTmuxCase):
    """A pane ID is only unique within one tmux server (kjelly/pilot#425, review of db19ac69), and a server exits with its last
    session. The module's own keeper normally prevents that; here the server is killed and started again, the way it goes
    when the operator kills the runner's session and has no other session, so that the next server gives the old pane's ID to
    another pane. The new keeper is started on the private socket explicitly and the socket is checked again."""

    def restarted(self, checkout):
        """An agent A of a server that has exited, and a new server (a new keeper, `%0`) that has not made `%1` yet."""
        old = self.agent(checkout, 7, "draft", "agent-a")
        self.assertEqual("%1", old.pane, "the keeper has %0")
        before = self.server()
        self.kill_server()
        self.start_keeper()
        self.assertNotEqual(before, self.server(), "another server: another PID, and another start time unless it is the same second")
        return old

    def test_the_new_agent_has_the_old_agents_pane_id_and_closing_the_old_one_leaves_it_alone(self):
        checkout = self.checkout()
        old = self.restarted(checkout)
        new = self.agent(checkout, 7, "ready", "agent-b")
        self.assertEqual(old.pane, new.pane, "the IDs collide: the new server numbers its panes again")
        self.assertNotEqual(old.server, new.server)
        self.assertEqual(new.server, self.server())
        old.close()
        self.assertEqual({checkout.session: ["7-ready"]}, self.sessions(), "the new agent is still there")
        self.assertEqual([f"7-ready|{new.pane}|0"], self.panes(checkout.session))
        self.assertEqual((False, False), new.status()[:2], "and it can still be read")
        with self.assertRaisesRegex(pr_loop.Stop, rf"^agent pane {old.pane} \(window 7-draft of tmux session "
                                                  rf"{re.escape(checkout.session)}\) is not the pane this agent was started in"):
            old.status()
        new.close()  # the control: the agent that owns the pane kills it
        self.assertEqual({}, self.sessions())

    def test_the_old_id_that_is_now_a_pane_of_the_operators_survives_and_nothing_is_pasted_into_it(self):
        checkout = self.checkout()
        old = self.restarted(checkout)
        ops = self.tmux_ok("new-session", "-d", "-s", "ops", "-P", "-F", "#{pane_id}", "exec sleep 600")
        self.assertEqual(old.pane, ops, "the operator's pane has the old agent's ID")
        old.close()
        self.assertEqual(["ops"], list(self.sessions()), "the operator's session is there")
        self.assertEqual([(ops, "0")], [tuple(row.split("|")[1:]) for row in self.panes("ops")], "and its pane is alive")
        with self.assertRaisesRegex(pr_loop.Stop, "is not the pane this agent was started in"):
            old.submit("typed into the operator's pane")
        self.assertEqual("", self.tmux_ok("list-buffers"), "nothing was loaded: the check comes first")
        self.assertNotIn("typed", self.tmux_ok("capture-pane", "-p", "-t", ops))

    def test_a_server_that_is_gone_means_the_pane_is_closed_and_a_stop_for_an_active_agent(self):
        checkout = self.checkout()
        old = self.agent(checkout)
        self.kill_server()
        old.close()  # `no server running on <the socket left behind>`: closed already
        with self.assertRaisesRegex(pr_loop.Stop, "is not the pane this agent was started in"):
            old.status()
        self.socket.unlink()  # and with no socket at all: `error connecting to ... (No such file or directory)`
        old.close()
        with self.assertRaisesRegex(pr_loop.Stop, "is not the pane this agent was started in"):
            old.submit("x")

    def test_a_pane_the_server_has_not_got_is_empty_fields_with_the_servers_own_and_exit_status_0(self):
        # The fake tmux says the same (FakeTmuxTests): this is the capture it rests on.
        checkout = self.checkout()
        agent = self.agent(checkout)
        pid, started = self.server()
        self.wait_for("the agent's script to reach sleep", lambda: self.tmux_ok(
            "display-message", "-p", "-t", agent.pane, "#{pane_current_command}") == "sleep")
        self.assertEqual((0, f"0|0|sleep|{pid}|{started}\n", ""), self.tmux("display-message", "-p", "-t", agent.pane,
                                                                            pr_loop.READ_FORMAT))
        self.assertEqual((0, f"|||{pid}|{started}\n", ""), self.tmux("display-message", "-p", "-t", "%987", pr_loop.READ_FORMAT))
        # The operator kills the session; the keeper keeps the server: the pane is gone on a server that is still there
        self.tmux_ok("kill-session", "-t", f"={checkout.session}")
        self.assertEqual((0, f"|||{pid}|{started}\n", ""), self.tmux("display-message", "-p", "-t", agent.pane,
                                                                    pr_loop.READ_FORMAT))
        agent.close()
        with self.assertRaisesRegex(pr_loop.Stop, "is not the pane this agent was started in"):
            agent.status()
        self.assertEqual({}, self.sessions())


class RealTmuxAnswerTests(RealTmuxCase):
    """The texts the runner compares exactly, as THIS tmux says them: when a tmux version words one differently these fail,
    and the runner must be looked at before the fake (pr_loop_fakes.py) is."""

    def test_a_session_name_in_use_is_a_duplicate_and_a_missing_one_cannot_be_found(self):
        checkout = self.checkout()
        self.agent(checkout)
        s = checkout.session
        new = ("new-session", "-d", "-s", s, "-n", "w", "-P", "-F", "#{pane_id}", "--", "exec sleep 600")
        self.assertEqual((1, "", f"duplicate session: {s}"), self.tmux(*new))
        self.assertEqual((1, "", f"can't find session: {s}-nothing"),
                         self.tmux("new-window", "-d", "-t", f"={s}-nothing:", "-P", "-F", "#{pane_id}", "--", "x"))
        self.assertEqual((1, "", "can't find pane: %9999"), self.tmux("kill-pane", "-t", "%9999"))

    def test_an_exact_target_never_reaches_a_session_whose_name_merely_starts_with_it(self):
        s = "pilot-pr-prefix-0123abcd"
        self.tmux_ok("new-session", "-d", "-s", s + "-eink", "exec sleep 600")  # the operator's session; S itself does not exist
        window = ("-d", "-P", "-F", "#{session_name}", "--", "exec sleep 600")
        self.assertEqual((1, "", f"can't find session: {s}"), self.tmux("new-window", "-t", f"={s}:", *window))
        self.assertEqual(1, len(self.sessions()[s + "-eink"]), "the exact target made nothing")
        rc, out, _ = self.tmux("new-window", "-t", f"{s}:", *window)  # prints the session that got the window
        self.assertEqual((0, s + "-eink"), (rc, out.strip()), "the inexact target fell back to the operator's session: "
                                                              "why the runner never uses it")
        self.assertEqual(2, len(self.sessions()[s + "-eink"]))


class RealTmuxPaneTests(RealTmuxCase):
    def test_the_runners_own_check_refuses_a_live_agent_pane_in_the_checkout_and_passes_a_dead_one(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        with self.assertRaisesRegex(pr_loop.Stop, rf"^agent pane {agent.pane} \(session {checkout.session}\) is still "
                                                  rf"running in {re.escape(str(checkout.path))}; inspect and close it "
                                                  r"before starting the runner again \(python3 scripts/pr_loop.py --clean lists "
                                                  r"what an earlier run left\)$"):
            pr_loop.check_panes(checkout.path)
        other = self.checkout("elsewhere")
        pr_loop.check_panes(other.path)  # control: a live pane in another directory is not in the way
        os.kill(int(self.tmux_ok("display-message", "-p", "-t", agent.pane, "#{pane_pid}")), signal.SIGKILL)
        self.wait_for("the pane to be dead", lambda: agent.status()[0])
        pr_loop.check_panes(checkout.path)  # a dead pane has no path: not in the way
        (found,) = [pane for pane in pr_loop.list_panes()[0] if pane.pane == agent.pane]
        self.assertEqual((checkout.session, True, ""), (found.session, found.dead, found.path), "dead, and no path")

    def test_a_twin_of_the_session_repeats_its_panes_and_still_refuses(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        self.tmux_ok("new-session", "-d", "-t", checkout.session, "-s", checkout.session + "-eink")
        rows = [(pane.session, pane.pane, pane.dead, pane.path) for pane in pr_loop.list_panes()[0]
                if pane.session.startswith(checkout.session)]
        self.assertEqual([(checkout.session, agent.pane, False, str(checkout.path)),
                          (checkout.session + "-eink", agent.pane, False, str(checkout.path))], rows)
        with self.assertRaisesRegex(pr_loop.Stop, rf"agent pane {agent.pane} \(session {checkout.session}\)"):
            pr_loop.check_panes(checkout.path)


class RealTmuxEnvironmentTests(RealTmuxCase):
    """A window of an existing session takes the SESSION's values of tmux's `update-environment` names, not the runner's:
    the runner passes its own, so that every agent sees the runner's environment (the operator signs commits through
    SSH_AUTH_SOCK)."""

    def recorder(self, name, *variables):
        """An agent that records its values of `variables` (default SSH_AUTH_SOCK), joined by `|`, in a file;
        `(executable, file)`."""
        out = self.root / f"{name}.out"
        shown = "|".join(f"${{{variable}}}" for variable in variables or ("SSH_AUTH_SOCK",))
        self.script(name, f"#!/bin/sh\nprintf '%s' \"{shown}\" > '{out}'\nexec sleep 600\n")
        return name, out

    def recorded(self, out):
        return self.wait_for("the agent to record its environment", lambda: out.exists() and out.read_text() or None)

    def test_a_later_agent_sees_the_runners_value_not_the_one_the_session_was_made_with(self):
        checkout = self.checkout()
        (first, first_out), (second, second_out), (third, third_out) = (self.recorder(n) for n in ("one", "two", "three"))
        with patch.dict(os.environ, {"SSH_AUTH_SOCK": "/synthetic/earlier.sock"}):
            self.agent(checkout, 7, "draft", first)
        with patch.dict(os.environ, {"SSH_AUTH_SOCK": "/synthetic/later.sock"}):
            self.agent(checkout, 7, "ready", second)
            # What the window would have got without the runner's `-e`: the session's value
            self.tmux_ok("new-window", "-d", "-t", f"={checkout.session}:", "-c", str(checkout.path), f"exec {self.bin / third}")
        self.assertEqual("/synthetic/earlier.sock", self.recorded(first_out), "a new session takes the runner's")
        self.assertEqual("/synthetic/later.sock", self.recorded(second_out), "a new window takes the runner's with -e")
        self.assertEqual("/synthetic/earlier.sock", self.recorded(third_out), "without -e it takes the session's: what -e fixes")

    def test_a_pattern_of_update_environment_is_matched_the_way_tmux_matches_it(self):
        # tmux 3.8 copies every variable of the client that an entry of the list matches: `FOO_*` copies `FOO_X` (captured on a
        # private server). The runner passes the runner's value of each such variable to a new window, and only those.
        self.tmux_ok("set-option", "-g", "update-environment", "FOO_*")
        self.assertEqual("FOO_*", self.tmux_ok("show-options", "-gv", "update-environment"))
        checkout = self.checkout()
        (first, first_out), (second, second_out), (third, third_out) = (
            self.recorder(name, "FOO_X", "FOO_Y", "BAR") for name in ("one", "two", "three"))
        with patch.dict(os.environ, {"FOO_X": "earlier", "FOO_Y": "y1", "BAR": "b1"}):
            self.agent(checkout, 7, "draft", first)
        with patch.dict(os.environ, {"FOO_X": "later", "FOO_Y": "y2", "BAR": "b2"}):
            self.agent(checkout, 7, "ready", second)
            self.tmux_ok("new-window", "-d", "-t", f"={checkout.session}:", "-c", str(checkout.path), f"exec {self.bin / third}")
        self.assertEqual("earlier|y1|", self.recorded(first_out), "a new session takes what the pattern matches, not BAR")
        self.assertEqual("later|y2|", self.recorded(second_out), "a new window takes the runner's, for every match, not BAR")
        self.assertEqual("earlier|y1|", self.recorded(third_out), "without -e it takes the session's: what -e fixes")

    def test_a_name_the_runner_does_not_have_is_not_passed_and_a_session_value_stays(self):
        checkout = self.checkout()
        first, first_out = self.recorder("one")
        second, second_out = self.recorder("two")
        with patch.dict(os.environ, {"SSH_AUTH_SOCK": "/synthetic/earlier.sock"}):
            self.agent(checkout, 7, "draft", first)
        with patch.dict(os.environ):
            os.environ.pop("SSH_AUTH_SOCK", None)
            self.agent(checkout, 7, "ready", second)
        self.assertEqual("/synthetic/earlier.sock", self.recorded(first_out))
        self.assertEqual("/synthetic/earlier.sock", self.recorded(second_out), "nothing to pass: the session's value stays")


def model(name, *args):
    """A function of the fake tmux's model (the one embedded in the fake), to compare what it says with what the real tmux says."""
    return pr_loop_fakes._model[name](*args)


class RealTmuxListingTests(RealTmuxCase):
    """The facts `--clean` and the fake tmux of the other tests rest on, asserted against this tmux (kjelly/pilot#442). A test here
    that fails on another tmux version tells which fact the fake has wrong for that version, before a test of the runner does."""

    def panes(self, *, checkout=None):
        """Every pane of the server as the runner reads it (`pr_loop.list_panes`), by pane ID."""
        found, said = pr_loop.list_panes()
        self.assertEqual("", said)
        return {pane.pane: pane for pane in found}

    def test_the_runner_reads_the_pane_it_started_as_its_own_and_the_start_command_is_shown_in_a_form_it_reads(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        pane = self.panes()[agent.pane]
        self.assertEqual((checkout.session, "7-draft", str(checkout.path), False, False, self.server(), str(self.socket)),
                         (pane.session, pane.window, pane.start_path, pane.dead, pane.in_mode, pane.server, pane.socket))
        executable = str(self.bin / "agent")
        given = "exec " + shlex.quote(executable)
        self.assertIn(pane.start_command, (model("start_shown", [given]), given),
                      "tmux shows the command either between double quotes, as 3.8 does, or as it was given; both are read")
        self.assertEqual(executable, pr_loop.started_with(pane.start_command))
        self.assertTrue(pr_loop.runners_own(pane, checkout.path, checkout.session))
        self.assertTrue(re.fullmatch(r"[0-9]+", pane.pid), "an alive pane has a process")
        self.assertEqual(int(self.tmux_ok("display-message", "-p", "-t", agent.pane, "#{pane_pid}")), int(pane.pid))
        self.wait_for("the agent's script to reach sleep", lambda: self.panes()[agent.pane].command == "sleep")

    def test_a_dead_pane_has_no_path_keeps_how_it_was_started_and_can_still_be_read(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        self.assertTrue(agent.wait_for_prompt(5), "the agent has printed its prompt")
        before = self.panes()[agent.pane]
        os.kill(int(before.pid), signal.SIGKILL)
        self.wait_for("the pane to be dead", lambda: self.panes()[agent.pane].dead)
        pane = self.panes()[agent.pane]
        self.assertEqual("", pane.path, "no current path")
        self.assertIn(pane.pid, ("", before.pid), "tmux 3.8 prints no process for it, 3.4 the one it had: never another")
        self.assertEqual((str(checkout.path), "7-draft", checkout.session), (pane.start_path, pane.window, pane.session))
        self.assertEqual(str(self.bin / "agent"), pr_loop.started_with(pane.start_command), "what it was started with is kept")
        self.assertTrue(pr_loop.runners_own(pane, checkout.path, checkout.session), "so it is still the runner's")
        screen = pr_loop.capture_pane(agent.pane)
        self.assertTrue(screen is not None and ("❯" in screen or "Pane is dead" in screen),
                        "and its screen can still be read, for the listing: what it showed, or what tmux says on it (3.8 "
                        "clears it and writes that the pane is dead; 3.4 keeps it for a moment first)")
        self.assertEqual("ours", pr_loop.probe_pane(agent.pane, pane.server)[0])
        self.assertEqual("ours", pr_loop.close_pane(agent.pane, pane.server), "closed with kill-pane")
        self.assertEqual({}, self.sessions())

    def test_a_pane_that_is_started_again_has_another_process_and_is_the_same_pane_in_every_other_way(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        before = self.panes()[agent.pane]
        self.tmux_ok("respawn-pane", "-k", "-t", agent.pane)
        self.wait_for("a new process", lambda: self.panes()[agent.pane].pid not in ("", before.pid))
        after = self.panes()[agent.pane]
        self.assertEqual((before.start_command, before.start_path, before.window, before.session, before.server),
                         (after.start_command, after.start_path, after.window, after.session, after.server))
        self.assertNotEqual(before.pid, after.pid)
        self.assertFalse(after.dead)

    def test_a_dead_pane_that_is_started_again_is_alive_with_a_process(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        os.kill(int(self.panes()[agent.pane].pid), signal.SIGKILL)
        self.wait_for("the pane to be dead", lambda: self.panes()[agent.pane].dead)
        self.tmux_ok("respawn-pane", "-t", agent.pane)
        self.wait_for("the pane to run again", lambda: not self.panes()[agent.pane].dead and self.panes()[agent.pane].pid)

    def test_a_split_of_yours_is_not_started_with_exec_whatever_its_directory_and_window_are(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        shell = self.tmux_ok("split-window", "-d", "-t", agent.pane, "-c", str(checkout.path), "-P", "-F", "#{pane_id}")
        command = self.tmux_ok("split-window", "-d", "-t", agent.pane, "-c", str(checkout.path), "-P", "-F", "#{pane_id}",
                               "tail -f /dev/null")
        words = self.tmux_ok("split-window", "-d", "-t", agent.pane, "-c", str(checkout.path), "-P", "-F", "#{pane_id}",
                             "tail", "-f", "/dev/null")
        panes = self.panes()
        for found in (shell, command, words):
            pane = panes[found]
            with self.subTest(pane=found):
                self.assertEqual((checkout.session, "7-draft", str(checkout.path)), (pane.session, pane.window, pane.start_path),
                                 "everything but how it was started says the runner's")
                self.assertFalse(pr_loop.runners_own(pane, checkout.path, checkout.session))
                self.assertIn(found, [blocking.pane for blocking in pr_loop.blocking_panes(checkout.path)],
                              "and it is in the way of the next run")
        self.assertEqual("", panes[shell].start_command, "the shell: no command")
        self.assertEqual(model("start_shown", ["tail -f /dev/null"]), panes[command].start_command)
        self.assertEqual(model("start_shown", ["tail", "-f", "/dev/null"]), panes[words].start_command)
        self.assertTrue(pr_loop.runners_own(panes[agent.pane], checkout.path, checkout.session), "control: the agent")

    def test_a_renamed_window_is_listed_under_its_new_name_and_is_no_longer_an_agents(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        self.tmux_ok("rename-window", "-t", agent.pane, "mine")
        pane = self.panes()[agent.pane]
        self.assertEqual("mine", pane.window)
        self.assertFalse(pr_loop.runners_own(pane, checkout.path, checkout.session))

    def test_where_a_pane_is_now_is_not_where_it_was_started(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        moved = self.tmux_ok("new-window", "-d", "-t", f"={checkout.session}:", "-n", "9-draft", "-c", str(checkout.path), "-P", "-F",
                             "#{pane_id}", f"cd {shlex.quote(str(elsewhere))} && exec sleep 600")
        self.wait_for("the pane to move", lambda: self.panes()[moved].path == str(elsewhere))
        pane = self.panes()[moved]
        self.assertEqual((str(checkout.path), str(elsewhere)), (pane.start_path, pane.path))
        self.assertNotIn(moved, [blocking.pane for blocking in pr_loop.blocking_panes(checkout.path)],
                         "it is not in the checkout now, so it is not in the way of the next run")
        self.assertIn(agent.pane, [blocking.pane for blocking in pr_loop.blocking_panes(checkout.path)], "control")

    def test_a_pane_in_copy_mode_says_so(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        self.tmux_ok("copy-mode", "-t", agent.pane)
        self.assertTrue(self.panes()[agent.pane].in_mode)
        self.tmux_ok("send-keys", "-t", agent.pane, "-X", "cancel")
        self.wait_for("copy mode to end", lambda: not self.panes()[agent.pane].in_mode)

    def test_the_twin_of_a_session_repeats_its_panes_with_the_same_ids_and_the_row_of_the_session_is_the_one_kept(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        twin = checkout.session + "-eink"
        self.tmux_ok("new-session", "-d", "-t", checkout.session, "-s", twin)
        found, _ = pr_loop.list_panes()
        rows = [pane for pane in found if pane.pane == agent.pane]
        self.assertEqual([checkout.session, twin], sorted(pane.session for pane in rows))
        self.assertEqual(1, len({(pane.window_id, pane.pid, pane.start_command, pane.start_path) for pane in rows}),
                         "one pane, shown twice")
        (kept,) = [pane for pane in pr_loop.distinct(found, checkout.session) if pane.pane == agent.pane]
        self.assertEqual(checkout.session, kept.session)
        self.assertTrue(pr_loop.runners_own(kept, checkout.path, checkout.session))
        self.assertFalse(pr_loop.runners_own([pane for pane in rows if pane.session == twin][0], checkout.path, checkout.session),
                         "the twin's row is not the runner's session")

    def test_a_window_knows_its_panes_so_that_the_last_one_of_it_can_be_told(self):
        checkout = self.checkout()
        first, second = self.agent(checkout, 7, "draft"), self.agent(checkout, 7, "ready")
        split = self.tmux_ok("split-window", "-d", "-t", first.pane, "-P", "-F", "#{pane_id}")
        panes = self.panes()
        self.assertEqual(panes[first.pane].window_id, panes[split].window_id)
        self.assertNotEqual(panes[first.pane].window_id, panes[second.pane].window_id)
        self.assertTrue(re.fullmatch(r"@[0-9]+", panes[first.pane].window_id))

    def test_a_value_the_format_quotes_comes_back_as_it_was_whatever_it_holds(self):
        # A directory is the free text a user chooses most freely: every character that is special to a shell, a newline, a
        # backslash, a bar and non-ASCII. They are in the start directory of a real pane, listed by the runner's own format.
        names = [f"x{char}y" for char in "|&;<>()$`\"'*?[#=%{}!~^ ,:@+-.]"] + ["x\\y", "x\\\\y", "x\ny", "x\n", "\\\n", "x||y", "é日本", "||"]
        made = {}
        for number, name in enumerate(names):
            where = self.root / f"dirs{number}" / name
            where.mkdir(parents=True)
            session = f"hostile-{number}"
            self.tmux_ok("new-session", "-d", "-s", session, "-n", "w", "-c", str(where), "exec sleep 600")
            made[session] = where
        found = {pane.session: pane for pane in self.panes().values() if pane.session in made}
        self.assertEqual(set(made), set(found), "every row was read: none ended its row or its field early")
        for session, where in made.items():
            with self.subTest(where=repr(str(where))):
                # (tmux 3.4 writes a `$` in the directory it was told to start in with a backslash before it, in both paths)
                self.assertEqual(str(where), found[session].start_path.replace("\\$", "$"))
                self.assertEqual(str(where), found[session].path.replace("\\$", "$"))
                self.assertIn(found[session].start_command, ('"exec sleep 600"', "exec sleep 600"))

    # The characters tmux 3.8 and tmux 3.4.1 both quote in `#{q:...}` (3.8 also quotes `{`, `}` and a newline; neither is a character
    # the runner needs to find in a field, and the reader undoes whatever backslash it finds).
    QUOTED_BY_BOTH = "|&;<>()`\"'*?[# =%"

    def test_q_quotes_what_a_shell_needs_quoted_and_every_value_is_read_back_whatever_this_tmux_quotes_besides(self):
        checkout = self.checkout()
        self.agent(checkout)
        for char in [chr(code) for code in range(33, 127) if chr(code) != "\\"] + [" "]:
            with self.subTest(char=char):
                window = self.tmux_ok("new-window", "-d", "-t", f"={checkout.session}:", "-n", f"x{char}y", "-P", "-F", "#{window_id}",
                                      "exec sleep 600")
                name = self.tmux_ok("display-message", "-p", "-t", window, "#{window_name}")  # (what tmux made of the name)
                quoted = self.tmux_ok("display-message", "-p", "-t", window, "#{q:window_name}")
                self.assertEqual(name, pr_loop.unquote(quoted), "the reader gets the value back")
                if char in self.QUOTED_BY_BOTH and char in name and name == f"x{char}y":
                    self.assertEqual(model("q", name), quoted, "the fake quotes what this tmux quotes")
        where = self.root / "nl\ndir"
        where.mkdir()
        self.tmux_ok("new-session", "-d", "-s", "newline", "-n", "w", "-c", str(where), "exec sleep 600")
        rc, out, _ = self.tmux("display-message", "-p", "-t", "=newline:", "#{q:pane_start_path}")
        self.assertIn(out, (model("q", str(where)) + "\n", str(where) + "\n"),
                      "a newline in a value comes out with a backslash before it (3.8) or as it is (3.4)")
        self.assertEqual(str(where), pr_loop.unquote(out.removesuffix("\n")))

    def test_the_start_command_is_shown_as_the_fake_shows_it(self):
        checkout = self.checkout()
        self.agent(checkout)
        self.tmux_ok("set-option", "-g", "remain-on-exit", "on")  # whatever a command does, its pane stays to be read
        # (A `$` is shown differently by 3.8 and 3.4, which writes `\\\\$`: the cases below have none, and a path with one is below them.)
        cases = [["exec /bin/sleep 600"], ["exec '/bin/sleep' 600"], ["sleep", "600"], ["sleep 600 # a comment"],
                 ["sleep 600; sleep 1"], ["sleep 600 # \"quoted\""], ["sleep 600 # \\ x"], ["sleep 600 # 'a b'"],
                 ["sh", "-c", "sleep 600 # a b"], ["sh", "-c", "exec sleep 600"], ["sleep", "6 0"], ["sleep", "a\"b"],
                 ["exec " + shlex.quote("/opt/my tools/agent x")], ["exec " + shlex.quote("/o'brien/bin/claude")]]
        for words in cases:
            with self.subTest(words=words):
                pane = self.tmux_ok("new-window", "-d", "-t", f"={checkout.session}:", "-P", "-F", "#{pane_id}", *words)
                shown = self.tmux_ok("display-message", "-p", "-t", pane, "#{pane_start_command}")
                self.assertEqual(model("start_shown", words), shown)
        pane = self.tmux_ok("new-window", "-d", "-t", f"={checkout.session}:", "-P", "-F", "#{pane_id}",
                            "exec " + shlex.quote("/a$b/c d"))
        self.assertIsNotNone(pr_loop.started_with(self.tmux_ok("display-message", "-p", "-t", pane, "#{pane_start_command}")),
                             "a path with a `$` in it is shown differently by different tmux, and is still the runner's shape")

    def test_the_formats_of_the_runner_are_answered_by_this_tmux_without_an_error(self):
        checkout = self.checkout()
        self.agent(checkout)
        done = subprocess.run(["tmux", "list-panes", "-a", "-F", LIST_FORMAT], capture_output=True, text=True, timeout=30,
                              stdin=subprocess.DEVNULL)
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual("", done.stderr)
        rows = pr_loop.split_listing(done.stdout)
        self.assertEqual(2, len(rows), "the keeper's pane and the agent's")
        self.assertTrue(all(len(row) == len(LIST_FORMAT.split("|")) for row in rows), "a field for every variable")
        self.assertTrue(all(field != "" for row in rows for field in row[:9]), "no variable of the format is empty here")
        self.assertEqual(str(self.socket), pr_loop.unquote(rows[0][7]), "#{socket_path} is the private socket")

    def test_the_last_pane_of_a_session_with_a_twin_ends_both_and_the_listing_says_who_goes(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        twin = checkout.session + "-eink"
        self.tmux_ok("new-session", "-d", "-t", checkout.session, "-s", twin)
        found, _ = pr_loop.list_panes()
        (pane,) = [pane for pane in pr_loop.distinct(found, checkout.session) if pane.pane == agent.pane]
        self.assertEqual(f"window 7-draft and session {checkout.session} and the sessions grouped with it ({twin}); an attached "
                         "client is detached", pr_loop.Clean.ends(SimpleNamespace(session=checkout.session), pane, found))
        self.assertEqual("ours", pr_loop.close_pane(agent.pane, pane.server))
        self.assertEqual({}, self.sessions(), "both sessions went with the last pane")


class RealTmuxScenarioTests(unittest.TestCase):
    """kjelly/pilot#442 from the entry point to the end, on a real tmux server of its own: a first runner dispatches an agent and
    stops on the phase timeout, leaving its pane alive in window `7-draft`; the same command again is refused; `--clean` lists the
    pane and the task directory and changes nothing; `--clean --yes` closes the pane; the runner starts again. The agents are real
    processes in real panes (scripts that print a prompt, and one that then prints `Working (Ns - esc to interrupt)` forever);
    gh is the fake of the other tests, and the PR stays a Draft, so that the runner can only stop on its timeout. The screens are
    SYNTHETIC: no real agent's screen is involved."""
    SCRIPT = ROOT / "scripts" / "pr_loop.py"
    IDLE = RealTmuxCase.PROMPT_AGENT
    # An agent that prints its prompt, waits for the line the runner pastes, and then works: it prints `Working (Ns - esc to
    # interrupt)` every second, so that its screen changes and says so. (A script that waits in `sh` would show `sh` as the
    # foreground command, which the runner takes for a shell; this one is `python3`.)
    BUSY = '''#!/usr/bin/env python3
import sys, time
out = sys.stdout.buffer
out.write("❯\\n".encode())
out.flush()
sys.stdin.readline()
n = 0
while True:
    n += 1
    out.write(("Working (%ds - esc to interrupt)\\n" % n).encode())
    out.flush()
    time.sleep(1)
'''

    def setUp(self):
        if shutil.which("tmux") is None:
            if os.environ.get("PR_LOOP_REQUIRE_TMUX") == "1":
                self.fail("tmux is not installed and PR_LOOP_REQUIRE_TMUX=1: the real-tmux tests are required here")
            self.skipTest("tmux is not installed")
        self.env = FakeEnv(self, real_tmux=True)
        self.top = self.env.checkout
        self.session = pr_loop.session_name(self.top)
        for name in ("claude", "codex"):
            self.env.write_agent(name, self.IDLE)

    def agents(self, text):
        for name in ("claude", "codex"):
            self.env.write_agent(name, text)

    def program(self, *argv):
        return subprocess.run([sys.executable, "-B", str(self.SCRIPT), *argv], capture_output=True, text=True, timeout=120,
                              cwd=self.top, stdin=subprocess.DEVNULL)

    def runner(self):
        """The first runner (and the next): the PR stays a Draft, so it dispatches the agent and gives up when its timeout is up."""
        return self.program("7", "--repo", "acme/demo", "--phase-timeout", "2", "--poll-interval", "0.2", "--startup-timeout", "20")

    def sessions(self):
        done = subprocess.run(["tmux", "list-sessions", "-F", "#{session_name}"], capture_output=True, text=True, timeout=30,
                              stdin=subprocess.DEVNULL)
        return sorted(name for name in done.stdout.split() if name != "keeper")

    def panes(self):
        return {pane.pane: pane for pane in pr_loop.list_panes()[0] if pane.session == self.session}

    def refusal(self, pane):
        return (f"pr-loop: agent pane {pane} (session {self.session}) is still running in {self.top}; inspect and close it before "
                "starting the runner again (python3 scripts/pr_loop.py --clean lists what an earlier run left)\n")

    def test_a_stopped_run_is_refused_then_listed_then_cleaned_and_the_runner_starts_again(self):
        first = self.runner()
        self.assertEqual(1, first.returncode, first.stdout + first.stderr)
        self.assertIn("timed out in draft", first.stderr)
        (found,) = self.panes().values()
        pane = found.pane
        self.assertEqual((self.session, "7-draft", False), (found.session, found.window, found.dead), "the run left its agent alive")
        self.assertEqual([self.session], self.sessions())
        # 1. the same command again: refused, and the refusal says where to look
        again = self.runner()
        self.assertEqual((1, "", self.refusal(pane)), (again.returncode, again.stdout, again.stderr))
        # 2. --clean lists the pane (alive, idle) and the task directory, and changes nothing
        before = (self.panes(), sorted(path.name for path in (self.top / pr_loop.TASK_DIR).iterdir()))
        listing = self.program("--clean", "--repo", "acme/demo")
        self.assertEqual((0, ""), (listing.returncode, listing.stderr))
        lines = listing.stdout.splitlines()
        self.assertEqual(f"Residue of earlier runs in {self.top} (tmux session {self.session} on {self.env.socket}):", lines[0])
        self.assertEqual(f"pane {pane} window 7-draft: alive, idle (at its prompt), sleep; would close: it is idle; closing it ends "
                         f"window 7-draft and session {self.session}; an attached client is detached", lines[1])
        self.assertTrue(all(line.startswith("  | ") for line in lines[2:-2]), "the last lines of its screen")
        self.assertIn("  | ❯", lines)
        self.assertRegex(lines[-2], r"^task [0-9a-f]{32}: PR #7 draft, [0-9]+s old, result none; kept: task directories are "
                                    r"removed only with --remove-task-dirs$")
        self.assertEqual("would close 1 panes and remove 0 task directories; the next run would start", lines[-1])
        self.assertEqual(before, (self.panes(), sorted(path.name for path in (self.top / pr_loop.TASK_DIR).iterdir())),
                         "the listing closed and removed nothing")
        self.assertEqual(self.refusal(pane), self.runner().stderr, "and the runner is still refused")
        # 3. --clean --yes closes it
        done = self.program("--clean", "--yes")
        self.assertEqual((0, ""), (done.returncode, done.stderr))
        self.assertIn(f"pane {pane} window 7-draft: alive, idle (at its prompt), sleep; closed: it is idle; closing it ends "
                      f"window 7-draft and session {self.session}; an attached client is detached", done.stdout.splitlines())
        self.assertEqual("closed 1 panes and removed 0 task directories; the next run would start", done.stdout.splitlines()[-1])
        self.assertEqual([], self.sessions(), "the pane, its window and its session are gone; the keeper's session is not")
        # 4. the runner starts again, and a second --clean --yes finds nothing
        second = self.runner()
        self.assertEqual(1, second.returncode, second.stdout + second.stderr)
        self.assertIn("timed out in draft", second.stderr)
        self.assertRegex(second.stdout, rf"PR #7 draft agent: %[0-9]+ in window 7-draft of tmux session {self.session}")
        self.assertEqual(1, len(self.panes()))
        for name in os.listdir(self.top / pr_loop.TASK_DIR):
            self.assertRegex(name, r"^[0-9a-f]{32}$")
        done = self.program("--clean", "--yes", "--remove-task-dirs")
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual("closed 1 panes and removed 2 task directories; the next run would start", done.stdout.splitlines()[-1],
                         "both runs' task directories, now that no pane of the runner is left")
        self.assertEqual([], list((self.top / pr_loop.TASK_DIR).iterdir()))
        final = self.program("--clean", "--yes")
        self.assertEqual((0, [f"Residue of earlier runs in {self.top} (tmux session {self.session} on {self.env.socket}):",
                              "closed 0 panes and removed 0 task directories; the next run would start"]),
                         (final.returncode, final.stdout.splitlines()))

    def test_a_pane_that_is_working_is_left_open_and_closed_only_when_busy_ones_are_asked_for(self):
        self.agents(self.BUSY)
        first = self.runner()
        self.assertEqual(1, first.returncode, first.stdout + first.stderr)
        self.assertIn("timed out in draft", first.stderr)
        (found,) = self.panes().values()
        pane = found.pane
        self.assertTrue(self.wait_for_screen(pane, "esc to interrupt"), "the agent is working")
        listing = self.program("--clean")
        self.assertEqual(0, listing.returncode, listing.stderr)
        line = [line for line in listing.stdout.splitlines() if line.startswith(f"pane {pane} ")][0]
        self.assertRegex(line, rf"^pane {pane} window 7-draft: alive, busy \((working|the screen is still changing)\), python3; left "
                               "open: it is busy; busy panes are closed only with --include-busy$")
        self.assertEqual(f"would close 0 panes and remove 0 task directories; the next run would still be refused ({pane})",
                         listing.stdout.splitlines()[-1])
        done = self.program("--clean", "--yes")
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual([self.session], self.sessions(), "a busy agent's pane is not closed without --include-busy")
        self.assertEqual(self.refusal(pane), self.runner().stderr)
        done = self.program("--clean", "--yes", "--include-busy")
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertIn(f"closed: it is busy, and --include-busy was given", [line for line in done.stdout.splitlines()
                                                                               if line.startswith(f"pane {pane} ")][0])
        self.assertEqual([], self.sessions())
        self.assertEqual("closed 1 panes and removed 0 task directories; the next run would start", done.stdout.splitlines()[-1])
        self.assertNotEqual(self.refusal(pane), self.runner().stderr, "the runner starts again")

    def wait_for_screen(self, pane, text, timeout=10.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if text in (pr_loop.capture_pane(pane) or ""):
                return True
            time.sleep(0.1)
        return False

    def test_a_pane_you_opened_in_the_runners_window_is_listed_as_in_the_way_and_never_closed(self):
        self.runner()
        (agent,) = self.panes()
        split = subprocess.run(["tmux", "split-window", "-d", "-t", agent, "-c", str(self.top), "-P", "-F", "#{pane_id}"],
                               capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL).stdout.strip()
        listing = self.program("--clean")
        self.assertIn(f"not the runner's: pane {split} (session {self.session}, window 7-draft) in {self.top}: left alone; the next "
                      "run refuses because of it", listing.stdout.splitlines())
        self.assertEqual(f"would close 1 panes and remove 0 task directories; the next run would still be refused ({split})",
                         listing.stdout.splitlines()[-1])
        done = self.program("--clean", "--yes")
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual({split}, set(self.panes()), "the agent's pane is closed, and the split of yours is alive")
        self.assertEqual(f"closed 1 panes and removed 0 task directories; the next run would still be refused ({split})",
                         done.stdout.splitlines()[-1])


if __name__ == "__main__":
    unittest.main()
