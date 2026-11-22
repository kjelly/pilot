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
"""
import os
import re
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
from pr_loop_fakes import UPDATE_ENVIRONMENT

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
                                                  "before starting the runner again$"):
            pr_loop.check_panes(checkout.path)
        other = self.checkout("elsewhere")
        pr_loop.check_panes(other.path)  # control: a live pane in another directory is not in the way
        os.kill(int(self.tmux_ok("display-message", "-p", "-t", agent.pane, "#{pane_pid}")), signal.SIGKILL)
        self.wait_for("the pane to be dead", lambda: agent.status()[0])
        pr_loop.check_panes(checkout.path)  # a dead pane has no path: not in the way
        rc, out, _ = self.tmux("list-panes", "-a", "-F", "#{session_name}|#{pane_id}|#{pane_dead}|#{pane_current_path}")
        self.assertIn(f"{checkout.session}|{agent.pane}|1|", out.splitlines())

    def test_a_twin_of_the_session_repeats_its_panes_and_still_refuses(self):
        checkout = self.checkout()
        agent = self.agent(checkout)
        self.tmux_ok("new-session", "-d", "-t", checkout.session, "-s", checkout.session + "-eink")
        rows = self.tmux_ok("list-panes", "-a", "-F", "#{session_name}|#{pane_id}|#{pane_dead}|#{pane_current_path}")
        self.assertEqual([f"{checkout.session}|{agent.pane}|0|{checkout.path}",
                          f"{checkout.session}-eink|{agent.pane}|0|{checkout.path}"],
                         [row for row in rows.splitlines() if row.startswith(checkout.session)])
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


if __name__ == "__main__":
    unittest.main()
