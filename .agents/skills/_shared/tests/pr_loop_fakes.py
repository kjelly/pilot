"""Fake `tmux`, `gh` and agent executables, a scratch remote with an operator's checkout of it, and a fake clock
for the scripts/pr_loop.py tests (not a test module).

NOTHING here may reach the developer's real tmux server, real GitHub or the network. `FakeEnv` puts its own `tmux`,
`gh`, `claude` and `codex` first on PATH and refuses to continue unless `shutil.which` resolves every one of them to
the fakes; the fake `tmux` and `gh` also refuse to run without their own state file, and git is limited to local
files (`GIT_ALLOW_PROTOCOL=file`). The screens, pane states and PR views they serve are SYNTHETIC: they are written
for these tests, not captured from a real tmux, agent or GitHub session, and they only claim to exercise the parsing
rules of scripts/pr_loop.py. The exceptions: the Ready signal's GitHub state (`signal_world`) is
`ready_signal_world.World`, which builds the timeline events and labels in the shapes of the reduced real captures of
kjelly/pilot#419, and what the fake `tmux` says about SESSIONS and WINDOWS is the real tmux 3.8 behaviour, captured on a
private tmux socket (kjelly/pilot#425): the error lines of `list-panes` (`NO_SERVER`, `NO_SOCKET`), `new-session` on a
name in use (`duplicate session: S`), `new-window` and the way it resolves its target (`=S:` is exactly S; `S:` is S,
else a session whose name merely starts with S; a target without a colon is a window name), `kill-pane` (a window
goes with its last pane, a session with its last window, and a grouped twin of it with the session), the rows of
`list-panes -a` (a dead pane has no path, a twin repeats the rows of its session) and `show-options -gv
update-environment`. The model lives in `MODEL`, which is both embedded in the fake `tmux` and executed by the tests
to set a state up (`FakeEnv.kill_session` and the like). git is always REAL: the checkout is a real clone of a real
bare repository.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from gitrepo import hermetic_env
import ready_signal_world as rw

HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[1]
RESULT_CLI = SKILLS / "_shared" / "scripts" / "pr_loop_result.py"
SIGNAL_MODULE = SKILLS / "_shared" / "scripts" / "ready_signal.py"
# The two helpers the default branch of the checkout's origin must carry (scripts/pr_loop.py `Checkout`).
HELPER_PATHS = (".agents/skills/_shared/scripts/pr_loop_result.py", ".agents/skills/_shared/scripts/ready_signal.py")
LOGIN = "reviewer"  # what the fake `gh api user` answers
HEAD = "a" * 40
URL = "https://github.com/acme/demo/pull/7"
# The fakes run with `python -S`: they need nothing but the standard library.
SHEBANG = f"#!{sys.executable} -S\n"

# What tmux 3.8 really prints (captured on a private socket) for `list-panes -a`, `display-message -p -t %N` and `kill-pane -t
# %N` alike when no server is running: the socket is left behind (a server ran and was killed), or there is none. Both exit 1.
NO_SERVER = "no server running on /tmp/tmux-1000/default"
NO_SOCKET = "error connecting to /tmp/tmux-1000/default (No such file or directory)"

# The session and window model of the fake `tmux`, as source: embedded in the fake (which runs as its own process, once per
# call) and executed by `FakeEnv` to set a state up or change it the way the operator would. `state["live"]` maps a
# session name to {"group": the session it is grouped with or None, "windows": [{"name", "cwd", "panes": [ids]}]};
# a grouped twin owns no windows of its own, it shows its group's. A tmux server exists while a session does: the last
# session going takes the server with it (pending buffers included), and the next session starts another server, with
# its own PID and start time and with pane IDs that start again (`state["server"]`, `state["next"]`): a pane ID is only
# unique within one server, which is what makes a stale `%N` dangerous.
MODEL = r'''
def live_of(state):
    return state.setdefault("live", {})


def leader(state, name):
    """The session that owns the windows `name` shows: itself, or the one it is grouped with."""
    return live_of(state)[name].get("group") or name


def server_running(state):
    return bool(live_of(state))


def server_exit(state):
    """The last session is gone and the server with it."""
    state["server"] = None
    state["buffers"] = {}


def server_start(state):
    """A new server: another PID and start time (deterministic), pane IDs from the start again."""
    n = state["incarnation"] = state.get("incarnation", 0) + 1
    state["server"] = {"pid": 4000 + 7 * n, "start": 1700000000 + 13 * n}
    state["next"] = 0


def server_identity(state):
    """`pid|start_time`, as the formats `#{pid}|#{start_time}` print them."""
    return "%d|%d" % (state["server"]["pid"], state["server"]["start"])


def pane_known(state, pane):
    return any(pane in window["panes"] for entry in live_of(state).values() for window in entry["windows"])


def find_session(state, target):
    """`(session or None, what tmux says when there is none)` for the `-t` of new-window in the one form the runner uses,
    `=S:`: exactly S. (`S:` and a target without a colon resolve to other sessions in ways tmux 3.8 was only seen to do
    when S is gone; the fake does not model them and the caller refuses them.)"""
    name = target[1:-1]
    return (name if name in live_of(state) else None), "can't find session: " + name


def make_session(state, name, window, cwd, pane):
    if state.get("server") is None:
        server_start(state)
    live_of(state)[name] = {"group": None, "windows": [{"name": window, "cwd": cwd, "panes": [pane]}]}


def add_window(state, session, window, cwd, pane):
    live_of(state)[leader(state, session)]["windows"].append({"name": window, "cwd": cwd, "panes": [pane]})


def add_twin(state, session, twin):
    """A session grouped with `session` (an operator's `<name>-eink` twin): it shows the same windows."""
    live_of(state)[twin] = {"group": session, "windows": []}


def add_split(state, pane, new):
    """The operator splits the window of `pane`: `new` is a second pane of it."""
    for entry in live_of(state).values():
        for window in entry["windows"]:
            if pane in window["panes"]:
                window["panes"].append(new)
                return True
    return False


def kill_session(state, name):
    """The operator kills session `name`. A grouped twin that survives keeps the windows, as a session of its own."""
    live = live_of(state)
    entry = live.pop(name, None)
    if entry is not None and not entry.get("group"):
        twins = [twin for twin, other in live.items() if other.get("group") == name]
        if twins:
            live[twins[0]].update(group=None, windows=entry["windows"])
            for twin in twins[1:]:
                live[twin]["group"] = twins[0]
        else:
            for window in entry["windows"]:
                for pane in window["panes"]:
                    state["panes"].setdefault(pane, {})["killed"] = True
    if entry is not None and not live:
        server_exit(state)


def kill_server(state):
    """The operator kills the server: every session, and every pane in them."""
    for name in list(live_of(state)):
        kill_session(state, name)
    live_of(state).clear()
    server_exit(state)


def kill_pane(state, pane):
    """`kill-pane -t pane`: False when there is no such pane. A window goes with its last pane, a session with its last
    window, the twins of a session with it, and the server with its last session."""
    live = live_of(state)
    for name, entry in list(live.items()):
        for window in entry["windows"]:
            if pane in window["panes"]:
                window["panes"].remove(pane)
                state["panes"].setdefault(pane, {})["killed"] = True
                if not window["panes"]:
                    entry["windows"].remove(window)
                if not entry["windows"]:
                    del live[name]
                    for twin in [twin for twin, other in live.items() if other.get("group") == name]:
                        del live[twin]
                if not live:
                    server_exit(state)
                return True
    return False


def rows(state):
    """`list-panes -a` as `(session, pane, dead, path)`, sorted by session name: a twin repeats the rows of its session,
    and a dead pane has no path."""
    live, found = live_of(state), []
    for name in sorted(live):
        for window in live[leader(state, name)]["windows"]:
            for pane in window["panes"]:
                dead = state["panes"].get(pane, {}).get("status", ["0|0|claude"])[0].split("|")[0] == "1"
                found.append((name, pane, "1" if dead else "0", "" if dead else window["cwd"]))
    return found
'''

FAKE_TMUX = r'''
import json, os, subprocess, sys

PATH = os.environ.get("FAKE_TMUX_STATE")
if not PATH:
    sys.stderr.write("fake tmux: FAKE_TMUX_STATE is not set\n")
    sys.exit(97)
# The formats the runner uses; the fake answers these and refuses any other loudly.
PANE_FORMAT = "#{pane_id}|#{pid}|#{start_time}"
READ_FORMAT = "#{pane_dead}|#{pane_in_mode}|#{pane_current_command}|#{pid}|#{start_time}"
LIST_FORMAT = "#{session_name}|#{pane_id}|#{pane_dead}|#{pane_current_path}"
''' + "NO_SERVER_TEXT = " + repr(NO_SERVER) + MODEL + r'''

def load():
    with open(PATH) as stream:
        return json.load(stream)


def save(state):
    temporary = PATH + ".tmp"
    with open(temporary, "w") as stream:
        json.dump(state, stream)
    os.replace(temporary, PATH)


def take(sequence, default):
    """The next element; the last one repeats (a pane stays in its final state)."""
    if not sequence:
        return default
    return sequence.pop(0) if len(sequence) > 1 else sequence[0]


def pane_of(state, name):
    pane = state["panes"].setdefault(name, {})
    pane.setdefault("status", ["0|0|claude"])
    pane.setdefault("screens", ["❯"])
    pane.setdefault("input", [])
    pane.setdefault("enter", [])
    return pane


def next_pane(state):
    """The pane ID the next new-session or new-window prints: a scripted one (`pane_ids`), else the next number."""
    pane = take(state.setdefault("pane_ids", []), None)
    if pane is None:
        state["next"] += 1
        pane = "%" + str(state["next"])
    if state["panes"].get(pane, {}).get("killed"):
        state["panes"][pane] = {}  # an ID of a pane that died with an earlier server: this is another pane
    pane_of(state, pane)
    return pane


def option(args, flag):
    return args[args.index(flag) + 1]


def refuse(state, code, text):
    save(state)
    sys.stderr.write(text + "\n")
    sys.exit(code)


def need_server(state):
    """Every command but new-session needs a server: without one tmux says so (the socket is left behind)."""
    if not server_running(state):
        refuse(state, 1, state.get("no_server") or NO_SERVER_TEXT)


def need_pane(state, pane, *, say="can't find pane: "):
    if not pane_known(state, pane):
        refuse(state, 1, say + pane)


def act(state, pane, action):
    if "gh" in action:
        gh_path = os.environ["FAKE_GH_STATE"]
        with open(gh_path) as stream:
            gh = json.load(stream)
        change = action["gh"]
        if "set_view" in change:
            gh["view"].update(change["set_view"])
            gh["seq"] = []
        if "set_seq" in change:
            gh["seq"] = change["set_seq"]
        if "set_timeline" in change:
            gh["timeline"] = change["set_timeline"]
        with open(gh_path + ".tmp", "w") as stream:
            json.dump(gh, stream)
        os.replace(gh_path + ".tmp", gh_path)
    if "result" in action:
        text = pane["input"][-1]
        marker = "--pr-loop-task="
        path = json.JSONDecoder().raw_decode(text[text.index(marker) + len(marker):])[0]
        with open(path) as stream:
            task = json.load(stream)
        with open(os.environ["FAKE_GH_STATE"]) as stream:
            head = json.load(stream)["view"]["headRefOid"]
        result = action["result"]
        command = [sys.executable, "-B", os.environ["FAKE_RESULT_CLI"], "--task", path, "--repo", task["repo"],
                   "--pr", str(task["pr"]), "--phase", task["phase"], "--head", head,
                   "--outcome", result["outcome"], "--reason", result["reason"]]
        done = subprocess.run(command, capture_output=True, text=True)
        state["cli"].append({"rc": done.returncode, "stderr": done.stderr})
        return done.returncode
    return 0


args = sys.argv[1:]
state = load()
call = {"argv": args}
if args and args[0] == "load-buffer":
    call["stdin"] = sys.stdin.read()
state["log"].append(call)
cmd = args[0] if args else ""
code = state["fail"].get(cmd, 0)
if code:
    save(state)
    sys.stderr.write("fake tmux: injected failure of " + cmd + "\n")
    sys.exit(code)
# Something the operator (or another process) does between two calls of the runner: the next call of `cmd` finds
# the state after it. {"kill_session": S} or {"create_session": S}; None: nothing this time.
hooks = state.get("before", {}).get(cmd)
if hooks:
    hook = hooks.pop(0)
    if hook and "kill_session" in hook:
        kill_session(state, hook["kill_session"])
    if hook and "create_session" in hook:
        state["foreign"] = state.get("foreign", 900) + 1
        make_session(state, hook["create_session"], "operator", hook.get("cwd", "/"), "%" + str(state["foreign"]))
# An answer a test scripts for the next call of `cmd`, {"rc": 1, "stderr": "..."}: what tmux says for a state the model
# does not make (None: this call goes to the model).
scripted = state.get("answers", {}).get(cmd)
if scripted:
    answer = scripted.pop(0)
    if answer:
        refuse(state, answer["rc"], answer["stderr"])
out = ""
if cmd in ("new-session", "new-window"):
    if state.get("lock_path"):
        # What a second runner would find while this dispatch happens: the lock file of the checkout, held or free.
        import fcntl
        probe = os.open(state["lock_path"], os.O_RDWR)
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            state.setdefault("lock_probes", []).append("free")
        except OSError:
            state.setdefault("lock_probes", []).append("held")
        os.close(probe)
    if "-F" not in args or option(args, "-F") != PANE_FORMAT:
        refuse(state, 98, "fake tmux: " + cmd + " is only answered with -P -F " + PANE_FORMAT)
    # Without `-n` tmux names the window after the program in it (and keeps renaming it as the program changes).
    window = option(args, "-n") if "-n" in args else os.path.basename(args[-1].split()[-1])
    cwd = option(args, "-c")
    if cmd == "new-session":
        session = option(args, "-s")
        if session in live_of(state):
            refuse(state, 1, "duplicate session: " + session)
        if state.get("server") is None:
            server_start(state)  # the first session starts a server
        pane = next_pane(state)
        make_session(state, session, window, cwd, pane)
    else:
        need_server(state)
        target = option(args, "-t")
        if not (len(target) > 2 and target.startswith("=") and target.endswith(":") and ":" not in target[:-1]):
            refuse(state, 98, "fake tmux: new-window -t " + target + " is not a target the runner uses (only =SESSION:)")
        session, error = find_session(state, target)
        if session is None:
            refuse(state, 1, error)
        pane = next_pane(state)
        add_window(state, session, window, cwd, pane)
    state["sessions"].append({"kind": cmd, "session": session, "window": window, "pane": pane, "cwd": cwd,
                              "command": args[-1], "env": [args[i + 1] for i, arg in enumerate(args) if arg == "-e"]})
    out = pane + "|" + server_identity(state) + "\n"
elif cmd == "show-options":
    need_server(state)
    if args[1:] != ["-gv", "update-environment"]:
        refuse(state, 98, "fake tmux: unexpected show-options " + " ".join(args[1:]))
    out = "".join(name + "\n" for name in state.get("update_environment", []))
elif cmd == "display-message":
    need_server(state)
    if len(args) != 5 or args[:3] != ["display-message", "-p", "-t"] or args[4] != READ_FORMAT:
        refuse(state, 98, "fake tmux: unexpected display-message " + " ".join(args[1:]))
    name = option(args, "-t")
    if pane_known(state, name):
        pane = pane_of(state, name)
        fields = take(pane["status"], "0|0|claude")
    else:
        fields = "||"  # tmux answers a pane it does not have with empty fields and exit status 0
    out = fields + "|" + server_identity(state) + "\n"
elif cmd == "capture-pane":
    need_server(state)
    need_pane(state, option(args, "-t"))
    pane = pane_of(state, option(args, "-t"))
    out = take(pane["screens"], "❯") + "\n"
elif cmd == "load-buffer":
    need_server(state)
    state["buffers"][option(args, "-b")] = call["stdin"]
elif cmd == "paste-buffer":
    need_server(state)
    name = option(args, "-b")
    need_pane(state, option(args, "-t"))
    pane = pane_of(state, option(args, "-t"))
    if name not in state["buffers"]:
        save(state)
        sys.stderr.write("fake tmux: no buffer " + name + "\n")
        sys.exit(1)
    pane["input"].append(state["buffers"].pop(name))
    if pane.get("die_on_paste"):
        pane["status"] = ["1|0|claude"]
elif cmd == "delete-buffer":
    need_server(state)
    state["buffers"].pop(option(args, "-b"), None)
elif cmd == "send-keys":
    need_server(state)
    need_pane(state, option(args, "-t"))
    pane = pane_of(state, option(args, "-t"))
    if args[-1] == "Enter" and pane["enter"]:
        rc = act(state, pane, pane["enter"].pop(0))
        if rc:
            save(state)
            sys.exit(rc)
elif cmd == "kill-pane":
    need_server(state)
    if not kill_pane(state, option(args, "-t")):
        refuse(state, 1, "can't find pane: " + option(args, "-t"))
elif cmd == "set-option":
    need_server(state)
    need_pane(state, option(args, "-t"), say="no such window: ")
elif cmd == "list-panes":
    if state.get("no_server"):
        refuse(state, 1, state["no_server"])
    listing = state.get("listing")
    if listing is None:
        need_server(state)
        if args[1:] != ["-a", "-F", LIST_FORMAT]:
            refuse(state, 98, "fake tmux: unexpected list-panes " + " ".join(args[1:]))
        listing = ["|".join(row) for row in rows(state)]
    out = "".join(line + "\n" for line in listing)
else:
    save(state)
    sys.stderr.write("fake tmux: unexpected subcommand " + cmd + "\n")
    sys.exit(98)
save(state)
sys.stdout.write(out)
'''

FAKE_GH = '''
import json, os, sys

PATH = os.environ.get("FAKE_GH_STATE")
if not PATH:
    sys.stderr.write("fake gh: FAKE_GH_STATE is not set\\n")
    sys.exit(97)
with open(PATH) as stream:
    state = json.load(stream)
args = sys.argv[1:]
state["calls"].append(args)


def done(code=0, out="", err=""):
    with open(PATH + ".tmp", "w") as stream:
        json.dump(state, stream)
    os.replace(PATH + ".tmp", PATH)
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(code)


if args[:2] == ["pr", "view"]:
    seq = state["seq"]
    if seq:
        step = seq.pop(0) if len(seq) > 1 else seq[0]
    else:
        step = {"view": state["view"]}
    if "exit" in step:
        done(step["exit"], err=step.get("stderr", "fake gh: injected failure"))
    done(0, json.dumps(step["view"]))
if args[:1] == ["api"] and args[-1] == "user":
    done(0, json.dumps({"login": state["login"]}))
if args[:1] == ["api"] and args[-1].split("?")[0].endswith("/timeline") and "--slurp" in args:
    done(0, json.dumps([state.get("timeline", [])]))
if args[:1] == ["api"] and args[-1].endswith("/comments?per_page=100"):
    pages = [[{"body": c["body"], "user": {"login": c["login"]}} for c in state["comments"]]]
    done(0, json.dumps(pages))
done(99, err="fake gh: unexpected call " + " ".join(args) + "\\n")
'''

# What `tmux show-options -gv update-environment` really prints, one name per line (tmux 3.8, a private server started with
# no configuration file): the variables a new session takes from the client that creates it.
UPDATE_ENVIRONMENT = ["DISPLAY", "KRB5CCNAME", "MSYSTEM", "SSH_ASKPASS", "SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_CONNECTION",
                      "WAYLAND_DISPLAY", "WINDOWID", "XAUTHORITY", "XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP",
                      "XDG_SESSION_TYPE"]

# The model, as functions the tests call on a state they loaded (the fake `tmux` runs the same source).
_model = {}
exec(MODEL, _model)

AGENT_STUB = SHEBANG + "# Only here so that shutil.which finds an agent executable; the fake tmux never runs it.\n"


def pr_view_json(phase="draft", number=7, head=HEAD, url=URL, labels=()):
    """A `gh pr view` document for one phase. Synthetic. `labels` are names, or label objects as given."""
    state = {"merged": "MERGED", "closed": "CLOSED"}.get(phase, "OPEN")
    names = list(labels) + (["merge-queue"] if phase == "queued" else [])
    return {"number": number, "url": url, "state": state, "isDraft": phase == "draft", "headRefOid": head,
            "labels": [name if isinstance(name, dict) else {"name": name} for name in names]}


def signal_world(head=HEAD, *, signed=True, **kwargs):
    """The signal-relevant GitHub state of a PR that went Draft -> Ready as the fake `gh` account `LOGIN`: with
    `signed` also the producer's marker comment and label, otherwise just the Ready transition. Keyword arguments
    go to `World.signed_ready` (`producer`, `actor`)."""
    world = rw.World(head=head, viewer=LOGIN)
    if signed:
        world.signed_ready(**kwargs)
    else:
        world.ready()
    return world


def ready_view(world, **fields):
    """The `gh pr view` document of the Ready PR `world` describes: its HEAD and the labels it shows."""
    return dict(pr_view_json("ready", head=world.s["head"], labels=world.view_labels()), **fields)


class FakeTime:
    """Stands in for the `time` module of scripts/pr_loop.py: sleeping advances a fake clock."""

    def __init__(self, limit=20000):
        self.now, self.sleeps, self.limit = 1000.0, [], limit

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        if len(self.sleeps) > self.limit:
            raise RuntimeError("runaway loop: the code under test never stops waiting")
        self.now += seconds


class FakeEnv:
    """A directory of fakes, put first on PATH for the duration of a test (see `start`)."""

    def __init__(self, test, *, remote_files=None):
        self.temp = tempfile.TemporaryDirectory(prefix="pr-loop-fakes-")
        test.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, source in (("tmux", FAKE_TMUX), ("gh", FAKE_GH), ("claude", AGENT_STUB), ("codex", AGENT_STUB)):
            path = self.bin / name
            path.write_text(source if name in ("claude", "codex") else SHEBANG + source)
            path.chmod(0o755)
        self.tmux_path, self.gh_path = self.root / "tmux.json", self.root / "gh.json"
        self.remote = self.root / "remote.git"
        self.home = self.root / "home"
        self.state_home = self.root / "state"
        self.home.mkdir()
        # Nothing may leave the machine: git refuses every transport but a local file (the origin of a scratch
        # checkout is a github.com URL that `insteadOf` sends to the scratch remote).
        self.git_env = dict(hermetic_env(self.home), GIT_ALLOW_PROTOCOL="file")
        self.make_remote(remote_files)
        self.checkout = self.make_checkout()
        self.reset_tmux()
        self.write_gh(calls=[], seq=[], view=pr_view_json(), login=LOGIN, comments=[], timeline=[])
        env = dict(self.git_env, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                   FAKE_TMUX_STATE=str(self.tmux_path), FAKE_GH_STATE=str(self.gh_path),
                   FAKE_RESULT_CLI=str(RESULT_CLI), XDG_STATE_HOME=str(self.state_home), GH_PROMPT_DISABLED="1", PYTHONDONTWRITEBYTECODE="1")
        env.pop("TMUX", None)  # it would point a real tmux at the developer's server
        for name in UPDATE_ENVIRONMENT:
            env.pop(name, None)  # the developer's session variables: a test that wants one sets it itself
        patcher = patch.dict(os.environ, env, clear=True)
        patcher.start()
        test.addCleanup(patcher.stop)
        # The safety net: a leaked call to the real tmux or gh would touch the developer's tmux server or GitHub.
        for name in ("tmux", "gh", "claude", "codex"):
            found = shutil.which(name)
            assert found == str(self.bin / name), f"{name} resolves to {found}, not to the fake in {self.bin}"
        self.environ = os.environ
        # The runner works in the operator's checkout and keeps no state of its own: whatever a test did, nothing may
        # exist under XDG_STATE_HOME afterwards (the managed clones of an earlier design lived there).
        test.addCleanup(self._assert_no_state_directory)

    def _assert_no_state_directory(self):
        assert not self.state_home.exists(), f"the runner created {self.state_home}: it keeps no state of its own"

    # ---- the scratch remote: what the operator's checkout is a clone of ------------------------------------
    def git(self, *args, cwd):
        done = subprocess.run(["git", *args], cwd=cwd, env=self.git_env, capture_output=True, text=True)
        assert done.returncode == 0, f"git {' '.join(args)}: {done.stderr}"
        return done.stdout.strip()

    def make_remote(self, files=None):
        """A bare repository whose `main` holds `files` (default: the two helpers the runner requires)."""
        if files is None:
            files = {HELPER_PATHS[0]: RESULT_CLI.read_text(), HELPER_PATHS[1]: SIGNAL_MODULE.read_text()}
        shutil.rmtree(self.remote, ignore_errors=True)
        work = self.root / "work"
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir()
        self.git("init", "-q", cwd=work)
        self.git("symbolic-ref", "HEAD", "refs/heads/main", cwd=work)
        for name, text in files.items():
            (work / name).parent.mkdir(parents=True, exist_ok=True)
            (work / name).write_text(text)
        (work / "README.txt").write_text("synthetic\n")
        self.git("add", "-A", cwd=work)
        self.git("commit", "-q", "-m", "synthetic main", cwd=work)
        self.git("clone", "-q", "--bare", str(work), str(self.remote), cwd=self.root)
        self.remote_head = self.git("rev-parse", "main", cwd=self.remote)

    # ---- the operator's checkout: a clone of the scratch remote whose origin is a github.com URL --------------
    ORIGIN = "https://github.com/acme/demo.git"

    def make_checkout(self, name="checkout"):
        """A clone of the scratch remote at `<root>/<name>`, on `main`: what the operator starts the runner in. Its
        origin is the github.com URL of the repository the tests drive; a repository-local `insteadOf` sends that
        URL to the scratch remote (the hermetic environment ignores every other git configuration)."""
        path = self.root / name
        shutil.rmtree(path, ignore_errors=True)
        self.git("clone", "-q", str(self.remote), name, cwd=self.root)
        self.git("remote", "set-url", "origin", self.ORIGIN, cwd=path)
        self.redirect_origin(path, self.ORIGIN)
        return path

    def redirect_origin(self, path, *urls, remote=None, replace=False):
        """Send each of `urls` to a local repository (default: the scratch remote) for the checkout at `path`; with
        `replace`, instead of whatever the checkout redirected before."""
        if replace:
            listed = subprocess.run(["git", "config", "--name-only", "--get-regexp", r"^url\..*\.insteadof$"],
                                    cwd=path, env=self.git_env, capture_output=True, text=True).stdout.split()
            for key in listed:
                self.git("config", "--unset-all", key, cwd=path)
        target = f"file://{remote or self.remote}"
        for url in urls:
            self.git("config", "--add", f"url.{target}.insteadOf", url, cwd=path)

    def advance_remote(self, name="advance.txt"):
        """Push one more commit to `main` of the scratch remote (the way a merged PR moves origin); its SHA."""
        work = self.root / "work"
        (work / name).write_text("advance\n")
        self.git("add", "-A", cwd=work)
        self.git("commit", "-q", "-m", "advance " + name, cwd=work)
        self.git("push", "-q", str(self.remote), "main", cwd=work)
        self.remote_head = self.git("rev-parse", "main", cwd=self.remote)
        return self.remote_head

    # ---- state files ---------------------------------------------------------------------------------------
    @staticmethod
    def _read(path):
        return json.loads(path.read_text())

    @staticmethod
    def _write(path, state):
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(json.dumps(state))
        os.replace(temporary, path)

    def write_tmux(self, **state):
        self._write(self.tmux_path, state)

    def reset_tmux(self):
        """A tmux server with no session, no call logged and nothing scripted. `listing` is None: `list-panes -a` is
        derived from the sessions and windows that exist (a test that sets a list gets that list instead)."""
        self.write_tmux(log=[], fail={}, panes={}, buffers={}, sessions=[], cli=[], pane_ids=[], next=0, listing=None,
                        live={}, before={}, answers={}, update_environment=UPDATE_ENVIRONMENT, server=None, incarnation=0)

    def write_gh(self, **state):
        self._write(self.gh_path, state)

    def tmux(self):
        return self._read(self.tmux_path)

    def gh(self):
        return self._read(self.gh_path)

    def update_tmux(self, **change):
        state = self.tmux()
        state.update(change)
        self._write(self.tmux_path, state)

    def update_gh(self, **change):
        state = self.gh()
        state.update(change)
        self._write(self.gh_path, state)

    def set_pane(self, pane, **fields):
        """Script a pane (its status, screens, what Enter does). An ID whose pane was killed names the NEXT pane to get it
        (a server that exited numbers its panes again): what the old one had is dropped first."""
        state = self.tmux()
        if state["panes"].get(pane, {}).get("killed"):
            state["panes"][pane] = {}
        state["panes"].setdefault(pane, {}).update(fields)
        self._write(self.tmux_path, state)

    def operator(self, function, *args):
        """What the operator does to the tmux server, between two calls of the runner: `function` of MODEL on the state."""
        state = self.tmux()
        result = _model[function](state, *args)
        self._write(self.tmux_path, state)
        return result

    def kill_session(self, name):
        self.operator("kill_session", name)

    def kill_server(self):
        """Every session and pane gone, and the server with them."""
        self.operator("kill_server")

    def keeper(self, name="operator"):
        """The operator's own session, there before the runner's: it keeps the server alive when the runner's session goes
        (without one, the last session takes the server with it). Returns its pane ID."""
        state = self.tmux()
        state["foreign"] = state.get("foreign", 900) + 1
        pane = f"%{state['foreign']}"
        _model["make_session"](state, name, "keeper", "/", pane)
        self._write(self.tmux_path, state)
        return pane

    def server(self):
        """`pid|start_time` of the server that runs, None when none does."""
        state = self.tmux()
        return _model["server_identity"](state) if state["server"] else None

    def add_twin(self, session, twin):
        self.operator("add_twin", session, twin)

    def add_split(self, pane):
        """The operator splits the window of `pane`; the ID of the new pane."""
        state = self.tmux()
        state["foreign"] = state.get("foreign", 900) + 1
        new = f"%{state['foreign']}"
        self._write(self.tmux_path, state)
        assert self.operator("add_split", pane, new), f"no window with {pane}"
        return new

    def live(self):
        """The sessions that exist: name -> the names of its windows (a grouped twin shows its group's)."""
        state = self.tmux()
        return {name: [window["name"] for window in state["live"][_model["leader"](state, name)]["windows"]]
                for name in sorted(state["live"])}

    def created(self):
        """Every agent pane tmux created (a session or a window), in order: what `sessions` of the state holds."""
        return self.tmux()["sessions"]

    def tmux_calls(self, command=None):
        """The argv of every tmux call (of one subcommand), in order."""
        calls = [call["argv"] for call in self.tmux()["log"]]
        return [call for call in calls if command is None or call[0] == command]

    def gh_calls(self):
        return self.gh()["calls"]
