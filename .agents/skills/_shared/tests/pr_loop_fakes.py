"""Fake `tmux`, `gh` and agent executables, a scratch remote with an operator's checkout of it, and a fake clock
for the scripts/pr_loop.py tests (not a test module).

NOTHING here may reach the developer's real tmux server, real GitHub or the network. `FakeEnv` puts its own `tmux`,
`gh`, `claude` and `codex` first on PATH and refuses to continue unless `shutil.which` resolves every one of them to
the fakes (`real_tmux=True` is the one exception: it leaves tmux real and puts it on a private server, see `FakeEnv`);
the fake `tmux` and `gh` also refuse to run without their own state file, and git is limited to local files
(`GIT_ALLOW_PROTOCOL=file`). The screens, pane states and PR views they serve are SYNTHETIC: they are written
for these tests, not captured from a real tmux, agent or GitHub session, and they only claim to exercise the parsing
rules of scripts/pr_loop.py. The exceptions: the Ready signal's GitHub state (`signal_world`) is
`ready_signal_world.World`, which builds the timeline events and labels in the shapes of the reduced real captures of
kjelly/pilot#419, and what the fake `tmux` says about SESSIONS and WINDOWS is the real tmux 3.8 behaviour, captured on a
private tmux socket (kjelly/pilot#425): the error lines of `list-panes` (`NO_SERVER`, `NO_SOCKET`), `new-session` on a
name in use (`duplicate session: S`), `new-window` and the way it resolves its target (`=S:` is exactly S; `S:` is S,
else a session whose name merely starts with S; a target without a colon is a window name), `kill-pane` (a window
goes with its last pane, a session with its last window, and a grouped twin of it with the session), the rows of
`list-panes -a` (a dead pane has no path and no process, keeps its start path and command, a twin repeats the rows of its
session; `#{q:...}` puts a backslash before every character special to a shell, a newline included; a start command that
holds a space is shown between double quotes; kjelly/pilot#442, each asserted against a real tmux in
tests/test_pr_loop_tmux.py, which runs on tmux 3.8 and on tmux 3.4.1: 3.4 differs from the fake in what `q:` quotes (not `{`, `}`
or a newline), in a `$` (it writes a backslash before it in a directory and two in a command) and in a dead pane, which
keeps its process there; scripts/pr_loop.py reads both) and `show-options -gv update-environment`. The model lives in
`MODEL`, which is both embedded in the fake `tmux` and executed by the tests to set a state up (`FakeEnv.kill_session` and
the like). git is always REAL: the checkout is a real clone of a real bare repository.
"""
import json
import os
import shlex
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

# What the runner asks `list-panes -a` for (scripts/pr_loop.py LIST_FORMAT; a test keeps the two equal).
LIST_FORMAT = ("#{pane_id}|#{window_id}|#{pane_dead}|#{pane_in_mode}|#{pane_pid}|#{pid}|#{start_time}|#{q:socket_path}|"
               "#{q:session_name}|#{q:window_name}|#{q:pane_start_path}|#{q:pane_start_command}|#{q:pane_current_path}|"
               "#{q:pane_current_command}")
# The socket tmux 3.8 printed for `#{socket_path}` on a server of the default name: the fake's server answers with it.
SOCKET = "/tmp/tmux-1000/default"

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
    """A new server: another PID and start time (deterministic), pane and window IDs from the start again."""
    n = state["incarnation"] = state.get("incarnation", 0) + 1
    state["server"] = {"pid": 4000 + 7 * n, "start": 1700000000 + 13 * n}
    state["next"] = 0
    state["next_window"] = 0


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


def q(text):
    """tmux 3.8's `#{q:text}`: a backslash before every character that is special to a shell, a newline included."""
    return "".join("\\" + char if char in "|&;<>()$`\\\"'*?[# =%{}\n" else char for char in text)


def args_escape(arg):
    """How tmux 3.8 shows one argument of a pane's start command (`args_escape`): between double quotes when it holds one of
    ` #';${}%`, else between single quotes when it holds a space or a double quote; a backslash, a newline and a tab are written
    C-style and, between double quotes, a double quote and a `$` get a backslash; a leading `~` gets one too."""
    if arg == "":
        return "''"
    quotes = '"' if any(char in " #';${}%" for char in arg) else "'" if any(char in ' "' for char in arg) else ""
    if len(arg) == 1 and arg != " " and (quotes or arg == "~"):
        return "\\" + arg
    body = "".join({"\\": "\\\\", "\n": "\\n", "\t": "\\t"}.get(char) or ("\\" + char if char in '"$' and quotes == '"' else
                                                                         char if char.isprintable() else "\\%03o" % ord(char))
                   for char in arg)
    tilde = "\\" if body.startswith("~") and quotes != "'" else ""
    return quotes + tilde + body + quotes


def start_shown(args):
    """The `pane_start_command` tmux 3.8 shows for a pane started with the arguments `args` (empty: a pane that runs the
    default shell has none): each one as `args_escape` shows it, joined by a space."""
    return " ".join(args_escape(arg) for arg in args)


def pane_pid(state, pane):
    """The process of a pane: synthetic, above the largest PID a system gives (so that it is never one of the test's own
    ancestors), another one for the pane an ID has on another server, another again for a pane that was started again."""
    meta = state["panes"].get(pane, {})
    return meta.get("pid") or 1000000000 + 1000 * state.get("incarnation", 0) + 10 * int(pane[1:]) + meta.get("respawns", 0)


def new_window(state, name, cwd, pane, command=""):
    """A window with the pane `pane` in it, started in `cwd` with the start command `command` (as tmux shows it)."""
    window = {"id": "@%d" % state.setdefault("next_window", 0), "name": name, "cwd": cwd, "panes": [pane]}
    state["next_window"] += 1
    state["panes"].setdefault(pane, {}).update(start_path=cwd, start_command=command)
    return window


def make_session(state, name, window, cwd, pane, command=""):
    if state.get("server") is None:
        server_start(state)
    live_of(state)[name] = {"group": None, "windows": [new_window(state, window, cwd, pane, command)]}


def add_window(state, session, window, cwd, pane, command=""):
    live_of(state)[leader(state, session)]["windows"].append(new_window(state, window, cwd, pane, command))


def add_twin(state, session, twin):
    """A session grouped with `session` (an operator's `<name>-eink` twin): it shows the same windows."""
    live_of(state)[twin] = {"group": session, "windows": []}


def add_split(state, pane, new, command=None, path=None):
    """The operator splits the window of `pane`: `new` is a second pane of it, started in `path` (default: the window's
    directory) with the arguments `command` (default: none, the shell), whose start command tmux shows as `start_shown`."""
    for entry in live_of(state).values():
        for window in entry["windows"]:
            if pane in window["panes"]:
                window["panes"].append(new)
                state["panes"].setdefault(new, {}).update(start_path=path or window["cwd"],
                                                          start_command=start_shown(command or []))
                return True
    return False


def respawn(state, pane):
    """The operator starts `pane` again (`respawn-pane -k`): a new process in the same pane, alive, with the command and
    directory it was started with."""
    meta = state["panes"].setdefault(pane, {})
    meta["respawns"] = meta.get("respawns", 0) + 1
    meta["status"] = ["0|0|claude"]
    return True


def set_status(state, pane, status):
    """The operator changes what `pane` shows of itself, `status` being `dead|in_mode|foreground command` (put in copy mode: `0|1|claude`;
    a shell in the foreground: `0|0|bash`), from now on."""
    state["panes"].setdefault(pane, {})["status"] = [status]
    return True


def reborn(state, session, window, cwd, pane, command=""):
    """The operator kills the server and starts another one, whose first session is `session`, whose first pane has the ID `pane`
    (one the old server had: a new server numbers its panes again) and was started in `cwd` with the start command `command`
    (as tmux shows it)."""
    kill_server(state)
    state["panes"][pane] = {}
    make_session(state, session, window, cwd, pane, command)
    return True


def rename_window(state, pane, name):
    """The operator renames the window of `pane`."""
    for entry in live_of(state).values():
        for window in entry["windows"]:
            if pane in window["panes"]:
                window["name"] = name
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
    """`list-panes -a` as one dict for each (session, pane), sorted by session name: a twin repeats the rows of its session,
    a dead pane has no process and no current path and keeps what it was started with."""
    live, found = live_of(state), []
    for name in sorted(live):
        for window in live[leader(state, name)]["windows"]:
            for pane in window["panes"]:
                meta = state["panes"].get(pane, {})
                dead, in_mode, command = (meta.get("status", ["0|0|claude"])[0].split("|") + ["", ""])[:3]
                start = meta.get("start_path", window["cwd"])
                found.append({"session": name, "pane": pane, "window_id": window["id"], "window": window["name"],
                              "dead": dead == "1", "in_mode": in_mode, "command": command, "start_path": start,
                              "start_command": meta.get("start_command", ""),
                              "pid": "" if dead == "1" else str(pane_pid(state, pane)),
                              "path": "" if dead == "1" else meta.get("path", start)})
    return found


def list_line(state, row, socket):
    """One line of `list-panes -a -F LIST_FORMAT`."""
    return "|".join((row["pane"], row["window_id"], "1" if row["dead"] else "0", row["in_mode"], row["pid"],
                     server_identity(state), q(socket), q(row["session"]), q(row["window"]), q(row["start_path"]),
                     q(row["start_command"]), q(row["path"]), q(row["command"])))
'''

FAKE_TMUX = r'''
import json, os, subprocess, sys

PATH = os.environ.get("FAKE_TMUX_STATE")
if not PATH:
    sys.stderr.write("fake tmux: FAKE_TMUX_STATE is not set\n")
    sys.exit(97)
# The formats the runner uses; the fake answers these and refuses any other loudly.
PANE_FORMAT = "#{pane_id}|#{pid}|#{start_time}"
READ_FORMAT = "#{pane_dead}|#{pane_in_mode}|#{pane_current_command}|#{pane_pid}|#{pid}|#{start_time}"
''' + "LIST_FORMAT = " + repr(LIST_FORMAT) + "\nSOCKET = " + repr(SOCKET) + "\nNO_SERVER_TEXT = " + repr(NO_SERVER) + MODEL + r'''

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
# the state after it. {"kill_session": S}, {"create_session": S} or {"call": function of the model, "args": [...]}; None:
# nothing this time.
hooks = state.get("before", {}).get(cmd)
if hooks:
    hook = hooks.pop(0)
    if hook and "kill_session" in hook:
        kill_session(state, hook["kill_session"])
    if hook and "create_session" in hook:
        state["foreign"] = state.get("foreign", 900) + 1
        make_session(state, hook["create_session"], "operator", hook.get("cwd", "/"), "%" + str(state["foreign"]))
    if hook and "call" in hook:  # any function of the model, with its arguments: {"call": "respawn", "args": ["%3"]}
        globals()[hook["call"]](state, *hook.get("args", []))
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
    shown = start_shown(args[args.index("--") + 1:] if "--" in args else [args[-1]])
    if cmd == "new-session":
        session = option(args, "-s")
        if session in live_of(state):
            refuse(state, 1, "duplicate session: " + session)
        if state.get("server") is None:
            server_start(state)  # the first session starts a server
        pane = next_pane(state)
        make_session(state, session, window, cwd, pane, shown)
    else:
        need_server(state)
        target = option(args, "-t")
        if not (len(target) > 2 and target.startswith("=") and target.endswith(":") and ":" not in target[:-1]):
            refuse(state, 98, "fake tmux: new-window -t " + target + " is not a target the runner uses (only =SESSION:)")
        session, error = find_session(state, target)
        if session is None:
            refuse(state, 1, error)
        pane = next_pane(state)
        add_window(state, session, window, cwd, pane, shown)
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
        # The pane's own process (never the server's): none for a dead pane, as tmux 3.8 prints it
        fields += "|" + ("" if fields.startswith("1|") else str(pane_pid(state, name)))
    else:
        fields = "|||"  # tmux answers a pane it does not have with empty fields and exit status 0
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
    if args[1:] != ["-a", "-F", LIST_FORMAT]:
        refuse(state, 98, "fake tmux: unexpected list-panes " + " ".join(args[1:]))
    listing = state.get("listing")
    if listing is None:
        need_server(state)
        listing = [list_line(state, row, state.get("socket", SOCKET)) for row in rows(state)]
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

    def time(self):
        """The wall clock: a fixed day, moved on by what was slept (the age of a file is read against it)."""
        return 1700000000.0 + self.now - 1000.0

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        if len(self.sleeps) > self.limit:
            raise RuntimeError("runaway loop: the code under test never stops waiting")
        self.now += seconds


class FakeEnv:
    """A directory of fakes, put first on PATH for the duration of a test (see `start`)."""

    def __init__(self, test, *, remote_files=None, real_tmux=False):
        """`real_tmux`: the fake `tmux` is not installed. tmux is the real one, on a server of its own that lives in a private
        directory (`TMUX_TMPDIR`) and is held open by a keeper session started with `-f /dev/null`; before anything is run the
        socket a plain `tmux` reaches must be inside that directory, or the test fails (see `start_real_tmux`). The agents
        `claude` and `codex` are then scripts a pane really runs (`write_agent`), not stubs."""
        self.temp = tempfile.TemporaryDirectory(prefix="pr-loop-fakes-")
        test.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.real_tmux = real_tmux
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, source in (("tmux", FAKE_TMUX), ("gh", FAKE_GH), ("claude", AGENT_STUB), ("codex", AGENT_STUB)):
            if name == "tmux" and real_tmux:
                continue
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
        for name in ("TMUX", "TMUX_PANE", "TMUX_TMPDIR"):
            env.pop(name, None)  # they would point a real tmux at the developer's server (a test that wants one sets it itself)
        for name in UPDATE_ENVIRONMENT:
            env.pop(name, None)  # the developer's session variables: a test that wants one sets it itself
        if real_tmux:
            self.tmux_dir = self.root / "tmux"
            env["TMUX_TMPDIR"] = str(self.tmux_dir)
        patcher = patch.dict(os.environ, env, clear=True)
        patcher.start()
        test.addCleanup(patcher.stop)
        # The safety net: a leaked call to the real tmux or gh would touch the developer's tmux server or GitHub.
        for name in ("tmux", "gh", "claude", "codex"):
            found = shutil.which(name)
            if name == "tmux" and real_tmux:
                assert found and not str(found).startswith(str(self.bin)), f"tmux resolves to {found}"
                continue
            assert found == str(self.bin / name), f"{name} resolves to {found}, not to the fake in {self.bin}"
        self.environ = os.environ
        if real_tmux:
            self.start_real_tmux(test)
        # The runner works in the operator's checkout and keeps no state of its own: whatever a test did, nothing may
        # exist under XDG_STATE_HOME afterwards (the managed clones of an earlier design lived there).
        test.addCleanup(self._assert_no_state_directory)

    SOCKET_LIMIT = 100  # a Unix socket path is limited to 107 bytes; stay well inside

    def start_real_tmux(self, test):
        """The real tmux on a private server: the socket is `<root>/tmux/tmux-<uid>/default`, a keeper session started with the
        socket named explicitly and `-f /dev/null` (no configuration file) keeps the server alive when the last session of a
        test goes, and the socket a PLAIN `tmux` reaches (which is what the runner runs) is checked to be that one before
        anything of the runner starts. Whatever is on the socket at the end is killed with the socket named explicitly, never by
        name or by default."""
        self.socket = self.tmux_dir / f"tmux-{os.getuid()}" / "default"
        if len(os.fsencode(self.socket)) >= self.SOCKET_LIMIT:
            test.skipTest(f"the socket path {self.socket} would be {len(os.fsencode(self.socket))} bytes long")
        self.socket.parent.mkdir(parents=True, mode=0o700)
        done = subprocess.run(["tmux", "-S", str(self.socket), "-f", "/dev/null", "new-session", "-d", "-s", "keeper",
                               "exec sleep 600"], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        assert done.returncode == 0, done.stderr
        test.addCleanup(subprocess.run, ["tmux", "-S", str(self.socket), "kill-server"], capture_output=True, timeout=30,
                        stdin=subprocess.DEVNULL)
        done = subprocess.run(["tmux", "display-message", "-p", "-t", "=keeper:", "#{socket_path}"], capture_output=True,
                              text=True, timeout=30, stdin=subprocess.DEVNULL)
        assert (done.returncode, done.stdout.strip()) == (0, str(self.socket)), \
            f"plain tmux does not reach the private server: {done.stdout!r} {done.stderr!r}"
        assert os.path.realpath(done.stdout.strip()).startswith(os.path.realpath(self.root) + os.sep)

    def write_agent(self, name, text):
        """An executable of that name in the fakes' directory (it replaces the stub): what a pane of the real tmux runs."""
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)
        return path

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

    def session(self, name, window="w", cwd="/", command=None):
        """A session somebody else made (the operator, another tool, another checkout's runner) with one pane that was started in
        `cwd` with the arguments `command` (default: the shell); its pane ID. It keeps the server alive, like `keeper`."""
        state = self.tmux()
        state["foreign"] = state.get("foreign", 900) + 1
        pane = f"%{state['foreign']}"
        _model["make_session"](state, name, window, str(cwd), pane, _model["start_shown"](command or []))
        self._write(self.tmux_path, state)
        return pane

    def window(self, session, name, cwd, command=None):
        """A window somebody else opened in `session` (started in `cwd` with the arguments `command`, by default the shell); its
        pane ID."""
        state = self.tmux()
        state["foreign"] = state.get("foreign", 900) + 1
        pane = f"%{state['foreign']}"
        _model["add_window"](state, session, name, str(cwd), pane, _model["start_shown"](command or []))
        self._write(self.tmux_path, state)
        return pane

    def server(self):
        """`pid|start_time` of the server that runs, None when none does."""
        state = self.tmux()
        return _model["server_identity"](state) if state["server"] else None

    def add_twin(self, session, twin):
        self.operator("add_twin", session, twin)

    def add_split(self, pane, command=None, path=None):
        """The operator splits the window of `pane` (a command as a list of arguments, a directory; by default the shell, in the
        window's directory); the ID of the new pane."""
        state = self.tmux()
        state["foreign"] = state.get("foreign", 900) + 1
        new = f"%{state['foreign']}"
        self._write(self.tmux_path, state)
        assert self.operator("add_split", pane, new, command, None if path is None else str(path)), f"no window with {pane}"
        return new

    def respawn(self, pane):
        """The operator starts `pane` again: a new process, alive."""
        self.operator("respawn", pane)

    def rename_window(self, pane, name):
        """The operator renames the window of `pane`."""
        assert self.operator("rename_window", pane, name), f"no window with {pane}"

    def row(self, session, pane, *, window="7-draft", dead=False, in_mode=False, pid=None, start_path=None,
            start_command=None, path=None, command="claude", window_id="@1", server=None, socket=SOCKET):
        """One line of `list-panes -a -F LIST_FORMAT` as tmux 3.8 would print it, for a test that scripts the whole listing
        (`update_tmux(listing=[...])`): by default a live agent pane of the runner's in the checkout `start_path` and `path`
        (both default to `self.checkout`), started with `exec <executable>`; `server` is `pid|start_time` (the fake's own by
        default, 4007|1700000013 without one)."""
        start_path = str(self.checkout) if start_path is None else str(start_path)
        path = ("" if dead else start_path) if path is None else str(path)  # (a path that is given wins, for a rule's trigger case)
        if start_command is None:
            start_command = _model["start_shown"](["exec " + shlex.quote(str(self.bin / "claude"))])
        identity = server or (self.server() or "4007|1700000013")
        return "|".join((pane, window_id, "1" if dead else "0", "1" if in_mode else "0",
                         "" if dead else str(1000000000 + int(pane[1:]) if pid is None else pid), identity, _model["q"](socket),
                         _model["q"](session), _model["q"](window), _model["q"](start_path), _model["q"](start_command),
                         _model["q"](path), _model["q"](command)))

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
