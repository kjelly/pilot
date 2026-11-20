"""Fake `tmux`, `gh` and agent executables, a scratch remote and a fake clock for the scripts/pr_loop.py tests
(not a test module).

NOTHING here may reach the developer's real tmux server or real GitHub. `FakeEnv` puts its own `tmux`, `gh`,
`claude` and `codex` first on PATH and refuses to continue unless `shutil.which` resolves every one of them to
the fakes; the fake `tmux` and `gh` also refuse to run without their own state file. The screens, pane states
and PR views they serve are SYNTHETIC: they are written for these tests, not captured from a real tmux,
agent or GitHub session, and they only claim to exercise the parsing rules of scripts/pr_loop.py.
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

HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[1]
RESULT_CLI = SKILLS / "_shared" / "scripts" / "pr_loop_result.py"
HEAD = "a" * 40
URL = "https://github.com/acme/demo/pull/7"
# The fakes run with `python -S`: they need nothing but the standard library.
SHEBANG = f"#!{sys.executable} -S\n"

FAKE_TMUX = '''
import json, os, subprocess, sys

PATH = os.environ.get("FAKE_TMUX_STATE")
if not PATH:
    sys.stderr.write("fake tmux: FAKE_TMUX_STATE is not set\\n")
    sys.exit(97)


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
    pane.setdefault("screens", ["\\u276f"])
    pane.setdefault("input", [])
    pane.setdefault("enter", [])
    return pane


def option(args, flag):
    return args[args.index(flag) + 1]


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
    sys.stderr.write("fake tmux: injected failure of " + cmd + "\\n")
    sys.exit(code)
out = ""
if cmd == "new-session":
    pane = take(state["new_session"], None)
    if pane is None:
        state["next"] += 1
        pane = "%" + str(state["next"])
    pane_of(state, pane)
    state["sessions"].append({"session": option(args, "-s"), "cwd": option(args, "-c"), "command": args[-1]})
    out = pane + "\\n"
elif cmd == "display-message":
    pane = pane_of(state, option(args, "-t"))
    out = take(pane["status"], "0|0|claude") + "\\n"
elif cmd == "capture-pane":
    pane = pane_of(state, option(args, "-t"))
    out = take(pane["screens"], "\\u276f") + "\\n"
elif cmd == "load-buffer":
    state["buffers"][option(args, "-b")] = call["stdin"]
elif cmd == "paste-buffer":
    name = option(args, "-b")
    pane = pane_of(state, option(args, "-t"))
    if name not in state["buffers"]:
        save(state)
        sys.stderr.write("fake tmux: no buffer " + name + "\\n")
        sys.exit(1)
    pane["input"].append(state["buffers"].pop(name))
    if pane.get("die_on_paste"):
        pane["status"] = ["1|0|claude"]
elif cmd == "delete-buffer":
    state["buffers"].pop(option(args, "-b"), None)
elif cmd == "send-keys":
    pane = pane_of(state, option(args, "-t"))
    if args[-1] == "Enter" and pane["enter"]:
        rc = act(state, pane, pane["enter"].pop(0))
        if rc:
            save(state)
            sys.exit(rc)
elif cmd == "kill-pane":
    pane_of(state, option(args, "-t"))["killed"] = True
elif cmd == "set-option":
    pass
else:
    save(state)
    sys.stderr.write("fake tmux: unexpected subcommand " + cmd + "\\n")
    sys.exit(98)
save(state)
sys.stdout.write(out)
'''

FAKE_GH = '''
import json, os, subprocess, sys

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
if args[:1] == ["api"] and args[-1].endswith("/comments?per_page=100"):
    pages = [[{"body": c["body"], "user": {"login": c["login"]}} for c in state["comments"]]]
    done(0, json.dumps(pages))
if args[:2] == ["repo", "clone"]:
    if state["clone_exit"]:
        done(state["clone_exit"], err="fake gh: injected clone failure")
    proc = subprocess.run(["git", "clone", "-q", os.environ["FAKE_GH_REMOTE"], args[3]],
                          capture_output=True, text=True)
    done(proc.returncode, proc.stdout, proc.stderr)
done(99, err="fake gh: unexpected call " + " ".join(args) + "\\n")
'''

AGENT_STUB = SHEBANG + "# Only here so that shutil.which finds an agent executable; the fake tmux never runs it.\n"


def pr_view_json(phase="draft", number=7, head=HEAD, url=URL, labels=()):
    """A `gh pr view` document for one phase. Synthetic."""
    state = {"merged": "MERGED", "closed": "CLOSED"}.get(phase, "OPEN")
    names = list(labels) + (["merge-queue"] if phase == "queued" else [])
    return {"number": number, "url": url, "state": state, "isDraft": phase == "draft", "headRefOid": head,
            "labels": [{"name": name} for name in names]}


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
        self.git_env = hermetic_env(self.home)
        self.make_remote(remote_files)
        self.write_tmux(log=[], fail={}, panes={}, buffers={}, sessions=[], cli=[], new_session=[], next=0)
        self.write_gh(calls=[], seq=[], view=pr_view_json(), login="reviewer", comments=[], clone_exit=0)
        env = dict(self.git_env, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                   FAKE_TMUX_STATE=str(self.tmux_path), FAKE_GH_STATE=str(self.gh_path),
                   FAKE_GH_REMOTE=str(self.remote), FAKE_RESULT_CLI=str(RESULT_CLI),
                   XDG_STATE_HOME=str(self.state_home), GH_PROMPT_DISABLED="1", PYTHONDONTWRITEBYTECODE="1")
        env.pop("TMUX", None)  # it would point a real tmux at the developer's server
        patcher = patch.dict(os.environ, env, clear=True)
        patcher.start()
        test.addCleanup(patcher.stop)
        # The safety net: a leaked call to the real tmux or gh would touch the developer's tmux server or GitHub.
        for name in ("tmux", "gh", "claude", "codex"):
            found = shutil.which(name)
            assert found == str(self.bin / name), f"{name} resolves to {found}, not to the fake in {self.bin}"
        self.environ = os.environ

    # ---- the scratch remote: what `gh repo clone` clones --------------------------------------------------
    def git(self, *args, cwd):
        done = subprocess.run(["git", *args], cwd=cwd, env=self.git_env, capture_output=True, text=True)
        assert done.returncode == 0, f"git {' '.join(args)}: {done.stderr}"
        return done.stdout.strip()

    def make_remote(self, files=None):
        """A bare repository whose `main` holds `files` (default: the result helper the runner requires)."""
        if files is None:
            files = {".agents/skills/_shared/scripts/pr_loop_result.py": RESULT_CLI.read_text()}
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
        state = self.tmux()
        state["panes"].setdefault(pane, {}).update(fields)
        self._write(self.tmux_path, state)

    def tmux_calls(self, command=None):
        """The argv of every tmux call (of one subcommand), in order."""
        calls = [call["argv"] for call in self.tmux()["log"]]
        return [call for call in calls if command is None or call[0] == command]

    def gh_calls(self):
        return self.gh()["calls"]
