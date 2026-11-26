"""In-run recorder of what a skill suite's own run reads, and the end-of-suite check against its derivation (kjelly/pilot#430).

`skill_suites.derive` says what a suite can read; `skill_suites.select` trusts it to choose the suites a change can reach. The
consistency oracle of `test_skill_suites.py` (TRACE) only LOADS the test modules under an audit hook, so a read made in a test
body, `setUp` or `setUpClass` was never compared with the derivation: dropping `.github/secret-scan.json` from `_shared`'s
derivation left every test green. This module closes that gap with the suites' own runs.

Each of the six suites has two thin modules: `tests/test_000_suite_reads_<suite>.py` (sorts first: it installs the recorder
before any other test module is imported) and `tests/test_zzz_suite_reads_<suite>.py` (sorts last: it checks what the run
read; `<suite>` is the suite's name with `-` as `_` and no leading `_`, so the module name is unique across suites: a suite
that puts another suite's tests directory on `sys.path` cannot import the wrong one). The recorder
is an audit hook, and the check runs in a child process (`python -I -B -c`) that imports `skill_suites`, so no suite imports
`skill_suites` in-process (it would carry `.agents/**` into every suite's derivation and select every suite for every change);
the child gets the records on stdin and reports the gaps. A gap is a tracked repository file the run read, or a directory it
listed, outside the suite's own directory, that the suite's derived sources do not name (`skill_suites.runtime_gaps`).

What a record is: the first time the run opened, imported, executed, listed (`os.listdir`, `os.scandir`, `glob.glob`,
`shutil.copytree`), copied (`shutil.copyfile`) or passed as an argument to a process (`subprocess.Popen`, `os.posix_spawn`) a
path under the repository, with the innermost frame of repository code that did it and the phase (load, test = a test body
with its `setUp` and `tearDown`, between = a class fixture or a module fixture).

What it does NOT observe (CPython raises no audit event for them or the run never gets there; CI runs the whole suite, which is
the backstop): reads made by a descendant process (a script run by a test, `git`, `make`, `tmux`, `sh`); existence probes
(`exists`, `is_file`, `is_dir`, `stat`, `samefile`); branches that did not run in this run (a skip without `tmux` or `git`, an
error path); listing coverage is judged by the prefix of a derived glob only; anything read before `test_000` is imported and
by the check itself; data-dependent path sets are observed only for the data present in this run; a path that reaches the
repository only through a symbolic link made outside it. The recorder wraps the public `unittest.TestCase.run` only to know
which phase and test a read belongs to.
"""
import atexit
import json
import os
import subprocess
import sys
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent                    # .agents/skills/_shared/tests
SCRIPTS_DIR = HERE.parent / "scripts"
REPO = HERE.parents[3]
# Every suite's derivation gets an edge to the module that runs the check (it is run, not imported: see the docstring).
assert (SCRIPTS_DIR / "skill_suites.py").is_file()

WATCH = frozenset(["open", "exec", "import", "os.listdir", "os.scandir", "glob.glob", "shutil.copytree", "shutil.copyfile",
                   "subprocess.Popen", "os.posix_spawn"])
PREFIX = str(REPO) + os.sep
SELF = str(HERE / "suite_reads.py")
CHILD_TIMEOUT = 300
DUMP_MARKER = "SUITE_READS_DUMP "

STATE = {"installed": False, "paused": False, "phase": "load", "test": None, "errors": 0, "modules": set()}
RECORDS: dict = {}
LOCAL = threading.local()
CACHE: dict = {}


def spell(value):
    """A path argument as a string, or None for a file descriptor, a missing value or something that is not a path."""
    if isinstance(value, int) or value is None:
        return None
    try:
        return os.fsdecode(value)
    except TypeError:
        return None


def absolute(path, base=None):
    """The absolute, normalised spelling of a path (relative ones against `base`, else the working directory)."""
    if not os.path.isabs(path):
        path = os.path.join(base or os.getcwd(), path)
    return os.path.normpath(path)


def glob_directory(pattern, root_dir):
    """The directory a `glob.glob` pattern starts listing at: its leading segments without a wildcard."""
    kept = []
    for segment in pattern.split("/"):
        if any(c in segment for c in "*?["):
            break
        kept.append(segment)
    else:
        kept = kept[:-1]
    start = "/".join(kept) or ("/" if pattern.startswith("/") else ".")
    return absolute(start, root_dir)


def targets(event, args):
    """[(event, absolute path)] an audit event names."""
    found = []
    if event == "open":
        path = spell(args[0])
        if path:
            found.append((event, absolute(path)))
    elif event == "exec":
        path = getattr(args[0], "co_filename", None)
        if isinstance(path, str) and os.path.isabs(path):
            found.append((event, path))
    elif event == "import":
        path = spell(args[1]) if len(args) > 1 else None
        if path:
            found.append((event, absolute(path)))
    elif event in ("os.listdir", "os.scandir"):
        path = spell(args[0]) if args[0] is not None else "."
        if path is not None:
            found.append((event, absolute(path)))
    elif event == "glob.glob":
        pattern = spell(args[0])
        root_dir = spell(args[2]) if len(args) > 2 else None
        if pattern:
            found.append((event, glob_directory(pattern, root_dir)))
    elif event in ("shutil.copyfile", "shutil.copytree"):
        path = spell(args[0])
        if path:
            found.append((event, absolute(path)))
    elif event == "subprocess.Popen":
        base = spell(args[2])
        for item in [args[0], *(args[1] or [])]:
            path = spell(item)
            if path and ("/" in path or "." in path) and not path.startswith("-"):
                found.append((event, absolute(path, base)))
        if base:
            found.append((event, absolute(base)))
    elif event == "os.posix_spawn":
        for item in [args[0], *(args[1] or [])]:
            path = spell(item)
            if path and ("/" in path or "." in path) and not path.startswith("-"):
                found.append((event, absolute(path)))
    return found


def hook(event, args):
    """The audit hook: remember, once per (event, path, site), what the run touches inside the repository."""
    if event not in WATCH or STATE["paused"] or getattr(LOCAL, "busy", False):
        return
    LOCAL.busy = True
    try:
        named = [(e, p) for e, p in targets(event, args) if p == str(REPO) or p.startswith(PREFIX)]
        if not named:
            return
        site, imported = None, False
        frame = sys._getframe(1)
        while frame is not None:
            name = frame.f_code.co_filename
            if name.startswith("<frozen importlib"):
                imported = True
            elif name.startswith(PREFIX) and name != SELF:
                site = (name, frame.f_lineno)
                break
            frame = frame.f_back
        for kind, path in named:
            if imported and kind in ("os.listdir", "os.scandir"):
                continue                                  # the import system listing a search path is not a read of the test
            RECORDS.setdefault((kind, path, site), [kind, path, site[0] if site else None, site[1] if site else None,
                                                    STATE["phase"], STATE["test"]])
    except Exception:                                     # never break the run being observed; the premise counts these
        STATE["errors"] += 1
    finally:
        LOCAL.busy = False


def wrap_test_case_run():
    """Know which test (and phase) a read belongs to: a test body with setUp/tearDown is `test`, outside any test `between`."""
    original = unittest.TestCase.run

    def run(self, result=None):
        before = (STATE["phase"], STATE["test"])
        STATE["phase"], STATE["test"] = "test", self.id()
        STATE["modules"].add(self.id().rsplit(".", 2)[0])
        try:
            return original(self, result)
        finally:
            STATE["phase"], STATE["test"] = ("between", None) if before[0] == "load" else before

    unittest.TestCase.run = run


def dump():
    """The records of this process on stderr (the producer of a test that needs the reads of a real run)."""
    sys.stderr.write("\n" + DUMP_MARKER + json.dumps(sorted(RECORDS.values(), key=repr)) + "\n")


def install():
    """Start recording. Idempotent; the audit hook stays for the life of the process."""
    if STATE["installed"]:
        return
    STATE["installed"] = True
    sys.addaudithook(hook)
    wrap_test_case_run()
    if os.environ.get("PILOT_SUITE_READS_DUMP") == "1":
        atexit.register(dump)


def records():
    """What the run has read so far: [[event, path, site_file, site_line, phase, test], ...]."""
    return [list(r) for r in RECORDS.values()]


CHILD = r'''
import json, os, subprocess, sys, traceback
try:
    payload = json.load(sys.stdin)
    sys.path.insert(0, payload["scripts"])
    import skill_suites as ss
    repo, suite = payload["repo"], payload["suite"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    listed = subprocess.run(["git", "-C", repo, "ls-files", "-z"], capture_output=True, env=env, timeout=120)
    tracked = [x.decode("utf-8", "surrogateescape") for x in listed.stdout.split(b"\0") if x] if listed.returncode == 0 else None
    deps = payload["deps"]
    if deps is None:
        try:
            deps = {suite: ss.derive_suite(repo, suite)}
        except Exception as exc:
            deps = {suite: {"error": f"{type(exc).__name__}: {exc}"}}
    everything = []
    def all_deps():
        if not everything:
            everything.append(deps if len(deps) > 1 else ss.derive(repo))
        return everything[0]
    observed = ss.normalise_observed(repo, payload["raw"], tracked)
    statement = ss.statement_starts(repo)
    gaps = ss.runtime_gaps(suite, observed, deps, statement, all_deps)
    own = ss.SKILLS_DIR + "/" + suite
    info = deps.get(suite) or {}
    outside = [o for o in observed if o["kind"] == "file" and not (o["path"] == own or o["path"].startswith(own + "/"))]
    body = [o for o in outside if o["phase"] in ("test", "between")]
    out = {"gaps": gaps, "tracked": tracked is not None, "files": len(outside), "body_files": len(body), "control": None}
    wide = ss.wide_sites(info, statement) if info and "error" not in info else set()
    for o in body:
        if ss.site_key(o["site"], statement) in wide:
            continue
        if o["path"] in info.get("files", {}) or any(ss.matches(g, o["path"]) for g in info.get("globs", {})):
            mutated = dict(deps)
            mutated[suite] = dict(info, files={k: v for k, v in info.get("files", {}).items() if k != o["path"]},
                                  globs={k: v for k, v in info.get("globs", {}).items() if not ss.matches(k, o["path"])})
            reported = [g for g in ss.runtime_gaps(suite, observed, mutated, statement, all_deps) if g["path"] == o["path"]]
            out["control"] = {"path": o["path"], "site": o["site"], "test": o["test"], "reported": bool(reported)}
            break
    print(json.dumps(out))
except BaseException:
    print(json.dumps({"error": traceback.format_exc()}))
'''


def check(suite, deps=None):
    """Compare what this run read with the derivation of `suite` in a child process; memoised per (suite, deps).

    deps: the derivation of every suite when the caller has it (`_shared`'s RealTree), else the child derives `suite`.
    Returns {"gaps", "files", "body_files", "control", "tracked", "errors", "tests"}; raises AssertionError when the child
    cannot run (the oracle failing to run is a failure, not a pass)."""
    key = (suite, id(deps))
    if key in CACHE:
        return CACHE[key]
    STATE["paused"] = True
    try:
        payload = {"scripts": str(SCRIPTS_DIR), "repo": str(REPO), "suite": suite, "deps": deps, "raw": records()}
        done = subprocess.run([sys.executable, "-I", "-B", "-c", CHILD], input=json.dumps(payload), capture_output=True,
                              text=True, timeout=CHILD_TIMEOUT)
    finally:
        STATE["paused"] = False
    try:
        out = json.loads(done.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        raise AssertionError(f"the end-of-suite check did not run (rc={done.returncode}): {done.stderr[-2000:]}")
    if "error" in out:
        raise AssertionError("the end-of-suite check failed to run:\n" + out["error"])
    out["errors"] = STATE["errors"]
    out["tests"] = sorted(STATE["modules"])
    CACHE[key] = out
    return out


def describe(gaps):
    """The gaps as lines a person can act on."""
    return "\n".join(f"  {g['kind']} {g['path']} (site {g['site']}, {g['phase']}, test {g['test']}): {g['why']}" for g in gaps)


class EndOfSuiteChecks:
    """The three end-of-suite tests of a suite (a mixin: a TestCase subclass in a test module sets SUITE)."""

    SUITE = None
    THIS_MODULE = None                                    # the module of the check itself: it does not count as "the run"
    THIS_FILE = None                                      # its file: it must sit in the tests directory of SUITE

    def derivation(self):
        """The derivation of every suite when the suite has it in hand (else None: the child derives its own)."""
        return None

    def result(self):
        self.assertEqual(self.SUITE, Path(self.THIS_FILE).resolve().parents[1].name,
                         "this module checks another suite than the one whose tests directory it is in")
        if not any(m != self.THIS_MODULE for m in STATE["modules"]):
            self.skipTest("no other test of the suite ran: this check judges the reads of a run")
        return check(self.SUITE, self.derivation())

    def test_every_file_and_directory_this_run_read_is_a_derived_source_of_the_suite(self):
        found = self.result()
        self.assertEqual([], found["gaps"], "the run read what the derivation does not name (repair the derivation: "
                                            "`python3 .agents/skills/_shared/scripts/skill_suites.py --derive`):\n"
                         + describe(found["gaps"]))

    def test_the_recorder_saw_reads_made_by_test_bodies_and_fixtures(self):
        found = self.result()
        self.assertTrue(STATE["installed"], "the recorder is not installed: the suite's test_000_suite_reads_* module did not run first")
        self.assertEqual(0, found["errors"], "the recorder failed on an event")
        self.assertTrue(found["tracked"], "git ls-files did not run: the check cannot tell tracked files from others")
        self.assertGreater(found["body_files"], 0, "no read from a test body, setUp or a class fixture was recorded: the "
                                                   "recorder observes nothing, so the check below proves nothing")

    def test_dropping_a_source_the_run_read_from_a_test_body_is_reported(self):
        control = self.result()["control"]
        self.assertIsNotNone(control, "no body read matched a derived source: the negative control has nothing to drop")
        self.assertTrue(control["reported"], f"the derivation lost {control['path']} (read at {control['site']} by "
                                             f"{control['test']}) and the check did not report it")
