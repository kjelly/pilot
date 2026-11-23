"""Ratchet lint: every process the skill scripts start goes through `bounded_run.run`, or is on an allowlist that only shrinks.

Class `unbounded-process-wait` (kjelly/pilot#427, AGENTS.md section 5.10 rule 2): a script that starts a command and waits for
it by the leader or by pipe EOF can hang, or call a finished command a timeout, and each such place was written on its own.
`.agents/skills/_shared/scripts/bounded_run.py` is the one implementation. This test reads the Python source (AST) of

* `.agents/skills/*/scripts/**/*.py` (the tests are not covered) and `scripts/pr_loop.py`, except the helper itself,

and fails on ANY reference (not only a call) to the names that start a process: `subprocess.run/Popen/call/check_call/
check_output/getoutput/getstatusoutput`, `os.system/popen/fork/forkpty/posix_spawn*` and the `os.exec*`/`os.spawn*` family (execl .. execvpe, spawnl .. spawnvpe),
`pty.spawn/fork`, `asyncio.create_subprocess_*`; on `from <those modules> import <such a name or *>`; on aliasing the
modules (`import subprocess as sp`); on `getattr`/`__import__`/`importlib.import_module` aimed at them by name; and on
`multiprocessing` and `ProcessPoolExecutor`. A reference that is not one of the forbidden FORMS (the module's own name followed
by a starter) is counted per function and compared with ALLOWLIST: `path::Qualname -> (count, reason)`. The count must match
exactly (migrating a site without lowering its count fails; copying a site fails), a stale or unknown key fails, an empty
reason or one that does not name the follow-up issue (#428; #296 for the secret scanner) fails, and the total is pinned by
CEILING. The helper is checked too: exactly one `Popen`, in a session of its own (`start_new_session=True`), and `run` takes
`limit` as a required keyword-only argument. Every call of `bounded_run.run` must name `limit=`.

What it cannot see: a computed `getattr` name, `exec`/`eval`, `ctypes`, `sys.modules[...]`, a start inside an imported module
outside the covered set, whether a reason is true or a limit is adequate, and shell scripts. The five sites that were
unbounded when this lint was written (checkout_preflight.git, pr_loop.run, pr_loop.git_change, merge_train.Train._run_git,
gh_runtime.run_gh) are migrated; the rest of the allowlist is kjelly/pilot#428, and it only shrinks.
"""
import ast
import collections
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
HELPER = ".agents/skills/_shared/scripts/bounded_run.py"
PR_LOOP = "scripts/pr_loop.py"
STARTERS = {
    "subprocess": {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"},
    "os": {"system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp",
           *(f"{kind}{suffix}" for kind in ("exec", "spawn") for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe"))},
    "pty": {"spawn", "fork"},
    "asyncio": {"create_subprocess_exec", "create_subprocess_shell"},
}
POOLS = {"ProcessPoolExecutor"}
FORBIDDEN_MODULES = {"multiprocessing"}
HELPER_MODULE = "bounded_run"

# The process starts that are not yet bounded: `path::Qualname -> (references, reason)`. Every reason names the issue that
# bounds it. The list only shrinks: migrate a site and delete its entry, lower the count of one that lost a start, lower CEILING.
GIT_READ = "a git call with no time limit and no process group of its own"
ALLOWLIST = {
    ".agents/skills/_shared/scripts/local_test_plan.py::main": (1, "`go list` of the repository's packages, no time limit: #428"),
    ".agents/skills/_shared/scripts/local_test_plan.py::main.git": (1, f"{GIT_READ}: #428"),
    ".agents/skills/_shared/scripts/secret_scan.py::_CatFile.__init__": (1, "the scanner's long-lived `git cat-file --batch` "
                                                                            "pipe; its budget is #296, not #428"),
    ".agents/skills/_shared/scripts/secret_scan.py::_Scan._walk": (1, "the scanner's `git` walk of a range; its budget is #296"),
    ".agents/skills/_shared/scripts/secret_scan.py::_run_git": (1, f"{GIT_READ}, in the secret scanner: #296"),
    ".agents/skills/_shared/scripts/skill_snapshot.py::create": (1, "`tar -x` of the snapshot, no time limit: #428"),
    ".agents/skills/_shared/scripts/skill_snapshot.py::git": (1, f"{GIT_READ}: #428"),
    ".agents/skills/issue-batch-planner/scripts/file_umbrella.py::run_command": (1, "a gh/git write with a leader-only timeout "
                                                                                 "(a finished write can be reported as a "
                                                                                 "timeout): #428"),
    ".agents/skills/issue-batch-planner/scripts/issue_batch_planner.py::run_readonly": (1, "a read with a leader-only timeout: #428"),
    ".agents/skills/issue-filing/scripts/create_issue.py::gh": (1, "a `gh` call with no time limit: #428"),
    ".agents/skills/issue-to-pr/scripts/claim.py::run": (1, "a claim command with a leader-only timeout: #428"),
    ".agents/skills/issue-to-pr/scripts/create_pr.py::execute": (1, "the PR-creating commands, no time limit: #428"),
    ".agents/skills/issue-to-pr/scripts/issue_gate.py::command": (1, "a gate command with no time limit: #428"),
    ".agents/skills/issue-to-pr/scripts/issue_gate.py::git": (1, f"{GIT_READ}: #428"),
    ".agents/skills/issue-to-pr/scripts/issue_gate.py::git_answer": (1, f"{GIT_READ}: #428"),
    ".agents/skills/issue-to-pr/scripts/issue_gate.py::remote_head": (1, "`git ls-remote` over the network, no time limit: #428"),
    ".agents/skills/issue-to-pr/scripts/repo_evidence.py::Context.read_file": (1, "`git show`, no time limit: #428"),
    ".agents/skills/issue-to-pr/scripts/repo_evidence.py::git": (1, f"{GIT_READ}: #428"),
    ".agents/skills/issue-to-pr/scripts/run_check.py::git": (1, f"{GIT_READ}: #428"),
    ".agents/skills/issue-to-pr/scripts/run_check.py::run_check": (1, "runs the repository's own test command, which may "
                                                                     "legitimately be long: its bound is a design decision "
                                                                     "of #428"),
    ".agents/skills/issue-to-pr/scripts/umbrella.py::gh_view": (1, "a `gh issue view` with a leader-only timeout: #428"),
    ".agents/skills/pr-ready/scripts/pr_gate.py::check_local.git": (1, f"{GIT_READ}: #428"),
    ".agents/skills/pr-ready/scripts/pr_gate.py::checkout_head": (1, f"{GIT_READ}: #428"),
    ".agents/skills/pr-ready/scripts/pr_gate.py::cmd": (1, "a gate command with no time limit: #428"),
    ".agents/skills/pr-ready/scripts/pr_gate.py::fetched_base": (1, f"{GIT_READ}: #428"),
    ".agents/skills/pr-ready/scripts/pr_gate.py::main": (2, "`gh pr ready` and the restore command, no time limit: #428"),
    ".agents/skills/pr-ready/scripts/pr_gate.py::tracked_entry": (1, f"{GIT_READ}: #428"),
    ".agents/skills/pr-ready/scripts/pr_gate.py::tracked_pin": (1, f"{GIT_READ}: #428"),
    ".agents/skills/pr-ready/scripts/run_check.py::main": (1, "runs the repository's own test command, which may "
                                                               "legitimately be long: its bound is a design decision of #428"),
    ".agents/skills/pr-ready/scripts/run_check.py::rev": (1, f"{GIT_READ}: #428"),
}
CEILING = 31  # the sum of the counts above: lower it when a site migrates; raising it needs a reason in review
FOLLOW_UP = {"secret_scan.py": "#296"}  # every other entry names #428
DEFAULT_FOLLOW_UP = "#428"


def is_starter(module, name):
    return name in STARTERS.get(module, ())


def literal_module(node):
    """The root module a string literal names (`"os"`, `"os.path"`), or None when `node` is not a literal."""
    return node.value.split(".")[0] if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def scan(source, rel):
    """(starts, calls, problems) of one source file: process-start references per `rel::Qualname` that the allowlist
    may cover; the functions that call `bounded_run.run` correctly; and the forms that nothing may use."""
    tree = ast.parse(source, rel)
    starts, calls, problems = collections.Counter(), collections.Counter(), []

    def where(quals):
        return f"{rel}::{'.'.join(quals) or '<module>'}"

    def forbid(node, quals, what):
        problems.append(f"{where(quals)} (line {node.lineno}): {what}")

    def note(node, quals):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in STARTERS and is_starter(node.value.id, node.attr):
                starts[where(quals)] += 1
            if node.attr in POOLS:
                forbid(node, quals, f"references {node.attr}: a process pool starts processes")
        elif isinstance(node, ast.Name) and node.id in POOLS:
            forbid(node, quals, f"references {node.id}: a process pool starts processes")
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            for alias in node.names:
                if root in STARTERS and (alias.name == "*" or is_starter(root, alias.name)):
                    forbid(node, quals, f"imports {alias.name} from {node.module} by name: use the module's own name, so that "
                                        "the references can be counted")
                elif root in FORBIDDEN_MODULES or alias.name in POOLS:
                    forbid(node, quals, f"imports {alias.name} from {node.module}: it starts processes")
                elif root == HELPER_MODULE and (alias.name == "*" or alias.name == "run"):
                    forbid(node, quals, "imports run from bounded_run by name: call bounded_run.run, so that its limit= can be checked")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    forbid(node, quals, f"imports {alias.name}: it starts processes")
                elif alias.asname and (alias.name in STARTERS or alias.name == HELPER_MODULE):
                    forbid(node, quals, f"imports {alias.name} as {alias.asname}: an alias hides the references")
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            first = node.args[0] if node.args else None
            if name == "getattr" and isinstance(func, ast.Name) and first is not None:
                target = first.id if isinstance(first, ast.Name) else literal_module(first)
                reached = literal_module(first.args[0]) if isinstance(first, ast.Call) and first.args else None
                if target in STARTERS or reached in STARTERS:
                    forbid(node, quals, "getattr on a module that starts processes: name the attribute, so that it can be counted")
            elif name in ("__import__", "import_module") and first is not None:
                module = literal_module(first)
                if module in STARTERS or module in FORBIDDEN_MODULES:
                    forbid(node, quals, f"{name}({first.value!r}) reaches a module that starts processes")
            elif name == "run" and isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                    and func.value.id == HELPER_MODULE:
                if any(keyword.arg == "limit" for keyword in node.keywords):
                    calls[where(quals)] += 1
                else:
                    forbid(node, quals, "bounded_run.run is called without limit=<seconds> as a keyword")

    def visit(node, quals):
        for child in ast.iter_child_nodes(node):
            inner = quals + [child.name] if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else quals
            note(child, inner)
            visit(child, inner)

    visit(tree, [])
    return starts, calls, problems


def helper_problems(source):
    """What is wrong with the helper itself: exactly one `Popen`, in a session of its own, and a required keyword `limit`."""
    tree = ast.parse(source, HELPER)
    problems = []
    popen = [n for n in ast.walk(tree) if (isinstance(n, ast.Attribute) and n.attr == "Popen")
             or (isinstance(n, ast.Name) and n.id == "Popen") or (isinstance(n, ast.alias) and n.name == "Popen")]
    if len(popen) != 1:
        problems.append(f"{HELPER} references Popen {len(popen)} times; it must start exactly one process, in one place")
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "Popen"):
        session = [k for k in call.keywords if k.arg == "start_new_session"]
        if not (len(session) == 1 and isinstance(session[0].value, ast.Constant) and session[0].value.value is True):
            problems.append(f"{HELPER}: Popen must say start_new_session=True literally: the group is what gets signalled")
    starts, _, forms = scan(source, HELPER)
    problems += forms
    if sum(starts.values()) != 1:
        problems.append(f"{HELPER} references {sum(starts.values())} names that start a process; it must be one (the Popen)")
    runs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "run"]
    if len(runs) != 1:
        problems.append(f"{HELPER} must define one run()")
    else:
        args = runs[0].args
        names = [a.arg for a in args.kwonlyargs]
        if "limit" not in names:
            problems.append(f"{HELPER}: run() must take `limit` as a keyword-only argument")
        elif args.kw_defaults[names.index("limit")] is not None:
            problems.append(f"{HELPER}: run()'s `limit` must have no default: every caller names its bound")
        if any(a.arg == "limit" for a in args.posonlyargs + args.args):
            problems.append(f"{HELPER}: run()'s `limit` must be keyword-only")
    return problems


def allowlist_problems(found, allow, ceiling):
    """The differences between the starts found and the allowlist, as one sentence each."""
    problems = []
    for key in sorted(found.keys() - allow.keys()):
        problems.append(f"{key}: {found[key]} unbounded process start(s) that are not on the allowlist; run the command through "
                        "bounded_run.run(argv, limit=...) (a new one may not be added to the allowlist)")
    for key in sorted(allow.keys() - found.keys()):
        problems.append(f"{key}: the allowlist names a function that no longer starts a process; delete the entry and lower CEILING")
    for key in sorted(allow.keys() & found.keys()):
        count, reason = allow[key]
        if count != found[key]:
            problems.append(f"{key}: the allowlist says {count} start(s) and there are {found[key]}; the count has to be exact "
                            "(a migrated site lowers it, a copied one is not allowed)")
        follow_up = next((v for name, v in FOLLOW_UP.items() if key.split("::")[0].endswith("/" + name)), DEFAULT_FOLLOW_UP)
        if not (isinstance(reason, str) and reason.strip() and re.search(re.escape(follow_up) + r"\b", reason)):
            problems.append(f"{key}: the reason must be non-empty and name {follow_up}, the issue that bounds it")
    if sum(count for count, _ in allow.values()) != ceiling:
        problems.append(f"the allowlist totals {sum(count for count, _ in allow.values())} start(s) and CEILING is {ceiling}: "
                        "the total only shrinks, so lower CEILING with the entry")
    return problems


def covered(root):
    """The files this lint reads under `root`: the skills' scripts (not their tests) and the PR loop, without the helper."""
    files = {p for p in root.glob(".agents/skills/*/scripts/**/*.py") if p.is_file() and "tests" not in p.relative_to(root).parts}
    if (root / PR_LOOP).is_file():
        files.add(root / PR_LOOP)
    return sorted(p for p in files if p.relative_to(root).as_posix() != HELPER)


def repo_problems(root, allow=None, ceiling=None):
    """Every problem of the tree under `root` (this repository, or a `git archive` of another revision)."""
    allow = ALLOWLIST if allow is None else allow
    ceiling = CEILING if ceiling is None else ceiling
    found, problems = collections.Counter(), []
    for path in covered(root):
        starts, _, forms = scan(path.read_text(), path.relative_to(root).as_posix())
        found.update(starts)
        problems += forms
    helper = root / HELPER
    problems += helper_problems(helper.read_text()) if helper.is_file() else [f"{HELPER} is missing: it is the one way to start a command"]
    return problems + allowlist_problems(found, allow, ceiling)


class RepositoryTests(unittest.TestCase):
    def test_every_process_start_goes_through_the_helper_or_is_on_the_allowlist(self):
        self.assertEqual([], repo_problems(ROOT))

    def test_the_lint_reads_what_it_says_it_reads(self):
        files = [p.relative_to(ROOT).as_posix() for p in covered(ROOT)]
        for expected in (PR_LOOP, ".agents/skills/_shared/scripts/checkout_preflight.py",
                         ".agents/skills/pr-review-merge/scripts/merge_train.py",
                         ".agents/skills/pr-review-merge/scripts/gh_runtime.py", ".agents/skills/pr-ready/scripts/pr_gate.py"):
            self.assertIn(expected, files)
        self.assertNotIn(HELPER, files, "the helper is checked on its own")
        self.assertGreaterEqual(len(files), 25, "a glob that stopped matching would pass everything")
        self.assertEqual([], [f for f in files if "/tests/" in f])

    def test_the_allowlist_only_shrinks_and_every_entry_gives_its_reason(self):
        self.assertEqual(CEILING, sum(count for count, _ in ALLOWLIST.values()))
        self.assertLessEqual(CEILING, 31, "31 at kjelly/pilot#427; #428 lowers it, and nothing may raise it without a review reason")
        for key, (count, reason) in ALLOWLIST.items():
            with self.subTest(key=key):
                self.assertGreaterEqual(count, 1)
                self.assertRegex(reason, r"#(428|296)\b")

    def test_the_five_sites_that_were_unbounded_run_through_the_helper(self):
        # The lint alone would pass a site that simply stopped starting its command: it has to CALL the helper.
        for rel, qualname in ((".agents/skills/_shared/scripts/checkout_preflight.py", "git"), (PR_LOOP, "run"),
                              (PR_LOOP, "git_change"), (".agents/skills/pr-review-merge/scripts/merge_train.py", "Train._run_git"),
                              (".agents/skills/pr-review-merge/scripts/gh_runtime.py", "run_gh")):
            with self.subTest(site=f"{rel}::{qualname}"):
                _, calls, _ = scan((ROOT / rel).read_text(), rel)
                self.assertEqual(1, calls[f"{rel}::{qualname}"], "one bounded_run.run(..., limit=...) call")

    def test_the_lint_fails_on_the_five_sites_before_they_were_migrated(self):
        # Shapes of the code of kjelly/pilot 7e183d3d, each under the name the allowlist would have to carry.
        before = {
            ".agents/skills/_shared/scripts/checkout_preflight.py": "import subprocess\ndef git(repo, *args):\n"
                                                                    "    return subprocess.run(['git', *args], capture_output=True)\n",
            PR_LOOP: "import subprocess\ndef run(args, timeout=1):\n    return subprocess.run(args, timeout=timeout)\n"
                     "def git_change(cwd, sub):\n    return subprocess.Popen(['git', sub], start_new_session=True)\n",
            ".agents/skills/pr-review-merge/scripts/merge_train.py": "import subprocess\nclass Train:\n    def _run_git(self, args, limit):\n"
                                                                    "        return subprocess.Popen(['git', *args], start_new_session=True)\n",
            ".agents/skills/pr-review-merge/scripts/gh_runtime.py": "import subprocess\ndef run_gh(args):\n"
                                                                   "    return subprocess.run(['gh', *args], timeout=75)\n",
        }
        found = collections.Counter()
        for rel, source in before.items():
            found.update(scan(source, rel)[0])
        named = sorted(problem.split(": ")[0] for problem in allowlist_problems(found, {}, 0) if "not on the allowlist" in problem)
        self.assertEqual(sorted([".agents/skills/_shared/scripts/checkout_preflight.py::git", f"{PR_LOOP}::run",
                                 f"{PR_LOOP}::git_change", ".agents/skills/pr-review-merge/scripts/merge_train.py::Train._run_git",
                                 ".agents/skills/pr-review-merge/scripts/gh_runtime.py::run_gh"]), named)
        with_this_allowlist = allowlist_problems(found, ALLOWLIST, CEILING)
        for key in found:
            self.assertTrue([p for p in with_this_allowlist if p.startswith(key + ":") and "not on the allowlist" in p], key)


class LintSelfTests(unittest.TestCase):
    """The lint finds what it must find and lets through what it must let through (AGENTS.md section 5.12): each form it
    forbids has a source that triggers it and a neighbouring source that passes."""

    def forms(self, source):
        return scan(source, "x/y.py")[2]

    def starts(self, source):
        return dict(scan(source, "x/y.py")[0])

    def test_a_reference_to_a_starter_is_counted_in_the_function_that_holds_it(self):
        self.assertEqual({"x/y.py::f": 1}, self.starts("import subprocess\ndef f():\n    return subprocess.run(['true'])\n"))
        self.assertEqual({"x/y.py::C.m": 1}, self.starts("import subprocess\nclass C:\n    def m(self):\n"
                                                         "        return subprocess.Popen(['true'])\n"))
        self.assertEqual({"x/y.py::f.g": 1}, self.starts("import os\ndef f():\n    def g():\n        os.system('true')\n"))
        self.assertEqual({"x/y.py::<module>": 1}, self.starts("import subprocess\nsubprocess.check_output(['true'])\n"))
        self.assertEqual({"x/y.py::f": 2}, self.starts("import subprocess\ndef f():\n    subprocess.run(['a'])\n    subprocess.run(['b'])\n"))

    def test_it_is_a_reference_not_a_call_that_counts(self):
        self.assertEqual({"x/y.py::f": 1}, self.starts("import subprocess\ndef f():\n    go = subprocess.run\n    return go\n"))
        self.assertEqual({"x/y.py::f": 1}, self.starts("import subprocess\ndef f():\n    return map(subprocess.check_output, [])\n"))
        self.assertEqual({"x/y.py::C": 1}, self.starts("import subprocess\nclass C(subprocess.Popen):\n    pass\n"))

    def test_every_starter_of_every_module_is_found(self):
        for module, names in STARTERS.items():
            for name in sorted(names):
                with self.subTest(name=f"{module}.{name}"):
                    self.assertEqual({"x/y.py::f": 1}, self.starts(f"import {module}\ndef f():\n    {module}.{name}()\n"))
        for name in ("execv", "execvp", "execlpe", "spawnl", "spawnvp", "spawnlpe"):
            with self.subTest(name=f"os.{name}"):
                self.assertEqual({"x/y.py::f": 1}, self.starts(f"import os\ndef f():\n    os.{name}()\n"))

    def test_what_is_not_a_starter_passes(self):
        for source in ("import subprocess\ndef f():\n    return subprocess.PIPE, subprocess.DEVNULL, subprocess.CompletedProcess\n",
                       "import subprocess\ndef f():\n    try:\n        pass\n    except subprocess.TimeoutExpired:\n        pass\n",
                       "import os\ndef f():\n    return os.path.join('a'), os.environ, os.killpg, os.getpid(), os.execution\n",
                       "import asyncio\nasync def f():\n    await asyncio.sleep(1)\n",
                       "import pty\ndef f():\n    return pty.STDIN_FILENO\n",
                       "def f(subprocess):\n    return subprocess\n",
                       "from subprocess import PIPE, CompletedProcess\nfrom os import path\nimport bounded_run\n",
                       "import bounded_run\ndef f():\n    return bounded_run.run(['true'], limit=5)\n"):
            with self.subTest(source=source):
                self.assertEqual(({}, []), (self.starts(source), self.forms(source)))

    def test_importing_a_starter_by_name_is_refused(self):
        for source in ("from subprocess import run\n", "from subprocess import Popen as P\n", "from subprocess import PIPE, check_output\n",
                       "from subprocess import *\n", "from os import system\n", "from os import execvp\n", "from os import *\n",
                       "from pty import spawn\n", "from asyncio import create_subprocess_exec\n"):
            with self.subTest(source=source):
                self.assertEqual(1, len(self.forms(source)), source)

    def test_aliasing_a_module_that_starts_processes_is_refused(self):
        for source in ("import subprocess as sp\n", "import os as o\n", "import pty as p\n", "import asyncio as aio\n",
                       "import multiprocessing as mp\n", "import bounded_run as br\n"):
            with self.subTest(source=source):
                self.assertEqual(1, len(self.forms(source)), source)
        self.assertEqual([], self.forms("import os.path as p\nimport json as j\n"), "an alias of a harmless module passes")

    def test_dynamic_access_by_name_is_refused(self):
        for source in ("import subprocess\ndef f():\n    return getattr(subprocess, 'run')\n",
                       "import os\ndef f(n):\n    return getattr(os, n)\n",
                       "def f():\n    return getattr(__import__('subprocess'), 'run')\n",
                       "def f():\n    return __import__('os').system('true')\n",
                       "def f():\n    return __import__('subprocess')\n",
                       "import importlib\ndef f():\n    return importlib.import_module('subprocess')\n",
                       "from importlib import import_module\ndef f():\n    return import_module('os')\n",
                       "def f():\n    return getattr('os', 'system')\n"):
            with self.subTest(source=source):
                self.assertTrue(self.forms(source), source)
        for source in ("def f(obj):\n    return getattr(obj, 'run')\n", "def f():\n    return __import__('json')\n",
                       "import importlib\ndef f():\n    return importlib.import_module('json')\n",
                       "import os\ndef f():\n    return getattr(os.path, 'join')\n"):
            with self.subTest(source=source):
                self.assertEqual([], self.forms(source), source)

    def test_process_pools_and_multiprocessing_are_refused(self):
        for source in ("import multiprocessing\n", "import multiprocessing.pool\n", "from multiprocessing import Process\n",
                       "from concurrent.futures import ProcessPoolExecutor\n",
                       "import concurrent.futures\ndef f():\n    return concurrent.futures.ProcessPoolExecutor()\n",
                       "def f(ProcessPoolExecutor):\n    return ProcessPoolExecutor()\n"):
            with self.subTest(source=source):
                self.assertTrue(self.forms(source), source)
        for source in ("from concurrent.futures import ThreadPoolExecutor\n",
                       "import concurrent.futures\ndef f():\n    return concurrent.futures.ThreadPoolExecutor()\n"):
            with self.subTest(source=source):
                self.assertEqual([], self.forms(source), source)

    def test_a_call_of_the_helper_must_name_its_limit(self):
        ok = "import bounded_run\ndef f(a):\n    return bounded_run.run(a, limit=5, cwd='.')\n"
        self.assertEqual(([], {"x/y.py::f": 1}), (self.forms(ok), dict(scan(ok, "x/y.py")[1])))
        for source in ("import bounded_run\ndef f(a):\n    return bounded_run.run(a)\n",
                       "import bounded_run\ndef f(a, **kw):\n    return bounded_run.run(a, **kw)\n",
                       "import bounded_run\ndef f(a):\n    return bounded_run.run(a, 5)\n",
                       "from bounded_run import run\n", "from bounded_run import *\n"):
            with self.subTest(source=source):
                self.assertTrue(self.forms(source), source)
        self.assertEqual([], self.forms("from bounded_run import Timeout\nimport bounded_run\n"), "the exception may be imported")

    GOOD_HELPER = ("import subprocess\nclass Timeout(subprocess.TimeoutExpired):\n    pass\n"
                   "def run(argv, *, limit, cwd=None):\n    return subprocess.Popen(argv, cwd=cwd, start_new_session=True)\n")

    def test_the_helper_must_start_one_process_in_a_session_of_its_own_and_require_a_limit(self):
        self.assertEqual([], helper_problems(self.GOOD_HELPER), "control: the helper as it must be")
        for case, source, expected in (
                ("a second Popen", self.GOOD_HELPER + "def other(a):\n    return subprocess.Popen(a, start_new_session=True)\n",
                 "references Popen 2 times"),
                ("no Popen", self.GOOD_HELPER.replace("subprocess.Popen(argv, cwd=cwd, start_new_session=True)", "None"),
                 "references Popen 0 times"),
                ("no new session", self.GOOD_HELPER.replace(", start_new_session=True", ""), "start_new_session=True literally"),
                ("a session that is switched off", self.GOOD_HELPER.replace("start_new_session=True", "start_new_session=False"),
                 "start_new_session=True literally"),
                ("a session that is a variable", self.GOOD_HELPER.replace("start_new_session=True", "start_new_session=flag"),
                 "start_new_session=True literally"),
                ("another start beside it", self.GOOD_HELPER + "def x():\n    return subprocess.run(['a'])\n",
                 "names that start a process; it must be one"),
                ("an os.system beside it", self.GOOD_HELPER + "import os\ndef x():\n    os.system('a')\n",
                 "names that start a process; it must be one"),
                ("a limit with a default", self.GOOD_HELPER.replace("limit, cwd", "limit=5, cwd"), "must have no default"),
                ("a positional limit", self.GOOD_HELPER.replace("*, limit, cwd=None", "limit, *, cwd=None"), "must be keyword-only"),
                ("no limit", self.GOOD_HELPER.replace("limit, ", ""), "must take `limit` as a keyword-only argument"),
                ("no run", self.GOOD_HELPER.replace("def run(", "def go("), "must define one run()")):
            with self.subTest(case=case):
                self.assertIn(expected, "; ".join(helper_problems(source)))

    def test_the_allowlist_must_match_exactly(self):
        found = collections.Counter({"a/b.py::f": 1, "a/b.py::g": 2})
        allow = {"a/b.py::f": (1, "unbounded git call: #428"), "a/b.py::g": (2, "two reads: #428")}
        self.assertEqual([], allowlist_problems(found, allow, 3), "control: exact")
        for case, change, expected in (
                ("a new site", dict(found, **{"a/b.py::h": 1}), "h: 1 unbounded process start(s) that are not on the allowlist"),
                ("a site copied inside a listed function", dict(found, **{"a/b.py::g": 3}), "g: the allowlist says 2 start(s) and there are 3"),
                ("a site that lost a start", dict(found, **{"a/b.py::g": 1}), "g: the allowlist says 2 start(s) and there are 1"),
                ("a migrated site left listed", {"a/b.py::f": 1}, "g: the allowlist names a function that no longer starts a process")):
            with self.subTest(case=case):
                self.assertIn(expected, "; ".join(allowlist_problems(collections.Counter(change), allow, 3)))
        for case, entry, expected in (("an empty reason", (1, ""), "f: the reason must be non-empty and name #428"),
                                      ("a blank reason", (1, "   "), "f: the reason must be non-empty and name #428"),
                                      ("a reason that names no issue", (1, "later"), "f: the reason must be non-empty and name #428"),
                                      ("a reason that names another issue", (1, "see #4280"), "f: the reason must be non-empty"),
                                      ("a reason that is not text", (1, None), "f: the reason must be non-empty")):
            with self.subTest(case=case):
                self.assertIn(expected, "; ".join(allowlist_problems(found, dict(allow, **{"a/b.py::f": entry}), 3)))
        self.assertIn("CEILING is 4", "; ".join(allowlist_problems(found, allow, 4)), "the total is pinned")
        scanner, found = {"x/secret_scan.py::f": (1, "a read: #428")}, collections.Counter({"x/secret_scan.py::f": 1})
        self.assertIn("name #296", "; ".join(allowlist_problems(found, scanner, 1)), "the secret scanner's follow-up is #296")
        self.assertEqual([], allowlist_problems(found, {"x/secret_scan.py::f": (1, "a read: #296")}, 1))


if __name__ == "__main__":
    unittest.main()
