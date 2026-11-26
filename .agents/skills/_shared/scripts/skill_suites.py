#!/usr/bin/env python3
"""Select the skill test suites a change can reach (kjelly/pilot#430): a derived, fail-closed local selection.

`make skill-test` runs every suite under `.agents/skills/*/tests`. This module derives, from the tests' own code, what each
suite can read, and maps a diff to the suites that can reach a changed path. It is a PURE module: it parses Python with
`ast` and walks the file tree, and starts no process and uses no network. CI keeps running the whole `make skill-test`; the
selection only decides what runs before a push, as the local receipt (`local_test_plan.py` prints it).

The invariant: the local receipt runs every skill suite whose tests can import, load or read a changed path; all suites when
any changed path is unknown (read by no suite), deleted, renamed or type-changed, or the derivation fails. Only an empty diff
selects none.

Derivation (`derive`). One abstract interpretation per suite, over the test modules `unittest discover -s tests -p test_*.py`
loads and every module they import, load by path or run. Only ANCHORED values lead to the repository: `__file__`, the
`__file__` of a repository module, the working directory (a suite runs with its own directory as cwd), and `git` run in a test
without `-C` or `cwd`. A bare string literal is not an edge (they are mostly fixture data). From an anchor the evaluator
follows constants, name, loop and comprehension bindings, `/` and `os.path.join`, `.parent`/`.parents[N]`, containers, and the
parameters of helpers through the call sites of the closure (a function that is only passed around, never called by name, has
none). An anchored value that reaches a read (`read_text`, `open`, `glob`, `iterdir`, `listdir`, `copytree`, a process
argument, `spec_from_file_location`, an import, a `mock.patch` target) is a source of the suite: a file, a subtree or a glob,
also under the name of the file a symbolic link points to. Imports resolve against the suite's search model (its `tests`
directory, the suite directory, the importer's directory and every `sys.path` insert of the closure), taking every candidate.
Values that do not come from an anchor (a temporary directory) cannot reach the repository. A parse error or any evaluation
error makes the suite's derivation fail, and a failed derivation selects every suite.

An `unbounded` read is one no path names: a path taken from the live environment or argv by test code (a variable the tests
set themselves is bounded), an import by a name nothing bounds, `exec` of text read from the repository, `git` run by a test in
the repository's own working directory. A suite with an unbounded read is selected whenever the diff selects by suite (a non-empty diff that is not already all).
A path joined to the repository root from a value the evaluator cannot compute (a name read out of a file or a listing) is
reported as `wide`, not followed.

Selection (`select`). The input is `git diff --name-status --no-renames -z BASE HEAD` as (status, path) pairs. An empty diff is
the ONLY empty selection. Any other diff selects every suite when it holds a status other than A or M (a deleted, renamed or
type-changed path), a path that is not canonical (absolute, `..`, empty, backslash), an added or modified path no suite
claims (an unknown path: not under `.agents/skills/<S>/` and matched by no derived file or glob), or when the derivation of any
suite failed or no suite was found; the reason names the first such path or cause, and a failed derivation is reported before
an unknown path. Otherwise `.agents/skills/<S>/...` selects S and every suite whose sources match the path; a suite with an
unbounded read is selected. The consequence is plain: a Go-only, playbook-only or docs-only change reaches no suite, is an
unknown path to every suite, and so selects the full suite (the local plan runs the plain `make skill-test` for it); CI's own
`docs` profile that skips `make skill-test` for such a change is not consulted.

Two oracles keep the derivation honest. `test_skill_suites.py` loads every suite's test modules under an audit hook and checks
that every file the LOAD touches is a derived source (it sees import-time reads only). Each suite also records what its own
RUN reads (`_shared/tests/suite_reads.py`: an audit hook installed by the suite's `test_000_suite_reads_<suite>.py`) and its
`test_zzz_suite_reads_<suite>.py` compares that with the derivation in a child process (`runtime_gaps`): a tracked file a test
body, `setUp` or `setUpClass` opened, imported or passed to a process, or a directory it listed, that no derived source names
is a failing test. The run oracle does NOT see: reads made by descendant processes (scripts, git, make, tmux, sh); existence
probes (`exists`, `is_file`, `stat`: CPython raises no audit event); branches that did not run (a skip, an error path); data
beyond what that run had; and a listing is judged by the directories the derived globs list. A read at a `wide` site is
accepted only when no other suite claims the path (an unclaimed path selects every suite).

Known limits (what the derivation cannot see; CI is the backstop): a path built from a bare literal, a value laundered through
a function the evaluator cannot resolve (a callback, a method of a third-party object), a directory handed to such a function,
an attribute of an object whose class it cannot tell, a data-dependent path under the repository root (`wide`), `getattr` with
a computed name, and what a test reads only when it chdirs elsewhere.
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import posixpath
import re
import sys

sys.dont_write_bytecode = True

SKILLS_DIR = ".agents/skills"
UNIVERSE_PREFIXES = (".agents/", ".claude/", ".codex/")
# `unittest discover -s tests -p 'test_*.py'`: the Makefile's glob and the same rule here.
TEST_PATTERN = re.compile(r"test_.*\.py\Z")
MAX_ALTERNATIVES = 64     # a value with more alternatives is widened (paths) or collapsed
MAX_TEXT = 200           # a string longer than this is prose, not a path: it is not tracked
MAX_DATA = 200           # a container of strings bigger than this is data, not a list of paths: it is not tracked
MAX_TEXT_GROWTH = 3      # times one stored value may gain new strings before they are not tracked any more
TEXT_KINDS = ("c", "r")
MAX_GROWTH = 16          # times one stored value may grow before it is widened
MAX_PASSES = 60          # passes over a closure that keeps growing
MAX_STEPS = 12_000_000   # evaluation budget of one suite: past it the derivation fails (fail closed)
MAX_REASONS = 8          # reasons listed per suite in a selection (the rest are counted)
RECURSION_LIMIT = 3000   # the evaluator recurses along the chains of names, calls and attributes it follows


# A call on a line that ends in this comment is not followed as a read. It is for the evaluator's own probes of the tree it
# analyses (`Analyzer.exists`): when a suite's tests import this module it is analysed like any other code, and a probe whose
# argument is a name from the analysed program (`list`, `file`, `e`, a dotfile) would otherwise claim a repository path of
# that name for the suite, so that a changed root file called `list` or `.gitignore` selected only `_shared` instead of every
# suite. A probe is not a claim; the real reads of this module (the walks of `.agents`, `.claude` and `.codex`) stay followed.
OPAQUE_MARK = re.compile(r"#\s*derive:\s*opaque\b")


class DeriveError(Exception):
    """The derivation of a suite failed (a parse or evaluation error): the selection must not trust it."""


# --------------------------------------------------------------------------------------------------------------------
# Values. A value is a frozenset of atoms; an atom is a tuple whose first item names its kind:
#   ("c", v)      a constant (str, int, float, bool, None, bytes)
#   ("p", pat)    an anchored path: repo-relative, "." is the repository root, `*` one segment, `**` any depth
#   ("r", pat)    a relative path or partly known string (`**` marks the unknown parts); it anchors at the cwd in a path sink
#   ("u",)        known not to reach the repository (a temporary directory, an object) or simply unknown
#   ("e",)        derived from the environment or argv: it may name anything, so a path sink reading it is unbounded
#   ("t", why)    anchor-derived and unbounded
#   ("m", pat)    a module (or a spec of one) whose file is pat
#   ("f", id) / ("k", id)   a function / class of the closure
#   ("seq", kind, elems, star)   elems: tuple of values; with star, the last value repeats any number of times
#   ("map", entries)             entries: tuple of (keys, values)
# --------------------------------------------------------------------------------------------------------------------
U = ("u",)
E = ("e",)
UNK = frozenset([U])
ENV = frozenset([E])
EMPTY: frozenset = frozenset()
WHITESPACE = re.compile(r"\s")
NOT_A_PATH = re.compile(r"[\s()\\|^$'\"{}=,;]")


def const(value) -> frozenset:
    """A string constant. Other constants (numbers, booleans, None) are not tracked: they cannot name a place."""
    if isinstance(value, str) and len(value) <= MAX_TEXT and not WHITESPACE.search(value):
        return frozenset([("c", value)])
    return UNK


def paths(*pats) -> frozenset:
    """A value of anchored paths (the patterns that stayed inside the repository)."""
    return frozenset(("p", p) for p in pats if p is not None)


def seq_of(elems, kind="list", star=False) -> frozenset:
    """A value that is one sequence of the given element values."""
    return frozenset([("seq", kind, tuple(elems), star)])


def norm(pat):
    """A repo-relative pattern in canonical form, or None when it leaves the repository (or is absolute)."""
    if pat.startswith("/"):
        return None
    out = posixpath.normpath(pat) if pat else "."
    if out == ".." or out.startswith("../"):
        return None
    return out


def join_pat(base, comp):
    """`base / comp` for two pattern strings; None when the result leaves the repository."""
    if comp.startswith("/"):
        return None
    return norm(comp if base == "." else base + "/" + comp)


def parent_pat(pat, n=1):
    """The n-th parent of a pattern, or None above the repository root."""
    for _ in range(n):
        if pat == ".":
            return None
        pat = posixpath.dirname(pat) or "."
    return pat


def has_wild(pat):
    """Whether a pattern holds a wildcard (an exact path does not)."""
    return "*" in pat or "?" in pat or "[" in pat


_REGEX_CACHE: dict = {}


def pattern_regex(pat):
    """The regex of a glob pattern: `**` matches any depth (also none after `/`), `*` and `?` stay inside a segment."""
    cached = _REGEX_CACHE.get(pat)
    if cached is None:
        out, i = [], 0
        while i < len(pat):
            if pat.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
            elif pat.startswith("**", i):
                out.append(".*")
                i += 2
            elif pat[i] == "*":
                out.append("[^/]*")
                i += 1
            elif pat[i] == "?":
                out.append("[^/]")
                i += 1
            else:
                out.append(re.escape(pat[i]))
                i += 1
        cached = _REGEX_CACHE[pat] = re.compile("".join(out) + r"\Z")
    return cached


def matches(source, path):
    """Whether a source pattern names the changed path: equal, or a glob that matches."""
    return source == path or (has_wild(source) and pattern_regex(source).match(path) is not None)


# --------------------------------------------------------------------------------------------------------------------
# Parsing and indexing of a module: scopes, bindings, calls.
# --------------------------------------------------------------------------------------------------------------------
class Scope:
    """A module, function, class or comprehension scope: its name bindings (flow-insensitive: every assignment counts)."""

    def __init__(self, kind, node, parent, mod):
        self.kind, self.node, self.parent, self.mod = kind, node, parent, mod
        self.bindings: dict = {}
        self.outer: dict = {}          # name -> the scope a `global` / `nonlocal` statement sends its assignments to

    def bind(self, name, binding):
        owner = self.outer.get(name, self)
        owner.bindings.setdefault(name, []).append(binding)


class Mod:
    """One parsed Python file of the closure."""

    def __init__(self, path, tree):
        self.path, self.tree = path, tree
        self.opaque_lines: set = set()  # lines marked `# derive: opaque`: their calls are not reads (see OPAQUE_MARK)
        self.dir = posixpath.dirname(path) or "."
        self.scope = Scope("module", tree, None, self)
        self.calls: list = []          # (Call, Scope)
        self.imports: list = []        # (kind, module name, level, node)
        self.attrs: dict = {}          # attribute name -> [(binding, scope, owner class id)] of `x.attr = value` and class bodies
        self.mutations: dict = {}      # name -> [(value node, scope)]: x.append(v), x[k] = v, x.update(...)
        self.sys_path: list = []       # (kind, node, scope): inserts into sys.path
        self.env_sets: list = []       # (kind, nodes..., scope): what the code puts into os.environ
        self.funcs: dict = {}          # id(FunctionDef) -> (FunctionDef, Scope of its body, class node or None)
        self.comp_scopes: dict = {}    # id(comprehension node) -> its Scope
        self.classes: dict = {}        # id(ClassDef) -> (ClassDef, Scope of its body)
        self.returns: dict = {}        # id(function node) -> [value nodes]


MUTATORS = {"append", "add", "appendleft", "extend", "update", "insert", "setdefault"}


class Indexer:
    """One traversal of a module: builds its scopes and records its bindings, calls, imports and stores."""

    def __init__(self, mod):
        self.mod = mod

    def run(self):
        self.stmts(self.mod.tree.body, self.mod.scope, None)
        return self.mod

    # -- statements ------------------------------------------------------------------------------------------------
    def stmts(self, body, scope, cls):
        for node in body:
            self.node(node, scope, cls)

    def node(self, node, scope, cls):
        mod = self.mod
        t = type(node)
        if t in (ast.FunctionDef, ast.AsyncFunctionDef):
            scope.bind(node.name, ("def", node))
            for deco in node.decorator_list:
                self.node(deco, scope, cls)
            for default in node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
                self.node(default, scope, cls)
            inner = Scope("func", node, scope, mod)
            args = node.args
            for a in args.posonlyargs + args.args + args.kwonlyargs:
                inner.bind(a.arg, ("param", node, a.arg))
            for a in (args.vararg, args.kwarg):
                if a is not None:
                    inner.bind(a.arg, ("unknown",))
            mod.funcs[id(node)] = (node, inner, cls)
            mod.returns[id(node)] = []
            self.stmts(node.body, inner, None)
        elif t is ast.ClassDef:
            scope.bind(node.name, ("class", node))
            for part in node.bases + [k.value for k in node.keywords] + node.decorator_list:
                self.node(part, scope, cls)
            inner = Scope("class", node, scope, mod)
            mod.classes[id(node)] = (node, inner)
            self.stmts(node.body, inner, node)
            for name, bindings in inner.bindings.items():     # class-level names are attributes of the class
                for b in bindings:
                    mod.attrs.setdefault(name, []).append((b, inner, id(node)))
        elif t is ast.Lambda:
            inner = Scope("func", node, scope, mod)
            for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                inner.bind(a.arg, ("unknown",))
            for a in (node.args.vararg, node.args.kwarg):
                if a is not None:
                    inner.bind(a.arg, ("unknown",))
            self.node(node.body, inner, cls)
        elif t in (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp):
            inner = Scope("comp", node, scope, mod)
            for gen in node.generators:
                self.target(inner, gen.target, ("iter", gen.iter, ()))
                self.node(gen.iter, inner, cls)
                for cond in gen.ifs:
                    self.node(cond, inner, cls)
            if t is ast.DictComp:
                self.node(node.key, inner, cls)
                self.node(node.value, inner, cls)
            else:
                self.node(node.elt, inner, cls)
            mod.comp_scopes[id(node)] = inner
        elif t is ast.Assign:
            self.node(node.value, scope, cls)
            for target in node.targets:
                self.target(scope, target, ("assign", node.value, ()))
        elif t is ast.AnnAssign:
            if node.value is not None:
                self.node(node.value, scope, cls)
                self.target(scope, node.target, ("assign", node.value, ()))
        elif t is ast.AugAssign:
            self.node(node.value, scope, cls)
            if isinstance(node.target, ast.Name):                  # `x += v` is `x = x + v`
                combined = ast.BinOp(left=ast.Name(id=node.target.id, ctx=ast.Load()), op=node.op, right=node.value)
                scope.bind(node.target.id, ("assign", ast.copy_location(combined, node), ()))
            else:
                self.target(scope, node.target, ("assign", node.value, ()))
        elif t in (ast.For, ast.AsyncFor):
            self.node(node.iter, scope, cls)
            self.target(scope, node.target, ("iter", node.iter, ()))
            self.stmts(node.body, scope, cls)
            self.stmts(node.orelse, scope, cls)
        elif t in (ast.With, ast.AsyncWith):
            for item in node.items:
                self.node(item.context_expr, scope, cls)
                if item.optional_vars is not None:
                    self.target(scope, item.optional_vars, ("unknown",))
            self.stmts(node.body, scope, cls)
        elif t is ast.Import:
            for alias in node.names:
                if alias.asname:
                    scope.bind(alias.asname, ("import", alias.name, None, alias.name, 0))
                else:
                    root = alias.name.split(".")[0]
                    scope.bind(root, ("import", root, None, root, 0))
                mod.imports.append(("import", alias.name, 0, node))
        elif t is ast.ImportFrom:
            module = node.module or ""
            for alias in node.names:
                if alias.name != "*":
                    scope.bind(alias.asname or alias.name, ("import", module, alias.name, module + "." + alias.name, node.level))
            mod.imports.append(("from", module, node.level, node))
            for alias in node.names:
                if alias.name != "*":
                    mod.imports.append(("from-name", (module + "." if module else "") + alias.name, node.level, node))
        elif t is ast.Try or t.__name__ == "TryStar":
            self.stmts(node.body, scope, cls)
            for handler in node.handlers:
                if handler.type is not None:
                    self.node(handler.type, scope, cls)
                if handler.name:
                    scope.bind(handler.name, ("unknown",))
                self.stmts(handler.body, scope, cls)
            self.stmts(node.orelse, scope, cls)
            self.stmts(node.finalbody, scope, cls)
        elif t is ast.Return:
            if node.value is not None:
                self.node(node.value, scope, cls)
                owner = self.owner_function(scope)
                if owner is not None:
                    mod.returns[id(owner)].append(node.value)
        elif t is ast.NamedExpr:
            self.node(node.value, scope, cls)
            self.target(scope, node.target, ("assign", node.value, ()))
        elif t is ast.Call:
            mod.calls.append((node, scope))
            self.note_call(node, scope)
            for child in ast.iter_child_nodes(node):
                self.node(child, scope, cls)
        elif t is ast.Global:
            for name in node.names:
                scope.outer[name] = mod.scope
        elif t is ast.Nonlocal:
            for name in node.names:
                enclosing = scope.parent
                while enclosing is not None and not (enclosing.kind == "func" and name in enclosing.bindings):
                    enclosing = enclosing.parent
                if enclosing is not None:
                    scope.outer[name] = enclosing
        else:
            for child in ast.iter_child_nodes(node):
                self.node(child, scope, cls)

    @staticmethod
    def owner_class(scope):
        """The id of the class whose method (or nested function) a scope is, or None."""
        while scope is not None:
            if scope.kind == "class":
                return id(scope.node)
            scope = scope.parent
        return None

    @staticmethod
    def owner_function(scope):
        while scope is not None and scope.kind not in ("func",):
            scope = scope.parent
        return scope.node if scope is not None else None

    # -- targets ---------------------------------------------------------------------------------------------------
    def target(self, scope, target, binding):
        """Bind an assignment target; `binding` is ("assign" | "iter", value node, projection path) or ("unknown",)."""
        mod = self.mod
        t = type(target)
        if t is ast.Name:
            scope.bind(target.id, binding)
        elif t in (ast.Tuple, ast.List):
            for i, element in enumerate(target.elts):
                if isinstance(element, ast.Starred):
                    self.target(scope, element.value, ("unknown",))
                elif binding[0] == "unknown":
                    self.target(scope, element, binding)
                else:
                    self.target(scope, element, (binding[0], binding[1], binding[2] + (i,)))
        elif t is ast.Starred:
            self.target(scope, target.value, ("unknown",))
        elif t is ast.Attribute:
            self.node(target.value, scope, None)
            if binding[0] in ("assign", "iter"):
                owner = self.owner_class(scope) if isinstance(target.value, ast.Name) and target.value.id in ("self", "cls") \
                    else None
                mod.attrs.setdefault(target.attr, []).append((binding, scope, owner))
            if isinstance(target.value, ast.Name) and target.value.id == "sys" and target.attr == "path":
                mod.sys_path.append(("assign", binding, scope))
        elif t is ast.Subscript:
            self.node(target.value, scope, None)
            self.node(target.slice, scope, None)
            if isinstance(target.value, ast.Attribute) and isinstance(target.value.value, ast.Name) \
                    and target.value.value.id == "sys" and target.value.attr == "path":
                mod.sys_path.append(("assign", binding, scope))
            elif isinstance(target.value, ast.Attribute) and target.value.attr == "environ" and binding[0] == "assign":
                mod.env_sets.append(("item", target.slice, binding[1], scope))
            elif isinstance(target.value, ast.Name) and binding[0] == "assign":
                mod.mutations.setdefault(target.value.id, []).append((("item", target.slice, binding[1]), scope))

    # -- calls: mutations and sys.path -------------------------------------------------------------------------------
    def note_call(self, call, scope):
        f = call.func
        if not isinstance(f, ast.Attribute):
            return
        if f.attr in ("update", "setdefault") and isinstance(f.value, ast.Attribute) and f.value.attr == "environ" and call.args:
            self.mod.env_sets.append(("call", f.attr, call, scope))
        if f.attr == "dict" and len(call.args) >= 2 and (
                (isinstance(call.args[0], ast.Attribute) and call.args[0].attr == "environ") or
                (isinstance(call.args[0], ast.Constant) and call.args[0].value == "os.environ")):
            self.mod.env_sets.append(("patch", "dict", call, scope))
        if f.attr in MUTATORS and isinstance(f.value, ast.Name) and call.args:
            self.mod.mutations.setdefault(f.value.id, []).append((("call", f.attr, call), scope))
        if isinstance(f.value, ast.Attribute) and isinstance(f.value.value, ast.Name) \
                and f.value.value.id == "sys" and f.value.attr == "path" and f.attr in ("insert", "append", "extend"):
            if call.args:
                self.mod.sys_path.append(("call", call, scope))


# --------------------------------------------------------------------------------------------------------------------
# Name tables of the evaluator.
# --------------------------------------------------------------------------------------------------------------------
PATH_CTORS = {"pathlib.Path", "pathlib.PurePath", "pathlib.PurePosixPath", "pathlib.PosixPath", "pathlib.PureWindowsPath",
              "pathlib.WindowsPath"}
# Calls that pass a path (or string) through unchanged: the result names the same place.
IDENTITY_CALLS = {"os.fspath", "os.path.abspath", "os.path.realpath", "os.path.normpath", "os.path.expanduser",
                  "os.path.expandvars", "os.path.normcase", "os.fsdecode", "os.fsencode", "pathlib.Path.resolve"}
IDENTITY_BUILTINS = {"str", "bytes", "repr", "format"}
SEQ_BUILTINS = {"list", "tuple", "set", "frozenset", "sorted", "reversed", "iter", "next"}
IDENTITY_METHODS = {"resolve", "absolute", "expanduser", "as_posix", "as_uri", "__fspath__", "__str__", "strip", "lstrip",
                    "rstrip", "lower", "upper", "casefold", "removeprefix", "removesuffix", "encode", "decode"}
# Calls that cannot read a file from a path value (they compare, format or measure it): not a "use" of their arguments.
PURE_BUILTINS = {"len", "isinstance", "issubclass", "type", "id", "hash", "bool", "int", "float", "print", "repr", "format",
                 "min", "max", "sum", "any", "all", "enumerate", "zip", "map", "filter", "range", "abs", "round", "divmod",
                 "callable", "hasattr", "getattr", "setattr", "vars", "dir", "super", "object", "property", "staticmethod",
                 "classmethod", "slice", "ord", "chr", "hex", "bin", "isinstance", "NotImplemented", "Exception", "ValueError",
                 "TypeError", "KeyError", "RuntimeError", "OSError", "AssertionError", "SystemExit", "dict", "list", "tuple",
                 "set", "frozenset", "sorted", "reversed", "iter", "next", "str", "bytes"}
ASSERT_PREFIXES = ("assert", "fail", "skipTest", "subTest", "addCleanup", "addTypeEqualityFunc", "enterContext")
# Path methods that read the file or the directory the receiver names (exact file).
FILE_READS = {"read_text", "read_bytes", "open", "exists", "is_file", "is_dir", "is_symlink", "stat", "lstat", "samefile",
              "readlink", "owner", "group", "is_mount"}
DIR_READS = {"iterdir"}
GLOB_READS = {"glob", "rglob"}
# Calls whose first argument is a path they read.
OS_FILE_CALLS = {"os.stat", "os.lstat", "os.path.exists", "os.path.isfile", "os.path.isdir", "os.path.islink",
                 "os.path.getsize", "os.path.getmtime", "os.path.samefile", "os.access", "os.readlink", "os.path.lexists",
                 "io.open", "codecs.open", "os.open"}
OS_DIR_CALLS = {"os.listdir", "os.scandir", "os.walk", "os.fwalk", "shutil.copytree", "shutil.make_archive"}
OS_FILE_COPY = {"shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copymode", "shutil.move"}
GLOB_CALLS = {"glob.glob", "glob.iglob"}
PROCESS_STARTS = {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
                  "subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen", "asyncio.create_subprocess_exec",
                  "asyncio.create_subprocess_shell", "pty.spawn"}
PROCESS_STARTS |= {f"os.{kind}{suffix}" for kind in ("exec", "spawn") for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")}
GIT_NO_REPO = {"init", "clone", "--version", "version", "help"}
# What a call of these cannot read from a path argument (it builds, compares or stores the path): not a use of the argument.
NO_READ_CALLS = PATH_CTORS | {"os.path.join", "os.path.dirname", "os.path.basename", "os.path.splitext", "os.path.split",
                              "os.path.relpath", "os.path.isabs", "sys.path.insert", "sys.path.append", "sys.path.extend",
                              "sys.path.remove", "os.chdir"} | IDENTITY_CALLS
NO_READ_METHODS = IDENTITY_METHODS | {"append", "extend", "add", "insert", "update", "get", "pop", "items", "keys", "values",
                                      "join", "split", "format", "startswith", "endswith", "replace", "index", "count", "copy",
                                      "relative_to", "is_relative_to", "with_name", "with_suffix", "with_stem", "joinpath",
                                      "mock_calls", "return_value"}
NOT_ARGUMENT_KEYWORDS = {"env", "text", "check", "capture_output", "timeout", "limit", "encoding", "errors", "input"}
SPEC_CALLS = {"importlib.util.spec_from_file_location", "importlib.machinery.SourceFileLoader",
              "importlib.util.spec_from_loader"}
RUN_PATH_CALLS = {"runpy.run_path"}
IMPORT_CALLS = {"importlib.import_module", "__import__"}
# The environment and argv are containers of values that may name anything (an environment-derived path is unbounded).
ENV_CONTAINERS = {"os.environ", "os.environb", "sys.argv"}
ENV_CALLS = {"os.getenv", "os.getenvb"}
CWD_QUALS = {"os.getcwd", "pathlib.Path.cwd", "os.curdir", "os.path.curdir"}
EXEC_CALLS = {"exec", "eval", "compile"}
PATCH_CALLS = {"unittest.mock.patch"}


class Analyzer:
    """The abstract interpretation of ONE suite."""

    def __init__(self, repo, suite, parse):
        self.repo, self.suite, self.parse = repo, suite, parse
        self.sdir = f"{SKILLS_DIR}/{suite}"
        self.mods: dict = {}
        self.in_process: set = set()     # modules the test process imports or loads
        self.via: dict = {}              # module path -> how it joined the closure
        self.search_extra: set = set()   # directories added to sys.path by the closure
        self.deps: dict = {}             # (kind, pattern) -> why
        self.unbounded: dict = {}        # why -> True
        self.wide: dict = {}             # why -> True: reads under the repository root of a path the evaluator cannot compute
        self.steps = 0
        # The values of the names, parameters, returns and attributes live in one store that only grows (a fixpoint): a pass
        # evaluates each of them once, a name that is met again while it is being evaluated answers with what the earlier
        # passes found, and passes repeat until nothing grows.
        self.store: dict = {}
        self.growth: dict = {}
        self.text_growth: dict = {}
        self.dirty = True
        self.visited: set = set()
        self.reentered: set = set()
        self.memo: dict = {}
        self.changed = False
        self.func_nodes: dict = {}
        self.class_nodes: dict = {}
        self.by_name: dict = {}

    def begin_pass(self):
        self.visited = set()
        self.memo = {}
        self.changed = False
        if self.dirty:
            self.dirty = False
            self.func_nodes, self.class_nodes, self.by_name = {}, {}, {}
            for mod in self.mods.values():
                for fid, (fnode, fscope, cls) in mod.funcs.items():
                    self.func_nodes[fid] = (fnode, fscope, cls, mod)
                for cid, (cnode, cscope) in mod.classes.items():
                    self.class_nodes[cid] = (cnode, cscope, mod)
                for call, scope in mod.calls:
                    name = self.terminal(call.func)
                    if name:
                        self.by_name.setdefault(name, []).append((call, scope))

    def keyed(self, key, compute):
        """The value stored under `key`, evaluated once per pass; re-entered while evaluating, it answers with the stored one
        (and is evaluated again at once, a few times, when that happened and its value grew)."""
        if key in self.visited:
            self.reentered.add(key)
            return self.store.get(key, EMPTY)
        self.visited.add(key)
        for _ in range(4):
            self.reentered.discard(key)
            new = compute()
            old = self.store.get(key, EMPTY)
            grew = False
            merged = old if new <= old else self.canon(old | new)
            if merged != old:
                grown = self.growth[key] = self.growth.get(key, 0) + 1
                if len(merged) > MAX_ALTERNATIVES or grown > MAX_GROWTH:
                    merged = self.widen(merged)
                elif any(a[0] in TEXT_KINDS for a in merged - old):
                    # A string that is built in a loop (`out += piece`) is longer after every pass: past a few passes the
                    # strings of this value are not tracked any more (a path is not built that way).
                    texts = self.text_growth[key] = self.text_growth.get(key, 0) + 1
                    if texts > MAX_TEXT_GROWTH:
                        merged = frozenset(a for a in merged if a[0] not in TEXT_KINDS) | frozenset([("r", "**")])
                if merged != old:
                    self.store[key] = merged
                    self.changed = grew = True
            if not grew or key not in self.reentered:
                break
        return self.store.get(key, EMPTY)

    # -- bookkeeping -------------------------------------------------------------------------------------------------
    def tick(self):
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise DeriveError("evaluation budget exceeded")

    def exists(self, rel):
        return os.path.isfile(os.path.join(self.repo, rel))  # derive: opaque (a probe of the analysed tree, not a claim)

    @staticmethod
    def terminal(func):
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    def add_module(self, rel, via, in_process=True):
        """Put a repository Python file into the closure (parsing it); False when it is not a file or already there.
        `in_process`: the test process imports or loads it (a script a test only runs as a process has a working directory
        of its own, which the test chooses)."""
        rel = norm(rel)
        if rel is None or not rel.endswith(".py"):
            return False
        if rel in self.mods:
            if in_process and rel not in self.in_process:
                self.in_process.add(rel)
                self.changed = True
            return False
        if not self.exists(rel):
            return False
        self.mods[rel] = self.parse(rel)
        self.via[rel] = via
        if in_process:
            self.in_process.add(rel)
        self.dirty = self.changed = True
        return True

    def dep(self, kind, pat, node_mod, node, how):
        """Record that the suite reads `pat` ("file", "tree" (a directory subtree) or "glob"); `how` names the edge."""
        if pat is None:
            return
        line = getattr(node, "lineno", 0)
        why = f"{how} at {node_mod.path}:{line}" if node_mod is not None else how
        if NOT_A_PATH.search(pat):
            # text that only looks like a path (a regular expression, a message): no repository file is named so
            self.wide.setdefault(f"{how} of text that is not a path at {node_mod.path if node_mod else '?'}:{line}", True)
            return
        if kind == "tree":
            pat = "**" if pat == "." else pat + "/**"
        if pat in ("**", "*", ".") or pat.startswith(("**", "*")):
            # A path joined to the repository root from a value the evaluator cannot compute (a name read out of a file or a
            # listing): the tests read data-dependent files. It is reported, not followed: a suite that does this is not
            # selected for every change, since nothing says which files it reads.
            self.wide.setdefault(f"{how} of an unknown path under the repository root at "
                                 f"{node_mod.path if node_mod else '?'}:{line}", True)
            return
        self.deps.setdefault((kind if kind != "tree" else "glob", pat), why)

    # -- the closure -------------------------------------------------------------------------------------------------
    def run(self):
        tests_dir = f"{self.sdir}/tests"
        try:
            names = sorted(os.listdir(os.path.join(self.repo, tests_dir)))
        except OSError as exc:
            raise DeriveError(f"cannot list {tests_dir}: {exc}")
        for name in names:
            rel = f"{tests_dir}/{name}"
            if TEST_PATTERN.match(name) and os.path.isfile(os.path.join(self.repo, rel)):
                self.add_module(rel, "unittest discovery")
        if not self.mods:
            return
        for _ in range(MAX_PASSES):
            self.begin_pass()
            for mod in list(self.mods.values()):
                self.process(mod)
            if not self.changed:
                break
        else:
            raise DeriveError("the evaluation did not reach a fixpoint")
        for rel in self.mods:
            self.deps.setdefault(("file", rel), f"{self.via[rel]}")

    def process(self, mod):
        for kind, node, scope in mod.sys_path:
            self.note_sys_path(mod, kind, node, scope)
        for item in mod.imports:
            self.resolve_import_edge(mod, item)
        for call, scope in mod.calls:
            self.effects(mod, call, scope)

    def note_sys_path(self, mod, kind, node, scope):
        if kind == "call":
            call = node
            vs = self.val(call.args[-1], scope) if call.args else EMPTY
        else:                                                   # sys.path[...] = value / sys.path = value
            binding = node
            vs = self.elems(self.binding_val(binding, scope)) | self.binding_val(binding, scope)
        for atom in self.flatten(vs):
            ap = self.to_ap(atom)
            if ap is not None and ap[0] == "p" and not has_wild(ap[1]) and ap[1] not in self.search_extra:
                self.search_extra.add(ap[1])
                self.changed = True

    def flatten(self, vs, depth=0):
        """The leaf atoms of a value (sequence elements included)."""
        out = []
        for atom in vs:
            if atom[0] == "seq" and depth < 4:
                for elem in atom[2]:
                    out.extend(self.flatten(elem, depth + 1))
            else:
                out.append(atom)
        return out

    # -- imports -----------------------------------------------------------------------------------------------------
    def search_dirs(self, mod):
        dirs = [f"{self.sdir}/tests", self.sdir, mod.dir]
        for d in sorted(self.search_extra):
            if d not in dirs:
                dirs.append(d)
        return dirs

    def module_candidates(self, mod, name, level):
        """Every repository file `import name` can load from `mod`: the module, and the `__init__.py` of its packages."""
        parts = [p for p in name.split(".") if p]
        out = []
        if level:                                    # a relative import: from the importer's package
            base = mod.dir
            for _ in range(level - 1):
                base = posixpath.dirname(base) or "."
            roots = [base]
        else:
            roots = self.search_dirs(mod)
        for root in roots:
            for i in range(1, len(parts) + 1):
                init = join_pat(root, "/".join(parts[:i]) + "/__init__.py")
                if init and self.exists(init):
                    out.append(init)
            if parts:
                for cand in (join_pat(root, "/".join(parts) + ".py"), join_pat(root, "/".join(parts) + "/__init__.py")):
                    if cand and self.exists(cand):
                        out.append(cand)
            elif level:
                init = join_pat(root, "__init__.py")
                if init and self.exists(init):
                    out.append(init)
        seen, ordered = set(), []
        for p in out:
            if p not in seen:
                seen.add(p)
                ordered.append(p)
        return ordered

    def resolve_import_edge(self, mod, item):
        _kind, name, level, node = item
        for cand in self.module_candidates(mod, name, level):
            self.add_module(cand, f"imported by {mod.path}:{node.lineno}")
            self.dep("file", cand, mod, node, "import")

    # -- scopes and names --------------------------------------------------------------------------------------------
    @staticmethod
    def lookup(scope, name):
        first = scope
        while scope is not None:
            if name in scope.bindings and not (scope.kind == "class" and scope is not first):
                return scope
            scope = scope.parent
        return None

    def qual(self, node, scope):
        """The dotted import name a Name/Attribute chain refers to (`os.path.join`, `pathlib.Path`), or None."""
        if isinstance(node, ast.Name):
            ds = self.lookup(scope, node.id)
            if ds is None:
                return node.id if node.id in PURE_BUILTINS or node.id in ("open", "exec", "eval", "compile", "__import__") else None
            quals = {b[3] for b in ds.bindings[node.id] if b[0] == "import"}
            if len(quals) == 1 and all(b[0] == "import" for b in ds.bindings[node.id]):
                return quals.pop()
            return None
        if isinstance(node, ast.Attribute):
            q = self.qual(node.value, scope)
            return q + "." + node.attr if q else None
        return None

    def name_val(self, scope, name):
        if name == "__file__":
            return paths(scope.mod.path)
        ds = self.lookup(scope, name)
        if ds is None:
            return UNK
        return self.keyed(("n", id(ds), name), lambda: self.compute_name(ds, name))

    def compute_name(self, ds, name):
        out = EMPTY
        for b in ds.bindings[name]:
            out = out | self.binding_val(b, ds)
        for b, bscope in ds.mod.mutations.get(name, ()):
            out = out | self.mutation_val(b, bscope)
        return out

    def mutation_val(self, binding, scope):
        """What `x.append(v)`, `x.update(m)` or `x[k] = v` adds to the container named x: a sequence or a mapping."""
        kind = binding[0]
        if kind == "item":
            return frozenset([("map", ((self.val(binding[1], scope), self.val(binding[2], scope)),))])
        if kind != "call":
            return EMPTY
        method, call = binding[1], binding[2]
        args = call.args
        if method == "update":
            return frozenset(a for a in self.val(args[0], scope) if a[0] == "map") | EMPTY
        if method == "extend":
            return seq_of([self.elems(self.val(args[0], scope))], "list", True)
        if method == "setdefault":
            return frozenset([("map", ((self.val(args[0], scope), self.val(args[1], scope) if len(args) > 1 else UNK),))])
        if method == "insert":
            return seq_of([self.val(args[-1], scope)], "list", True)
        return seq_of([self.val(args[0], scope)], "list", True)

    def weight(self, atom, budget):
        """(size, whether it holds a path, module, function or environment value) of an atom, counted up to `budget`."""
        size, rich, stack = 0, False, [atom]
        while stack and size <= budget:
            a = stack.pop()
            size += 1
            k = a[0]
            if k == "seq":
                stack.extend(x for e in a[2] for x in e)
            elif k == "map":
                stack.extend(x for key, v in a[1] for x in (*key, *v))
            elif k in ("p", "t", "e", "m", "f", "k", "o"):
                rich = True
        return size, rich

    def prune(self, vs):
        """Data that cannot lead to a path (a big container of strings: fixtures, messages) is dropped to unknown."""
        if not any(a[0] in ("seq", "map") for a in vs):
            return vs
        out = set()
        for a in vs:
            if a[0] in ("seq", "map"):
                size, rich = self.weight(a, MAX_DATA)
                if size > MAX_DATA and not rich:
                    out.add(("seq", "list", (UNK,), True))
                    continue
            out.add(a)
        return frozenset(out)

    def canon(self, vs, depth=0):
        """A value in a form that cannot grow without bound: one sequence atom, one mapping atom, nesting limited."""
        vs = self.prune(vs)
        seqs = [a for a in vs if a[0] == "seq"]
        maps = [a for a in vs if a[0] == "map"]
        if len(seqs) <= 1 and len(maps) <= 1 and depth == 0 and not any(
                a[0] in ("seq", "map") and self.deep(a, 3) for a in vs):
            return vs
        out = {a for a in vs if a[0] not in ("seq", "map")}
        if seqs:
            if depth >= 3 or (depth >= 2 and not any(self.weight(a, 8)[1] for a in seqs)):
                out.add(("seq", "list", (UNK,), True))
            elif len(seqs) == 1:
                a = seqs[0]
                out.add(("seq", a[1], tuple(self.canon_part(e, depth + 1) for e in a[2]), a[3]))
            else:
                kind = seqs[0][1] if all(a[1] == seqs[0][1] for a in seqs) else "list"
                shapes = {(len(a[2]), a[3]) for a in seqs}
                if len(shapes) == 1:
                    n, star = shapes.pop()
                    out.add(("seq", kind, tuple(self.canon_part(self.union_all(a[2][i] for a in seqs), depth + 1)
                                                for i in range(n)), star))
                else:
                    merged = self.union_all(e for a in seqs for e in a[2])
                    out.add(("seq", "list", (self.canon_part(merged, depth + 1),), True))
        if maps:
            if depth >= 3 or (depth >= 2 and not any(self.weight(a, 8)[1] for a in maps)):
                out.add(("map", ((UNK, UNK),)))
            else:
                grouped: dict = {}
                for a in maps:
                    for k, v in a[1]:
                        sig = self.signature(k)
                        grouped[sig] = (k, grouped[sig][1] | v) if sig in grouped else (k, v)
                entries = [grouped[sig] for sig in sorted(grouped)]      # a fixed order: equal values must compare equal
                if len(entries) > 256:
                    entries = [(self.union_all(k for k, _ in entries), self.union_all(v for _, v in entries))]
                out.add(("map", tuple((self.canon_part(k, depth + 1), self.canon_part(v, depth + 1)) for k, v in entries)))
        return frozenset(out)

    def signature(self, vs):
        """A string that is the same for equal values (a set prints in no fixed order)."""
        return "{" + "|".join(sorted(self.atom_signature(a) for a in vs)) + "}"

    def atom_signature(self, a):
        k = a[0]
        if k == "seq":
            return f"S{a[1]}{int(a[3])}(" + ",".join(self.signature(e) for e in a[2]) + ")"
        if k == "map":
            return "M(" + ",".join(self.signature(key) + ":" + self.signature(v) for key, v in a[1]) + ")"
        return repr(a)

    def canon_part(self, vs, depth):
        vs = self.canon(vs, depth)
        return self.widen(vs) if len(vs) > MAX_ALTERNATIVES else vs

    def deep(self, atom, limit):
        """Whether an atom nests sequences or mappings deeper than `limit`."""
        if limit < 0:
            return True
        if atom[0] == "seq":
            return any(self.deep(a, limit - 1) for e in atom[2] for a in e)
        if atom[0] == "map":
            return any(self.deep(a, limit - 1) for k, v in atom[1] for a in (*k, *v))
        return False

    def leaves(self, vs, depth=0):
        """The atoms of a value with its containers flattened away."""
        out = set()
        for a in vs:
            if a[0] == "seq" and depth < 6:
                for e in a[2]:
                    out |= self.leaves(e, depth + 1)
            elif a[0] == "map" and depth < 6:
                for k, v in a[1]:
                    out |= self.leaves(k, depth + 1) | self.leaves(v, depth + 1)
            elif a[0] not in ("seq", "map"):
                out.add(a)
        return out

    def widen(self, vs):
        """A value that keeps growing: only what can lead to the repository survives, collapsed into a finite form (its paths
        into their common directory, its containers into one sequence of that)."""
        leaves = self.leaves(vs)
        ps = [a for a in leaves if a[0] == "p"]
        keep = {a for a in leaves if a[0] in ("t", "e", "m", "f", "k", "o")}
        if ps:
            heads = [a[1].split("*")[0].rstrip("/") or "." for a in ps]
            common = posixpath.commonpath(heads)
            keep.add(("p", join_pat(common, "**") if common != "." else "**"))
        out = set(keep)
        out.add(U)
        if any(a[0] in ("seq", "map") for a in vs):
            out.add(("seq", "list", (frozenset(keep | {U}),), True))
        return frozenset(out)

    def binding_val(self, b, scope):
        kind = b[0]
        if kind == "assign":
            return self.proj(self.val(b[1], scope), b[2])
        if kind == "iter":
            return self.proj(self.elems(self.val(b[1], scope)), b[2])
        if kind == "param":
            return self.param_val(b[1], b[2])
        if kind == "def":
            return frozenset([("f", id(b[1]))])
        if kind == "class":
            return frozenset([("k", id(b[1]))])
        if kind == "import":
            return self.import_val(b, scope)
        return UNK

    def import_val(self, b, scope):
        _, module, attr, _qual, level = b
        out = EMPTY
        mod = scope.mod
        if attr is None:
            for cand in self.module_candidates(mod, module, level):
                if cand in self.mods:
                    out = out | frozenset([("m", cand)])
            return out or UNK
        subs = self.module_candidates(mod, (module + "." if module else "") + attr, level)
        for cand in subs:
            if cand in self.mods and posixpath.basename(cand) in (attr + ".py", "__init__.py"):
                out = out | frozenset([("m", cand)])
        for cand in self.module_candidates(mod, module, level):
            target = self.mods.get(cand)
            if target is not None:
                out = out | self.module_attr(target, attr)
        return out or UNK

    def module_attr(self, target, attr):
        """The value of `module.attr`: the module's own binding of it, and what other code stores on attributes of that name."""
        if attr == "__file__":
            return paths(target.path)
        out = EMPTY
        if attr in target.scope.bindings:
            out = out | self.name_val(target.scope, attr)
        if any(attr in mod.attrs for mod in self.mods.values()):
            out = out | self.class_attr_val(attr)
        return out

    # -- parameters and calls to functions of the closure --------------------------------------------------------------------
    def is_static(self, fnode):
        return any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in fnode.decorator_list)

    def param_val(self, fnode, argname):
        return self.keyed(("p", id(fnode), argname), lambda: self.compute_param(fnode, argname))

    def compute_param(self, fnode, argname):
        info = self.func_nodes.get(id(fnode))
        if info is None:
            return UNK
        _fnode, fscope, cls, _mod = info
        args = fnode.args
        positional = [a.arg for a in args.posonlyargs + args.args]
        if cls is not None and not self.is_static(fnode) and positional and argname == positional[0]:
            classmethod_ = any(isinstance(d, ast.Name) and d.id == "classmethod" for d in fnode.decorator_list)
            return frozenset([("k" if classmethod_ else "o", id(cls))])          # self / cls
        defaults = dict(zip(reversed(positional), reversed(args.defaults)))
        defaults.update({a.arg: d for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None})
        out, found = EMPTY, False
        for call, cscope, offset in self.callsites(fnode):
            value = self.arg_for(call, cscope, positional, argname, offset)
            if value is not None:
                out, found = out | value, True
        if argname in defaults:
            out, found = out | self.val(defaults[argname], fscope.parent), True
        return out if found else UNK

    def arg_for(self, call, scope, positional, argname, offset):
        """The value a call passes for one parameter, or None when it passes nothing for it."""
        if argname in positional:
            index = positional.index(argname) - offset
            if any(isinstance(a, ast.Starred) for a in call.args[:max(index, 0) + 1]):
                return UNK
            if 0 <= index < len(call.args):
                return self.val(call.args[index], scope)
        for kw in call.keywords:
            if kw.arg == argname:
                return self.val(kw.value, scope)
            if kw.arg is None:
                return UNK
        return None

    def callsites(self, fnode):
        """(call, scope, offset) for every call of the closure that can reach `fnode`; offset: the bound self/cls skipped."""
        info = self.func_nodes.get(id(fnode))
        if info is None:
            return []
        cls = info[2]
        name = cls.name if fnode.name == "__init__" and cls is not None else fnode.name
        sites = []
        for call, scope in self.by_name.get(name, ()):
            for atom in self.callee_set(call, scope):
                if atom[1] == id(fnode):
                    sites.append((call, scope, atom[2]))
        return sites

    def callee_set(self, call, scope):
        """{("fn", id of a function node, offset)}: the functions of the closure a call can reach (constructors included)."""
        return self.keyed(("c", id(call)), lambda: self.compute_callees(call, scope))

    def compute_callees(self, call, scope):
        f = call.func
        out = set()
        recv_is_class = False
        if isinstance(f, ast.Attribute):
            recv = self.val(f.value, scope)
            recv_is_class = bool(recv) and all(a[0] == "k" for a in recv)
        for atom in self.val(f, scope):
            if atom[0] == "f":
                info = self.func_nodes.get(atom[1])
                if info is None:
                    continue
                fnode, _fs, cls, _m = info
                offset = 0
                if cls is not None and not self.is_static(fnode):
                    classmethod_ = any(isinstance(d, ast.Name) and d.id == "classmethod" for d in fnode.decorator_list)
                    offset = 1 if (isinstance(f, ast.Attribute) and (not recv_is_class or classmethod_)) else 0
                out.add(("fn", id(fnode), offset))
            elif atom[0] == "k":
                cinfo = self.class_nodes.get(atom[1])
                if cinfo is not None:
                    for b in cinfo[1].bindings.get("__init__", ()):
                        if b[0] == "def":
                            out.add(("fn", id(b[1]), 1))
        return frozenset(out)

    def ret_val(self, fnode):
        return self.keyed(("r", id(fnode)), lambda: self.compute_ret(fnode))

    def compute_ret(self, fnode):
        info = self.func_nodes.get(id(fnode))
        if info is None:
            return UNK
        _fnode, fscope, _cls, mod = info
        out = EMPTY
        for node in mod.returns.get(id(fnode), ()):
            out = out | self.val(node, fscope)
        return out or UNK

    # -- projections of containers ---------------------------------------------------------------------------------------
    def proj(self, vs, path):
        for index in path:
            nxt = EMPTY
            for atom in vs:
                nxt = nxt | (self.seq_item(atom, index) if atom[0] == "seq" else UNK)
            vs = nxt
        return vs

    def seq_item(self, atom, index):
        """The value at a position of a sequence atom (the last value repeats when it is starred)."""
        elems = atom[2]
        if not elems:
            return UNK
        if index < len(elems) - (1 if atom[3] else 0):
            return elems[index]
        return elems[-1] if atom[3] else self.union_all(elems)

    @staticmethod
    def union_all(items):
        out = EMPTY
        for item in items:
            out = out | item
        return out

    def elems(self, vs):
        """The values iterating `vs` yields."""
        out = EMPTY
        for atom in vs:
            kind = atom[0]
            if kind == "seq":
                out = out | self.union_all(atom[2])
            elif kind == "map":
                out = out | self.union_all(k for k, _v in atom[1])
            elif kind in ("e", "t"):
                out = out | frozenset([atom])
            else:
                out = out | UNK
        return out

    # -- anchoring -------------------------------------------------------------------------------------------------------
    def to_ap(self, atom):
        """A path atom a sink can read: anchored as is; a relative string or path is anchored at the suite directory."""
        kind = atom[0]
        if kind == "p" or kind == "t" or kind == "e":
            return atom
        if kind == "c" and isinstance(atom[1], str):
            if atom[1].startswith(("/", "~")):
                return None
            pat = join_pat(self.sdir, atom[1]) if atom[1] else self.sdir
            return ("p", pat) if pat is not None else None
        if kind == "r":
            if atom[1].startswith(("/", "~")):
                return None
            pat = join_pat(self.sdir, atom[1])
            return ("p", pat) if pat is not None else None
        return None

    # -- evaluation ----------------------------------------------------------------------------------------------------------
    def val(self, node, scope) -> frozenset:
        key = (id(node), id(scope))
        hit = self.memo.get(key)
        if hit is not None:
            return hit
        out = self.memo[key] = self.val_uncached(node, scope)
        return out

    def val_uncached(self, node, scope) -> frozenset:
        self.tick()
        t = type(node)
        if t is ast.Constant:
            return const(node.value) if isinstance(node.value, str) else UNK
        if t is ast.Name:
            return self.name_val(scope, node.id)
        if t is ast.Attribute:
            return self.attr_val(node, scope)
        if t is ast.Subscript:
            return self.subscript_val(node, scope)
        if t is ast.BinOp:
            return self.binop_val(node, scope)
        if t is ast.JoinedStr:
            return self.fstring_val(node, scope)
        if t is ast.Call:
            return self.call_val(node, scope)
        if t in (ast.Tuple, ast.List, ast.Set):
            kind = {ast.Tuple: "tuple", ast.List: "list", ast.Set: "set"}[t]
            elems, star = [], False
            for e in node.elts:
                starred = isinstance(e, ast.Starred)
                v = self.elems(self.val(e.value, scope)) if starred else self.val(e, scope)
                if star:
                    elems[-1] = elems[-1] | v          # after a starred part the positions are unknown
                else:
                    elems.append(v)
                    star = starred
            return seq_of(elems, kind, star)
        if t is ast.Dict:
            entries = []
            for k, v in zip(node.keys, node.values):
                if k is None:
                    for atom in self.val(v, scope):
                        if atom[0] == "map":
                            entries.extend(atom[1])
                        elif atom[0] != "em":
                            entries.append((UNK, UNK))
                else:
                    entries.append((self.val(k, scope), self.val(v, scope)))
            return frozenset([("map", tuple(entries))])
        if t in (ast.ListComp, ast.SetComp, ast.GeneratorExp):
            inner = self.comp_scope(node, scope)
            return seq_of([self.val(node.elt, inner)], "list", True)
        if t is ast.DictComp:
            inner = self.comp_scope(node, scope)
            return frozenset([("map", ((self.val(node.key, inner), self.val(node.value, inner)),))])
        if t is ast.IfExp:
            return self.val(node.body, scope) | self.val(node.orelse, scope)
        if t is ast.BoolOp:
            out = EMPTY
            for v in node.values:
                out = out | self.val(v, scope)
            return out
        if t is ast.NamedExpr:
            return self.val(node.value, scope)
        if t is ast.Starred:
            return self.val(node.value, scope)
        if t is ast.Await:
            return self.val(node.value, scope)
        return UNK

    @staticmethod
    def is_test_module(mod):
        """Test code lives in a `tests/` directory. A script under test reads the environment its tests give it (a
        temporary directory), so only test code reads a path out of the live environment or argv that nothing controls."""
        return "/tests/" in "/" + mod.path

    @staticmethod
    def env_container(q):
        """`os.environ` (the live environment, an atom of its own) and `sys.argv` (a list): what is read out of them may
        name anything. A copy of the environment (`dict(os.environ, ...)`) is what a test hands to a process: its own data."""
        if q == "sys.argv":
            return seq_of([ENV], "list", True)
        return frozenset([("em",)])

    def comp_scope(self, node, scope):
        return scope.mod.comp_scopes.get(id(node), scope)

    def binop_val(self, node, scope):
        left = self.val(node.left, scope)
        right = self.val(node.right, scope)
        op = type(node.op)
        out = EMPTY
        if op is ast.Div:
            for l in left:
                for r in right:
                    out = out | self.join_atoms(l, r)
            return out or UNK
        if op is ast.Add:
            for l in left:
                for r in right:
                    out = out | self.add_atoms(l, r)
            return out or UNK
        return UNK

    def join_atoms(self, l, r):
        """`l / r` on paths."""
        lk, rk = l[0], r[0]
        if lk in ("e", "t"):
            return frozenset([l])
        if rk in ("e", "t"):
            return frozenset([r])
        if lk == "p":
            if rk == "c" and isinstance(r[1], str):
                return paths(join_pat(l[1], r[1])) or UNK
            if rk == "r":
                return paths(join_pat(l[1], r[1])) or UNK
            if rk == "p":
                return frozenset([r])                        # an absolute right operand replaces the left
            if rk == "u" or rk == "c":
                return paths(join_pat(l[1], "**")) or UNK
            return paths(join_pat(l[1], "**")) or UNK
        if lk in ("c", "r") and isinstance(l[1], str):
            if rk == "c" and isinstance(r[1], str):
                return frozenset([("r", posixpath.join(l[1], r[1]))])
            if rk == "r":
                return frozenset([("r", posixpath.join(l[1], r[1]))])
            if rk == "p":
                return frozenset([r])
            return frozenset([("r", posixpath.join(l[1], "**"))])
        return UNK

    def add_atoms(self, l, r):
        lk, rk = l[0], r[0]
        if lk == "c" and rk == "c":
            if isinstance(l[1], str) and isinstance(r[1], str):
                return const(l[1] + r[1])
            return UNK
        if lk == "seq" and rk == "seq":
            if not l[3] and len(l[2]) + len(r[2]) <= 24:
                return frozenset([("seq", l[1], l[2] + r[2], r[3])])
            return seq_of([self.union_all(l[2] + r[2])], l[1], True)
        if lk == "p" and rk in ("c", "r") and isinstance(r[1], str):
            return paths(norm(l[1] + r[1]) if not r[1].startswith("/") else join_pat(l[1], r[1])) or UNK
        if lk == "p" and rk == "u":
            return paths(norm(l[1] + "**")) or UNK
        if lk in ("c", "r") and rk in ("c", "r") and isinstance(l[1], str) and isinstance(r[1], str):
            return self.partial(l[1] + r[1])
        if lk in ("c", "r") and rk == "u" and isinstance(l[1], str):
            return self.partial(l[1] + "**")
        if lk == "u" and rk in ("c", "r") and isinstance(r[1], str):
            return self.partial("**" + r[1])
        if lk == "e" or rk == "e":
            return ENV
        if lk == "t":
            return frozenset([l])
        if rk == "t":
            return frozenset([r])
        return UNK

    @staticmethod
    def partial(text):
        """A partly known string; prose (white space, long) is not a path, so it is not tracked."""
        if len(text) > MAX_TEXT or WHITESPACE.search(text):
            return UNK
        return frozenset([("r", text)])

    def fstring_val(self, node, scope):
        """`f"{ROOT}/x/{name}.py"`: pieces joined; unknown parts are `**`. A path first keeps the string a path."""
        results = [("", None)]
        for part in node.values:
            if isinstance(part, ast.Constant):
                piece = [("c", part.value)]
            elif isinstance(part, ast.FormattedValue):
                piece = list(self.val(part.value, scope)) or [U]
            else:
                piece = [U]
            nxt = []
            for text, anchor in results:
                for atom in piece[:8]:
                    k = atom[0]
                    if k == "c":
                        nxt.append((text + str(atom[1]), anchor))
                    elif k == "p":
                        nxt.append((text + atom[1], "p" if not text else "mixed"))
                    elif k == "r":
                        nxt.append((text + atom[1], anchor))
                    elif k in ("e", "t"):
                        nxt.append((text, "env"))
                    else:
                        nxt.append((text + "**", anchor))
            results = nxt[:MAX_ALTERNATIVES]
        out = EMPTY
        for text, anchor in results:
            if anchor == "env":
                out = out | ENV
            elif anchor == "mixed":
                out = out | UNK                     # a repository path inside a longer string is no longer a path
            elif anchor == "p":
                n = norm(text) if not text.startswith("/") and not WHITESPACE.search(text) else None
                out = out | (paths(n) if n is not None else UNK)         # a path followed by prose is a message
            elif "**" in text:
                out = out | self.partial(text)
            else:
                out = out | const(text)
        return out or UNK

    def attr_val(self, node, scope):
        q = self.qual(node, scope)
        if q in ENV_CONTAINERS:
            return self.env_container(q) if self.is_test_module(scope.mod) else UNK
        if q in CWD_QUALS:
            return paths(self.sdir)
        attr = node.attr
        out = EMPTY
        recv = self.val(node.value, scope)
        for atom in recv:
            k = atom[0]
            if k == "p":
                out = out | self.path_attr(atom, attr)
            elif k in ("c", "r") and isinstance(atom[1], str):
                out = out | self.str_attr(atom, attr)
            elif k == "m":
                target = self.mods.get(atom[1])
                if target is not None:
                    out = out | self.module_attr(target, attr)
                elif attr == "__file__":
                    out = out | paths(atom[1])
                else:
                    out = out | UNK
            elif k == "e":
                out = out | ENV
            elif k == "t":
                out = out | frozenset([atom])
            elif k in ("o", "k"):
                out = out | self.family_attr(atom[1], attr)
            else:
                out = out | UNK                    # an object the evaluator cannot type: its attributes are not followed
        return out or UNK

    def class_bases(self, cid):
        """The classes of the closure a class derives from, directly."""
        info = self.class_nodes.get(cid)
        if info is None:
            return frozenset()
        cnode, cscope, _mod = info
        out = set()
        for base in cnode.bases:
            for atom in self.val(base, cscope.parent):
                if atom[0] == "k" and atom[1] in self.class_nodes:
                    out.add(atom[1])
        return frozenset(out)

    def family(self, cid):
        """A class with the classes it derives from and the classes derived from it: where `self.attr` can be defined."""
        key = ("fam", cid)
        done = self.memo.get(key)
        if done is not None:
            return done
        up, todo = {cid}, [cid]
        while todo:
            for base in self.class_bases(todo.pop()):
                if base not in up:
                    up.add(base)
                    todo.append(base)
        family = set(up)
        for other in self.class_nodes:
            if other not in family:
                chain, todo = {other}, [other]
                while todo:
                    for base in self.class_bases(todo.pop()):
                        if base not in chain:
                            chain.add(base)
                            todo.append(base)
                if chain & up:
                    family.add(other)
        self.memo[key] = result = frozenset(family)
        return result

    def family_attr(self, cid, attr):
        """`obj.attr` for an object (or class) of a class of the closure: only the family of that class is searched."""
        return self.keyed(("fa", cid, attr), lambda: self.compute_family_attr(cid, attr))

    def compute_family_attr(self, cid, attr):
        fam = self.family(cid)
        out = EMPTY
        for mod in self.mods.values():
            for b, bscope, owner in mod.attrs.get(attr, ()):
                if owner in fam:
                    out = out | (self.def_attr(b[1]) if b[0] == "def" else self.binding_val(b, bscope))
        return out or UNK

    def class_attr_val(self, attr):
        """`obj.attr` for an object of a class of the closure: every `x.attr = v` and class-level `attr` of the closure."""
        return self.keyed(("a", attr), lambda: self.compute_attr(attr))

    def compute_attr(self, attr):
        out = EMPTY
        for mod in self.mods.values():
            for b, bscope, _ in mod.attrs.get(attr, ()):
                if b[0] == "def":
                    out = out | self.def_attr(b[1])
                else:
                    out = out | self.binding_val(b, bscope)
        return out or UNK

    def def_attr(self, fnode):
        if any((isinstance(d, ast.Name) and d.id in ("property", "cached_property", "classproperty")) or
               (isinstance(d, ast.Attribute) and d.attr in ("cached_property", "setter", "getter")) for d in fnode.decorator_list):
            return self.ret_val(fnode)
        return frozenset([("f", id(fnode))])

    def path_attr(self, atom, attr):
        pat = atom[1]
        if attr == "parent":
            return paths(parent_pat(pat, 1)) or UNK
        if attr == "parents":
            chain, cur = [], pat
            while True:
                cur = parent_pat(cur, 1)
                if cur is None:
                    break
                chain.append(cur)
                if cur == ".":
                    break
            return seq_of([paths(*chain)] if chain else [UNK], "tuple", True)
        if attr in ("name", "stem", "suffix"):
            if has_wild(pat):
                return UNK
            base = posixpath.basename(pat) if pat != "." else ""
            stem, ext = posixpath.splitext(base)
            return const({"name": base, "stem": stem, "suffix": ext}[attr])
        if attr == "parts":
            return seq_of([const(p) for p in pat.split("/")]) if not has_wild(pat) else UNK
        if attr == "path":                                     # os.scandir entries
            return frozenset([atom])
        return UNK

    def str_attr(self, atom, attr):
        text = atom[1]
        if attr == "parent":
            return frozenset([("r", posixpath.dirname(text) or ".")])
        if attr in ("name", "stem", "suffix") and atom[0] == "c":
            base = posixpath.basename(text)
            stem, ext = posixpath.splitext(base)
            return const({"name": base, "stem": stem, "suffix": ext}[attr])
        if attr == "parents":
            return seq_of([frozenset([("r", posixpath.dirname(text) or ".")])], "tuple", True)
        return UNK

    def subscript_val(self, node, scope):
        value = node.value
        index = node.slice
        # `p.parents[N]`
        if isinstance(value, ast.Attribute) and value.attr == "parents" and isinstance(index, ast.Constant) \
                and isinstance(index.value, int) and index.value >= 0:
            out = EMPTY
            for atom in self.val(value.value, scope):
                if atom[0] == "p":
                    up = parent_pat(atom[1], index.value + 1)
                    out = out | (paths(up) if up is not None else UNK)
                elif atom[0] in ("c", "r") and isinstance(atom[1], str):
                    cur = atom[1]
                    for _ in range(index.value + 1):
                        cur = posixpath.dirname(cur) or "."
                    out = out | frozenset([("r", cur)])
                elif atom[0] in ("e", "t"):
                    out = out | frozenset([atom])
                else:
                    out = out | UNK
            return out or UNK
        base = self.val(value, scope)
        key = self.val(index, scope) if not isinstance(index, ast.Slice) else UNK
        out = EMPTY
        for atom in base:
            k = atom[0]
            if k == "seq":
                if isinstance(index, ast.Slice):
                    out = out | frozenset([atom])
                    continue
                if isinstance(index, ast.Constant) and isinstance(index.value, int) and not isinstance(index.value, bool) \
                        and index.value >= 0:
                    out = out | self.seq_item(atom, index.value)
                else:
                    out = out | self.union_all(atom[2])
            elif k == "map":
                key_consts = [a for a in key if a[0] == "c"]
                hit = EMPTY
                for ks, vs in atom[1]:
                    if any(c in ks for c in key_consts):
                        hit = hit | vs
                out = out | (hit or self.union_all(v for _k, v in atom[1]))
            elif k in ("e", "t"):
                out = out | frozenset([atom])
            elif k == "em":
                out = out | self.environ_read(key)
            else:
                out = out | UNK
        return out or UNK

    # -- calls (values) -----------------------------------------------------------------------------------------------------
    def call_val(self, node, scope):
        f = node.func
        q = self.qual(f, scope)
        args = node.args
        if q in PATH_CTORS:
            return self.path_ctor(node, scope)
        if q in CWD_QUALS:
            return paths(self.sdir)
        if q in ENV_CALLS:
            if not self.is_test_module(scope.mod):
                return UNK
            return self.environ_read(self.val(args[0], scope)) if args else ENV
        if q in IDENTITY_CALLS or q in IDENTITY_BUILTINS:
            return self.val(args[0], scope) if args else UNK
        if q == "os.path.join":
            return self.os_join(node, scope)
        if q == "os.path.dirname":
            return self.map_atoms(self.val(args[0], scope), lambda a: self.up_atom(a, 1)) if args else UNK
        if q in SPEC_CALLS:
            return self.spec_val(node, scope)
        if q == "importlib.util.module_from_spec":
            return self.val(args[0], scope) if args else UNK
        if q in IMPORT_CALLS:
            return self.import_call_val(node, scope)
        if q == "os.listdir":                                  # names, not paths
            return seq_of([frozenset([("r", "**")])], "list", True)
        if q == "os.scandir":                                  # entries whose `.path` is the path
            return self.listing(self.val(args[0], scope) if args else paths(self.sdir), "*")
        if q in ("os.walk", "os.fwalk"):                       # (directory path, names, names)
            wide = frozenset(self.listing_atoms(self.val(args[0], scope) if args else paths(self.sdir), "**")) or UNK
            names = seq_of([frozenset([("r", "**")])], "list", True)
            return seq_of([frozenset([("seq", "tuple", (wide, names, names), False)])], "list", True)
        if q in GLOB_CALLS:
            return self.glob_atoms_value(args, scope)
        if q in SEQ_BUILTINS:
            return self.seq_builtin(q, node, scope)
        if q == "enumerate" and args:
            return seq_of([frozenset([("seq", "tuple", (UNK, self.elems(self.val(args[0], scope))), False)])], "list", True)
        if q == "zip" and args:
            return seq_of([frozenset([("seq", "tuple", tuple(self.elems(self.val(a, scope)) for a in args), False)])],
                          "list", True)
        if q == "dict":
            return self.dict_call(node, scope)
        if q in ("map", "filter", "getattr", "next", "min", "max"):
            return UNK
        out = EMPTY
        for atom in self.callee_set(node, scope):
            info = self.func_nodes.get(atom[1])
            if info is not None:
                out = out | self.ret_val(info[0])
        if isinstance(f, ast.Attribute):
            out = out | self.method_val(node, scope)
        for atom in self.val(f, scope):
            if atom[0] == "k":
                out = out | frozenset([("o", atom[1])])
        return out or UNK

    def seq_builtin(self, q, node, scope):
        args = node.args
        if not args:
            return seq_of([])
        out = EMPTY
        keep_kind = q in ("tuple", "set", "frozenset")
        for atom in self.val(args[0], scope):
            if atom[0] == "seq":
                out = out | frozenset([("seq", atom[1] if keep_kind else "list", atom[2], atom[3])])
            else:
                out = out | seq_of([self.elems(frozenset([atom]))], "list", True)
        return out or UNK

    def map_atoms(self, vs, fn):
        out = EMPTY
        for a in vs:
            out = out | fn(a)
        return out or UNK

    def up_atom(self, atom, n):
        if atom[0] == "p":
            return paths(parent_pat(atom[1], n)) or UNK
        if atom[0] in ("c", "r") and isinstance(atom[1], str):
            cur = atom[1]
            for _ in range(n):
                cur = posixpath.dirname(cur) or "."
            return frozenset([("r", cur)])
        if atom[0] in ("e", "t"):
            return frozenset([atom])
        return UNK

    def path_ctor(self, node, scope):
        """`Path(a, b, ...)`: a path anchored where its first part is; a relative first part stays relative."""
        if not node.args:
            return frozenset([("r", ".")])
        out = EMPTY
        for atom in self.join_all(self.val(node.args[0], scope), node.args[1:], scope):
            k = atom[0]
            if k in ("p", "e", "t", "r"):
                out = out | frozenset([atom])
            elif k == "c" and isinstance(atom[1], str):
                out = out | (UNK if atom[1].startswith(("/", "~")) else frozenset([("r", atom[1] or ".")]))
            else:
                out = out | UNK
        return out or UNK

    def os_join(self, node, scope):
        args = node.args
        if not args:
            return UNK
        acc = self.val(args[0], scope)
        for extra in args[1:]:
            if isinstance(extra, ast.Starred):
                acc = self.map_atoms(acc, lambda l: self.join_atoms(l, ("u",)))
                continue
            nxt = EMPTY
            for l in acc:
                for r in self.val(extra, scope):
                    if l[0] == "c" and r[0] == "c" and isinstance(l[1], str) and isinstance(r[1], str):
                        nxt = nxt | const(r[1] if r[1].startswith("/") else posixpath.join(l[1], r[1]))
                    else:
                        nxt = nxt | self.join_atoms(l, r)
            acc = nxt
        return acc or UNK

    def spec_val(self, node, scope):
        """`spec_from_file_location(name, location)`: a module value on the location's file."""
        args = node.args
        loc = args[1] if len(args) > 1 else next((k.value for k in node.keywords if k.arg == "location"), None)
        if loc is None:
            return UNK
        out = EMPTY
        for atom in self.val(loc, scope):
            ap = self.to_ap(atom)
            if ap is not None and ap[0] == "p":
                out = out | frozenset([("m", ap[1])])
            else:
                out = out | UNK
        return out or UNK

    def import_call_val(self, node, scope):
        args = node.args
        if not args:
            return UNK
        out = EMPTY
        for atom in self.val(args[0], scope):
            if atom[0] == "c" and isinstance(atom[1], str):
                for cand in self.module_candidates(scope.mod, atom[1], 0):
                    if cand in self.mods:
                        out = out | frozenset([("m", cand)])
        return out or UNK

    def dict_call(self, node, scope):
        entries = []
        for a in node.args:
            for atom in self.val(a, scope):
                if atom[0] == "map":
                    entries.extend(atom[1])
                elif atom[0] == "seq":
                    for pair in atom[2]:
                        for p in pair:
                            if p[0] == "seq" and len(p[2]) == 2:
                                entries.append((p[2][0], p[2][1]))
        for kw in node.keywords:
            if kw.arg:
                entries.append((const(kw.arg), self.val(kw.value, scope)))
            else:
                for atom in self.val(kw.value, scope):
                    if atom[0] == "map":
                        entries.extend(atom[1])
        return frozenset([("map", tuple(entries))])

    def listing(self, vs, tail):
        atoms = self.listing_atoms(vs, tail)
        return seq_of([frozenset(atoms) or UNK], "list", True)

    def listing_atoms(self, vs, tail):
        out = []
        for atom in vs:
            ap = self.to_ap(atom)
            if ap is None:
                out.append(U)
            elif ap[0] == "p":
                joined = join_pat(ap[1], tail)
                out.append(("p", joined) if joined is not None else U)
            else:
                out.append(ap)
        return out

    def glob_atoms_value(self, args, scope):
        if not args:
            return UNK
        out = EMPTY
        for atom in self.val(args[0], scope):
            ap = self.to_ap(atom)
            if ap is not None and ap[0] == "p":
                out = out | paths(ap[1])
            elif ap is not None:
                out = out | frozenset([ap])
            else:
                out = out | UNK
        return seq_of([out], "list", True)

    def method_val(self, node, scope):
        """What a method call on a value of a known kind returns (the methods of the closure are in `call_val`)."""
        f = node.func
        attr = f.attr
        out = EMPTY
        for atom in self.val(f.value, scope):
            k = atom[0]
            if k == "p":
                out = out | self.path_method(atom, attr, node, scope)
            elif k in ("c", "r") and isinstance(atom[1], str):
                out = out | self.str_method(atom, attr, node, scope)
            elif k == "map":
                out = out | self.map_method(atom, attr, node, scope)
            elif k == "seq":
                out = out | self.seq_method(atom, attr, node, scope)
            elif k == "em":
                out = out | self.environ_method(attr, node, scope)
            elif k in ("e", "t"):
                out = out | frozenset([atom])
        return out

    def environ_method(self, attr, node, scope):
        if attr in ("get", "pop", "setdefault"):
            return self.environ_read(self.val(node.args[0], scope)) if node.args else ENV
        if attr in ("items", "values"):
            return seq_of([ENV], "list", True)
        if attr == "copy":
            return frozenset([("map", ())])
        return UNK

    def environ_read(self, keys):
        """What reading an environment variable yields: what the tests put there when they put something under that name
        (a temporary directory), the live environment otherwise."""
        out = EMPTY
        for key in keys:
            if key[0] == "c":
                assigned = self.env_assigned(key[1])
                out = out | (assigned if assigned else ENV)
            else:
                out = out | ENV
        return out or ENV

    def env_assigned(self, name):
        return self.keyed(("env", name), lambda: self.compute_env(name))

    def compute_env(self, name):
        out = EMPTY
        for mod in self.mods.values():
            for entry in mod.env_sets:
                kind, scope = entry[0], entry[-1]
                if kind == "item":
                    if const(name) <= self.val(entry[1], scope) or ("u",) in self.val(entry[1], scope):
                        out = out | self.val(entry[2], scope)
                elif kind == "call":
                    method, call = entry[1], entry[2]
                    if method == "setdefault" and len(call.args) > 1:
                        if const(name) <= self.val(call.args[0], scope):
                            out = out | self.val(call.args[1], scope)
                    else:
                        out = out | self.map_value(self.val(call.args[0], scope), name)
                else:                                   # patch.dict(os.environ, {...}, ...)
                    call = entry[2]
                    out = out | self.map_value(self.val(call.args[1], scope), name)
        return out

    def map_value(self, vs, name):
        out = EMPTY
        for atom in vs:
            if atom[0] == "map":
                for keys, values in atom[1]:
                    if const(name) <= keys:
                        out = out | values
        return out

    def path_method(self, atom, attr, node, scope):
        """What a method call on an anchored path returns; the reads it makes are recorded by `effects`."""
        pat = atom[1]
        args = node.args
        if attr in IDENTITY_METHODS or attr == "readlink":
            return frozenset([atom])
        if attr == "joinpath":
            return self.join_all(frozenset([atom]), args, scope)
        if attr in ("with_name", "with_suffix", "with_stem"):
            parent = parent_pat(pat, 1)
            if parent is None:
                return UNK
            if not args:
                return paths(join_pat(parent, "**")) or UNK
            return self.map_atoms(self.val(args[0], scope), lambda a: self.with_atom(parent, pat, attr, a))
        if attr in GLOB_READS:
            out = EMPTY
            for a in (self.val(args[0], scope) if args else UNK):
                if a[0] == "c" and isinstance(a[1], str):
                    out = out | paths(join_pat(pat, a[1] if attr == "glob" else "**/" + a[1]))
                else:
                    out = out | paths(join_pat(pat, "**"))
            return seq_of([out or UNK], "list", True)
        if attr in DIR_READS:
            return seq_of([paths(join_pat(pat, "*")) or UNK], "list", True)
        return UNK

    def join_all(self, acc, nodes, scope):
        """`acc / n1 / n2 ...` for the argument nodes of `joinpath` or `Path(a, b)`."""
        for extra in nodes:
            nxt = EMPTY
            for l in acc:
                for r in self.val(extra, scope):
                    nxt = nxt | self.join_atoms(l, r)
            acc = nxt
        return acc or UNK

    def with_atom(self, parent, pat, attr, arg):
        if arg[0] == "c" and isinstance(arg[1], str):
            if attr == "with_name":
                return paths(join_pat(parent, arg[1])) or UNK
            base = posixpath.basename(pat)
            stem = posixpath.splitext(base)[0]
            name = stem + arg[1] if attr == "with_suffix" else arg[1] + posixpath.splitext(base)[1]
            return paths(join_pat(parent, name)) or UNK
        return paths(join_pat(parent, "**")) or UNK

    def str_method(self, atom, attr, node, scope):
        """A method call on a relative path or string."""
        if attr in IDENTITY_METHODS:
            return frozenset([atom])
        if attr == "joinpath":
            return self.join_all(frozenset([atom]), node.args, scope)
        if attr in ("with_name", "with_suffix", "with_stem"):
            return frozenset([("r", "**")])
        if attr in GLOB_READS or attr in DIR_READS:
            return seq_of([frozenset([("r", posixpath.join(atom[1], "**"))])], "list", True)
        return UNK

    def map_method(self, atom, attr, node, scope):
        entries = atom[1]
        if attr == "items":
            return seq_of([frozenset([("seq", "tuple", (k, v), False)]) for k, v in entries] or [UNK], "list", True)
        if attr == "keys":
            return seq_of([self.union_all(k for k, _ in entries) or UNK], "list", True)
        if attr == "values":
            return seq_of([self.union_all(v for _, v in entries) or UNK], "list", True)
        if attr in ("get", "pop", "setdefault"):
            out = self.union_all(v for _, v in entries)
            if len(node.args) > 1:
                out = out | self.val(node.args[1], scope)
            return out or UNK
        if attr == "copy":
            return frozenset([atom])
        return UNK

    def seq_method(self, atom, attr, node, scope):
        if attr == "copy":
            return frozenset([atom])
        if attr == "pop":
            return self.union_all(atom[2]) or UNK
        return UNK

    # -- effects: where a value reaches the repository ------------------------------------------------------------------------
    def effects(self, mod, node, scope):
        if getattr(node, "lineno", 0) in mod.opaque_lines:
            return                                      # a probe marked `# derive: opaque`: not a claim on any path
        f = node.func
        q = self.qual(f, scope)
        args, kws = node.args, {k.arg: k.value for k in node.keywords if k.arg}
        if q in SPEC_CALLS:
            loc = args[1] if len(args) > 1 else kws.get("location")
            if loc is not None:
                self.reads_files(mod, node, self.val(loc, scope), "load by path", load=True)
            return
        if q in RUN_PATH_CALLS and args:
            self.reads_files(mod, node, self.val(args[0], scope), "run_path", load=True)
            return
        if q in IMPORT_CALLS:
            self.import_by_name(mod, node, scope)
            return
        if q in EXEC_CALLS:
            self.exec_text(mod, node, scope)
            return
        if q in PATCH_CALLS and args:
            self.patch_target(mod, node, scope)
            return
        if q == "open" or q in OS_FILE_CALLS:
            if args:
                self.reads_files(mod, node, self.val(args[0], scope), "read")
            return
        if q in OS_FILE_COPY:
            for a in args[:1]:
                self.reads_files(mod, node, self.val(a, scope), "copy")
            return
        if q in OS_DIR_CALLS:
            self.reads_tree(mod, node, self.val(args[0], scope) if args else paths(self.sdir), "list")
            return
        if q in GLOB_CALLS:
            if args:
                for atom in self.val(args[0], scope):
                    ap = self.to_ap(atom)
                    self.record_atom(mod, node, ap, "glob", "glob")
            return
        if q in PROCESS_STARTS:
            self.process_start(mod, node, scope)
            return
        if isinstance(f, ast.Attribute):
            if f.attr in FILE_READS or f.attr in DIR_READS or f.attr in GLOB_READS:
                recv = self.val(f.value, scope)
                if f.attr in FILE_READS and not self.is_path_receiver(recv):
                    return self.generic_use(mod, node, scope)
                if f.attr in DIR_READS:
                    self.reads_tree(mod, node, recv, f.attr)
                elif f.attr in GLOB_READS:
                    pats = self.val(node.args[0], scope) if node.args else UNK
                    for atom in recv:
                        ap = self.to_ap(atom)
                        if ap is not None and ap[0] == "p":
                            for a in pats:
                                if a[0] == "c" and isinstance(a[1], str):
                                    sub = a[1] if f.attr == "glob" else "**/" + a[1]
                                    self.record_atom(mod, node, ("p", join_pat(ap[1], sub)), "glob", f.attr)
                                else:
                                    self.record_atom(mod, node, ("p", join_pat(ap[1], "**")), "glob", f.attr)
                        else:
                            self.record_atom(mod, node, ap, "glob", f.attr)
                else:
                    self.reads_files(mod, node, recv, f.attr)
                return
            if f.attr in ("exec_module", "load_module", "get_data", "get_source"):
                return
        self.generic_use(mod, node, scope)

    @staticmethod
    def is_path_receiver(vs):
        return any(a[0] in ("p", "r", "e", "t") or (a[0] == "c" and isinstance(a[1], str)) for a in vs)

    def reads_files(self, mod, node, vs, how, load=False):
        for atom in vs:
            ap = self.to_ap(atom)
            if ap is None:
                continue
            if ap[0] == "p":
                if has_wild(ap[1]):
                    self.dep("glob", ap[1], mod, node, how)
                else:
                    self.dep("file", ap[1], mod, node, how)
                if load and not has_wild(ap[1]) and ap[1].endswith(".py"):
                    self.add_module(ap[1], f"loaded by path at {mod.path}:{node.lineno}")
            else:
                self.record_atom(mod, node, ap, "file", how)

    def reads_tree(self, mod, node, vs, how):
        for atom in vs:
            ap = self.to_ap(atom)
            if ap is None:
                continue
            if ap[0] == "p":
                self.dep("tree", ap[1], mod, node, how)
            else:
                self.record_atom(mod, node, ap, "file", how)

    def record_atom(self, mod, node, ap, kind, how):
        if ap is None or (ap[0] == "p" and ap[1] is None):
            return
        if ap[0] == "p":
            self.dep(kind, ap[1], mod, node, how)
        elif ap[0] == "e":
            self.unbounded.setdefault(f"{how} of a path derived from the environment or argv at {mod.path}:{node.lineno}", True)
        elif ap[0] == "t":
            self.unbounded.setdefault(f"{how} of an unbounded anchored path ({ap[1]}) at {mod.path}:{node.lineno}", True)

    def generic_use(self, mod, node, scope):
        """A call the evaluator cannot see into: every anchored argument counts as read (an exact file)."""
        f = node.func
        name = self.terminal(f)
        if name is None or name in PURE_BUILTINS or name.startswith(ASSERT_PREFIXES):
            return
        q = self.qual(f, scope)
        if q in NO_READ_CALLS or (isinstance(f, ast.Attribute) and f.attr in NO_READ_METHODS):
            return
        if self.callee_set(node, scope):
            return                                      # a function of the closure: what it reads is read where it reads it
        values = list(node.args) + [k.value for k in node.keywords if k.arg not in NOT_ARGUMENT_KEYWORDS]
        for arg in values:
            for atom in self.flatten(self.val(arg, scope)):
                if atom[0] == "p":
                    kind = "glob" if has_wild(atom[1]) else "file"
                    self.dep(kind, atom[1], mod, node, f"use as an argument of {name}()")
                elif atom[0] == "t":
                    self.record_atom(mod, node, atom, "file", f"use as an argument of {name}()")

    def import_by_name(self, mod, node, scope):
        if not node.args:
            return
        for atom in self.val(node.args[0], scope):
            if atom[0] == "c" and isinstance(atom[1], str):
                for cand in self.module_candidates(mod, atom[1], 0):
                    self.add_module(cand, f"imported by {mod.path}:{node.lineno}")
                    self.dep("file", cand, mod, node, "import by name")
            elif atom[0] == "e":
                continue                       # bounded by the argv of the process that runs this module
            else:
                self.unbounded.setdefault(f"import of a name the derivation cannot bound at {mod.path}:{node.lineno}", True)

    def patch_target(self, mod, node, scope):
        """`mock.patch("pkg.module.name")` imports `pkg.module` when it patches: an edge to that module."""
        for atom in self.val(node.args[0], scope):
            if atom[0] == "c" and isinstance(atom[1], str) and "." in atom[1]:
                for cand in self.module_candidates(mod, atom[1].rsplit(".", 1)[0], 0):
                    self.add_module(cand, f"patched by {mod.path}:{node.lineno}")
                    self.dep("file", cand, mod, node, "patch target")

    def exec_text(self, mod, node, scope):
        for arg in node.args[:1]:
            for atom in self.flatten(self.val(arg, scope)):
                if atom[0] in ("p", "t", "e"):
                    self.unbounded.setdefault(f"exec/eval/compile of text derived from the repository at "
                                              f"{mod.path}:{node.lineno}", True)

    def process_start(self, mod, node, scope):
        """A process: its anchored arguments are read (and a Python file run is part of the closure); git on the repository
        reads its whole state."""
        args = node.args
        kws = {k.arg: k.value for k in node.keywords if k.arg}
        argv_nodes = args[:1]
        cwd_vals = self.val(kws["cwd"], scope) if "cwd" in kws else None
        for argv in argv_nodes:
            value = self.val(argv, scope)
            for atom in value:
                if atom[0] == "seq":
                    self.process_argv(mod, node, atom, cwd_vals)
                elif atom[0] == "p":
                    self.dep_atom(mod, node, atom, "process argument")
                elif atom[0] == "t":
                    self.record_atom(mod, node, atom, "file", "process argument")
        if cwd_vals is not None:
            for atom in cwd_vals:
                if atom[0] == "p":
                    self.dep_atom(mod, node, atom, "process working directory")
                elif atom[0] == "t":
                    self.record_atom(mod, node, atom, "file", "process working directory")

    def dep_atom(self, mod, node, atom, how):
        if has_wild(atom[1]):
            self.dep("glob", atom[1], mod, node, how)
        else:
            self.dep("file", atom[1], mod, node, how)
            if atom[1].endswith(".py"):
                self.add_module(atom[1], f"run by {mod.path}:{node.lineno}", in_process=False)

    def process_argv(self, mod, node, seq, cwd_vals):
        items, star = seq[2], seq[3]
        for item in items:
            for atom in item:
                if atom[0] == "p":
                    self.dep_atom(mod, node, atom, "process argument")
                elif atom[0] == "t":
                    self.record_atom(mod, node, atom, "file", "process argument")
        exact = items[:-1] if star else items          # the positions before a repeated tail are known
        if not exact:
            return
        if not any(a[0] == "c" and isinstance(a[1], str) and posixpath.basename(a[1]) == "git" for a in exact[0]):
            return
        repo_dir, sub, i = None, None, 1
        while i < len(exact):
            texts = [a[1] for a in exact[i] if a[0] == "c" and isinstance(a[1], str)]
            if texts and all(t in ("-C", "--git-dir", "--work-tree") for t in texts) and i + 1 < len(exact):
                repo_dir = exact[i + 1] if repo_dir is None else repo_dir | exact[i + 1]
                i += 2
            elif texts and all(t in ("-c", "--namespace", "--exec-path") for t in texts):
                i += 2
            elif texts and all(t.startswith("-") and t not in GIT_NO_REPO for t in texts):
                i += 1
            else:
                sub = texts
                break
        if sub and all(t in GIT_NO_REPO for t in sub) and repo_dir is None:
            return                                       # init, clone, --version: no repository is read
        where = repo_dir if repo_dir is not None else cwd_vals
        if where is None:
            # git run without -C or cwd works in the repository itself: its state (HEAD, the index, history) is an input that no
            # path names. Only a test does that on purpose: a script under test gets the working directory its test gives it.
            if self.is_test_module(mod):
                self.unbounded.setdefault(f"git reads the state of the repository at {mod.path}:{node.lineno}", True)
            return
        for atom in where:
            ap = self.to_ap(atom)
            if ap is not None and ap[0] == "t":
                self.unbounded.setdefault(f"git reads the state of an unbounded path at {mod.path}:{node.lineno}", True)
                return
            if ap is not None and ap[0] == "p":
                self.wide.setdefault(f"git reads the state of {ap[1]} at {mod.path}:{node.lineno}", True)


# --------------------------------------------------------------------------------------------------------------------
# derive
# --------------------------------------------------------------------------------------------------------------------
class ParseCache:
    """Parsed and indexed modules of one tree, shared by the suites (an indexed module holds no suite state)."""

    def __init__(self, repo):
        self.repo = repo
        self.mods: dict = {}

    def __call__(self, rel):
        mod = self.mods.get(rel)
        if mod is None:
            full = os.path.join(self.repo, rel)
            try:
                with open(full, "rb") as handle:
                    source = handle.read()
                tree = ast.parse(source, rel)
            except (OSError, SyntaxError, ValueError) as exc:
                raise DeriveError(f"cannot parse {rel}: {exc}")
            parsed = Mod(rel, tree)
            parsed.opaque_lines = {n for n, line in enumerate(source.decode("utf-8", "replace").splitlines(), 1)
                                   if OPAQUE_MARK.search(line)}
            mod = self.mods[rel] = Indexer(parsed).run()
        return mod


def discover(repo):
    """The suites: the directories under .agents/skills that have a tests/ directory (the Makefile's glob and rule)."""
    root = os.path.join(repo, SKILLS_DIR)
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return []
    return [n for n in names if os.path.isdir(os.path.join(root, n, "tests"))]


def symlinks(repo):
    """[(link, target)]: the symbolic links under `.agents`, `.claude` and `.codex` that point inside the repository (the
    skills are linked into `.claude/skills`), both as repo-relative paths."""
    real = os.path.realpath(repo)
    found = []
    for top in UNIVERSE_PREFIXES:
        for directory, dirnames, filenames in os.walk(os.path.join(repo, top.rstrip("/"))):
            for name in dirnames + filenames:
                full = os.path.join(directory, name)
                if os.path.islink(full):
                    target = os.path.relpath(os.path.realpath(full), real)
                    if target != ".." and not target.startswith("../"):
                        found.append((os.path.relpath(full, repo), target))
    return sorted(found)


def alias_patterns(pattern, links):
    """The spellings of a source that go through a symbolic link: reading `.claude/skills/x/SKILL.md` reads the file the link
    `.claude/skills/x` points to, and that is the path a change names."""
    out, segments = set(), pattern.split("/")
    for link, target in links:
        parts = link.split("/")
        lead = segments[:len(parts)]
        if "**" in lead:                                    # the pattern may descend through the link: all of its target
            before = segments[:segments.index("**")]
            if len(before) < len(parts) and all(fnmatch.fnmatchcase(p, q) for q, p in zip(before, parts)):
                out.add(target + "/**")
        elif len(lead) == len(parts) and all(fnmatch.fnmatchcase(p, q) for q, p in zip(lead, parts)):
            out.add("/".join([target] + segments[len(parts):]))
    return out - {pattern}


def derive_suite(repo, suite, parse=None, links=None):
    """The sources of one suite: {"files", "globs", "unbounded", "wide", "modules"} (sources inside the suite's own directory
    dropped: a path under `.agents/skills/<suite>/` selects it anyway). Raises DeriveError."""
    analyzer = Analyzer(repo, suite, parse or ParseCache(repo))
    links = symlinks(repo) if links is None else links
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(limit, RECURSION_LIMIT))
    try:
        analyzer.run()
    except RecursionError as exc:
        raise DeriveError(f"evaluation too deep: {exc}")
    finally:
        sys.setrecursionlimit(limit)
    own = analyzer.sdir + "/"
    files, globs = {}, {}
    for (_kind, pat), why in sorted(analyzer.deps.items()):
        for spelling, reason in [(pat, why)] + [(a, f"{why}, through a symbolic link") for a in sorted(alias_patterns(pat, links))]:
            if spelling.startswith(own) or spelling == own[:-1]:
                continue
            (globs if has_wild(spelling) else files)[spelling] = reason
    return {"files": files, "globs": globs, "unbounded": sorted(analyzer.unbounded), "wide": sorted(analyzer.wide),
            "modules": sorted(analyzer.mods)}


def derive(repo):
    """{suite: sources} for every suite; a suite whose derivation failed carries {"error": message} instead."""
    repo = os.path.abspath(repo)
    parse = ParseCache(repo)
    links = symlinks(repo)
    out = {}
    for suite in discover(repo):
        try:
            out[suite] = derive_suite(repo, suite, parse, links)
        except DeriveError as exc:
            out[suite] = {"error": str(exc)}
        except Exception as exc:                       # an evaluator bug must not read as "no dependency"
            out[suite] = {"error": f"{type(exc).__name__}: {exc}"}
    return out


# --------------------------------------------------------------------------------------------------------------------
# select
# --------------------------------------------------------------------------------------------------------------------
def canonical(path):
    """Whether a changed path is a plain repo-relative POSIX path."""
    if not path or path.startswith("/") or "\\" in path or "\0" in path:
        return False
    parts = path.split("/")
    return not any(p in ("", ".", "..") for p in parts)


def parse_name_status(data: bytes):
    """`git diff --name-status --no-renames -z` output -> [(status, path)]; ValueError on a malformed stream."""
    tokens = data.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    if len(tokens) % 2:
        raise ValueError("odd number of fields in the name-status stream")
    return [(tokens[i].decode("utf-8", "surrogateescape"), tokens[i + 1].decode("utf-8", "surrogateescape"))
            for i in range(0, len(tokens), 2)]


def select(changes, deps, suites=None):
    """The suites a change can reach.

    changes: [(status, path)]. deps: what `derive` returned. Returns {"selection": "all" | [suite, ...], "reasons":
    {suite: [why, ...]}, "reason": why "all" (or None), "universe": [the changed paths judged]}.

    Fail closed: an empty diff is the only empty selection. A changed path no suite claims (not under `.agents/skills/<S>/` and
    matched by no derived file or glob), a status other than A or M anywhere, a path that is not canonical, a failed derivation
    and "no suite found" all select every suite; the reason names the first such path or cause (a failed derivation first)."""
    suites = sorted(deps) if suites is None else sorted(suites)
    result = {"selection": [], "reasons": {}, "reason": None, "universe": []}
    changes = [(str(s), str(p)) for s, p in changes]

    def claimed_by(path):
        why = {}
        m = re.match(re.escape(SKILLS_DIR) + r"/([^/]+)/", path)
        if m and m.group(1) in suites:
            why[m.group(1)] = f"{path} is under .agents/skills/{m.group(1)}/"
        for suite in suites:
            info = deps.get(suite) or {}
            if "error" in info:
                continue
            for pat, how in sorted({**info.get("files", {}), **info.get("globs", {})}.items()):
                if matches(pat, path):
                    why.setdefault(suite, f"{path} is read by the {suite} tests ({how})")
                    break
        return why

    if not changes:
        return result                                  # nothing changed: the only empty selection
    failed = sorted(s for s in suites if "error" in (deps.get(s) or {}))
    result["universe"] = [path for _status, path in changes]
    reason = None
    if failed:
        # what a suite whose derivation failed reads is not known, so no path is known to be outside what it reads
        reason = f"the derivation failed for {', '.join(failed)}: {deps[failed[0]]['error']}"
    elif not suites:
        reason = "no suite was found"
    else:
        for status, path in changes:
            if status not in ("A", "M"):
                reason = f"{path} has status {status} (only added and modified files are mapped)"
                break
            if not canonical(path):
                reason = f"{path!r} is not a canonical repo-relative path"
                break
            if not claimed_by(path):
                reason = f"{path} is read by no suite the derivation knows of (an unknown path)"
                break
    if reason is not None:
        result["selection"] = "all"
        result["reason"] = reason
        for suite in suites:
            result["reasons"][suite] = [f"all suites: {reason}"]
        return result
    reasons: dict = {}
    for _status, path in changes:
        for suite, why in claimed_by(path).items():
            reasons.setdefault(suite, []).append(why)
    for suite in suites:
        info = deps.get(suite) or {}
        if info.get("unbounded"):
            reasons.setdefault(suite, []).append(f"unbounded read: {info['unbounded'][0]}")
    for suite, why in reasons.items():
        if len(why) > MAX_REASONS:                         # a big diff: the first paths say how, the rest only how many
            reasons[suite] = why[:MAX_REASONS] + [f"and {len(why) - MAX_REASONS} more changed paths"]
    result["selection"] = sorted(reasons)
    result["reasons"] = {s: reasons[s] for s in sorted(reasons)}
    return result


# --------------------------------------------------------------------------------------------------------------------
# runtime gaps: what a suite's own run read that its derivation does not name (kjelly/pilot#430, the in-run oracle)
# --------------------------------------------------------------------------------------------------------------------
LISTING_EVENTS = ("os.listdir", "os.scandir", "glob.glob", "shutil.copytree")
WIDE_SITE = re.compile(r" at (\S+):(\d+)\Z")


def listed_directories(pattern):
    """[(directory pattern, recursive)]: the directories a glob lists when it runs ("." is the repository root). A literal
    segment is looked up, not listed; a segment with a wildcard lists the directory before it, and `**` lists everything below
    it (recursive). `docs/*.md` lists `docs`; `a/*/b.py` lists `a`; `.*` lists the root; `x/**` lists `x` and all below."""
    segments = pattern.split("/")
    found = []
    for i, segment in enumerate(segments):
        if has_wild(segment):
            found.append(("/".join(segments[:i]) or ".", segment == "**"))
    return found


def listing_covered(directory, globs):
    """Whether some derived glob lists `directory` (a repository-relative path, "." for the root), or lists a directory below
    it that the glob's literal prefix names."""
    for pattern in globs:
        for where, recursive in listed_directories(pattern):
            if matches(where, directory) or (recursive and (where == "." or matches(where + "/**", directory))):
                return True
            # Python 3.12's pathlib also lists the directories above the one a glob's literal prefix names (`scripts/*.py`
            # lists the root as well); the ancestor of a listed directory is covered, a sibling is not
            if not has_wild(where) and where != "." and (directory == "." or where.startswith(directory + "/")):
                return True
    return False


def normalise_observed(repo, raw, tracked=None):
    """Raw records of an in-run recorder -> what `runtime_gaps` judges.

    raw: [[event, path, site_file, site_line, phase, test], ...] as `suite_reads.py` records them (absolute, as spelled).
    tracked: the repository's tracked files (`git ls-files`), or None when there is no git (a file that exists then counts).
    Returns [{"event", "kind" ("file" | "listing"), "path" (repo-relative, symbolic links resolved), "site" ("path:line"),
    "phase", "test"}]; whatever lies outside the repository, under `.git` or `__pycache__`, or is not a tracked file (a
    listing names a directory) is dropped. Only the realpath of a path is taken: no process is started."""
    real = os.path.realpath(repo)
    tracked_set = None if tracked is None else set(tracked)
    out = []
    for event, path, site_file, site_line, phase, test in raw:
        full = os.path.realpath(path)
        if full != real and not full.startswith(real + os.sep):
            continue
        rel = "." if full == real else os.path.relpath(full, real)
        parts = rel.split("/")
        if parts[0] == ".git" or "__pycache__" in parts:
            continue
        kind = "listing" if event in LISTING_EVENTS else "file"
        if kind == "file":
            if tracked_set is not None:
                if rel not in tracked_set:
                    continue
            elif not os.path.isfile(full):
                continue
        site = None
        if site_file:
            sreal = os.path.realpath(site_file)
            if sreal.startswith(real + os.sep):
                site = f"{os.path.relpath(sreal, real)}:{site_line}"
        out.append({"event": event, "kind": kind, "path": rel, "site": site, "phase": phase, "test": test})
    return out


def statement_starts(repo):
    """A function (path, line) -> the first line of the innermost statement that holds the line. Python 3.10 and 3.11 report a
    different line for a call that spans lines; a site and a derived `wide` entry are compared by the statement they sit in.
    A file that cannot be parsed, or a line outside every statement, maps to itself (the comparison then fails closed)."""
    cache: dict = {}

    def starts(path, line):
        spans = cache.get(path)
        if spans is None:
            spans = []
            try:
                with open(os.path.join(repo, path), "rb") as handle:
                    tree = ast.parse(handle.read(), path)
                spans = sorted((n.lineno, getattr(n, "end_lineno", n.lineno) or n.lineno) for n in ast.walk(tree)
                               if isinstance(n, ast.stmt))
            except (OSError, SyntaxError, ValueError):
                pass
            cache[path] = spans
        best = None
        for lo, hi in spans:
            if lo <= line <= hi and (best is None or lo >= best[0]):
                best = (lo, hi)
        return best[0] if best else line

    return starts


def site_key(site, statement=None):
    """A site "path:line" as (path, first line of its statement); None for no site."""
    if not site:
        return None
    path, _, line = site.rpartition(":")
    return (path, statement(path, int(line)) if statement else int(line))


def wide_sites(info, statement=None):
    """The sites of the `wide` entries of one suite's derivation: {(path, first line of the statement)}."""
    found = set()
    for text in info.get("wide", []):
        match = WIDE_SITE.search(text)
        if match:
            found.add(site_key(f"{match.group(1)}:{match.group(2)}", statement))
    return found


def runtime_gaps(suite, observed, deps, statement=None, all_deps=None):
    """The reads of a suite's own run that its derivation does not name: [{"kind", "path", "site", "phase", "test", "why"}].

    observed: `normalise_observed` output of the run of `suite`. deps: what `derive` returned (at least for `suite`).
    statement: `statement_starts(repo)` (a site and a `wide` entry are compared by the statement they sit in); None compares
    the lines as they are. all_deps: a function returning the derivation of every suite, called only when a read at a `wide`
    site needs to know whether another suite claims the path (None: `deps` holds every suite).

    A file read is a gap unless the suite's files or globs name it, or it sits under the suite's own directory, or it was made
    at a `wide` site the derivation reported (a data-dependent path it does not follow) and no other suite claims the path
    (then a change to it is an unknown path and selects every suite; a path another suite claims would select only that suite).
    A listing of a directory is a gap unless a derived glob lists it (`listed_directories`). A suite whose derivation
    failed is a gap of its own (a failed derivation selects every suite, but nothing is known to compare against)."""
    info = deps.get(suite)
    if info is None or "error" in info:
        why = "no derivation" if info is None else f"the derivation failed: {info['error']}"
        return [{"kind": "derivation", "path": suite, "site": None, "phase": None, "test": None, "why": why}]
    own = f"{SKILLS_DIR}/{suite}"
    files = set(info.get("files", {}))
    globs = sorted(info.get("globs", {}))
    wide = wide_sites(info, statement)

    def at_wide_site(site):
        return site_key(site, statement) in wide

    def claimed_elsewhere(path):
        everything = all_deps() if all_deps else deps
        for other, other_info in sorted(everything.items()):
            if other == suite or "error" in other_info:
                continue
            if path.startswith(f"{SKILLS_DIR}/{other}/") or any(
                    matches(pat, path) for pat in {**other_info.get("files", {}), **other_info.get("globs", {})}):
                return True
        return False

    gaps, seen = [], set()
    for record in observed:
        path, kind = record["path"], record["kind"]
        if path == own or path.startswith(own + "/") or (kind, path) in seen:
            continue
        if kind == "file":
            if path in files or any(matches(g, path) for g in globs):
                continue
            if at_wide_site(record["site"]) and not claimed_elsewhere(path):
                continue
            why = "read by the run, named by no file or glob of the derivation"
        else:
            if listing_covered(path, globs):
                continue
            why = "listed by the run, by no glob of the derivation"
        seen.add((kind, path))
        gaps.append({"kind": kind, "path": path, "site": record["site"], "phase": record["phase"], "test": record["test"],
                     "why": why})
    return sorted(gaps, key=lambda g: (g["path"], g["kind"]))


# --------------------------------------------------------------------------------------------------------------------
# command line: the derivation and the selection, for a person to read
# --------------------------------------------------------------------------------------------------------------------
def main(argv=None):
    """The command line: list the suites, print what each reads (--derive), or print the selection for a diff (--changes)."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", default=".", help="the checkout to derive from (default: the current directory)")
    parser.add_argument("--derive", action="store_true", help="print what each suite reads")
    parser.add_argument("--changes", metavar="FILE", help="`git diff --name-status --no-renames -z BASE HEAD` output ('-' = stdin): "
                                                           "print the selection")
    args = parser.parse_args(argv)
    deps = derive(args.repo)
    if args.changes:
        data = sys.stdin.buffer.read() if args.changes == "-" else open(args.changes, "rb").read()
        print(json.dumps(select(parse_name_status(data), deps), indent=2))
    elif args.derive:
        print(json.dumps(deps, indent=2, sort_keys=True))
    else:
        print(json.dumps(discover(os.path.abspath(args.repo))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
