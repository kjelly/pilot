"""The skill-suite selection (kjelly/pilot#430): what a change can reach, derived from the tests' own code.

`make skill-test` runs every suite under `.agents/skills/*/tests`; the local receipt runs the suites a change can reach and CI
runs them all. The invariant under test: the local receipt runs every skill suite whose tests can import, load or read a changed
path, and all suites when the mapping is unknown, a file was deleted or renamed, or the derivation fails. Four groups:

* the selector (`select`), on hand-written sources: one case per path class, each with the control that shows the case is not
  a constant answer (AGENTS.md section 5.12);
* the derivation (`derive`), on synthetic trees: one case per construct the evaluator follows, each with the neighbouring
  construct it must NOT follow (a temporary directory is no edge), and the failures that select every suite;
* the real tree: the pins of what the selection is for this repository, and an ORACLE that loads every suite under an audit
  hook and checks that every repository file the load touches outside the suite is a derived source of it (a derivation that
  loses an edge fails here, and the oracle itself is shown to fail on a lost edge);
* the Makefile: `make skill-test SKILL_SUITES="a b"` against a `python3` shim, next to the recipe it replaced.
"""
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from gitrepo import load_module  # noqa: E402

SCRIPTS = HERE.parent / "scripts"
REPO = HERE.parents[3]
ss = load_module(SCRIPTS / "skill_suites.py")
SKILLS = ".agents/skills"


def sources(files=(), globs=(), unbounded=(), error=None):
    """Hand-written sources of one suite, in the shape `derive` returns."""
    if error:
        return {"error": error}
    return {"files": {f: "test" for f in files}, "globs": {g: "test" for g in globs}, "unbounded": list(unbounded),
            "wide": [], "modules": []}


class SelectTests(unittest.TestCase):
    """`select` on sources that are written out: the rule of the selection, one case per path class."""

    DEPS = {"alpha": sources(files=["README.md", "scripts/pr_loop.py"], globs=["docs/*.md"]),
            "beta": sources(files=["scripts/pr_loop.py", ".agents/skills/alpha/scripts/lib.py"]),
            "gamma": sources(),
            "delta": sources(unbounded=["reads a path derived from the environment at x.py:1"])}

    def select(self, *changes, deps=None):
        return ss.select(list(changes), self.DEPS if deps is None else deps)

    def test_a_diff_with_no_path_in_the_universe_selects_nothing(self):
        for changes in ((), (("M", "cmd/pilot/main.go"),), (("D", "internal/x/y.go"), ("A", "docs/new.txt")),
                        (("M", ".github/workflows/ci.yml"),)):
            with self.subTest(changes=changes):
                result = self.select(*changes)
                self.assertEqual([], result["selection"])
                self.assertIsNone(result["reason"])
        # control: the same kind of path IS selected once a suite reads it (the universe grows with what is read)
        self.assertEqual(["alpha", "delta"], self.select(("M", "README.md"))["selection"])

    def test_a_path_under_a_suite_selects_it_and_whoever_reads_that_path(self):
        self.assertEqual(["delta", "gamma"], self.select(("M", ".agents/skills/gamma/tests/test_x.py"))["selection"])
        # beta reads a script of alpha: a change there selects alpha (its own directory) and beta (its source)
        self.assertEqual(["alpha", "beta", "delta"], self.select(("M", ".agents/skills/alpha/scripts/lib.py"))["selection"])
        # control: another file of alpha is not beta's source
        self.assertEqual(["alpha", "delta"], self.select(("M", ".agents/skills/alpha/scripts/other.py"))["selection"])

    def test_the_reason_names_the_changed_path_and_the_edge(self):
        result = self.select(("M", "scripts/pr_loop.py"))
        self.assertEqual(["alpha", "beta", "delta"], result["selection"])
        for suite in ("alpha", "beta"):
            self.assertTrue(any("scripts/pr_loop.py" in why and f"read by the {suite} tests" in why
                                for why in result["reasons"][suite]), result["reasons"])
        self.assertTrue(any("unbounded" in why for why in result["reasons"]["delta"]), result["reasons"])
        self.assertNotIn("gamma", result["reasons"])

    def test_a_big_diff_lists_the_first_reasons_and_counts_the_rest(self):
        changes = [("M", f".agents/skills/gamma/references/file{i}.md") for i in range(20)]
        why = self.select(*changes)["reasons"]["gamma"]
        self.assertEqual(ss.MAX_REASONS + 1, len(why))
        self.assertEqual(f"and {20 - ss.MAX_REASONS} more changed paths", why[-1])
        self.assertIn("file0.md", why[0])

    def test_a_glob_source_selects_what_it_matches_and_nothing_else(self):
        self.assertEqual(["alpha", "delta"], self.select(("A", "docs/new.md"))["selection"])
        self.assertEqual([], self.select(("A", "docs/new.txt"))["selection"])
        self.assertEqual([], self.select(("A", "docs/deeper/new.md"))["selection"])   # `*` stays inside one segment

    def test_a_suite_with_an_unbounded_read_is_selected_whenever_something_is_in_the_universe(self):
        self.assertIn("delta", self.select(("M", "README.md"))["selection"])
        self.assertIn("delta", self.select(("M", ".agents/skills/gamma/SKILL.md"))["selection"])
        self.assertNotIn("delta", self.select(("M", "cmd/pilot/main.go"))["selection"])   # control: no universe path

    def test_a_deleted_or_type_changed_file_selects_every_suite(self):
        for status in ("D", "T", "U", "R100", "C"):
            with self.subTest(status=status):
                result = self.select(("M", ".agents/skills/gamma/SKILL.md"), (status, "README.md"))
                self.assertEqual("all", result["selection"])
                self.assertIn(status, result["reason"])
        self.assertEqual("all", self.select(("D", ".agents/skills/gamma/SKILL.md"))["selection"])
        # a deletion outside the universe changes nothing when the rest of the diff is outside it too ...
        self.assertEqual([], self.select(("D", "internal/x/y.go"))["selection"])
        # ... and selects everything when the diff also reaches the universe (a rename arrives as D + A, both judged)
        renamed = self.select(("D", "internal/x/old.go"), ("A", "internal/x/new.go"), ("M", "README.md"))
        self.assertEqual("all", renamed["selection"])
        # control: the same diff with the deletion removed is narrow
        self.assertEqual(["alpha", "delta"], self.select(("A", "internal/x/new.go"), ("M", "README.md"))["selection"])

    def test_a_path_that_is_not_canonical_selects_every_suite(self):
        for spelling in ("/etc/passwd", "../outside.txt", "a/../README.md", "", "a\\b.md", "./README.md", "a//b", "a/./b"):
            with self.subTest(path=spelling):
                self.assertEqual("all", self.select(("M", spelling))["selection"])
        self.assertEqual(["alpha", "delta"], self.select(("M", "README.md"))["selection"])   # control: the canonical spelling

    def test_a_path_that_is_not_canonical_selects_every_suite_even_when_a_glob_would_claim_it(self):
        broad = dict(self.DEPS, gamma=sources(globs=["**/*.md", "*.md"]))
        for spelling in ("../evil.md", "/abs/x.md", "a\\b.md"):
            with self.subTest(path=spelling):
                self.assertTrue(ss.matches("**/*.md", spelling) or ss.matches("*.md", spelling), "premise: the glob claims it")
                self.assertEqual("all", self.select(("M", spelling), deps=broad)["selection"])
        self.assertEqual(["delta", "gamma"], self.select(("M", "x.md"), deps=broad)["selection"])      # control: canonical

    def test_an_unattributed_path_of_the_universe_selects_every_suite(self):
        result = self.select(("M", ".claude/zzz"))
        self.assertEqual("all", result["selection"])
        self.assertIn(".claude/zzz", result["reason"])
        self.assertEqual("all", self.select(("A", ".agents/x"))["selection"])
        self.assertEqual("all", self.select(("M", ".codex/config.toml"))["selection"])
        self.assertEqual("all", self.select(("M", ".agents/other/readme.md"))["selection"])
        # control: once a suite reads the path it selects that suite and the unbounded one, and nothing else
        read = dict(self.DEPS, beta=sources(files=[".claude/zzz"]))
        self.assertEqual(["beta", "delta"], self.select(("M", ".claude/zzz"), deps=read)["selection"])

    def test_a_suite_whose_derivation_failed_selects_every_suite(self):
        broken = dict(self.DEPS, gamma=sources(error="cannot parse x.py: invalid syntax"))
        result = self.select(("M", "README.md"), deps=broken)
        self.assertEqual("all", result["selection"])
        self.assertIn("gamma", result["reason"])
        self.assertIn("cannot parse", result["reason"])
        # what the failed suite reads is not known, so no path is known to be outside the universe: a Go-only diff selects all
        self.assertEqual("all", self.select(("M", "cmd/pilot/main.go"), deps=broken)["selection"])
        # control: with nothing changed there is nothing to run, and with nothing failed a Go-only diff selects nothing
        self.assertEqual([], self.select(deps=broken)["selection"])
        self.assertEqual([], self.select(("M", "cmd/pilot/main.go"))["selection"])

    def test_no_suite_at_all_selects_nothing_to_narrow_to(self):
        self.assertEqual("all", ss.select([("M", ".agents/skills/new/SKILL.md")], {})["selection"])

    def test_a_new_skill_directory_with_tests_selects_its_suite(self):
        deps = dict(self.DEPS, newskill=sources())
        result = self.select(("A", ".agents/skills/newskill/tests/test_new.py"), ("A", ".agents/skills/newskill/SKILL.md"),
                             deps=deps)
        self.assertEqual(["delta", "newskill"], result["selection"])
        # control: with sources derived before the directory existed the same diff cannot be mapped
        self.assertEqual("all", self.select(("A", ".agents/skills/newskill/tests/test_new.py"))["selection"])


class Tree(unittest.TestCase):
    """A synthetic repository in a temporary directory."""

    def tree(self, files):
        tmp = tempfile.TemporaryDirectory(prefix="skill-suites-test-")
        self.addCleanup(tmp.cleanup)
        root = Path(os.path.realpath(tmp.name))
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(text) if rel.endswith(".py") else text)
        return root

    def derive(self, files, suite="s1"):
        deps = ss.derive(str(self.tree(files)))
        self.assertIn(suite, deps)
        self.assertNotIn("error", deps[suite], deps[suite])
        return deps[suite]


def module(body):
    """A test module of suite s1 with the usual anchors in front of `body` (indented under a test method)."""
    return ("import os, sys, subprocess, tempfile, shutil, unittest, importlib.util\nfrom pathlib import Path\n"
            "ROOT = Path(__file__).resolve().parents[4]\nSKILLS = ROOT / '.agents' / 'skills'\n"
            "class T(unittest.TestCase):\n    def test_x(self):\n" + textwrap.indent(textwrap.dedent(body), "        "))


S1 = ".agents/skills/s1/tests/test_a.py"
S2 = ".agents/skills/s2/tests/test_b.py"


class DerivationTests(Tree):
    """`derive`: one construct per case, with the construct next to it that must not be followed."""

    def test_the_file_anchor_leads_to_the_files_a_test_reads(self):
        found = self.derive({S1: module('''
            (ROOT / "README.md").read_text()
            (ROOT / "docs" / "a.md").read_bytes()
            open(os.path.join(ROOT, "docs", "b.md"))
            (Path(__file__).resolve().parents[2] / "s2" / "x.txt").exists()
            Path(__file__).with_name("data.json").read_text()
        ''')})
        self.assertLessEqual({"README.md", "docs/a.md", "docs/b.md", ".agents/skills/s2/x.txt"}, set(found["files"]))
        self.assertNotIn(".agents/skills/s1/tests/data.json", found["files"])           # the suite's own directory is not listed

    def test_a_temporary_directory_is_not_an_edge(self):
        found = self.derive({S1: module('''
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "README.md").write_text("x")
                (Path(tmp) / "README.md").read_text()
                Path(tmp).joinpath("docs", "a.md").exists()
                open(os.path.join(tmp, "b.md"))
                list(Path(tmp).iterdir())
                shutil.copytree(tmp, tmp + "-copy")
        ''')})
        self.assertEqual({}, found["files"])
        self.assertEqual({}, found["globs"])
        self.assertEqual([], found["unbounded"])

    def test_a_read_that_is_only_written_down_is_no_edge(self):
        found = self.derive({S1: module('''
            self.assertEqual("README.md", "README.md")
            text = "see README.md and docs/a.md"
            self.assertIn("README.md", text)
        ''')})
        self.assertEqual({}, found["files"])               # a bare string literal is not an anchor

    def test_a_dict_key_loop_reaches_each_key(self):
        found = self.derive({S1: module('''
            NAMES = {"a.txt": 1, "b.txt": 2}
            for name in NAMES:
                (ROOT / "data" / name).read_text()
            for rel, _n in (("p.txt", 1), ("q/r.txt", 2)):
                (ROOT / rel).exists()
            [(ROOT / f"{n}.md").read_text() for n in ("x", "y")]
        ''')})
        self.assertLessEqual({"data/a.txt", "data/b.txt", "p.txt", "q/r.txt", "x.md", "y.md"}, set(found["files"]))
        self.assertNotIn("data/1", found["files"])

    def test_a_helper_parameter_is_resolved_through_its_call_sites(self):
        files = {S1: ("import unittest\nfrom pathlib import Path\nfrom helpers import load\nROOT = Path(__file__).resolve().parents[4]\n"
                      "class T(unittest.TestCase):\n    def test_x(self):\n        load(ROOT / 'docs' / 'a.md')\n"
                      "        load(rel=ROOT / 'docs' / 'b.md')\n"),
                 ".agents/skills/s1/tests/helpers.py": "def load(rel):\n    return rel.read_text()\n"}
        found = self.derive(files)
        self.assertLessEqual({"docs/a.md", "docs/b.md"}, set(found["files"]))
        # control: the helper called with a temporary path only reads nothing in the repository
        calm = dict(files, **{S1: files[S1].replace("ROOT / 'docs' / 'a.md'", "Path(tempfile.gettempdir())")
                              .replace("ROOT / 'docs' / 'b.md'", "Path(tempfile.gettempdir()) / 'b.md'")
                              .replace("import unittest", "import tempfile, unittest")})
        self.assertEqual({}, self.derive(calm)["files"])

    def test_a_method_parameter_and_an_attribute_are_followed_on_self(self):
        found = self.derive({S1: ("import unittest\nfrom pathlib import Path\n"
                                  "class T(unittest.TestCase):\n    ROOT = Path(__file__).resolve().parents[4]\n"
                                  "    def setUp(self):\n        self.doc = self.ROOT / 'docs' / 'setup.md'\n"
                                  "    def read(self, rel):\n        return (self.ROOT / rel).read_text()\n"
                                  "    def test_x(self):\n        self.doc.read_text()\n        self.read('docs/x.md')\n")})
        self.assertLessEqual({"docs/setup.md", "docs/x.md"}, set(found["files"]))

    def test_a_glob_a_listing_and_a_copy_are_subtrees_and_patterns(self):
        found = self.derive({S1: module('''
            list(ROOT.glob("docs/*.md"))
            list(SKILLS.rglob("*.md"))
            list((ROOT / "fixtures").iterdir())
            os.listdir(ROOT / "listed")
            shutil.copytree(ROOT / "copied", Path(tempfile.gettempdir()) / "c")
        ''')})
        self.assertLessEqual({"docs/*.md", ".agents/skills/**/*.md", "fixtures/**"}, set(found["globs"]))
        self.assertLessEqual({"listed/**", "copied/**"}, set(found["globs"]))
        self.assertTrue(ss.matches("docs/*.md", "docs/new.md") and not ss.matches("docs/*.md", "docs/a/new.md"))

    def test_a_sys_path_insert_makes_a_module_importable_and_the_import_is_an_edge(self):
        files = {S1: module('''
                     sys.path.insert(0, str(SKILLS / "lib" / "scripts"))
                     import helper
                 '''),
                 ".agents/skills/lib/scripts/helper.py": "VALUE = 1\n"}
        found = self.derive(files)
        self.assertIn(".agents/skills/lib/scripts/helper.py", found["files"])
        # control: the same import with no insert finds no module of the repository
        bare = self.derive(dict(files, **{S1: files[S1].replace('sys.path.insert(0, str(SKILLS / "lib" / "scripts"))', "pass")}))
        self.assertNotIn(".agents/skills/lib/scripts/helper.py", bare["files"])

    def test_an_import_is_followed_through_a_script_to_what_that_imports(self):
        # test -> script -> bounded_run: the second level is reached through the script's own sys.path insert
        files = {S1: module('''
                     sys.path.insert(0, str(SKILLS / "lib" / "scripts"))
                     import first
                 '''),
                 ".agents/skills/lib/scripts/first.py": ("import sys\nfrom pathlib import Path\n"
                                                         "sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'base' / 'scripts'))\n"
                                                         "import bounded\nSAYS = (Path(__file__).parents[4] / 'NOTICE.md').read_text()\n"),
                 ".agents/skills/base/scripts/bounded.py": "LIMIT = 1\n"}
        found = self.derive(files)
        self.assertLessEqual({".agents/skills/lib/scripts/first.py", ".agents/skills/base/scripts/bounded.py", "NOTICE.md"},
                             set(found["files"]))
        # control: a suite that imports only `first`'s sibling that imports nothing does not reach bounded.py
        other = self.derive({S1: module('''
                     sys.path.insert(0, str(SKILLS / "lib" / "scripts"))
                     import plain
                 '''), ".agents/skills/lib/scripts/plain.py": "X = 1\n", ".agents/skills/base/scripts/bounded.py": "LIMIT = 1\n"})
        self.assertNotIn(".agents/skills/base/scripts/bounded.py", other["files"])

    def test_every_candidate_of_a_name_is_followed(self):
        found = self.derive({S1: module('''
                                 sys.path.insert(0, str(SKILLS / "one" / "scripts"))
                                 sys.path.insert(0, str(SKILLS / "two" / "scripts"))
                                 import twin
                             '''),
                             ".agents/skills/one/scripts/twin.py": "A = 1\n", ".agents/skills/two/scripts/twin.py": "B = 1\n"})
        self.assertLessEqual({".agents/skills/one/scripts/twin.py", ".agents/skills/two/scripts/twin.py"}, set(found["files"]))

    def test_a_module_loaded_by_path_is_an_edge_and_part_of_the_closure(self):
        files = {S1: module('''
                     spec = importlib.util.spec_from_file_location("m", ROOT / "tools" / "x.py")
                     m = importlib.util.module_from_spec(spec)
                     spec.loader.exec_module(m)
                 '''),
                 "tools/x.py": ("from pathlib import Path\nDATA = (Path(__file__).resolve().parent / 'data.json').read_text()\n")}
        found = self.derive(files)
        self.assertLessEqual({"tools/x.py", "tools/data.json"}, set(found["files"]))        # what the loaded module reads too
        calm = self.derive(dict(files, **{S1: files[S1].replace('ROOT / "tools" / "x.py"', 'Path(tempfile.gettempdir()) / "x.py"')}))
        self.assertNotIn("tools/x.py", calm["files"])

    def test_a_load_through_a_helper_function_reaches_its_call_sites(self):
        files = {S1: ("import importlib.util, unittest\nfrom pathlib import Path\nSCRIPTS = Path(__file__).resolve().parents[2] / 'lib' / 'scripts'\n"
                      "def load(name):\n    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + '.py'))\n"
                      "    module = importlib.util.module_from_spec(spec)\n    spec.loader.exec_module(module)\n    return module\n"
                      "one = load('one')\ntwo = load('two')\nclass T(unittest.TestCase):\n    def test_x(self):\n"
                      "        Path(one.__file__).read_text()\n"),
                 ".agents/skills/lib/scripts/one.py": "A = 1\n", ".agents/skills/lib/scripts/two.py": "B = 1\n"}
        found = self.derive(files)
        self.assertLessEqual({".agents/skills/lib/scripts/one.py", ".agents/skills/lib/scripts/two.py"}, set(found["files"]))

    def test_a_patch_target_named_by_a_string_imports_its_module(self):
        files = {S1: ("import sys, unittest\nfrom pathlib import Path\nfrom unittest import mock\nSKILLS = Path(__file__).resolve().parents[2]\n"
                      "sys.path.insert(0, str(SKILLS / 'lib' / 'scripts'))\nclass T(unittest.TestCase):\n"
                      "    def test_x(self):\n        with mock.patch('patched.VALUE', 2):\n            pass\n"
                      "        with mock.patch.object(self, 'assertTrue'):\n            pass\n"),
                 ".agents/skills/lib/scripts/patched.py": "VALUE = 1\n", ".agents/skills/lib/scripts/other.py": "VALUE = 1\n"}
        found = self.derive(files)
        self.assertIn(".agents/skills/lib/scripts/patched.py", found["files"])       # patching imports the module it names
        self.assertNotIn(".agents/skills/lib/scripts/other.py", found["files"])      # control: a module nothing names is no edge

    def test_a_script_a_test_runs_as_a_process_is_part_of_the_closure(self):
        files = {S1: module('''
                     subprocess.run([sys.executable, str(ROOT / "tools" / "run.py"), "--help"], check=True)
                 '''),
                 "tools/run.py": ("import subprocess\nfrom pathlib import Path\n(Path(__file__).parent / 'cfg.json').read_text()\n"
                                  "subprocess.run(['git', 'rev-parse', 'HEAD'])\n")}
        found = self.derive(files)
        self.assertLessEqual({"tools/run.py", "tools/cfg.json"}, set(found["files"]))
        # the process has the working directory its test gives it: its own git call is not a read of this repository
        self.assertEqual([], found["unbounded"])

    def test_a_relative_path_is_anchored_at_the_suite_directory(self):
        found = self.derive({S1: module('''
            open("../s2/data.txt")
            Path("../s2/more.txt").read_text()
            Path("local.txt").exists()
        ''')})
        self.assertLessEqual({".agents/skills/s2/data.txt", ".agents/skills/s2/more.txt"}, set(found["files"]))
        self.assertNotIn(".agents/skills/s1/local.txt", found["files"])

    def test_an_import_by_name_is_an_edge_and_an_unknown_name_is_unbounded(self):
        files = {S1: module('''
                     sys.path.insert(0, str(SKILLS / "lib" / "scripts"))
                     importlib.import_module("named")
                 '''), ".agents/skills/lib/scripts/named.py": "X = 1\n"}
        found = self.derive(files)
        self.assertIn(".agents/skills/lib/scripts/named.py", found["files"])
        self.assertEqual([], found["unbounded"])
        unknown = self.derive({S1: module('''
                     name = tempfile.mkdtemp()
                     importlib.import_module(name)
                 ''')})
        self.assertTrue(any("import of a name" in why for why in unknown["unbounded"]), unknown["unbounded"])

    def test_a_path_taken_from_the_environment_is_an_unbounded_read(self):
        read = self.derive({S1: module('''
            Path(os.environ["WHERE_IS_IT"]).read_text()
        ''')})
        self.assertTrue(any("environment" in why for why in read["unbounded"]), read["unbounded"])
        for control, body in (
                ("the test puts a temporary directory there itself",
                 'os.environ["WHERE_IS_IT"] = tempfile.mkdtemp()\nPath(os.environ["WHERE_IS_IT"]).read_text()'),
                ("a copy of the environment handed to a process", 'env = dict(os.environ, A="1")\nPath(env["A"]).read_text()'),
                ("a path that is not taken from the environment", 'Path(tempfile.gettempdir()).read_text()')):
            with self.subTest(control=control):
                self.assertEqual([], self.derive({S1: module(body)})["unbounded"])

    def test_a_script_under_test_reads_the_environment_its_test_gives_it(self):
        files = {S1: module('''
                     sys.path.insert(0, str(SKILLS / "lib" / "scripts"))
                     import state
                 '''), ".agents/skills/lib/scripts/state.py": ("import os\nfrom pathlib import Path\n"
                                                              "DIR = Path(os.environ.get('STATE_DIR', '/nonexistent'))\n"
                                                              "def read():\n    return (DIR / 'x').read_text()\n")}
        self.assertEqual([], self.derive(files)["unbounded"])

    def test_git_in_the_working_directory_of_a_test_is_an_unbounded_read_of_the_repository(self):
        read = self.derive({S1: module('''
            subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True)
        ''')})
        self.assertTrue(any("git reads the state" in why for why in read["unbounded"]), read["unbounded"])
        for control, body in (("git in a temporary directory", 'subprocess.run(["git", "init"], cwd=tempfile.mkdtemp())'),
                              ("git named by -C", 'subprocess.run(["git", "-C", tempfile.mkdtemp(), "status"])'),
                              ("git that reads no repository", 'subprocess.run(["git", "--version"])')):
            with self.subTest(control=control):
                self.assertEqual([], self.derive({S1: module(body)})["unbounded"])

    def test_a_listing_of_the_repository_root_that_names_no_file_is_reported_but_not_followed(self):
        found = self.derive({S1: module('''
            for name in os.listdir(ROOT / "docs"):
                (ROOT / name).read_text()
        ''')})
        self.assertEqual([], found["unbounded"])
        self.assertTrue(any("under the repository root" in why for why in found["wide"]), found["wide"])
        self.assertIn("docs/**", found["globs"])

    def test_a_suite_with_no_tests_directory_is_no_suite(self):
        root = self.tree({S1: module("pass\n"), ".agents/skills/plain/SKILL.md": "x\n"})
        self.assertEqual(["s1"], ss.discover(str(root)))
        self.assertEqual([], ss.discover(str(self.tree({"README.md": "x"}))))
        (root / ".agents/skills/plain/tests").mkdir()
        self.assertEqual(["plain", "s1"], ss.discover(str(root)))

    def test_only_test_star_files_are_loaded_and_the_rest_by_import(self):
        found = self.derive({S1: module("pass\n"),
                             ".agents/skills/s1/tests/notatest.py": "from pathlib import Path\n(Path(__file__).parents[4] / 'X.md').read_text()\n"})
        self.assertNotIn("X.md", found["files"])

    def test_global_nonlocal_and_walrus_bindings_carry_a_path_to_where_it_is_read(self):
        found = self.derive({S1: ("import asyncio, unittest\nfrom pathlib import Path\nROOT = Path(__file__).resolve().parents[4]\n"
                                  "DOC = None\nLATE = []\n"
                                  "def setup():\n    global DOC\n    DOC = ROOT / 'docs' / 'global.md'\n    LATE.append(ROOT / 'docs' / 'late.md')\n"
                                  "def outer():\n    held = ROOT / 'docs' / 'before.md'\n    def inner():\n        nonlocal held\n"
                                  "        held = ROOT / 'docs' / 'nonlocal.md'\n    inner()\n    return held\n"
                                  "async def later():\n    return (ROOT / 'docs' / 'async.md').read_text()\n"
                                  "class T(unittest.TestCase):\n    def test_x(self):\n        DOC.read_text()\n"
                                  "        LATE[0].read_text()\n        outer().read_text()\n"
                                  "        (walrus := ROOT / 'docs' / 'walrus.md').read_text()\n"
                                  "        asyncio.run(later())\n")})
        self.assertLessEqual({"docs/global.md", "docs/late.md", "docs/nonlocal.md", "docs/walrus.md", "docs/async.md"},
                             set(found["files"]))

    def test_a_read_through_a_symbolic_link_is_a_source_under_the_name_a_change_carries(self):
        files = {S1: module('''
                     (ROOT / ".claude" / "skills" / "s2" / "SKILL.md").read_text()
                     list(ROOT.glob(".claude/skills/*/NOTES.md"))
                     (ROOT / ".claude" / "agents" / "coder.md").read_text()
                 '''),
                 ".agents/skills/s2/SKILL.md": "x\n", ".agents/skills/s2/NOTES.md": "x\n",
                 ".agents/skills/s1/platforms/coder.md": "x\n"}
        root = self.tree(files)
        for link, target in ((".claude/skills/s2", "../../.agents/skills/s2"),
                             (".claude/agents/coder.md", "../../.agents/skills/s1/platforms/coder.md")):
            (root / link).parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, root / link)
        found = ss.derive(str(root))["s1"]
        self.assertIn(".agents/skills/s2/SKILL.md", found["files"])          # the file a change to s2 names
        self.assertIn(".claude/skills/s2/SKILL.md", found["files"])
        self.assertIn(".agents/skills/s2/NOTES.md", found["files"])         # a glob over the links, spelled as their targets
        change = [("M", ".agents/skills/s2/SKILL.md")]
        self.assertEqual(["s1"], ss.select(change, ss.derive(str(root)))["selection"])
        # control: the same reads with no link name nothing under the targets' names, and the change cannot be mapped
        plain = ss.derive(str(self.tree(files)))
        self.assertNotIn(".agents/skills/s2/SKILL.md", plain["s1"]["files"])
        self.assertEqual("all", ss.select(change, plain)["selection"])

    def test_a_module_that_does_not_parse_fails_the_derivation_and_selects_every_suite(self):
        files = {S1: module("(ROOT / 'README.md').read_text()\n"), S2: "def broken(:\n", "README.md": "x\n"}
        deps = ss.derive(str(self.tree(files)))
        self.assertIn("cannot parse", deps["s2"]["error"])
        self.assertNotIn("error", deps["s1"])
        result = ss.select([("M", "README.md")], deps)
        self.assertEqual("all", result["selection"])
        self.assertIn("s2", result["reason"])
        # control: with the module repaired the same change selects only the suite that reads the file
        repaired = ss.derive(str(self.tree(dict(files, **{S2: "def fine():\n    pass\n"}))))
        self.assertEqual(["s1"], ss.select([("M", "README.md")], repaired)["selection"])

    def test_an_error_while_evaluating_fails_the_derivation_and_selects_every_suite(self):
        root = self.tree({S1: module("(ROOT / 'README.md').read_text()\n"), "README.md": "x\n"})
        with mock.patch.object(ss.Analyzer, "effects", side_effect=RuntimeError("an evaluator bug")):
            deps = ss.derive(str(root))
        self.assertIn("an evaluator bug", deps["s1"]["error"])
        self.assertEqual("all", ss.select([("M", "README.md")], deps)["selection"])
        # an evaluation that never ends is cut off by its budget and fails the same way
        with mock.patch.object(ss, "MAX_STEPS", 5):
            deps = ss.derive(str(root))
        self.assertIn("budget", deps["s1"]["error"])
        self.assertEqual("all", ss.select([("M", "README.md")], deps)["selection"])

    def test_the_command_line_prints_the_selection_for_a_name_status_stream(self):
        root = self.tree({S1: module("(ROOT / 'README.md').read_text()\n"), S2: module("pass\n"), "README.md": "x\n"})
        stream = b"M\0README.md\0"
        p = subprocess.run([sys.executable, "-B", str(SCRIPTS / "skill_suites.py"), "--repo", str(root), "--changes", "-"],
                           input=stream, capture_output=True, timeout=120)
        self.assertEqual(0, p.returncode, p.stderr)
        self.assertEqual(["s1"], json.loads(p.stdout)["selection"])
        listing = subprocess.run([sys.executable, "-B", str(SCRIPTS / "skill_suites.py"), "--repo", str(root)],
                                 capture_output=True, timeout=120)
        self.assertEqual(["s1", "s2"], json.loads(listing.stdout))
        self.assertEqual(0, subprocess.run([sys.executable, "-B", str(SCRIPTS / "skill_suites.py"), "--help"],
                                           capture_output=True, timeout=60).returncode)

    def test_a_malformed_name_status_stream_is_refused(self):
        self.assertEqual([("M", "a"), ("D", "b")], ss.parse_name_status(b"M\0a\0D\0b\0"))
        self.assertEqual([], ss.parse_name_status(b""))
        with self.assertRaises(ValueError):
            ss.parse_name_status(b"M\0a\0D\0")


class RealTree(unittest.TestCase):
    """The selection for this repository: the pins, and the oracle that the derivation loses no edge."""

    @classmethod
    def setUpClass(cls):
        cls.deps = ss.derive(str(REPO))

    def select(self, *changes):
        return ss.select(list(changes), self.deps)

    def test_the_suites_are_the_directories_with_tests(self):
        expected = sorted(p.name for p in (REPO / SKILLS).iterdir() if (p / "tests").is_dir())
        self.assertEqual(expected, ss.discover(str(REPO)))
        self.assertEqual(expected, sorted(self.deps))
        self.assertGreaterEqual(len(expected), 6)
        self.assertEqual([], [s for s in self.deps if "error" in self.deps[s]], "every suite derives")

    def test_a_change_to_the_pr_loop_runner_selects_the_suite_that_reads_it_only(self):
        self.assertEqual(["_shared"], self.select(("M", "scripts/pr_loop.py"))["selection"])

    def test_a_change_to_the_shared_bounded_runner_selects_the_suites_that_import_it(self):
        result = self.select(("M", ".agents/skills/_shared/scripts/bounded_run.py"))
        self.assertEqual(["_shared", "issue-to-pr", "pr-ready", "pr-review-merge"], result["selection"])
        for suite in ("issue-batch-planner", "issue-filing"):
            self.assertNotIn(suite, result["selection"])
        self.assertTrue(any("bounded_run.py" in why for why in result["reasons"]["pr-ready"]), result["reasons"]["pr-ready"])

    def test_a_change_to_the_root_readme_selects_the_suite_that_reads_it(self):
        self.assertEqual(["_shared"], self.select(("M", "README.md"))["selection"])

    def test_a_change_to_the_controller_image_selects_the_suites_that_fingerprint_it(self):
        self.assertEqual(["issue-to-pr", "pr-review-merge"],
                         self.select(("M", "images/evidence-controller/Dockerfile"))["selection"])

    def test_a_change_to_the_workflow_and_to_go_code_selects_nothing(self):
        for path in (".github/workflows/ci.yml", "cmd/pilot/cmd/deploy.go", "internal/spec/x_test.go"):
            with self.subTest(path=path):
                self.assertEqual([], self.select(("M", path))["selection"])

    def test_a_deleted_file_of_the_universe_selects_every_suite(self):
        result = self.select(("D", "README.md"))
        self.assertEqual("all", result["selection"])
        self.assertEqual(sorted(self.deps), sorted(result["reasons"]))

    def test_the_makefile_is_read_by_the_suite_that_runs_it(self):
        self.assertEqual(["_shared"], self.select(("M", "Makefile"))["selection"])

    def test_the_suite_that_derives_the_selection_reads_the_three_trees_so_it_claims_what_is_new_in_them(self):
        # test_skill_suites.py walks .agents, .claude and .codex (symlinks(), on the real repository): a path nothing else reads
        # is claimed by `_shared`, whose tests read it; the unattributed rule is for a tree no suite reads (the synthetic cases)
        for path in (".claude/zzz", ".agents/zzz/new.txt", ".codex/zzz.toml"):
            with self.subTest(path=path):
                self.assertEqual(["_shared"], self.select(("A", path))["selection"])

    # -- the oracle ---------------------------------------------------------------------------------------------------

    TRACE = textwrap.dedent('''
        import json, os, sys
        repo, suite, out = os.path.realpath(sys.argv[1]), sys.argv[2], sys.argv[3]
        seen = set()
        def hook(event, args):
            # a file opened, a module imported or executed, a listing, a glob, a process: what loading the tests touches
            if event in ("open", "import", "exec", "os.listdir", "os.scandir", "glob.glob", "subprocess.Popen"):
                if event == "exec":
                    names = [getattr(args[0], "co_filename", None)]
                elif event == "import":
                    names = [args[1]]
                elif event == "subprocess.Popen":
                    names = [args[0], *(args[1] or []), args[2]]
                else:
                    names = [args[0]]
                for name in names:
                    if isinstance(name, (str, bytes, os.PathLike)) and name != "":
                        try:
                            path = os.path.realpath(os.fsdecode(name))
                        except (TypeError, ValueError):
                            continue
                        if path.startswith(repo + os.sep):
                            seen.add((event, os.path.relpath(path, repo)))
        os.chdir(os.path.join(repo, ".agents", "skills", suite))
        sys.path.insert(0, os.path.join(os.getcwd(), "tests"))   # what `unittest discover -s tests` does
        sys.path.insert(0, "")
        sys.addaudithook(hook)
        import unittest
        unittest.defaultTestLoader.discover("tests", pattern="test_*.py")      # loads the modules; runs no test
        with open(out, "w") as handle:
            json.dump(sorted(seen), handle)
    ''')

    def trace(self, suite):
        """The (event, repo-relative path) pairs loading the suite touches, in a process of its own."""
        with tempfile.TemporaryDirectory(prefix="skill-suites-trace-") as tmp:
            out = Path(tmp) / "trace.json"
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            p = subprocess.run([sys.executable, "-B", "-c", self.TRACE, str(REPO), suite, str(out)], cwd=str(REPO), env=env,
                               capture_output=True, text=True, timeout=180)
            self.assertEqual(0, p.returncode, p.stderr[-2000:])
            return [tuple(item) for item in json.loads(out.read_text())]

    @staticmethod
    def unreached(suite, trace, info):
        """Files the load touched outside the suite that no derived source of the suite names."""
        own = f"{SKILLS}/{suite}/"
        sources = list(info["files"]) + list(info["globs"])
        found = []
        for _event, rel in trace:
            if "__pycache__" in rel.split("/") or rel.startswith(own) or (REPO / rel).is_dir():
                continue
            if not any(ss.matches(source, rel) for source in sources):
                found.append(rel)
        return sorted(set(found))

    def test_every_repository_file_loading_a_suite_touches_is_a_source_of_that_suite(self):
        for suite in sorted(self.deps):
            with self.subTest(suite=suite):
                trace = self.trace(suite)
                self.assertGreater(len(trace), 5, f"the trace of {suite} saw nothing: the oracle would pass anything")
                self.assertEqual([], self.unreached(suite, trace, self.deps[suite]))

    def test_the_oracle_sees_an_import_across_suites_and_fails_on_a_lost_edge(self):
        trace = self.trace("pr-review-merge")
        touched = {rel for _event, rel in trace}
        self.assertIn(f"{SKILLS}/_shared/scripts/bounded_run.py", touched)          # pr-review-merge loads the shared runner
        self.assertNotIn(f"{SKILLS}/issue-filing/scripts/create_issue.py", touched)
        info = self.deps["pr-review-merge"]
        self.assertEqual([], self.unreached("pr-review-merge", trace, info))
        lost = dict(info, files={k: v for k, v in info["files"].items() if not k.endswith("/bounded_run.py")})
        self.assertEqual([f"{SKILLS}/_shared/scripts/bounded_run.py"], self.unreached("pr-review-merge", trace, lost))


MAKEFILE = REPO / "Makefile"
# The recipe `skill-test` had before the selection: the plain run must print and run exactly what it did.
OLD_RECIPE = ("skill-test:\n\t@for skill in .agents/skills/*/; do \\\n\t  [ -d \"$$skill/tests\" ] || continue; \\\n"
              "\t  printf '── %s\\n' \"$$skill\"; \\\n"
              "\t  (cd \"$$skill\" && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py') || exit 1; \\\n"
              "\tdone\n")


def recipe_lines(text, target):
    """The tab-indented lines after `target:` up to the first line that is not (what cmd/pilot/cmd makeTargetRecipe reads)."""
    lines = text.split("\n")
    start = next(i for i, line in enumerate(lines) if line.startswith(target + ":"))
    out = []
    for line in lines[start + 1:]:
        if not line.startswith("\t"):
            break
        out.append(line)
    return out


class MakefileTests(unittest.TestCase):
    """`make skill-test` with and without SKILL_SUITES, against a `python3` that only records how it was called."""

    # What `python3` is in these runs: it records where and how it was called, and fails in the suite named by SHIM_FAIL.
    SHIM = ("#!/bin/sh\nprintf '%s|%s\\n' \"$PWD\" \"$*\" >> \"$SHIM_LOG\"\n"
            "case \"$PWD\" in */\"${SHIM_FAIL:-no-such-suite}\") exit 1;; esac\nexit 0\n")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="skill-test-make-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(os.path.realpath(tmp.name))
        for name in ("alpha", "beta", "gamma"):
            (self.root / SKILLS / name / "tests").mkdir(parents=True)
        (self.root / SKILLS / "plain").mkdir(parents=True)            # a skill directory with no tests: not a suite
        shim = self.root / "bin"
        shim.mkdir()
        (shim / "python3").write_text(self.SHIM)
        (shim / "python3").chmod(0o755)
        self.log = self.root / "shim.log"
        self.bin = shim

    def make(self, *args, env=None, makefile=MAKEFILE):
        environ = {k: v for k, v in os.environ.items() if k not in ("SKILL_SUITES", "MAKEFLAGS", "MFLAGS")}
        environ.update(PATH=f"{self.bin}{os.pathsep}{environ['PATH']}", SHIM_LOG=str(self.log), HOME=str(self.root))
        environ.update(env or {})
        self.log.write_text("")
        done = subprocess.run(["make", "--no-print-directory", "-f", str(makefile), "skill-test", *args], cwd=str(self.root),
                              env=environ, capture_output=True, text=True, timeout=120)
        visited = [line.split("|")[0].replace(str(self.root) + "/", "") for line in self.log.read_text().splitlines()]
        return done, visited

    def headers(self, done):
        return [line for line in done.stdout.splitlines() if line.startswith("──")]

    def test_the_plain_run_prints_and_runs_what_the_recipe_before_it_did(self):
        old = self.root / "Makefile.old"
        old.write_text(OLD_RECIPE)
        before, visited_before = self.make(makefile=old)
        after, visited_after = self.make()
        self.assertEqual(0, before.returncode, before.stderr)
        self.assertEqual((before.returncode, before.stdout, before.stderr), (after.returncode, after.stdout, after.stderr))
        self.assertEqual(visited_before, visited_after)
        self.assertEqual([f"── {SKILLS}/alpha/", f"── {SKILLS}/beta/", f"── {SKILLS}/gamma/"], self.headers(after))
        self.assertEqual([f"{SKILLS}/{n}" for n in ("alpha", "beta", "gamma")], visited_after)
        with open(self.log) as handle:
            self.assertTrue(all(line.rstrip().endswith("-m unittest discover -s tests -p test_*.py") for line in handle))

    def test_a_selection_runs_those_suites_with_the_same_command_and_headers(self):
        done, visited = self.make("SKILL_SUITES=beta")
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual([f"{SKILLS}/beta"], visited)
        self.assertEqual([f"── {SKILLS}/beta/"], self.headers(done))
        done, visited = self.make("SKILL_SUITES=gamma alpha")                  # glob order, not the order given
        self.assertEqual([f"{SKILLS}/alpha", f"{SKILLS}/gamma"], visited)
        self.assertEqual([f"── {SKILLS}/alpha/", f"── {SKILLS}/gamma/"], self.headers(done))

    def test_names_separated_by_tabs_and_newlines_are_all_run_and_none_is_skipped_silently(self):
        done, visited = self.make("SKILL_SUITES=alpha\tgamma\nbeta")
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual([f"{SKILLS}/{n}" for n in ("alpha", "beta", "gamma")], visited)
        for empty in ("SKILL_SUITES=", "SKILL_SUITES= ", "SKILL_SUITES=\t\n"):
            with self.subTest(value=repr(empty)):
                done, visited = self.make(empty)                              # empty = all, never none
                self.assertEqual(0, done.returncode, done.stderr)
                self.assertEqual(3, len(visited))

    def test_a_name_that_is_not_a_suite_is_refused_before_anything_runs(self):
        for value in ("nope", "../x", "-x", "alpha nope", "alpha ../beta", "plain", "*", "a/b", "alpha;ls"):
            with self.subTest(value=value):
                done, visited = self.make(f"SKILL_SUITES={value}")
                self.assertEqual(2, done.returncode, done.stdout + done.stderr)
                self.assertEqual([], visited)
                self.assertIn("skill-test:", done.stderr)
        done, visited = self.make("SKILL_SUITES=alpha")                       # control: a real name runs
        self.assertEqual((0, [f"{SKILLS}/alpha"]), (done.returncode, visited))

    def test_a_selection_from_the_environment_is_refused_so_it_never_narrows_the_plain_command(self):
        done, visited = self.make(env={"SKILL_SUITES": "alpha"})
        self.assertEqual(2, done.returncode, done.stdout + done.stderr)
        self.assertEqual([], visited)
        self.assertIn("environment", done.stderr)
        done, visited = self.make(env={"SKILL_SUITES": ""})
        self.assertEqual((2, []), (done.returncode, visited))
        done, visited = self.make("-e", env={"SKILL_SUITES": "alpha"})        # make -e: the environment overrides, still refused
        self.assertEqual((2, []), (done.returncode, visited))
        # control: the command line wins over a stray variable, and is accepted
        done, visited = self.make("SKILL_SUITES=gamma", env={"SKILL_SUITES": "alpha"})
        self.assertEqual((0, [f"{SKILLS}/gamma"]), (done.returncode, visited))

    def test_a_failing_suite_stops_the_run(self):
        done, visited = self.make(env={"SHIM_FAIL": "beta"})
        self.assertNotEqual(0, done.returncode)
        self.assertEqual([f"{SKILLS}/alpha", f"{SKILLS}/beta"], visited)      # gamma is not run

    def test_the_recipe_is_one_block_of_tab_indented_lines_without_a_timeout_and_nothing_else_changed(self):
        text = MAKEFILE.read_text()
        block = recipe_lines(text, "skill-test")
        self.assertGreater(len(block), 5)
        self.assertEqual([], [line for line in block if "-timeout" in line or re.match(r"\s*(ifn?eq|ifn?def|else|endif)\b", line)])
        self.assertIn(".PHONY: skill-test", text)
        self.assertIn("SKILL_SUITES", text.split("skill-test:", 1)[1].split("\n", 1)[0], "the help text names the variable")
        self.assertEqual(1, text.count("\nskill-test:"))
        for needle in ("$(origin SKILL_SUITES)", "$$SKILL_SUITES", "-m unittest discover -s tests -p 'test_*.py'",
                       "for skill in .agents/skills/*/; do", "printf '── %s\\n' \"$$skill\""):
            self.assertIn(needle, "\n".join(block), needle)
        self.assertNotIn("$(SKILL_SUITES)", text)                               # the value is read by the shell, not by make


class PurityTests(unittest.TestCase):
    """The derivation is advice that must be cheap and safe to compute: it starts nothing and reaches no network."""

    def test_the_module_imports_nothing_that_starts_a_process_or_opens_a_connection(self):
        tree = ast.parse((SCRIPTS / "skill_suites.py").read_text())
        imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        self.assertEqual(set(), imported & {"subprocess", "socket", "urllib", "http", "multiprocessing", "asyncio", "shutil",
                                            "ctypes", "pty", "importlib"})
        self.assertLessEqual(imported, {"__future__", "argparse", "ast", "fnmatch", "json", "os", "posixpath", "re", "sys"})


if __name__ == "__main__":
    unittest.main()
