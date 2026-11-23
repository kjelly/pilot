"""Who reads "is this PR Ready?" and what each reader does about the Ready signal (kjelly/pilot#421).

A Ready PR claims "quality is already mergeable", and `ready_signal` is the proof that pr-ready (or issue-to-pr's
mark_ready.py) verified it. Every script that looks at a PR's Draft state is therefore classified here, and the
classification is checked: a script that acts on a Ready PR must import `ready_signal` and ask it (a consumer that
does not is an unguarded way to act on a PR nobody verified), a script that makes a PR Ready must load the module and
call its `prepare` and `write`, the merge train must stay out of it (it trusts the entry it saved when the PR was queued, which the actor
only wrote for a PR with a valid signal), and everything else only displays the state.

The guard is an AST scan of `.agents/skills/*/scripts/**/*.py` and `scripts/*.py` for the string `"draft"` and the
GraphQL field `isDraft` (also inside a `--json` field list), without docstrings. A file that reads either and is not
in `CLASSIFIED` fails the test with its name, so a new reader cannot be added unclassified; a classified file that
stopped reading the Draft state fails too, so the table cannot outlive its reasons.
"""
from __future__ import annotations

import ast
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
REPO_ROOT = HERE.parents[3]

PRODUCER = "producer"    # makes a Draft PR Ready, and signs it after its post-action verification
CONSUMER = "consumer"    # acts on, or selects, a Ready PR: only when the signal is valid
TRAIN = "train"          # entry-bound: trusts the saved entry of a PR the actor queued; never reads the signal
DISPLAY = "display"      # shows or passes on the Draft state; decides nothing about acting on a Ready PR
HOME = "home"            # the signal module itself

CLASSIFIED = {
    ".agents/skills/pr-ready/scripts/pr_gate.py": PRODUCER,
    ".agents/skills/issue-to-pr/scripts/mark_ready.py": PRODUCER,
    ".agents/skills/pr-review-merge/scripts/list_ready.py": CONSUMER,
    ".agents/skills/pr-review-merge/scripts/review_gate.py": CONSUMER,
    ".agents/skills/pr-review-merge/scripts/apply_decision.py": CONSUMER,
    "scripts/pr_loop.py": CONSUMER,
    ".agents/skills/pr-review-merge/scripts/merge_train.py": TRAIN,
    # Reads the field to hand it on or show it; the decision is made by the scripts above.
    ".agents/skills/pr-review-merge/scripts/gh_runtime.py": DISPLAY,        # the field list of `gh pr view`
    ".agents/skills/issue-to-pr/scripts/pr_ci.py": DISPLAY,                 # reports a PR's CI; refuses a Draft
    # Creates a PR (a Draft; Ready only on an explicit `--ready`): never a Draft -> Ready transition, so no signal.
    ".agents/skills/issue-to-pr/scripts/create_pr.py": DISPLAY,
    ".agents/skills/issue-batch-planner/scripts/issue_batch_planner.py": DISPLAY,  # plans; changes nothing
    ".agents/skills/_shared/scripts/pr_loop_result.py": DISPLAY,            # `draft` is the phase of a result file
    ".agents/skills/_shared/scripts/ready_signal.py": HOME,
}
SIGNAL = "ready_signal"
# What a producer must call on the module: `prepare` before it makes a PR Ready, `write` after it verified it.
PREPARES, WRITES = "prepare", "write"
# What a consumer must call, directly (`ready_signal.assess`) or through the gate built on it (`ready_signal_gate`,
# in review_gate.py): a bare `import ready_signal` proves nothing.
ASSESS, GATE = "assess", "ready_signal_gate"


def scanned(root: Path) -> list[Path]:
    files = sorted(root.glob(".agents/skills/*/scripts/**/*.py")) + sorted(root.glob("scripts/*.py"))
    return [f for f in files if "__pycache__" not in f.parts]


def _docstrings(tree: ast.AST) -> set[int]:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                found.add(id(first.value))
    return found


def reads_draft(tree: ast.AST) -> bool:
    """Whether the code (not its docstrings) holds the string "draft" or the field name `isDraft`."""
    skip = _docstrings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            if node.value == "draft" or "isDraft" in re.split(r"[,\s]+", node.value):
                return True
    return False


def references(tree: ast.AST, name: str) -> bool:
    """Whether the code imports, loads or mentions `name` (the module, a name taken from it, its file name or its path)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(alias.name.split(".")[0] == name for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == name:
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.fullmatch(rf"{name}(\.py)?", node.value):
            return True  # `load_by_path("ready_signal", ...)`
        if isinstance(node, ast.Name) and node.id.lower() == f"{name}_path":
            return True
    return False


def imports(tree: ast.AST, name: str) -> bool:
    return any((isinstance(node, ast.Import) and any(alias.name == name for alias in node.names))
               or (isinstance(node, ast.ImportFrom) and node.module == name) for node in ast.walk(tree))


def calls_on_the_module(tree: ast.AST, name: str) -> bool:
    """Whether the code calls `.name(...)` on the loaded signal module: a producer holds it as `signal` or as
    `self.signal` (a wrapper of its own named `prepare` or `write` does not count)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == name:
            receiver = node.func.value
            if (isinstance(receiver, ast.Name) and receiver.id in ("signal", SIGNAL)) \
                    or (isinstance(receiver, ast.Attribute) and receiver.attr == "signal"):
                return True
    return False


def asks(tree: ast.AST) -> bool:
    """Whether the code uses the module's `assess` or the gate (`ready_signal_gate`) built on it."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == ASSESS and isinstance(node.value, ast.Name) \
                and node.value.id == SIGNAL:
            return True
        if isinstance(node, ast.Name) and node.id == GATE:
            return True
    return False


def problems(root: Path, table: dict[str, str]) -> list[str]:
    """Every way the tree at `root` breaks the classification, each naming the file."""
    found = []
    seen = set()
    for path in scanned(root):
        rel = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if not reads_draft(tree):
            continue
        seen.add(rel)
        kind = table.get(rel)
        if kind is None:
            found.append(f"{rel} reads the Draft state and is not classified: say whether it produces, consumes, "
                         "trusts (train) or only displays a Ready PR")
        elif kind == CONSUMER and not (imports(tree, SIGNAL) and asks(tree)):
            found.append(f"{rel} is a consumer of Ready PRs but does not import ready_signal and ask it "
                         "(ready_signal.assess, or review_gate.ready_signal_gate)")
        elif kind == PRODUCER and not (references(tree, SIGNAL) and calls_on_the_module(tree, PREPARES)
                                       and calls_on_the_module(tree, WRITES)):
            found.append(f"{rel} makes PRs Ready but does not load the ready_signal module and call its "
                         f"{PREPARES} and {WRITES} to sign them")
        elif kind == TRAIN and references(tree, SIGNAL):
            found.append(f"{rel} is the merge train and must not read the Ready signal: it trusts its saved entry")
    for rel, kind in sorted(table.items()):
        if rel not in seen:
            found.append(f"{rel} is classified as {kind} but no longer exists or no longer reads the Draft state: "
                         "remove it from the table")
    return found


class ReadyReadersClassified(unittest.TestCase):
    def test_every_reader_of_the_draft_state_is_classified_and_does_what_its_class_requires(self):
        self.assertEqual([], problems(REPO_ROOT, CLASSIFIED))

    def test_the_scan_covers_the_skills_and_the_runner(self):
        names = {f.relative_to(REPO_ROOT).as_posix() for f in scanned(REPO_ROOT)}
        for needed in CLASSIFIED:
            self.assertIn(needed, names)

    # -- the guard has to fire: a pass and a trigger case for every rule (AGENTS.md 5.12) ---------------------------
    @staticmethod
    def tree(files: dict[str, str]):
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return directory, root

    GOOD = {
        "scripts/consumer.py": 'import ready_signal\nok = ready_signal.assess(1, 2, 3, 4) and pr["isDraft"]\n',
        "scripts/producer.py": 'signal = load_by_path("ready_signal", PATH)\nsignal.prepare(1)\nself.signal.write(1)\nx = "draft"\n',
        "scripts/train.py": 'draft = view["isDraft"]\n',
        "scripts/display.py": 'FIELDS = "number,url,isDraft"\n',
    }
    TABLE = {"scripts/consumer.py": CONSUMER, "scripts/producer.py": PRODUCER, "scripts/train.py": TRAIN,
             "scripts/display.py": DISPLAY}

    def check(self, files):
        directory, root = self.tree(files)
        self.addCleanup(directory.cleanup)
        return problems(root, self.TABLE)

    def test_a_tree_that_follows_the_rules_passes(self):
        self.assertEqual([], self.check(self.GOOD))

    def test_an_unclassified_reader_is_named(self):
        got = self.check(dict(self.GOOD, **{"scripts/new_reader.py": 'if pr["isDraft"]:\n    pass\n'}))
        self.assertEqual(1, len(got), got)
        self.assertRegex(got[0], r"^scripts/new_reader\.py reads the Draft state and is not classified")

    def test_a_script_that_does_not_read_the_draft_state_needs_no_classification(self):
        self.assertEqual([], self.check(dict(self.GOOD, **{"scripts/other.py": '"""A draft in a docstring."""\nx = 1\n'})))

    def test_a_consumer_without_the_import_is_named(self):
        got = self.check(dict(self.GOOD, **{"scripts/consumer.py": 'ok = pr["isDraft"]\n'}))
        self.assertEqual(1, len(got), got)
        self.assertRegex(got[0], r"^scripts/consumer\.py is a consumer of Ready PRs but does not import ready_signal")

    def test_a_consumer_that_imports_the_module_but_never_asks_it_is_named(self):
        got = self.check(dict(self.GOOD, **{"scripts/consumer.py": 'import ready_signal\nLABEL = ready_signal.LABEL\nx = "draft"\n'}))
        self.assertEqual(1, len(got), got)
        self.assertRegex(got[0], r"^scripts/consumer\.py is a consumer")

    def test_a_consumer_may_ask_through_the_gate(self):
        via_gate = 'import ready_signal\nfrom review_gate import ready_signal_gate\nx = ready_signal_gate(1)\ny = "draft"\n'
        self.assertEqual([], self.check(dict(self.GOOD, **{"scripts/consumer.py": via_gate})))

    def test_a_producer_that_does_not_use_the_module_is_named(self):
        loaded = 'signal = load_by_path("ready_signal", PATH)\n'
        for case, text in (("no module", 'x = "draft"\n'),
                           ("loaded, never called", loaded + 'x = "draft"\n'),
                           ("no write", loaded + 'signal.prepare(1)\nx = "draft"\n'),
                           ("no prepare", loaded + 'signal.write(1)\nx = "draft"\n'),
                           ("a wrapper of its own is not the module", loaded + "gate.prepare()\ngate.write()\nx = 'draft'\n")):
            with self.subTest(case=case):
                got = self.check(dict(self.GOOD, **{"scripts/producer.py": text}))
                self.assertEqual(1, len(got), got)
                self.assertRegex(got[0], r"^scripts/producer\.py makes PRs Ready but does not load the ready_signal "
                                         r"module and call its prepare and write")

    def test_a_train_that_reads_the_signal_is_named(self):
        got = self.check(dict(self.GOOD, **{"scripts/train.py": 'import ready_signal\nx = view["isDraft"]\n'}))
        self.assertEqual(1, len(got), got)
        self.assertRegex(got[0], r"^scripts/train\.py is the merge train and must not read the Ready signal")

    def test_a_classified_file_that_no_longer_reads_the_draft_state_is_named(self):
        got = self.check(dict(self.GOOD, **{"scripts/display.py": "x = 1\n"}))
        self.assertEqual(1, len(got), got)
        self.assertRegex(got[0], r"^scripts/display\.py is classified as display but no longer exists or no longer reads")

    def test_a_classified_file_that_is_gone_is_named(self):
        files = {name: text for name, text in self.GOOD.items() if name != "scripts/display.py"}
        got = self.check(files)
        self.assertEqual(1, len(got), got)
        self.assertRegex(got[0], r"^scripts/display\.py is classified as display")

    def test_a_json_field_list_counts_as_a_read_and_a_substring_does_not(self):
        read = ast.parse('FIELDS = "number,url,isDraft,headRefOid"\n')
        other = ast.parse('FIELDS = "isDraftish,notdraft"\nNAME = "draftsman"\n')
        self.assertTrue(reads_draft(read))
        self.assertFalse(reads_draft(other))


if __name__ == "__main__":
    unittest.main()
