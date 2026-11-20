"""pr_loop_result.py: the pr-loop task is bound before a gate runs, and one immutable result is published.

Every validation test asserts the reject REASON, not only that something failed, and each gate is
paired with the case that must pass: a validator that rejects everything, or accepts everything, fails
one of the two. The scripts pr_gate.py and apply_decision.py are tested end to end with a fake gh in
their own skills (`--pr-loop-task`); this file is the contract of the shared module itself.
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "pr_loop_result.py"
spec = importlib.util.spec_from_file_location("pr_loop_result", SCRIPT)
plr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plr)

HEAD = "a" * 40
START = "c" * 40
NONCE = "1" * 32
REPO = "acme/demo"
# The messages are spelled out on purpose: they are what the skills and the runner show.
LAYOUT = "expected the absolute path of <checkout>/.pr-loop/<nonce>/task.json"
MISMATCH = "pr-loop task does not match this PR invocation"
NONCE_DIR = "pr-loop task nonce does not match its directory"
TOO_LARGE = "pr-loop task is too large"
BAD_RESULT = "invalid pr-loop result outcome or HEAD"
BAD_WAIT = "invalid pr-loop waiting hand-off"
DIFFERENT = "this pr-loop task already has a different result"
RESULT_KEYS = {"version", "repo", "pr", "phase", "nonce", "start_head",
               "head_sha", "outcome", "reason", "wait_kind", "person_handoff"}


def task_body(**overrides):
    body = dict(version=1, repo=REPO, pr=42, phase="ready", nonce=NONCE, start_head=START)
    body.update(overrides)
    return body


class TaskCase(unittest.TestCase):
    """A scratch directory laid out as scripts/pr_loop.py lays out a task: <dir>/.pr-loop/<nonce>/task.json,
    the directory named after the task's own nonce (unless a test names another parent)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="plr-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def task_file(self, body=None, *, parent=None, name="task.json", raw=None):
        if parent is None:
            named = (body or {}).get("nonce")
            parent = ".pr-loop/" + (named if isinstance(named, str) and re.fullmatch("[0-9a-f]{32}", named) else NONCE)
        path = self.root / parent / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw if raw is not None else json.dumps(task_body() if body is None else body))
        return path

    def result_of(self, path):
        return json.loads(path.with_name("result.json").read_text())

    def result_exists(self, path):
        return path.with_name("result.json").exists()


class LoadTaskTests(TaskCase):
    def load(self, path, repo=REPO, pr=42, phase="ready"):
        return plr.load_task(path, repo, pr, phase)

    def test_a_valid_task_is_returned_unchanged(self):
        body = task_body()
        self.assertEqual(body, self.load(self.task_file(body)))
        draft = task_body(phase="draft", pr=7)
        self.assertEqual(draft, self.load(self.task_file(draft), pr=7, phase="draft"))

    def test_the_repository_is_compared_case_insensitively(self):
        path = self.task_file(task_body(repo="Acme/Demo"))
        self.assertEqual("Acme/Demo", self.load(path, repo="acme/DEMO")["repo"])

    def test_an_uppercase_start_head_is_a_valid_sha(self):
        self.assertEqual("A" * 40, self.load(self.task_file(task_body(start_head="A" * 40)))["start_head"])

    def assert_mismatch(self, body, *, repo=REPO, pr=42, phase="ready", raw=None):
        path = self.task_file(body, raw=raw)
        with self.assertRaises(ValueError) as caught:
            self.load(path, repo=repo, pr=pr, phase=phase)
        self.assertEqual(MISMATCH, str(caught.exception))

    def test_a_task_for_another_repository_pr_or_phase_is_refused(self):
        self.assert_mismatch(task_body(), repo="acme/other")
        self.assert_mismatch(task_body(), repo="other/demo")
        self.assert_mismatch(task_body(), pr=43)
        self.assert_mismatch(task_body(), phase="draft")
        self.assert_mismatch(task_body(phase="draft"), phase="ready")
        self.assert_mismatch(task_body(repo="acme/other"))
        self.assert_mismatch(task_body(pr=43))

    def test_a_phase_that_is_neither_draft_nor_ready_is_refused_even_when_both_sides_say_it(self):
        self.assert_mismatch(task_body(phase="review"), phase="review")

    def test_the_nonce_is_exactly_32_lowercase_hex_characters(self):
        for nonce in ("1" * 31, "1" * 33, "", "A" * 32, "g" * 32, "1" * 31 + "-", 123, None, ["1" * 32]):
            with self.subTest(nonce=nonce):
                self.assert_mismatch(task_body(nonce=nonce))
        self.assertEqual("0123456789abcdef" * 2,
                         self.load(self.task_file(task_body(nonce="0123456789abcdef" * 2)))["nonce"])

    def test_start_head_must_be_a_full_sha(self):
        for head in ("c" * 39, "c" * 41, "g" * 40, "", 1, None):
            with self.subTest(start_head=head):
                self.assert_mismatch(task_body(start_head=head))

    def test_version_and_pr_must_be_real_integers(self):
        for version in (2, 0, "1", True, 1.0, None):
            with self.subTest(version=version):
                self.assert_mismatch(task_body(version=version))
        for pr in ("42", True, 42.0, None):
            with self.subTest(pr=pr):
                self.assert_mismatch(task_body(pr=pr))
        # True == 1 in Python: a boolean pr must not satisfy --pr 1.
        self.assert_mismatch(task_body(pr=True), pr=1)
        self.assert_mismatch(task_body(pr=0), pr=0)
        self.assert_mismatch(task_body(pr=-3), pr=-3)

    def test_repo_must_be_a_string(self):
        self.assert_mismatch(task_body(repo=None))
        self.assert_mismatch(task_body(repo=["acme/demo"]))

    def test_every_key_is_required_and_no_other_key_is_allowed(self):
        for key in sorted(plr.TASK_KEYS):
            with self.subTest(missing=key):
                body = task_body()
                del body[key]
                self.assert_mismatch(body)
        for extra in ({"extra": 1}, {"head_sha": HEAD}, {"outcome": "READY"}):
            with self.subTest(extra=sorted(extra)):
                self.assert_mismatch(task_body(**extra))

    def test_a_task_that_is_not_a_json_object_is_refused(self):
        for raw in ("[]", "null", '"task"', "42"):
            with self.subTest(raw=raw):
                self.assert_mismatch(None, raw=raw)

    def test_malformed_json_and_a_missing_file_fail_without_a_result(self):
        path = self.task_file(raw="{not json")
        with self.assertRaises(ValueError):
            self.load(path)
        missing = self.root / ".pr-loop" / ("3" * 32) / "task.json"
        with self.assertRaises(OSError):
            self.load(missing)
        self.assertFalse(self.result_exists(path))

    def test_the_size_limit_is_4096_bytes(self):
        base = json.dumps(task_body())
        exactly = self.task_file(raw=base + " " * (4096 - len(base)))
        self.assertEqual(4096, exactly.stat().st_size)
        self.assertEqual(NONCE, self.load(exactly)["nonce"])
        over = self.task_file(raw=base + " " * (4097 - len(base)), parent=".pr-loop/" + "2" * 32)
        self.assertEqual(4097, over.stat().st_size)
        with self.assertRaises(ValueError) as caught:
            self.load(over)
        self.assertEqual(TOO_LARGE, str(caught.exception))

    NEUTRAL = ".pr-loop/" + NONCE
    # Every refused layout: the body at the path is VALID for this invocation, so the refusal is for the layout.
    REFUSED_LAYOUTS = {
        "result.json instead of task.json": dict(parent=NEUTRAL, name="result.json"),
        "another file name": dict(parent=NEUTRAL, name="task.json.bak"),
        "a 31 character nonce directory": dict(parent=".pr-loop/" + "1" * 31),
        "a 33 character nonce directory": dict(parent=".pr-loop/" + "1" * 33),
        "an uppercase nonce directory": dict(parent=".pr-loop/" + "A" * 32),
        "a non hex nonce directory": dict(parent=".pr-loop/" + "g" * 32),
        "a legacy-style name under the new directory": dict(parent=".pr-loop/tmux-ai-pr-x"),
        "a hex name without the legacy prefix under the legacy directory": dict(parent=".tmux-ai-pr/" + NONCE),
        "the new directory name without its leading dot": dict(parent="pr-loop/" + NONCE),
        "a directory name that only starts like the new one": dict(parent=".pr-loop-x/" + NONCE),
        "a directory name that only ends like the new one": dict(parent="x.pr-loop/" + NONCE),
        "no nonce directory": dict(parent=".pr-loop"),
        "a nonce directory too deep": dict(parent=".pr-loop/" + NONCE + "/sub"),
        "legacy parent without the prefix": dict(parent=".tmux-ai-pr/other-fixture"),
        "legacy prefix without the dash": dict(parent=".tmux-ai-pr/tmux-ai-prfixture"),
        "legacy directory with another name": dict(parent="tmux-ai-pr/tmux-ai-pr-fixture"),
        "legacy directory name plus a letter": dict(parent=".tmux-ai-prs/tmux-ai-pr-fixture"),
        "legacy name without any directory above it": dict(parent="tmux-ai-pr-fixture"),
    }

    def test_the_path_must_be_the_absolute_task_json_of_a_task_directory(self):
        for case, layout in self.REFUSED_LAYOUTS.items():
            with self.subTest(case=case):
                path = self.task_file(**layout)
                with self.assertRaises(ValueError) as caught:
                    self.load(path)
                self.assertEqual(LAYOUT, str(caught.exception))

    def test_the_layout_is_judged_before_the_file_is_read(self):
        # No file exists at any refused path: reading first would raise OSError, not the layout error.
        for case, layout in self.REFUSED_LAYOUTS.items():
            with self.subTest(case=case):
                path = self.root / layout["parent"] / layout.get("name", "task.json")
                self.assertFalse(path.exists())
                with self.assertRaises(ValueError) as caught:
                    self.load(path)
                self.assertEqual(LAYOUT, str(caught.exception))
        # Control: an accepted layout whose file is missing gets as far as reading it.
        for parent in (self.NEUTRAL, ".tmux-ai-pr/tmux-ai-pr-123456"):
            with self.subTest(accepted=parent):
                with self.assertRaises(FileNotFoundError):
                    self.load(self.root / parent / "task.json")

    def test_a_refused_layout_is_not_read_even_when_the_file_is_oversized_or_malformed(self):
        for raw in ("x" * 5000, "{not json"):
            with self.subTest(size=len(raw)):
                path = self.task_file(raw=raw, parent=".pr-loop-x/" + NONCE)
                with self.assertRaises(ValueError) as caught:
                    self.load(path)
                self.assertEqual(LAYOUT, str(caught.exception))

    def test_a_relative_path_is_refused_before_the_file_is_read(self):
        relative = Path(".pr-loop") / NONCE / "task.json"
        self.assertFalse(relative.is_absolute())
        previous = os.getcwd()
        self.addCleanup(os.chdir, previous)
        self.task_file()
        os.chdir(self.root)  # the file IS there relative to the working directory
        self.assertTrue(relative.exists())
        with self.assertRaises(ValueError) as caught:
            self.load(relative)
        self.assertEqual(LAYOUT, str(caught.exception))
        # Control: the same file by its absolute path is accepted.
        self.assertEqual(NONCE, self.load(self.root / relative)["nonce"])

    def test_the_task_directory_name_is_the_tasks_nonce(self):
        other = "2" * 32
        path = self.task_file(task_body(nonce=other), parent=self.NEUTRAL)  # valid body, wrong directory
        with self.assertRaises(ValueError) as caught:
            self.load(path)
        self.assertEqual(NONCE_DIR, str(caught.exception))
        # Control: the same body in the directory named after its nonce is accepted.
        self.assertEqual(other, self.load(self.task_file(task_body(nonce=other)))["nonce"])

    def test_the_content_is_judged_before_the_nonce_directory(self):
        # A body that is wrong in two ways reports the content error, as before the directory rule existed.
        path = self.task_file(task_body(nonce="2" * 31), parent=self.NEUTRAL)
        with self.assertRaises(ValueError) as caught:
            self.load(path)
        self.assertEqual(MISMATCH, str(caught.exception))

    def test_a_legacy_task_is_still_accepted_read_only(self):
        # A driver written before .pr-loop existed puts the task under .tmux-ai-pr/tmux-ai-pr-<anything>/;
        # that directory name carries no nonce, so none is compared with it.
        for parent in (".tmux-ai-pr/tmux-ai-pr-123456", ".tmux-ai-pr/tmux-ai-pr-" + NONCE,
                       ".tmux-ai-pr/tmux-ai-pr-" + "2" * 32):
            with self.subTest(parent=parent):
                path = self.task_file(parent=parent)
                self.assertEqual(task_body(), self.load(path))
        # The legacy layout is judged by the same content rules.
        bad = self.task_file(task_body(pr=43), parent=".tmux-ai-pr/tmux-ai-pr-bad")
        with self.assertRaises(ValueError) as caught:
            self.load(bad)
        self.assertEqual(MISMATCH, str(caught.exception))

    def test_a_result_is_written_beside_a_legacy_task_too(self):
        path = self.task_file(parent=".tmux-ai-pr/tmux-ai-pr-123456")
        plr.write_result(path, self.load(path), outcome="ENQUEUED", head=HEAD, reason="queued")
        self.assertEqual("ENQUEUED", self.result_of(path)["outcome"])

    def test_the_layout_constants_are_the_ones_the_runner_writes(self):
        self.assertEqual((".pr-loop", ".tmux-ai-pr", "tmux-ai-pr-"),
                         (plr.TASK_DIR, plr.LEGACY_TASK_DIR, plr.LEGACY_TASK_PREFIX))
        self.assertEqual(LAYOUT, plr.LAYOUT)


class WriteResultTests(TaskCase):
    def setUp(self):
        super().setUp()
        self.path = self.task_file()
        self.task = plr.load_task(self.path, REPO, 42, "ready")

    def write(self, task=None, **kwargs):
        args = dict(outcome="ENQUEUED", head=HEAD, reason="queued")
        args.update(kwargs)
        plr.write_result(self.path, task or self.task, **args)

    def assert_refused(self, message, **kwargs):
        before = sorted(p.name for p in self.path.parent.iterdir())
        with self.assertRaises(ValueError) as caught:
            self.write(**kwargs)
        self.assertEqual(message, str(caught.exception))
        self.assertFalse(self.result_exists(self.path), "a refused result must leave no file behind")
        self.assertEqual(before, sorted(p.name for p in self.path.parent.iterdir()))

    def test_the_result_has_exactly_the_documented_keys_and_a_lowercase_head(self):
        self.write(head="A" * 40, reason="queued")
        result = self.result_of(self.path)
        self.assertEqual(RESULT_KEYS, set(result))
        self.assertEqual(
            dict(self.task, head_sha="a" * 40, outcome="ENQUEUED", reason="queued", wait_kind="", person_handoff=False),
            result)
        raw = self.path.with_name("result.json").read_text()
        self.assertTrue(raw.endswith("}\n") and raw.count("\n") == 1, "one JSON line")
        self.assertEqual(["result.json", "task.json"], sorted(p.name for p in self.path.parent.iterdir()),
                         "no temporary file is left next to the task")

    def test_an_outcome_of_the_other_phase_is_refused(self):
        for outcome in ("READY", "WAIT-INTERRUPTED", "DRAFT-BLOCKED"):  # draft-phase (or gate) words
            with self.subTest(phase="ready", outcome=outcome):
                self.assert_refused(BAD_RESULT, outcome=outcome)
        draft_path = self.task_file(task_body(phase="draft", nonce="2" * 32))
        draft = plr.load_task(draft_path, REPO, 42, "draft")
        for outcome in ("DRAFT", "ENQUEUED", "MERGED", "WAITING", "SKIP", "WAITING-CI", "GATE-PASS", "DRY_RUN_MERGE"):
            with self.subTest(phase="draft", outcome=outcome):
                with self.assertRaises(ValueError) as caught:
                    plr.write_result(draft_path, draft, outcome=outcome, head=HEAD, reason="r")
                self.assertEqual(BAD_RESULT, str(caught.exception))
                self.assertFalse(self.result_exists(draft_path))
        for outcome in sorted(plr.OUTCOMES["draft"]):
            with self.subTest(phase="draft accepted", outcome=outcome):
                plr.write_result(draft_path, draft, outcome=outcome, head=HEAD, reason="r")
                draft_path.with_name("result.json").unlink()

    def test_every_outcome_of_the_phase_is_accepted(self):
        for outcome in sorted(plr.OUTCOMES["ready"]):
            with self.subTest(outcome=outcome):
                self.write(outcome=outcome)
                self.assertEqual(outcome, self.result_of(self.path)["outcome"])
                self.path.with_name("result.json").unlink()

    def test_a_head_that_is_not_a_full_sha_is_refused(self):
        for head in ("a" * 39, "a" * 41, "g" * 40, "", "a" * 40 + "\n", HEAD + " "):
            with self.subTest(head=head):
                self.assert_refused(BAD_RESULT, head=head)

    def test_wait_kind_and_person_handoff_only_belong_to_a_waiting_outcome(self):
        for kind in ("person", "transient"):
            with self.subTest(outcome="ENQUEUED", wait_kind=kind):
                self.assert_refused(BAD_WAIT, outcome="ENQUEUED", wait_kind=kind)
        for outcome in ("DRAFT", "MERGED", "SKIP", "ERROR"):
            with self.subTest(outcome=outcome, person_handoff=True):
                self.assert_refused(BAD_WAIT, outcome=outcome, person_handoff=True)
        self.assert_refused(BAD_WAIT, outcome="ENQUEUED", wait_kind="person", person_handoff=True)

    def test_a_person_handoff_needs_the_person_wait_kind(self):
        self.assert_refused(BAD_WAIT, outcome="WAITING", wait_kind="transient", person_handoff=True)
        self.assert_refused(BAD_WAIT, outcome="WAITING", wait_kind="", person_handoff=True)

    def test_an_unknown_wait_kind_is_refused(self):
        for kind in ("later", "PERSON", "Transient", " person", None):
            with self.subTest(wait_kind=kind):
                self.assert_refused(BAD_WAIT, outcome="WAITING", wait_kind=kind)

    def test_the_valid_waiting_combinations_are_accepted(self):
        for kind, handoff in (("transient", False), ("person", False), ("person", True), ("", False)):
            with self.subTest(wait_kind=kind, person_handoff=handoff):
                self.write(outcome="WAITING", wait_kind=kind, person_handoff=handoff)
                result = self.result_of(self.path)
                self.assertEqual((kind, handoff), (result["wait_kind"], result["person_handoff"]))
                self.path.with_name("result.json").unlink()

    def test_the_reason_is_one_clean_line_clipped_to_600_characters(self):
        self.write(reason="line one\nline two\t\x00tab\x1b[31m  red\r\n")
        self.assertEqual("line one line two tab [31m red", self.result_of(self.path)["reason"])
        self.path.with_name("result.json").unlink()
        self.write(reason="x" * 700)
        self.assertEqual("x" * 600, self.result_of(self.path)["reason"])
        self.path.with_name("result.json").unlink()
        self.write(reason="y" * 600)
        self.assertEqual("y" * 600, self.result_of(self.path)["reason"])
        self.path.with_name("result.json").unlink()
        # Whitespace is collapsed BEFORE the clip, so it does not eat into the 600 characters.
        self.write(reason=("z \n" * 400))
        reason = self.result_of(self.path)["reason"]
        self.assertEqual(600, len(reason))
        self.assertNotIn("\n", reason)
        self.assertNotIn("  ", reason)

    def test_a_different_second_result_is_refused_and_the_first_stays_byte_identical(self):
        self.write(outcome="ENQUEUED", reason="first")
        first = self.path.with_name("result.json").read_bytes()
        for second in (dict(outcome="ERROR", reason="first"),
                       dict(outcome="ENQUEUED", reason="second"),
                       dict(outcome="ENQUEUED", reason="first", head="b" * 40),
                       dict(outcome="WAITING", reason="first", wait_kind="person")):
            with self.subTest(second=second):
                with self.assertRaises(ValueError) as caught:
                    self.write(**second)
                self.assertEqual(DIFFERENT, str(caught.exception))
                self.assertEqual(first, self.path.with_name("result.json").read_bytes())
        self.assertEqual(["result.json", "task.json"], sorted(p.name for p in self.path.parent.iterdir()))

    def test_an_identical_republish_is_accepted_and_changes_nothing(self):
        self.write(outcome="ENQUEUED", reason="first")
        target = self.path.with_name("result.json")
        first, inode = target.read_bytes(), target.stat().st_ino
        self.write(outcome="ENQUEUED", reason="first")
        self.write(outcome="ENQUEUED", reason="first", head=HEAD.upper())  # same result once normalized
        self.assertEqual((first, inode), (target.read_bytes(), target.stat().st_ino))

    def test_the_result_is_published_atomically_complete_or_absent(self):
        # os.link of a finished temporary file: there is no moment at which result.json is partial.
        target = self.path.with_name("result.json")
        seen = []
        real_link = os.link

        def watching_link(source, dest, *args, **kwargs):
            seen.append(Path(source).read_text())
            self.assertFalse(Path(dest).exists())
            return real_link(source, dest, *args, **kwargs)

        os.link, previous = watching_link, os.link
        try:
            self.write(reason="complete")
        finally:
            os.link = previous
        self.assertEqual([target.read_text()], seen, "the temporary file was fully written before it was linked")


class PublishGateResultTests(TaskCase):
    """The existing gate/actor report, normalized: every status of both phases."""

    def publish(self, phase, result, *, start_head=START):
        self.runs = getattr(self, "runs", 0) + 1  # a fresh task directory per call: no result is shared
        nonce = format(self.runs, "032x")  # the directory is named after the nonce
        path = self.task_file(task_body(phase=phase, start_head=start_head, nonce=nonce))
        task = plr.load_task(path, REPO, 42, phase)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            plr.publish_gate_result(path, task, result)
        return path, stderr.getvalue()

    def assert_published(self, phase, result, expected, **kwargs):
        path, stderr = self.publish(phase, result, **kwargs)
        self.assertEqual("", stderr)
        published = self.result_of(path)
        self.assertEqual(RESULT_KEYS, set(published))
        for key, value in expected.items():
            self.assertEqual(value, published[key], key)
        return published

    def assert_silent_no_result(self, phase, result):
        path, stderr = self.publish(phase, result)
        self.assertFalse(self.result_exists(path), result)
        self.assertEqual("", stderr, "progress is not a failed publish: nothing is reported")

    def test_draft_phase_gate_statuses(self):
        cases = [
            ({"status": "READY", "head_sha": HEAD}, dict(outcome="READY", reason="READY")),
            ({"status": "DRAFT-BLOCKED", "head_sha": HEAD, "errors": ["go test failed", "second"]},
             dict(outcome="DRAFT-BLOCKED", reason="go test failed")),
            ({"status": "WAIT-INTERRUPTED", "head_sha": HEAD, "errors": ["Explicit wait timeout reached"]},
             dict(outcome="WAIT-INTERRUPTED", reason="Explicit wait timeout reached")),
            ({"status": "ERROR", "head_sha": HEAD, "error": "boom", "errors": ["ignored"]},
             dict(outcome="ERROR", reason="boom")),
        ]
        for report, expected in cases:
            with self.subTest(status=report["status"]):
                self.assert_published("draft", report, dict(expected, head_sha=HEAD, phase="draft",
                                                            wait_kind="", person_handoff=False))

    def test_ready_phase_actor_outcomes(self):
        gate = {"head_sha": HEAD, "reasons": ["a reason"]}
        cases = [
            ({"outcome": "DRAFT-BLOCKED", "gate": gate}, dict(outcome="DRAFT", reason="a reason")),
            ({"outcome": "ENQUEUED", "gate": {"head_sha": HEAD}}, dict(outcome="ENQUEUED", reason="ENQUEUED")),
            ({"outcome": "MERGED", "head_sha": HEAD, "message": "merged by the train"},
             dict(outcome="MERGED", reason="merged by the train")),
            ({"outcome": "SKIP", "gate": {"head_sha": HEAD, "reasons": ["PR is not an open non-draft PR"]}},
             dict(outcome="SKIP", reason="PR is not an open non-draft PR")),
            ({"outcome": "ERROR", "error_kind": "GitHubError", "error": "PR state changed", "gate": gate},
             dict(outcome="ERROR", reason="PR state changed")),
        ]
        for report, expected in cases:
            with self.subTest(outcome=report["outcome"]):
                self.assert_published("ready", report, dict(expected, head_sha=HEAD, phase="ready",
                                                            wait_kind="", person_handoff=False))

    def test_ready_phase_draft_blocked_is_published_as_draft_only_in_the_ready_phase(self):
        report = {"outcome": "DRAFT-BLOCKED", "gate": {"head_sha": HEAD, "reasons": ["blocker"]}}
        self.assert_published("ready", report, dict(outcome="DRAFT"))
        # In the draft phase DRAFT-BLOCKED is already the pr-ready word and is kept as it is.
        self.assert_published("draft", {"status": "DRAFT-BLOCKED", "head_sha": HEAD, "errors": ["blocker"]},
                              dict(outcome="DRAFT-BLOCKED"))
        # The gate word `status` DRAFT is not a draft-phase completion.
        self.assert_silent_no_result("draft", {"outcome": "DRAFT", "gate": {"head_sha": HEAD}})

    def test_a_waiting_that_resolves_by_itself_is_transient_without_a_handoff(self):
        self.assert_published("ready", {"outcome": "WAITING", "wait_kind": "transient",
                                        "gate": {"head_sha": HEAD, "person_handoff": False,
                                                 "reasons": ["checks pending"]}},
                              dict(outcome="WAITING", wait_kind="transient", person_handoff=False,
                                   reason="checks pending", head_sha=HEAD))

    def test_a_waiting_for_a_person_carries_the_handoff(self):
        published = self.assert_published(
            "ready", {"outcome": "WAITING", "wait_kind": "person",
                      "gate": {"head_sha": HEAD, "person_handoff": True,
                               "reasons": ["GitHub reviewDecision is CHANGES_REQUESTED"]}},
            dict(outcome="WAITING", wait_kind="person", person_handoff=True, head_sha=HEAD,
                 reason="GitHub reviewDecision is CHANGES_REQUESTED"))
        self.assertIs(True, published["person_handoff"])

    def test_a_person_wait_without_the_gate_handoff_is_not_a_handoff(self):
        # wait_kind person alone is the merge train's catch-all, not a hand-off (apply_decision.py).
        for gate in ({"head_sha": HEAD}, {"head_sha": HEAD, "person_handoff": False},
                     {"head_sha": HEAD, "person_handoff": "true"}, {"head_sha": HEAD, "person_handoff": 1}):
            with self.subTest(gate=gate):
                self.assert_published("ready", {"outcome": "WAITING", "wait_kind": "person", "gate": gate},
                                      dict(wait_kind="person", person_handoff=False))

    def test_wait_fields_of_a_non_waiting_outcome_are_not_published(self):
        report = {"outcome": "ENQUEUED", "wait_kind": "person",
                  "gate": {"head_sha": HEAD, "person_handoff": True}}
        self.assert_published("ready", report, dict(outcome="ENQUEUED", wait_kind="", person_handoff=False))

    def test_a_handoff_the_task_cannot_express_is_reported_on_stderr_and_publishes_nothing(self):
        report = {"outcome": "WAITING", "wait_kind": "transient", "gate": {"head_sha": HEAD, "person_handoff": True}}
        path, stderr = self.publish("ready", report)
        self.assertFalse(self.result_exists(path))
        self.assertEqual(f"pr-loop result could not be published: {BAD_WAIT}\n", stderr)

    def test_progress_and_dry_run_reports_are_not_results_in_either_phase(self):
        for phase in ("draft", "ready"):
            for report in ({"status": "WAITING-CI", "head_sha": HEAD, "pending_checks": ["go test"]},
                           {"status": "GATE-PASS", "head_sha": HEAD},
                           {"outcome": "DRY_RUN_MERGE", "gate": {"head_sha": HEAD}},
                           {"outcome": "DRY_RUN_DRAFT", "gate": {"head_sha": HEAD}},
                           {"outcome": "WAITING-CI"}, {}, {"status": None}, {"status": "unknown"}):
                with self.subTest(phase=phase, report=report):
                    self.assert_silent_no_result(phase, report)

    def test_a_word_of_the_other_phase_is_not_a_result(self):
        for report in ({"status": "READY", "head_sha": HEAD}, {"status": "WAIT-INTERRUPTED", "head_sha": HEAD},
                       {"outcome": "WAIT-INTERRUPTED", "gate": {"head_sha": HEAD}}):
            with self.subTest(phase="ready", report=report):
                self.assert_silent_no_result("ready", report)
        for report in ({"outcome": "ENQUEUED", "gate": {"head_sha": HEAD}}, {"outcome": "MERGED", "head_sha": HEAD},
                       {"outcome": "SKIP", "gate": {"head_sha": HEAD}}, {"outcome": "WAITING", "gate": {}}):
            with self.subTest(phase="draft", report=report):
                self.assert_silent_no_result("draft", report)

    def test_the_result_carries_the_judged_head_not_the_head_the_task_started_with(self):
        # The PR was repaired after the driver took the task: the gate judged a newer HEAD than start_head.
        self.assertNotEqual(START, HEAD)
        reports = {
            "pr_gate top-level head_sha (draft)": ("draft", {"status": "READY", "head_sha": HEAD}),
            "actor gate head_sha (ready)": ("ready", {"outcome": "ENQUEUED", "gate": {"head_sha": HEAD}}),
            "actor top-level head_sha (ready)": ("ready", {"outcome": "MERGED", "head_sha": HEAD}),
        }
        for case, (phase, report) in reports.items():
            with self.subTest(case=case):
                published = self.assert_published(phase, report, dict(head_sha=HEAD, start_head=START))
                self.assertNotEqual(published["start_head"], published["head_sha"])

    def test_an_invalid_judged_head_is_reported_and_never_replaced_by_start_head(self):
        path, stderr = self.publish("ready", {"outcome": "ENQUEUED", "gate": {"head_sha": "not-a-sha"}})
        self.assertFalse(self.result_exists(path))
        self.assertEqual(f"pr-loop result could not be published: {BAD_RESULT}\n", stderr)

    def test_a_second_different_report_is_reported_and_the_first_result_stays(self):
        path, stderr = self.publish("draft", {"status": "DRAFT-BLOCKED", "head_sha": HEAD, "errors": ["first"]})
        self.assertEqual("", stderr)
        first = path.with_name("result.json").read_bytes()
        task = plr.load_task(path, REPO, 42, "draft")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            plr.publish_gate_result(path, task, {"status": "READY", "head_sha": HEAD})
        self.assertEqual(f"pr-loop result could not be published: {DIFFERENT}\n", stderr.getvalue())
        self.assertEqual(first, path.with_name("result.json").read_bytes())

    def test_an_identical_report_published_twice_is_silent(self):
        report = {"status": "DRAFT-BLOCKED", "head_sha": HEAD, "errors": ["same"]}
        path, _ = self.publish("draft", report)
        task = plr.load_task(path, REPO, 42, "draft")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            plr.publish_gate_result(path, task, report)
        self.assertEqual("", stderr.getvalue())


class CommandLineTests(TaskCase):
    def run_cli(self, path, *extra, repo=REPO, pr="42", phase="ready", head=HEAD, outcome="ERROR", reason="because"):
        args = [sys.executable, "-B", str(SCRIPT), "--task", str(path), "--repo", repo, "--pr", pr,
                "--phase", phase, "--head", head, "--outcome", outcome, "--reason", reason, *extra]
        return subprocess.run(args, capture_output=True, text=True, timeout=30,
                              env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))

    def setUp(self):
        super().setUp()
        self.path = self.task_file()

    def test_a_valid_invocation_publishes_the_result(self):
        proc = self.run_cli(self.path, outcome="WAITING", reason="needs a decision", head="B" * 40,
                            *("--wait-kind", "person", "--person-handoff"))
        self.assertEqual((0, "", ""), (proc.returncode, proc.stdout, proc.stderr))
        self.assertEqual(dict(task_body(), head_sha="b" * 40, outcome="WAITING", reason="needs a decision",
                              wait_kind="person", person_handoff=True), self.result_of(self.path))

    def test_the_draft_phase_vocabulary(self):
        path = self.task_file(task_body(phase="draft", nonce="2" * 32))
        proc = self.run_cli(path, phase="draft", outcome="DRAFT-BLOCKED", reason="blocked early")
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual("DRAFT-BLOCKED", self.result_of(path)["outcome"])
        other = self.run_cli(path, phase="draft", outcome="ENQUEUED")
        self.assertEqual(2, other.returncode)
        self.assertIn(BAD_RESULT, other.stderr)

    def test_a_task_that_does_not_match_is_refused_with_exit_2_and_no_result(self):
        cases = {
            "repo": dict(repo="acme/other"),
            "pr": dict(pr="43"),
            "phase": dict(phase="draft"),
        }
        for case, kwargs in cases.items():
            with self.subTest(case=case):
                proc = self.run_cli(self.path, **kwargs)
                self.assertEqual(2, proc.returncode)
                self.assertEqual(f"pr-loop result: {MISMATCH}\n", proc.stderr)
                self.assertEqual("", proc.stdout)
                self.assertFalse(self.result_exists(self.path))

    def test_a_task_in_the_wrong_place_is_refused(self):
        wrong = self.task_file(parent="elsewhere/" + NONCE)
        proc = self.run_cli(wrong)
        self.assertEqual(2, proc.returncode)
        self.assertEqual(f"pr-loop result: {LAYOUT}\n", proc.stderr)
        self.assertFalse(self.result_exists(wrong))

    def test_a_missing_task_file_is_exit_2(self):
        gone = self.root / ".pr-loop" / ("3" * 32) / "task.json"
        proc = self.run_cli(gone)
        self.assertEqual(2, proc.returncode)
        self.assertIn("pr-loop result:", proc.stderr)
        self.assertIn("No such file", proc.stderr)

    def test_an_outcome_hand_off_or_head_the_task_cannot_carry_is_refused(self):
        for kwargs, message in (
                (dict(outcome="READY"), BAD_RESULT),
                (dict(head="abc"), BAD_RESULT),
                (dict(outcome="ENQUEUED", extra=("--wait-kind", "transient")), BAD_WAIT),
                (dict(outcome="WAITING", extra=("--wait-kind", "transient", "--person-handoff")), BAD_WAIT),
                (dict(outcome="WAITING", extra=("--person-handoff",)), BAD_WAIT)):
            with self.subTest(kwargs=kwargs):
                extra = kwargs.pop("extra", ())
                proc = self.run_cli(self.path, *extra, **kwargs)
                self.assertEqual(2, proc.returncode)
                self.assertEqual(f"pr-loop result: {message}\n", proc.stderr)
                self.assertFalse(self.result_exists(self.path))

    def test_an_unknown_phase_or_wait_kind_is_an_argument_error(self):
        for extra, kwargs, needle in (((), dict(phase="review"), "--phase"),
                                      (("--wait-kind", "later"), dict(outcome="WAITING"), "--wait-kind")):
            with self.subTest(needle=needle):
                proc = self.run_cli(self.path, *extra, **kwargs)
                self.assertEqual(2, proc.returncode)
                self.assertIn("invalid choice", proc.stderr)
                self.assertIn(needle, proc.stderr)
                self.assertFalse(self.result_exists(self.path))

    def test_the_same_result_again_succeeds_and_a_different_one_is_refused(self):
        self.assertEqual(0, self.run_cli(self.path, outcome="ERROR", reason="first").returncode)
        target = self.path.with_name("result.json")
        first = target.read_bytes()
        again = self.run_cli(self.path, outcome="ERROR", reason="first")
        self.assertEqual((0, ""), (again.returncode, again.stderr))
        self.assertEqual(first, target.read_bytes())
        for kwargs in (dict(outcome="SKIP", reason="first"), dict(outcome="ERROR", reason="second"),
                       dict(outcome="ERROR", reason="first", head="b" * 40)):
            with self.subTest(kwargs=kwargs):
                different = self.run_cli(self.path, **kwargs)
                self.assertEqual(2, different.returncode)
                self.assertEqual(f"pr-loop result: {DIFFERENT}\n", different.stderr)
                self.assertEqual(first, target.read_bytes())


if __name__ == "__main__":
    unittest.main()
