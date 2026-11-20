import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts"))
import pr_loop
from pr_loop_result import write_result


class PRLoopTests(unittest.TestCase):
    def test_reuses_a_role_within_a_pr_but_restarts_it_for_the_next(self):
        view_states = {7: "ready", 8: "ready"}
        dispatched, started, closed = [], [], []
        head = "a" * 40

        def view(_repo, number):
            state = view_states[number]
            if state == "queued":
                view_states[number] = "merged"
            return dict(number=number, state="MERGED" if state == "merged" else "OPEN",
                        isDraft=state == "draft", headRefOid=head,
                        labels=[{"name": pr_loop.QUEUE_LABEL}] if state == "queued" else [])

        class Checkout:
            def __init__(self, *_):
                pass

            def verify(self):
                pass

            def task(self, _repo, _number, _phase, _head):
                return Path(tmp) / "task.json", {}

            def clean_up(self):
                pass

        class Agent:
            def __init__(self, exe, _checkout, number, phase):
                self.identity = (number, phase, exe, len(started))
                started.append(self.identity)

            def status(self):
                return False, False, "agent"

            def wait_for_prompt(self, *_args, **_kwargs):
                return True

            def submit(self, text):
                number, phase, _, _ = self.identity
                prefix = "/pr-ready" if phase == "draft" else "$pr-review-merge"
                if not text.startswith(f"{prefix} {number} --pr-loop-task="):
                    raise AssertionError(text)
                dispatched.append(self.identity)
                if phase == "draft":
                    view_states[number] = "ready"
                elif number == 7 and dispatched.count(self.identity) == 1:
                    view_states[number] = "draft"
                else:
                    view_states[number] = "queued"

            def close(self):
                closed.append(self.identity)

        args = SimpleNamespace(pr=[7, 8], dry_run=False, phase_timeout=10, startup_timeout=1,
                               max_actions=5, poll_interval=0.01, ready_agent="codex", draft_agent="claude",
                               ready_command="$pr-review-merge {pr}", draft_command="/pr-ready {pr}")
        with tempfile.TemporaryDirectory() as tmp, patch.object(pr_loop, "observe", side_effect=view), \
             patch.object(pr_loop, "Agent", Agent), patch.object(pr_loop, "Checkout", Checkout), \
             patch.object(pr_loop, "tell"), patch.object(pr_loop.time, "sleep"):
            pr_loop.Batch(pr_loop.Repo.parse("kjelly/pilot"), args).run()
        self.assertEqual([(7, "ready", "codex", 0), (7, "draft", "claude", 1), (8, "ready", "codex", 2)], started)
        self.assertEqual([started[0], started[1], started[0], started[2]], dispatched)
        self.assertEqual(started, closed)

    def test_receipt_only_blocks_the_current_dispatch_and_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.json"
            head = "a" * 40
            task = dict(version=1, repo="kjelly/pilot", pr=7, phase="draft", nonce="b" * 32, start_head=head)
            write_result(path, task, outcome="DRAFT-BLOCKED", head=head, reason="fix failed")
            pr_loop.check_result(path, task, "c" * 40)
            with self.assertRaisesRegex(pr_loop.Stop, "DRAFT-BLOCKED.*fix failed"):
                pr_loop.check_result(path, task, head)
            with self.assertRaisesRegex(pr_loop.Stop, "does not belong"):
                pr_loop.check_result(path, dict(task, nonce="d" * 32), head)

    def test_success_receipt_does_not_drive_github_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.json"
            head = "a" * 40
            task = dict(version=1, repo="kjelly/pilot", pr=7, phase="ready", nonce="b" * 32, start_head=head)
            write_result(path, task, outcome="ENQUEUED", head=head, reason="enqueued")
            self.assertIsNone(pr_loop.check_result(path, task, head))

    def test_moved_head_is_not_held_by_old_person_marker(self):
        current, new = "a" * 40, "b" * 40
        original = dict(number=7, state="OPEN", isDraft=False, labels=[{"name": "needs-person"}], headRefOid=current)
        marker = f"<!-- pr-review-merge:needs-person head={current} live-base={'c' * 40} reasons={'d' * 16} -->"
        repo = pr_loop.Repo.parse("kjelly/pilot")
        for latest in (original, dict(original, headRefOid=new)):
            with patch.object(pr_loop, "pr_view", side_effect=[original, latest]), \
                 patch.object(pr_loop, "viewer_login", return_value="reviewer"), \
                 patch.object(pr_loop, "issue_comments", return_value=[{"login": "reviewer", "body": marker}]):
                if latest["headRefOid"] == current:
                    with self.assertRaisesRegex(pr_loop.Stop, "needs a person"):
                        pr_loop.observe(repo, 7)
                else:
                    self.assertEqual(latest, pr_loop.observe(repo, 7))
