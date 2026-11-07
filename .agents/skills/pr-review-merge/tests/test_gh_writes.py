"""The real `gh_runtime` write wrappers, as the actor and the merge train call them (kjelly/pilot#307).

`run_gh` is replaced, so each test sees the exact `gh` argv. The train's tests use a fake client and never
reach these wrappers; without these, a merge without `--match-head-commit`, or one with `--admin`, would
pass every other test.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import gh_runtime  # noqa: E402
from gh_runtime import Repo  # noqa: E402

REPO = Repo.parse('acme/demo')
SHA = 'a' * 40


class Recorder:
    """A `run_gh` stand-in: remembers every argv and what the `--body-file` held when gh would have read it."""

    def __init__(self, stdout=''):
        self.calls, self.bodies, self.stdout = [], [], stdout

    def __call__(self, args, *, input_text=None, check=True):
        self.calls.append(list(args))
        if '--body-file' in args:
            self.bodies.append(Path(args[args.index('--body-file') + 1]).read_text(encoding='utf-8'))
        return subprocess.CompletedProcess(['gh', *args], 0, self.stdout, '')


class WriteWrapperTests(unittest.TestCase):
    def run_wrapper(self, fn, *args, **kwargs):
        rec = Recorder()
        with mock.patch.object(gh_runtime, 'run_gh', rec):
            fn(REPO, *args, **kwargs)
        self.assertEqual(1, len(rec.calls), rec.calls)
        return rec

    def test_merge_pins_the_head_commit_and_never_bypasses_protection_or_waits_for_auto_merge(self):
        rec = self.run_wrapper(gh_runtime.merge_pr, 7, SHA)
        self.assertEqual(['pr', 'merge', '7', '-R', 'acme/demo', '--merge', '--match-head-commit', SHA], rec.calls[0])
        for flag in ('--admin', '--auto', '--squash', '--rebase', '--delete-branch', '--body', '--subject'):
            self.assertNotIn(flag, rec.calls[0])

    def test_labels_are_added_and_removed_by_name_on_the_given_pr(self):
        add = self.run_wrapper(gh_runtime.edit_label, 7, 'merge-queue', add=True)
        self.assertEqual(['pr', 'edit', '7', '-R', 'acme/demo', '--add-label', 'merge-queue'], add.calls[0])
        remove = self.run_wrapper(gh_runtime.edit_label, 7, 'merge-queue', add=False)
        self.assertEqual(['pr', 'edit', '7', '-R', 'acme/demo', '--remove-label', 'merge-queue'], remove.calls[0])

    def test_a_comment_is_posted_from_a_file_that_holds_the_body_and_is_removed_after(self):
        body = '## Merge train: enqueued\n\nText with `backticks`, $dollars and "quotes".\n'
        rec = self.run_wrapper(gh_runtime.post_comment, 7, body)
        argv = rec.calls[0]
        self.assertEqual(['pr', 'comment', '7', '-R', 'acme/demo', '--body-file'], argv[:6])
        self.assertEqual([body], rec.bodies)
        self.assertFalse(Path(argv[6]).exists(), 'the temporary body file is removed')

    def test_mark_draft_is_the_ready_undo(self):
        rec = self.run_wrapper(gh_runtime.mark_draft, 7)
        self.assertEqual(['pr', 'ready', '7', '-R', 'acme/demo', '--undo'], rec.calls[0])

    def test_a_host_qualified_repository_is_passed_whole_to_every_write(self):
        repo = Repo.parse('ghe.example.com/acme/demo')
        rec = Recorder()
        with mock.patch.object(gh_runtime, 'run_gh', rec):
            gh_runtime.merge_pr(repo, 7, SHA)
            gh_runtime.edit_label(repo, 7, 'merge-queue', add=True)
            gh_runtime.mark_draft(repo, 7)
        self.assertEqual(['ghe.example.com/acme/demo'] * 3, [call[call.index('-R') + 1] for call in rec.calls])

    def test_pr_view_asks_for_the_labels_the_train_re_checks(self):
        view = {'number': 7, 'labels': [{'name': 'merge-queue'}]}
        rec = Recorder(json.dumps(view))
        with mock.patch.object(gh_runtime, 'run_gh', rec):
            self.assertEqual(view, gh_runtime.pr_view(REPO, 7))
        fields = rec.calls[0][rec.calls[0].index('--json') + 1].split(',')
        self.assertIn('labels', fields)
        for needed in ('state', 'isDraft', 'headRefOid', 'baseRefName', 'headRefName', 'isCrossRepository'):
            self.assertIn(needed, fields)


if __name__ == '__main__':
    unittest.main()
