"""Merge train (kjelly/pilot#307): queue order, integration, CI wait and the outcomes.

Real Git: a bare `origin`, a developer clone that makes the commits, and the consumer's own bare
clone. The fake GitHub client reads PR HEAD, base tip, ancestry, file lists and trees from `origin`
(as GitHub would), so the review-coverage and alignment checks run for real against the merge commit
the train pushes. Only CI, labels, comments, Draft and merge are simulated.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import merge_train  # noqa: E402
import review_gate  # noqa: E402
from gh_runtime import GitHubError, Repo  # noqa: E402
from scan_stub import CleanScan  # noqa: E402
from test_gate import sample  # noqa: E402

setUpModule, tearDownModule = CleanScan.up, CleanScan.down

REPO = Repo.parse('acme/demo')
PASS = {'name': 'go test', 'bucket': 'pass', 'state': 'SUCCESS'}
PENDING = {'name': 'go test', 'bucket': 'pending', 'state': 'IN_PROGRESS'}
FAIL = {'name': 'go test', 'bucket': 'fail', 'state': 'FAILURE', 'link': 'https://ci.example/1'}


def git(path, *args):
    return subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True, check=True).stdout.strip()


class FakeGitHub:
    """GitHub as the train sees it, backed by the bare `origin` repository."""

    def __init__(self, origin):
        self.origin = origin
        self.prs = {}          # number -> {'branch', 'state', 'isDraft', 'base', 'cross', 'mergeable'}
        self.labels = {}       # number -> time the queue label was added
        self.checks = {}       # number -> list of check lists, one per poll (the last repeats)
        self.comments = []
        self.writes = []
        self.on_checks = None  # callback(number, poll) to move things between polls
        self.polls = {}
        self.merge_confirms = True

    # GitHub reads
    def head(self, number):
        return git(self.origin, 'rev-parse', 'refs/heads/' + self.prs[number]['branch'])

    def pr_view(self, repo, number):
        pr = self.prs[number]
        head = self.head(number)
        git(self.origin, 'update-ref', f'refs/pull/{number}/head', head)
        return {'number': number, 'url': f'https://github.com/acme/demo/pull/{number}', 'state': pr['state'],
                'isDraft': pr['isDraft'], 'headRefOid': head, 'headRefName': pr['branch'],
                'isCrossRepository': pr.get('cross', False), 'baseRefOid': pr['base'], 'baseRefName': 'main',
                'mergeable': pr.get('mergeable', 'MERGEABLE'),
                'mergeStateStatus': 'DIRTY' if pr.get('mergeable') == 'CONFLICTING' else 'CLEAN',
                'reviewDecision': '', 'autoMergeRequest': None}

    def branch_head(self, repo, name):
        return git(self.origin, 'rev-parse', 'refs/heads/' + name)

    def is_ancestor(self, repo, base, head):
        return subprocess.run(['git', '-C', str(self.origin), 'merge-base', '--is-ancestor', base, head]).returncode == 0

    def merge_base(self, repo, a, b):
        return git(self.origin, 'merge-base', a, b)

    def compare(self, repo, base, head):
        mb = git(self.origin, 'merge-base', base, head)
        files = [f for f in git(self.origin, 'diff', '--name-only', '--no-renames', mb, head).split('\n') if f]
        return {'files': files, 'merge_base': mb, 'ancestor': mb == base, 'status': 'ahead'}

    def tree_entries(self, repo, revision):
        out = {}
        for line in git(self.origin, 'ls-tree', '-r', '--full-tree', revision).split('\n'):
            if line:
                meta, path = line.split('\t', 1)
                mode, _, oid = meta.split()
                out[path] = (mode, oid)
        return out

    def file_at(self, repo, path, ref):
        return None  # no .github/pr-evidence.json: no target record is required

    def commit_tree(self, repo, revision):
        return git(self.origin, 'rev-parse', revision + '^{tree}')

    def pr_checks(self, repo, number):
        poll = self.polls.get(number, 0)
        self.polls[number] = poll + 1
        if self.on_checks:
            self.on_checks(number, poll)
        seq = self.checks.get(number, [[PASS]])
        return seq[min(poll, len(seq) - 1)]

    def unresolved_threads(self, repo, number):
        return 0

    def branch_rules(self, repo, branch):
        return []

    # queue
    def labeled_open_prs(self, repo, label):
        return [n for n in self.labels if self.prs[n]['state'] == 'OPEN']

    def label_added_at(self, repo, number, label):
        return self.labels.get(number)

    # writes
    def edit_label(self, repo, number, label, *, add):
        self.writes.append(('label+' if add else 'label-', number))
        if add:
            self.labels[number] = '2026-11-06T00:00:00Z'
        else:
            self.labels.pop(number, None)

    def post_comment(self, repo, number, body):
        self.writes.append(('comment', number))
        self.comments.append((number, body))

    def mark_draft(self, repo, number):
        self.writes.append(('draft', number))
        self.prs[number]['isDraft'] = True

    def merge_pr(self, repo, number, head):
        self.writes.append(('merge', number, head))
        if self.head(number) != head:
            raise GitHubError('Head branch was modified')
        if self.merge_confirms:
            self.prs[number]['state'] = 'MERGED'


class TrainTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='merge-train-')
        self.addCleanup(tmp.cleanup)
        self.t = Path(tmp.name)
        state = self.t / 'state'
        patcher = mock.patch.dict(os.environ, {'PRM_STATE_DIR': str(state), 'GIT_AUTHOR_NAME': 't',
                                               'GIT_AUTHOR_EMAIL': 't@example.org', 'GIT_COMMITTER_NAME': 't',
                                               'GIT_COMMITTER_EMAIL': 't@example.org'})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.origin = self.t / 'origin.git'
        subprocess.run(['git', 'init', '-q', '--bare', '-b', 'main', str(self.origin)], check=True)
        self.dev = self.t / 'dev'
        subprocess.run(['git', 'clone', '-q', str(self.origin), str(self.dev)], check=True,
                       capture_output=True)
        git(self.dev, 'config', 'user.email', 't@example.org')
        git(self.dev, 'config', 'user.name', 't')
        self.write('README.md', 'base\n')
        self.write('pkg/a.go', 'package a\n')
        self.fork = self.commit('fork', push='main')
        git(self.dev, 'switch', '-q', '-c', 'feature')
        self.write('pkg/a.go', 'package a // PR change\n')
        self.reviewed = self.commit('PR change', push='feature')
        self.consumer = self.t / 'train.git'
        subprocess.run(['git', 'clone', '-q', '--bare', str(self.origin), str(self.consumer)], check=True,
                       capture_output=True)
        self.gh = FakeGitHub(self.origin)
        self.gh.prs[42] = {'branch': 'feature', 'state': 'OPEN', 'isDraft': False, 'base': self.fork}

    # helpers
    def write(self, path, text):
        f = self.dev / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        git(self.dev, 'add', path)

    def commit(self, message, push=None):
        git(self.dev, 'commit', '-q', '-m', message)
        sha = git(self.dev, 'rev-parse', 'HEAD')
        if push:
            git(self.dev, 'push', '-q', 'origin', f'HEAD:refs/heads/{push}')
        return sha

    def advance_main(self, path='docs/x.md', text='main moved\n'):
        current = git(self.dev, 'branch', '--show-current')
        git(self.dev, 'fetch', '-q', 'origin')
        git(self.dev, 'switch', '-q', '--detach', 'origin/main')
        self.write(path, text)
        sha = self.commit('advance main ' + path, push='main')
        git(self.dev, 'switch', '-q', current)
        return sha

    def evidence(self, head=None):
        e = sample()
        e.update(repo='acme/demo', pr=42, head_sha=head or self.reviewed, base_sha=self.fork)
        e['tests'][0]['sha'] = head or self.reviewed
        return e

    def queue(self, number=42, head=None):
        gate = {'decision': 'MERGE', 'head_sha': head or self.reviewed, 'base_sha': self.fork,
                'live_base_sha': self.gh.branch_head(REPO, 'main')}
        return merge_train.enqueue(REPO, number, self.evidence(head), gate, client=self.gh)

    def train(self, **kw):
        clock = {'t': 0.0}

        def sleep(seconds):
            clock['t'] += max(seconds, 1)
        kw.setdefault('poll', 1)
        kw.setdefault('registration_grace', 0)
        return merge_train.Train(REPO, self.consumer, client=self.gh, sleep=sleep,
                                 monotonic=lambda: clock['t'], **kw)

    # tests
    def test_enqueue_saves_the_evidence_before_labelling_and_refuses_other_decisions(self):
        out = self.queue()
        self.assertEqual('ENQUEUED', out['outcome'])
        self.assertEqual([('label+', 42), ('comment', 42)], self.gh.writes)
        saved = merge_train.load_entry(REPO, 42)
        self.assertEqual(self.reviewed, saved['reviewed_head'])
        self.assertEqual(self.evidence(), saved['evidence'])
        self.assertEqual(0o600, merge_train.entry_path(REPO, 42).stat().st_mode & 0o777)
        with self.assertRaises(ValueError):
            merge_train.enqueue(REPO, 42, self.evidence(), {'decision': 'DRAFT', 'head_sha': self.reviewed},
                                client=self.gh)

    def test_aligned_pr_waits_for_ci_and_merges_without_a_push(self):
        self.queue()
        self.gh.checks[42] = [[PENDING], [PENDING], [PASS]]
        out = self.train().run()
        self.assertEqual(['MERGED'], [r['outcome'] for r in out['results']], out)
        self.assertEqual(self.reviewed, self.gh.head(42))
        self.assertIn(('merge', 42, self.reviewed), self.gh.writes)
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_behind_pr_gets_the_live_base_merged_in_and_the_review_still_covers_it(self):
        self.queue()
        live = self.advance_main()
        train = self.train()
        out = train.run()
        self.assertEqual(['MERGED'], [r['outcome'] for r in out['results']], out)
        head = self.gh.head(42)
        self.assertNotEqual(self.reviewed, head)
        self.assertEqual(f'{self.reviewed} {live}', git(self.origin, 'log', '-1', '--format=%P', head))
        self.assertIn(('merge', 42, head), self.gh.writes)
        # The pushed commit is a pure import: the PR's file kept its reviewed bytes, main's file came in.
        self.assertEqual('package a // PR change', git(self.origin, 'show', f'{head}:pkg/a.go'))
        self.assertEqual('main moved', git(self.origin, 'show', f'{head}:docs/x.md'))
        reuse, why = review_gate.review_covers(self.gh, REPO, self.reviewed, head, live, 'main')
        self.assertEqual('pure-base-import', reuse['method'], why)
        self.assertEqual(['docs/x.md'], reuse['changed'])

    def test_overlap_and_conflict_return_the_pr_to_draft_without_a_push(self):
        for case in ('overlap', 'conflict'):
            with self.subTest(case=case):
                self.setUp()
                self.queue()
                if case == 'overlap':
                    self.advance_main('pkg/a.go', 'package a // main change\n')
                else:
                    self.advance_main()
                    self.gh.prs[42]['mergeable'] = 'CONFLICTING'
                out = self.train().run()
                self.assertEqual(['DRAFTED'], [r['outcome'] for r in out['results']], out)
                self.assertEqual(self.reviewed, self.gh.head(42), 'nothing was pushed')
                self.assertEqual(['comment', 'label-', 'draft'], [w[0] for w in self.gh.writes[2:]])
                body = self.gh.comments[-1][1]
                self.assertIn('Draft required', body)
                self.assertIn('pr-ready', body)
                self.assertIn('both sides changed pkg/a.go' if case == 'overlap' else 'merge conflict', body)
                self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_a_merge_that_is_not_a_pure_import_is_never_pushed(self):
        # GitHub's file lists miss the overlap: both sides edit pkg/long.go far apart, so Git merges it
        # cleanly. The train's own per-file check against the base still refuses the push.
        lines = [f'line {i}' for i in range(30)]
        self.advance_main('pkg/long.go', '\n'.join(lines) + '\n')
        git(self.dev, 'fetch', '-q', 'origin')
        git(self.dev, 'merge', '-q', '--no-edit', 'origin/main')
        self.write('pkg/long.go', '\n'.join(['PR first line'] + lines[1:]) + '\n')
        self.reviewed = self.commit('PR edits the first line', push='feature')
        self.queue()
        self.advance_main('pkg/long.go', '\n'.join(lines[:-1] + ['main last line']) + '\n')
        real = self.gh.compare
        self.gh.compare = lambda repo, base, head: dict(
            real(repo, base, head), files=[f for f in real(repo, base, head)['files'] if f != 'pkg/long.go'])
        out = self.train().run()
        self.assertEqual('DRAFTED', out['results'][0]['outcome'], out)
        self.assertIn('changes pkg/long.go differently from main', self.gh.comments[-1][1])
        self.assertEqual(self.reviewed, self.gh.head(42), 'nothing was pushed')

    def test_failed_ci_on_the_integrated_head_drafts(self):
        self.queue()
        self.advance_main()
        self.gh.checks[42] = [[FAIL]]
        out = self.train().run()
        self.assertEqual(['DRAFTED'], [r['outcome'] for r in out['results']], out)
        self.assertIn('go test is fail', self.gh.comments[-1][1])
        self.assertFalse(any(w[0] == 'merge' for w in self.gh.writes))

    def test_ci_timeout_and_unknown_mergeability_keep_the_pr_queued(self):
        self.queue()
        self.gh.checks[42] = [[PENDING]]
        out = self.train(ci_timeout=5).run()
        self.assertEqual(['WAITING'], [r['outcome'] for r in out['results']])
        self.assertIn(42, self.gh.labels)
        self.assertIsNotNone(merge_train.load_entry(REPO, 42))
        self.advance_main()
        self.gh.prs[42]['mergeable'] = 'UNKNOWN'
        out = self.train(max_align=2).run()
        self.assertEqual('WAITING', out['results'][0]['outcome'])
        self.assertIn("'UNKNOWN'", out['results'][0]['reason'])
        self.assertIn(42, self.gh.labels)

    def test_base_moving_during_ci_is_integrated_again_up_to_the_limit(self):
        self.queue()
        moves = []

        def move(number, poll):
            if poll == 0:
                moves.append(self.advance_main(f'docs/m{len(moves)}.md'))
        self.gh.on_checks = move
        self.gh.checks[42] = [[PENDING], [PASS]]
        out = self.train().run()
        self.assertEqual(['MERGED'], [r['outcome'] for r in out['results']], out)
        head = self.gh.head(42)
        self.assertEqual(moves[0], git(self.origin, 'log', '-1', '--format=%P', head).split()[1])
        # A base that never stops moving exhausts the integrations and keeps the PR enqueued.
        self.setUp()
        self.queue()
        self.gh.on_checks = lambda number, poll: self.advance_main(f'docs/n{poll}.md')
        self.gh.checks[42] = [[PENDING]]
        out = self.train(max_align=2).run()
        self.assertEqual('WAITING', out['results'][0]['outcome'], out)
        self.assertIn('moved 2 times', out['results'][0]['reason'])
        self.assertIn(42, self.gh.labels)

    def test_head_changed_outside_the_train_or_stale_review_leaves_the_queue(self):
        self.queue()

        def push(number, poll):
            if poll == 0:
                self.write('pkg/b.go', 'package b\n')
                self.commit('PR change after the review', push='feature')
        self.gh.on_checks = push
        self.gh.checks[42] = [[PENDING], [PASS]]
        out = self.train().run()
        self.assertEqual('DEQUEUED', out['results'][0]['outcome'], out)
        self.assertIn('HEAD changed outside the merge train', out['results'][0]['reason'])
        self.assertNotIn(42, self.gh.labels)
        # Enqueued at an older HEAD: after the train integrates main, the delta since the review still
        # holds a PR-side change, which is not a base import.
        self.setUp()
        self.write('pkg/b.go', 'package b\n')
        self.commit('PR change after the review', push='feature')
        self.queue(head=self.reviewed)
        self.advance_main()
        out = self.train().run()
        self.assertEqual('DEQUEUED', out['results'][0]['outcome'], out)
        self.assertIn('no longer covers', out['results'][0]['reason'])
        self.assertIn('neither evidence-only nor a pure base import: pkg/b.go', out['results'][0]['reason'])
        self.assertFalse(any(w[0] == 'merge' for w in self.gh.writes))

    def test_target_record_that_stops_covering_head_drafts(self):
        self.queue()
        self.advance_main()
        with mock.patch.object(review_gate, 'check_target_validation',
                               return_value=(['the run at cccc does not cover HEAD (rerun_paths: internal/x.go)'], {})):
            out = self.train().run()
        self.assertEqual('DRAFTED', out['results'][0]['outcome'], out)
        self.assertIn('target record no longer covers HEAD', self.gh.comments[-1][1])

    def test_entries_the_train_cannot_handle_leave_the_queue(self):
        # No saved evidence on this host.
        self.gh.labels[42] = '2026-11-06T00:00:00Z'
        out = self.train().run()
        self.assertEqual('DEQUEUED', out['results'][0]['outcome'])
        self.assertIn('no saved review evidence', out['results'][0]['reason'])
        # A fork PR.
        self.queue()
        self.gh.prs[42]['cross'] = True
        out = self.train().run()
        self.assertEqual('DEQUEUED', out['results'][0]['outcome'])
        self.assertIn('only to branches of this repository', out['results'][0]['reason'])
        # A Draft leaves silently.
        self.gh.prs[42]['cross'] = False
        self.queue()
        self.gh.prs[42]['isDraft'] = True
        before = len(self.gh.comments)
        out = self.train().run()
        self.assertEqual('DEQUEUED', out['results'][0]['outcome'])
        self.assertEqual(before, len(self.gh.comments))

    def test_unconfirmed_merge_is_an_error_and_stops_the_run(self):
        self.queue()
        self.gh.merge_confirms = False
        out = self.train().run()
        self.assertEqual('ERROR', out['results'][0]['outcome'])
        self.assertIn('not confirmed MERGED', out['results'][0]['reason'])

    def test_queue_order_is_the_label_time_and_a_stop_keeps_the_rest_queued(self):
        self.gh.prs[43] = {'branch': 'other', 'state': 'OPEN', 'isDraft': False, 'base': self.fork}
        git(self.dev, 'switch', '-q', '-c', 'other', self.fork)
        self.write('pkg/c.go', 'package c\n')
        other = self.commit('other PR', push='other')
        self.queue(42)
        merge_train.enqueue(REPO, 43, dict(self.evidence(other), pr=43),
                            {'decision': 'MERGE', 'head_sha': other, 'base_sha': self.fork,
                             'live_base_sha': self.fork}, client=self.gh)
        self.gh.labels.update({42: '2026-11-06T02:00:00Z', 43: '2026-11-06T01:00:00Z'})
        self.assertEqual([43, 42], self.train().order())
        self.gh.checks[43] = [[PENDING]]
        out = self.train(ci_timeout=3).run()
        self.assertEqual([(43, 'WAITING')], [(r['pr'], r['outcome']) for r in out['results']])
        self.assertIn(42, self.gh.labels)

    def test_a_single_item_run_handles_only_the_selected_pr_at_the_head(self):
        self.gh.prs[43] = {'branch': 'other', 'state': 'OPEN', 'isDraft': False, 'base': self.fork}
        git(self.dev, 'switch', '-q', '-c', 'other', self.fork)
        self.write('pkg/c.go', 'package c\n')
        other = self.commit('other PR', push='other')
        self.queue(42)
        merge_train.enqueue(REPO, 43, dict(self.evidence(other), pr=43),
                            {'decision': 'MERGE', 'head_sha': other, 'base_sha': self.fork,
                             'live_base_sha': self.fork}, client=self.gh)
        self.gh.labels.update({42: '2026-11-06T02:00:00Z', 43: '2026-11-06T01:00:00Z'})
        out = self.train().run(only=42)
        self.assertEqual(('NOT_AT_HEAD', [43, 42], []), (out['status'], out['queue'], out['results']))
        self.assertFalse(any(w[0] in ('merge', 'draft') for w in self.gh.writes))
        out = self.train().run(only=43)
        self.assertEqual([(43, 'MERGED')], [(r['pr'], r['outcome']) for r in out['results']])
        self.assertEqual('OPEN', self.gh.prs[42]['state'], 'the other PR is left to the timer')

    def test_one_consumer_per_repository(self):
        with merge_train.consumer_lock(REPO) as first:
            self.assertTrue(first)
            with merge_train.consumer_lock(REPO) as second:
                self.assertFalse(second)
        with merge_train.consumer_lock(REPO) as again:
            self.assertTrue(again)


if __name__ == '__main__':
    unittest.main()
