"""Merge train (kjelly/pilot#307): queue order, integration, CI wait and the outcomes.

Real Git: a bare `origin`, a developer clone that makes the commits, and the consumer's own bare
clone. The fake GitHub client reads PR HEAD, base tip, ancestry, file lists and trees from `origin`
(as GitHub would), so the review-coverage and alignment checks run for real against the merge commit
the train pushes. Only CI, labels, comments, Draft and merge are simulated.
"""
import contextlib
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
from gh_runtime import CompareLimitError, GitHubError, Repo  # noqa: E402
from scan_stub import CleanScan  # noqa: E402
from test_gate import sample  # noqa: E402

# The real scanner, taken before the module-wide clean-scan stub starts (setUpModule below).
REAL_CHECK_SECRETS = review_gate.check_secrets
setUpModule, tearDownModule = CleanScan.up, CleanScan.down

REPO = Repo.parse('acme/demo')
# A base manifest that requires an actual-run record for playbook changes (and declares evidence-only paths).
MANIFEST = json.dumps({'schema_version': 1, 'evidence_only_paths': ['docs/evidence/**'],
                       'required_evidence': [{'id': 'actual-run', 'kind': 'target-run',
                                              'source': 'AGENTS.md section 1.4',
                                              'artifact_glob': 'docs/evidence/**/*.md',
                                              'required_paths': ['playbooks/**']}]})
NOT_NEEDED = {'decision': 'not-needed', 'reason': 'The PR changes only pkg/, which no playbook or contract reads.'}
PASS = {'name': 'go test', 'bucket': 'pass', 'state': 'SUCCESS'}
PENDING = {'name': 'go test', 'bucket': 'pending', 'state': 'IN_PROGRESS'}
FAIL = {'name': 'go test', 'bucket': 'fail', 'state': 'FAILURE', 'link': 'https://ci.example/1'}


def git(path, *args):
    return subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True, check=True).stdout.strip()


class FakeGitHub:
    """GitHub as the train sees it, backed by the bare `origin` repository."""

    def __init__(self, origin):
        self.origin = origin
        self.prs = {}          # number -> {'branch', 'state', 'isDraft', 'base', 'base_name', 'cross', 'mergeable'}
        self.labels = {}       # number -> time the queue label was added
        self.checks = {}       # number -> list of check lists, one per poll (the last repeats)
        self.comments = []
        self.writes = []
        self.on_checks = None  # callback(number, poll) to move things between polls
        self.polls = {}
        self.merge_confirms = True
        self.failing = {}      # method name -> exception raised by it (an outage of that one call)
        self.fail_from = {}    # method name -> first call (1-based) that fails; absent: every call
        self.counts = {}
        self.pull_ref = {}     # number -> commit refs/pull/<n>/head shows (GitHub lags the branch)
        self.manifest = None   # text of .github/pr-evidence.json at every revision, or None (absent)
        self.rules = []

    def outage(self, name):
        self.counts[name] = self.counts.get(name, 0) + 1
        if name in self.failing and self.counts[name] >= self.fail_from.get(name, 1):
            raise self.failing[name]

    # GitHub reads
    def head(self, number):
        return git(self.origin, 'rev-parse', 'refs/heads/' + self.prs[number]['branch'])

    def pr_view(self, repo, number):
        pr = self.prs[number]
        head = self.head(number)
        git(self.origin, 'update-ref', f'refs/pull/{number}/head', self.pull_ref.get(number, head))
        return {'number': number, 'url': f'https://github.com/acme/demo/pull/{number}', 'state': pr['state'],
                'isDraft': pr['isDraft'], 'headRefOid': head, 'headRefName': pr['branch'],
                'isCrossRepository': pr.get('cross', False), 'baseRefOid': pr['base'],
                'baseRefName': pr.get('base_name', 'main'),
                'mergeable': pr.get('mergeable', 'MERGEABLE'),
                'mergeStateStatus': pr.get('merge_state') or (
                    'DIRTY' if pr.get('mergeable') == 'CONFLICTING' else 'CLEAN'),
                'reviewDecision': pr.get('review', ''), 'autoMergeRequest': None,
                'labels': [{'name': 'merge-queue'}] if number in self.labels else []}

    def branch_head(self, repo, name):
        return git(self.origin, 'rev-parse', 'refs/heads/' + name)

    def is_ancestor(self, repo, base, head):
        self.outage('is_ancestor')
        return subprocess.run(['git', '-C', str(self.origin), 'merge-base', '--is-ancestor', base, head]).returncode == 0

    def merge_base(self, repo, a, b):
        return git(self.origin, 'merge-base', a, b)

    def compare(self, repo, base, head):
        self.outage('compare')
        mb = git(self.origin, 'merge-base', base, head)
        files = [f for f in git(self.origin, 'diff', '--name-only', '--no-renames', mb, head).split('\n') if f]
        return {'files': files, 'merge_base': mb, 'ancestor': mb == base, 'status': 'ahead'}

    def tree_entries(self, repo, revision):
        self.outage('tree_entries')
        out = {}
        for line in git(self.origin, 'ls-tree', '-r', '--full-tree', revision).split('\n'):
            if line:
                meta, path = line.split('\t', 1)
                mode, _, oid = meta.split()
                out[path] = (mode, oid)
        return out

    def file_at(self, repo, path, ref):
        self.outage('file_at')
        if path == '.github/pr-evidence.json' and self.manifest is not None:
            return self.manifest.encode()
        return None  # no .github/pr-evidence.json (the default): no target record is required

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
        self.outage('unresolved_threads')
        return 0

    def branch_rules(self, repo, branch):
        return self.rules

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


class TrainHarness(unittest.TestCase):
    """A repository with one open PR (#42: a feature branch forked from main), a consumer clone, a fake
    GitHub, and the helpers the tests share. It has no tests of its own."""

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

    def queue(self, number=42, head=None, gate_head=None, **evidence_changes):
        """Enqueue as `apply_decision` does: the evidence names `head`; the gate decided MERGE for
        `gate_head` (the same commit unless the review covers a later HEAD by a pure import)."""
        gate = {'decision': 'MERGE', 'head_sha': gate_head or head or self.reviewed, 'base_sha': self.fork,
                'live_base_sha': self.gh.branch_head(REPO, 'main')}
        return merge_train.enqueue(REPO, number, dict(self.evidence(head), **evidence_changes), gate, client=self.gh)

    def second_pr(self, number=43, start=None):
        """A second healthy PR (adds pkg/c.go on a branch from the fork, or from `start`), enqueued after #42."""
        branch = 'other' if number == 43 else f'other{number}'
        self.gh.prs[number] = {'branch': branch, 'state': 'OPEN', 'isDraft': False, 'base': self.fork}
        git(self.dev, 'switch', '-q', '-c', branch, start or self.fork)
        self.write(f'pkg/c{number}.go', 'package c\n')
        head = self.commit(f'PR {number}', push=branch)
        git(self.dev, 'switch', '-q', 'feature')
        gate = {'decision': 'MERGE', 'head_sha': head, 'base_sha': self.fork,
                'live_base_sha': self.gh.branch_head(REPO, 'main')}
        merge_train.enqueue(REPO, number, dict(self.evidence(head), pr=number), gate, client=self.gh)
        return head

    def lock_hook(self, action):
        """A mutation lock that runs `action` as it is first taken: the moment between a check made before
        the lock and the guarded write, when someone else may act."""
        calls = []

        @contextlib.contextmanager
        def lock(repo):
            if not calls:
                calls.append(1)
                action()
            yield
        return lock

    def train(self, **kw):
        clock = {'t': 0.0}

        def sleep(seconds):
            clock['t'] += max(seconds, 1)
        kw.setdefault('poll', 1)
        kw.setdefault('registration_grace', 0)
        return merge_train.Train(REPO, self.consumer, client=self.gh, sleep=sleep,
                                 monotonic=lambda: clock['t'], **kw)



class TrainTests(TrainHarness):
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
                # Draft first, then the label: a PR that was not converted keeps its place in the queue.
                self.assertEqual(['comment', 'draft', 'label-'], [w[0] for w in self.gh.writes[2:]])
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
        # The gate decided MERGE for a HEAD the evidence does not name (a review covers it only by a pure
        # import): after the train integrates main, the delta since the review still holds a PR-side
        # change, which is not a base import.
        self.setUp()
        self.write('pkg/b.go', 'package b\n')
        later = self.commit('PR change after the review', push='feature')
        self.queue(head=self.reviewed, gate_head=later)
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
        # Only a verified MERGED forgets the PR: an unconfirmed merge stays enqueued, and counted.
        self.assertEqual(1, merge_train.load_entry(REPO, 42)['errors'])
        self.assertIn(42, self.gh.labels)

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


class DeliveryTests(TrainHarness):
    """Helpers for the tests below that act as other people on the PR branch."""

    def push_to_pr(self, path='pkg/b.go', text='package b\n'):
        """Someone pushes a commit to the PR branch (the developer clone sits on `feature`)."""
        self.write(path, text)
        return self.commit('push to the PR branch', push='feature')

    def merge_main_keeping_ours(self, conflict_file=None):
        """The author merges main into the PR branch and keeps the PR's side of what main changed."""
        git(self.dev, 'fetch', '-q', 'origin')
        if conflict_file:
            merge = subprocess.run(['git', '-C', str(self.dev), 'merge', '--no-edit', 'origin/main'],
                                   capture_output=True, text=True)
            self.assertNotEqual(0, merge.returncode, 'the merge was supposed to conflict')
            git(self.dev, 'checkout', '--ours', conflict_file)
            git(self.dev, 'add', conflict_file)
            git(self.dev, 'commit', '-q', '--no-edit')
        else:
            git(self.dev, 'merge', '-q', '-s', 'ours', '--no-edit', 'origin/main')
        git(self.dev, 'push', '-q', 'origin', 'HEAD:refs/heads/feature')
        return git(self.dev, 'rev-parse', 'HEAD')

    def merge_main(self):
        """The author merges main into the PR branch the ordinary way."""
        git(self.dev, 'fetch', '-q', 'origin')
        git(self.dev, 'merge', '-q', '--no-edit', 'origin/main')
        git(self.dev, 'push', '-q', 'origin', 'HEAD:refs/heads/feature')
        return git(self.dev, 'rev-parse', 'HEAD')

    def pushes(self, train):
        """Record every `git push` the train runs (and still run it)."""
        seen, real = [], train.git

        def git_spy(*args, **kw):
            if args and args[0] == 'push':
                seen.append(args)
            return real(*args, **kw)
        train.git = git_spy
        return seen

    def merges(self):
        return [w for w in self.gh.writes if w[0] == 'merge']

    def quiet_after_enqueue(self):
        """Nothing was written to the PR after the enqueue's label and comment."""
        return self.gh.writes[2:] == [] and len(self.gh.comments) == 1


class BindingTests(DeliveryTests):
    """The train acts only on a HEAD the gate decided on or the train built (kjelly/pilot#307)."""

    def test_a_merge_that_keeps_the_pr_side_is_refused_by_the_gate_and_never_merged(self):
        cases = (('merge -s ours', None, 'docs/x.md'), ('conflict resolved with --ours', 'pkg/a.go', 'pkg/a.go'))
        for name, conflict, dropped in cases:
            for manifest in (None, MANIFEST):
                with self.subTest(case=name, manifest=bool(manifest)):
                    self.setUp()
                    self.gh.manifest = manifest
                    self.queue()                                  # reviewed and gated at the PR's first commit
                    if conflict:
                        self.advance_main('pkg/a.go', 'package a // main change\n')
                    live = self.advance_main('docs/x.md')
                    head = self.merge_main_keeping_ours(conflict)
                    self.assertEqual(self.reviewed, git(self.origin, 'rev-parse', head + '^1'))
                    self.assertEqual(live, git(self.origin, 'rev-parse', head + '^2'))
                    # The gate (the same call the Ready gate and the final gate make): main's change is gone.
                    reuse, why = review_gate.review_covers(self.gh, REPO, self.reviewed, head, live, 'main')
                    self.assertIsNone(reuse)
                    self.assertIn('base change not carried into HEAD: ' + dropped, why)
                    gate = review_gate.evaluate(REPO, 42, self.evidence(), client=self.gh, worktree=self.consumer)
                    self.assertEqual('WAITING', gate['decision'], gate['reasons'])
                    self.assertIn('base change not carried into HEAD: ' + dropped, ' '.join(gate['reasons']))
                    self.assertEqual('person', gate['wait_kind'])
                    # The train: that HEAD was never gated for the merge, so it leaves the queue and nothing is pushed.
                    train = self.train()
                    pushes = self.pushes(train)
                    out = train.run()
                    self.assertEqual('DEQUEUED', out['results'][0]['outcome'], out)
                    self.assertIn('HEAD changed since it was enqueued', out['results'][0]['reason'])
                    self.assertEqual((head, [], []), (self.gh.head(42), pushes, self.merges()))

    def test_a_saved_review_that_does_not_cover_the_enqueued_head_is_not_merged_either(self):
        # Defense in depth: even when the entry names the keep-ours HEAD (a gate that predates the base-side
        # check passed it), the train's own check of the saved review refuses the merge.
        for manifest in (None, MANIFEST):
            with self.subTest(manifest=bool(manifest)):
                self.setUp()
                self.gh.manifest = manifest
                self.queue()
                self.advance_main('pkg/a.go', 'package a // main change\n')
                self.advance_main('docs/x.md')
                head = self.merge_main_keeping_ours('pkg/a.go')
                self.queue(gate_head=head)             # the entry is replaced; the PR graph is kept
                out = self.train().run()
                self.assertEqual('DEQUEUED', out['results'][0]['outcome'], out)
                self.assertIn('no longer covers HEAD', out['results'][0]['reason'])
                self.assertIn('base change not carried into HEAD: pkg/a.go', out['results'][0]['reason'])
                self.assertEqual([], self.merges())

    def test_a_push_after_the_enqueue_leaves_the_queue_with_nothing_pushed(self):
        self.queue()
        self.advance_main()
        external = self.push_to_pr()
        train = self.train()
        pushes = self.pushes(train)
        out = train.run()
        self.assertEqual('DEQUEUED', out['results'][0]['outcome'], out)
        self.assertIn('HEAD changed since it was enqueued; run `pr-review-merge` again', out['results'][0]['reason'])
        self.assertEqual((external, [], []), (self.gh.head(42), pushes, self.merges()))
        self.assertNotIn(42, self.gh.labels)
        self.assertIsNone(merge_train.load_entry(REPO, 42))
        self.assertEqual('Merge train: left the queue', self.gh.comments[-1][1].splitlines()[0][3:])

    def test_the_head_is_checked_again_when_the_final_gate_runs(self):
        # A push lands while CI runs on an aligned PR: wait_ci notices; one that lands after wait_ci
        # settled (before finish) is caught by finish's own check.
        self.queue()
        original = merge_train.Train.wait_ci

        def settle_then_push(train, *args):
            state = original(train, *args)
            self.push_to_pr()
            return state
        with mock.patch.object(merge_train.Train, 'wait_ci', settle_then_push):
            out = self.train().run()
        self.assertEqual('DEQUEUED', out['results'][0]['outcome'], out)
        self.assertIn('HEAD changed since it was enqueued', out['results'][0]['reason'])
        self.assertEqual([], self.merges())

    def test_commits_the_train_pushes_are_recorded_before_and_accepted_after(self):
        self.queue()
        self.advance_main()
        seen = []
        self.gh.on_checks = lambda number, poll: seen.append(merge_train.load_entry(REPO, 42)['train_commits'])
        out = self.train().run()
        self.assertEqual(['MERGED'], [r['outcome'] for r in out['results']], out)
        self.assertEqual([self.gh.head(42)], seen[0])
        self.assertNotEqual(self.reviewed, seen[0][0])

    def test_a_crash_between_the_record_and_the_push_leaves_a_harmless_entry(self):
        self.queue()
        self.advance_main()
        train = self.train()
        real = train.git

        def refuse_push(*args, **kw):
            if args[0] == 'push':
                raise merge_train.TrainError('git push failed (1): remote: permission denied')
            return real(*args, **kw)
        train.git = refuse_push
        out = train.run()
        self.assertEqual('ERROR', out['results'][0]['outcome'], out)
        entry = merge_train.load_entry(REPO, 42)
        self.assertEqual([], entry['train_commits'], 'a commit that never landed is not kept')
        self.assertEqual(1, entry['errors'])
        self.assertEqual(self.reviewed, self.gh.head(42))

    def test_enqueue_records_both_heads_and_the_comment_names_the_reviewed_one(self):
        later = self.push_to_pr()
        self.queue(head=self.reviewed, gate_head=later)
        saved = merge_train.load_entry(REPO, 42)
        self.assertEqual((self.reviewed, later, []), (saved['reviewed_head'], saved['enqueued_head'], saved['train_commits']))
        body = self.gh.comments[-1][1]
        self.assertIn(f'Reviewed HEAD: `{self.reviewed}`', body)
        self.assertIn(f'HEAD when enqueued: `{later}`', body)
        self.setUp()
        self.queue()
        body = self.gh.comments[-1][1]
        self.assertIn(f'Reviewed HEAD: `{self.reviewed}`', body)
        self.assertNotIn('HEAD when enqueued', body)

    def test_enqueue_needs_evidence_that_names_a_reviewed_head_and_old_entries_are_not_trusted(self):
        gate = {'decision': 'MERGE', 'head_sha': self.reviewed, 'base_sha': self.fork, 'live_base_sha': self.fork}
        for bad in ({'head_sha': 'abc'}, {'head_sha': None}):
            with self.assertRaises(ValueError):
                merge_train.enqueue(REPO, 42, dict(self.evidence(), **bad), gate, client=self.gh)
        self.queue()
        path = merge_train.entry_path(REPO, 42)
        entry = json.loads(path.read_text())
        for field in ('enqueued_head', 'train_commits', 'entry_id'):
            broken = {k: v for k, v in entry.items() if k != field}
            path.write_text(json.dumps(broken))
            self.assertIsNone(merge_train.load_entry(REPO, 42), field)
        path.write_text(json.dumps(dict(entry, train_commits=['not-a-sha'])))
        self.assertIsNone(merge_train.load_entry(REPO, 42))
        for bad_id in ('', 'abc', 42, 'g' * 32):
            path.write_text(json.dumps(dict(entry, entry_id=bad_id)))
            self.assertIsNone(merge_train.load_entry(REPO, 42), bad_id)


class FetchTests(DeliveryTests):
    """Every processing attempt fetches the PR head and the base, aligned PRs included."""

    def clone_without_the_pr(self):
        """The consumer's clone as it was before the PR branch existed (main only)."""
        stale = self.t / 'stale.git'
        subprocess.run(['git', 'clone', '-q', '--bare', '--no-local', '--single-branch', '-b', 'main', str(self.origin), str(stale)],
                       check=True, capture_output=True)
        missing = subprocess.run(['git', '-C', str(stale), 'cat-file', '-e', self.reviewed + '^{commit}'], capture_output=True)
        self.assertNotEqual(0, missing.returncode, 'the stale clone must not hold the PR commit')
        return stale

    def test_an_aligned_pr_merges_with_a_clone_that_never_saw_its_branch_under_the_real_secret_scan(self):
        stale = self.clone_without_the_pr()
        self.queue()
        train = self.train()
        train.worktree = stale
        self.assertIsNot(review_gate.check_secrets, REAL_CHECK_SECRETS, 'the module stub is expected to be active')
        with mock.patch.object(review_gate, 'check_secrets', REAL_CHECK_SECRETS):
            out = train.run()
        self.assertEqual(['MERGED'], [r['outcome'] for r in out['results']], out)
        self.assertEqual(self.reviewed, git(stale, 'rev-parse', f'refs/merge-train/pr/42'))

    def test_a_behind_pr_still_merges_with_that_clone(self):
        stale = self.clone_without_the_pr()
        self.queue()
        self.advance_main()
        train = self.train()
        train.worktree = stale
        with mock.patch.object(review_gate, 'check_secrets', REAL_CHECK_SECRETS):
            out = train.run()
        self.assertEqual(['MERGED'], [r['outcome'] for r in out['results']], out)

    def test_a_pull_ref_that_lags_the_pr_head_waits_and_then_merges(self):
        self.queue()
        self.gh.pull_ref[42] = self.fork          # GitHub has not moved refs/pull/42/head yet
        out = self.train().run()
        self.assertEqual('WAITING', out['results'][0]['outcome'], out)
        self.assertIn('has not updated refs/pull/42/head', out['results'][0]['reason'])
        self.assertEqual([], self.merges())
        self.assertIn(42, self.gh.labels)
        del self.gh.pull_ref[42]
        out = self.train().run()
        self.assertEqual(['MERGED'], [r['outcome'] for r in out['results']], out)


class LabelTests(DeliveryTests):
    """Removing the merge-queue label withdraws a PR at every step: nothing is written to it."""

    def assertWithdrawn(self, out, number=42):
        result = next(r for r in out['results'] if r['pr'] == number)
        self.assertEqual('DEQUEUED', result['outcome'], out)
        self.assertIn('label was removed', result['reason'])
        self.assertIsNone(merge_train.load_entry(REPO, number))
        self.assertEqual([], [m for m in self.merges() if m[1] == number])
        self.assertEqual([], [w for w in self.gh.writes if w[1] == number and w[0] in ('draft', 'label-')])
        self.assertEqual(1, len([c for c in self.gh.comments if c[0] == number]), 'only the enqueue comment')

    def test_label_removed_while_ci_runs_cancels_the_merge(self):
        self.queue()
        self.gh.checks[42] = [[PENDING], [PENDING], [PASS]]
        self.gh.on_checks = lambda number, poll: self.gh.labels.pop(42, None) if poll == 1 else None
        out = self.train().run()
        self.assertWithdrawn(out)
        self.assertEqual(2, self.gh.polls[42], 'CI polling stops at the poll after the label went')

    def test_label_removed_from_a_later_pr_while_an_earlier_one_is_processed(self):
        self.queue()
        self.second_pr(43)
        self.gh.labels[43] = '2026-11-06T01:00:00Z'
        self.gh.labels[42] = '2026-11-06T00:00:00Z'
        self.gh.checks[42] = [[PENDING], [PASS]]
        self.gh.on_checks = lambda number, poll: self.gh.labels.pop(43, None) if number == 42 else None
        out = self.train().run()
        self.assertEqual([(42, 'MERGED'), (43, 'DEQUEUED')], [(r['pr'], r['outcome']) for r in out['results']])
        self.assertWithdrawn(out, 43)
        self.assertEqual('OPEN', self.gh.prs[43]['state'])

    def test_label_removed_between_the_final_check_and_the_merge(self):
        self.queue()
        out = self.train(mutation_lock=self.lock_hook(lambda: self.gh.labels.pop(42))).run()
        self.assertWithdrawn(out)

    def test_label_removed_between_the_check_and_the_push(self):
        self.queue()
        self.advance_main()
        train = self.train(mutation_lock=self.lock_hook(lambda: self.gh.labels.pop(42)))
        pushes = self.pushes(train)
        out = train.run()
        self.assertWithdrawn(out)
        self.assertEqual(([], self.reviewed), (pushes, self.gh.head(42)))

    def test_a_view_without_labels_is_an_error_not_a_withdrawal(self):
        self.queue()
        real = self.gh.pr_view
        self.gh.pr_view = lambda repo, number: {k: v for k, v in real(repo, number).items() if k != 'labels'}
        out = self.train().run()
        self.assertEqual('ERROR', out['results'][0]['outcome'], out)
        self.assertIsNotNone(merge_train.load_entry(REPO, 42))


class LockedRecheckTests(DeliveryTests):
    """What changes between the checks made before the lock and the write under it is checked again."""

    def test_the_merge_is_not_made_when_the_pr_changed_before_the_lock(self):
        changes = {
            'the PR was made a Draft': lambda: self.gh.prs[42].update(isDraft=True),
            'the base moved': lambda: self.advance_main(),
            'the PR branch moved': lambda: self.push_to_pr(),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                self.setUp()
                self.queue()
                out = self.train(mutation_lock=self.lock_hook(change)).run()
                self.assertEqual('WAITING', out['results'][0]['outcome'], out)
                self.assertIn('changed immediately before the merge', out['results'][0]['reason'])
                self.assertEqual([], self.merges())
                self.assertIn(42, self.gh.labels, 'it stays enqueued')

    def test_the_push_is_not_made_when_the_pr_changed_before_the_lock(self):
        self.queue()
        self.advance_main()
        train = self.train(mutation_lock=self.lock_hook(lambda: self.advance_main('docs/y.md')))
        pushes = self.pushes(train)
        out = train.run()
        # The base moved after the merge was built: that attempt pushed nothing; the next one integrated both.
        self.assertEqual(['MERGED'], [r['outcome'] for r in out['results']], out)
        self.assertEqual(1, len(pushes))
        head = self.gh.head(42)
        self.assertEqual('main moved', git(self.origin, 'show', f'{head}:docs/x.md'))
        self.assertEqual('main moved', git(self.origin, 'show', f'{head}:docs/y.md'))
        self.assertEqual(self.reviewed, git(self.origin, 'rev-parse', head + '^1'))

    def test_the_push_is_not_made_when_the_pr_branch_or_draft_state_changed_before_the_lock(self):
        for name, change, reason in (
                ('draft', lambda: self.gh.prs[42].update(isDraft=True), None),
                ('branch', lambda: self.push_to_pr(), 'HEAD changed since it was enqueued')):
            with self.subTest(change=name):
                self.setUp()
                self.queue()
                self.advance_main()
                train = self.train(mutation_lock=self.lock_hook(change))
                pushes = self.pushes(train)
                out = train.run()
                self.assertEqual('DEQUEUED', out['results'][0]['outcome'], out)
                self.assertEqual([], pushes)
                self.assertEqual([], self.merges())
                if reason:
                    self.assertIn(reason, out['results'][0]['reason'])

    def test_the_push_is_never_forced_when_the_pr_branch_moves_after_the_recheck(self):
        self.queue()
        self.advance_main()
        train = self.train()
        real = train.git
        pushes, moved = [], []

        def push_after_someone_else(*args, **kw):
            if args[0] == 'push':
                pushes.append(args)
                moved.append(self.push_to_pr('pkg/concurrent.go', 'package concurrent\n'))
            return real(*args, **kw)
        train.git = push_after_someone_else
        out = train.run()
        self.assertEqual(1, len(pushes))
        self.assertNotIn('--force', pushes[0])
        self.assertNotIn('-f', pushes[0])
        self.assertFalse(any(arg.startswith('+') for arg in pushes[0]), pushes[0])
        self.assertEqual(moved[0], self.gh.head(42), 'the concurrent commit stays on the PR branch')
        self.assertEqual([], self.merges())
        self.assertEqual('DEQUEUED', out['results'][0]['outcome'], out)
        self.assertIn('HEAD changed since it was enqueued', out['results'][0]['reason'])


class OutageTests(DeliveryTests):
    """A GitHub failure says nothing about the review or the target record: the PR stays enqueued."""

    def assertStaysEnqueued(self, out, *, why):
        self.assertEqual(['WAITING'], [r['outcome'] for r in out['results']], out)
        self.assertIn(why, out['results'][0]['reason'])
        self.assertIn(42, self.gh.labels)
        self.assertIsNotNone(merge_train.load_entry(REPO, 42), 'the saved evidence is kept')
        self.assertEqual([('label+', 42), ('comment', 42)], self.gh.writes[:2])
        self.assertEqual([], [w for w in self.gh.writes[2:] if w[0] != 'push'])
        self.assertEqual(1, len(self.gh.comments), 'no comment beyond the enqueue one')
        self.assertFalse(self.gh.prs[42]['isDraft'])

    def test_an_outage_while_checking_that_the_review_covers_head(self):
        for call in ('file_at', 'tree_entries', 'compare'):
            with self.subTest(call=call):
                self.setUp()
                self.gh.manifest = MANIFEST
                self.queue(target_validation=NOT_NEEDED)
                self.advance_main()                    # the train integrates it: the review is reused by delta
                self.gh.on_checks = lambda number, poll: self.gh.failing.update(
                    {call: GitHubError(f'gh api {call} failed (1): HTTP 502')})
                self.assertStaysEnqueued(self.train().run(), why='HTTP 502')

    def test_an_outage_while_reading_the_target_record_requirements(self):
        for call, nth in (('file_at', 1), ('compare', 1)):
            with self.subTest(call=call):
                self.setUp()
                self.gh.manifest = MANIFEST
                self.queue(target_validation=NOT_NEEDED)     # same HEAD: nothing is read for the review
                self.gh.on_checks = lambda number, poll: self.gh.failing.update(
                    {call: GitHubError(f'gh api {call} failed (1): HTTP 502')})
                self.assertStaysEnqueued(self.train().run(), why='HTTP 502')

    def test_a_real_gap_in_the_target_record_still_drafts_and_a_healthy_one_merges(self):
        # The PR touches playbooks/, which the manifest requires an actual-run record for: not-needed is wrong.
        self.write('playbooks/x.yml', '- hosts: all\n')
        head = self.commit('touch a playbook', push='feature')
        self.reviewed = head
        self.gh.manifest = MANIFEST
        self.queue(target_validation=NOT_NEEDED)
        out = self.train().run()
        self.assertEqual('DRAFTED', out['results'][0]['outcome'], out)
        self.assertIn('not-needed, but the PR changes playbooks/x.yml', self.gh.comments[-1][1])
        self.setUp()
        self.gh.manifest = MANIFEST
        self.queue(target_validation=NOT_NEEDED)
        out = self.train().run()
        self.assertEqual(['MERGED'], [r['outcome'] for r in out['results']], out)

    def test_an_outage_in_the_final_gate_waits(self):
        self.queue()
        self.gh.on_checks = lambda number, poll: self.gh.failing.update(
            {'unresolved_threads': GitHubError('graphql failed (1): HTTP 502')})
        self.assertStaysEnqueued(self.train().run(), why='Cannot verify review threads')

    def test_a_secret_scan_that_could_not_run_waits(self):
        self.queue()
        unavailable = ([], ['Secret scan unavailable: the head revision does not resolve to a commit in this clone'],
                       {'status': 'ERROR'})
        with mock.patch.object(review_gate, 'check_secrets', return_value=unavailable):
            out = self.train().run()
        self.assertStaysEnqueued(out, why='Secret scan unavailable')

    def test_check_target_validation_keeps_failures_to_read_apart_from_gaps(self):
        evidence = self.evidence()
        for target_validation, call, where in (
                (NOT_NEEDED, 'file_at', 'manifest'), (NOT_NEEDED, 'compare', 'changed files')):
            with self.subTest(call=call):
                self.setUp()
                self.gh.manifest = MANIFEST
                self.gh.failing[call] = GitHubError('HTTP 502')
                infra = []
                gaps, _ = review_gate.check_target_validation(
                    self.gh, REPO, self.reviewed, self.fork, dict(evidence, target_validation=target_validation),
                    infra=infra)
                self.assertEqual(([], 1), (gaps, len(infra)), (gaps, infra))
                self.assertIn('HTTP 502', infra[0])
                # Without the out-parameter every message is a gap, as before.
                gaps, _ = review_gate.check_target_validation(
                    self.gh, REPO, self.reviewed, self.fork, dict(evidence, target_validation=target_validation))
                self.assertEqual(1, len(gaps))
        # A manifest that does not parse is the base branch's state, not a defect of the PR's record.
        self.gh.failing.clear()
        self.gh.manifest = '{not json'
        infra = []
        self.assertEqual(([], 1), (review_gate.check_target_validation(
            self.gh, REPO, self.reviewed, self.fork, evidence, infra=infra)[0], len(infra)))
        # A real gap stays a gap.
        self.gh.manifest = MANIFEST
        infra = []
        gaps, _ = review_gate.check_target_validation(self.gh, REPO, self.reviewed, self.fork, evidence, infra=infra)
        self.assertEqual(([], 1), ([], len(gaps)))
        self.assertIn('target_validation is missing or not an object', gaps[0])

    def test_an_unreadable_record_beside_a_real_gap_still_waits(self):
        # The comparison failed AND another gap was found: the gap may be an artefact of the failure, so
        # the train does not Draft the PR for it.
        self.queue()
        with mock.patch.object(review_gate, 'check_target_validation') as check:
            def both(*args, infra=None, **kwargs):
                infra.append('cannot verify that the run at cccccccccccc covers HEAD: HTTP 502')
                return ['artifact docs/evidence/x.md is not committed at HEAD'], {}
            check.side_effect = both
            out = self.train().run()
        self.assertEqual('WAITING', out['results'][0]['outcome'], out)
        self.assertIn('HTTP 502', out['results'][0]['reason'])
        self.assertEqual([], [w for w in self.gh.writes[2:]])

    def test_review_covers_raises_on_an_outage_and_returns_a_verdict_otherwise(self):
        self.gh.manifest = MANIFEST
        live = self.advance_main()
        integrated = self.merge_main()
        for call in ('file_at', 'tree_entries', 'compare'):
            with self.subTest(call=call):
                self.gh.failing = {call: GitHubError('HTTP 502')}
                with self.assertRaises(GitHubError):
                    review_gate.review_covers(self.gh, REPO, self.reviewed, integrated, live, 'main')
        self.gh.failing = {}
        reuse, why = review_gate.review_covers(self.gh, REPO, self.reviewed, integrated, live, 'main')
        self.assertEqual('pure-base-import', reuse['method'], why)
        # A PR-side commit after the integration is a verdict about the review, not an error.
        later = self.push_to_pr()
        reuse, why = review_gate.review_covers(self.gh, REPO, self.reviewed, later, live, 'main')
        self.assertIsNone(reuse)
        self.assertIn('neither evidence-only nor a pure base import: pkg/b.go', why)
        # A base manifest that does not parse is not a verdict about the review either.
        self.gh.manifest = '{not json'
        with self.assertRaises(GitHubError):
            review_gate.review_covers(self.gh, REPO, self.reviewed, later, live, 'main')


class HeadOfLineTests(DeliveryTests):
    """A PR that needs a person leaves the queue with the reasons; only transient states stop the run."""

    PERSON = {
        'changes requested': (lambda t: t.gh.prs[42].update(review='CHANGES_REQUESTED'), {}, 'CHANGES_REQUESTED'),
        'approval required': (lambda t: t.gh.prs[42].update(review='REVIEW_REQUIRED'), {}, 'Human approval required'),
        'approval rule': (lambda t: (setattr(t.gh, 'rules', [{'type': 'pull_request',
                                                              'parameters': {'required_approving_review_count': 1}}]),
                                     t.gh.prs[43].update(review='APPROVED')), {}, 'require reviewer approval'),
        'failing check the reviewer confirmed unrelated': (
            lambda t: t.gh.checks.update({42: [[FAIL]]}),
            {'unrelated_failing_checks': [{'name': 'go test', 'reviewer_confirmed': True,
                                           'reason': 'The same timeout fails on main at the base SHA, run 123456789'}]},
            'unrelated to this PR'),
        'disputed finding': (
            lambda t: None,
            {'verdict': 'BLOCK', 'findings': [{'severity': 'P2', 'path': 'pkg/a.go', 'line': 1, 'blocking': True,
                                               'reason': 'Rescue skips rollback', 'recommendation': 'Tag it always',
                                               'disputed_reply_url': 'https://github.com/acme/demo/pull/42#issuecomment-1'}]},
            'without new evidence'),
        'merge state that is not clean for another reason': (
            lambda t: t.gh.prs[42].update(merge_state='BLOCKED'), {}, "Merge state is not CLEAN: 'BLOCKED'"),
        'an unrecognised review decision': (
            lambda t: t.gh.prs[42].update(review='SOMETHING_NEW'), {}, 'Unrecognized GitHub reviewDecision'),
    }

    def test_a_pr_that_needs_a_person_leaves_the_queue_and_the_run_goes_on(self):
        for name, (arrange, changes, reason) in self.PERSON.items():
            with self.subTest(case=name):
                self.setUp()
                self.queue(**changes)
                self.second_pr(43)
                self.gh.labels.update({42: '2026-11-06T00:00:00Z', 43: '2026-11-06T01:00:00Z'})
                arrange(self)
                out = self.train().run()
                self.assertEqual([(42, 'DEQUEUED'), (43, 'MERGED')], [(r['pr'], r['outcome']) for r in out['results']], out)
                self.assertIn(reason, out['results'][0]['reason'])
                self.assertIn(reason, [c for c in self.gh.comments if c[0] == 42][-1][1])
                self.assertIn('pr-review-merge', [c for c in self.gh.comments if c[0] == 42][-1][1])
                self.assertNotIn(42, self.gh.labels)
                self.assertIsNone(merge_train.load_entry(REPO, 42))
                self.assertFalse(self.gh.prs[42]['isDraft'], 'the PR stays Ready')
                self.assertEqual('MERGED', self.gh.prs[43]['state'])

    def test_a_comparison_github_cut_needs_a_person(self):
        self.queue()
        live = self.advance_main()
        self.second_pr(43, start=live)           # already contains main: no comparison needed
        self.gh.labels.update({42: '2026-11-06T00:00:00Z', 43: '2026-11-06T01:00:00Z'})
        self.gh.failing['compare'] = CompareLimitError('GitHub lists at most 300 changed files')
        out = self.train().run()
        self.assertEqual([(42, 'DEQUEUED'), (43, 'MERGED')], [(r['pr'], r['outcome']) for r in out['results']], out)
        self.assertIn('300 changed files', out['results'][0]['reason'])
        self.assertIn('integrate the base', [c for c in self.gh.comments if c[0] == 42][-1][1])
        self.assertFalse(self.gh.prs[42]['isDraft'])
        self.assertEqual([], [m for m in self.merges() if m[1] == 42])

    def assertTransient(self, out):
        self.assertEqual([(42, 'WAITING')], [(r['pr'], r['outcome']) for r in out['results']], out)
        self.assertIn(42, self.gh.labels)
        self.assertIn(43, self.gh.labels, 'the PR behind it was not touched')
        self.assertIsNotNone(merge_train.load_entry(REPO, 42))
        self.assertEqual([], [c for c in self.gh.comments if c[0] == 42][1:])
        self.assertEqual([], self.merges())

    def arrange_two(self):
        self.queue()
        self.second_pr(43)
        self.gh.labels.update({42: '2026-11-06T00:00:00Z', 43: '2026-11-06T01:00:00Z'})

    def test_transient_states_keep_the_pr_enqueued_and_stop_the_run(self):
        def pending():
            self.gh.checks[42] = [[PENDING]]
            return {'ci_timeout': 5}

        def merge_state_unknown():
            self.gh.prs[42]['merge_state'] = 'UNKNOWN'
            return {}

        def mergeability_not_computed():
            self.advance_main()
            self.gh.prs[42]['mergeable'] = 'UNKNOWN'
            return {'max_align': 2}

        def api_error():
            self.gh.on_checks = lambda number, poll: self.gh.failing.update(
                {'unresolved_threads': GitHubError('HTTP 502')}) if number == 42 else None
            return {}

        def base_keeps_moving():
            self.gh.on_checks = lambda number, poll: self.advance_main(f'docs/n{poll}.md') if number == 42 else None
            self.gh.checks[42] = [[PENDING]]
            return {'max_align': 2}

        for name, arrange in (('CI pending', pending), ('merge state not computed', merge_state_unknown),
                              ('mergeability not computed', mergeability_not_computed),
                              ('API error', api_error), ('base keeps moving', base_keeps_moving)):
            with self.subTest(case=name):
                self.setUp()
                self.arrange_two()
                kw = arrange()
                self.assertTransient(self.train(**kw).run())

    def test_a_secret_scan_that_could_not_run_stops_the_run_without_dequeueing(self):
        self.arrange_two()
        unavailable = ([], ['Secret scan unavailable: pass --worktree'], {'status': 'NOT_RUN'})
        with mock.patch.object(review_gate, 'check_secrets', return_value=unavailable):
            self.assertTransient(self.train().run())

    def test_errors_are_counted_and_the_third_in_a_row_leaves_the_queue(self):
        self.arrange_two()
        refused = GitHubError('gh pr merge 42 failed (1): merge refused')

        def refuse(repo, number, head):
            if number == 42:
                raise refused
            self.gh.__class__.merge_pr(self.gh, repo, number, head)
        self.gh.merge_pr = refuse
        for attempt in (1, 2):
            out = self.train().run()
            self.assertEqual([(42, 'ERROR')], [(r['pr'], r['outcome']) for r in out['results']], out)
            self.assertEqual(attempt, merge_train.load_entry(REPO, 42)['errors'])
        out = self.train().run()
        self.assertEqual([(42, 'DEQUEUED'), (43, 'MERGED')], [(r['pr'], r['outcome']) for r in out['results']], out)
        self.assertIn('3 runs in a row', out['results'][0]['reason'])
        self.assertIn('merge refused', [c for c in self.gh.comments if c[0] == 42][-1][1])
        self.assertNotIn(42, self.gh.labels)
        self.assertFalse(self.gh.prs[42]['isDraft'])

    def test_a_run_that_is_not_an_error_resets_the_count(self):
        self.arrange_two()
        self.gh.merge_pr = lambda repo, number, head: (_ for _ in ()).throw(GitHubError('merge refused'))
        self.assertEqual('ERROR', self.train().run()['results'][0]['outcome'])
        self.assertEqual('ERROR', self.train().run()['results'][0]['outcome'])
        self.assertEqual(2, merge_train.load_entry(REPO, 42)['errors'])
        self.gh.checks[42] = [[PENDING]]
        self.assertEqual('WAITING', self.train(ci_timeout=5).run()['results'][0]['outcome'])
        self.assertEqual(0, merge_train.load_entry(REPO, 42)['errors'])
        self.gh.checks[42] = [[PASS]]
        self.assertEqual('ERROR', self.train().run()['results'][0]['outcome'])
        self.assertEqual('ERROR', self.train().run()['results'][0]['outcome'])
        self.assertIsNotNone(merge_train.load_entry(REPO, 42), 'two in a row after the reset: still enqueued')
        self.assertIn(42, self.gh.labels)

    def test_a_failing_dequeue_does_not_hide_the_error(self):
        self.queue()
        self.gh.merge_pr = lambda repo, number, head: (_ for _ in ()).throw(GitHubError('merge refused'))
        entry = merge_train.load_entry(REPO, 42)
        merge_train.save_entry(REPO, 42, dict(entry, errors=2))
        self.gh.post_comment = lambda repo, number, body: (_ for _ in ()).throw(GitHubError('comment denied'))
        out = self.train().run()
        self.assertEqual('ERROR', out['results'][0]['outcome'], out)
        self.assertEqual(3, merge_train.load_entry(REPO, 42)['errors'])
        self.assertIn(42, self.gh.labels)


if __name__ == '__main__':
    unittest.main()
