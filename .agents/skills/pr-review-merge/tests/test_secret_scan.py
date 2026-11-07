"""The merge gate scans EVERY commit of the PR locally (--worktree): a leak is DRAFT, an unscanned PR WAITs.

Real git repositories and the real scanner; the GitHub side is the fake client (in-process) or a fake gh
executable (end to end). Secrets are built at run time (secret_fixtures.py) and never written to this repository.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'scripts'))
sys.path.insert(0, str(HERE.parents[1] / '_shared' / 'tests'))
sys.path.insert(0, str(HERE))
import apply_decision  # noqa: E402
import review_gate  # noqa: E402
import secret_fixtures as fx  # noqa: E402
from gh_runtime import Repo  # noqa: E402
from gitrepo import Repo as GitRepo  # noqa: E402
from test_gate import Fake, sample  # noqa: E402
import test_integration as integration  # noqa: E402

GUIDE = '.agents/skills/_shared/committed-secrets.md'


class RealPr(unittest.TestCase):
    """A repository with the PR's commits: B1 (value replaced later) and B2 (one placeholder commit)."""

    def setUp(self):
        self.r = GitRepo(self)
        self.r.write('README.md', 'base\n')
        self.r.commit('base')
        self.b = fx.build_leak_branches(self.r.path, self.r.env)
        self.base, self.b1, self.b2, self.value = self.b['base'], self.b['b1'], self.b['b2'], self.b['value']

    def pr(self, head, **kw):
        """(evidence, fake client) for a PR whose head/base are real commits."""
        evidence = sample()
        evidence.update(head_sha=head, base_sha=self.base)
        evidence['tests'][0]['sha'] = head
        gh = Fake()
        gh.v.update(headRefOid=head, baseRefOid=self.base)
        gh.live_base = self.base
        return evidence, gh

    def evaluate(self, head, **kw):
        evidence, gh = self.pr(head)
        return review_gate.evaluate(Repo.parse('acme/demo'), 42, evidence, client=gh, **kw)


class SecretScanGate(RealPr):
    def test_a_value_replaced_in_a_later_commit_is_draft_and_the_one_commit_control_merges(self):
        result = self.evaluate(self.b1, worktree=self.r.path)
        self.assertEqual('DRAFT', result['decision'], result['reasons'])
        text = ' '.join(result['reasons'])
        self.assertIn('freeipa-secret-attribute', text)
        self.assertIn('testdata/user.json', text)
        self.assertIn(self.b['leak_commit'][:12], text)
        self.assertIn('scrubs the value does not clear this finding', text)
        self.assertEqual('FOUND', result['secret_scan']['status'])
        for part in (self.value, self.value[:10], self.value[-10:]):
            self.assertNotIn(part, json.dumps(result))
        # Control: the same final tree, one commit that adds only the placeholder.
        passed = self.evaluate(self.b2, worktree=self.r.path)
        self.assertEqual('MERGE', passed['decision'], passed['reasons'])
        self.assertEqual('CLEAN', passed['secret_scan']['status'])
        self.assertEqual(self.r.out('rev-parse', f'{self.b1}^{{tree}}'), self.r.out('rev-parse', f'{self.b2}^{{tree}}'))

    def test_a_finding_is_a_defect_even_when_the_rest_is_incomplete(self):
        evidence, gh = self.pr(self.b1)
        evidence['verdict'] = 'NEEDS_MORE_EVIDENCE'
        result = review_gate.evaluate(Repo.parse('acme/demo'), 42, evidence, client=gh, worktree=self.r.path)
        self.assertEqual('DRAFT', result['decision'])
        self.assertTrue(any(r.startswith('Also awaiting') for r in result['reasons']))

    def test_without_a_worktree_the_gate_waits_and_never_merges(self):
        result = self.evaluate(self.b2)
        self.assertEqual('WAITING', result['decision'])
        self.assertIn('Secret scan unavailable', ' '.join(result['reasons']))
        self.assertEqual('NOT_RUN', result['secret_scan']['status'])

    def test_commits_that_are_not_in_the_clone_make_the_gate_wait_with_a_fetch_hint(self):
        evidence, gh = self.pr('e' * 40)
        result = review_gate.evaluate(Repo.parse('acme/demo'), 42, evidence, client=gh, worktree=self.r.path)
        self.assertEqual('WAITING', result['decision'])
        self.assertRegex(' '.join(result['reasons']), r'Secret scan could not be completed.*fetch')

    def test_a_scanner_that_cannot_be_loaded_makes_the_gate_wait(self):
        broken = Path(self.r.base) / 'secret_scan.py'
        broken.write_text('def (:\n')
        for path in (broken, Path(self.r.base) / 'absent.py'):
            with self.subTest(path=path.name), mock.patch.dict(sys.modules), \
                    mock.patch.object(review_gate, 'SECRET_SCAN_PATH', path):
                sys.modules.pop('pilot_secret_scan', None)
                result = self.evaluate(self.b2, worktree=self.r.path)
                self.assertEqual('WAITING', result['decision'])
                self.assertIn('Secret scan unavailable', ' '.join(result['reasons']))
        self.assertEqual('MERGE', self.evaluate(self.b2, worktree=self.r.path)['decision'], 'control: the real scanner loads')

    def test_a_secret_file_value_is_a_defect_and_an_unusable_file_waits(self):
        known = fx.mixed(18)
        self.r.git('switch', '-q', '-c', 'notes', self.base)
        self.r.write('notes.txt', f'scratch {known}\n')
        self.r.commit('notes')
        self.r.write('notes.txt', 'scrubbed\n')
        head = self.r.commit('scrub')
        secrets_file = Path(self.r.base) / 'known.txt'
        secrets_file.write_text(f'{known}\n')
        evidence, gh = self.pr(head)
        found = review_gate.evaluate(Repo.parse('acme/demo'), 42, evidence, client=gh, worktree=self.r.path,
                                     secret_files=[secrets_file])
        self.assertEqual('DRAFT', found['decision'], found['reasons'])
        self.assertIn('known-value', ' '.join(found['reasons']))
        self.assertNotIn(known, json.dumps(found))
        evidence, gh = self.pr(head)
        clean = review_gate.evaluate(Repo.parse('acme/demo'), 42, evidence, client=gh, worktree=self.r.path)
        self.assertEqual('MERGE', clean['decision'], 'control: without the secret file nothing is known to leak')
        short = Path(self.r.base) / 'short.txt'
        short.write_text(f'{fx.mixed(14)}\n{fx.mixed(5)}\n')
        evidence, gh = self.pr(head)
        waits = review_gate.evaluate(Repo.parse('acme/demo'), 42, evidence, client=gh, worktree=self.r.path,
                                     secret_files=[short])
        self.assertEqual('WAITING', waits['decision'])
        self.assertIn('line 2', ' '.join(waits['reasons']))

    def test_the_draft_comment_tells_root_to_stop_and_leaves_the_decision_to_the_user(self):
        result = self.evaluate(self.b1, worktree=self.r.path)
        comment = apply_decision.comment_text(result)
        self.assertIn('Stop', comment)
        self.assertIn('The user decides', comment)
        self.assertIn('does not clear this finding', comment)
        self.assertIn(GUIDE, comment)
        self.assertNotIn('Address blocking findings', comment, 'the generic next step would invite a scrubbing commit')
        for part in (self.value, self.value[:10]):
            self.assertNotIn(part, comment)
        # Any other Draft keeps the generic next steps.
        other = self.evaluate(self.b2, worktree=self.r.path)
        other.update(decision='DRAFT', reasons=['CI failed'])
        self.assertIn('Address blocking findings', apply_decision.comment_text(other))
        self.assertNotIn('Stop', apply_decision.comment_text(other))

    def test_the_actor_re_runs_the_gate_with_the_same_worktree(self):
        evidence, gh = self.pr(self.b2)
        with mock.patch.object(apply_decision, 'evaluate', wraps=review_gate.evaluate) as ev:
            apply_decision._perform_locked(Repo.parse('acme/demo'), 42, evidence, 'merge', False,
                                           worktree=self.r.path, secret_files=[Path('/x')])
        self.assertEqual(self.r.path, ev.call_args.kwargs['worktree'])
        self.assertEqual([Path('/x')], ev.call_args.kwargs['secret_files'])


class SecretScanIntegration(RealPr):
    """End to end: the scripts, a fake gh, and a real repository behind --worktree."""

    setUp_integration = integration.Integration.setUp
    state = integration.Integration.state
    patch = integration.Integration.patch
    actor_args = None

    def setUp(self):
        RealPr.setUp(self)
        self.setUp_integration()
        self.use(self.b1)

    def use(self, head):
        """Point the fixture gh and the review evidence at a real head of the repository."""
        data = integration.fixture()
        data['view'].update(headRefOid=head, baseRefOid=self.base)
        self.fixture_file.write_text(json.dumps(data))
        evidence = integration.evidence()
        evidence.update(head_sha=head, base_sha=self.base)
        evidence['tests'][0]['sha'] = head
        self.evidence_file.write_text(json.dumps(evidence))

    def run_script(self, name, *args, worktree=True):
        extra = ['--worktree', str(self.r.path)] if worktree else []
        return subprocess.run([sys.executable, str(HERE.parent / 'scripts' / name), '--repo', 'acme/demo', *args, *extra],
                              env=self.env, capture_output=True, text=True)

    def actor(self, execute=False, **kw):
        args = ['--pr', '42', '--evidence', str(self.evidence_file)] + (['--execute'] if execute else [])
        proc = self.run_script('apply_decision.py', *args, **kw)
        try:
            out = json.loads(proc.stdout)
        except ValueError:
            self.fail(f'bad json: {proc.stdout}\n{proc.stderr}')
        return proc, out

    def writes(self):
        return [a[1] for a in self.state()['calls'] if a[:2] in (['pr', 'comment'], ['pr', 'ready'], ['pr', 'merge'])]

    def test_review_gate_refuses_b1_and_passes_b2(self):
        proc = self.run_script('review_gate.py', '--pr', '42', '--evidence', str(self.evidence_file))
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual('DRAFT', out['decision'])
        self.assertIn('freeipa-secret-attribute', ' '.join(out['reasons']))
        for channel in (proc.stdout, proc.stderr):
            for part in (self.value, self.value[:10], self.value[-10:]):
                self.assertNotIn(part, channel)
        self.use(self.b2)
        proc = self.run_script('review_gate.py', '--pr', '42', '--evidence', str(self.evidence_file))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual('MERGE', json.loads(proc.stdout)['decision'])
        self.assertFalse(any(c[0] == 'pr' and c[1] in ('merge', 'comment', 'ready') for c in self.state()['calls']))

    def test_apply_decision_dry_run_drafts_b1_and_merges_b2(self):
        proc, out = self.actor()
        self.assertEqual((0, 'DRY_RUN_DRAFT'), (proc.returncode, out['outcome']), proc.stdout + proc.stderr)
        self.assertEqual([], self.writes())
        self.use(self.b2)
        proc, out = self.actor()
        self.assertEqual((0, 'DRY_RUN_MERGE'), (proc.returncode, out['outcome']), proc.stdout + proc.stderr)
        for channel in (proc.stdout, proc.stderr):
            self.assertNotIn(self.value, channel)

    def test_apply_decision_executes_the_draft_with_a_value_free_stop_comment(self):
        proc, out = self.actor(execute=True)
        self.assertEqual((0, 'DRAFT-BLOCKED'), (proc.returncode, out['outcome']), proc.stdout + proc.stderr)
        state = self.state()
        self.assertEqual(['comment', 'ready'], self.writes())
        self.assertTrue(state['view']['isDraft'])
        comment = state['comments'][0]
        self.assertIn('freeipa-secret-attribute', comment)
        self.assertIn('Stop', comment)
        self.assertIn(GUIDE, comment)
        self.assertNotIn('Address blocking findings', comment)
        for part in (self.value, self.value[:10], self.value[-10:]):
            for channel in (comment, proc.stdout, proc.stderr, json.dumps(state)):
                self.assertNotIn(part, channel)

    def test_apply_decision_queues_b2_because_its_re_run_of_the_gate_can_return_merge(self):
        # MERGE queues the PR for the merge train (kjelly/pilot#307); the train merges it.
        self.use(self.b2)
        proc, out = self.actor(execute=True)
        self.assertEqual((0, 'ENQUEUED'), (proc.returncode, out['outcome']), proc.stdout + proc.stderr)
        self.assertEqual(['comment'], self.writes())
        self.assertEqual(['merge-queue'], self.state()['labels'])

    def test_without_a_worktree_nothing_is_merged(self):
        self.use(self.b2)
        proc, out = self.actor(execute=True, worktree=False)
        self.assertEqual('WAITING', out['outcome'], proc.stdout)
        self.assertIn('Secret scan unavailable', ' '.join(out['gate']['reasons']))
        self.assertEqual([], self.writes())

    def test_a_secret_file_is_handed_to_both_scripts(self):
        known = fx.mixed(18)
        self.r.git('switch', '-q', '-c', 'notes', self.base)
        self.r.write('notes.txt', f'x {known}\n')
        head = self.r.commit('notes')
        self.use(head)
        secrets_file = Path(self.r.base) / 'known.txt'
        secrets_file.write_text(f'{known}\n')
        proc = self.run_script('review_gate.py', '--pr', '42', '--evidence', str(self.evidence_file),
                               '--secret-file', str(secrets_file))
        self.assertEqual(1, proc.returncode, proc.stdout)
        self.assertIn('known-value', proc.stdout)
        proc, out = self.actor(execute=False)
        self.assertEqual('DRY_RUN_MERGE', out['outcome'], 'control: without the secret file nothing is known to leak')
        proc = self.run_script('apply_decision.py', '--pr', '42', '--evidence', str(self.evidence_file),
                               '--secret-file', str(secrets_file))
        self.assertEqual('DRY_RUN_DRAFT', json.loads(proc.stdout)['outcome'])
        for channel in (proc.stdout, proc.stderr):
            self.assertNotIn(known, channel)


if __name__ == '__main__':
    unittest.main()
