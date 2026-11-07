"""End-to-end tests of the CLI with a fake gh executable (no GitHub writes)."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEAD = 'a'*40
BASE = 'b'*40
COVERAGE = ('requirements', 'correctness', 'architecture', 'security', 'concurrency',
            'edge_cases', 'semantic_regression', 'tests')
MOCK_GH = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
p = Path(os.environ['MOCK_GH_DATA'])
d = json.loads(p.read_text())
a = sys.argv[1:]
name = ' '.join(a[:2]) if len(a) > 1 else str(a)
d.setdefault('calls', []).append(a)
def persist(): p.write_text(json.dumps(d))
def emit(o): persist(); print(json.dumps(o)); sys.exit(0)
if a[:2] == ['pr', 'view']:
    d['view_count'] = d.get('view_count', 0) + 1
    if d.get('race_on_view') == d['view_count']:
        d['view']['headRefOid'] = 'c'*40
    names = d.get('base_name_on_view', {})
    count = str(d['view_count'])
    if count in names:
        if names[count] is None:
            d['view'].pop('baseRefName', None)
        else:
            d['view']['baseRefName'] = names[count]
    emit(d['view'])
if a[:2] == ['pr', 'checks']:
    persist()
    print(json.dumps(d['checks']))
    sys.exit(d.get('checks_rc', 0))
if a[:2] == ['api', 'graphql'] or ('graphql' in a and a[0] == 'api'):
    if d.get('threads_error'):
        print('permission denied', file=sys.stderr); persist(); sys.exit(1)
    nodes = [{'isResolved': False} for _ in range(d.get('threads', 0))]
    emit({'data': {'repository': {'pullRequest': {'reviewThreads': {'nodes': nodes,
           'pageInfo': {'hasNextPage': False, 'endCursor': None}}}}}})
if a[0] == 'api' and '/rules/branches/' in a[-1]:
    if d.get('rules_error'):
        print('rules denied', file=sys.stderr); persist(); sys.exit(1)
    emit([d.get('rules', [])])
if a[0] == 'api' and '/git/ref/heads/' in a[-1]:
    d['ref_count'] = d.get('ref_count', 0) + 1
    if d.get('ref_error'):
        persist(); print('ref unavailable', file=sys.stderr); sys.exit(1)
    if d.get('race_on_ref') == d['ref_count']:
        d['live_base'] = 'd'*40
    emit({'object': {'type': 'commit', 'sha': d.get('live_base', d['view']['baseRefOid'])}})
if a[0] == 'api' and '/pulls?' in a[-1]:
    emit(d.get('pages', []))
if a[0] == 'api' and '/issues?' in a[-1]:
    label = a[-1].split('labels=')[1].split('&')[0]
    emit([[{'number': d['view']['number'], 'pull_request': {}}] if label in d.get('labels', []) else []])
if a[:2] == ['pr', 'edit']:
    if d.get('fail_label'):
        persist(); print('label denied', file=sys.stderr); sys.exit(1)
    labels = d.setdefault('labels', [])
    if '--add-label' in a:
        labels.append(a[a.index('--add-label') + 1])
    if '--remove-label' in a:
        name = a[a.index('--remove-label') + 1]
        d['labels'] = [x for x in labels if x != name]
    persist(); sys.exit(0)
if a[0] == 'api' and '/compare/' in a[-1] and a[-1] not in d.get('api', {}):
    if d.get('ancestry_error'):
        persist(); print('comparison unavailable', file=sys.stderr); sys.exit(1)
    base, head = a[-1].split('/compare/')[1].split('...')
    aligned = d.get('ancestor', True)
    emit({'status': 'ahead' if aligned else 'diverged', 'behind_by': 0 if aligned else 1,
          'merge_base_commit': {'sha': base if aligned else 'e'*40}})
if a[0] == 'api' and ('/contents/' in a[-1] or '/compare/' in a[-1]):
    # Answers recorded from real `gh api` calls (fixtures/github_api.json); anything else is
    # GitHub's real 404 for a path or commit it does not have.
    d.setdefault('api_calls', []).append(a[-1])
    answer = d.get('api', {}).get(a[-1], d['not_found'])
    persist(); sys.stdout.write(answer['stdout']); sys.stderr.write(answer['stderr']); sys.exit(answer['rc'])
if a[:2] == ['pr', 'comment']:
    if d.get('fail_comment'):
        persist(); print('comment denied', file=sys.stderr); sys.exit(1)
    path = a[a.index('--body-file')+1]
    d.setdefault('comments', []).append(Path(path).read_text())
    persist(); sys.exit(0)
if a[:2] == ['pr', 'ready']:
    if d.get('fail_draft'):
        persist(); print('draft denied', file=sys.stderr); sys.exit(1)
    d['view']['isDraft'] = True
    persist(); sys.exit(0)
if a[:2] == ['pr', 'merge']:
    if d.get('fail_merge'):
        persist(); print('merge denied', file=sys.stderr); sys.exit(1)
    sha = a[a.index('--match-head-commit') + 1]
    if sha != d['view']['headRefOid']:
        persist(); print('SHA mismatch', file=sys.stderr); sys.exit(1)
    if not d.get('simulate_merge_unconfirmed'):
        d['view']['state'] = 'MERGED'
    persist(); sys.exit(0)
if a[:2] == ['repo', 'view']:
    persist(); print('acme/demo'); sys.exit(0)
persist(); print('unknown gh invocation ' + repr(a), file=sys.stderr); sys.exit(1)
'''


def evidence():
    return {'schema_version':1, 'repo':'acme/demo', 'pr':42, 'head_sha':HEAD, 'base_sha':BASE,
            'reviewer_id':'prm-reviewer', 'independent':True, 'verdict':'PASS',
            'summary':'Full patch plus impacted modules independently reviewed.',
            'coverage':{k:True for k in COVERAGE}, 'findings':[],
            'tests':[{'name':'unit','status':'PASS','sha':HEAD,'evidence':'test logs evidence: run id 3'}],
            'dependencies':{'resolved':True,'evidence':'No outstanding PR dependencies'},
            'no_ci_rationale':''}


GITHUB_API = json.loads((ROOT / 'tests' / 'fixtures' / 'github_api.json').read_text())


def fixture():
    return {'view': {'number':42, 'url':'https://github.com/acme/demo/pull/42',
                     'state':'OPEN', 'isDraft':False, 'headRefOid':HEAD, 'baseRefOid':BASE,
                     'baseRefName':'main', 'mergeable':'MERGEABLE', 'mergeStateStatus':'CLEAN',
                     'reviewDecision':'APPROVED', 'autoMergeRequest':None},
            'checks':[{'name':'unit','bucket':'pass','state':'SUCCESS','link':'https://example.com'}],
            'rules':[], 'threads':0, 'api': {},
            'not_found': GITHUB_API['contents']['manifest_absent_at_d013ed95']}


class Integration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='prm-test-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.bin = self.path / 'bin'; self.bin.mkdir()
        (self.bin / 'gh').write_text(MOCK_GH)
        (self.bin / 'gh').chmod(0o755)
        self.fixture_file = self.path / 'fixture.json'; self.fixture_file.write_text(json.dumps(fixture()))
        self.evidence_file = self.path / 'evidence.json'; self.evidence_file.write_text(json.dumps(evidence()))
        # The actor's repository flock lives under PRM_STATE_DIR (default ~/.cache/pr-review-merge).
        # A per-test directory keeps overlapping test runs from contending for the user's real lock.
        state = str(self.path / 'state')
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ.get('PATH','')}",
                        MOCK_GH_DATA=str(self.fixture_file), PRM_STATE_DIR=state)
        previous = os.environ.get('PRM_STATE_DIR')
        os.environ['PRM_STATE_DIR'] = state
        self.addCleanup(lambda: os.environ.__setitem__('PRM_STATE_DIR', previous) if previous is not None
                        else os.environ.pop('PRM_STATE_DIR', None))

    def state(self):
        return json.loads(self.fixture_file.read_text())

    def patch(self, **kwargs):
        d = self.state(); d.update(kwargs)
        self.fixture_file.write_text(json.dumps(d))

    def conflict(self, **kwargs):
        """HEAD lacks the live base and GitHub's test merge conflicts: the merge train cannot integrate
        it, so the gate drafts without a review (kjelly/pilot#307)."""
        d = self.state(); d.update(kwargs, ancestor=False)
        d['view'].update(mergeable='CONFLICTING', mergeStateStatus='DIRTY')
        self.fixture_file.write_text(json.dumps(d))

    def script(self, name, *args):
        """Run a script with the secret scan replaced by a clean one: these PRs have fake SHAs that no
        repository holds. The scan itself is tested below with a real repository (SecretScanIntegration)."""
        return subprocess.run([sys.executable, str(ROOT / 'tests' / 'scan_stub_runner.py'), str(ROOT / 'scripts' / name),
                               '--repo', 'acme/demo', *args], env=self.env, capture_output=True, text=True)

    def actor(self, execute=False):
        a = ['--pr','42','--evidence',str(self.evidence_file)]
        if execute: a.append('--execute')
        proc = self.script('apply_decision.py', *a)
        try: output = json.loads(proc.stdout)
        except ValueError: self.fail(f'bad json: {proc.stdout}\n{proc.stderr}')
        return proc, output

    def test_read_only_gate(self):
        proc = self.script('review_gate.py','--pr','42','--evidence',str(self.evidence_file))
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['decision'],'MERGE')
        self.assertFalse(any(c[0]=='pr' and c[1] in ('merge','comment','ready') for c in self.state()['calls']))

    def test_merge_dry_run(self):
        proc,out = self.actor()
        self.assertEqual(proc.returncode,0)
        self.assertEqual(out['outcome'],'DRY_RUN_MERGE')
        self.assertEqual(self.state()['view']['state'],'OPEN')

    def test_merge_decision_queues_for_the_train(self):
        # The actor never merges: it saves the evidence and labels the PR; merge_train.py merges it.
        proc,out = self.actor(execute=True)
        self.assertEqual(proc.returncode,0,proc.stdout + proc.stderr)
        self.assertEqual(out['outcome'],'ENQUEUED')
        d = self.state()
        self.assertEqual(d['view']['state'],'OPEN')
        self.assertEqual(d['labels'], ['merge-queue'])
        self.assertFalse(any(a[:2]==['pr','merge'] for a in d['calls']))
        self.assertIn('Merge train: enqueued', d['comments'][0])
        self.assertIn(HEAD, d['comments'][0])
        sys.path.insert(0, str(ROOT / 'scripts'))
        import merge_train
        from gh_runtime import Repo
        saved = merge_train.load_entry(Repo.parse('acme/demo'), 42)
        self.assertEqual((saved['reviewed_head'], saved['evidence']), (HEAD, evidence()))

    def test_queue_label_failure_is_an_error_not_queued(self):
        self.patch(fail_label=True)
        proc, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'ERROR')
        self.assertFalse(self.state().get('labels'))

    def test_other_merge_methods_are_not_queued(self):
        a = ['--pr','42','--evidence',str(self.evidence_file),'--method','squash','--execute']
        out = json.loads(self.script('apply_decision.py', *a).stdout)
        self.assertEqual(out['outcome'], 'ERROR')
        self.assertIn('merge commits', out['error'])
        self.assertFalse(self.state().get('labels'))

    def test_confirmed_blocker_comments_then_drafts(self):
        e = evidence(); e['verdict'] = 'BLOCK';
        e['findings'] = [{'severity':'P1','path':'pkg/a.go','line':34,
                          'reason':'incorrect value on empty input', 'recommendation':'guard empty input', 'blocking':True}]
        self.evidence_file.write_text(json.dumps(e))
        proc,out=self.actor(execute=True)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertEqual(out['outcome'],'DRAFT-BLOCKED')
        d=self.state()
        self.assertTrue(d['view']['isDraft'])
        self.assertIn('pkg/a.go:34',d['comments'][0])
        calls=[a[1] for a in d['calls'] if a[0]=='pr' and a[1] in ('comment','ready','merge')]
        self.assertEqual(calls,['comment','ready'])

    def test_base_mismatch_comments_then_drafts_without_review(self):
        self.conflict(live_base='c'*40)
        self.evidence_file.write_text('{}')
        proc, out = self.actor(execute=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(out['outcome'], 'DRAFT-BLOCKED')
        d = self.state()
        self.assertTrue(d['view']['isDraft'])
        self.assertIn(BASE, d['comments'][0])
        self.assertIn('c'*40, d['comments'][0])
        self.assertIn('pr-ready', d['comments'][0])
        writes = [a[1] for a in d['calls'] if a[:2] in
                  (['pr', 'comment'], ['pr', 'ready'], ['pr', 'merge'])]
        self.assertEqual(writes, ['comment', 'ready'])

    def test_base_mismatch_comment_failure_preserves_ready(self):
        self.conflict(live_base='c'*40, fail_comment=True)
        _, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'ERROR')
        self.assertFalse(self.state()['view']['isDraft'])

    def test_behind_head_comments_then_drafts_without_review(self):
        self.conflict()
        self.evidence_file.write_text('{}')
        proc, out = self.actor(execute=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(out['outcome'], 'DRAFT-BLOCKED')
        d = self.state()
        self.assertTrue(d['view']['isDraft'])
        self.assertIn(HEAD, d['comments'][0])
        self.assertIn(BASE, d['comments'][0])
        self.assertIn('pr-ready', d['comments'][0])
        writes = [a[1] for a in d['calls'] if a[:2] in
                  (['pr', 'comment'], ['pr', 'ready'], ['pr', 'merge'])]
        self.assertEqual(writes, ['comment', 'ready'])

    def test_behind_head_comment_failure_preserves_ready(self):
        self.conflict(fail_comment=True)
        _, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'ERROR')
        self.assertFalse(self.state()['view']['isDraft'])

    def test_ancestry_unavailable_never_mutates(self):
        self.patch(ancestry_error=True)
        _, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'WAITING')
        self.assertFalse(self.state().get('comments'))

    def test_base_moves_after_ancestry_gate_never_mutates(self):
        self.conflict(race_on_ref=3)
        _, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'ERROR')
        self.assertFalse(self.state().get('comments'))
        self.assertFalse(self.state()['view']['isDraft'])

    def test_head_repaired_during_comment_prevents_draft(self):
        self.conflict(race_on_view=4)
        _, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'ERROR')
        self.assertTrue(self.state().get('comments'))
        self.assertFalse(self.state()['view']['isDraft'])
        self.assertFalse(any(a[:2] == ['pr', 'ready'] for a in self.state()['calls']))

    def test_base_ref_unavailable_never_mutates(self):
        self.patch(ref_error=True)
        _, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'WAITING')
        self.assertFalse(self.state().get('comments'))

    def test_base_moves_after_mismatch_gate_never_mutates(self):
        self.conflict(live_base='c'*40, race_on_ref=3)
        _, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'ERROR')
        self.assertFalse(self.state().get('comments'))
        self.assertFalse(self.state()['view']['isDraft'])

    def test_base_name_changes_before_action_never_write(self):
        # Both branch names resolve to the same live SHA. Only branch identity changes.
        for mode in ('base_mismatch', 'base_behind', 'merge', 'semantic_draft'):
            for name in ('release', None, '', 7):
                with self.subTest(mode=mode, name=name):
                    d = fixture()
                    if mode == 'base_mismatch':
                        d['live_base'] = 'c'*40
                    if mode.startswith('base_'):
                        d['ancestor'] = False
                        d['view'].update(mergeable='CONFLICTING', mergeStateStatus='DIRTY')
                    if mode == 'semantic_draft':
                        d['checks'][0]['bucket'] = 'fail'
                    d['base_name_on_view'] = {'3': name}
                    self.fixture_file.write_text(json.dumps(d))
                    self.evidence_file.write_text('{}' if mode.startswith('base_') else json.dumps(evidence()))
                    proc, out = self.actor(execute=True)
                    self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                    self.assertEqual(out['outcome'], 'ERROR')
                    self.assertIn('changed immediately before action', out['error'])
                    self.assertFalse(out['executed'])
                    state = self.state()
                    self.assertFalse(state['view']['isDraft'])
                    self.assertEqual(state['view']['state'], 'OPEN')
                    self.assertFalse(any(a[:2] in (['pr', 'comment'], ['pr', 'ready'], ['pr', 'merge'])
                                         for a in state['calls']))

    def test_base_name_changes_during_confirmation_wait_without_writes(self):
        for mode in ('base_mismatch', 'base_behind'):
            with self.subTest(mode=mode):
                d = fixture()
                if mode == 'base_mismatch':
                    d['live_base'] = 'c'*40
                else:
                    d['ancestor'] = False
                d['base_name_on_view'] = {'2': 'release'}
                self.fixture_file.write_text(json.dumps(d))
                self.evidence_file.write_text('{}')
                proc, out = self.actor(execute=True)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertEqual(out['outcome'], 'WAITING')
                self.assertIn('changed while confirming', ' '.join(out['gate']['reasons']))
                self.assertFalse(any(a[:2] in (['pr', 'comment'], ['pr', 'ready'], ['pr', 'merge'])
                                     for a in self.state()['calls']))

    def test_base_name_changes_during_final_gate_wait_without_writes(self):
        for fail_ci in (False, True):
            for name in ('release', None, '', 7):
                with self.subTest(fail_ci=fail_ci, name=name):
                    d = fixture()
                    d['base_name_on_view'] = {'2': name}
                    if fail_ci:
                        d['checks'][0]['bucket'] = 'fail'
                    self.fixture_file.write_text(json.dumps(d))
                    proc, out = self.actor(execute=True)
                    self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                    self.assertEqual(out['outcome'], 'WAITING')
                    self.assertIn('changed during live gate', ' '.join(out['gate']['reasons']))
                    self.assertFalse(any(a[:2] in (['pr', 'comment'], ['pr', 'ready'], ['pr', 'merge'])
                                         for a in self.state()['calls']))

    def test_base_name_changes_after_comment_prevent_draft(self):
        for mode in ('base_mismatch', 'base_behind', 'semantic_draft'):
            for name in ('release', None, '', 7):
                with self.subTest(mode=mode, name=name):
                    d = fixture()
                    if mode == 'base_mismatch':
                        d['live_base'] = 'c'*40
                    if mode.startswith('base_'):
                        d['ancestor'] = False
                        d['view'].update(mergeable='CONFLICTING', mergeStateStatus='DIRTY')
                    if mode == 'semantic_draft':
                        d['checks'][0]['bucket'] = 'fail'
                    d['base_name_on_view'] = {'4': name}
                    self.fixture_file.write_text(json.dumps(d))
                    self.evidence_file.write_text('{}' if mode.startswith('base_') else json.dumps(evidence()))
                    proc, out = self.actor(execute=True)
                    self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                    self.assertEqual(out['outcome'], 'ERROR')
                    self.assertIn('changed after comment', out['error'])
                    self.assertTrue(out['comment_posted'])
                    self.assertFalse(out['executed'])
                    self.assertFalse(self.state()['view']['isDraft'])
                    writes = [a[1] for a in self.state()['calls'] if a[:2] in
                              (['pr', 'comment'], ['pr', 'ready'], ['pr', 'merge'])]
                    self.assertEqual(writes, ['comment'])

    def test_failed_ci_draft(self):
        self.patch(checks=[{'name':'lint','state':'FAILURE','bucket':'fail'}])
        proc,out=self.actor(execute=True)
        self.assertEqual(out['outcome'],'DRAFT-BLOCKED')
        self.assertIn('lint',self.state()['comments'][0])

    def test_pending_ci_waiting(self):
        self.patch(checks=[{'name':'lint','state':'PENDING','bucket':'pending'}])
        proc,out=self.actor(execute=True)
        self.assertEqual(out['outcome'],'WAITING')
        self.assertFalse(self.state().get('comments'))
        self.assertEqual(self.state()['view']['state'],'OPEN')

    def test_concurrent_writer_lock_refuses_mutation(self):
        from sys import path as syspath
        syspath.insert(0, str(ROOT / 'scripts'))
        from apply_decision import repo_mutation_lock
        from gh_runtime import Repo
        lock_dir = self.path / 'lockroot'
        self.env['PRM_STATE_DIR'] = str(lock_dir)
        old = os.environ.get('PRM_STATE_DIR')
        try:
            os.environ['PRM_STATE_DIR'] = str(lock_dir)
            with repo_mutation_lock(Repo.parse('acme/demo')):
                proc, out = self.actor(execute=True)
                self.assertEqual(out['outcome'], 'ERROR')
                self.assertIn('Another', out['error'])
                self.assertEqual(self.state().get('calls',[]), [])
        finally:
            if old is None:
                os.environ.pop('PRM_STATE_DIR',None)
            else:
                os.environ['PRM_STATE_DIR'] = old

    def test_merge_queue_waiting(self):
        self.patch(rules=[{'type':'merge_queue'}])
        proc,out=self.actor(execute=True)
        self.assertEqual(out['outcome'],'WAITING')
        self.assertFalse(any(a[:2]==['pr','merge'] for a in self.state()['calls']))

    def test_unreviewed_new_head_waiting(self):
        d=self.state(); d['view']['headRefOid']='d'*40; self.fixture_file.write_text(json.dumps(d))
        proc,out=self.actor(execute=True)
        self.assertEqual(out['outcome'],'WAITING')
        self.assertFalse(any(a[:2]==['pr','merge'] for a in self.state()['calls']))

    def test_race_after_gate(self):
        self.patch(race_on_view=3)
        proc,out=self.actor(execute=True)
        self.assertEqual(out['outcome'],'ERROR')
        self.assertFalse(any(a[:2]==['pr','merge'] for a in self.state()['calls']))

    def test_base_moves_during_successful_ancestry_check_never_mutates(self):
        self.patch(race_on_ref=2)
        _, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'WAITING')
        self.assertFalse(self.state().get('comments'))
        self.assertFalse(any(a[:2] == ['pr', 'merge'] for a in self.state()['calls']))

    def test_draft_comment_failure_prevents_downgrade(self):
        self.patch(fail_comment=True, checks=[{'name':'unit','state':'FAILURE','bucket':'fail'}])
        proc,out=self.actor(execute=True)
        self.assertEqual(out['outcome'],'ERROR')
        self.assertFalse(self.state()['view']['isDraft'])

    def test_branch_rules_error_fails_closed(self):
        self.patch(rules_error=True)
        proc,out=self.actor(execute=True)
        self.assertEqual(out['outcome'],'WAITING')
        self.assertFalse(any(a[:2]==['pr','merge'] for a in self.state()['calls']))

    def test_actor_lock_stays_in_the_test_state_dir(self):
        proc, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'ENQUEUED', proc.stderr)
        self.assertTrue(any((self.path / 'state' / 'locks').glob('*.lock')))
        self.assertTrue(any((self.path / 'state' / 'queue').glob('*/42.json')))

    # kjelly/pilot PR #177's tail, as GitHub answered it: candidate 2d70670 plus the evidence-only
    # commit 1262c6a7 that records its run, against a base (main at fdb6f03e) whose
    # .github/pr-evidence.json requires the actual-run record.
    CAPTURED_HEAD = '1262c6a7ba7fcd83326165c3e05647c62129b9c8'
    CAPTURED_BASE = 'fdb6f03e9152de5e48dc6b9870cab2d050bf962e'
    CANDIDATE = '2d70670935bdfe8b3ac5fbbb337ce6e5b0c874c5'
    RECORD = 'docs/evidence/os-patch-sla/2026-10-29-2d70670.md'

    def use_captured_pr(self, target_validation):
        head, base, api = self.CAPTURED_HEAD, self.CAPTURED_BASE, GITHUB_API
        d = self.state()
        d['view'].update(headRefOid=head, baseRefOid=base)
        d['api'] = {
            f'repos/acme/demo/contents/.github/pr-evidence.json?ref={base}': api['contents']['manifest_at_fdb6f03e'],
            f'repos/acme/demo/contents/{self.RECORD}?ref={head}': api['contents']['evidence_record'],
            f'repos/acme/demo/compare/{self.CANDIDATE}...{head}': api['compare']['ahead_evidence_only'],
            f'repos/acme/demo/compare/d013ed95cf65216a40deefcc2de9c6a4dd57f4ef...{head}': api['compare']['ahead_with_code'],
        }
        self.fixture_file.write_text(json.dumps(d))
        e = evidence()
        e.update(head_sha=head, base_sha=base)
        e['tests'][0]['sha'] = head
        if target_validation is not None:
            e['target_validation'] = target_validation
        self.evidence_file.write_text(json.dumps(e))

    def captured_record(self, **extra):
        tv = {'decision': 'required', 'artifact': self.RECORD, 'tested_revision': self.CANDIDATE,
              'reason': 'Changes playbooks/apply/os-patch-sla-apply.yml (AGENTS.md 1.4 actual-run rule)'}
        tv.update(extra)
        return tv

    def test_captured_pr_with_its_record_merges(self):
        self.use_captured_pr(self.captured_record())
        proc = self.script('review_gate.py', '--pr', '42', '--evidence', str(self.evidence_file))
        out = json.loads(proc.stdout)
        self.assertEqual(out['decision'], 'MERGE', out['reasons'])
        self.assertEqual([self.CANDIDATE], [d['from'] for d in out['target_validation']['delta_accepted']])
        calls = self.state()['api_calls']
        self.assertIn(f'repos/acme/demo/contents/.github/pr-evidence.json?ref={self.CAPTURED_BASE}', calls)
        self.assertNotIn(f'repos/acme/demo/contents/.github/pr-evidence.json?ref={self.CAPTURED_HEAD}', calls)

    def test_captured_pr_without_a_record_is_not_merged(self):
        self.use_captured_pr(None)
        proc, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'WAITING', proc.stderr)
        self.assertIn("requires the 'actual-run' record", ' '.join(out['gate']['reasons']))
        self.assertFalse(any(a[:2] in (['pr', 'merge'], ['pr', 'comment'], ['pr', 'ready'])
                             for a in self.state()['calls']))

    def test_captured_pr_record_of_an_older_candidate_waits(self):
        self.use_captured_pr(self.captured_record(tested_revision='d013ed95cf65216a40deefcc2de9c6a4dd57f4ef'))
        proc = self.script('review_gate.py', '--pr', '42', '--evidence', str(self.evidence_file))
        self.assertEqual(proc.returncode, 1)
        reasons = ' '.join(json.loads(proc.stdout)['reasons'])
        self.assertIn('does not cover HEAD', reasons)
        self.assertIn('playbooks/apply/os-patch-sla-apply.yml', reasons)
        # The record names d013ed9 as its baseline, so naming a SHA alone does not bind it: the
        # ancestry and evidence-only delta check is what refuses this.
        self.assertNotIn('does not name the tested revision', reasons)

    def test_ready_inventory_paginated(self):
        ready = {'number':42,'state':'open','draft':False,'html_url':'https://github.com/acme/demo/pull/42',
                 'title':'Fix A','head':{'sha':HEAD},'base':{'sha':BASE,'ref':'main'}}
        closed = dict(ready, number=20,state='closed')
        draft = dict(ready, number=30,draft=True)
        ready2 = dict(ready, number=50,title='Fix B')
        self.patch(pages=[[ready,draft],[ready2,closed]])
        proc = self.script('list_ready.py')
        self.assertEqual(proc.returncode,0,proc.stderr)
        arr = json.loads(proc.stdout)['pull_requests']
        self.assertEqual([a['number'] for a in arr],[42,50])

if __name__ == '__main__': unittest.main()
