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
if a[0] == 'api' and '/pulls?' in a[-1]:
    emit(d.get('pages', []))
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

    def script(self, name, *args):
        return subprocess.run([sys.executable, str(ROOT / 'scripts' / name), '--repo', 'acme/demo',
                               *args], env=self.env, capture_output=True, text=True)

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

    def test_real_merge_and_sha_guard(self):
        proc,out = self.actor(execute=True)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertEqual(out['outcome'],'MERGED')
        self.assertEqual(self.state()['view']['state'],'MERGED')
        merges = [a for a in self.state()['calls'] if a[:2]==['pr','merge']]
        self.assertEqual(len(merges),1)
        self.assertIn('--match-head-commit',merges[0])
        self.assertEqual(merges[0][merges[0].index('--match-head-commit')+1],HEAD)
        self.assertNotIn('--admin',merges[0]); self.assertNotIn('--auto',merges[0])

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

    def test_draft_comment_failure_prevents_downgrade(self):
        self.patch(fail_comment=True, checks=[{'name':'unit','state':'FAILURE','bucket':'fail'}])
        proc,out=self.actor(execute=True)
        self.assertEqual(out['outcome'],'ERROR')
        self.assertFalse(self.state()['view']['isDraft'])

    def test_merge_command_unconfirmed_not_succeeded(self):
        self.patch(simulate_merge_unconfirmed=True)
        proc,out=self.actor(execute=True)
        self.assertEqual(out['outcome'],'WAITING')
        self.assertNotEqual(self.state()['view']['state'],'MERGED')

    def test_branch_rules_error_fails_closed(self):
        self.patch(rules_error=True)
        proc,out=self.actor(execute=True)
        self.assertEqual(out['outcome'],'WAITING')
        self.assertFalse(any(a[:2]==['pr','merge'] for a in self.state()['calls']))

    def test_actor_lock_stays_in_the_test_state_dir(self):
        proc, out = self.actor(execute=True)
        self.assertEqual(out['outcome'], 'MERGED', proc.stderr)
        self.assertTrue(any((self.path / 'state' / 'locks').glob('*.lock')))

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
