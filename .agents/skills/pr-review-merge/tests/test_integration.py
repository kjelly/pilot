"""End-to-end tests of the CLI with a fake gh executable (no GitHub writes)."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
# The shared model of a PR's Ready-signal state (_shared/tests/ready_signal_world.py): the fake gh answers the
# signal's calls (the PR's timeline, the signal label's edits, the labels of `pr view`) from it.
SIGNAL_LIB = ROOT.parent / '_shared' / 'tests'
sys.path.append(str(SIGNAL_LIB))   # after this directory: _shared/tests has a test_secret_scan of its own
import ready_signal_world as rw  # noqa: E402
from signal_cases import LABEL, RECOVERY, Worlds  # noqa: E402
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
# The Ready signal's state (a ready_signal_world.World) lives beside this file's data, one per PR: the test
# directory's own is PR 42's, a `pr-<n>/` directory beside it holds the one of another PR.
STATE = p.parent
def world():
    sys.path.insert(0, os.environ['MOCK_GH_SIGNAL_LIB'])
    import ready_signal_world
    return ready_signal_world
def signal_state(number):
    special = STATE / f'pr-{number}'
    return special if special.is_dir() else STATE
if a[:1] == ['api'] and a[-1].split('?')[0].endswith('/timeline') and '--slurp' in a:
    persist(); sys.exit(world().handle(a, signal_state(a[-1].split('/issues/')[1].split('/')[0])))
if a[:2] == ['pr', 'edit'] and world().LABEL in a:
    persist(); sys.exit(world().handle(a, STATE))
if a[:2] == ['pr', 'view']:
    d['view_count'] = d.get('view_count', 0) + 1
    if d.get('race_on_view') == d['view_count']:
        d['view']['headRefOid'] = 'c'*40
    if d.get('drop_signal_on_view') == d['view_count']:
        rw = world(); w = rw.World.load(STATE); w.label(rw.OTHER, add=False); w.save(STATE)
    names = d.get('base_name_on_view', {})
    count = str(d['view_count'])
    if count in names:
        if names[count] is None:
            d['view'].pop('baseRefName', None)
        else:
            d['view']['baseRefName'] = names[count]
    # What `gh pr view --json labels` reports: the labels the PR carries (the listing below is a different
    # read, and lags it in real life).
    shown = dict(d['view'], labels=[{'name': n} for n in d.get('labels', [])] + world().view_labels(STATE))
    if d.get('draft_lag_left', 0) > 0:   # GitHub's read still shows the PR Ready after the Draft conversion
        d['draft_lag_left'] -= 1
        shown['isDraft'] = False
    emit(shown)
if a[:2] == ['pr', 'checks']:
    persist()
    # Answers recorded from real `gh pr checks` calls (fixtures/github_api.json, `pr_checks`): a PR with no
    # check at all is answered with rc 1, empty stdout and a stderr line, never with `[]`; `checks_capture`
    # replays any other recorded answer (an authentication, unknown-PR or network failure).
    answer = d.get('checks_capture') or (d['checks_zero'] if not d['checks'] else None)
    if answer:
        sys.stdout.write(answer['stdout']); sys.stderr.write(answer['stderr']); sys.exit(answer['rc'])
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
if a[0] == 'api' and a[-1] == 'user':
    emit({'login': d.get('viewer', 'prm-bot')})
if a[0] == 'api' and '/issues/' in a[-1] and '/comments?' in a[-1]:
    if d.get('comments_error'):
        persist(); print('comments unavailable', file=sys.stderr); sys.exit(1)
    number = a[-1].split('/issues/')[1].split('/')[0]
    emit([d.get('issue_comments', {}).get(number, [])])
if a[0] == 'api' and '/issues?' in a[-1]:
    label = a[-1].split('labels=')[1].split('&')[0]
    d['listing_reads'] = d.get('listing_reads', 0) + 1
    lagging = d['listing_reads'] <= d.get('listing_lag', 0)   # the issues listing lags the label write
    emit([[{'number': d['view']['number'], 'pull_request': {}}] if label in d.get('labels', []) and not lagging else []])
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
    # The same comment as the issues comments API lists it, authored by the account gh runs as.
    d.setdefault('issue_comments', {}).setdefault(a[2], []).append(
        {'body': Path(path).read_text(), 'user': {'login': d.get('viewer', 'prm-bot')}})
    persist(); sys.exit(0)
if a[:2] == ['pr', 'ready']:
    if d.get('fail_draft'):
        persist(); print('draft denied', file=sys.stderr); sys.exit(1)
    if not d.get('draft_unconfirmed'):   # accepted, but the PR never shows the Draft state
        d['view']['isDraft'] = True
        d['draft_lag_left'] = d.get('draft_lag', 0)
        rw = world(); w = rw.World.load(STATE); w.log('draft'); w.to_draft(); w.save(STATE)
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
            'checks_zero': GITHUB_API['pr_checks']['zero_checks'],
            'rules':[], 'threads':0, 'api': {},
            'not_found': GITHUB_API['contents']['manifest_absent_at_d013ed95']}


class IntegrationBase(unittest.TestCase):
    """The fake gh executable and the per-test state directory; no tests of its own, so a subclass
    does not run another class's tests again."""

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
        # `PRM_TEST_READ_INTERVAL`: the actor's wait between two reads of a write that GitHub shows late is
        # not taken (scan_stub_runner.py); the bound on the number of reads stays.
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ.get('PATH','')}",
                        MOCK_GH_DATA=str(self.fixture_file), PRM_STATE_DIR=state,
                        MOCK_GH_SIGNAL_LIB=str(SIGNAL_LIB), PRM_TEST_READ_INTERVAL='0')
        previous = os.environ.get('PRM_STATE_DIR')
        os.environ['PRM_STATE_DIR'] = state
        self.addCleanup(lambda: os.environ.__setitem__('PRM_STATE_DIR', previous) if previous is not None
                        else os.environ.pop('PRM_STATE_DIR', None))
        self.sign()   # the PR got to Ready through a verified Draft -> Ready step: the default for every PR below

    def sign(self, head=HEAD, *, number=42, producer='pr-ready', actor=None):
        """The Ready signal of PR `number` as a producer leaves it: Draft -> Ready, the marker comment naming
        `head`, then the label. The account `gh` runs as is `prm-bot` (the fake's `api user`)."""
        world = rw.World(head=head, viewer='prm-bot', number=number)
        world.signed_ready(producer=producer, actor=actor)
        self.save_world(world, number)
        return world

    def save_world(self, world, number=42):
        folder = self.path if number == 42 else self.path / f'pr-{number}'
        folder.mkdir(exist_ok=True)
        world.save(folder)

    def world(self, number=42):
        return rw.World.load(self.path if number == 42 else self.path / f'pr-{number}')

    def mutations(self):
        """The `gh` calls that write to the PR, in the order they were made."""
        return [a for a in self.state().get('calls', []) if a[:2] in
                (['pr', 'comment'], ['pr', 'edit'], ['pr', 'ready'], ['pr', 'merge'])]

    def world_writes(self, number=42):
        """What was written to the PR's Ready-signal state (the label, a comment, the Draft conversion)."""
        return [op for op in self.world(number).calls() if op in ('add-label', 'remove-label', 'comment', 'draft')]

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


class Integration(IntegrationBase):
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

    def test_a_listing_that_lags_the_label_write_does_not_make_the_actor_report_an_error(self):
        # Seen live on #271: the issues listing lagged the label write by seconds, the actor read it and
        # reported ERROR for a PR that was enqueued. The PR itself shows its label at once.
        self.patch(listing_lag=1000)
        proc, out = self.actor(execute=True)
        self.assertEqual((proc.returncode, out['outcome'], out['verified_remote_state']), (0, 'ENQUEUED', 'ENQUEUED'),
                         proc.stdout + proc.stderr)
        d = self.state()
        self.assertEqual(d['labels'], ['merge-queue'])
        self.assertIn('Merge train: enqueued', d['comments'][0])
        self.assertEqual(0, d.get('listing_reads', 0), 'the actor must not depend on the issues listing')

    def test_an_enqueued_comment_that_fails_after_the_label_is_a_warning(self):
        self.patch(fail_comment=True)
        proc, out = self.actor(execute=True)
        self.assertEqual((proc.returncode, out['outcome']), (0, 'ENQUEUED'), proc.stdout + proc.stderr)
        self.assertIn('could not be posted', out['warnings'][0])
        self.assertIn('comment denied', out['warnings'][0])
        self.assertEqual(self.state()['labels'], ['merge-queue'])
        sys.path.insert(0, str(ROOT / 'scripts'))
        import merge_train
        from gh_runtime import Repo
        self.assertIsNotNone(merge_train.load_entry(Repo.parse('acme/demo'), 42), 'the saved evidence is kept')

    def test_a_state_directory_that_cannot_hold_the_entry_is_a_structured_error_not_a_traceback(self):
        # The saved entry is written first, under the real lock. When that fails (a full disk, a queue
        # directory that is a file) the command must still print its JSON and exit 2.
        state = Path(self.env['PRM_STATE_DIR'])
        state.mkdir(parents=True)
        (state / 'queue').write_text('not a directory')
        proc = self.script('apply_decision.py', '--pr', '42', '--evidence', str(self.evidence_file), '--execute')
        self.assertNotIn('Traceback', proc.stderr)
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(('ERROR', 'NotADirectoryError'), (out['outcome'], out['error_kind']), out)
        self.assertIn('queue', out['error'])
        self.assertFalse(self.state().get('labels'), 'nothing was labelled')
        self.assertFalse(self.state().get('comments'))

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
        self.conflict(race_on_view=5)   # the view read after the comment (the 3rd is the signal's, the 4th the one before the action)
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
                    d['base_name_on_view'] = {'4': name}   # the view read right before the action (the 3rd is the signal's)
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
                    d['base_name_on_view'] = {'5': name}   # the view read after the comment (the 4th is the one before the action)
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

    def test_pr_loop_task_result_for_pending_ci_leaves_ready(self):
        self.patch(checks=[{'name': 'lint', 'state': 'PENDING', 'bucket': 'pending'}])
        task = self.path / (".pr-loop/" + "2" * 32) / "task.json"
        task.parent.mkdir(parents=True)
        task.write_text(json.dumps(dict(version=1, repo="acme/demo", pr=42, phase="ready",
                                        nonce="2" * 32, start_head=HEAD)))
        proc = self.script("apply_decision.py", "--pr", "42", "--evidence", str(self.evidence_file),
                           "--execute", "--pr-loop-task", str(task))
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        result = json.loads(task.with_name("result.json").read_text())
        self.assertEqual("WAITING", result["outcome"])
        self.assertEqual("transient", result["wait_kind"])
        self.assertEqual(HEAD, result["head_sha"])
        self.assertFalse(result["person_handoff"])
        self.assertFalse(self.state().get("comments"))
        self.assertFalse(self.state()["view"]["isDraft"])

    # ---- pr-loop `--pr-loop-task`: bound before any gh call, one result, no change to the actor ----

    LOOP_START = 'c' * 40   # differs from the PR HEAD: a result must carry the HEAD the gate judged

    @staticmethod
    def loop_nonce(name):
        """The nonce (and so the directory name) of the task called `name`."""
        return hashlib.sha256(name.encode()).hexdigest()[:32]

    def loop_task(self, name='fixture', **overrides):
        body = dict(version=1, repo='acme/demo', pr=42, phase='ready', nonce=self.loop_nonce(name),
                    start_head=self.LOOP_START)
        body.update(overrides)
        task = self.path / '.pr-loop' / self.loop_nonce(name) / 'task.json'
        task.parent.mkdir(parents=True, exist_ok=True)
        task.write_text(json.dumps(body))
        return task

    def loop_actor(self, task, *extra, flag=True):
        args = ['--pr', '42', '--evidence', str(self.evidence_file), '--execute', *extra]
        if flag:
            args += ['--pr-loop-task', str(task)]
        return self.script('apply_decision.py', *args)

    def published(self, task):
        return json.loads(task.with_name('result.json').read_text())

    def gh_calls(self):
        return self.state().get('calls', [])

    def test_pr_loop_task_invalid_task_makes_no_gh_call_and_changes_nothing(self):
        refused = {
            'another repository': (dict(repo='acme/other'), 'pr-loop task does not match this PR invocation'),
            'another PR': (dict(pr=43), 'pr-loop task does not match this PR invocation'),
            'the draft phase': (dict(phase='draft'), 'pr-loop task does not match this PR invocation'),
            'a short nonce': (dict(nonce='2' * 31), 'pr-loop task does not match this PR invocation'),
            'a valid nonce that is not the directory\'s': (dict(nonce='4' * 32),
                                                          'pr-loop task nonce does not match its directory'),
        }
        for case, (overrides, reason) in refused.items():
            with self.subTest(case=case):
                self.fixture_file.write_text(json.dumps(fixture()))
                task = self.loop_task(case.replace(' ', '-'), **overrides)
                proc = self.loop_actor(task)
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                out = json.loads(proc.stdout)
                self.assertEqual(('ERROR', 'ValueError', reason), (out['outcome'], out['error_kind'], out['error']))
                self.assertEqual([], self.gh_calls(), 'the task is bound before the first gh call')
                self.assertFalse(task.with_name('result.json').exists())
                self.assertFalse((Path(self.env['PRM_STATE_DIR']) / 'queue').exists(), 'nothing was saved for the train')

    def test_pr_loop_task_at_a_wrong_path_or_that_is_unreadable_makes_no_gh_call(self):
        wrong = self.loop_task('layout')
        wrong = wrong.rename(wrong.with_name('job.json'))
        invalid = self.loop_task('json')
        invalid.write_text('{not json')
        misplaced = self.loop_task('misplaced')   # a valid task, outside <checkout>/.pr-loop/
        moved = self.path / 'elsewhere' / misplaced.parent.name
        moved.parent.mkdir()
        misplaced.parent.rename(moved)
        misplaced = moved / 'task.json'
        for case, task, needle in (('wrong file name', wrong, 'expected the absolute path of <checkout>/.pr-loop/<nonce>/task.json'),
                                   ('wrong directory', misplaced,
                                    'expected the absolute path of <checkout>/.pr-loop/<nonce>/task.json'),
                                   ('not json', invalid, 'Expecting property name'),
                                   ('missing file', self.path / '.pr-loop' / ('3' * 32) / 'task.json',
                                    'No such file or directory')):
            with self.subTest(case=case):
                proc = self.loop_actor(task)
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                out = json.loads(proc.stdout)
                self.assertEqual('ERROR', out['outcome'])
                self.assertIn(needle, out['error'])
                self.assertEqual([], self.gh_calls())

    def test_pr_loop_task_valid_task_is_the_control_of_the_refusals_above(self):
        task = self.loop_task()
        proc = self.loop_actor(task)
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual('ENQUEUED', json.loads(proc.stdout)['outcome'])
        self.assertIn(['pr', 'view'], [call[:2] for call in self.gh_calls()])

    def test_pr_loop_task_loop_task_requires_execute(self):
        task = self.loop_task()
        proc = self.script('apply_decision.py', '--pr', '42', '--evidence', str(self.evidence_file),
                           '--pr-loop-task', str(task))
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual('', proc.stdout)
        self.assertIn('error: --pr-loop-task requires --execute', proc.stderr)
        self.assertEqual([], self.gh_calls())
        self.assertFalse(task.with_name('result.json').exists())

    def loop_scenario(self, name):
        """Set up one actor outcome; returns (expected outcome, expected exit code, extra expectations)."""
        if name == 'ENQUEUED':
            return 'ENQUEUED', 0, {'wait_kind': '', 'person_handoff': False, 'head_sha': HEAD}
        if name == 'DRAFT-BLOCKED':
            self.patch(checks=[{'name': 'lint', 'state': 'FAILURE', 'bucket': 'fail'}])
            return 'DRAFT', 0, {'wait_kind': '', 'person_handoff': False, 'head_sha': HEAD}
        if name == 'SKIP':
            d = self.state()
            d['view']['isDraft'] = True
            self.fixture_file.write_text(json.dumps(d))
            return 'SKIP', 0, {'wait_kind': '', 'person_handoff': False, 'head_sha': HEAD}
        if name == 'WAITING-person':
            d = self.state()
            d['view']['reviewDecision'] = 'CHANGES_REQUESTED'
            self.fixture_file.write_text(json.dumps(d))
            return 'WAITING', 1, {'wait_kind': 'person', 'person_handoff': True, 'head_sha': HEAD}
        if name == 'WAITING-transient':
            self.patch(checks=[{'name': 'lint', 'state': 'PENDING', 'bucket': 'pending'}])
            return 'WAITING', 1, {'wait_kind': 'transient', 'person_handoff': False, 'head_sha': HEAD}
        if name == 'ERROR-returned':
            self.patch(fail_label=True)
            return 'ERROR', 1, {'wait_kind': '', 'person_handoff': False, 'head_sha': HEAD}
        raise AssertionError(name)

    def test_pr_loop_task_publishes_the_outcome_wait_hand_off_and_judged_head(self):
        for name in ('ENQUEUED', 'DRAFT-BLOCKED', 'SKIP', 'WAITING-person', 'WAITING-transient', 'ERROR-returned'):
            with self.subTest(scenario=name):
                self.fixture_file.write_text(json.dumps(fixture()))
                self.sign()   # the Draft scenario takes the signal's label off: each scenario starts signed
                outcome, code, expected = self.loop_scenario(name)
                task = self.loop_task(name.lower())
                proc = self.loop_actor(task)
                self.assertEqual(code, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual('', proc.stderr)
                report = json.loads(proc.stdout)
                result = self.published(task)
                self.assertEqual(outcome, result['outcome'])
                wanted = dict(expected, phase='ready', start_head=self.LOOP_START, nonce=task.parent.name,
                              pr=42, repo='acme/demo', version=1)
                self.assertEqual(wanted, {key: result[key] for key in wanted})
                self.assertNotEqual(result['start_head'], result['head_sha'], 'the judged HEAD, not the starting one')
                self.assertEqual({'version', 'repo', 'pr', 'phase', 'nonce', 'start_head', 'head_sha', 'outcome',
                                  'reason', 'wait_kind', 'person_handoff'}, set(result))
                self.assertTrue(result['reason'])
                if name == 'DRAFT-BLOCKED':
                    self.assertEqual('DRAFT-BLOCKED', report['outcome'], 'the actor still reports its own word')
                    self.assertIn('lint', result['reason'])
                if name == 'WAITING-person':
                    self.assertIn('CHANGES_REQUESTED', result['reason'])
                    self.assertEqual('needs-person', report['handoff'])
                if name == 'SKIP':
                    self.assertEqual('PR is not an open non-draft PR', result['reason'])
                if name == 'ERROR-returned':
                    self.assertIn('label denied', report['error'] + result['reason'])
                    self.assertEqual(report['error'], result['reason'])

    def test_pr_loop_task_an_exception_is_published_as_error(self):
        state = Path(self.env['PRM_STATE_DIR'])
        state.mkdir(parents=True)
        (state / 'queue').write_text('not a directory')
        task = self.loop_task('exception', start_head=HEAD)
        proc = self.loop_actor(task)
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(('ERROR', 'NotADirectoryError'), (report['outcome'], report['error_kind']))
        result = self.published(task)
        self.assertEqual(('ERROR', HEAD, False, ''), (result['outcome'], result['head_sha'],
                                                      result['person_handoff'], result['wait_kind']))
        self.assertIn('queue', result['reason'])
        self.assertEqual(report['error'], result['reason'])

    def normalized_run(self, scenario, task, *, flag):
        """One actor run from a fresh fixture and a fresh state directory: what it printed, its exit code and
        what it did to GitHub (the fake gh's call log and final state), with the temporary comment file's path
        (the one per-run value) masked."""
        self.fixture_file.write_text(json.dumps(fixture()))
        self.sign()   # each run starts from a signed PR: the Draft scenario takes the signal's label off
        state = self.path / f'state-{scenario}'   # the same path both times: an error message may name it
        shutil.rmtree(state, ignore_errors=True)
        state.mkdir()
        if scenario == 'ERROR-exception':
            (state / 'queue').write_text('not a directory')
        else:
            self.loop_scenario(scenario)
        self.env['PRM_STATE_DIR'] = str(state)
        proc = self.loop_actor(task, flag=flag)
        final = self.state()
        for call in final.get('calls', []):
            if '--body-file' in call:
                call[call.index('--body-file') + 1] = '<comment file>'
        return {'returncode': proc.returncode, 'stdout': json.loads(proc.stdout), 'gh': final}, proc

    def test_pr_loop_task_flag_changes_neither_stdout_nor_exit_code_nor_gh_calls(self):
        for scenario in ('ENQUEUED', 'DRAFT-BLOCKED', 'SKIP', 'WAITING-person', 'WAITING-transient',
                         'ERROR-returned', 'ERROR-exception'):
            with self.subTest(scenario=scenario):
                task = self.loop_task(scenario.lower())
                without, _ = self.normalized_run(scenario, task, flag=False)
                self.assertFalse(task.with_name('result.json').exists(), 'no flag, no result')
                with_flag, proc = self.normalized_run(scenario, task, flag=True)
                self.assertEqual('', proc.stderr)
                self.assertTrue(task.with_name('result.json').exists())
                self.assertEqual(without, with_flag)
                self.assertTrue(without['gh'].get('calls'), 'the scenario really ran against the fake gh')

    def test_pr_loop_task_a_result_that_cannot_be_published_does_not_change_the_actor(self):
        task = self.loop_task()
        without, _ = self.normalized_run('ENQUEUED', task, flag=False)
        earlier = task.with_name('result.json')
        earlier.write_text("an earlier invocation's result\n")
        with_flag, proc = self.normalized_run('ENQUEUED', task, flag=True)
        self.assertEqual(without, with_flag)
        self.assertEqual(0, proc.returncode)
        self.assertEqual('pr-loop result could not be published: this pr-loop task already has a different result\n',
                         proc.stderr)
        self.assertEqual("an earlier invocation's result\n", earlier.read_text())

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
        self.patch(race_on_view=4)   # the view read right before the action (the 3rd is the signal's)
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
        self.sign(head)   # signed at its tail, as pr-ready leaves it
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
        self.assertFalse(any(a[:2] in (['pr', 'merge'], ['pr', 'ready']) for a in self.state()['calls']))
        # No reviewer finding drafts it. The evidence has no target_validation at all: the next review
        # run can supply it, so this is the merge train's `person` but no hand-off (no comment, no label).
        self.assertEqual(('person', None), (out['wait_kind'], out.get('handoff')), out)
        self.assertFalse(out['gate']['person_handoff'])
        d = self.state()
        self.assertFalse(d.get('labels'))
        self.assertFalse(d.get('comments'))

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

    # ---- the Ready signal: the actor acts only on a Ready PR that pr-ready (or mark_ready.py) verified ----

    def test_a_valid_signal_is_the_control_of_the_refusals_below(self):
        proc, out = self.actor(execute=True)
        self.assertEqual((0, 'ENQUEUED'), (proc.returncode, out['outcome']), proc.stdout + proc.stderr)
        seen = out['gate']['ready_signal']
        self.assertEqual(('valid', HEAD, 'pr-ready'), (seen['state'], seen['marker_head'], seen['producer']))
        self.assertEqual(2, self.world().calls().count('timeline'), 'after the gate, and again right before the action')
        self.assertIn(['api', 'user'], self.gh_calls())
        self.assertEqual(['edit', 'comment'], [a[1] for a in self.mutations()])

    def refused(self, proc, out, fragment, *, way_back=True):
        """`way_back`: the refusal is about the signal and says how to get one (False: nothing is known about the
        signal, the reads failed or the PR moved, and the refusal says to run again)."""
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual(('WAITING', 'transient', False, False),
                         (out['outcome'], out.get('wait_kind'), out['gate'].get('person_handoff'), out['executed']))
        reason = out['gate']['reasons'][0]
        self.assertEqual([reason], out['gate']['reasons'])
        self.assertIn(fragment, reason)
        for needle in RECOVERY if way_back else ('run again',):
            self.assertIn(needle, reason)
        for key in ('handoff', 'comment_posted', 'enqueued', 'warnings', 'error'):
            self.assertNotIn(key, out)
        # Nothing was written: not one gh call that writes, nothing in the signal's own state, nothing saved
        # for the merge train.
        self.assertEqual([], self.mutations())
        self.assertEqual([], self.world_writes())
        self.assertFalse((Path(self.env['PRM_STATE_DIR']) / 'queue').exists())

    def test_a_pr_without_a_valid_signal_is_waiting_nothing_is_written_and_the_pr_loop_is_told(self):
        for name, (builder, state, fragment) in Worlds.CASES.items():
            with self.subTest(signal=name):
                self.fixture_file.write_text(json.dumps(fixture()))
                self.save_world(getattr(Worlds, builder)(HEAD))
                task = self.loop_task(name.replace(' ', '-'))
                proc = self.loop_actor(task)
                out = json.loads(proc.stdout)
                self.refused(proc, out, fragment)
                self.assertEqual(state, out['gate']['ready_signal']['state'])
                self.assertEqual('MERGE', out['gate'].get('underlying', {}).get('decision'), 'only the signal stands in the way')
                result = self.published(task)
                self.assertEqual(('WAITING', 'transient', False, HEAD),
                                 (result['outcome'], result['wait_kind'], result['person_handoff'], result['head_sha']))
                for needle in (fragment, *RECOVERY):
                    self.assertIn(needle, result['reason'], 'what the pr-loop reads names the way back')

    def test_a_pr_without_a_valid_signal_is_not_drafted_or_handed_off_either(self):
        for name in ('DRAFT-BLOCKED', 'WAITING-person', 'WAITING-transient'):
            with self.subTest(decision=name):
                self.fixture_file.write_text(json.dumps(fixture()))
                self.save_world(Worlds.never_signed(HEAD))
                self.loop_scenario(name)
                proc, out = self.actor(execute=True)
                self.refused(proc, out, f'does not carry the {LABEL} label')
                self.assertEqual({'DRAFT-BLOCKED': 'DRAFT'}.get(name, 'WAITING'), out['gate'].get('underlying', {}).get('decision'))

    def test_a_dry_run_reports_the_refusal_too(self):
        self.save_world(Worlds.never_signed(HEAD))
        proc, out = self.actor()
        self.refused(proc, out, f'does not carry the {LABEL} label')

    def test_a_head_that_moves_before_the_first_look_waits_without_a_write(self):
        self.patch(race_on_view=3)   # the view of the first look: the gate's two views come before
        proc, out = self.actor(execute=True)
        self.refused(proc, out, 'after the gate judged it', way_back=False)
        self.assertEqual(0, self.world().calls().count('timeline'), 'the signal of a PR that is not the one judged is not read')

    def test_a_label_removed_after_the_first_look_stops_the_action(self):
        self.patch(drop_signal_on_view=4)   # GitHub changes between the first look (3rd view) and the action (4th)
        proc, out = self.actor(execute=True)
        self.refused(proc, out, f'does not carry the {LABEL} label')
        self.assertEqual(2, self.world().calls().count('timeline'), 'the refusal is the second look')
        self.assertEqual(['unlabeled'], [e['event'] for e in self.world().s['events'][-1:]])

    def test_the_read_only_gate_applies_the_signal_too(self):
        self.save_world(Worlds.never_signed(HEAD))
        proc = self.script('review_gate.py', '--pr', '42', '--evidence', str(self.evidence_file))
        out = json.loads(proc.stdout)
        self.assertEqual((1, 'WAITING', 'transient', False), (proc.returncode, out['decision'], out.get('wait_kind'), out.get('person_handoff')))
        self.assertEqual('MERGE', out.get('underlying', {}).get('decision'))
        self.assertIn(f'does not carry the {LABEL} label', out['reasons'][0])
        self.assertEqual([], self.mutations())
        self.save_world(Worlds.valid(HEAD))
        proc = self.script('review_gate.py', '--pr', '42', '--evidence', str(self.evidence_file))
        self.assertEqual((0, 'MERGE'), (proc.returncode, json.loads(proc.stdout)['decision']))

    # The captured PR #177: its tail is the candidate 2d70670 plus an evidence-only commit, and d013ed95 is an
    # earlier commit that GitHub's compare shows differing in code (the real `compare` answers of the fixtures).
    def test_a_signal_for_an_earlier_head_carries_across_an_evidence_only_delta(self):
        self.use_captured_pr(self.captured_record())
        self.sign(self.CANDIDATE)
        proc, out = self.actor(execute=True)
        self.assertEqual((0, 'ENQUEUED'), (proc.returncode, out['outcome']), proc.stdout + proc.stderr)
        seen = out['gate']['ready_signal']
        self.assertEqual(('stale', self.CANDIDATE), (seen['state'], seen['marker_head']))
        self.assertTrue(seen['carried'])

    def test_a_stale_signal_whose_coverage_cannot_be_read_waits_without_a_write(self):
        # The PR moved to 'd'*40 after the signal and has been reviewed there (the gate says MERGE). Whether that HEAD
        # is covered by the signal's takes GitHub's compare, which the fake gh answers without the files list the real
        # one gives: the reads fail and the PR is left alone (the refusal for a real code change is asserted over
        # real Git in test_ready_signal_gate.py: this harness has no capture of the base-to-HEAD compare it needs).
        new = 'd' * 40
        data = self.state()
        data['view']['headRefOid'] = new
        self.fixture_file.write_text(json.dumps(data))
        e = evidence()
        e['head_sha'] = new
        e['tests'][0]['sha'] = new
        self.evidence_file.write_text(json.dumps(e))
        proc, out = self.actor(execute=True)
        self.refused(proc, out, 'Invalid compare response', way_back=False)
        self.assertEqual('MERGE', out['gate'].get('underlying', {}).get('decision'))
        self.assertEqual('stale', out['gate']['ready_signal']['state'])

    # ---- the Draft path takes the label off, once the Draft is confirmed ----

    FAILING = [{'name': 'lint', 'state': 'FAILURE', 'bucket': 'fail'}]

    def test_a_draft_takes_the_signals_label_off_after_the_comment_and_the_draft(self):
        self.patch(checks=self.FAILING)
        proc, out = self.actor(execute=True)
        self.assertEqual((0, 'DRAFT-BLOCKED', 'released'), (proc.returncode, out['outcome'], out.get('ready_label')), proc.stdout)
        mutations = self.mutations()
        self.assertEqual(['comment', 'ready', 'edit'], [a[1] for a in mutations])
        self.assertEqual(['--remove-label', LABEL], mutations[-1][-2:])
        world = self.world()
        self.assertEqual([], world.label_names())
        self.assertEqual(['draft', 'remove-label'], [op for op in world.calls() if op in ('draft', 'remove-label')])
        self.assertNotIn('warnings', out)

    def test_the_label_goes_only_after_the_draft_was_read_back(self):
        self.patch(checks=self.FAILING, draft_lag=2)   # the PR shows the Draft only at the 3rd read after the conversion
        proc, out = self.actor(execute=True)
        self.assertEqual((0, 'DRAFT-BLOCKED'), (proc.returncode, out['outcome']), proc.stdout)
        names = [' '.join(a[:2]) for a in self.gh_calls()]
        after = [n for n in names[names.index('pr ready'):] if n in ('pr ready', 'pr view', 'pr edit')]
        self.assertEqual(['pr ready', 'pr view', 'pr view', 'pr view', 'pr edit'], after)
        self.assertEqual([], self.world().label_names())

    def test_a_draft_that_is_never_shown_keeps_the_label(self):
        self.patch(checks=self.FAILING, draft_unconfirmed=True)
        proc, out = self.actor(execute=True)
        self.assertEqual((1, 'ERROR'), (proc.returncode, out['outcome']), proc.stdout)
        self.assertIn('Draft state was not confirmed', out['error'])
        self.assertEqual(['comment', 'ready'], [a[1] for a in self.mutations()], 'no label call: the PR is not known to be a Draft')
        self.assertEqual([LABEL], self.world().label_names())
        self.assertNotIn('remove-label', self.world().calls())

    def test_a_label_that_cannot_be_removed_is_a_warning_and_not_retried(self):
        self.patch(checks=self.FAILING)
        world = self.world()
        world.fail('remove-label')
        self.save_world(world)
        proc, out = self.actor(execute=True)
        self.assertEqual((0, 'DRAFT-BLOCKED', True), (proc.returncode, out['outcome'], out['executed']), proc.stdout)
        self.assertNotIn('error', out)
        self.assertEqual(1, len(out.get('warnings', [])), out)
        for needle in (f'The `{LABEL}` label could not be removed', 'HTTP 502', 'pr-ready removes it before'):
            self.assertIn(needle, out['warnings'][0])
        self.assertEqual(1, self.world().calls().count('remove-label'), 'one attempt')
        self.assertEqual([LABEL], self.world().label_names())

    def test_enqueueing_leaves_the_signals_label_on(self):
        proc, out = self.actor(execute=True)
        self.assertEqual('ENQUEUED', out['outcome'], proc.stdout)
        self.assertEqual([LABEL], self.world().label_names())
        self.assertNotIn('remove-label', self.world().calls())

    def test_ready_inventory_paginated(self):
        ready = {'number':42,'state':'open','draft':False,'html_url':'https://github.com/acme/demo/pull/42',
                 'title':'Fix A','head':{'sha':HEAD},'base':{'sha':BASE,'ref':'main'},
                 'labels':[rw.LABEL_CAPTURE]}
        closed = dict(ready, number=20,state='closed')
        draft = dict(ready, number=30,draft=True)
        ready2 = dict(ready, number=50,title='Fix B')
        self.patch(pages=[[ready,draft],[ready2,closed]])
        proc = self.script('list_ready.py')
        self.assertEqual(proc.returncode,0,proc.stderr)
        arr = json.loads(proc.stdout)['pull_requests']
        self.assertEqual([a['number'] for a in arr],[42,50])


class ReadySignalListing(IntegrationBase):
    """`list_ready.py` lists a Ready PR only when its Ready signal holds: order is the queue, then the signal, then
    the needs-person wait. A PR without the signal's label costs no timeline read."""

    def pr(self, number, *, signed=True, labels=(), head=HEAD):
        """The PR as the pulls listing shows it: `signed` gives it the signal's label (a real label object)."""
        return {'number': number, 'state': 'open', 'draft': False, 'html_url': f'u{number}', 'title': f't{number}',
                'labels': ([rw.LABEL_CAPTURE] if signed else []) + [{'name': name} for name in labels],
                'head': {'sha': head}, 'base': {'sha': BASE, 'ref': 'main'}}

    def listing(self, *prs):
        self.patch(pages=[list(prs)])
        proc = self.script('list_ready.py')
        return proc, json.loads(proc.stdout)

    def urls(self):
        return [a[-1] for a in self.state().get('calls', []) if a[0] == 'api']

    def test_a_pr_without_the_label_is_excluded_and_no_timeline_is_read(self):
        proc, out = self.listing(self.pr(42, signed=False))
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual([], out['pull_requests'])
        self.assertEqual([{'number': 42, 'reason': f'ready signal absent: the PR does not carry the {LABEL} label; '
                                                   'convert the PR to Draft and run pr-ready again to have it verified and signed'}],
                         out['excluded'])
        self.assertEqual([], [u for u in self.urls() if '/timeline' in u or u == 'user'], 'not the timeline, not the account')
        self.assertEqual(0, self.world().calls().count('timeline'))

    def test_the_state_of_the_signal_decides_the_listing(self):
        cases = {1: ('valid', 'valid', {}),
                 2: ('stale', 'valid', {'stale_ready_signal': True}),
                 3: ('label by another account', None, 'was added by someone-else'),
                 4: ('earlier Ready epoch', None, "before the PR's last Ready transition"),
                 5: ('created Ready', None, 'no Ready transition from Draft'),
                 6: ('marker by another account', None, 'no signal comment by prm-bot'),
                 7: ('back to Draft', None, 'converted to Draft after its last Ready transition'),
                 8: ('newer Ready after the signal', None, 'certifies Ready transition'),
                 9: ('Draft, base-import push, Ready', None, 'certifies Ready transition')}
        prs = []
        for number, (name, listed, extra) in cases.items():
            if name == 'valid':
                self.save_world(Worlds.valid(HEAD), number)
            elif name == 'stale':
                self.save_world(Worlds.valid('b' * 40), number)    # signed at an earlier HEAD
            else:
                self.save_world(getattr(Worlds, Worlds.CASES[name][0])(HEAD), number)
            prs.append(self.pr(number))
        proc, out = self.listing(*prs)
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual({1: False, 2: True}, {p['number']: p.get('stale_ready_signal', False) for p in out['pull_requests']})
        excluded = {e['number']: e['reason'] for e in out['excluded']}
        self.assertEqual({3, 4, 5, 6, 7, 8, 9}, set(excluded))
        for number in (3, 4, 5, 6, 7, 8, 9):
            expected = cases[number][2]
            self.assertIn(expected, excluded[number])
            self.assertTrue(excluded[number].startswith(f'ready signal {Worlds.CASES[cases[number][0]][1]}: '), excluded[number])
            self.assertIn('convert the PR to Draft and run pr-ready again', excluded[number])
        self.assertEqual(1, self.urls().count('user'), 'the account is read once per listing')

    def test_the_order_is_the_queue_then_the_signal_then_the_needs_person_wait(self):
        marker = NeedsPersonHandoff.marker_comment
        queued_unsigned = self.pr(1, signed=False, labels=['merge-queue'])
        waiting_unsigned = self.pr(2, signed=False, labels=['needs-person'])
        waiting_signed = self.pr(3, labels=['needs-person'])
        queued_signed = self.pr(4, labels=['merge-queue'])
        self.save_world(Worlds.valid(HEAD), 3)
        self.save_world(Worlds.valid(HEAD), 4)
        self.patch(issue_comments={'2': [marker(self, 'prm-bot')], '3': [marker(self, 'prm-bot')]})
        proc, out = self.listing(queued_unsigned, waiting_unsigned, waiting_signed, queued_signed)
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual([], out['pull_requests'])
        reasons = {e['number']: e['reason'] for e in out['excluded']}
        self.assertEqual('merge-queue: the merge train owns it', reasons[1])
        self.assertTrue(reasons[2].startswith('ready signal absent: '), 'the signal comes before the wait: ' + reasons[2])
        self.assertTrue(reasons[3].startswith(f'needs-person: waiting for a person at HEAD {HEAD[:12]}'), reasons[3])
        self.assertEqual('merge-queue: the merge train owns it', reasons[4])
        reads = self.urls()
        self.assertEqual(['repos/acme/demo/issues/3/comments?per_page=100'], [u for u in reads if '/comments' in u],
                         'only the signalled PR waiting for a person had its comments read')
        self.assertEqual(['repos/acme/demo/issues/3/timeline?per_page=100'], [u for u in reads if '/timeline' in u],
                         'no timeline for a PR the queue owns or that has no label')

    def test_a_timeline_that_cannot_be_read_fails_the_listing(self):
        world = Worlds.valid(HEAD)
        world.fail('timeline')
        self.save_world(world)
        proc, out = self.listing(self.pr(42))
        self.assertEqual(2, proc.returncode)
        self.assertEqual([], out['pull_requests'])
        self.assertIn('failed', out['error'])

    def test_a_timeline_entry_of_an_unexpected_shape_excludes_that_pr_alone(self):
        broken = Worlds.valid(HEAD)
        broken.s['events'].append({'event': 'commented', 'user': 'not an object', 'body': 'x'})
        self.save_world(broken, 7)
        self.save_world(Worlds.valid(HEAD), 8)
        proc, out = self.listing(self.pr(7), self.pr(8))
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual([8], [p['number'] for p in out['pull_requests']])
        self.assertEqual([(7, 'ready signal unreadable: ')], [(e['number'], e['reason'][:25]) for e in out['excluded']])
        self.assertIn('malformed user', out['excluded'][0]['reason'])

    def test_listing_is_read_only(self):
        self.save_world(Worlds.valid(HEAD))
        self.listing(self.pr(42))
        self.assertEqual([], self.mutations())
        self.assertEqual([], self.world_writes())


class NeedsPersonHandoff(IntegrationBase):
    """A WAITING gate that waits for a person leaves the PR Ready with a comment and the `needs-person`
    label; DRAFT, ENQUEUED and a transient WAITING take the label off again."""

    def waits_for_a_person(self, **kwargs):
        d = self.state()
        d['view']['reviewDecision'] = 'CHANGES_REQUESTED'
        d.update(kwargs)
        self.fixture_file.write_text(json.dumps(d))

    def marker_comment(self, login, head=HEAD):
        sys.path.insert(0, str(ROOT / 'scripts'))
        import needs_person
        body = needs_person.comment_text({'head_sha': head, 'base_sha': BASE, 'live_base_sha': BASE,
                                          'reasons': ['GitHub reviewDecision is CHANGES_REQUESTED: waiting for '
                                                      'that reviewer to re-review']})
        return {'body': body, 'user': {'login': login}}

    def writes(self):
        return [a[1] for a in self.state()['calls'] if a[:2] in
                (['pr', 'comment'], ['pr', 'edit'], ['pr', 'ready'], ['pr', 'merge'])]

    def test_a_wait_for_a_person_is_commented_and_labelled(self):
        self.waits_for_a_person()
        proc, out = self.actor(execute=True)
        self.assertEqual((proc.returncode, out['outcome'], out['wait_kind'], out.get('handoff')),
                         (1, 'WAITING', 'person', 'needs-person'), proc.stdout + proc.stderr)
        d = self.state()
        self.assertEqual(['needs-person'], d['labels'])
        self.assertFalse(d['view']['isDraft'])
        self.assertEqual(['comment', 'edit'], self.writes())
        comment = d['comments'][0]
        self.assertIn(f'Judged HEAD: `{HEAD}`', comment)
        self.assertIn('CHANGES_REQUESTED', comment)
        self.assertIn(f'<!-- pr-review-merge:needs-person head={HEAD} ', comment)

    def test_the_hand_off_is_made_once_per_head_and_reasons(self):
        self.waits_for_a_person()
        self.actor(execute=True)
        proc, out = self.actor(execute=True)
        self.assertEqual('needs-person', out.get('handoff'), proc.stdout)
        self.assertEqual(1, len(self.state()['comments']), 'the same HEAD and reasons are not commented again')
        # A person removes the label while the reasons stand: the next run puts it back without a comment.
        self.patch(labels=[])
        self.actor(execute=True)
        self.assertEqual((['needs-person'], 1), (self.state()['labels'], len(self.state()['comments'])))
        # Different reasons on the same HEAD: a new comment, the label stays.
        self.patch(rules=[{'type': 'merge_queue'}])
        self.actor(execute=True)
        d = self.state()
        self.assertEqual(2, len(d['comments']))
        self.assertIn('merge queue', d['comments'][1])
        self.assertEqual(['needs-person'], d['labels'])

    def test_a_marker_by_another_account_does_not_count(self):
        self.waits_for_a_person(labels=['needs-person'],
                                issue_comments={'42': [self.marker_comment('someone-else')]})
        _, out = self.actor(execute=True)
        self.assertEqual('needs-person', out.get('handoff'))
        self.assertEqual(['comment'], self.writes(), 'only the comment: the label is already on')
        # The actor's own marker for this HEAD and these reasons suppresses it.
        self.patch(calls=[], issue_comments={'42': [self.marker_comment('prm-bot')]})
        _, out = self.actor(execute=True)
        self.assertEqual(('needs-person', []), (out.get('handoff'), self.writes()))

    def test_a_transient_wait_releases_the_label(self):
        self.patch(labels=['needs-person'], checks=[{'name': 'lint', 'state': 'PENDING', 'bucket': 'pending'}])
        _, out = self.actor(execute=True)
        self.assertEqual(('WAITING', 'transient', 'released'), (out['outcome'], out['wait_kind'], out.get('handoff')))
        self.assertEqual([], self.state()['labels'])
        self.assertFalse(self.state().get('comments'))

    def test_enqueue_releases_the_label(self):
        self.patch(labels=['needs-person'])
        proc, out = self.actor(execute=True)
        self.assertEqual(('ENQUEUED', 'released'), (out['outcome'], out.get('handoff')), proc.stdout + proc.stderr)
        self.assertEqual(['merge-queue'], self.state()['labels'])

    def test_draft_releases_the_label(self):
        self.patch(labels=['needs-person'], checks=[{'name': 'lint', 'state': 'FAILURE', 'bucket': 'fail'}])
        _, out = self.actor(execute=True)
        self.assertEqual(('DRAFT-BLOCKED', 'released'), (out['outcome'], out.get('handoff')))
        self.assertEqual([], self.state()['labels'])

    def test_a_label_that_cannot_be_removed_after_a_draft_is_a_warning(self):
        self.patch(labels=['needs-person'], fail_label=True,
                   checks=[{'name': 'lint', 'state': 'FAILURE', 'bucket': 'fail'}])
        proc, out = self.actor(execute=True)
        self.assertEqual((0, 'DRAFT-BLOCKED'), (proc.returncode, out['outcome']), proc.stdout)
        self.assertIn('could not be removed', ' '.join(out['warnings']))

    def test_a_label_that_cannot_be_added_is_a_warning(self):
        self.waits_for_a_person(fail_label=True)
        proc, out = self.actor(execute=True)
        self.assertEqual((1, 'WAITING'), (proc.returncode, out['outcome']))
        self.assertIsNone(out.get('handoff'))
        self.assertIn('label denied', ' '.join(out['warnings']))
        self.assertEqual(1, len(self.state()['comments']), 'the explanation is posted before the label')

    def test_unreadable_comments_hand_off_nothing(self):
        self.waits_for_a_person(comments_error=True)
        _, out = self.actor(execute=True)
        self.assertEqual(('WAITING', None), (out['outcome'], out.get('handoff')))
        self.assertIn('comments unavailable', ' '.join(out['warnings']))
        self.assertEqual([], self.writes())

    def test_a_dry_run_hands_off_nothing(self):
        self.waits_for_a_person()
        _, out = self.actor()
        self.assertEqual(('WAITING', 'person'), (out['outcome'], out['wait_kind']))
        self.assertEqual([], self.writes())

    def test_a_head_that_moves_after_the_gate_hands_off_nothing(self):
        self.waits_for_a_person(race_on_view=4)   # the hand-off's own view (the 3rd is the signal's)
        _, out = self.actor(execute=True)
        self.assertEqual(('WAITING', None), (out['outcome'], out.get('handoff')))
        self.assertIn('changed after the gate', ' '.join(out['warnings']))
        self.assertEqual([], self.writes())

    def review_side_wait(self):
        """Incomplete reviewer coverage: `wait_kind` is `person` for the merge train, but the next
        pr-review-merge run supplies it, so nobody is waited for."""
        e = evidence()
        e['coverage']['security'] = False
        self.evidence_file.write_text(json.dumps(e))

    def test_a_review_side_wait_is_neither_commented_nor_labelled(self):
        self.review_side_wait()
        proc, out = self.actor(execute=True)
        self.assertEqual(('WAITING', 'person', None, False),
                         (out['outcome'], out['wait_kind'], out.get('handoff'), out['gate']['person_handoff']),
                         proc.stdout + proc.stderr)
        self.assertIn('coverage incomplete', ' '.join(out['gate']['reasons']))
        self.assertEqual([], self.writes())
        self.assertFalse(self.state().get('labels'))
        self.assertFalse(self.state().get('comments'))

    def test_a_review_side_wait_releases_a_stale_label_and_stays_listable(self):
        self.review_side_wait()
        self.patch(labels=['needs-person'])
        _, out = self.actor(execute=True)
        self.assertEqual(('WAITING', 'person', 'released'), (out['outcome'], out['wait_kind'], out.get('handoff')))
        self.assertEqual([], self.state()['labels'])
        self.assertFalse(self.state().get('comments'))
        pr = {'number': 42, 'state': 'open', 'draft': False, 'html_url': 'u', 'title': 't',
              'labels': [{'name': name} for name in self.state()['labels']] + [rw.LABEL_CAPTURE],
              'head': {'sha': HEAD}, 'base': {'sha': BASE, 'ref': 'main'}}
        self.patch(pages=[[pr]])
        proc = self.script('list_ready.py')
        self.assertEqual(0, proc.returncode, proc.stderr)
        listing = json.loads(proc.stdout)
        self.assertEqual(([42], []), ([p['number'] for p in listing['pull_requests']], listing['excluded']))

    def listed(self, labels):
        pr = {'number': 42, 'state': 'open', 'draft': False, 'html_url': 'u', 'title': 't',
              'labels': [{'name': name} for name in labels] + [rw.LABEL_CAPTURE],
              'head': {'sha': HEAD}, 'base': {'sha': BASE, 'ref': 'main'}}
        self.patch(pages=[[pr]])
        proc = self.script('list_ready.py')
        self.assertEqual(0, proc.returncode, proc.stderr)
        out = json.loads(proc.stdout)
        return [p['number'] for p in out['pull_requests']], [e['number'] for e in out['excluded']]

    def test_required_checks_without_results_hand_off_with_contract_evidence(self):
        # The branch requires status checks and GitHub returned none; the evidence is what the contract asks
        # for (no no_ci_rationale: that field is for a branch without required checks). A rationale gap that
        # hid this reason made the actor leave the PR unlabelled and list_ready select it every run.
        self.patch(checks=[], rules=[{'type': 'required_status_checks'}])
        proc, out = self.actor(execute=True)
        self.assertEqual(('WAITING', 'person', 'needs-person', True),
                         (out['outcome'], out['wait_kind'], out.get('handoff'), out['gate']['person_handoff']),
                         proc.stdout + proc.stderr)
        d = self.state()
        self.assertEqual(['needs-person'], d['labels'])
        self.assertIn('Branch requires status checks, but GitHub returned no completed checks', d['comments'][0])
        self.assertNotIn('No GitHub CI', d['comments'][0])
        self.assertEqual(([], [42]), self.listed(d['labels']))

    def gh(self, *args):
        return subprocess.run(['gh', *args], env=self.env, capture_output=True, text=True)

    def test_the_fake_gh_answers_zero_checks_as_the_recorded_gh_does(self):
        # The fake used to print `[]`, which real gh never does for a PR without checks; the empty-CI tests
        # passed on that and the production adapter raised. Pin the fake to the recorded capture.
        real = GITHUB_API['pr_checks']['zero_checks']
        self.patch(checks=[])
        proc = self.gh('pr', 'checks', '42', '-R', 'acme/demo', '--json', 'name,state,bucket,link,workflow')
        self.assertEqual((real['rc'], real['stdout'], real['stderr']), (proc.returncode, proc.stdout, proc.stderr))
        self.assertNotIn('[]', proc.stdout)
        # With checks it prints what the recorded answer looks like: a JSON list of check objects.
        recorded = json.loads(GITHUB_API['pr_checks']['with_checks']['stdout'])
        self.assertTrue(recorded and all({'name', 'state', 'bucket', 'link', 'workflow'} == set(c) for c in recorded))
        self.patch(checks=[{'name': 'unit', 'bucket': 'pass', 'state': 'SUCCESS', 'link': 'u', 'workflow': 'CI'}])
        proc = self.gh('pr', 'checks', '42', '-R', 'acme/demo')
        self.assertEqual((0, ''), (proc.returncode, proc.stderr))
        self.assertEqual('unit', json.loads(proc.stdout)[0]['name'])

    def test_a_failed_checks_read_on_a_required_checks_branch_is_transient_not_a_hand_off(self):
        # Negative control of the test above: the same branch, but GitHub answered with a real 401 instead of
        # "no checks reported". That is an infrastructure failure: no comment, no label, still listable.
        for key in ('auth_failure', 'no_such_pr', 'network_failure'):
            with self.subTest(key):
                self.fixture_file.write_text(json.dumps(fixture()))
                self.patch(checks=[], rules=[{'type': 'required_status_checks'}],
                           checks_capture=GITHUB_API['pr_checks'][key])
                proc, out = self.actor(execute=True)
                self.assertEqual(('WAITING', 'transient', None, False),
                                 (out['outcome'], out['wait_kind'], out.get('handoff'), out['gate']['person_handoff']),
                                 proc.stdout + proc.stderr)
                d = self.state()
                self.assertFalse(d.get('labels'))
                self.assertFalse(d.get('comments'))
                self.assertEqual(([42], []), self.listed([]))

    def test_no_checks_without_a_required_checks_rule_is_not_a_hand_off(self):
        self.patch(checks=[], rules=[])
        proc, out = self.actor(execute=True)
        self.assertEqual(('WAITING', False, None), (out['outcome'], out['gate']['person_handoff'], out.get('handoff')),
                         proc.stdout + proc.stderr)
        self.assertIn('No GitHub CI', ' '.join(out['gate']['reasons']))
        d = self.state()
        self.assertFalse(d.get('labels'))
        self.assertFalse(d.get('comments'))
        self.assertEqual(([42], []), self.listed([]))

    def test_list_ready_leaves_out_the_queue_and_a_current_wait(self):
        signed = [rw.LABEL_CAPTURE]   # every PR below got to Ready through pr-ready: it carries the signal's label
        pr = {'number': 1, 'state': 'open', 'draft': False, 'html_url': 'u', 'title': 't', 'labels': signed,
              'head': {'sha': HEAD}, 'base': {'sha': BASE, 'ref': 'main'}}
        queued = dict(pr, number=2, labels=signed + [{'name': 'merge-queue'}])
        waiting = dict(pr, number=3, labels=signed + [{'name': 'needs-person'}])
        moved = dict(pr, number=4, labels=signed + [{'name': 'needs-person'}], head={'sha': 'c' * 40})
        forged = dict(pr, number=5, labels=signed + [{'name': 'needs-person'}])
        unmarked = dict(pr, number=6, labels=signed + [{'name': 'needs-person'}])
        self.patch(pages=[[pr, queued, waiting, moved, forged, unmarked]],
                   issue_comments={'3': [self.marker_comment('prm-bot')], '4': [self.marker_comment('prm-bot')],
                                   '5': [self.marker_comment('someone-else')]})
        proc = self.script('list_ready.py')
        self.assertEqual(0, proc.returncode, proc.stderr)
        out = json.loads(proc.stdout)
        listed = {p['number']: p.get('stale_needs_person', False) for p in out['pull_requests']}
        self.assertEqual({1: False, 4: True, 5: True, 6: True}, listed)
        self.assertEqual([2, 3], [e['number'] for e in out['excluded']])
        self.assertEqual([], self.writes(), 'listing is read-only')

if __name__ == '__main__': unittest.main()
