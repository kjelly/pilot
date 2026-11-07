import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from gh_runtime import CompareLimitError, Repo, GitHubError
from review_gate import evaluate, COVERAGE
from scan_stub import CleanScan

setUpModule, tearDownModule = CleanScan.up, CleanScan.down

H = 'a' * 40
B = 'b' * 40


def sample():
    return {
        'schema_version': 1, 'repo': 'acme/demo', 'pr': 42,
        'head_sha': H, 'base_sha': B, 'reviewer_id': 'prm-reviewer',
        'independent': True, 'verdict': 'PASS', 'summary': 'Fully reviewed the entire patch and touched modules.',
        'coverage': {k: True for k in COVERAGE}, 'findings': [],
        'tests': [{'name': 'unit', 'status': 'PASS', 'sha': H, 'evidence': 'CI: unit run 12'}],
        'dependencies': {'resolved': True, 'evidence': 'No upstream PR dependencies detected'},
        'no_ci_rationale': ''
    }


def view():
    return {'number': 42, 'url': 'https://github.com/acme/demo/pull/42',
            'state': 'OPEN', 'isDraft': False, 'headRefOid': H, 'baseRefOid': B,
            'baseRefName': 'main', 'mergeable': 'MERGEABLE', 'mergeStateStatus': 'CLEAN',
            'reviewDecision': 'APPROVED', 'autoMergeRequest': None}


class Fake:
    def __init__(self):
        self.v = view()
        self.c = [{'name': 'test', 'bucket': 'pass', 'state': 'SUCCESS'}]
        self.r = []
        self.t = 0
        self.counter = 0
        # {(path, ref): bytes}; no entry is GitHub's 404, so no .github/pr-evidence.json.
        self.files = {}
        # {(base, head): compare result as gh_runtime.compare returns it}
        self.compares = {}
        self.calls = []
        self.live_base = B
        self.ancestor = True
        # {(base, head): bool}; pairs not listed answer `ancestor`.
        self.ancestry = {}

    def is_ancestor(self, repo, base, head):
        self.calls.append(('is_ancestor', base, head))
        return self.ancestry.get((base, head), self.ancestor)

    def merge_base(self, repo, a, b):
        self.calls.append(('merge_base', a, b))
        if (a, b) in self.compares and self.compares[(a, b)] is not None:
            return self.compares[(a, b)]['merge_base']
        if a == b or self.ancestry.get((a, b), self.ancestor) is True:
            return a
        raise GitHubError('merge base unknown to the fake')

    def branch_head(self, repo, branch):
        return self.live_base

    def file_at(self, repo, path, ref):
        self.calls.append(('file_at', path, ref))
        return self.files.get((path, ref))

    def compare(self, repo, base, head):
        self.calls.append(('compare', base, head))
        return self.compares.get((base, head))

    def pr_view(self, repo, number):
        self.counter += 1
        return dict(self.v)

    def pr_checks(self, repo, number):
        return self.c

    def branch_rules(self, repo, branch):
        return self.r

    def unresolved_threads(self, repo, number):
        return self.t


class GateTests(unittest.TestCase):
    def gate(self, data=None, gh=None):
        return evaluate(Repo.parse('acme/demo'), 42, sample() if data is None else data,
                        client=Fake() if gh is None else gh)

    def test_merge_full_pass(self):
        result = self.gate()
        self.assertEqual(result['decision'], 'MERGE')
        self.assertEqual(result['base_name'], 'main')

    def test_skip_draft(self):
        f = Fake(); f.v['isDraft'] = True
        self.assertEqual(self.gate(gh=f)['decision'], 'SKIP')

    def test_lagging_base_metadata_alone_is_not_a_draft(self):
        # HEAD already contains the live tip; only PR Base metadata lags (kjelly/pilot#307).
        f = Fake(); f.live_base = 'c' * 40
        result = self.gate(gh=f)
        self.assertEqual('aligned', result['alignment'])
        self.assertFalse(result['needs_alignment'])
        self.assertEqual('MERGE', result['decision'], result['reasons'])
        self.assertIn(('is_ancestor', 'c' * 40, H), f.calls)

    def test_missing_or_malformed_base_name_waits(self):
        for name in (None, '', 7, []):
            with self.subTest(name=name):
                f = Fake(); f.v['baseRefName'] = name
                result = self.gate(gh=f)
                self.assertEqual(result['decision'], 'WAITING')
                self.assertIn('base branch name unavailable', ' '.join(result['reasons']))

    def test_actor_missing_gate_base_identity_fails_closed(self):
        from unittest import mock
        import apply_decision
        for decision in ('DRAFT', 'MERGE'):
            for name in (None, '', 7, []):
                with self.subTest(decision=decision, name=name):
                    gate = {'decision': decision, 'head_sha': H, 'base_sha': B, 'live_base_sha': B}
                    if name is not None:
                        gate['base_name'] = name
                    with mock.patch.object(apply_decision, 'evaluate', return_value=gate), \
                         mock.patch.object(apply_decision, 'pr_view') as read, \
                         mock.patch.object(apply_decision, 'run_gh') as write:
                        result = apply_decision._perform_locked(Repo.parse('acme/demo'), 42, {}, 'merge', True)
                    self.assertEqual(result['outcome'], 'ERROR')
                    self.assertIn('Gate base branch identity unavailable', result['error'])
                    read.assert_not_called()
                    write.assert_not_called()

    def test_base_ref_unavailable_waits(self):
        f = Fake()
        def unavailable(repo, branch):
            raise GitHubError('permission denied')
        f.branch_head = unavailable
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def behind(self, pr_files=('pkg/a.go',), base_files=('docs/x.md',)):
        f = Fake(); f.ancestor = False
        f.compares[(B, H)] = {'files': list(pr_files), 'merge_base': 'e' * 40, 'ancestor': False}
        f.compares[(H, B)] = {'files': list(base_files), 'merge_base': 'e' * 40, 'ancestor': False}
        return f

    def test_head_behind_with_a_clean_disjoint_merge_goes_to_the_train(self):
        f = self.behind()
        result = self.gate(gh=f)
        self.assertEqual('train', result['alignment'])
        self.assertTrue(result['base_behind'])
        self.assertTrue(result['needs_alignment'])
        self.assertEqual('MERGE', result['decision'], result['reasons'])
        self.assertIn(('is_ancestor', B, H), f.calls)

    def test_head_behind_with_overlap_or_conflict_drafts_without_review(self):
        f = self.behind(base_files=('pkg/a.go', 'docs/x.md'))
        result = self.gate(data={}, gh=f)
        self.assertEqual(('DRAFT', 'overlap', ['pkg/a.go']), (result['decision'], result['alignment'], result['overlap']))
        self.assertIn(H, result['reasons'][0])
        self.assertIn('both sides changed pkg/a.go', result['reasons'][0])
        self.assertIn('pr-ready', result['reasons'][0])
        for mergeable, state in (('CONFLICTING', 'DIRTY'), ('CONFLICTING', 'CLEAN'), ('MERGEABLE', 'DIRTY')):
            with self.subTest(mergeable=mergeable, state=state):
                f = self.behind(); f.v['mergeable'] = mergeable; f.v['mergeStateStatus'] = state
                result = self.gate(data={}, gh=f)
                self.assertEqual(('DRAFT', 'conflict'), (result['decision'], result['alignment']))
                self.assertIn('merge conflict', result['reasons'][0])

    def test_head_behind_with_unknown_mergeability_or_file_lists_waits(self):
        f = self.behind(); f.v['mergeable'] = 'UNKNOWN'
        result = self.gate(gh=f)
        self.assertEqual(('WAITING', 'unknown'), (result['decision'], result['alignment']))
        self.assertIn("'UNKNOWN'", result['reasons'][0])
        f = self.behind(); del f.compares[(H, B)]
        result = self.gate(gh=f)
        self.assertEqual(('WAITING', 'unknown'), (result['decision'], result['alignment']))
        f = self.behind()
        def too_many(repo, base, head):
            raise GitHubError('GitHub lists at most 300 changed files')
        f.compare = too_many
        result = self.gate(gh=f)
        self.assertEqual(('WAITING', 'unknown'), (result['decision'], result['alignment']))
        self.assertIn('300', result['reasons'][0])

    def test_unknown_ancestry_waits(self):
        f = Fake(); f.ancestor = None
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_ancestry_api_failure_waits(self):
        f = Fake()
        def unavailable(*args):
            raise GitHubError('comparison unavailable')
        f.is_ancestor = unavailable
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_base_moves_while_confirming_behind_waits(self):
        f = Fake(); f.ancestor = False
        refs = iter([B, 'c' * 40])
        f.branch_head = lambda repo, branch: next(refs)
        self.assertEqual(self.gate(data={}, gh=f)['decision'], 'WAITING')

    def test_head_moves_while_confirming_behind_waits(self):
        f = Fake(); f.ancestor = False
        original = f.pr_view
        def moving(repo, number):
            v = original(repo, number)
            if f.counter > 1:
                v['headRefOid'] = 'c' * 40
            return v
        f.pr_view = moving
        self.assertEqual(self.gate(data={}, gh=f)['decision'], 'WAITING')

    def test_base_ref_mismatch_changes_during_confirmation_waits(self):
        f = Fake(); refs = iter(['c' * 40, B])
        f.branch_head = lambda repo, branch: next(refs)
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_stale_head(self):
        e = sample(); e['head_sha'] = B
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')

    def test_stale_base(self):
        # A reviewed Base that is not on the live base branch does not bind the review.
        f = Fake(); f.ancestry[('c' * 40, B)] = False
        e = sample(); e['base_sha'] = 'c' * 40
        result = self.gate(data=e, gh=f)
        self.assertEqual(result['decision'], 'WAITING')
        self.assertIn('is not on live main', ' '.join(result['reasons']))

    def test_older_reviewed_base_on_the_live_branch_still_binds_the_same_head(self):
        f = Fake(); f.ancestry[('c' * 40, B)] = True
        e = sample(); e['base_sha'] = 'c' * 40
        self.assertEqual('MERGE', self.gate(data=e, gh=f)['decision'])

    def test_missing_independent_review(self):
        e = sample(); e['independent'] = False
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')

    def test_missing_coverage(self):
        e = sample(); e['coverage']['security'] = False
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')

    def test_blocker(self):
        e = sample(); e['verdict'] = 'BLOCK'
        e['findings'] = [{'severity':'P1', 'path':'pkg/a.go', 'line':21,
                          'reason':'Data race in writes', 'recommendation':'Use mutex', 'blocking':True}]
        result = self.gate(data=e)
        self.assertEqual(result['decision'], 'DRAFT')
        self.assertIn('pkg/a.go:21', ' '.join(result['reasons']))

    def test_block_verdict_without_finding_not_automatic_draft(self):
        e = sample(); e['verdict'] = 'BLOCK'
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')

    def test_test_receipt_stale_sha(self):
        e = sample(); e['tests'][0]['sha'] = B
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')

    def test_invalid_evidence_type_fail_closed(self):
        e = sample(); e['head_sha'] = 123
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')

    def test_failed_tests(self):
        e = sample(); e['tests'][0]['status'] = 'FAIL'
        self.assertEqual(self.gate(data=e)['decision'], 'DRAFT')

    def test_pending_ci(self):
        f = Fake(); f.c[0]['bucket'] = 'pending'
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_failed_ci(self):
        f = Fake(); f.c[0]['bucket'] = 'fail'
        self.assertEqual(self.gate(gh=f)['decision'], 'DRAFT')

    def test_unresolved_threads(self):
        f = Fake(); f.t = 2
        self.assertEqual(self.gate(gh=f)['decision'], 'DRAFT')

    def test_graphql_unavailable(self):
        f = Fake()
        def fail(repo, n):
            raise GitHubError('access denied')
        f.unresolved_threads = fail
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_approval_required(self):
        f = Fake(); f.v['reviewDecision'] = 'REVIEW_REQUIRED'
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_changes_requested_waits_for_re_review(self):
        # pr-ready marks a PR Ready without waiting for re-approval; a Draft here would loop.
        f = Fake(); f.v['reviewDecision'] = 'CHANGES_REQUESTED'
        result = self.gate(gh=f)
        self.assertEqual(result['decision'], 'WAITING')
        self.assertIn('re-review', ' '.join(result['reasons']))

    def test_p4_finding_is_nonblocking(self):
        e = sample()
        e['findings'] = [{'severity': 'P4', 'path': 'pkg/a.go', 'line': 3, 'reason': 'Naming nit',
                          'recommendation': 'Rename the helper'}]
        self.assertEqual(self.gate(data=e)['decision'], 'MERGE')
        e['findings'][0]['severity'] = 'P5'
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')

    def test_unrelated_failing_check_waits_instead_of_draft(self):
        f = Fake(); f.c[0]['bucket'] = 'fail'
        e = sample()
        e['unrelated_failing_checks'] = [{'name': 'test', 'reviewer_confirmed': True,
                                          'reason': 'Same timeout fails on main at the base SHA, run 40802511042'}]
        result = self.gate(data=e, gh=f)
        self.assertEqual(result['decision'], 'WAITING')
        self.assertIn('unrelated to this PR', ' '.join(result['reasons']))
        for bad in ({'name': 'test', 'reviewer_confirmed': False, 'reason': e['unrelated_failing_checks'][0]['reason']},
                    {'name': 'test', 'reviewer_confirmed': True, 'reason': 'flaky'}):
            e['unrelated_failing_checks'] = [bad]
            self.assertEqual(self.gate(data=e, gh=f)['decision'], 'DRAFT')
        e['unrelated_failing_checks'] = [{'name': 'other', 'reviewer_confirmed': True,
                                          'reason': 'Same timeout fails on main at the base SHA, run 40802511042'}]
        self.assertEqual(self.gate(data=e, gh=f)['decision'], 'DRAFT')
        e['unrelated_failing_checks'] = 'test'
        self.assertEqual(self.gate(data=e, gh=f)['decision'], 'DRAFT')

    def test_repeated_disputed_finding_needs_new_evidence(self):
        reply = 'https://github.com/acme/demo/pull/42#issuecomment-6501033173'
        e = sample(); e['verdict'] = 'BLOCK'
        e['findings'] = [{'severity': 'P2', 'path': 'pkg/a.go', 'line': 21, 'reason': 'Rescue skips rollback',
                          'recommendation': 'Tag the rescue always', 'blocking': True,
                          'disputed_reply_url': reply}]
        result = self.gate(data=e)
        self.assertEqual(result['decision'], 'WAITING')
        self.assertIn('without new evidence', ' '.join(result['reasons']))
        self.assertNotIn('BLOCK verdict needs', ' '.join(result['reasons']))
        e['findings'][0]['new_evidence'] = 'short'
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')
        e['findings'][0]['new_evidence'] = '--tags C3 run on HEAD left /etc/x modified: log ci/run-77'
        result = self.gate(data=e)
        self.assertEqual(result['decision'], 'DRAFT')
        self.assertIn('Disputed in ' + reply, ' '.join(result['reasons']))

    def test_disputed_reply_url_must_be_on_this_pr(self):
        e = sample(); e['verdict'] = 'BLOCK'
        e['findings'] = [{'severity': 'P1', 'path': 'pkg/a.go', 'line': 21, 'reason': 'Data race in writes',
                          'recommendation': 'Use mutex', 'blocking': True,
                          'new_evidence': 'go test -race ./pkg reports the race at a.go:21 on HEAD'}]
        for url in ('https://github.com/acme/demo/pull/43#issuecomment-1',
                    'https://github.com/other/demo/pull/42#issuecomment-1',
                    'https://github.com/acme/demo/pull/42',
                    'https://github.com/acme/demo/pull/42#issuecomment-1x', 7):
            e['findings'][0]['disputed_reply_url'] = url
            result = self.gate(data=e)
            self.assertEqual(result['decision'], 'WAITING', url)
            self.assertIn('not a comment on this PR', ' '.join(result['reasons']))
        e['findings'][0]['disputed_reply_url'] = 'https://github.com/acme/demo/pull/42#discussion_r2470013377'
        self.assertEqual(self.gate(data=e)['decision'], 'DRAFT')

    def test_merge_conflict(self):
        f = Fake(); f.v['mergeable'] = 'CONFLICTING'
        self.assertEqual(self.gate(gh=f)['decision'], 'DRAFT')

    def test_merge_queue(self):
        f = Fake(); f.r = [{'type': 'merge_queue'}]
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_rules_unavailable(self):
        f = Fake()
        def fail(repo, branch):
            raise GitHubError('forbidden')
        f.branch_rules = fail
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_no_checks_no_rationale(self):
        f = Fake(); f.c = []
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_no_checks_with_evidence(self):
        f = Fake(); f.c = []
        e = sample(); e['no_ci_rationale'] = 'This repository has no configured CI jobs; unit test receipt captured.'
        self.assertEqual(self.gate(data=e, gh=f)['decision'], 'MERGE')

    def test_no_checks_but_required(self):
        f = Fake(); f.c = []; f.r = [{'type': 'required_status_checks'}]
        e = sample(); e['no_ci_rationale'] = 'No CI on this branch but the unit tests have been run separately.'
        self.assertEqual(self.gate(data=e, gh=f)['decision'], 'WAITING')

    def test_require_approval_from_active_rules(self):
        f = Fake(); f.v['reviewDecision'] = None
        f.r = [{'type': 'pull_request', 'parameters': {'required_approving_review_count': 1}}]
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_base_changed_during_gate(self):
        f = Fake()
        original = f.pr_view
        def changing(repo, n):
            state = original(repo, n)
            if f.counter == 2:
                state['baseRefOid'] = 'c'*40
            return state
        f.pr_view = changing
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_unrecognized_check(self):
        f = Fake(); f.c[0]['bucket'] = 'weird'
        self.assertEqual(self.gate(gh=f)['decision'], 'WAITING')

    def test_unresolved_dependencies(self):
        e = sample(); e['dependencies']['resolved'] = False
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')

class WaitKindTests(unittest.TestCase):
    """Every WAITING result says whether it resolves by itself (`transient`) or needs a person.

    The merge train keeps a transient PR enqueued and stops its run; it takes a `person` PR out of the
    queue with the reasons, so the PRs behind it can merge (kjelly/pilot#307). Each class below has a case
    that reaches it through the real `evaluate`, and a case that must NOT be taken for the other class.
    """

    def waiting(self, gh=None, data=None, patch=None):
        from unittest import mock
        with mock.patch.object(__import__('review_gate'), 'check_secrets', **(patch or {'return_value': (
                [], [], {'status': 'CLEAN'})})):
            result = evaluate(Repo.parse('acme/demo'), 42, sample() if data is None else data,
                              client=Fake() if gh is None else gh)
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        return result['wait_kind'], ' | '.join(result['reasons'])

    def fails(self, name, exc=GitHubError('HTTP 502')):
        def raise_it(*args, **kwargs):
            raise exc
        return name, raise_it

    def test_a_gate_that_decides_has_no_wait_kind(self):
        self.assertNotIn('wait_kind', evaluate(Repo.parse('acme/demo'), 42, sample(), client=Fake()))
        f = Fake(); f.c[0]['bucket'] = 'fail'
        self.assertNotIn('wait_kind', evaluate(Repo.parse('acme/demo'), 42, sample(), client=f))

    def test_transient_states_resolve_by_themselves(self):
        cases = {}
        f = Fake(); f.c[0]['bucket'] = 'pending'
        cases['CI pending'] = (f, None, None)
        f = Fake(); f.v['mergeable'] = 'UNKNOWN'; f.v['mergeStateStatus'] = 'UNKNOWN'
        cases['mergeability and merge state not computed'] = (f, None, None)
        f = Fake(); f.v['mergeStateStatus'] = 'BEHIND'
        cases['merge state BEHIND'] = (f, None, None)
        for name, label in (('pr_checks', 'CI state unavailable'), ('unresolved_threads', 'Cannot verify review threads'),
                            ('branch_rules', 'active branch rules')):
            f = Fake(); setattr(f, *self.fails(name))
            cases['API error: ' + label] = (f, None, None)
        f = Fake(); setattr(f, *self.fails('pr_view'))
        cases['API error: PR unreadable'] = (f, None, None)
        f = Fake(); setattr(f, *self.fails('branch_head'))
        cases['API error: base unreadable'] = (f, None, None)
        f = Fake(); f.ancestor = None
        cases['ancestry unavailable'] = (f, None, None)
        f = Fake(); setattr(f, *self.fails('is_ancestor'))
        cases['API error: ancestry'] = (f, None, None)
        f = Fake(); f.files[('.github/pr-evidence.json', B)] = b'{not json'
        cases['base manifest does not parse'] = (f, None, None)
        f = Fake()
        cases['secret scan could not run'] = (f, None, {'return_value': ([], ['Secret scan unavailable: no checkout'],
                                                                         {'status': 'NOT_RUN'})})
        f = Fake(); f.ancestor = False
        f.compares[(B, H)] = {'files': ['pkg/a.go'], 'merge_base': 'e' * 40, 'ancestor': False}
        f.compares[(H, B)] = {'files': ['docs/x.md'], 'merge_base': 'e' * 40, 'ancestor': False}
        f.v['mergeable'] = 'UNKNOWN'
        cases['behind and mergeability not computed'] = (f, None, None)
        f = Fake(); f.ancestor = False
        f.compares[(B, H)] = {'files': ['pkg/a.go'], 'merge_base': 'e' * 40, 'ancestor': False}
        setattr(f, *self.fails('compare'))
        cases['behind and a comparison failed'] = (f, None, None)
        for name, (gh, data, patch) in cases.items():
            with self.subTest(case=name):
                kind, reasons = self.waiting(gh, data, patch)
                self.assertEqual('transient', kind, reasons)

    def test_states_only_a_person_can_change(self):
        reasons = {}
        for decision, text in (('CHANGES_REQUESTED', 're-review'), ('REVIEW_REQUIRED', 'Human approval required'),
                               ('SOMETHING_NEW', 'Unrecognized GitHub reviewDecision')):
            f = Fake(); f.v['reviewDecision'] = decision
            reasons[text] = (f, None, None)
        f = Fake(); f.v['reviewDecision'] = None
        f.r = [{'type': 'pull_request', 'parameters': {'required_approving_review_count': 1}}]
        reasons['require reviewer approval'] = (f, None, None)
        f = Fake(); f.c[0]['bucket'] = 'fail'
        e = sample()
        e['unrelated_failing_checks'] = [{'name': 'test', 'reviewer_confirmed': True,
                                          'reason': 'Same timeout fails on main at the base SHA, run 40802511042'}]
        reasons['unrelated to this PR'] = (f, e, None)
        e = sample(); e['verdict'] = 'BLOCK'
        e['findings'] = [{'severity': 'P2', 'path': 'pkg/a.go', 'line': 21, 'reason': 'Rescue skips rollback',
                          'recommendation': 'Tag the rescue always', 'blocking': True,
                          'disputed_reply_url': 'https://github.com/acme/demo/pull/42#issuecomment-6501033173'}]
        reasons['without new evidence'] = (Fake(), e, None)
        f = Fake(); f.v['mergeStateStatus'] = 'BLOCKED'
        reasons["Merge state is not CLEAN: 'BLOCKED'"] = (f, None, None)
        f = Fake(); f.v['mergeable'] = 'SOMETHING_NEW'
        reasons['Mergeability unknown/not mergeable'] = (f, None, None)
        f = Fake(); f.r = [{'type': 'merge_queue'}]
        reasons['merge queue'] = (f, None, None)
        f = Fake(); f.c = []
        reasons['No GitHub CI'] = (f, None, None)
        f = Fake(); f.c[0]['bucket'] = 'weird'
        reasons['Unknown GitHub CI check bucket'] = (f, None, None)
        e = sample(); e['independent'] = False
        reasons['independent prm-reviewer'] = (Fake(), e, None)
        e = sample(); e['head_sha'] = B
        reasons['Stale review evidence'] = (Fake(), e, None)
        e = sample(); e['coverage']['security'] = False
        reasons['coverage incomplete'] = (Fake(), e, None)
        e = sample(); e['dependencies']['resolved'] = False
        reasons['inter-PR dependencies'] = (Fake(), e, None)
        f = Fake(); f.ancestor = False
        f.compares[(B, H)] = {'files': ['pkg/a.go'], 'merge_base': 'e' * 40, 'ancestor': False}
        def cut(repo, base, head):
            raise CompareLimitError('GitHub lists at most 300 changed files')
        f.compare = cut
        reasons['300 changed files'] = (f, None, None)
        for text, (gh, data, patch) in reasons.items():
            with self.subTest(reason=text):
                kind, joined = self.waiting(gh, data, patch)
                self.assertEqual('person', kind, joined)
                self.assertIn(text, joined)

    def test_a_person_reason_wins_over_a_transient_one_and_a_derived_one_follows_the_others(self):
        f = Fake(); f.c[0]['bucket'] = 'pending'; f.v['reviewDecision'] = 'CHANGES_REQUESTED'
        self.assertEqual('person', self.waiting(f)[0])
        f = Fake(); f.c[0]['bucket'] = 'pending'; f.v['mergeStateStatus'] = 'BLOCKED'
        kind, reasons = self.waiting(f)
        self.assertEqual('transient', kind, 'BLOCKED only says that the pending check is not done: ' + reasons)
        f = Fake(); f.v['mergeStateStatus'] = 'UNSTABLE'
        self.assertEqual('person', self.waiting(f)[0], 'nothing else explains it')

    def test_a_reason_nobody_registered_needs_a_person(self):
        from review_gate import WaitKinds
        kinds = WaitKinds()
        later = kinds.later('GitHub is down')
        self.assertEqual('transient', kinds.kind([later]))
        self.assertEqual('person', kinds.kind([later, 'a reason nobody classified']))
        self.assertEqual('person', kinds.kind(['a reason nobody classified']))
        self.assertEqual('person', kinds.kind([]))
        self.assertEqual('person', kinds.kind([kinds.secondary('merge state')]))
        self.assertEqual('transient', kinds.kind([later, kinds.secondary('merge state')]))

    def test_train_alignment_says_whether_unknown_will_pass_or_needs_a_person(self):
        from review_gate import train_alignment
        def view_of(f):
            return f.pr_view(None, 42)
        f = Fake(); f.ancestor = False; f.v['mergeable'] = 'UNKNOWN'
        out = train_alignment(f, Repo.parse('acme/demo'), 42, view_of(f))
        self.assertEqual(('unknown', 'transient'), (out['alignment'], out['unknown_reason']))
        f = Fake(); f.ancestor = False
        setattr(f, *self.fails('compare'))
        out = train_alignment(f, Repo.parse('acme/demo'), 42, view_of(f))
        self.assertEqual(('unknown', 'transient'), (out['alignment'], out['unknown_reason']))
        f = Fake(); f.ancestor = False
        setattr(f, *self.fails('compare', CompareLimitError('GitHub lists at most 300 changed files')))
        out = train_alignment(f, Repo.parse('acme/demo'), 42, view_of(f))
        self.assertEqual(('unknown', 'needs-person'), (out['alignment'], out['unknown_reason']))
        f = Fake(); f.ancestor = False
        out = train_alignment(f, Repo.parse('acme/demo'), 42, view_of(f))
        self.assertEqual(('unknown', 'transient'), (out['alignment'], out['unknown_reason']), 'no compare answer')


if __name__ == '__main__':
    unittest.main()
