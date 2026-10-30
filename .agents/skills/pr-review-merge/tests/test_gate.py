import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from gh_runtime import Repo, GitHubError
from review_gate import evaluate, COVERAGE

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
        self.assertEqual(self.gate()['decision'], 'MERGE')

    def test_skip_draft(self):
        f = Fake(); f.v['isDraft'] = True
        self.assertEqual(self.gate(gh=f)['decision'], 'SKIP')

    def test_stale_head(self):
        e = sample(); e['head_sha'] = B
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')

    def test_stale_base(self):
        e = sample(); e['base_sha'] = H
        self.assertEqual(self.gate(data=e)['decision'], 'WAITING')

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

if __name__ == '__main__':
    unittest.main()
