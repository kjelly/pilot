"""pr-ready and pr-review-merge must not hand a PR back and forth.

pr-ready marks a Draft PR Ready when its gate passes; pr-review-merge returns a
Ready PR to Draft when its gate finds a defect. If a GitHub state passed the
first and drafted under the second, each run of the two skills would undo the
other. For every state below that pr-ready accepts, pr-review-merge (given the
same reviewer-confirmed exemptions) must not decide DRAFT.
"""
import importlib.util
import itertools
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'scripts'))
from gh_runtime import Repo  # noqa: E402
from review_gate import evaluate as prm_evaluate  # noqa: E402
from test_gate import Fake, sample  # noqa: E402

spec = importlib.util.spec_from_file_location(
    'pr_ready_gate', HERE.parents[1] / 'pr-ready' / 'scripts' / 'pr_gate.py')
pr_ready = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pr_ready
spec.loader.exec_module(pr_ready)

H = 'a' * 40
REASON = 'Same failure on main at the base SHA (CI run 40802511042), not touched by this diff'


def ready_evidence(failing, unresolved, exempt_threads):
    assessment = {k: True for k in (
        'acceptance_criteria_passed', 'root_cause_fixed', 'architecture_sound',
        'description_matches_code', 'dependencies_resolved', 'major_review_comments_resolved',
        'related_ci_failures_resolved')}
    assessment['rationale'] = 'AC traced to test cases, issue root cause is fixed and diff matches description.'
    evidence = {'schema_version': 1, 'repo': 'acme/demo', 'pr': 42, 'head_sha': H,
                'assessment': assessment,
                'independent_review': {'agent': 'pr-reviewer', 'head_sha': H, 'status': 'PASS',
                                       'blocking_findings': [], 'report': 'Independent review on this HEAD.'},
                'local_validation': {key: [{'command': f'run {key}', 'exit_code': 0, 'head_sha': H,
                                            'log': f'.pr-ready/logs/{key}.log'}]
                                     for key in ('tests', 'lint', 'static_analysis')},
                'unrelated_failing_checks': [{'name': name, 'reason': REASON, 'reviewer_confirmed': True}
                                             for name in failing]}
    if exempt_threads:
        evidence['unresolved_nonblocking_threads'] = [
            {'id': tid, 'severity': 'P3', 'reason': 'Stylistic suggestion unrelated to acceptance criteria',
             'reviewer_confirmed': True} for tid in unresolved]
    return evidence


class HandoffTests(unittest.TestCase):
    def states(self):
        """GitHub states a PR can be in when pr-ready runs; this repository has no required checks."""
        for bucket, thread_resolved, decision, exempt_check, exempt_thread, required in itertools.product(
                ('pass', 'fail', 'cancel', 'skipping'), (True, False),
                (None, 'REVIEW_REQUIRED', 'CHANGES_REQUESTED', 'APPROVED'),
                (False, True), (False, True), (False, True)):
            yield dict(bucket=bucket, thread_resolved=thread_resolved, decision=decision,
                       exempt_check=exempt_check, exempt_thread=exempt_thread, required=required)

    def pr_ready_passes(self, st):
        checks = [{'name': 'Go test', 'bucket': 'pass', 'state': 'SUCCESS'},
                  {'name': 'Playbook lint', 'bucket': st['bucket'], 'state': st['bucket'].upper()}]
        pr = {'number': 42, 'url': 'https://github.com/acme/demo/pull/42', 'headRefOid': H,
              'headRefName': 'fix', 'state': 'OPEN', 'isDraft': True, 'mergeable': 'MERGEABLE',
              'reviewDecision': st['decision']}
        threads = [{'id': 'PRRT_1', 'isResolved': st['thread_resolved']}]
        failing = ['Playbook lint'] if st['exempt_check'] and st['bucket'] in ('fail', 'cancel') else []
        unresolved = [] if st['thread_resolved'] else ['PRRT_1']
        snapshot = pr_ready.Snapshot(pr, checks, checks if st['required'] else [], threads)
        errors = pr_ready.evaluate(snapshot, ready_evidence(failing, unresolved, st['exempt_thread']),
                                   repo='acme/demo', number=42, local=None)
        return not errors, checks, failing, len(unresolved)

    def prm_decision(self, st, checks, failing, unresolved):
        gh = Fake()
        gh.v['reviewDecision'] = st['decision']
        gh.v['headRefOid'] = H
        gh.c = checks
        gh.t = unresolved
        evidence = sample()
        evidence['unrelated_failing_checks'] = [{'name': n, 'reason': REASON, 'reviewer_confirmed': True}
                                                for n in failing]
        return prm_evaluate(Repo.parse('acme/demo'), 42, evidence, client=gh)['decision']

    def test_a_pr_marked_ready_is_never_drafted_for_the_same_state(self):
        accepted = []
        for st in self.states():
            passes, checks, failing, unresolved = self.pr_ready_passes(st)
            if not passes:
                continue
            decision = self.prm_decision(st, checks, failing, unresolved)
            accepted.append((st, decision))
            self.assertNotEqual('DRAFT', decision, st)
        decisions = {d for _, d in accepted}
        # The matrix has to reach both sides of the contract to mean anything.
        self.assertIn('MERGE', decisions)
        self.assertIn('WAITING', decisions)
        self.assertTrue(any(st['bucket'] == 'fail' for st, _ in accepted))
        self.assertTrue(any(st['decision'] == 'CHANGES_REQUESTED' for st, _ in accepted))
        self.assertFalse(any(not st['thread_resolved'] for st, _ in accepted))

    def test_a_ready_pr_never_merges_with_a_failing_check(self):
        for st in self.states():
            passes, checks, failing, unresolved = self.pr_ready_passes(st)
            if passes and st['bucket'] in ('fail', 'cancel'):
                self.assertEqual('WAITING', self.prm_decision(st, checks, failing, unresolved), st)


if __name__ == '__main__':
    unittest.main()
