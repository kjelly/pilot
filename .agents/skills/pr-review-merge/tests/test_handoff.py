"""Every gate result has an owner: a PR the gate cannot merge either goes back to pr-ready as a Draft
with the steps, or is marked as waiting for a person.

Two gate rules (the actor's needs-person mark is tested end to end in test_integration.py):

* The merge train's integration would bring runtime files the saved target record cannot cover: the
  train's step 5 would Draft the PR after integrating it and waiting for CI, so the gate decides that
  Draft before the PR is queued.
* An unresolved dependency the reviewer says pr-ready can resolve on the branch (`branch_repair`) is a
  Draft with those steps; any other unresolved dependency still waits for a person.
"""
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'scripts'))
sys.path.insert(0, str(HERE))
from gh_runtime import CompareLimitError, GitHubError, Repo  # noqa: E402
import needs_person  # noqa: E402
import review_gate  # noqa: E402
from review_gate import evaluate, train_import_invalidates_record  # noqa: E402
from test_gate import B, H, Fake, sample  # noqa: E402
from scan_stub import CleanScan  # noqa: E402
import test_target_validation as tvt  # noqa: E402  (its fixtures only; no TestCase class is imported)

setUpModule, tearDownModule = CleanScan.up, CleanScan.down

REPO = Repo.parse('acme/demo')
MANIFEST = '.github/pr-evidence.json'
REPO_MANIFEST = (HERE.parents[3] / MANIFEST).read_bytes()
ART = 'docs/evidence/feature/issue-1.md'
MB = 'e' * 40


def record(decision='required'):
    return {'decision': decision, 'reason': 'Changes playbooks/apply/x.yml; run on vm-target per AGENTS.md 1.4',
            'artifact': ART, 'tested_revision': H}


def train_pr(base_import, *, pr_files=('playbooks/apply/x.yml', ART), manifest=REPO_MANIFEST):
    """HEAD lacks the live tip B; GitHub's test merge is clean and no file changed on both sides."""
    gh = Fake()
    gh.ancestor = False
    if manifest is not None:
        gh.files[(MANIFEST, B)] = manifest
    gh.files[(ART, H)] = b'Tested candidate `' + H.encode() + b'`'
    gh.compares[(B, H)] = {'files': list(pr_files), 'merge_base': MB, 'ancestor': False}
    gh.compares[(H, B)] = {'files': list(base_import), 'merge_base': MB, 'ancestor': False}
    return gh


def gate(gh, tv=None, **evidence):
    e = sample()
    e['target_validation'] = record() if tv is None else tv
    e.update(evidence)
    return evaluate(REPO, 42, e, client=gh)


class TrainImportTests(unittest.TestCase):
    def test_a_rerun_paths_import_drafts_before_the_queue(self):
        # PR #375: main brought contracts/log-server.yaml, a rerun_paths file; the reviewer left the
        # dependency unresolved and the PR waited Ready with nobody acting on it.
        result = gate(train_pr(['contracts/log-server.yaml', 'docs/runbooks/x.md']))
        self.assertEqual('DRAFT', result['decision'], result['reasons'])
        self.assertEqual('train', result['alignment'])
        self.assertEqual(['contracts/log-server.yaml'], result['train_import_rerun'])
        reason = ' '.join(result['reasons'])
        self.assertIn('contracts/log-server.yaml (rerun_paths)', reason)
        self.assertNotIn('docs/runbooks/x.md', reason)
        for step in ('merge live main into HEAD', '--evidence-record', 'commit the evidence-only record',
                     'fresh independent review', 'step 5'):
            self.assertIn(step, reason)

    def test_runtime_files_outside_rerun_paths_draft_without_the_tag(self):
        # playbooks/site.yml is under required_paths (never non-execution) and not under rerun_paths:
        # after the integration only a new run or a reviewed target_reuse keeps a record.
        result = gate(train_pr(['playbooks/site.yml']))
        self.assertEqual('DRAFT', result['decision'], result['reasons'])
        reason = ' '.join(result['reasons'])
        self.assertIn('playbooks/site.yml', reason)
        self.assertNotIn('(rerun_paths)', reason)

    def test_evidence_only_and_non_execution_imports_still_queue(self):
        result = gate(train_pr(['docs/evidence/other/x.md', '.agents/skills/a/SKILL.md', 'README.md',
                                'internal/spec/x_test.go', '.github/workflows/ci.yml']))
        self.assertEqual('MERGE', result['decision'], result['reasons'])
        self.assertEqual([], result['train_import_rerun'])

    def test_docs_verification_is_never_non_execution(self):
        result = gate(train_pr(['docs/verification/dns.md']))
        self.assertEqual('DRAFT', result['decision'], result['reasons'])

    def test_no_record_needed_means_no_prediction(self):
        result = gate(train_pr(['contracts/log-server.yaml'], pr_files=('README.md',)),
                      tv={'decision': 'not-needed', 'reason': 'Docs-only change; nothing a target run reads.',
                          'artifact': '', 'tested_revision': ''})
        self.assertEqual('MERGE', result['decision'], result['reasons'])

    def test_no_manifest_means_no_prediction(self):
        result = gate(train_pr(['contracts/log-server.yaml'], manifest=None))
        self.assertEqual('MERGE', result['decision'], result['reasons'])

    def test_an_aligned_pr_is_never_predicted(self):
        # After pr-ready integrates the base the PR is aligned, so the Draft cannot repeat for that state.
        gh = Fake()
        gh.files[(MANIFEST, B)] = REPO_MANIFEST
        gh.files[(ART, H)] = b'Tested candidate `' + H.encode() + b'`'
        gh.compares[(B, H)] = {'files': ['playbooks/apply/x.yml', ART], 'merge_base': B, 'ancestor': True}
        result = gate(gh)
        self.assertEqual('MERGE', result['decision'], result['reasons'])
        self.assertEqual('aligned', result['alignment'])
        self.assertNotIn('train_import_rerun', result)

    def test_an_unreadable_manifest_waits_and_never_predicts(self):
        gh = train_pr(['contracts/log-server.yaml'])

        def fail(repo, path, ref):
            if path == MANIFEST:
                raise GitHubError('gh api contents failed (1): HTTP 502')
            return Fake.file_at(gh, repo, path, ref)
        gh.file_at = fail
        result = gate(gh)
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        self.assertEqual('transient', result['wait_kind'])

    def test_the_prediction_is_a_subset_of_the_trains_step_5(self):
        """Every file the prediction names is one the saved record cannot cover after the integration:
        neither evidence-only nor non-execution under the same manifest the train reads."""
        manifest = json.loads(REPO_MANIFEST)
        ctx = review_gate.repo_evidence.Context(None, '', manifest, [], [])
        files = ['contracts/a.yaml', 'docs/evidence/x/y.md', 'docs/a.md', 'cmd/pilot/main.go', 'cmd/x_test.go',
                 'playbooks/site.yml', 'docs/verification/a.md', '.agents/x.md', 'group_vars/all.yml']
        got = train_import_invalidates_record(manifest, record(), files)
        for path in got['files']:
            self.assertFalse(any(rx.match(path) for rx in ctx.patterns), path)
            self.assertFalse(ctx.non_execution_path(path), path)
        self.assertEqual(['cmd/pilot/main.go', 'contracts/a.yaml', 'docs/verification/a.md', 'group_vars/all.yml',
                          'playbooks/site.yml'], got['files'])
        self.assertEqual(['cmd/pilot/main.go', 'contracts/a.yaml', 'group_vars/all.yml'], got['rerun'])
        self.assertEqual({'files': [], 'rerun': []}, train_import_invalidates_record(manifest, record('blocked'), files))
        self.assertEqual({'files': [], 'rerun': []}, train_import_invalidates_record(None, record(), files))


class BranchRepairDependencyTests(unittest.TestCase):
    def deps(self, **extra):
        d = {'resolved': False, 'evidence': 'Merging main brings contracts/log-server.yaml into the closure.'}
        d.update(extra)
        return d

    def repair(self, **extra):
        r = {'reason': 'The record must be rerun after main is integrated',
             'steps': ['Merge live main into HEAD', 'Run vm-target test with --evidence-record',
                       'Commit the evidence record']}
        r.update(extra)
        return r

    def test_a_branch_repairable_dependency_drafts_with_its_steps(self):
        result = gate(Fake(), tv={}, dependencies=self.deps(branch_repair=self.repair()))
        self.assertEqual('DRAFT', result['decision'], result['reasons'])
        reason = result['reasons'][0]
        self.assertIn('pr-ready can resolve on this branch', reason)
        self.assertIn('1. Merge live main into HEAD 2. Run vm-target test', reason)

    def test_an_unresolved_dependency_without_a_repair_waits_for_a_person(self):
        result = gate(Fake(), tv={}, dependencies=self.deps())
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        self.assertEqual(('person', True), (result['wait_kind'], result['person_handoff']))
        self.assertEqual(['Unresolved inter-PR dependency: Merging main brings contracts/log-server.yaml '
                          'into the closure.'], result['reasons'])

    def test_a_malformed_repair_waits(self):
        for bad in (self.repair(steps=[]), self.repair(steps='merge main'), self.repair(reason='short'),
                    self.repair(steps=['ok', ' ']), self.repair(steps=['s'] * 13), 'merge main'):
            with self.subTest(bad=bad):
                result = gate(Fake(), tv={}, dependencies=self.deps(branch_repair=bad))
                self.assertEqual('WAITING', result['decision'], result['reasons'])
                self.assertIn('dependencies.branch_repair needs', ' '.join(result['reasons']))

    def test_a_repair_on_a_resolved_dependency_is_contradictory(self):
        result = gate(Fake(), tv={}, dependencies=self.deps(resolved=True, branch_repair=self.repair()))
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        self.assertIn('only for an unresolved dependency', ' '.join(result['reasons']))

    def test_a_repair_needs_the_dependency_explanation(self):
        result = gate(Fake(), tv={}, dependencies={'resolved': False, 'evidence': 'x',
                                                   'branch_repair': self.repair()})
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        self.assertIn('Unresolved/unverified inter-PR dependencies', result['reasons'])
        self.assertFalse(result['person_handoff'], 'the reviewer can still supply the explanation')

    def test_a_resolved_dependency_still_merges(self):
        self.assertEqual('MERGE', gate(Fake(), tv={})['decision'])


class PersonHandoffTests(unittest.TestCase):
    """`wait_kind: person` is the merge train's catch-all for every reason nobody registered as transient.
    The `needs-person` label hides the PR from `list_ready.py` until a person acts, so it follows
    `person_handoff` instead: true only when a reason is registered as person-owned where the gate emits
    it, and no reason is an unregistered one (stale or missing evidence, an incomplete review, a record
    shaped wrongly: the next pr-review-merge run settles those)."""

    def waiting(self, gh=None, data=None):
        result = evaluate(REPO, 42, sample() if data is None else data, client=Fake() if gh is None else gh)
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        return result

    def tv_gh(self, manifest=None, artifact=tvt.RECORD):
        f = Fake()
        f.files[(tvt.MANIFEST, B)] = tvt.captured_manifest() if manifest is None else manifest
        if artifact is not None:
            f.files[(tvt.ART, H)] = artifact
        f.compares[(tvt.R, H)] = {'status': 'ahead', 'ancestor': True, 'files': [tvt.ART]}
        f.compares[(B, H)] = {'status': 'ahead', 'ancestor': True, 'files': ['README.md', tvt.ART]}
        return f

    def with_tv(self, tv):
        e = sample()
        if tv is not None:
            e['target_validation'] = tv
        return e

    def person_cases(self):
        """family -> (client, evidence): each is a WAITING only a person can resolve."""
        cases = {}

        def vary(**view):
            f = Fake(); f.v.update(view)
            return f
        cases['CHANGES_REQUESTED'] = (vary(reviewDecision='CHANGES_REQUESTED'), None)
        cases['REVIEW_REQUIRED'] = (vary(reviewDecision='REVIEW_REQUIRED'), None)
        f = vary(reviewDecision=None)
        f.r = [{'type': 'pull_request', 'parameters': {'required_approving_review_count': 1}}]
        cases['branch rules require approval'] = (f, None)
        e = sample(); e['verdict'] = 'BLOCK'
        e['findings'] = [{'severity': 'P2', 'path': 'pkg/a.go', 'line': 21, 'reason': 'Rescue skips rollback',
                          'recommendation': 'Tag the rescue always', 'blocking': True,
                          'disputed_reply_url': 'https://github.com/acme/demo/pull/42#issuecomment-6501033173'}]
        cases['repeated dispute without new evidence'] = (Fake(), e)
        f = Fake(); f.c[0]['bucket'] = 'fail'
        e = sample()
        e['unrelated_failing_checks'] = [{'name': 'test', 'reviewer_confirmed': True,
                                          'reason': 'Same timeout fails on main at the base SHA, run 40802511042'}]
        cases['unrelated failing check'] = (f, e)
        f = Fake(); f.r = [{'type': 'merge_queue'}]
        cases['merge queue'] = (f, None)
        f = Fake(); f.c = []; f.r = [{'type': 'required_status_checks'}]
        e = sample(); e['no_ci_rationale'] = 'The repository has no CI workflow for this docs-only change'
        cases['required checks without results'] = (f, e)
        cases['auto-merge configured'] = (vary(autoMergeRequest={'enabledAt': '2026-11-19T00:00:00Z'}), None)
        f = Fake(); f.ancestor = False
        f.compares[(B, H)] = {'files': ['pkg/a.go'], 'merge_base': 'e' * 40, 'ancestor': False}

        def cut(repo, base, head):
            raise CompareLimitError('GitHub lists at most 300 changed files')
        f.compare = cut
        cases['comparison cut by GitHub'] = (f, None)
        e = sample(); e['dependencies']['resolved'] = False
        cases['stated unresolved dependency'] = (Fake(), e)
        f = self.tv_gh()
        f.compares[(tvt.R, H)] = {'status': 'ahead', 'ancestor': True,
                                  'files': [tvt.ART, 'playbooks/apply/os-patch-sla-apply.yml']}
        cases['target run does not cover HEAD'] = (f, self.with_tv(tvt.record()))
        cases['target artifact not committed at HEAD'] = (
            self.tv_gh(), self.with_tv(tvt.record(artifact='docs/evidence/feature/missing.md')))
        cases['target artifact does not name the revision'] = (self.tv_gh(artifact=b'no revision at all'),
                                                               self.with_tv(tvt.record()))
        cases['target blocked'] = (self.tv_gh(), self.with_tv(
            tvt.record('blocked', reason='vm-target host has no free KVM capacity this week')))
        two = json.loads(tvt.captured_manifest())
        two['required_evidence'].append(dict(two['required_evidence'][0], id='second'))
        cases['manifest requires two records'] = (self.tv_gh(manifest=json.dumps(two).encode()),
                                                  self.with_tv(tvt.record()))
        return cases

    def review_side_cases(self):
        """family -> (client, evidence): the next pr-review-merge run can supply what is missing."""
        cases = {}
        e = sample(); e['head_sha'] = B
        cases['stale review HEAD'] = (Fake(), e)
        e = sample(); e['verdict'] = 'NEEDS_MORE_EVIDENCE'
        cases['NEEDS_MORE_EVIDENCE'] = (Fake(), e)
        e = sample(); e['coverage']['security'] = False
        cases['coverage incomplete'] = (Fake(), e)
        e = sample(); e['independent'] = False
        cases['independent is not true'] = (Fake(), e)
        e = sample(); e['summary'] = 'too short'
        cases['summary too short'] = (Fake(), e)
        e = sample(); e['tests'][0]['sha'] = B
        cases['tests bound to another SHA'] = (Fake(), e)
        e = sample(); e['dependencies'] = {'resolved': False, 'evidence': 'Needs main merged first for the record',
                                           'branch_repair': 'merge main'}
        cases['malformed branch_repair'] = (Fake(), e)
        e = sample(); e['dependencies'] = {'resolved': False, 'evidence': 'x'}
        cases['unverified dependency'] = (Fake(), e)
        cases['target_validation missing'] = (self.tv_gh(), self.with_tv(None))
        cases['target decision invalid'] = (self.tv_gh(), self.with_tv(tvt.record('skip')))
        cases['target reason too short'] = (self.tv_gh(), self.with_tv(tvt.record(reason='docs only')))
        cases['target revision not a full SHA'] = (self.tv_gh(), self.with_tv(tvt.record(tested_revision='ccccccc')))
        cases['target artifact outside the glob'] = (
            self.tv_gh(), self.with_tv(tvt.record(artifact='docs/runbooks/os-patch-sla.md')))
        tv = tvt.record('not-needed', reason='Docs-only change; no playbook, spec or contract touched.')
        f = self.tv_gh(manifest=tvt.repo_manifest())
        f.compares[(B, H)] = {'status': 'diverged', 'ancestor': False,
                              'files': ['README.md', 'playbooks/apply/os-patch-sla-apply.yml']}
        cases['target not-needed refused for required_paths'] = (f, self.with_tv(tv))
        cases['no CI without a rationale'] = (self.checks_none(), None)
        f = Fake(); f.c[0]['bucket'] = 'weird'
        cases['unknown CI bucket'] = (f, None)
        return cases

    def checks_none(self):
        f = Fake(); f.c = []
        return f

    def test_every_person_owned_family_is_a_hand_off(self):
        for family, (gh, data) in self.person_cases().items():
            with self.subTest(family=family):
                result = self.waiting(gh, data)
                self.assertEqual('person', result['wait_kind'], result['reasons'])
                self.assertIs(True, result['person_handoff'], result['reasons'])

    def test_every_review_side_family_is_left_listable(self):
        for family, (gh, data) in self.review_side_cases().items():
            with self.subTest(family=family):
                result = self.waiting(gh, data)
                # The merge train still dequeues these (its catch-all), but nobody is waited for.
                self.assertEqual('person', result['wait_kind'], result['reasons'])
                self.assertIs(False, result['person_handoff'], result['reasons'])

    def test_one_review_side_reason_keeps_a_person_owned_wait_listable(self):
        persons = self.person_cases()
        for family, (gh, data) in self.review_side_cases().items():
            if family.startswith('target') or family.startswith('no CI') or family.startswith('unknown CI'):
                continue
            with self.subTest(family=family):
                data = sample() if data is None else data
                gh = Fake() if gh is None else gh
                gh.v['reviewDecision'] = 'CHANGES_REQUESTED'
                result = self.waiting(gh, data)
                if family not in ('stale review HEAD', 'independent is not true'):   # these stop the gate early
                    self.assertIn('CHANGES_REQUESTED', ' '.join(result['reasons']))
                self.assertIs(False, result['person_handoff'], result['reasons'])
        # The same pair, reached through different families.
        gh, data = persons['target blocked']
        gh.v['reviewDecision'] = 'CHANGES_REQUESTED'
        self.assertIs(True, self.waiting(gh, data)['person_handoff'])
        gh, data = persons['target blocked']
        gh.v['reviewDecision'] = 'CHANGES_REQUESTED'
        data['coverage']['security'] = False
        self.assertIs(False, self.waiting(gh, data)['person_handoff'])

    def test_transient_and_derived_reasons_do_not_cancel_a_person_owned_one(self):
        f = Fake(); f.c[0]['bucket'] = 'pending'; f.v['reviewDecision'] = 'CHANGES_REQUESTED'
        result = self.waiting(f)
        self.assertEqual(('person', True), (result['wait_kind'], result['person_handoff']), result['reasons'])
        f = Fake(); f.v['reviewDecision'] = 'CHANGES_REQUESTED'; f.v['mergeStateStatus'] = 'BLOCKED'
        result = self.waiting(f)
        self.assertIn("Merge state is not CLEAN: 'BLOCKED'", ' '.join(result['reasons']))
        self.assertIs(True, result['person_handoff'])

    def test_waits_without_a_person_owned_reason_are_not_hand_offs(self):
        f = Fake(); f.c[0]['bucket'] = 'pending'
        result = self.waiting(f)
        self.assertEqual(('transient', False), (result['wait_kind'], result['person_handoff']))
        f = Fake(); f.v['mergeStateStatus'] = 'UNSTABLE'
        result = self.waiting(f)
        self.assertEqual(('person', False), (result['wait_kind'], result['person_handoff']),
                         'a derived reason alone says only that something else is wrong')
        f = Fake(); f.v['mergeable'] = 'SOMETHING_NEW'
        self.assertIs(False, self.waiting(f)['person_handoff'])
        f = Fake(); f.v['reviewDecision'] = 'SOMETHING_NEW'
        self.assertIs(False, self.waiting(f)['person_handoff'])

    def test_a_gate_that_decides_has_no_person_handoff(self):
        self.assertNotIn('person_handoff', evaluate(REPO, 42, sample(), client=Fake()))

    def test_the_registry_holds_only_what_was_registered(self):
        kinds = review_gate.WaitKinds()
        owned, later, derived = kinds.person('a person decides'), kinds.later('GitHub is down'), kinds.secondary('state')
        self.assertTrue(kinds.handoff([owned]))
        self.assertTrue(kinds.handoff([owned, later, derived]))
        self.assertFalse(kinds.handoff([owned, 'a reason nobody registered']))
        self.assertFalse(kinds.handoff(['a reason nobody registered']))
        self.assertFalse(kinds.handoff([later, derived]))
        self.assertFalse(kinds.handoff([]))
        self.assertEqual('person', kinds.kind(['a reason nobody registered']), 'the train is unchanged')

    def test_the_actor_needs_both_the_kind_and_the_flag(self):
        import apply_decision
        from unittest import mock
        gate = {'decision': 'WAITING', 'wait_kind': 'person', 'head_sha': H, 'base_sha': B, 'live_base_sha': B,
                'base_name': 'main', 'reasons': ['GitHub reviewDecision is CHANGES_REQUESTED: waiting']}
        shown = {'state': 'OPEN', 'isDraft': False, 'headRefOid': H, 'baseRefOid': B, 'baseRefName': 'main',
                 'labels': []}
        for extra, labelled in (({'person_handoff': True}, True), ({'person_handoff': False}, False), ({}, False),
                                ({'person_handoff': 'yes'}, False)):
            with self.subTest(extra=extra), mock.patch.object(apply_decision, 'pr_view', return_value=shown), \
                    mock.patch.object(apply_decision, 'branch_head', return_value=B), \
                    mock.patch.object(apply_decision, 'issue_comments', return_value=[]), \
                    mock.patch.object(apply_decision, 'viewer_login', return_value='bot'), \
                    mock.patch.object(apply_decision, 'post_comment') as comment, \
                    mock.patch.object(apply_decision, 'edit_label') as label, \
                    mock.patch.object(apply_decision, '_read_until', return_value=(True, shown, None)):
                apply_decision._waiting_handoff(REPO, 42, dict(gate, **extra), {}, sleep=lambda s: None)
            self.assertEqual(labelled, label.called)
            self.assertEqual(labelled, comment.called)


class MarkerTests(unittest.TestCase):
    def gate_result(self, reasons=('GitHub reviewDecision is CHANGES_REQUESTED: waiting for that reviewer',)):
        return {'head_sha': H, 'base_sha': B, 'live_base_sha': B, 'reasons': list(reasons)}

    def test_the_comment_names_the_head_and_round_trips(self):
        text = needs_person.comment_text(self.gate_result())
        self.assertIn(f'Judged HEAD: `{H}`', text)
        self.assertIn('`needs-person`', text)
        marker = needs_person.latest_marker([{'login': 'bot', 'body': text}], 'bot')
        self.assertEqual({'head': H, 'live_base': B,
                          'reasons': needs_person.reasons_digest(self.gate_result()['reasons'])}, marker)

    def test_only_the_actors_own_newest_marker_counts(self):
        mine = needs_person.comment_text(self.gate_result())
        newer = needs_person.comment_text(dict(self.gate_result(), head_sha='c' * 40))
        self.assertIsNone(needs_person.latest_marker([{'login': 'someone', 'body': mine}], 'bot'))
        got = needs_person.latest_marker([{'login': 'bot', 'body': mine}, {'login': 'someone', 'body': newer},
                                          {'login': 'bot', 'body': 'unrelated'}], 'bot')
        self.assertEqual(H, got['head'])
        got = needs_person.latest_marker([{'login': 'bot', 'body': mine}, {'login': 'bot', 'body': newer}], 'bot')
        self.assertEqual('c' * 40, got['head'])

    def test_list_ready_names_the_trains_label(self):
        import list_ready
        import merge_train
        self.assertEqual(merge_train.QUEUE_LABEL, list_ready.QUEUE_LABEL)

    def test_the_digest_ignores_order_but_not_content(self):
        d = needs_person.reasons_digest
        self.assertEqual(d(['a', 'b']), d(['b', 'a']))
        self.assertNotEqual(d(['a']), d(['a', 'b']))


if __name__ == '__main__':
    unittest.main()
