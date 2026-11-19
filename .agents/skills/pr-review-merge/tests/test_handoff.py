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
from gh_runtime import GitHubError, Repo  # noqa: E402
import needs_person  # noqa: E402
import review_gate  # noqa: E402
from review_gate import evaluate, train_import_invalidates_record  # noqa: E402
from test_gate import B, H, Fake, sample  # noqa: E402
from scan_stub import CleanScan  # noqa: E402

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
        self.assertEqual('person', result['wait_kind'])
        self.assertIn('Unresolved/unverified inter-PR dependencies', result['reasons'])

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

    def test_a_resolved_dependency_still_merges(self):
        self.assertEqual('MERGE', gate(Fake(), tv={})['decision'])


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
