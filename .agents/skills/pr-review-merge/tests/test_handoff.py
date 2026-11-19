"""Every gate result has an owner: a PR the gate cannot merge either goes back to pr-ready as a Draft
with the steps, or is marked as waiting for a person.

Two gate rules (the actor's needs-person mark is tested end to end in test_integration.py):

* The merge train's integration would bring runtime files the saved target record cannot cover: the
  train's step 5 would Draft the PR after integrating it and waiting for CI, so the gate decides that
  Draft before the PR is queued.
* An unresolved dependency the reviewer says pr-ready can resolve on the branch (`branch_repair`) is a
  Draft with those steps; any other unresolved dependency still waits for a person.
"""
import ast
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


def tv_gh(manifest=None, artifact=tvt.RECORD):
    """A client whose base branch holds a pr-evidence manifest and whose HEAD holds the artifact."""
    f = Fake()
    f.files[(tvt.MANIFEST, B)] = tvt.captured_manifest() if manifest is None else manifest
    if artifact is not None:
        f.files[(tvt.ART, H)] = artifact
    f.compares[(tvt.R, H)] = {'status': 'ahead', 'ancestor': True, 'files': [tvt.ART]}
    f.compares[(B, H)] = {'status': 'ahead', 'ancestor': True, 'files': ['README.md', tvt.ART]}
    return f


def _record_evidence(*args, **kw):
    def apply(e):
        e['target_validation'] = tvt.record(*args, **kw)
    return apply


def _cut(f):
    f.ancestor = False
    f.compares[(B, H)] = {'files': ['pkg/a.go'], 'merge_base': 'e' * 40, 'ancestor': False}

    def cut(repo, base, head):
        raise CompareLimitError('GitHub lists at most 300 changed files')
    f.compare = cut


def _cover(f):
    f.compares[(tvt.R, H)] = {'status': 'ahead', 'ancestor': True,
                              'files': [tvt.ART, 'playbooks/apply/os-patch-sla-apply.yml']}


def _two_records():
    two = json.loads(tvt.captured_manifest())
    two['required_evidence'].append(dict(two['required_evidence'][0], id='second'))
    return json.dumps(two).encode()


def _evidence(**delta):
    def apply(e):
        e.update(delta)
    return apply


_DISPUTED = [{'severity': 'P2', 'path': 'pkg/a.go', 'line': 21, 'reason': 'Rescue skips rollback',
              'recommendation': 'Tag the rescue always', 'blocking': True,
              'disputed_reply_url': 'https://github.com/acme/demo/pull/42#issuecomment-6501033173'}]
_UNRELATED = [{'name': 'test', 'reviewer_confirmed': True,
               'reason': 'Same timeout fails on main at the base SHA, run 40802511042'}]
_REQUIRED_CHECKS = 'Branch requires status checks, but GitHub returned no completed checks'
_BLOCKED_TARGET = dict(reason='vm-target host has no free KVM capacity this week')

def _replace_tv(f, **kw):
    """Give `f` the files of a tv_gh() client (a family's `github` function works on a plain Fake)."""
    other = tv_gh(**kw)
    f.files.update(other.files)
    f.compares.update(other.compares)


# Every family of WAITING that only a person can resolve, as a declarative table. A case is built from
# `Fake()` + `sample()` plus ONLY the deltas the family declares, so nothing else (a `no_ci_rationale` that
# a reviewer following the contract would not write, a stray finding) can make it pass for another reason.
#   view / checks / rules: GitHub's PR view fields, check list and branch rules that differ from the default
#   github:   a function that applies the rest of the GitHub delta (files, compares, a failing compare)
#   evidence: a function that applies the evidence delta; `touches` lists the top-level keys it may change
#   verdicts: the verdicts a reviewer following references/evidence-contract.md gives for this state
#   state:    the merge state GitHub reports for it besides CLEAN (None when it reports none)
#   emits:    the literal text of the `kinds.person(...)`/`owned(...)` call sites that produce its reason
PERSON_FAMILIES = {
    'CHANGES_REQUESTED': dict(
        view={'reviewDecision': 'CHANGES_REQUESTED'}, state='BLOCKED',
        emits=('GitHub reviewDecision is CHANGES_REQUESTED: waiting for that reviewer to re-review',)),
    'REVIEW_REQUIRED': dict(
        view={'reviewDecision': 'REVIEW_REQUIRED'}, state='BLOCKED',
        emits=('Human approval required by repository rules',)),
    'branch rules require approval': dict(
        view={'reviewDecision': None}, state='BLOCKED',
        rules=[{'type': 'pull_request', 'parameters': {'required_approving_review_count': 1}}],
        emits=('Branch rules require reviewer approval',)),
    'repeated dispute without new evidence': dict(
        evidence=_evidence(findings=_DISPUTED), touches=('verdict', 'findings'), verdicts=('BLOCK',),
        emits=(' without new evidence; a person decides between the finding and the dispute',)),
    'unrelated failing check': dict(
        checks='fail', state='UNSTABLE',
        evidence=_evidence(unrelated_failing_checks=_UNRELATED), touches=('unrelated_failing_checks',),
        emits=(', unrelated to this PR per the reviewer (',)),
    'merge queue': dict(
        rules=[{'type': 'merge_queue'}], state='BLOCKED',
        emits=('Base branch requires merge queue; no unattended queue/auto-merge',)),
    'required checks without results': dict(
        checks=[], rules=[{'type': 'required_status_checks'}], state='BLOCKED',
        emits=(_REQUIRED_CHECKS,)),
    'auto-merge configured': dict(
        view={'autoMergeRequest': {'enabledAt': '2026-11-19T00:00:00Z'}},
        emits=('PR already has auto-merge configured; do not modify silently',)),
    'comparison cut by GitHub': dict(
        github=_cut, emits=(' and the merge train cannot classify it yet: ',)),
    'stated unresolved dependency': dict(
        evidence=_evidence(dependencies={'resolved': False, 'evidence': 'Needs kjelly/pilot#400 merged first: '
                                                                          'it adds the contract this PR reads'}),
        touches=('dependencies',), verdicts=('PASS', 'BLOCK'),
        emits=('Unresolved inter-PR dependency:',)),
    'target run does not cover HEAD': dict(
        github=lambda f: (_replace_tv(f), _cover(f)), evidence=_record_evidence(), touches=('target_validation',),
        emits=(' does not cover HEAD ',)),
    'target artifact not committed at HEAD': dict(
        github=lambda f: _replace_tv(f), touches=('target_validation',),
        evidence=_record_evidence(artifact='docs/evidence/feature/missing.md'),
        emits=(' is not committed at HEAD ',)),
    'target artifact does not name the revision': dict(
        github=lambda f: _replace_tv(f, artifact=b'no revision at all'), touches=('target_validation',),
        evidence=_record_evidence(), emits=(' does not name the tested revision ',)),
    'target blocked': dict(
        github=lambda f: _replace_tv(f), touches=('target_validation',), verdicts=('PASS', 'BLOCK'),
        evidence=_record_evidence('blocked', **_BLOCKED_TARGET), emits=('; target validation is blocked: ',)),
    'manifest requires two records': dict(
        github=lambda f: _replace_tv(f, manifest=_two_records()), touches=('target_validation',),
        evidence=_record_evidence(), emits=('); target_validation records one, so a person decides',)),
}
FAMILY_FIELDS = {'view', 'checks', 'rules', 'github', 'evidence', 'touches', 'verdicts', 'state', 'emits'}


def build_family(family, verdict='PASS', state='CLEAN'):
    """The client and evidence of one family under one verdict and merge state."""
    spec = PERSON_FAMILIES[family]
    f = Fake()
    f.v.update(spec.get('view', {}))
    if spec.get('checks') == 'fail':
        f.c[0]['bucket'] = 'fail'
    elif spec.get('checks') is not None:
        f.c = list(spec['checks'])
    if 'rules' in spec:
        f.r = list(spec['rules'])
    if 'github' in spec:
        spec['github'](f)
    f.v['mergeStateStatus'] = state
    e = sample()
    if 'evidence' in spec:
        spec['evidence'](e)
    e['verdict'] = verdict
    return f, e


def person_call_keys(source):
    """The literal text each `kinds.person(...)`/`owned(...)` call of review_gate.py registers: the longest
    run of literal text of its argument (an f-string's constants, a module constant substituted, a name
    resolved to the string assigned to it in the same function). A call whose argument cannot be resolved
    is reported in the second result; `person(gap) if gap in target_person` hands the choice to the
    `owned(...)` calls, which are scanned themselves."""
    tree = ast.parse(source)
    consts = {n.targets[0].id: n.value.value for n in tree.body
              if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
              and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)}
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def runs(node, call):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.Name) and node.id in consts:
            return [consts[node.id]]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = runs(node.left, call), runs(node.right, call)
            return None if left is None or right is None else [''.join(left + right)]
        if isinstance(node, ast.JoinedStr):
            out, cur = [], ''
            for part in node.values:
                if isinstance(part, ast.Constant):
                    cur += part.value
                elif isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name) \
                        and part.value.id in consts:
                    cur += consts[part.value.id]
                else:
                    out.append(cur)
                    cur = ''
            return out + [cur]
        if isinstance(node, ast.Name):
            scope = call
            while scope in parents and not isinstance(scope, ast.FunctionDef):
                scope = parents[scope]
            assigned = [n for n in ast.walk(scope) if isinstance(n, ast.Assign) and n.lineno < call.lineno
                        and any(isinstance(t, ast.Name) and t.id == node.id for t in n.targets)]
            if assigned:
                return runs(max(assigned, key=lambda n: n.lineno).value, call)
            up = call
            while up in parents:                    # `person(g) if g.startswith(CONST + ":") else g`
                up = parents[up]
                if isinstance(up, ast.IfExp):
                    test = up.test
                    if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) \
                            and test.func.attr == 'startswith' and test.args:
                        return runs(test.args[0], call)
                    break
        return None

    keys, unresolved = set(), []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or len(call.args) != 1:
            continue
        func = call.func
        if not ((isinstance(func, ast.Attribute) and func.attr == 'person' and isinstance(func.value, ast.Name)
                 and func.value.id == 'kinds') or (isinstance(func, ast.Name) and func.id == 'owned')):
            continue
        got = runs(call.args[0], call)
        if got is None:
            if isinstance(call.args[0], ast.Name) and any(
                    isinstance(p, ast.IfExp) and ast.unparse(p.test) == f'{call.args[0].id} in target_person'
                    for p in _ancestors(call, parents)):
                continue
            unresolved.append(f'line {call.lineno}: {ast.unparse(call)}')
        else:
            keys.add(max(got, key=len))
    return keys, unresolved


def _ancestors(node, parents):
    while node in parents:
        node = parents[node]
        yield node


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
        return tv_gh(manifest, artifact)

    def with_tv(self, tv):
        e = sample()
        if tv is not None:
            e['target_validation'] = tv
        return e

    def person_cases(self):
        """family -> (client, evidence): each is a WAITING only a person can resolve (PERSON_FAMILIES,
        under the first verdict the contract gives it)."""
        return {family: build_family(family, spec.get('verdicts', ('PASS',))[0])
                for family, spec in PERSON_FAMILIES.items()}

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
        # Each family under each verdict a reviewer following the contract gives it, and under CLEAN and the
        # merge state GitHub reports for it. Nothing else is set: a gate that hands off only because the case
        # also carries an unrelated field (the old `no_ci_rationale` on a branch that requires CI) fails here.
        for family, spec in PERSON_FAMILIES.items():
            for verdict in spec.get('verdicts', ('PASS',)):
                for state in ('CLEAN',) + ((spec['state'],) if spec.get('state') else ()):
                    with self.subTest(family=family, verdict=verdict, state=state):
                        gh, data = build_family(family, verdict, state)
                        result = self.waiting(gh, data)
                        self.assertEqual('person', result['wait_kind'], result['reasons'])
                        self.assertIs(True, result['person_handoff'], result['reasons'])
                        for text in spec['emits']:
                            self.assertTrue(any(text in r for r in result['reasons']), (text, result['reasons']))

    def test_the_family_table_adds_nothing_it_does_not_declare(self):
        base = sample()
        for family, spec in PERSON_FAMILIES.items():
            with self.subTest(family=family):
                self.assertLessEqual(set(spec), FAMILY_FIELDS)
                self.assertTrue(spec['emits'], 'a family names the call sites that produce its reason')
                for verdict in spec.get('verdicts', ('PASS',)):
                    self.assertIn(verdict, ('PASS', 'BLOCK'), 'NEEDS_MORE_EVIDENCE is not a contract verdict here')
                    gh, data = build_family(family, verdict)
                    changed = {k for k in set(data) | set(base) if data.get(k) != base.get(k)}
                    self.assertLessEqual(changed, set(spec.get('touches', ())) | {'verdict'}, changed)
                    self.assertEqual('', data['no_ci_rationale'], 'a reviewer writes no rationale for a branch '
                                     'without CI only when the branch has no required checks')
                    self.assertEqual(base['tests'], data['tests'])
                    self.assertEqual(base['coverage'], data['coverage'])

    def test_the_family_table_covers_every_registered_person_reason(self):
        """Registry completeness: every `kinds.person(...)`/`owned(...)` call site of review_gate.py is
        exercised by a family, and every family names call sites that exist. A reason registered as
        person-owned without a family here would be an untested hand-off (and one that another, unregistered
        reason could mask, as the required-checks one was)."""
        source = Path(review_gate.__file__).read_text(encoding='utf-8')
        keys, unresolved = person_call_keys(source)
        self.assertEqual([], unresolved, 'teach person_call_keys the new call form or register a literal')
        declared = {text for spec in PERSON_FAMILIES.values() for text in spec['emits']}
        self.assertEqual(sorted(keys), sorted(declared))

    def test_the_registry_lint_fails_on_a_person_reason_without_a_family(self):
        source = Path(review_gate.__file__).read_text(encoding='utf-8')
        reason = '"Base branch requires merge queue; no unattended queue/auto-merge"'
        self.assertIn(reason, source)
        declared = sorted(text for spec in PERSON_FAMILIES.values() for text in spec['emits'])
        keys, _ = person_call_keys(source.replace(reason, '"A brand new person-owned reason"', 1))
        self.assertIn('A brand new person-owned reason', keys)
        self.assertNotEqual(sorted(keys), declared)
        # and a call whose argument it cannot read is reported instead of ignored
        call = f'kinds.person({reason})'
        self.assertIn(call, source)
        self.assertEqual(1, len(person_call_keys(source.replace(call, 'kinds.person(some_function())', 1))[1]))

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


class RequiredChecksTests(unittest.TestCase):
    """No GitHub checks: the no-CI rationale gap applies only on a branch without required checks. On one
    that requires them, the branch protection is what waits for a person, whatever the evidence says."""
    RATIONALE = 'The repository has no CI workflow for this docs-only change'

    def gate(self, rules=None, rationale='', tested=True, view=None, gh=None):
        f = Fake() if gh is None else gh
        f.c = []
        if rules is not None:
            f.r = list(rules)
        f.v.update(view or {})
        e = sample()
        e['no_ci_rationale'] = rationale
        if not tested:
            e['tests'][0].update(status='SKIPPED', reason='no runner on this host today')
        return evaluate(REPO, 42, e, client=f)

    def test_contract_evidence_waits_on_the_branch_rule_alone(self):
        result = self.gate([{'type': 'required_status_checks'}])
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        self.assertEqual([_REQUIRED_CHECKS], result['reasons'])
        self.assertEqual(('person', True), (result['wait_kind'], result['person_handoff']))

    def test_a_rationale_never_merges_a_branch_that_requires_checks(self):
        for tested in (True, False):
            with self.subTest(tested=tested):
                result = self.gate([{'type': 'required_status_checks'}], self.RATIONALE, tested)
                self.assertEqual('WAITING', result['decision'], result['reasons'])
                self.assertEqual([_REQUIRED_CHECKS], result['reasons'])
                self.assertIs(True, result['person_handoff'])

    def test_a_branch_without_required_checks_keeps_the_rationale_gap(self):
        for rules in (None, [{'type': 'pull_request', 'parameters': {}}]):
            with self.subTest(rules=rules):
                result = self.gate(rules)
                self.assertEqual('WAITING', result['decision'], result['reasons'])
                self.assertEqual(['No GitHub CI: requires a concrete no-CI rationale and passing test evidence'],
                                 result['reasons'])
                self.assertEqual(('person', False), (result['wait_kind'], result['person_handoff']))
        self.assertEqual('MERGE', self.gate(None, self.RATIONALE)['decision'])
        self.assertEqual('WAITING', self.gate(None, self.RATIONALE, tested=False)['decision'])

    def test_unreadable_rules_keep_the_rationale_gap_and_fail_closed(self):
        def unreadable(repo, branch):
            raise GitHubError('gh api rules failed (1): HTTP 502')
        f = Fake(); f.branch_rules = unreadable
        result = self.gate(gh=f)
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        self.assertIn('No GitHub CI: requires a concrete no-CI rationale and passing test evidence', result['reasons'])
        self.assertEqual(('person', False), (result['wait_kind'], result['person_handoff']))
        # With a rationale the unreadable rules alone wait: the branch is never assumed to be free of them.
        f = Fake(); f.branch_rules = unreadable
        result = self.gate(gh=f, rationale=self.RATIONALE)
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        self.assertFalse(any('No GitHub CI' in r for r in result['reasons']))
        self.assertIn('Unable to verify active branch rules', ' '.join(result['reasons']))
        self.assertIs(False, result['person_handoff'])

    def test_the_reason_order_is_unchanged(self):
        # The rationale gap stays ahead of the rule and review reasons; the required-checks reason follows
        # the merge queue reason.
        result = self.gate(None, view={'reviewDecision': 'REVIEW_REQUIRED'})
        self.assertEqual(['No GitHub CI: requires a concrete no-CI rationale and passing test evidence',
                          'Human approval required by repository rules'], result['reasons'])
        result = self.gate([{'type': 'required_status_checks'}, {'type': 'merge_queue'}])
        self.assertEqual(['Base branch requires merge queue; no unattended queue/auto-merge', _REQUIRED_CHECKS],
                         result['reasons'])

    def test_a_merge_queue_with_required_checks_and_no_checks_hands_off(self):
        result = self.gate([{'type': 'merge_queue'}, {'type': 'required_status_checks'}],
                           view={'mergeStateStatus': 'BLOCKED'})
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        self.assertIs(True, result['person_handoff'], result['reasons'])
        self.assertFalse(any('No GitHub CI' in r for r in result['reasons']))

    def test_checks_that_ran_are_unaffected_by_the_rule(self):
        f = Fake(); f.r = [{'type': 'required_status_checks'}]
        self.assertEqual('MERGE', evaluate(REPO, 42, sample(), client=f)['decision'])


class BlockVerdictTests(unittest.TestCase):
    """A BLOCK verdict judges the diff and needs a finding or a failed test. A state only a person can change
    (a stated unresolved dependency, a blocked target record) is not a finding, but a reviewer who answers
    BLOCK for it still hands the PR to that person; any other BLOCK without a finding stays unexplained."""
    NO_FINDING = 'BLOCK verdict needs a specific finding or failed test'

    def case(self, family, verdict):
        gh, data = build_family(family, verdict)
        return evaluate(REPO, 42, data, client=gh)

    def test_block_for_a_stated_dependency_or_a_blocked_target_hands_off(self):
        for family in ('stated unresolved dependency', 'target blocked'):
            with self.subTest(family=family):
                result = self.case(family, 'BLOCK')
                self.assertEqual('WAITING', result['decision'], result['reasons'])
                self.assertNotIn(self.NO_FINDING, result['reasons'])
                self.assertEqual(('person', True), (result['wait_kind'], result['person_handoff']), result['reasons'])

    def test_block_alone_keeps_its_message(self):
        e = sample(); e['verdict'] = 'BLOCK'
        result = evaluate(REPO, 42, e, client=Fake())
        self.assertEqual('WAITING', result['decision'])
        self.assertEqual([self.NO_FINDING], result['reasons'])
        self.assertIs(False, result['person_handoff'])

    def test_block_with_a_person_state_that_is_not_stated_keeps_its_message(self):
        # A dependency explanation too short to count, a record that is only malformed, a record that
        # is required but not blocked: none of them is a state only a person can change.
        e = sample(); e['verdict'] = 'BLOCK'; e['dependencies'] = {'resolved': False, 'evidence': 'x'}
        result = evaluate(REPO, 42, e, client=Fake())
        self.assertIn(self.NO_FINDING, result['reasons'])
        self.assertIs(False, result['person_handoff'])
        gh, data = build_family('target artifact not committed at HEAD', 'BLOCK')
        result = evaluate(REPO, 42, data, client=gh)
        self.assertIn(self.NO_FINDING, result['reasons'])

    def test_the_message_keeps_its_place_among_the_reasons(self):
        e = sample(); e['verdict'] = 'BLOCK'; e['coverage']['security'] = False
        reasons = evaluate(REPO, 42, e, client=Fake())['reasons']
        self.assertEqual([self.NO_FINDING], reasons[:1])
        self.assertIn('coverage incomplete', reasons[1])

    def test_needs_more_evidence_stays_listable_for_those_states(self):
        for family in ('stated unresolved dependency', 'target blocked'):
            with self.subTest(family=family):
                result = self.case(family, 'NEEDS_MORE_EVIDENCE')
                self.assertEqual('WAITING', result['decision'], result['reasons'])
                self.assertIn('Reviewer requested further evidence', result['reasons'])
                self.assertEqual(('person', False), (result['wait_kind'], result['person_handoff']))

    def test_pass_for_those_states_is_what_the_contract_says_and_never_merges(self):
        for family in ('stated unresolved dependency', 'target blocked'):
            with self.subTest(family=family):
                self.assertEqual('WAITING', self.case(family, 'PASS')['decision'])


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
