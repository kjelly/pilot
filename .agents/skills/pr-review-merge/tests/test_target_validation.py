"""The gate enforces the actual-run record that the base branch's .github/pr-evidence.json mandates.

GitHub answers come from fixtures/github_api.json: read-only `gh api` captures against
kjelly/pilot (exit status, stdout, stderr). Gate-level tests use test_gate's Fake client with
the manifest bytes and compare results those captures decode to.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
sys.path.insert(0, str(HERE.parent / 'scripts'))
sys.path.insert(0, str(HERE))
import gh_runtime  # noqa: E402
from gh_runtime import GitHubError, Repo  # noqa: E402
from review_gate import evaluate  # noqa: E402
from test_gate import B, H, Fake, sample  # noqa: E402

API = json.loads((HERE / 'fixtures' / 'github_api.json').read_text())
MANIFEST = '.github/pr-evidence.json'
REPO = Repo.parse('acme/demo')
R = 'c' * 40   # tested candidate, an ancestor of H
ART = 'docs/evidence/feature/2026-10-31-ccccccc.md'
RECORD = b'| Tested candidate | `ccccccc` (tree `0123abc...`) |\n'


def replay(capture):
    """run_gh stand-in that returns one recorded gh invocation and remembers the endpoint."""
    seen = []

    def run_gh(args, *, input_text=None, check=True):
        seen.append(args[-1])
        return subprocess.CompletedProcess(['gh', *args], capture['rc'], capture['stdout'], capture['stderr'])
    return run_gh, seen


def captured_manifest():
    """The manifest bytes on kjelly/pilot main at fdb6f03e, through gh_runtime.file_at."""
    run_gh, _ = replay(API['contents']['manifest_at_fdb6f03e'])
    with mock.patch.object(gh_runtime, 'run_gh', run_gh):
        return gh_runtime.file_at(REPO, MANIFEST, 'fdb6f03e9152de5e48dc6b9870cab2d050bf962e')


def captured_compare(name):
    entry = API['compare'][name]
    run_gh, _ = replay(entry)
    with mock.patch.object(gh_runtime, 'run_gh', run_gh):
        return gh_runtime.compare(REPO, *entry['args'])


def repo_manifest():
    """This repository's own manifest (with required_paths), as a later base will carry it."""
    return (REPO_ROOT / MANIFEST).read_bytes()


def record(decision='required', **extra):
    tv = {'decision': decision, 'reason': 'Changes playbooks/apply/x.yml; run on vm-target per AGENTS.md 1.4',
          'artifact': ART, 'tested_revision': R}
    tv.update(extra)
    return tv


class GitHubShapeTests(unittest.TestCase):
    """gh_runtime.file_at / compare read the recorded GitHub answers correctly."""

    def call(self, fn, capture, *args):
        run_gh, seen = replay(capture)
        with mock.patch.object(gh_runtime, 'run_gh', run_gh):
            return fn(REPO, *args), seen

    def test_manifest_present_absent_and_unknown_ref(self):
        c = API['contents']
        raw, seen = self.call(gh_runtime.file_at, c['manifest_at_fdb6f03e'], MANIFEST, c['manifest_at_fdb6f03e']['ref'])
        self.assertEqual(['actual-run'], [r['id'] for r in json.loads(raw)['required_evidence']])
        self.assertEqual([f"repos/acme/demo/contents/{MANIFEST}?ref={c['manifest_at_fdb6f03e']['ref']}"], seen)
        self.assertIsNone(self.call(gh_runtime.file_at, c['manifest_absent_at_d013ed95'], MANIFEST,
                                    c['manifest_absent_at_d013ed95']['ref'])[0])
        # An unknown commit is not "no manifest": that would drop the requirement.
        with self.assertRaisesRegex(GitHubError, 'No commit found'):
            self.call(gh_runtime.file_at, c['unknown_ref'], MANIFEST, 'd' * 40)

    def test_only_the_exact_404_means_absent(self):
        absent = API['contents']['missing_file']
        for changed in (dict(absent, stderr='gh: Bad Gateway (HTTP 502)\n'), dict(absent, rc=2),
                        dict(absent, stdout=absent['stdout'].replace('Not Found', 'Moved')),
                        dict(absent, stdout='not json')):
            with self.subTest(changed=changed), self.assertRaises(GitHubError):
                self.call(gh_runtime.file_at, changed, 'docs/evidence/x.md', H)

    def test_evidence_record_directory_and_missing_file(self):
        c = API['contents']
        raw, _ = self.call(gh_runtime.file_at, c['evidence_record'], c['evidence_record']['path'], c['evidence_record']['ref'])
        self.assertIn(b'`2d70670`', raw)
        with self.assertRaisesRegex(GitHubError, 'directory'):
            self.call(gh_runtime.file_at, c['directory'], c['directory']['path'], c['directory']['ref'])
        self.assertIsNone(self.call(gh_runtime.file_at, c['missing_file'], c['missing_file']['path'],
                                    c['missing_file']['ref'])[0])
        # The answer must be for the requested path (a symlink resolves to another one).
        with self.assertRaisesRegex(GitHubError, 'not a regular file'):
            self.call(gh_runtime.file_at, c['evidence_record'], 'docs/evidence/other.md', c['evidence_record']['ref'])
        with self.assertRaises(ValueError):
            gh_runtime.file_at(REPO, MANIFEST, 'main')

    def test_compare_ancestry_and_files(self):
        cases = {'ahead_evidence_only': (True, ['docs/evidence/os-patch-sla/2026-10-29-2d70670.md']),
                 'identical': (True, []),
                 'behind': (False, []),
                 'diverged': (False, None),
                 'ahead_with_code': (True, None)}
        for name, (ancestor, files) in cases.items():
            with self.subTest(name):
                got = captured_compare(name)
                self.assertEqual(ancestor, got['ancestor'])
                if files is not None:
                    self.assertEqual(files, got['files'])
        self.assertIn('playbooks/apply/os-patch-sla-apply.yml', captured_compare('ahead_with_code')['files'])

    def test_compare_lists_both_names_of_a_rename(self):
        files = captured_compare('rename')['files']
        self.assertIn('docs/evidence/freeipa-identity/2026-10-30-5075282.md', files)
        self.assertIn('docs/evidence/freeipa-identity/2026-10-29-46dce32.md', files)

    def test_compare_cut_at_300_files_and_unknown_commit(self):
        with self.assertRaisesRegex(GitHubError, 'at most 300'):
            captured_compare('over_300_files')
        self.assertIsNone(captured_compare('unknown_sha'))


class TargetValidationTests(unittest.TestCase):
    def gh(self, manifest=None, head_manifest=None, artifact=RECORD):
        f = Fake()
        if manifest is not None:
            f.files[(MANIFEST, B)] = manifest
        if head_manifest is not None:
            f.files[(MANIFEST, H)] = head_manifest
        if artifact is not None:
            f.files[(ART, H)] = artifact
        # R..H changed only an evidence record; the PR (B...H) changed docs only.
        f.compares[(R, H)] = {'status': 'ahead', 'ancestor': True, 'files': [ART]}
        f.compares[(B, H)] = {'status': 'ahead', 'ancestor': True, 'files': ['README.md', ART]}
        return f

    def gate(self, tv=None, gh=None, drop=False):
        e = sample()
        if not drop:
            e['target_validation'] = record() if tv is None else tv
        return evaluate(REPO, 42, e, client=self.gh(captured_manifest()) if gh is None else gh)

    def assertWaits(self, result, text):
        self.assertEqual('WAITING', result['decision'], result['reasons'])
        self.assertIn(text, ' '.join(result['reasons']))

    def test_required_record_covering_head_merges(self):
        gh = self.gh(captured_manifest(), artifact=b'Tested candidate `' + H.encode() + b'`')
        result = self.gate(record(tested_revision=H), gh=gh)
        self.assertEqual('MERGE', result['decision'], result['reasons'])
        self.assertEqual('loaded', result['target_validation']['manifest'])

    def test_required_record_after_an_evidence_only_delta_merges(self):
        result = self.gate()
        self.assertEqual('MERGE', result['decision'], result['reasons'])
        self.assertEqual([R], [d['from'] for d in result['target_validation']['delta_accepted']])
        self.assertEqual('MERGE', self.gate(record(tested_revision=R.upper()))['decision'])

    def test_missing_record_waits_and_never_drafts(self):
        result = self.gate(drop=True)
        self.assertWaits(result, "requires the 'actual-run' record")
        self.assertIn('target_validation is missing', ' '.join(result['reasons']))

    def test_malformed_record_waits(self):
        for tv in ('not-needed', ['required'], {}, None):
            e = sample(); e['target_validation'] = tv
            with self.subTest(tv=tv):
                self.assertEqual('WAITING', evaluate(REPO, 42, e, client=self.gh(captured_manifest()))['decision'])

    def test_decision_must_be_known(self):
        for decision in ('skip', 'NOT-NEEDED', '', None):
            with self.subTest(decision=decision):
                self.assertWaits(self.gate(record(decision)), 'decision must be one of')

    def test_reason_is_required(self):
        for reason in (None, '', 'docs only', 'x' * 29, 42):
            with self.subTest(reason=reason):
                self.assertWaits(self.gate(record('not-needed', reason=reason)), 'reason must state')
        self.assertEqual('MERGE', self.gate(record('not-needed', reason='y' * 30))['decision'])

    def test_blocked_waits(self):
        result = self.gate(record('blocked', reason='vm-target host has no free KVM capacity this week'))
        self.assertWaits(result, 'target validation is blocked: vm-target host has no free KVM')

    def test_not_needed_without_required_paths_trusts_the_reviewer(self):
        # The manifest captured from main has no required_paths: a reasoned not-needed passes.
        result = self.gate(record('not-needed', reason='Docs-only change; no playbook, spec or contract touched.'))
        self.assertEqual('MERGE', result['decision'], result['reasons'])

    def test_not_needed_is_refused_for_required_paths(self):
        tv = record('not-needed', reason='Docs-only change; no playbook, spec or contract touched.')
        gh = self.gh(repo_manifest())
        self.assertEqual('MERGE', self.gate(tv, gh=gh)['decision'])
        for path in ('playbooks/apply/os-patch-sla-apply.yml', 'contracts/dns.yaml'):
            gh.compares[(B, H)] = {'status': 'diverged', 'ancestor': False, 'files': ['README.md', path]}
            with self.subTest(path=path):
                self.assertWaits(self.gate(tv, gh=gh), f'not-needed, but the PR changes {path}')
        # A spec edit is the reviewer's call: prose-only edits need no run (docs/actual-run-evidence.md §4).
        gh.compares[(B, H)] = {'status': 'diverged', 'ancestor': False, 'files': ['docs/verification/dns.md']}
        self.assertEqual('MERGE', self.gate(tv, gh=gh)['decision'])
        gh.compares[(B, H)] = None
        self.assertWaits(self.gate(tv, gh=gh), 'could not compare')

        def too_large(repo, base, head):
            raise GitHubError('GitHub lists at most 300 changed files')
        gh.compare = too_large
        self.assertWaits(self.gate(tv, gh=gh), 'cannot be listed')

    def test_tested_revision_must_cover_head(self):
        gh = self.gh(captured_manifest())
        gh.compares[(R, H)] = {'status': 'ahead', 'ancestor': True,
                               'files': [ART, 'playbooks/apply/os-patch-sla-apply.yml']}
        self.assertWaits(self.gate(gh=gh), 'files outside evidence_only_paths changed: playbooks/apply/')
        for cmp in ({'status': 'diverged', 'ancestor': False, 'files': [ART]}, None):
            gh.compares[(R, H)] = cmp
            with self.subTest(cmp=cmp):
                self.assertWaits(self.gate(gh=gh), 'not an ancestor of HEAD')

    def test_a_rename_out_of_code_is_not_evidence_only(self):
        # Real rename capture, with the old name moved out of docs/evidence.
        entry = dict(API['compare']['rename'])
        body = json.loads(entry['stdout'])
        body['files'] = [dict(body['files'][0], previous_filename='playbooks/apply/x.yml')]
        run_gh, _ = replay(dict(entry, stdout=json.dumps(body)))
        with mock.patch.object(gh_runtime, 'run_gh', run_gh):
            cmp = gh_runtime.compare(REPO, *entry['args'])
        gh = self.gh(captured_manifest())
        gh.compares[(R, H)] = cmp
        self.assertWaits(self.gate(gh=gh), 'playbooks/apply/x.yml')

    def test_tested_revision_must_be_a_full_sha(self):
        for rev in (None, '', 'ccccccc', 'g' * 40, 'c' * 41, 7):
            with self.subTest(rev=rev):
                self.assertWaits(self.gate(record(tested_revision=rev)), 'full 40-hex SHA')

    def test_artifact_must_be_a_committed_record_in_the_required_location(self):
        cases = {'docs/runbooks/os-patch-sla.md': 'outside the required location docs/evidence/**/*.md',
                 'docs/evidence/feature/run.txt': 'outside the required location',
                 '/docs/evidence/a/b.md': 'repository-relative path',
                 'docs/evidence/../../playbooks/x.md': 'repository-relative path',
                 '': 'repository-relative path', None: 'repository-relative path',
                 'docs/evidence/feature/missing.md': 'is not committed at HEAD'}
        for art, text in cases.items():
            with self.subTest(art=art):
                self.assertWaits(self.gate(record(artifact=art)), text)

    def test_artifact_must_name_the_tested_revision(self):
        for body in (b'Tested candidate `dddddd0`', b'no revision at all', b'cccccc short', b'xcccccccx'):
            with self.subTest(body=body):
                self.assertWaits(self.gate(gh=self.gh(captured_manifest(), artifact=body)),
                                 'does not name the tested revision')
        self.assertEqual('MERGE', self.gate(gh=self.gh(captured_manifest(), artifact=R.encode()))['decision'])

    def test_unreadable_artifact_waits(self):
        gh = self.gh(captured_manifest())
        original = gh.file_at

        def fail_on_record(repo, path, ref):
            if path == ART:
                raise GitHubError('gh api contents failed (1): HTTP 502')
            return original(repo, path, ref)
        gh.file_at = fail_on_record
        self.assertWaits(self.gate(gh=gh), 'cannot read artifact')

    def test_manifest_is_read_at_base_never_head(self):
        weaker = json.dumps({'schema_version': 1, 'evidence_only_paths': ['docs/evidence/**']}).encode()
        gh = self.gh(captured_manifest(), head_manifest=weaker)
        result = self.gate(gh=gh, drop=True)
        self.assertWaits(result, "requires the 'actual-run' record")
        self.assertIn(('file_at', MANIFEST, B), gh.calls)
        self.assertNotIn(('file_at', MANIFEST, H), gh.calls)
        # A requirement the PR adds itself applies only once it is merged.
        self.assertEqual('MERGE', self.gate(gh=self.gh(None, head_manifest=captured_manifest()), drop=True)['decision'])

    def test_no_manifest_keeps_todays_behaviour(self):
        result = self.gate(gh=self.gh(None), drop=True)
        self.assertEqual('MERGE', result['decision'])
        self.assertEqual('absent', result['target_validation']['manifest'])
        no_requirement = json.dumps({'schema_version': 1, 'evidence_only_paths': ['docs/evidence/**']}).encode()
        self.assertEqual('MERGE', self.gate(gh=self.gh(no_requirement), drop=True)['decision'])

    def test_unreadable_or_invalid_manifest_waits(self):
        two = json.loads(captured_manifest())
        two['required_evidence'].append(dict(two['required_evidence'][0], id='second'))
        cases = {b'{not json': 'not valid JSON', b'\xff\xfe': 'not valid JSON',
                 b'{"schema_version": 2}': 'schema_version 1',
                 b'{"schema_version": 1, "evidence_only_paths": ["**"]}': 'defeat SHA binding',
                 json.dumps(dict(json.loads(repo_manifest()), required_evidence=[
                     dict(json.loads(repo_manifest())['required_evidence'][0], required_paths=['/etc/**'])
                 ])).encode(): 'required_paths must be',
                 json.dumps(two).encode(): 'requires 2 records'}
        for raw, text in cases.items():
            with self.subTest(raw=raw[:40]):
                self.assertWaits(self.gate(gh=self.gh(raw)), text)
        gh = self.gh(None)

        def fail(repo, path, ref):
            raise GitHubError('gh api contents .github/pr-evidence.json failed (1): HTTP 502')
        gh.file_at = fail
        self.assertWaits(self.gate(gh=gh, drop=True), 'Cannot read .github/pr-evidence.json at base')

    def test_draft_comes_only_from_the_reviewers_finding(self):
        e = sample(); e['verdict'] = 'BLOCK'
        e['findings'] = [{'severity': 'P1', 'path': 'playbooks/apply/x.yml', 'line': 1, 'blocking': True,
                          'reason': 'Playbook change has no docs/evidence actual-run record (AGENTS.md 1)',
                          'recommendation': 'Run vm-target test on the candidate and commit the record'}]
        result = evaluate(REPO, 42, e, client=self.gh(captured_manifest()))
        self.assertEqual('DRAFT', result['decision'])
        self.assertIn("Also awaiting: The base branch requires the 'actual-run' record", ' '.join(result['reasons']))


class RepositoryManifestTests(unittest.TestCase):
    def test_issue_to_pr_accepts_the_repository_manifest(self):
        import review_gate
        manifest = json.loads(repo_manifest())
        self.assertEqual([], review_gate.repo_evidence.validate_manifest(manifest))
        paths = manifest['required_evidence'][0]['required_paths']
        for path in ('playbooks/apply/dns-apply.yml', 'contracts/dns.yaml'):
            self.assertTrue(any(review_gate.repo_evidence.glob_regex(p).match(path) for p in paths), path)
        for path in ('docs/verification/dns.md', 'docs/runbooks/dns.md', '.agents/skills/x/SKILL.md', 'docs/evidence/dns/a.md'):
            self.assertFalse(any(review_gate.repo_evidence.glob_regex(p).match(path) for p in paths), path)

    def test_the_gate_uses_issue_to_pr_repo_evidence(self):
        import review_gate
        self.assertEqual(HERE.parents[1] / 'issue-to-pr' / 'scripts' / 'repo_evidence.py',
                         Path(review_gate.repo_evidence.__file__))
        self.assertTrue(issubclass(review_gate.RemoteContext, review_gate.repo_evidence.Context))


if __name__ == '__main__':
    unittest.main()
