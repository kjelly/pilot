"""The real `gh_runtime` read wrappers fed with answers recorded from real `gh` (AGENTS.md section 5.6).

`subprocess.run` is replaced by a replay of fixtures/github_api.json (`pr_checks`, `issue_comments`,
`user`), so `run_gh` and the wrappers run unchanged. The train's and the gate's tests use fake clients,
and the integration tests' fake gh executable is only as truthful as this replay: a PR with no check at all
is answered by real gh with rc 1, empty stdout and a stderr line (never `[]`), which the adapter must read
as "no checks" while every other empty answer stays a GitHubError.
"""
import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'scripts'))
import gh_runtime  # noqa: E402
import needs_person  # noqa: E402
from gh_runtime import GitHubError, Repo  # noqa: E402

REPO = Repo.parse('kjelly/pilot')
API = json.loads((HERE / 'fixtures' / 'github_api.json').read_text())


def replay(capture):
    """A `subprocess.run` that answers with a recorded gh result."""
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, capture['rc'], capture['stdout'], capture['stderr'])
    return mock.patch.object(gh_runtime.subprocess, 'run', side_effect=run)


class ChecksReplay(unittest.TestCase):
    def checks(self, capture):
        with replay(capture) as run:
            result = gh_runtime.pr_checks(REPO, 106)
        run.assert_called_once()
        return result

    def test_the_recorded_zero_check_answers_are_no_checks(self):
        # All three recorded forms are the same answer: rc 1, empty stdout, one stderr line.
        for key in ('zero_checks', 'zero_checks_required', 'zero_checks_plain'):
            with self.subTest(key):
                capture = API['pr_checks'][key]
                self.assertEqual((1, ''), (capture['rc'], capture['stdout']))
                self.assertEqual(API['pr_checks']['zero_checks']['stderr'], capture['stderr'])
                self.assertEqual([], self.checks(capture))

    def test_the_recorded_answer_with_checks_is_the_list(self):
        result = self.checks(API['pr_checks']['with_checks'])
        self.assertEqual(3, len(result))
        self.assertEqual({'name', 'state', 'bucket', 'link', 'workflow'}, set(result[0]))

    def test_the_recorded_failures_are_github_errors_not_an_empty_ci(self):
        for key in ('auth_failure', 'no_such_pr', 'network_failure'):
            with self.subTest(key):
                capture = API['pr_checks'][key]
                self.assertEqual(1, capture['rc'])
                self.assertEqual('', capture['stdout'])
                with self.assertRaises(GitHubError):
                    self.checks(capture)

    def test_only_the_exact_recorded_answer_is_no_checks(self):
        zero = API['pr_checks']['zero_checks']
        line = zero['stderr']
        cases = {
            'an extra stderr line': dict(zero, stderr=line + 'HTTP 502: Bad Gateway\n'),
            'a line before it': dict(zero, stderr='warning: something\n' + line),
            'upper case': dict(zero, stderr=line.upper()),
            'rc 0': dict(zero, rc=0),
            'rc 2': dict(zero, rc=2),
            'rc 4': dict(zero, rc=4),
            'junk stdout': dict(zero, stdout='not json'),
            'a stdout that is no list': dict(zero, stdout='{}'),
            'the --required wording': dict(zero, stderr="no required checks reported on the "
                                                        "'fix/freeipa-identity-passwd-failures' branch\n"),
            'no branch name': dict(zero, stderr="no checks reported on the '' branch\n"),
            'nothing on stderr': dict(zero, stderr=''),
            'a longer sentence': dict(zero, stderr=line.rstrip('\n') + ' yet\n'),
        }
        for label, capture in cases.items():
            with self.subTest(label):
                with self.assertRaises(GitHubError):
                    self.checks(capture)

    def test_the_branch_name_does_not_matter(self):
        zero = API['pr_checks']['zero_checks']
        for branch in ('main', 'feat/with spaces and \'quotes', 'x'):
            with self.subTest(branch):
                self.assertEqual([], self.checks(dict(zero, stderr=f"no checks reported on the '{branch}' branch\n")))
        # The line without its newline (a gh that stops adding it) is the same answer.
        self.assertEqual([], self.checks(dict(zero, stderr=zero['stderr'].rstrip('\n'))))


class CommentsReplay(unittest.TestCase):
    def test_a_pr_without_comments_is_an_empty_list(self):
        capture = API['issue_comments']['no_comments']
        self.assertEqual('[[]]', capture['stdout'])
        with replay(capture):
            self.assertEqual([], gh_runtime.issue_comments(REPO, 1))

    def test_pages_are_flattened_oldest_first(self):
        capture = API['issue_comments']['paged']
        pages = json.loads(capture['stdout'])
        self.assertEqual(2, len(pages), 'the capture is a real two-page answer')
        with replay(capture):
            comments = gh_runtime.issue_comments(REPO, 389)
        self.assertEqual([c['body'] for page in pages for c in page], [c['body'] for c in comments])
        self.assertEqual(3, len(comments))
        self.assertTrue(all(c['login'] == pages[0][0]['user']['login'] for c in comments))
        dates = [c['created_at'] for page in pages for c in page]
        self.assertEqual(sorted(dates), dates)

    def test_the_marker_is_found_in_the_replayed_list_only_for_its_author(self):
        with replay(API['issue_comments']['paged']):
            comments = gh_runtime.issue_comments(REPO, 389)
        author = comments[0]['login']
        self.assertIsNone(needs_person.latest_marker(comments, author), 'real review comments carry no marker')
        marker = needs_person.comment_text({'head_sha': 'a' * 40, 'base_sha': 'b' * 40, 'live_base_sha': 'c' * 40,
                                            'reasons': ['waiting for a person']})
        marked = comments + [{'login': author, 'body': marker}]
        found = needs_person.latest_marker(marked, author)
        self.assertEqual(('a' * 40, 'c' * 40), (found['head'], found['live_base']))
        self.assertIsNone(needs_person.latest_marker(marked, 'someone-else'))
        # The newest marker wins, whatever sits after it.
        newer = marked + [{'login': author, 'body': 'no marker here'}]
        self.assertEqual(found, needs_person.latest_marker(newer, author))

    def test_a_failed_api_call_is_an_error(self):
        # A real 401 (any recorded failure of a gh api call) raises through run_gh's own rc check.
        capture = copy.deepcopy(API['user']['auth_failure'])
        with replay(capture), self.assertRaises(GitHubError):
            gh_runtime.issue_comments(REPO, 389)


class ViewerReplay(unittest.TestCase):
    def test_the_login_is_read_from_the_recorded_user(self):
        capture = API['user']['ok']
        with replay(capture):
            login = gh_runtime.viewer_login(REPO)
        self.assertEqual(json.loads(capture['stdout'])['login'], login)
        self.assertEqual({'login', 'id', 'type', 'site_admin'}, set(json.loads(capture['stdout'])))

    def test_an_authentication_failure_is_an_error_not_a_login(self):
        capture = API['user']['auth_failure']
        self.assertEqual(1, capture['rc'])
        self.assertIn('Bad credentials', capture['stderr'])
        with replay(capture), self.assertRaises(GitHubError):
            gh_runtime.viewer_login(REPO)

    def test_a_user_answer_without_a_login_is_an_error(self):
        capture = dict(API['user']['ok'], stdout='{"id":1,"type":"User"}\n')
        with replay(capture), self.assertRaises(GitHubError):
            gh_runtime.viewer_login(REPO)


if __name__ == '__main__':
    unittest.main()
