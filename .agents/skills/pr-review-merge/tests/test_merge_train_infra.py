"""Infrastructure is never the PR's verdict (kjelly/pilot#310).

Four things the merge train and its actor got wrong before they could run unattended, each proved with
what an operator can observe from outside (the result, the exit code, the label, the saved entry, the
comments, the processes that are left):

1. The actor reported ERROR for a PR it had enqueued, because it read the label from a listing that lags
   the write. It reads the PR itself now, again a bounded number of times.
2. The `merge-queue` label stayed on a merged PR. It comes off once MERGED is read back, and its failure
   changes nothing.
3. `git fetch` and `git push` had no time limit; a stalled push held the mutation lock for ever. Every git
   command ends at its limit, with its whole process group (a fake `git` that sleeps in a child process).
4. Three consecutive infrastructure failures dequeued a PR and dropped its saved review. Only an ERROR the
   PR itself caused counts (`Train._pr_error`); everything else stops the run (status INFRA, exit 2) and
   changes nothing.

The fake GitHub is the real-Git one of test_merge_train.py; `outage()` makes any of its methods fail and
`lag` makes its reads trail its writes.
"""
import ast
import contextlib
import errno
import functools
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import apply_decision  # noqa: E402
import gh_runtime  # noqa: E402
import merge_train  # noqa: E402
import review_gate  # noqa: E402
from gh_runtime import GitHubError, MutationLockHeld, MutationLockUnavailable  # noqa: E402
from scan_stub import CleanScan  # noqa: E402
from test_merge_train import PASS, PENDING, REPO, DeliveryTests, git  # noqa: E402

setUpModule, tearDownModule = CleanScan.up, CleanScan.down

NO_LIMIT = 50   # more sleeps than this in one wait means the wait has no bound


class NoLock:
    """A mutation lock that is always free."""

    def __call__(self, repo):
        return contextlib.nullcontext()


def outcomes(out):
    return [(r['pr'], r['outcome']) for r in out['results']]


# -- 1. the actor ------------------------------------------------------------------------------------------

class ActorHarness(DeliveryTests):
    """The real actor (`apply_decision.perform`, the real gate and the real mutation lock) against the
    real-Git fake GitHub. Its sleeps are recorded, never taken."""

    def setUp(self):
        super().setUp()
        self.sleeps = []
        self.runs = []
        patches = [
            mock.patch.object(apply_decision, 'evaluate', functools.partial(review_gate.evaluate, client=self.gh)),
            mock.patch.object(apply_decision, 'pr_view', self.gh.pr_view),
            mock.patch.object(apply_decision, 'branch_head', self.gh.branch_head),
            mock.patch.object(apply_decision, 'run_gh', self.run_gh),
            mock.patch.object(gh_runtime, 'edit_label', self.gh.edit_label),
            mock.patch.object(gh_runtime, 'post_comment', self.gh.post_comment),
            # Nothing here may reach the real `gh`: the actor must not read the listing, and if it did,
            # it would read this one.
            mock.patch.object(gh_runtime, 'labeled_open_prs', self.gh.labeled_open_prs),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def run_gh(self, args, *, input_text=None, check=True):
        """The two `gh` writes the actor's Draft path makes directly."""
        self.runs.append(list(args))
        number = int(args[2])
        if args[:2] == ['pr', 'comment']:
            self.gh.post_comment(REPO, number, Path(args[args.index('--body-file') + 1]).read_text())
        elif args[:2] == ['pr', 'ready'] and '--undo' in args:
            self.gh.mark_draft(REPO, number)
        else:
            raise AssertionError(f'unexpected gh call {args}')
        return subprocess.CompletedProcess(['gh', *args], 0, '', '')

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        if len(self.sleeps) > NO_LIMIT:
            raise AssertionError('the wait has no bound')

    def act(self, evidence=None):
        return apply_decision.perform(REPO, 42, evidence or self.evidence(), 'merge', True,
                                      worktree=self.consumer, sleep=self.sleep)

    def blocked_evidence(self):
        return dict(self.evidence(), verdict='BLOCK', findings=[{
            'severity': 'P1', 'path': 'pkg/a.go', 'line': 1, 'reason': 'incorrect value on empty input',
            'recommendation': 'guard empty input', 'blocking': True}])

    def assertEnqueued(self):
        self.assertIn(42, self.gh.labels)
        self.assertIsNotNone(merge_train.load_entry(REPO, 42))


class ActorReadAfterWriteTests(ActorHarness):
    """The actor says ENQUEUED when the PR carries the label, however late GitHub shows it."""

    def test_a_label_the_pr_shows_late_is_still_enqueued(self):
        self.gh.lag['label_view'] = 3
        out = self.act()
        self.assertEqual(('ENQUEUED', 'ENQUEUED'), (out['outcome'], out['verified_remote_state']), out)
        self.assertEqual([apply_decision.READ_INTERVAL] * 3, self.sleeps)
        self.assertEnqueued()

    def test_a_listing_that_lags_for_ever_is_not_consulted(self):
        # The issues listing lagged the label write on #271 and the actor reported ERROR. The PR shows its
        # label at once; the listing has nothing to say.
        self.gh.lag['listing'] = 10 ** 6
        out = self.act()
        self.assertEqual('ENQUEUED', out['outcome'], out)
        self.assertEqual([], self.sleeps)
        self.assertEqual(0, self.gh.counts.get('labeled_open_prs', 0), 'the actor must not read the listing')
        self.assertEnqueued()

    def test_a_label_that_never_shows_is_an_error_exactly_at_the_bound(self):
        self.gh.lag['label_view'] = 10 ** 6
        out = self.act()
        self.assertEqual(('ERROR', None), (out['outcome'], out['verified_remote_state']), out)
        self.assertIn(f'after {apply_decision.READ_TRIES} reads', out['error'])
        self.assertEqual([apply_decision.READ_INTERVAL] * (apply_decision.READ_TRIES - 1), self.sleeps)
        self.assertEnqueued()   # the write did happen: the evidence and the label are there

    def test_the_wait_is_short_enough_to_run_under_the_mutation_lock(self):
        # The actor waits while it holds the repository mutation lock: the train sees it held and waits too.
        self.assertLessEqual((apply_decision.READ_TRIES - 1) * apply_decision.READ_INTERVAL, 30)
        self.assertGreater(apply_decision.READ_TRIES, 1)

    def test_a_comment_that_fails_after_the_label_is_a_warning_not_an_error(self):
        self.gh.failing['post_comment'] = GitHubError('gh pr comment failed (1): HTTP 502')
        out = self.act()
        self.assertEqual('ENQUEUED', out['outcome'], out)
        self.assertIn('could not be posted', out['warnings'][0])
        self.assertIn('HTTP 502', out['warnings'][0])
        self.assertEnqueued()

    def test_a_label_write_that_fails_is_still_an_error(self):
        self.gh.failing['edit_label'] = GitHubError('gh pr edit failed (1): HTTP 403')
        out = self.act()
        self.assertEqual('ERROR', out['outcome'], out)
        self.assertIn('HTTP 403', out['error'])
        self.assertNotIn(42, self.gh.labels)
        self.assertEqual([], self.sleeps, 'nothing was written, so there is nothing to wait for')

    def test_a_read_that_fails_is_read_again_and_a_read_that_always_fails_is_reported(self):
        real, calls = self.gh.pr_view, []

        def flaky(repo, number):
            calls.append(number)
            if 42 in self.gh.labels and len(calls) % 2 == 0:
                raise GitHubError('gh pr view failed (1): HTTP 502')
            return real(repo, number)
        with mock.patch.object(apply_decision, 'pr_view', flaky):
            out = self.act()
        self.assertEqual('ENQUEUED', out['outcome'], out)
        self.setUp()
        self.gh.lag['label_view'] = 10 ** 6
        real = self.gh.pr_view
        always = {'on': False}

        def down(repo, number):
            if always['on']:
                raise GitHubError('gh pr view failed (1): HTTP 503')
            return real(repo, number)
        real_edit = self.gh.edit_label
        self.gh.edit_label = lambda *a, **kw: (real_edit(*a, **kw), always.update(on=True))[0]
        with mock.patch.object(apply_decision, 'pr_view', down), \
                mock.patch.object(gh_runtime, 'edit_label', self.gh.edit_label):
            out = self.act()
        self.assertEqual('ERROR', out['outcome'], out)
        self.assertIn('the last read failed: gh pr view failed (1): HTTP 503', out['error'])
        self.assertEqual(apply_decision.READ_TRIES - 1, len(self.sleeps))

    def test_the_train_sees_the_lock_held_while_the_actor_waits_and_merges_after(self):
        # The actor holds the mutation lock while it waits for GitHub; the train, which runs from a timer,
        # waits (WAITING, nothing counted) and merges as soon as the actor is done.
        self.gh.lag['label_view'] = 1
        seen = []

        def sleep(seconds):
            self.sleeps.append(seconds)
            with self.assertRaises(MutationLockHeld):
                with apply_decision.repo_mutation_lock(REPO):
                    pass
            seen.append(self.train(mutation_lock=None).run())
        self.sleep = sleep
        out = self.act()
        self.assertEqual('ENQUEUED', out['outcome'], out)
        self.assertEqual(1, len(seen), 'the train ran once, while the actor waited')
        for during in seen:
            self.assertEqual([(42, 'WAITING')], outcomes(during), during)
            self.assertIn('mutation lock', during['results'][0]['reason'])
        self.assertEqual(0, merge_train.load_entry(REPO, 42)['errors'])
        self.assertEqual([(42, 'MERGED')], outcomes(self.train(mutation_lock=None).run()))

    def test_a_draft_the_pr_shows_late_is_confirmed_and_one_it_never_shows_is_an_error(self):
        self.gh.lag['draft'] = 3
        out = self.act(self.blocked_evidence())
        self.assertEqual(('DRAFT-BLOCKED', 'OPEN'), (out['outcome'], out['verified_remote_state']), out)
        self.assertEqual([apply_decision.READ_INTERVAL] * 3, self.sleeps)
        self.assertTrue(self.gh.prs[42]['isDraft'])
        self.setUp()
        self.gh.lag['draft'] = 10 ** 6
        out = self.act(self.blocked_evidence())
        self.assertEqual('ERROR', out['outcome'], out)
        self.assertIn('Draft state was not confirmed', out['error'])
        self.assertEqual([apply_decision.READ_INTERVAL] * (apply_decision.READ_TRIES - 1), self.sleeps)

    def test_the_actor_reports_a_lock_it_cannot_take_by_type(self):
        with apply_decision.repo_mutation_lock(REPO):
            with self.assertRaises(MutationLockHeld) as held:
                with apply_decision.repo_mutation_lock(REPO):
                    pass
        self.assertIn('Another pr-review-merge actor', str(held.exception))
        lock = Path(os.environ['PRM_STATE_DIR']) / 'locks' / (merge_train._key(REPO) + '.lock')
        lock.unlink()
        lock.mkdir()
        with self.assertRaises(MutationLockUnavailable) as unusable:
            with apply_decision.repo_mutation_lock(REPO):
                pass
        self.assertIn('Cannot acquire GitHub mutation lock', str(unusable.exception))

    def test_a_failure_inside_the_lock_is_not_a_lock_failure(self):
        # An OSError raised by what runs under the lock (a full disk while a file is saved) used to be
        # reported as "Cannot acquire GitHub mutation lock": the same error type, a different cause.
        with self.assertRaises(OSError) as raised:
            with apply_decision.repo_mutation_lock(REPO):
                raise OSError(errno.ENOSPC, 'No space left on device')
        self.assertNotIsInstance(raised.exception, (MutationLockHeld, MutationLockUnavailable))
        self.assertEqual(errno.ENOSPC, raised.exception.errno)
        with apply_decision.repo_mutation_lock(REPO):   # and the lock was released
            pass


# -- 2. the label after the merge ------------------------------------------------------------------------------

class LabelCleanupTests(DeliveryTests):
    """The label comes off a merged PR, after MERGED is read back and under the guard, and never changes
    what the merge was."""

    def test_the_label_is_removed_after_the_merge_is_verified(self):
        self.queue()
        head = self.gh.head(42)
        out = self.train().run()
        self.assertEqual([(42, 'MERGED')], outcomes(out), out)
        self.assertNotIn(42, self.gh.labels)
        self.assertEqual([('merge', 42, head), ('label-', 42)], self.gh.writes[2:])
        self.assertEqual(1, len(self.gh.comments), 'no comment: a merge needs none')
        self.assertIsNone(merge_train.load_entry(REPO, 42))
        self.assertNotIn('warnings', out['results'][0])

    def test_nothing_is_removed_while_the_merge_is_not_shown(self):
        self.queue()
        self.gh.merge_confirms = False
        out = self.train().run()
        self.assertEqual([(42, 'ERROR')], outcomes(out), out)
        self.assertIn(42, self.gh.labels)
        self.assertNotIn(('label-', 42), self.gh.writes)
        self.assertIsNotNone(merge_train.load_entry(REPO, 42))

    def test_a_merge_the_pr_shows_late_is_still_a_merge(self):
        self.queue()
        self.gh.lag['merged'] = 2
        train = self.train()
        out = train.run()
        self.assertEqual([(42, 'MERGED')], outcomes(out), out)
        self.assertNotIn(42, self.gh.labels)
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_a_merge_the_pr_never_shows_is_the_prs_error_after_the_bound(self):
        self.queue()
        self.gh.lag['merged'] = 10 ** 6
        sleeps = []
        train = self.train()
        train.sleep = sleeps.append
        out = train.run()
        self.assertEqual([(42, 'ERROR')], outcomes(out), out)
        self.assertEqual('merge-unconfirmed', out['results'][0]['kind'])
        self.assertEqual([merge_train.CONFIRM_INTERVAL] * (merge_train.CONFIRM_TRIES - 1), sleeps)
        self.assertIn(42, self.gh.labels)
        self.assertNotIn(('label-', 42), self.gh.writes)

    def test_reads_that_fail_after_the_merge_are_a_stop_not_an_unconfirmed_merge(self):
        # Not being able to look says nothing about the PR: it must not count as "the merge did not show".
        # Only the reads that confirm the merge fail: the ones after them (the error count's) would work,
        # so an ERROR made of the failed reads would be counted, and the run would not stop.
        self.queue()
        real_merge, real_view, outage = self.gh.merge_pr, self.gh.pr_view, {'reads': 0}

        def merge_then_outage(repo, number, head):
            real_merge(repo, number, head)
            outage['reads'] = merge_train.CONFIRM_TRIES

        def view(repo, number):
            if outage['reads'] > 0:
                outage['reads'] -= 1
                raise GitHubError('gh pr view failed (1): HTTP 502')
            return real_view(repo, number)
        self.gh.merge_pr, self.gh.pr_view = merge_then_outage, view
        out = self.train().run()
        self.assertEqual(('INFRA', 'GitHubError', 42), (out['status'], out['error_kind'], out['pr']), out)
        self.assertIn('HTTP 502', out['error'])
        self.assertEqual('MERGED', self.gh.prs[42]['state'])
        self.assertEqual(0, merge_train.load_entry(REPO, 42)['errors'], 'a failure to look is not the PR\'s error')
        self.assertNotIn(('label-', 42), self.gh.writes, 'nothing is cleaned up for a merge that was never read back')

    def test_a_label_that_cannot_be_removed_does_not_change_the_merge(self):
        self.queue()
        self.second_pr(43)
        self.gh.labels.update({42: '2026-11-06T00:00:00Z', 43: '2026-11-06T01:00:00Z'})
        self.gh.counts.clear()
        self.gh.failing['edit_label'] = GitHubError('gh pr edit failed (1): HTTP 502')
        train = self.train()
        out = train.run()
        self.assertEqual('DONE', out['status'], out)
        self.assertEqual([(42, 'MERGED'), (43, 'MERGED')], outcomes(out), 'the run goes on with the next PR')
        self.assertIn('label could not be removed', out['results'][0]['warnings'][0])
        self.assertTrue([line for line in train.log if 'merged, but' in line and 'HTTP 502' in line], train.log)
        self.assertEqual(('MERGED', 'MERGED'), (self.gh.prs[42]['state'], self.gh.prs[43]['state']))
        self.assertIsNone(merge_train.load_entry(REPO, 42), 'the entry is dropped before the label is touched')
        self.assertEqual(0, self.exit_code(out))

    def test_an_entry_that_cannot_be_removed_does_not_change_the_merge_either(self):
        self.queue()
        with mock.patch.object(merge_train, 'drop_entry', side_effect=OSError(errno.EIO, 'Input/output error')):
            out = self.train().run()
        self.assertEqual([(42, 'MERGED')], outcomes(out), out)
        self.assertIn('saved entry could not be removed', out['results'][0]['warnings'][0])
        self.assertNotIn(42, self.gh.labels, 'the label is still removed')

    @staticmethod
    def exit_code(out):
        if out['status'] == 'INFRA':
            return 2
        return 0 if all(r['outcome'] != 'ERROR' for r in out['results']) else 1

    def test_a_pr_merged_or_closed_by_hand_keeps_its_label_and_nothing_is_written(self):
        # Housekeeping belongs to a merge the train made. Someone else's merge is none of its business.
        for state in ('MERGED', 'CLOSED'):
            with self.subTest(state=state):
                self.setUp()
                self.queue()
                self.gh.prs[42]['state'] = state
                out = self.train().run()
                self.assertEqual([], out['results'], 'a closed PR is not listed at all')
                self.assertEqual([('label+', 42), ('comment', 42)], self.gh.writes)


# -- 3. git commands that do not finish ---------------------------------------------------------------------------

# A stand-in for `git` that runs first on PATH. `<command>` in $FAKE_GIT_DIR names what it does for that git
# subcommand: nothing listed, or "pass": the real git; "hang": sleep in a child process (a grandchild of the
# train, as ssh or a remote helper would be) and leave a marker when it gets SIGTERM; "stubborn": ignore
# SIGTERM (marker only) so that only SIGKILL ends it; "run-then-hang": run the real git, then hang.
FAKE_GIT = r'''#!/bin/sh
dir="$FAKE_GIT_DIR"
command="$3"
echo "$2 $command prompt=$GIT_TERMINAL_PROMPT" >> "$dir/calls"
mode=$(cat "$dir/$command" 2>/dev/null)
record() {
    echo "$$" > "$dir/$command.leader"
    ps -o pgid= -p $$ | tr -d ' ' > "$dir/$command.pgid"
    ps -o sid= -p $$ | tr -d ' ' > "$dir/$command.sid"
}
hang() {
    record
    trap 'echo term > "$dir/$command.term"; exit 143' TERM
    sleep 600 &
    echo $! > "$dir/$command.child"
    wait
}
stubborn() {
    record
    trap 'echo term > "$dir/$command.term"' TERM
    while :; do sleep 1; done
}
case "$mode" in
    hang) hang ;;
    stubborn) stubborn ;;
    run-then-hang) "$REAL_GIT" "$@"; hang ;;
    *) exec "$REAL_GIT" "$@" ;;
esac
'''


def alive(pid):
    """Is the process running (a zombie nobody has reaped yet is not)?"""
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] != 'Z'
    except (FileNotFoundError, ProcessLookupError):
        return False


class GitHarness(DeliveryTests):
    """A fake `git` in front of the real one, and a way to run the train without hanging the test run when
    the code under test has no time limit."""

    def setUp(self):
        super().setUp()
        self.bin = self.t / 'fakebin'
        self.gitdir = self.t / 'fakegit'
        self.bin.mkdir()
        self.gitdir.mkdir()
        script = self.bin / 'git'
        script.write_text(FAKE_GIT)
        script.chmod(0o755)
        patcher = mock.patch.dict(os.environ, {'PATH': f"{self.bin}:{os.environ['PATH']}",
                                               'FAKE_GIT_DIR': str(self.gitdir),
                                               'REAL_GIT': shutil.which('git')})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.kill_leftovers)

    def mode(self, **modes):
        for command, mode in modes.items():
            (self.gitdir / command.replace('_', '-')).write_text(mode)

    def pid(self, name):
        return int((self.gitdir / name).read_text().strip())

    def kill_leftovers(self):
        for path in list(self.gitdir.glob('*.leader')) + list(self.gitdir.glob('*.child')):
            with contextlib.suppress(OSError, ValueError):
                pid = int(path.read_text().strip())
                if path.suffix == '.leader':
                    os.killpg(pid, signal.SIGKILL)
                os.kill(pid, signal.SIGKILL)

    def train(self, **kw):
        kw.setdefault('fetch_timeout', 2)
        kw.setdefault('push_timeout', 2)
        kw.setdefault('git_kill_grace', 1)
        return super().train(**kw)

    def bounded(self, fn, limit=30):
        """Run `fn` and return (its result, seconds it took); fail, instead of hanging, when it takes longer."""
        box = {}

        def target():
            try:
                box['value'] = fn()
            except BaseException as exc:  # reported below, in the test's thread
                box['error'] = exc
        started = time.monotonic()
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(limit)
        if thread.is_alive():
            self.kill_leftovers()
            thread.join(10)
            self.fail(f'still running after {limit} s: the git command has no time limit')
        if 'error' in box:
            raise box['error']
        return box['value'], time.monotonic() - started

    def assertGone(self, name):
        """The process whose pid `name` holds is dead (a moment is allowed for init to reap it)."""
        pid = self.pid(name)
        for _ in range(30):
            if not alive(pid):
                return
            time.sleep(0.1)
        self.fail(f'{name} (pid {pid}) is still running')

    def assertLocksFree(self):
        with apply_decision.repo_mutation_lock(REPO):
            pass
        with merge_train.consumer_lock(REPO) as acquired:
            self.assertTrue(acquired)

    def assertStillEnqueued(self, *, writes=2):
        entry = merge_train.load_entry(REPO, 42)
        self.assertIsNotNone(entry, 'the saved review is kept')
        self.assertEqual(0, entry['errors'])
        self.assertIn(42, self.gh.labels)
        self.assertEqual(writes, len(self.gh.writes), self.gh.writes)
        self.assertEqual(1, len(self.gh.comments), 'nothing was said to the PR')
        self.assertFalse(self.gh.prs[42]['isDraft'])
        return entry


class GitTimeoutTests(GitHarness):
    """Every git command ends at its limit, takes its whole process group with it, and leaves nothing
    held: the PR stays enqueued with its saved review."""

    def test_a_hung_fetch_ends_at_the_timeout_and_the_pr_stays_enqueued(self):
        self.queue()
        self.mode(fetch='hang')
        out, took = self.bounded(self.train().run)
        self.assertLess(took, 10)
        self.assertGreaterEqual(took, 2)
        self.assertEqual(('INFRA', 'GitTimeout', 42, []), (out['status'], out['error_kind'], out['pr'], out['results']), out)
        self.assertIn('git fetch did not finish within 2 s', out['error'])
        self.assertStillEnqueued()
        self.assertTrue((self.gitdir / 'fetch.term').exists(), 'SIGTERM comes first: git cleans up after itself on it')
        self.assertGone('fetch.leader')
        self.assertGone('fetch.child')   # the grandchild, which only a signal to the whole group reaches
        self.assertLocksFree()

    def test_a_hung_push_ends_at_the_timeout_and_frees_the_mutation_lock(self):
        self.queue()
        self.advance_main()
        self.mode(push='hang')
        out, took = self.bounded(self.train().run)
        self.assertLess(took, 12)
        self.assertEqual(('INFRA', 'GitTimeout', 42), (out['status'], out['error_kind'], out['pr']), out)
        self.assertIn('git push did not finish within 2 s', out['error'])
        entry = self.assertStillEnqueued()
        self.assertEqual(1, len(entry['train_commits']), 'the commit stays recorded: it may have landed')
        self.assertEqual(self.reviewed, self.gh.head(42), 'it did not land')
        self.assertTrue((self.gitdir / 'push.term').exists())
        self.assertGone('push.leader')
        self.assertGone('push.child')
        self.assertLocksFree()

    def test_a_push_that_lands_and_then_hangs_is_found_on_the_remote_and_goes_on(self):
        self.queue()
        live = self.advance_main()
        self.mode(push='run-then-hang')
        train = self.train()
        out, took = self.bounded(train.run)
        self.assertEqual([(42, 'MERGED')], outcomes(out), out)
        self.assertTrue([line for line in train.log if 'the push landed' in line], train.log)
        head = self.gh.head(42)
        self.assertEqual(f'{self.reviewed} {live}', git(self.origin, 'log', '-1', '--format=%P', head))
        self.assertEqual(('merge', 42, head), self.gh.writes[2])
        self.assertTrue((self.gitdir / 'push.term').exists(), 'the hung client was ended')
        self.assertGone('push.child')

    def test_a_push_that_landed_with_the_remote_unreadable_stays_enqueued_and_merges_next_run(self):
        self.queue()
        live = self.advance_main()
        self.mode(push='run-then-hang', ls_remote='hang')
        out, _ = self.bounded(self.train().run)
        self.assertEqual(('INFRA', 'GitTimeout', 42), (out['status'], out['error_kind'], out['pr']), out)
        self.assertIn('git push did not finish', out['error'], 'the push error is the one reported')
        entry = merge_train.load_entry(REPO, 42)
        self.assertEqual((0, 1), (entry['errors'], len(entry['train_commits'])))
        landed = self.gh.head(42)
        self.assertEqual([landed], entry['train_commits'], 'the commit that landed is the one that stayed recorded')
        self.assertIn(42, self.gh.labels)
        self.assertEqual(1, len(self.gh.comments))
        self.assertEqual([], [w for w in self.gh.writes if w[0] in ('merge', 'label-', 'draft')])
        # The next run (git healthy again) finds a HEAD the train built, and merges it.
        for name in ('push', 'ls-remote'):
            (self.gitdir / name).unlink()
        out, _ = self.bounded(self.train().run)
        self.assertEqual([(42, 'MERGED')], outcomes(out), out)
        self.assertEqual(landed, self.gh.head(42))
        self.assertEqual(f'{self.reviewed} {live}', git(self.origin, 'log', '-1', '--format=%P', landed))

    def test_a_git_that_ignores_sigterm_is_killed_after_the_grace(self):
        self.queue()
        self.mode(fetch='stubborn')
        out, took = self.bounded(self.train().run)
        self.assertEqual(('INFRA', 'GitTimeout'), (out['status'], out['error_kind']), out)
        self.assertIn('SIGTERM, then SIGKILL', out['error'])
        self.assertGreaterEqual(took, 3 - 0.2, 'the timeout, then the grace, before SIGKILL')
        self.assertLess(took, 12)
        self.assertTrue((self.gitdir / 'fetch.term').exists(), 'it was asked first')
        self.assertGone('fetch.leader')
        self.assertStillEnqueued()

    def test_a_git_that_ends_on_sigterm_is_not_killed(self):
        self.queue()
        self.mode(fetch='hang')
        out, took = self.bounded(self.train(git_kill_grace=20).run)
        self.assertLess(took, 8, 'it ended on SIGTERM; nothing waited for the grace')
        self.assertIn('(SIGTERM)', out['error'])

    def test_git_runs_in_a_session_of_its_own_and_never_prompts(self):
        self.queue()
        self.mode(fetch='hang')
        self.bounded(self.train().run)
        leader = self.pid('fetch.leader')
        self.assertEqual(leader, self.pid('fetch.pgid'), 'its own process group: the whole of it can be signalled')
        self.assertEqual(leader, self.pid('fetch.sid'), 'its own session: no terminal to prompt on')
        self.assertNotEqual(os.getpgid(0), leader)
        # What the train ran (in the consumer's clone), not what the fake GitHub runs against the origin.
        calls = [c for c in (self.gitdir / 'calls').read_text().split('\n') if c.startswith(str(self.consumer) + ' ')]
        self.assertIn(f'{self.consumer} fetch prompt=0', calls)
        self.assertEqual([], [c for c in calls if not c.endswith('prompt=0')], 'GIT_TERMINAL_PROMPT=0 for every command')

    def test_limits_come_from_the_train_and_the_cli(self):
        self.assertEqual((300.0, 120.0, 120.0, 30.0), (merge_train.FETCH_TIMEOUT, merge_train.PUSH_TIMEOUT,
                                                     merge_train.GIT_TIMEOUT, merge_train.GIT_KILL_GRACE))
        train = merge_train.Train(REPO, self.consumer, client=self.gh)
        self.assertEqual((300.0, 120.0, 120.0, 30.0), (train.fetch_timeout, train.push_timeout, train.git_timeout,
                                                       train.git_kill_grace))
        seen = {}
        real = merge_train.Train

        def factory(*args, **kw):
            seen.update(kw)
            return real(*args, client=self.gh, **kw)
        with mock.patch.object(merge_train, 'Train', factory), contextlib.redirect_stdout(io.StringIO()):
            merge_train.main(['process', '--repo', 'acme/demo', '--worktree', str(self.consumer), '--fetch-timeout', '7',
                              '--push-timeout', '8', '--git-timeout', '9'])
        self.assertEqual((7.0, 8.0, 9.0), (seen['fetch_timeout'], seen['push_timeout'], seen['git_timeout']))

    def test_the_cli_reports_a_hung_fetch_as_an_infrastructure_stop_and_frees_the_consumer_lock(self):
        self.queue()
        self.mode(fetch='hang')
        real = merge_train.Train
        stdout = io.StringIO()

        def run_main():
            with mock.patch.object(merge_train, 'Train', lambda *a, **kw: real(*a, client=self.gh, git_kill_grace=1, **kw)), \
                    contextlib.redirect_stdout(stdout):
                return merge_train.main(['process', '--repo', 'acme/demo', '--worktree', str(self.consumer),
                                         '--fetch-timeout', '2', '--push-timeout', '2'])
        code, took = self.bounded(run_main)
        self.assertEqual(2, code)
        self.assertLess(took, 10)
        report = json.loads(stdout.getvalue())
        self.assertEqual(('INFRA', 42, 'GitTimeout', []), (report['status'], report['pr'], report['error_kind'],
                                                           report['results']), report)
        self.assertTrue([line for line in report['log'] if 'infrastructure failure on #42' in line], report['log'])
        self.assertStillEnqueued()
        self.assertLocksFree()

    def test_every_git_command_has_a_limit_and_the_network_ones_have_their_own(self):
        seen = []
        train = self.train(fetch_timeout=11, push_timeout=22, git_timeout=33)
        real = train._run_git

        def spy(args, limit):
            seen.append((args[0], limit))
            return real(args, limit)
        train._run_git = spy
        self.queue()
        self.advance_main()
        train.run()
        limits = {}
        for command, limit in seen:
            limits.setdefault(command, set()).add(limit)
        self.assertEqual({11}, limits['fetch'])
        self.assertEqual({22}, limits['push'])
        for local in ('rev-parse', 'merge-tree', 'commit-tree', 'diff', 'ls-tree'):
            self.assertEqual({33}, limits[local], local)


# -- 4. what counts against a PR ----------------------------------------------------------------------------------

class Harness(DeliveryTests):
    """Helpers for the tests below."""

    def two(self):
        self.queue()
        self.second_pr(43)
        self.gh.labels.update({42: '2026-11-06T00:00:00Z', 43: '2026-11-06T01:00:00Z'})

    def ticks(self, count, **kw):
        """`count` runs of the train, as a timer would start them: a new train each time."""
        return [self.train(**kw).run() for _ in range(count)]

    def bodies(self, number=42):
        return [body for n, body in self.gh.comments if n == number]

    def assertInfra(self, out, *, kind=None, pr=42, within=None):
        self.assertEqual('INFRA', out['status'], out)
        self.assertEqual(pr, out['pr'], out)
        if kind is not None:
            self.assertEqual(kind, out['error_kind'], out)
        self.assertIn('not counted against the PR', out['message'])
        if within is not None:
            self.assertIn(within, out['error'])

    def assertUntouched(self, *numbers):
        """Every PR is still enqueued with its saved review, nothing was counted, nothing was said."""
        for number in numbers or (42,):
            entry = merge_train.load_entry(REPO, number)
            self.assertIsNotNone(entry, f'#{number}: the saved review was dropped')
            self.assertEqual(0, entry['errors'], f'#{number}: counted')
            self.assertNotIn('last_error', entry)
            self.assertIn(number, self.gh.labels, f'#{number}: the label was removed')
            self.assertEqual(1, len(self.bodies(number)), f'#{number}: something was said besides the enqueue comment')
            self.assertEqual('OPEN', self.gh.prs[number]['state'])
            self.assertFalse(self.gh.prs[number]['isDraft'])


class PrCausedErrorTests(Harness):
    """The only thing that counts against a PR is what the PR itself caused: three of those in a row still
    dequeue it, with a comment."""

    def test_an_unconfirmed_merge_three_runs_in_a_row_dequeues_with_a_comment(self):
        self.two()
        self.gh.merge_unconfirmed.add(42)
        for count in (1, 2):
            out = self.train().run()
            self.assertEqual([(42, 'ERROR')], outcomes(out), out)
            self.assertEqual('merge-unconfirmed', out['results'][0]['kind'])
            self.assertEqual(count, merge_train.load_entry(REPO, 42)['errors'])
            self.assertIn(42, self.gh.labels)
        third = self.train().run()
        self.assertEqual([(42, 'DEQUEUED'), (43, 'MERGED')], outcomes(third), third)
        self.assertIn('3 runs in a row', third['results'][0]['reason'])
        self.assertIn('not confirmed MERGED', self.bodies(42)[-1])
        self.assertEqual('Merge train: left the queue', self.bodies(42)[-1].splitlines()[0][3:])
        self.assertNotIn(42, self.gh.labels)
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_a_draft_that_is_never_shown_three_runs_in_a_row_dequeues_with_a_comment(self):
        self.queue()
        self.advance_main('pkg/a.go', 'package a // main change\n')   # an overlap: the train must Draft it
        self.gh.mark_draft = lambda repo, number: self.gh.writes.append(('draft', number))   # GitHub ignores it
        for count in (1, 2):
            out = self.train().run()
            self.assertEqual([(42, 'ERROR')], outcomes(out), out)
            self.assertEqual('draft-unconfirmed', out['results'][0]['kind'])
            self.assertEqual(count, merge_train.load_entry(REPO, 42)['errors'])
        out = self.train().run()
        self.assertEqual([(42, 'DEQUEUED')], outcomes(out), out)
        self.assertIn('Draft conversion was not confirmed', self.bodies(42)[-1])
        self.assertNotIn(42, self.gh.labels)

    def test_an_error_needs_a_registered_kind(self):
        train = self.train()
        self.assertEqual(('merge-unconfirmed', 'draft-unconfirmed'), merge_train.PR_ERROR_KINDS)
        with self.assertRaises(merge_train.TrainError):
            train._pr_error(42, 'anything-else', 'x')
        self.queue()
        with self.assertRaises(merge_train.TrainError):
            train._track_errors(42, {'pr': 42, 'outcome': 'ERROR', 'reason': 'made by hand'},
                                merge_train._Attempt(merge_train.load_entry(REPO, 42)['entry_id']))
        self.assertEqual(0, merge_train.load_entry(REPO, 42)['errors'])

    def test_infrastructure_failures_do_not_reset_what_the_pr_really_caused(self):
        # Two errors of its own, then outages: neither a third error nor a reset.
        self.queue()
        self.gh.merge_unconfirmed.add(42)
        self.ticks(2)
        self.gh.failing['pr_checks'] = GitHubError('HTTP 502')
        self.gh.merge_unconfirmed.clear()
        for out in self.ticks(3):
            self.assertInfra(out)
        entry = merge_train.load_entry(REPO, 42)
        self.assertEqual(2, entry['errors'], 'neither counted nor reset')
        self.assertIn(42, self.gh.labels)


class MergeRefusedTests(Harness):
    """`gh pr merge` failing is read from the PR, not from the message: what the PR shows decides."""

    def failing_merge(self, effect=None, error='gh pr merge 42 failed (1): HTTP 502'):
        real = self.gh.merge_pr

        def merge(repo, number, head):
            if effect is not None:
                effect(real, repo, number, head)
            else:
                self.gh.writes.append(('merge', number, head))
            raise GitHubError(error)
        self.gh.merge_pr = merge

    def test_a_merge_that_landed_while_the_client_reported_failure_is_a_merge(self):
        self.queue()
        head = self.gh.head(42)
        self.failing_merge(lambda real, repo, number, h: real(repo, number, h), 'gh unavailable or timed out')
        out = self.train().run()
        self.assertEqual([(42, 'MERGED')], outcomes(out), out)
        self.assertEqual(head, out['results'][0]['head_sha'])
        self.assertNotIn(42, self.gh.labels, 'housekeeping follows a merge that happened, however it was reported')
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_a_merge_refused_because_the_head_moved_looks_at_the_pr_again_and_dequeues_it(self):
        self.queue()
        moved = {}
        self.failing_merge(lambda real, repo, number, h: moved.update(head=self.push_to_pr()),
                           'gh pr merge 42 failed (1): Head branch was modified')
        out = self.train().run()
        self.assertEqual([(42, 'DEQUEUED')], outcomes(out), out)
        self.assertIn('HEAD changed since it was enqueued', out['results'][0]['reason'])
        self.assertEqual(moved['head'], self.gh.head(42))
        self.assertEqual('OPEN', self.gh.prs[42]['state'])
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_a_merge_refused_because_the_merge_state_is_no_longer_clean_is_judged_by_the_gate(self):
        self.queue()
        self.failing_merge(lambda real, repo, number, h: self.gh.prs[42].update(merge_state='BLOCKED'),
                           'gh pr merge 42 failed (1): Pull request is not mergeable')
        out = self.train().run()
        self.assertEqual([(42, 'DEQUEUED')], outcomes(out), out)
        self.assertIn("Merge state is not CLEAN: 'BLOCKED'", out['results'][0]['reason'])
        self.assertIn("Merge state is not CLEAN: 'BLOCKED'", self.bodies(42)[-1])
        self.assertNotIn(42, self.gh.labels)
        self.assertFalse(self.gh.prs[42]['isDraft'], 'it stays Ready')

    def test_a_merge_refused_for_a_reason_the_pr_does_not_show_is_infrastructure_whatever_it_says(self):
        self.queue()
        self.failing_merge(None, 'gh pr merge 42 failed (1): Merge commits are not allowed on this repository')
        for _ in range(3):
            out = self.train().run()
            self.assertInfra(out, kind='GitHubError', within='Merge commits are not allowed')
            self.assertEqual([], out['results'])
        self.assertUntouched()
        self.assertEqual(3, len([w for w in self.gh.writes if w[0] == 'merge']), 'the merge was tried each run')

    def test_a_pr_merged_by_someone_else_while_the_merge_failed_is_skipped_not_claimed(self):
        self.queue()
        self.failing_merge(lambda real, repo, number, h: (self.push_to_pr(), self.gh.prs[42].update(state='MERGED')),
                           'gh pr merge 42 failed (1): Pull request is already merged')
        out = self.train().run()
        self.assertEqual([(42, 'SKIP')], outcomes(out), out)
        self.assertNotIn(('label-', 42), self.gh.writes, 'a merge the train did not make is none of its business')


class NamedRegressionTests(Harness):
    """The ways infrastructure used to be counted as the PR's fault, each as it was found."""

    def test_r1_a_missing_commit_identity_drains_nothing(self):
        self.two()
        self.advance_main()                       # both PRs are behind: integrating needs a commit
        git(self.consumer, 'config', 'user.useConfigOnly', 'true')
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update(HOME=str(self.t / 'nohome'), GIT_CONFIG_NOSYSTEM='1')
        with mock.patch.dict(os.environ, env, clear=True):
            runs = self.ticks(6)
        for out in runs:
            self.assertInfra(out, kind='TrainError', within='commit-tree')
        self.assertUntouched(42, 43)
        self.assertEqual([], [w for w in self.gh.writes[4:]], 'nothing was written after the two enqueues')

    def test_r2_an_origin_that_cannot_be_reached_drains_nothing(self):
        self.two()
        git(self.consumer, 'remote', 'set-url', 'origin', str(self.t / 'gone.git'))
        for out in self.ticks(6):
            self.assertInfra(out, kind='TrainError', within='does not appear to be a git repository')
        self.assertUntouched(42, 43)

    def test_r3_a_5xx_while_ci_is_pending_never_adds_up(self):
        self.two()
        self.gh.checks[42] = [[PENDING]]
        self.gh.failing['pr_checks'] = GitHubError('gh pr checks failed (1): HTTP 502')
        for out in self.ticks(4):
            self.assertInfra(out, kind='GitHubError', within='HTTP 502')
        self.assertUntouched(42, 43)

    def test_r4_an_entry_that_cannot_be_read_is_not_no_evidence(self):
        for number in (errno.EACCES, errno.EIO, errno.ENOTDIR):
            with self.subTest(errno=errno.errorcode[number]):
                self.setUp()
                self.queue()
                path = merge_train.entry_path(REPO, 42)
                real = Path.read_text

                def read_text(self_, *args, **kwargs):
                    if self_ == path:
                        raise OSError(number, os.strerror(number), str(self_))
                    return real(self_, *args, **kwargs)
                with mock.patch.object(Path, 'read_text', read_text):
                    out = self.train().run()
                self.assertInfra(out, within=os.strerror(number))
                self.assertTrue(path.exists(), 'the saved review is still there')
                self.assertUntouched()

    @unittest.skipIf(os.geteuid() == 0, 'root reads a file whatever its mode')
    def test_r4_a_file_that_is_really_unreadable(self):
        self.queue()
        path = merge_train.entry_path(REPO, 42)
        path.chmod(0)
        self.addCleanup(lambda: path.chmod(0o600))
        out = self.train().run()
        self.assertInfra(out, kind='PermissionError')
        path.chmod(0o600)
        self.assertUntouched()

    def test_a_missing_or_foreign_entry_is_still_no_evidence(self):
        # What does not make it infrastructure: no file, text that is not JSON, a record of another schema.
        self.queue()
        path = merge_train.entry_path(REPO, 42)
        for text in (None, '{not json', json.dumps({'schema': 'something-else'})):
            with self.subTest(text=text):
                if text is None:
                    path.unlink()
                else:
                    path.write_text(text)
                self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_r5_a_full_disk_inside_the_lock_is_not_a_lock_failure(self):
        self.queue()
        self.advance_main()
        real = merge_train.save_entry

        def enospc(repo, number, record):
            if record.get('train_commits'):
                raise OSError(errno.ENOSPC, 'No space left on device')
            return real(repo, number, record)
        with mock.patch.object(merge_train, 'save_entry', enospc):
            out = self.train(mutation_lock=None).run()        # the real lock, as in production
        self.assertInfra(out, kind='OSError', within='No space left on device')
        self.assertNotIn('Cannot acquire', out['error'])
        self.assertUntouched()
        with apply_decision.repo_mutation_lock(REPO):
            pass

    def test_r9_a_base_that_moves_while_the_alignment_is_confirmed_is_not_the_prs_error(self):
        self.queue()
        self.advance_main()
        real, calls = self.gh.branch_head, []

        def moving(repo, name):
            calls.append(name)
            if len(calls) == 2:
                self.advance_main('docs/m.md')
            return real(repo, name)
        self.gh.branch_head = moving
        out = self.train().run()
        self.assertInfra(out, kind='GitHubError', within='changed while confirming base alignment')
        self.assertUntouched()
        self.gh.branch_head = real
        self.assertEqual([(42, 'MERGED')], outcomes(self.train().run()), 'the next run takes it')


class CliHarness(Harness):
    def cli(self, *extra, command='process'):
        """`merge_train.main` against the fake GitHub: (exit code, the JSON it printed)."""
        real, clock, out = merge_train.Train, {'t': 0.0}, io.StringIO()

        def sleep(seconds):
            clock['t'] += max(seconds, 1)

        def factory(*args, **kw):
            return real(*args, client=self.gh, sleep=sleep, monotonic=lambda: clock['t'], registration_grace=0, **kw)
        argv = [command, '--repo', 'acme/demo', *(['--worktree', str(self.consumer)] if command == 'process' else []),
                *extra]
        with mock.patch.object(merge_train, 'Train', factory), contextlib.redirect_stdout(out):
            code = merge_train.main(argv)
        return code, json.loads(out.getvalue())


class LockAndExitCodeTests(CliHarness):
    """A lock another actor holds is a wait (exit 0); one that cannot be used, or anything nobody foresaw,
    is infrastructure (exit 2); exit 1 means a PR ended in ERROR, and nothing else."""

    def test_a_lock_another_actor_holds_is_a_wait_and_exit_0(self):
        self.queue()
        with apply_decision.repo_mutation_lock(REPO):
            code, report = self.cli()
        self.assertEqual(0, code)
        self.assertEqual([(42, 'WAITING')], outcomes(report), report)
        self.assertIn('mutation lock', report['results'][0]['reason'])
        self.assertUntouched()

    def test_a_lock_that_cannot_be_used_is_infrastructure_and_exit_2(self):
        self.queue()
        lock = Path(os.environ['PRM_STATE_DIR']) / 'locks' / (merge_train._key(REPO) + '.lock')
        lock.mkdir(parents=True)                       # opening it for locking fails, for good
        code, report = self.cli()
        self.assertEqual(2, code)
        self.assertEqual(('INFRA', 42, 'MutationLockUnavailable'), (report['status'], report['pr'], report['error_kind']), report)
        self.assertIn('Cannot acquire GitHub mutation lock', report['error'])
        self.assertUntouched()

    def test_a_lock_directory_that_cannot_be_created_is_infrastructure_and_exit_2(self):
        self.queue()
        locks = Path(os.environ['PRM_STATE_DIR']) / 'locks'
        locks.mkdir(parents=True)
        shutil.rmtree(locks)
        locks.write_text('not a directory')
        code, report = self.cli()
        self.assertEqual(2, code)
        self.assertEqual('INFRA', report['status'], report)
        self.assertIn(report['error_kind'], ('FileExistsError', 'NotADirectoryError'))
        locks.unlink()
        self.assertUntouched()

    def test_a_second_consumer_is_busy_and_exit_0(self):
        with merge_train.consumer_lock(REPO):
            code, report = self.cli()
        self.assertEqual((0, 'BUSY'), (code, report['status']))

    def test_an_unexpected_exception_is_infrastructure_not_a_traceback_and_not_exit_1(self):
        # KeyError and TypeError from a response that changed shape used to be counted against the PR
        # (KeyError) or escape the CLI as a traceback with exit code 1, the code of "a PR ended in ERROR".
        self.queue()
        for exc in (KeyError('headRefOid'), TypeError("'NoneType' object is not subscriptable"), IndexError('x')):
            with self.subTest(exc=type(exc).__name__):
                self.gh.failing['pr_view'] = exc
                self.gh.counts.clear()
                code, report = self.cli()
                self.assertEqual(2, code)
                self.assertEqual(('INFRA', 42, type(exc).__name__), (report['status'], report['pr'], report['error_kind']), report)
                self.assertTrue(report['log'], 'the log is printed too')
                self.assertUntouched()

    def test_an_exception_outside_the_run_is_still_infrastructure(self):
        self.gh.failing['labeled_open_prs'] = KeyError('number')
        for command in ('process', 'status'):
            with self.subTest(command=command):
                self.gh.counts.clear()
                code, report = self.cli(command=command)
                self.assertEqual(2, code)
                self.assertEqual(('INFRA', 'KeyError'), (report['status'], report['error_kind']), report)
        self.gh.failing.clear()
        self.queue()
        os.chmod(merge_train.entry_path(REPO, 42), 0o600)
        with mock.patch.object(merge_train, 'load_entry', side_effect=OSError(errno.EIO, 'Input/output error')):
            code, report = self.cli(command='status')
        self.assertEqual((2, 'INFRA', 'OSError'), (code, report['status'], report['error_kind']), report)

    def test_exit_codes(self):
        self.queue()
        self.gh.merge_unconfirmed.add(42)
        code, report = self.cli()
        self.assertEqual((1, [(42, 'ERROR')]), (code, outcomes(report)))
        self.gh.merge_unconfirmed.clear()
        code, report = self.cli()
        self.assertEqual((0, [(42, 'MERGED')]), (code, outcomes(report)))
        code, report = self.cli()
        self.assertEqual((0, []), (code, report['results']))

    def test_a_stop_reports_what_the_run_had_done_before_it(self):
        self.two()
        self.gh.checks[43] = [[PENDING], [PASS]]
        self.gh.on_checks = lambda number, poll: self.gh.failing.update({'pr_checks': GitHubError('HTTP 502')}) \
            if number == 43 else None
        code, report = self.cli()
        self.assertEqual(2, code)
        self.assertEqual([(42, 'MERGED')], outcomes(report), 'partial results are printed')
        self.assertEqual(('INFRA', 43), (report['status'], report['pr']))
        self.assertUntouched(43)


class Plan:
    """Where one run of the train fails: `exc()` is raised from the `nth` call of `point` on (a point that
    goes down stays down for the rest of the run). Every call of a point that is not a method of the fake
    GitHub (`git:<command>`, `state:<function>`, `lock`) is counted here and entered in `calls`, the
    census of the run, in the order the fake GitHub's own calls are."""

    def __init__(self, calls, point=None, nth=1, exc=None):
        self.calls, self.point, self.nth, self.exc = calls, point, nth, exc
        self.counts = {}

    def hit(self, point):
        self.calls.append(point)
        self.counts[point] = self.counts.get(point, 0) + 1
        if point == self.point and self.counts[point] >= self.nth:
            raise self.exc()


class InjectionMatrixTests(Harness):
    """Every call the train makes, failing in every way an infrastructure failure can, on the way to the
    first thing it writes: the run stops, or waits (the gate's own handling of an outage); it never counts,
    dequeues, drafts, merges or says anything, however many runs in a row meet the same failure."""

    EXCEPTIONS = {
        'GitHubError': lambda: GitHubError('gh pr view failed (1): HTTP 502'),
        'TrainError': lambda: merge_train.TrainError('git fetch failed (128): fatal: unable to access'),
        'OSError': lambda: OSError(errno.ENOSPC, 'No space left on device'),
        'TimeoutExpired': lambda: subprocess.TimeoutExpired(['git', 'fetch'], 120),
        'TypeError': lambda: TypeError("'NoneType' object is not subscriptable"),
    }
    RUNS = 3
    # What the run has done once one of these has been called is no longer "nothing" (a comment, the label,
    # Draft, the merge, the push): the matrix goes up to and including the first of them. What follows
    # one that landed (the push, the merge) is in the tests above and below.
    EXTERNAL_WRITES = {'merge_pr', 'mark_draft', 'post_comment', 'edit_label', 'git:push'}
    CLIENT = ('pr_view', 'branch_head', 'pr_checks', 'labeled_open_prs', 'label_added_at', 'merge_base',
              'commit_tree', 'branch_rules', 'is_ancestor', 'compare', 'tree_entries', 'file_at',
              'unresolved_threads', 'edit_label', 'post_comment', 'mark_draft', 'merge_pr')

    def aligned(self):
        self.queue()

    def behind(self):
        self.queue()
        self.advance_main()

    def overlap(self):
        self.queue()
        self.advance_main('pkg/a.go', 'package a // main change\n')

    def stale(self):
        """The saved review does not cover the HEAD the gate decided on: after the checks the train dequeues it."""
        self.write('pkg/b.go', 'package b\n')
        later = self.commit('PR change after the review', push='feature')
        self.queue(head=self.reviewed, gate_head=later)

    # What each scenario may have written by the time a failure stops it. (A PR that needs a person is not
    # a scenario: an outage next to a reason only a person can fix still dequeues it, by the gate's rule,
    # because the reason stands whether or not GitHub answers.)
    SCENARIOS = {'aligned': ('aligned', set()), 'behind': ('behind', set()),
                 'overlap': ('overlap', {'comment'}), 'stale': ('stale', {'comment'})}

    def run_once(self, point=None, nth=1, make_exc=None):
        """One run with `point` failing from its `nth` call on: (the result, the calls it made, in order)."""
        self.gh.counts.clear()
        self.gh.calls.clear()
        self.gh.failing, self.gh.fail_from = {}, {}
        plan = Plan(self.gh.calls, point, nth, make_exc)
        if point in self.CLIENT:
            self.gh.failing[point] = make_exc()
            self.gh.fail_from[point] = nth
        train = self.train(mutation_lock=functools.partial(self.take, plan))
        real_git = train.git

        def traced_git(*args, **kw):
            plan.hit('git:' + args[0])
            return real_git(*args, **kw)
        train.git = traced_git
        patches = [mock.patch.object(merge_train, name, functools.partial(self.state, plan, name, getattr(merge_train, name)))
                   for name in ('load_entry', 'save_entry', 'drop_entry')]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            out = train.run()
        return out, list(self.gh.calls)

    @contextlib.contextmanager
    def take(self, plan, repo):
        plan.hit('lock')
        yield

    @staticmethod
    def state(plan, name, real, *args, **kw):
        plan.hit('state:' + name)
        return real(*args, **kw)

    def points(self, arrange):
        """Every (point, nth) a run of the scenario calls before its first write, the write included."""
        self.setUp()
        arrange()
        out, calls = self.run_once()
        prefix, seen = [], {}
        for name in calls:
            seen[name] = seen.get(name, 0) + 1
            prefix.append((name, seen[name]))
            if name in self.EXTERNAL_WRITES:
                break
        else:
            self.fail(f'the scenario never wrote anything: {out}')
        return prefix

    def test_every_point_of_every_scenario_is_covered(self):
        # The census itself: the matrix is only as good as the calls it finds.
        seen = set()
        for name, (arrange, _) in self.SCENARIOS.items():
            with self.subTest(scenario=name):
                points = self.points(getattr(self, arrange))
                seen |= {point for point, _ in points}
        for expected in ('labeled_open_prs', 'label_added_at', 'pr_view', 'branch_head', 'is_ancestor', 'compare',
                         'pr_checks', 'branch_rules', 'unresolved_threads', 'merge_pr', 'post_comment',
                         'git:fetch', 'git:rev-parse', 'git:merge-tree', 'git:commit-tree',
                         'git:diff', 'git:ls-tree', 'git:push', 'state:load_entry', 'state:save_entry', 'lock'):
            self.assertIn(expected, seen)

    def test_nothing_is_counted_written_or_dequeued_whatever_fails_wherever(self):
        for scenario, (arrange, allowed) in self.SCENARIOS.items():
            points = self.points(getattr(self, arrange))
            self.setUp()          # one repository for the scenario: every run leaves it as it found it
            getattr(self, arrange)()
            baseline = len(self.gh.writes)
            for point, nth in points:
                with self.subTest(scenario=scenario, point=point, nth=nth):
                    for exc_name, make_exc in self.EXCEPTIONS.items():
                        for run in range(self.RUNS):
                            out, _ = self.run_once(point, nth, make_exc)
                            where = f'{scenario}: {point} #{nth} {exc_name}, run {run + 1}'
                            self.assertInvariants(out, baseline, allowed, where, exc_name, point)

    def assertInvariants(self, out, baseline, allowed, where, exc_name, point):
        if out['status'] == 'INFRA':
            self.assertEqual(exc_name, out['error_kind'], where)
            self.assertEqual(None if point in ('labeled_open_prs', 'label_added_at') else 42, out['pr'], where)
        else:
            # The gate's own handling of an outage: the PR waits, stays enqueued, nothing is counted.
            self.assertEqual(('DONE', [(42, 'WAITING')]), (out['status'], outcomes(out)), f'{where}: {out}')
        entry = merge_train.load_entry(REPO, 42)
        self.assertIsNotNone(entry, f'{where}: the saved review was dropped')
        self.assertEqual(0, entry['errors'], f'{where}: counted')
        self.assertNotIn('last_error', entry, where)
        self.assertIn(42, self.gh.labels, f'{where}: the label was removed')
        self.assertEqual('OPEN', self.gh.prs[42]['state'], where)
        self.assertFalse(self.gh.prs[42]['isDraft'], where)
        written = {w[0] for w in self.gh.writes[baseline:]}
        self.assertLessEqual(written, allowed, f'{where}: wrote {self.gh.writes[baseline:]}')


class LaterWriteTests(Harness):
    """What follows the first write of a scenario (the matrix stops there): a failure after a comment, a
    Draft or a label change is still infrastructure, counts nothing, and heals on the next run."""

    def test_a_label_that_cannot_be_removed_after_the_comment_keeps_the_pr_enqueued(self):
        self.queue()
        self.gh.prs[42]['review'] = 'CHANGES_REQUESTED'      # a person must act: the train dequeues it
        self.gh.counts.clear()
        self.gh.failing['edit_label'] = GitHubError('gh pr edit failed (1): HTTP 502')
        for _ in range(3):
            out = self.train().run()
            self.assertInfra(out, kind='GitHubError', within='HTTP 502')
        entry = merge_train.load_entry(REPO, 42)
        self.assertEqual(0, entry['errors'])
        self.assertIn(42, self.gh.labels)
        self.assertNotIn(('label-', 42), self.gh.writes)
        self.gh.failing.clear()
        out = self.train().run()
        self.assertEqual([(42, 'DEQUEUED')], outcomes(out), 'it heals on the next run')
        self.assertNotIn(42, self.gh.labels)

    def test_a_draft_that_cannot_be_requested_leaves_the_pr_enqueued_and_the_next_run_drafts_it(self):
        self.queue()
        self.advance_main('pkg/a.go', 'package a // main change\n')
        self.gh.failing['mark_draft'] = GitHubError('gh pr ready failed (1): HTTP 502')
        for _ in range(3):
            out = self.train().run()
            self.assertInfra(out, kind='GitHubError', within='HTTP 502')
        self.assertEqual(0, merge_train.load_entry(REPO, 42)['errors'])
        self.assertIn(42, self.gh.labels)
        self.assertFalse(self.gh.prs[42]['isDraft'])
        self.gh.failing.clear()
        self.assertEqual([(42, 'DRAFTED')], outcomes(self.train().run()))

    def test_a_label_that_cannot_be_removed_after_the_draft_is_settled_silently_next_run(self):
        self.queue()
        self.advance_main('pkg/a.go', 'package a // main change\n')
        self.gh.counts.clear()
        self.gh.failing['edit_label'] = GitHubError('gh pr edit failed (1): HTTP 502')
        out = self.train().run()
        self.assertInfra(out, kind='GitHubError')
        self.assertTrue(self.gh.prs[42]['isDraft'], 'the Draft was made and confirmed')
        self.assertEqual(0, merge_train.load_entry(REPO, 42)['errors'])
        self.gh.failing.clear()
        comments = len(self.gh.comments)
        out = self.train().run()
        self.assertEqual([(42, 'DEQUEUED')], outcomes(out), out)
        self.assertEqual(comments, len(self.gh.comments), 'a Draft leaves the queue silently')
        self.assertNotIn(42, self.gh.labels)
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_an_entry_that_cannot_be_dropped_after_the_label_went_is_a_stop_not_an_error(self):
        self.queue()
        self.gh.prs[42]['review'] = 'CHANGES_REQUESTED'
        with mock.patch.object(merge_train, 'drop_entry', side_effect=OSError(errno.EIO, 'Input/output error')):
            out = self.train().run()
        self.assertInfra(out, kind='OSError', within='Input/output error')
        self.assertNotIn(42, self.gh.labels, 'the PR is out of the queue')
        self.assertEqual([], self.train().run()['results'], 'and nothing is listed any more')


# -- the lint --------------------------------------------------------------------------------------------------

def error_outcome_violations(source):
    """Every way `class Train` could make a result that counts against a PR other than `_pr_error`, and
    every way an exception could reach the counter:

    * the `"outcome": "ERROR"` literal (as a dict entry, a keyword or an assignment to ["outcome"]) outside
      `_pr_error`;
    * a call of `_pr_error` whose kind is not a literal registered in PR_ERROR_KINDS, or that sits inside an
      `except` handler (an exception is never a reason to count: the PR's state is);
    * `_track_errors` called from inside an `except` handler;
    * an `except` handler in `process_one` that does not end by returning or raising, so that it falls
      through to `_track_errors` with whatever it made."""
    tree = ast.parse(source)
    train = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Train')
    kinds = next(ast.literal_eval(node.value) for node in tree.body
                 if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'PR_ERROR_KINDS'
                                                         for t in node.targets))
    found = []

    def is_error(node):
        return isinstance(node, ast.Constant) and node.value == 'ERROR'

    def is_outcome(node):
        return isinstance(node, ast.Constant) and node.value == 'outcome'

    def self_call(node, name):
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == name
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 'self')

    def visit(node, where, in_handler):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            where = node.name
        spelled = None
        if isinstance(node, ast.Dict):
            spelled = any(is_outcome(k) and is_error(v) for k, v in zip(node.keys, node.values))
        elif isinstance(node, ast.keyword):
            spelled = node.arg == 'outcome' and is_error(node.value)
        elif isinstance(node, ast.Assign):
            spelled = is_error(node.value) and any(isinstance(t, ast.Subscript) and is_outcome(t.slice)
                                                   for t in node.targets)
        if spelled and where != '_pr_error':
            found.append(f'{where}:{node.lineno}: an ERROR result made outside _pr_error')
        if self_call(node, '_pr_error'):
            kind = node.args[1] if len(node.args) > 1 else None
            if not (isinstance(kind, ast.Constant) and kind.value in kinds):
                found.append(f'{where}:{node.lineno}: _pr_error with a kind that is not a registered literal')
            if in_handler:
                found.append(f'{where}:{node.lineno}: _pr_error inside an except handler')
        if self_call(node, '_track_errors') and in_handler:
            found.append(f'{where}:{node.lineno}: _track_errors called from an except handler')
        if isinstance(node, ast.Try) and where == 'process_one':
            for handler in node.handlers:
                if not isinstance(handler.body[-1], (ast.Return, ast.Raise)):
                    found.append(f'{where}:{handler.lineno}: an except handler that falls through to _track_errors')
        for child in ast.iter_child_nodes(node):
            visit(child, where, in_handler or isinstance(child, ast.ExceptHandler))

    visit(train, 'Train', False)
    return found


# What `process_one` and the two places that said ERROR looked like before kjelly/pilot#310 (d8b89f25): an
# exception became an ERROR result, and the result was counted.
BASE_SHAPE = '''
PR_ERROR_KINDS = ("merge-unconfirmed", "draft-unconfirmed")
class Train:
    def process_one(self, number):
        attempt = _Attempt()
        try:
            result = self._process(number, attempt)
        except LockBusy as exc:
            return self.waiting(number, "busy")
        except (GitHubError, TrainError, ValueError, KeyError) as exc:
            result = {"pr": number, "outcome": "ERROR", "reason": str(exc)}
        return self._track_errors(number, result, attempt)
    def merge(self, number):
        return {"pr": number, "outcome": "ERROR", "reason": "not confirmed MERGED"}
    def to_draft(self, number):
        return {"pr": number, "outcome": "ERROR", "reason": "Draft conversion was not confirmed"}
'''
FIXED_SHAPE = '''
PR_ERROR_KINDS = ("merge-unconfirmed", "draft-unconfirmed")
class Train:
    def process_one(self, number):
        try:
            result = self._process(number, attempt)
        except MutationLockHeld as exc:
            return self.waiting(number, "busy")
        except Exception as exc:
            raise RunStopped(number, exc) from exc
        return self._track_errors(number, result, attempt)
    def _pr_error(self, number, kind, reason):
        return {"pr": number, "outcome": "ERROR", "kind": kind, "reason": reason}
    def merge(self, number):
        return self._pr_error(number, "merge-unconfirmed", "not confirmed MERGED")
'''


class ErrorClassificationLintTests(unittest.TestCase):
    """A result that counts against a PR is made in one place, from the PR's state; the lint is proved on
    the code that counted exceptions."""

    def test_the_train_makes_a_counted_result_only_in_pr_error(self):
        self.assertEqual([], error_outcome_violations(Path(merge_train.__file__).read_text(encoding='utf-8')))

    def test_the_lint_accepts_the_fixed_shape_and_rejects_the_one_that_counted_exceptions(self):
        self.assertEqual([], error_outcome_violations(FIXED_SHAPE))
        found = sorted(re.sub(r':\d+:', ':', line) for line in error_outcome_violations(BASE_SHAPE))
        self.assertEqual(sorted(['process_one: an ERROR result made outside _pr_error',
                                 'process_one: an except handler that falls through to _track_errors',
                                 'merge: an ERROR result made outside _pr_error',
                                 'to_draft: an ERROR result made outside _pr_error']), found)

    def test_the_lint_sees_each_spelling_and_each_way_to_count_an_exception(self):
        spellings = {
            'a dict': 'return {"pr": n, "outcome": "ERROR"}',
            'a keyword': 'return dict(pr=n, outcome="ERROR")',
            'an assignment': 'result["outcome"] = "ERROR"',
        }
        for name, line in spellings.items():
            with self.subTest(spelling=name):
                head = 'PR_ERROR_KINDS = ("merge-unconfirmed",)\nclass Train:\n'
                self.assertEqual(1, len(error_outcome_violations(f'{head}    def f(self, n):\n        {line}\n')))
                self.assertEqual([], error_outcome_violations(f'{head}    def _pr_error(self, n, kind, reason):\n        {line}\n'))
        head = 'PR_ERROR_KINDS = ("merge-unconfirmed",)\nclass Train:\n    def f(self, n):\n'
        cases = {
            'an unregistered kind': ('        return self._pr_error(n, "disk-full", "x")\n', 1),
            'a kind that is not a literal': ('        return self._pr_error(n, kind, "x")\n', 1),
            'a registered kind': ('        return self._pr_error(n, "merge-unconfirmed", "x")\n', 0),
            'an exception counted': ('        try:\n            g()\n        except OSError:\n'
                                     '            return self._pr_error(n, "merge-unconfirmed", "x")\n', 1),
            'the counter fed by a handler': ('        try:\n            g()\n        except OSError:\n'
                                              '            self._track_errors(n, {}, a)\n', 1),
        }
        for name, (body, expected) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(expected, len(error_outcome_violations(head + body)), name)
