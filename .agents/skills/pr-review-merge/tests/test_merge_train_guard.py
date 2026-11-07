"""Every write the merge train makes is made on what it reads under the mutation lock (kjelly/pilot#308).

A destructive write (a comment, the label, Draft, the merge, the push, the saved entry) used to act on an
observation taken before the lock and never read it again: the author repaired the HEAD or withdrew the
label while the train waited for the lock, and the train drafted the repaired PR anyway. The class is
closed at one choke point, `Train._guard`, and these tests drive the real `Train.run` (real Git behind a
fake GitHub, as in test_merge_train.py) through the moments something else can act:

* T1: after the decision, before the lock is granted (`Lock.at`);
* T2: between the comment and the next write (a Draft comment cannot be taken back);
* T3: after the last read under the lock, which nothing can see (GitHub has no compare-and-swap for a
  comment, a label or Draft; the merge and the push have one).

and through the changes that matter: the HEAD repaired, the label withdrawn, the PR Drafted, closed or
merged by hand, the base moved or the PR retargeted, the same PR enqueued again, the lock busy. The last
class is a lint over `Train`: no write may sit outside `with self._guard(...)`.
"""
import ast
import contextlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import merge_train  # noqa: E402
import review_gate  # noqa: E402
from gh_runtime import MutationLockHeld  # noqa: E402
from scan_stub import CleanScan  # noqa: E402
from test_merge_train import PASS, PENDING, REPO, DeliveryTests, git  # noqa: E402

setUpModule, tearDownModule = CleanScan.up, CleanScan.down

DRAFT_COMMENT = 'Draft required'
SUPERSEDED = 'Draft comment superseded'
LEFT_QUEUE = 'left the queue'


class Lock:
    """A mutation lock the tests can watch and arm.

    `held` is true while it is taken. `at` maps the n-th take (1-based) to an action run just before the
    lock is granted: the moment between a decision made before the lock and the guarded read. From the
    `busy_from`-th take on the lock is held by someone else (`MutationLockHeld`, as `apply_decision`
    raises it). `outside` is true while an armed action runs: those writes are another person's."""

    def __init__(self):
        self.held = False
        self.outside = False
        self.takes = 0
        self.at = {}
        self.fired = []
        self.busy_from = None

    def __call__(self, repo):
        return self._take()

    @contextlib.contextmanager
    def _take(self):
        self.takes += 1
        if self.busy_from is not None and self.takes >= self.busy_from:
            raise MutationLockHeld('Another pr-review-merge actor is modifying this repository')
        if self.takes in self.at:
            self.fired.append(self.takes)
            self.outside = True
            try:
                self.at[self.takes]()
            finally:
                self.outside = False
        self.held = True
        try:
            yield
        finally:
            self.held = False


class GuardHarness(DeliveryTests):
    """Scenarios and helpers; it has no tests of its own."""

    def locked(self, **at):
        lock = Lock()
        lock.at = {int(key[1:]): action for key, action in at.items()}   # t1=..., t2=... name the take
        return lock

    def run_train(self, lock=None, **kw):
        lock = lock or Lock()
        train = self.train(mutation_lock=lock, **kw)
        return train, train.run(), lock

    def tail(self):
        """The names of the writes since the scenario was armed (`self.mark`)."""
        return [w[0] for w in self.gh.writes[self.mark:] if w[1] == 42]

    def comments_since(self):
        return [body for number, body in self.gh.comments[self.mark_comments:] if number == 42]

    def arm(self):
        self.mark = len(self.gh.writes)
        self.mark_comments = len(self.gh.comments)

    def overlap(self):
        """#42 was enqueued; main then changed pkg/a.go too: the train must hand it back to Draft."""
        self.queue()
        self.live_before = self.advance_main('pkg/a.go', 'package a // main change\n')
        self.arm()

    def repair(self):
        """The author integrates main, resolving the overlap, and pushes the result (H2)."""
        git(self.dev, 'fetch', '-q', 'origin')
        subprocess.run(['git', '-C', str(self.dev), 'merge', '--no-edit', 'origin/main'], capture_output=True)
        self.write('pkg/a.go', 'package a // PR change + main change\n')
        git(self.dev, 'commit', '-q', '--no-edit')
        git(self.dev, 'push', '-q', 'origin', 'HEAD:refs/heads/feature')
        return git(self.dev, 'rev-parse', 'HEAD')

    def push_on_top(self):
        """The author pushes a commit on top of whatever the PR branch holds now (the train's merge too)."""
        git(self.dev, 'fetch', '-q', 'origin')
        git(self.dev, 'reset', '-q', '--hard', 'origin/feature')
        return self.push_to_pr()

    def withdraw(self):
        self.gh.labels.pop(42, None)

    def draft(self):
        self.gh.prs[42]['isDraft'] = True

    def close(self):
        self.gh.prs[42]['state'] = 'CLOSED'

    def merge_by_hand(self):
        self.gh.prs[42]['state'] = 'MERGED'

    def after_comment(self, action, marker=DRAFT_COMMENT):
        """Run `action` once, right after the train posts a comment that contains `marker`."""
        real, done = self.gh.post_comment, []

        def post(repo, number, body):
            real(repo, number, body)
            if marker in body and not done:
                done.append(1)
                action()
        self.gh.post_comment = post

    def before_write(self, name, action):
        """Run `action` once, right before the train makes the write `name`: after its last read."""
        real, done = getattr(self.gh, name), []

        def write(*args):
            if not done:
                done.append(1)
                action()
            return real(*args)
        setattr(self.gh, name, write)

    def only(self, out):
        self.assertEqual(1, len(out['results']), out)
        return out['results'][0]

    def assertQuiet(self, msg='the train wrote nothing'):
        self.assertEqual([], self.tail(), msg)
        self.assertEqual([], self.comments_since(), msg)



class DraftRaceTests(GuardHarness):
    """to_draft (overlap, conflict, a non-pure merge, a target gap, a gate DRAFT) acts only on the PR the
    reasons were derived from."""

    def test_t1_a_repaired_head_is_not_drafted_and_no_obsolete_claim_is_made(self):
        self.overlap()
        repaired = {}
        lock = self.locked(t1=lambda: repaired.update(head=self.repair()))
        _, out, lock = self.run_train(lock)
        result = self.only(out)
        self.assertEqual([1], lock.fired)
        self.assertEqual('DEQUEUED', result['outcome'], out)
        self.assertIn('HEAD changed since it was enqueued', result['reason'])
        # The only comment is the dequeue's; none says the repaired HEAD lacks main.
        self.assertEqual(['comment', 'label-'], self.tail())
        self.assertEqual([LEFT_QUEUE], [b.splitlines()[0][len('## Merge train: '):] for b in self.comments_since()])
        self.assertNotIn(DRAFT_COMMENT, ''.join(self.comments_since()))
        self.assertEqual(repaired['head'], self.gh.head(42))
        self.assertFalse(self.gh.prs[42]['isDraft'])

    def test_t1_a_repaired_head_with_the_label_withdrawn_writes_nothing(self):
        self.overlap()
        _, out, lock = self.run_train(self.locked(t1=lambda: (self.repair(), self.withdraw())))
        self.assertEqual([1], lock.fired)
        self.assertEqual('DEQUEUED', self.only(out)['outcome'], out)
        self.assertIn('label was removed', self.only(out)['reason'])
        self.assertQuiet()
        self.assertIsNone(merge_train.load_entry(REPO, 42))
        self.assertFalse(self.gh.prs[42]['isDraft'])

    def test_t1_a_withdrawal_writes_nothing(self):
        self.overlap()
        _, out, lock = self.run_train(self.locked(t1=self.withdraw))
        self.assertEqual([1], lock.fired)
        self.assertIn('label was removed', self.only(out)['reason'])
        self.assertQuiet()
        self.assertIsNone(merge_train.load_entry(REPO, 42))
        self.assertFalse(self.gh.prs[42]['isDraft'])

    def test_t1_a_pr_someone_made_a_draft_leaves_silently_and_is_not_drafted_again(self):
        self.overlap()
        _, out, lock = self.run_train(self.locked(t1=self.draft))
        self.assertEqual([1], lock.fired)
        self.assertEqual('DEQUEUED', self.only(out)['outcome'], out)
        self.assertEqual(['label-'], self.tail())
        self.assertEqual([], self.comments_since())
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_t1_a_pr_closed_or_merged_by_hand_is_skipped_without_a_write(self):
        for name, change in (('closed', self.close), ('merged by hand', self.merge_by_hand)):
            with self.subTest(change=name):
                self.setUp()
                self.overlap()
                _, out, lock = self.run_train(self.locked(t1=change))
                self.assertEqual([1], lock.fired)
                self.assertEqual('SKIP', self.only(out)['outcome'], out)
                self.assertQuiet()
                self.assertIsNone(merge_train.load_entry(REPO, 42), 'the entry of a finished PR is dropped')

    def test_t1_a_base_that_moved_is_read_again_and_the_comment_names_the_live_tip(self):
        self.overlap()
        moved = {}
        lock = self.locked(t1=lambda: moved.update(live=self.advance_main('docs/y.md')))
        _, out, lock = self.run_train(lock)
        self.assertEqual('DRAFTED', self.only(out)['outcome'], out)
        self.assertEqual(['comment', 'draft', 'label-'], self.tail())
        body = self.comments_since()[-1]
        self.assertIn(moved['live'], body)
        self.assertNotIn(self.live_before, body, 'the comment would have named a base that is no longer the live one')

    def test_t1_a_base_that_keeps_moving_stays_enqueued(self):
        self.overlap()
        lock = Lock()
        count = []

        def move():
            count.append(self.advance_main(f'docs/m{len(count)}.md'))
        lock.at = {n: move for n in range(1, 8)}
        _, out, lock = self.run_train(lock, max_align=2)
        self.assertEqual('WAITING', self.only(out)['outcome'], out)
        self.assertIn('kept changing', self.only(out)['reason'])
        self.assertQuiet()
        self.assertIn(42, self.gh.labels)
        self.assertIsNotNone(merge_train.load_entry(REPO, 42))

    def test_t1_the_pr_enqueued_again_is_processed_as_the_new_entry(self):
        self.overlap()
        ids = {}

        def reenqueue():
            ids['old'] = merge_train.load_entry(REPO, 42)['entry_id']
            self.queue(note='fresh review')
            ids['new'] = merge_train.load_entry(REPO, 42)['entry_id']
            self.arm()
        _, out, lock = self.run_train(self.locked(t1=reenqueue))
        self.assertNotEqual(ids['old'], ids['new'])
        self.assertEqual('DRAFTED', self.only(out)['outcome'], out)
        self.assertEqual(['comment', 'draft', 'label-'], self.tail())
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_t1_a_repaired_head_that_is_enqueued_again_is_merged_never_drafted(self):
        self.overlap()
        _, out, lock = self.run_train(self.locked(t1=lambda: self.queue(head=self.repair())))
        self.assertEqual([1], lock.fired)
        self.assertEqual('MERGED', self.only(out)['outcome'], out)
        self.assertNotIn('draft', [w[0] for w in self.gh.writes])
        self.assertNotIn(DRAFT_COMMENT, ''.join(body for _, body in self.gh.comments))

    def test_t1_a_busy_lock_waits_and_counts_nothing_against_the_pr(self):
        self.overlap()
        for run in range(3):
            lock = Lock()
            lock.busy_from = 1
            _, out, _ = self.run_train(lock)
            self.assertEqual('WAITING', self.only(out)['outcome'], (run, out))
            self.assertIn('mutation lock', self.only(out)['reason'])
        self.assertQuiet()
        self.assertEqual(0, merge_train.load_entry(REPO, 42)['errors'])
        self.assertIn(42, self.gh.labels)
        # The lock frees up: the PR is handled as if nothing had happened.
        _, out, _ = self.run_train()
        self.assertEqual('DRAFTED', self.only(out)['outcome'], out)

    def test_t2_a_head_repaired_after_the_comment_is_not_drafted_and_the_comment_says_it_is_void(self):
        self.overlap()
        repaired = {}
        self.after_comment(lambda: repaired.update(head=self.repair()))
        train, out, _ = self.run_train()
        self.assertEqual('DEQUEUED', self.only(out)['outcome'], out)
        self.assertIn('HEAD changed since it was enqueued', self.only(out)['reason'])
        self.assertNotIn('draft', self.tail())
        bodies = self.comments_since()
        self.assertEqual(3, len(bodies), bodies)
        self.assertIn(DRAFT_COMMENT, bodies[0])
        self.assertIn(SUPERSEDED, bodies[1])
        self.assertIn(self.reviewed, bodies[1], 'it names the HEAD the voided comment judged')
        self.assertIn('did not convert the PR to Draft', bodies[1])
        self.assertIn(LEFT_QUEUE, bodies[2])
        self.assertTrue([line for line in train.log if 'voided' in line and self.reviewed[:12] in line], train.log)
        self.assertFalse(self.gh.prs[42]['isDraft'])

    def test_t2_a_withdrawal_after_the_comment_removes_no_label_and_drafts_nothing(self):
        self.overlap()
        self.after_comment(self.withdraw)
        _, out, _ = self.run_train()
        self.assertIn('label was removed', self.only(out)['reason'])
        self.assertEqual(['comment', 'comment'], self.tail())
        self.assertIn(SUPERSEDED, self.comments_since()[1])
        self.assertFalse(self.gh.prs[42]['isDraft'])
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_t2_a_draft_made_by_someone_after_the_comment_is_not_converted_again(self):
        self.overlap()
        self.after_comment(self.draft)
        _, out, _ = self.run_train()
        self.assertEqual('DEQUEUED', self.only(out)['outcome'], out)
        self.assertEqual(['comment', 'comment', 'label-'], self.tail())
        self.assertIn(SUPERSEDED, self.comments_since()[1])

    def test_t2_a_pr_closed_after_the_comment_is_not_converted(self):
        for name, change in (('closed', self.close), ('merged by hand', self.merge_by_hand)):
            with self.subTest(change=name):
                self.setUp()
                self.overlap()
                self.after_comment(change)
                _, out, _ = self.run_train()
                self.assertEqual('SKIP', self.only(out)['outcome'], out)
                self.assertEqual(['comment', 'comment'], self.tail())
                self.assertNotIn('draft', self.tail())

    def test_t2_a_base_that_moved_after_the_comment_voids_it_and_the_next_comment_names_the_new_tip(self):
        self.overlap()
        moved = {}
        self.after_comment(lambda: moved.update(live=self.advance_main('docs/y.md')))
        _, out, _ = self.run_train()
        self.assertEqual('DRAFTED', self.only(out)['outcome'], out)
        self.assertEqual(['comment', 'comment', 'comment', 'draft', 'label-'], self.tail())
        bodies = self.comments_since()
        self.assertIn(self.live_before, bodies[0])
        self.assertIn(SUPERSEDED, bodies[1])
        self.assertIn(moved['live'], bodies[2])

    def test_t2_the_pr_enqueued_again_after_the_comment_is_not_drafted_on_the_old_entry(self):
        self.overlap()
        self.after_comment(lambda: self.queue(note='fresh review'))
        _, out, _ = self.run_train()
        self.assertEqual('DRAFTED', self.only(out)['outcome'], out)
        self.assertEqual(1, self.tail().count('draft'), 'converted once, for the entry that is saved now')
        self.assertIn(SUPERSEDED, ''.join(self.comments_since()))
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_t3_a_head_that_moves_after_the_last_read_cannot_be_seen_but_is_reported(self):
        # The irreducible window: GitHub cannot refuse a Draft for a moved HEAD. The train says so.
        self.overlap()
        moved = {}
        self.before_write('mark_draft', lambda: moved.update(head=self.repair()))
        train, out, _ = self.run_train()
        self.assertEqual('DRAFTED', self.only(out)['outcome'], out)
        self.assertTrue(self.gh.prs[42]['isDraft'])
        self.assertTrue([line for line in train.log if 'while it was converted to Draft' in line], train.log)

    def test_a_draft_that_does_not_take_effect_is_an_error_and_keeps_the_pr_enqueued(self):
        self.overlap()
        self.gh.mark_draft = lambda repo, number: self.gh.writes.append(('draft', number))   # GitHub ignores it
        _, out, _ = self.run_train()
        self.assertEqual('ERROR', self.only(out)['outcome'], out)
        self.assertIn('Draft conversion was not confirmed', self.only(out)['reason'])
        self.assertIn(42, self.gh.labels, 'not Drafted: the label stays')
        entry = merge_train.load_entry(REPO, 42)
        self.assertEqual(1, entry['errors'])
        self.assertEqual(['comment', 'draft'], self.tail())

    def test_the_label_is_removed_only_after_the_draft_is_confirmed(self):
        for case in ('overlap', 'conflict'):
            with self.subTest(case=case):
                self.setUp()
                self.queue()
                if case == 'overlap':
                    self.advance_main('pkg/a.go', 'package a // main change\n')
                else:
                    self.advance_main()
                    self.gh.prs[42]['mergeable'] = 'CONFLICTING'
                self.arm()
                seen = []
                real_draft = self.gh.mark_draft

                def mark(repo, number):
                    seen.append(42 in self.gh.labels)
                    real_draft(repo, number)
                self.gh.mark_draft = mark
                self.assertEqual('DRAFTED', self.only(self.run_train()[1])['outcome'])
                self.assertEqual([True], seen, 'the label was still on when the Draft was requested')

    def test_every_caller_of_to_draft_is_guarded(self):
        # The four other callers: a non-pure merge, a target gap, a gate DRAFT (failed CI on the integrated
        # HEAD), each repaired before the lock; the push that integrates is never made for them either.
        cases = {}

        def non_pure():
            lines = [f'line {i}' for i in range(30)]
            self.advance_main('pkg/long.go', '\n'.join(lines) + '\n')
            git(self.dev, 'fetch', '-q', 'origin')
            git(self.dev, 'merge', '-q', '--no-edit', 'origin/main')
            self.write('pkg/long.go', '\n'.join(['PR first line'] + lines[1:]) + '\n')
            self.reviewed = self.commit('PR edits the first line', push='feature')
            self.queue()
            self.advance_main('pkg/long.go', '\n'.join(lines[:-1] + ['main last line']) + '\n')
            real = self.gh.compare
            self.gh.compare = lambda repo, base, head: dict(
                real(repo, base, head), files=[f for f in real(repo, base, head)['files'] if f != 'pkg/long.go'])
        cases['a merge that is not a pure import'] = (non_pure, 1)

        def target_gap():
            self.queue()
            self.advance_main()
        cases['a target record that stopped covering HEAD'] = (target_gap, 2)

        def failed_ci():
            self.queue()
            self.gh.checks[42] = [[{'name': 'go test', 'bucket': 'fail', 'state': 'FAILURE', 'link': 'https://ci/1'}]]
        cases['a gate DRAFT'] = (failed_ci, 1)

        for name, (arrange, take) in cases.items():
            for change_name, change in (('repaired', None), ('withdrawn', self.withdraw)):
                with self.subTest(case=name, change=change_name):
                    self.setUp()
                    arrange()
                    self.arm()
                    lock = self.locked(**{f't{take}': self.push_on_top if change is None else change})
                    train = self.train(mutation_lock=lock)
                    with mock.patch.object(review_gate, 'check_target_validation',
                                           return_value=(['the run does not cover HEAD'], {})) \
                            if name.startswith('a target') else contextlib.nullcontext():
                        out = train.run()
                    self.assertEqual([take], lock.fired, out)
                    self.assertNotIn('draft', self.tail())
                    self.assertNotIn(DRAFT_COMMENT, ''.join(self.comments_since()))
                    self.assertFalse(self.gh.prs[42]['isDraft'])
                    self.assertEqual('DEQUEUED', self.only(out)['outcome'], out)


class DequeueRaceTests(GuardHarness):
    """dequeue (a person must act, the HEAD moved, the saved review is stale, three errors in a row) acts
    only on the PR and the entry it was decided for, and withdrawal is silent however late it comes."""

    def person_needed(self):
        self.queue()
        self.gh.prs[42]['review'] = 'CHANGES_REQUESTED'
        self.arm()

    def head_moves_during_ci(self):
        self.queue()
        self.pushed = {}
        self.gh.checks[42] = [[PENDING], [PASS]]
        self.gh.on_checks = lambda number, poll: self.pushed.setdefault('head', self.push_to_pr()) if poll == 0 else None
        self.arm()

    def stale_review(self):
        self.write('pkg/b.go', 'package b\n')
        later = self.commit('PR change after the review', push='feature')
        self.queue(head=self.reviewed, gate_head=later)
        self.advance_main()
        self.arm()

    def failing_merge(self):
        self.queue()
        merge_train.save_entry(REPO, 42, dict(merge_train.load_entry(REPO, 42), errors=2))
        self.gh.merge_unconfirmed.add(42)       # accepted by GitHub, never shown: the PR's own error
        self.arm()

    def test_t1_withdrawal_before_a_person_dequeue_writes_nothing(self):
        self.person_needed()
        _, out, lock = self.run_train(self.locked(t1=self.withdraw))
        self.assertEqual([1], lock.fired)
        self.assertIn('label was removed', self.only(out)['reason'])
        self.assertQuiet('a withdrawn PR gets no comment')
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_t1_a_pr_drafted_or_closed_before_a_person_dequeue_gets_no_comment(self):
        for name, change, outcome, writes in (('drafted', self.draft, 'DEQUEUED', ['label-']),
                                              ('closed', self.close, 'SKIP', [])):
            with self.subTest(change=name):
                self.setUp()
                self.person_needed()
                _, out, lock = self.run_train(self.locked(t1=change))
                self.assertEqual([1], lock.fired)
                self.assertEqual(outcome, self.only(out)['outcome'], out)
                self.assertEqual(writes, self.tail())
                self.assertEqual([], self.comments_since())

    def test_t1_a_head_that_moved_after_a_person_decision_is_judged_as_a_moved_head(self):
        self.person_needed()
        _, out, lock = self.run_train(self.locked(t1=self.push_to_pr))
        self.assertEqual('DEQUEUED', self.only(out)['outcome'], out)
        self.assertIn('HEAD changed since it was enqueued', self.only(out)['reason'])
        self.assertEqual(1, len(self.comments_since()))
        self.assertNotIn('CHANGES_REQUESTED', self.comments_since()[0], 'the reasons were about the old HEAD')

    def test_t1_the_pr_enqueued_again_is_not_dequeued_for_the_old_entry(self):
        self.person_needed()

        def fixed_and_enqueued_again():
            self.gh.prs[42]['review'] = ''
            self.queue(note='fresh review')
            self.arm()
        _, out, lock = self.run_train(self.locked(t1=fixed_and_enqueued_again))
        self.assertEqual([1], lock.fired)
        self.assertEqual('MERGED', self.only(out)['outcome'], out)
        self.assertNotIn(LEFT_QUEUE, ''.join(self.comments_since()))
        # Merged on the new entry; the label comes off once, after the merge, as housekeeping (no dequeue).
        self.assertEqual(['merge', 'label-'], self.tail())

    def test_t1_a_head_moved_dequeue_is_for_the_entry_it_saw(self):
        for name, change, expect in (('enqueued again at the new HEAD', 'reenqueue', 'MERGED'),
                                     ('withdrawn', 'withdraw', 'DEQUEUED')):
            with self.subTest(change=name):
                self.setUp()
                self.head_moves_during_ci()
                action = (lambda: (self.queue(head=self.pushed['head']), self.arm())) if change == 'reenqueue' \
                    else self.withdraw
                _, out, lock = self.run_train(self.locked(t1=action))
                self.assertEqual([1], lock.fired)
                self.assertEqual(expect, self.only(out)['outcome'], out)
                self.assertNotIn(LEFT_QUEUE, ''.join(self.comments_since()))
                # Merged on the new entry: the label comes off once, after the merge. Withdrawn: nothing at all.
                self.assertEqual(['merge', 'label-'] if change == 'reenqueue' else [], self.tail())

    def test_t1_withdrawal_before_a_stale_review_dequeue_writes_nothing(self):
        self.stale_review()
        _, out, lock = self.run_train(self.locked(t2=self.withdraw))
        self.assertEqual([2], lock.fired, 'the first lock is the push; the second is the dequeue')
        self.assertIn('label was removed', self.only(out)['reason'])
        self.assertQuiet()
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_t1_the_third_error_does_not_dequeue_a_withdrawn_pr(self):
        self.failing_merge()
        _, out, lock = self.run_train(self.locked(t3=self.withdraw))
        self.assertEqual([3], lock.fired, 'merge, count, dequeue')
        self.assertEqual('ERROR', self.only(out)['outcome'], out)
        # The merge GitHub accepted and the PR never showed is the only write; no "failed in 3 runs" comment
        # and no label write for a PR that was withdrawn.
        self.assertEqual(['merge'], self.tail(), 'no "failed in 3 runs" comment on a PR that was withdrawn')
        self.assertEqual([], self.comments_since())
        self.assertNotIn(42, self.gh.labels)
        self.assertEqual(3, merge_train.load_entry(REPO, 42)['errors'], 'counted; the withdrawn PR is not in the queue')
        _, out, _ = self.run_train()
        self.assertEqual([], out['results'], 'a withdrawn PR is not listed, so nothing more is done to it')
        self.assertEqual(['merge'], self.tail())
        self.assertEqual([], self.comments_since())


class MergeRaceTests(GuardHarness):
    """merge acts only on the HEAD the entry binds, on the base it was gated against, on an open PR."""

    def test_t1_a_pr_closed_or_merged_by_hand_is_not_merged_again(self):
        for name, change in (('closed', self.close), ('merged by hand', self.merge_by_hand)):
            with self.subTest(change=name):
                self.setUp()
                self.queue()
                self.arm()
                _, out, lock = self.run_train(self.locked(t1=change))
                self.assertEqual([1], lock.fired)
                self.assertEqual('SKIP', self.only(out)['outcome'], out)
                self.assertEqual([], self.merges())
                self.assertQuiet()
                self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_t1_a_retargeted_pr_is_not_merged_even_when_both_bases_share_a_tip(self):
        # The branch name is part of the identity: `release` points at the same commit as `main`.
        self.queue()
        git(self.origin, 'update-ref', 'refs/heads/release', git(self.origin, 'rev-parse', 'refs/heads/main'))
        self.arm()
        _, out, lock = self.run_train(self.locked(t1=lambda: self.gh.prs[42].update(base_name='release')))
        self.assertEqual([1], lock.fired)
        self.assertEqual('WAITING', self.only(out)['outcome'], out)
        self.assertIn('changed immediately before the merge', self.only(out)['reason'])
        self.assertIn('retargeted', self.only(out)['reason'])
        self.assertEqual([], self.merges())
        self.assertIn(42, self.gh.labels)

    def test_t1_a_head_the_entry_does_not_bind_is_never_merged_even_when_the_gate_approved_it(self):
        # The author merges main into the branch after finish read the HEAD and before the gate read it: the
        # gate approves H2 (a pure import of main), the PR still shows H2, but H2 was never enqueued.
        self.queue()
        self.arm()
        real = review_gate.evaluate
        seen = {}

        def evaluate(*args, **kw):
            self.advance_main()
            seen['head'] = self.merge_main()
            return real(*args, **kw)
        with mock.patch.object(review_gate, 'evaluate', evaluate):
            _, out, lock = self.run_train()
        self.assertEqual('WAITING', self.only(out)['outcome'], out)
        self.assertEqual([], self.merges())
        self.assertEqual(seen['head'], self.gh.head(42))
        # The next run finds the HEAD unbound and takes the PR out of the queue.
        _, out, _ = self.run_train()
        self.assertEqual('DEQUEUED', self.only(out)['outcome'], out)
        self.assertIn('HEAD changed since it was enqueued', self.only(out)['reason'])
        self.assertEqual([], self.merges())

    def test_t1_the_pr_enqueued_again_is_merged_on_the_new_evidence(self):
        self.queue()
        self.arm()
        gates = []
        real = review_gate.evaluate

        def evaluate(repo, number, evidence, **kw):
            gates.append(evidence.get('note'))
            return real(repo, number, evidence, **kw)
        with mock.patch.object(review_gate, 'evaluate', evaluate):
            _, out, lock = self.run_train(self.locked(t1=lambda: self.queue(note='fresh review')))
        self.assertEqual([1], lock.fired)
        self.assertEqual('MERGED', self.only(out)['outcome'], out)
        self.assertEqual([None, 'fresh review'], gates, 'the gate ran again on the entry that is saved now')
        self.assertEqual(1, len(self.merges()))
        self.assertIsNone(merge_train.load_entry(REPO, 42))

    def test_t3_a_head_that_moves_after_the_last_read_is_refused_by_github(self):
        self.queue()
        self.arm()
        moved = {}
        self.before_write('merge_pr', lambda: moved.update(head=self.push_to_pr()))
        _, out, _ = self.run_train()
        # GitHub refuses the merge. The PR shows why (its HEAD moved), so the run looks at it again and the
        # new HEAD, which was never gated, takes it out of the queue: the PR's own verdict, not an error.
        self.assertEqual('DEQUEUED', self.only(out)['outcome'], out)
        self.assertIn('HEAD changed since it was enqueued', self.only(out)['reason'])
        self.assertEqual('OPEN', self.gh.prs[42]['state'])
        self.assertEqual(moved['head'], self.gh.head(42))
        self.assertNotIn(42, self.gh.labels)
        self.assertIsNone(merge_train.load_entry(REPO, 42))


class IntegrateRaceTests(GuardHarness):
    """integrate pushes only for the PR and the entry it was decided for, and records its commit on the
    entry as the lock found it."""

    def test_t1_a_closed_pr_is_not_pushed_to(self):
        self.queue()
        self.advance_main()
        self.arm()
        train = self.train(mutation_lock=self.locked(t1=self.close))
        pushes = self.pushes(train)
        out = train.run()
        self.assertEqual('SKIP', self.only(out)['outcome'], out)
        self.assertEqual([], pushes)
        self.assertEqual(self.reviewed, self.gh.head(42))
        self.assertQuiet()

    def test_t1_the_new_entry_keeps_its_evidence_and_receives_the_train_commit(self):
        self.queue()
        self.advance_main()
        self.arm()
        seen = {}

        def peek(number, poll):
            if poll == 0:
                entry = merge_train.load_entry(REPO, 42)
                seen.update(note=entry['evidence'].get('note'), entry_id=entry['entry_id'],
                            commits=entry['train_commits'])
        self.gh.on_checks = peek
        ids = {}

        def reenqueue():
            ids['old'] = merge_train.load_entry(REPO, 42)['entry_id']
            self.queue(note='fresh review')
            ids['new'] = merge_train.load_entry(REPO, 42)['entry_id']
        train = self.train(mutation_lock=self.locked(t1=reenqueue))
        pushes = self.pushes(train)
        out = train.run()
        self.assertEqual('MERGED', self.only(out)['outcome'], out)
        self.assertEqual(1, len(pushes), 'the refused attempt pushed nothing')
        self.assertEqual({'note': 'fresh review', 'entry_id': ids['new'], 'commits': [self.gh.head(42)]}, seen)
        self.assertNotEqual(ids['old'], ids['new'])


    def test_t1_the_train_commit_is_recorded_on_the_entry_as_the_lock_found_it(self):
        # Same enqueue (same entry id), but the saved entry changed after the train read it.
        self.queue()
        self.advance_main()
        self.arm()
        seen = {}

        def peek(number, poll):
            if poll == 0:
                entry = merge_train.load_entry(REPO, 42)
                seen.update(errors=entry['errors'], last_error=entry.get('last_error'), commits=entry['train_commits'])
        self.gh.on_checks = peek

        def edit_entry():
            entry = merge_train.load_entry(REPO, 42)
            merge_train.save_entry(REPO, 42, dict(entry, errors=1, last_error='earlier run'))
        train = self.train(mutation_lock=self.locked(t1=edit_entry))
        out = train.run()
        self.assertEqual('MERGED', self.only(out)['outcome'], out)
        self.assertEqual({'errors': 1, 'last_error': 'earlier run', 'commits': [self.gh.head(42)]}, seen,
                         'the train commit went onto the entry as saved, not onto the copy read before the lock')


class CiWaitTests(GuardHarness):
    """The CI wait stops at the first poll that shows the PR is no longer one the train may act on."""

    def test_a_pr_that_leaves_while_ci_runs_stops_the_wait_and_is_settled_without_a_comment(self):
        for name, change, outcome, writes in (('withdrawn', self.withdraw, 'DEQUEUED', []),
                                              ('made a Draft', self.draft, 'DEQUEUED', ['label-']),
                                              ('closed', self.close, 'SKIP', [])):
            with self.subTest(change=name):
                self.setUp()
                self.queue()
                self.arm()
                self.gh.checks[42] = [[PENDING], [PENDING], [PENDING], [PASS]]
                self.gh.on_checks = lambda number, poll, change=change: change() if poll == 1 else None
                _, out, _ = self.run_train()
                self.assertEqual(outcome, self.only(out)['outcome'], out)
                self.assertEqual(2, self.gh.polls[42], 'the wait stops at the poll after the change')
                self.assertEqual(writes, self.tail())
                self.assertEqual([], self.comments_since())
                self.assertEqual([], self.merges())
                self.assertIsNone(merge_train.load_entry(REPO, 42))


class WithdrawalRaceTests(GuardHarness):
    """The drop of a saved entry (a withdrawn label, a closed PR) removes the entry that was read, and only it."""

    def test_t1_a_withdrawal_does_not_delete_the_entry_of_the_pr_enqueued_again(self):
        self.queue()
        self.withdraw()                      # withdrawn after the train listed the queue (`order` below)
        self.arm()
        ids = {}

        def reenqueue():
            self.queue(note='fresh review')
            ids['new'] = merge_train.load_entry(REPO, 42)['entry_id']
        lock = self.locked(t1=reenqueue)
        train = self.train(mutation_lock=lock)
        with mock.patch.object(train, 'order', return_value=[42]):
            out = train.run()
        self.assertEqual([1], lock.fired, 'the drop of an entry takes the lock')
        self.assertEqual('MERGED', self.only(out)['outcome'], out)
        self.assertEqual(1, len(self.merges()))
        self.assertNotIn(LEFT_QUEUE, ''.join(self.comments_since()))

    def test_t1_a_closed_pr_that_is_reopened_and_enqueued_again_keeps_the_new_entry(self):
        self.queue()
        self.close()
        self.arm()

        def reopen_and_enqueue():
            self.gh.prs[42]['state'] = 'OPEN'
            self.queue(note='fresh review')
        lock = self.locked(t1=reopen_and_enqueue)
        train = self.train(mutation_lock=lock)
        with mock.patch.object(train, 'order', return_value=[42]):
            out = train.run()
        self.assertEqual([1], lock.fired)
        self.assertEqual('MERGED', self.only(out)['outcome'], out)


class ErrorCountRaceTests(GuardHarness):
    """The error count belongs to the entry the failing run acted on, and a busy lock is never an error."""

    def failing_merge(self):
        self.queue()
        self.gh.merge_unconfirmed.add(42)       # accepted by GitHub, never shown: the PR's own error
        self.arm()

    def test_t1_an_error_is_not_counted_against_an_entry_enqueued_since(self):
        self.failing_merge()
        _, out, lock = self.run_train(self.locked(t2=lambda: self.queue(note='fresh review')))
        self.assertEqual([2], lock.fired, 'merge, then the count')
        self.assertEqual('ERROR', self.only(out)['outcome'], out)
        entry = merge_train.load_entry(REPO, 42)
        self.assertEqual(('fresh review', 0), (entry['evidence'].get('note'), entry['errors']))
        self.assertNotIn('last_error', entry)

    def test_a_busy_lock_while_counting_is_not_counted_either(self):
        self.failing_merge()
        lock = Lock()
        lock.busy_from = 2
        _, out, _ = self.run_train(lock)
        self.assertEqual('ERROR', self.only(out)['outcome'], out)
        self.assertEqual(0, merge_train.load_entry(REPO, 42)['errors'])

    def test_lock_contention_is_a_wait_not_an_error_and_the_count_survives_it(self):
        self.failing_merge()
        self.assertEqual('ERROR', self.run_train()[1]['results'][0]['outcome'])
        self.assertEqual(1, merge_train.load_entry(REPO, 42)['errors'])
        for _ in range(3):
            lock = Lock()
            lock.busy_from = 1
            _, out, _ = self.run_train(lock)
            self.assertEqual('WAITING', self.only(out)['outcome'], out)
        self.assertEqual(1, merge_train.load_entry(REPO, 42)['errors'], 'neither reset nor counted')
        self.assertIn(42, self.gh.labels)
        self.assertEqual([], self.comments_since())


class LockDisciplineTests(GuardHarness):
    """Every write the train makes happens while it holds the mutation lock: the lock is what makes the
    re-read under it mean anything."""

    def watched(self, train, lock):
        bad, seen = [], []

        def spy(name, real):
            def call(*args, **kw):
                seen.append(name)
                if not (lock.held or lock.outside):
                    bad.append(name)
                return real(*args, **kw)
            return call
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for name in ('edit_label', 'post_comment', 'mark_draft', 'merge_pr'):
            stack.enter_context(mock.patch.object(self.gh, name, spy(name, getattr(self.gh, name))))
        for name in ('save_entry', 'drop_entry'):
            stack.enter_context(mock.patch.object(merge_train, name, spy(name, getattr(merge_train, name))))
        real_git = train.git

        def git_spy(*args, **kw):
            if args[0] == 'push':
                spy('push', lambda: None)()
            return real_git(*args, **kw)
        train.git = git_spy
        return bad, seen

    def scenario(self, name):
        if name == 'draft (overlap)':
            self.overlap()
        elif name == 'dequeue (a person must act)':
            self.queue()
            self.gh.prs[42]['review'] = 'CHANGES_REQUESTED'
        elif name == 'dequeue (the HEAD moved)':
            self.queue()
            self.gh.checks[42] = [[PENDING], [PASS]]
            self.gh.on_checks = lambda number, poll: self.push_to_pr() if poll == 0 else None
        elif name == 'integrate and merge':
            self.queue()
            self.advance_main()
        elif name == 'withdrawn':
            self.queue()
            self.withdraw()
        elif name == 'closed':
            self.queue()
            self.close()
        elif name == 'three errors':
            self.queue()
            merge_train.save_entry(REPO, 42, dict(merge_train.load_entry(REPO, 42), errors=2))
            self.gh.merge_unconfirmed.add(42)

    EXPECT = {
        'draft (overlap)': {'post_comment', 'mark_draft', 'edit_label', 'drop_entry'},
        'dequeue (a person must act)': {'post_comment', 'edit_label', 'drop_entry'},
        'dequeue (the HEAD moved)': {'post_comment', 'edit_label', 'drop_entry'},
        'integrate and merge': {'push', 'save_entry', 'merge_pr', 'drop_entry', 'edit_label'},
        'withdrawn': {'drop_entry'},
        'closed': {'drop_entry'},
        'three errors': {'save_entry', 'post_comment', 'edit_label', 'drop_entry'},
    }

    def test_every_write_is_made_under_the_lock(self):
        for name, expected in self.EXPECT.items():
            with self.subTest(scenario=name):
                self.setUp()
                self.scenario(name)
                lock = Lock()
                train = self.train(mutation_lock=lock)
                bad, seen = self.watched(train, lock)
                with mock.patch.object(train, 'order', return_value=[42]):
                    for _ in range(3 if name == 'three errors' else 1):
                        train.run()
                self.assertEqual([], bad, f'written without the lock: {bad}')
                self.assertTrue(expected <= set(seen), f'the scenario must reach {sorted(expected)}, got {sorted(set(seen))}')


class EntryTests(GuardHarness):
    def test_each_enqueue_names_its_entry_and_an_entry_without_a_name_is_not_trusted(self):
        self.queue()
        first = merge_train.load_entry(REPO, 42)['entry_id']
        self.queue()
        second = merge_train.load_entry(REPO, 42)['entry_id']
        self.assertEqual((32, 32), (len(first), len(second)))
        self.assertNotEqual(first, second)
        path = merge_train.entry_path(REPO, 42)
        entry = json.loads(path.read_text())
        del entry['entry_id']
        path.write_text(json.dumps(entry))
        out = self.train().run()
        self.assertEqual('DEQUEUED', out['results'][0]['outcome'], out)
        self.assertIn('no saved review evidence', out['results'][0]['reason'])


# -- the lint -------------------------------------------------------------------------------

CLIENT_WRITES = {'post_comment', 'edit_label', 'mark_draft', 'merge_pr'}
ENTRY_WRITES = {'save_entry', 'drop_entry'}


def guard_violations(source):
    """Every write inside `class Train` that is not lexically inside `with self._guard(...)`, every
    `_guard` nested in another (the lock is not reentrant), and every use of `self._locked()` outside
    `_guard` itself. A function or lambda defined inside a guarded block is not guarded (it may run later).
    The lint is lexical: it knows the spellings the class uses (the four client writes, `save_entry`,
    `drop_entry`, `self.git("push", ...)`); a new write method must be added to CLIENT_WRITES."""
    tree = ast.parse(source)
    train = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Train')
    found = []

    def is_self_call(node, name):
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == name
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 'self')

    def write(node):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in CLIENT_WRITES | ENTRY_WRITES:
            return func.attr
        if isinstance(func, ast.Name) and func.id in ENTRY_WRITES:
            return func.id
        if is_self_call(node, 'git') and node.args and isinstance(node.args[0], ast.Constant) \
                and node.args[0].value == 'push':
            return 'git push'
        return None

    def visit(node, guarded, where):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            guarded, where = False, getattr(node, 'name', where)
        if isinstance(node, ast.With):
            opens = any(is_self_call(item.context_expr, '_guard') for item in node.items)
            if opens and guarded:
                found.append(f'{where}:{node.lineno}: a guard inside a guard')
            for item in node.items:
                visit(item.context_expr, guarded, where)
            for child in node.body:
                visit(child, guarded or opens, where)
            return
        if isinstance(node, ast.Call):
            what = write(node)
            if what and not guarded:
                found.append(f'{where}:{node.lineno}: {what} outside `with self._guard(...)`')
            if is_self_call(node, '_locked') and where != '_guard':
                found.append(f'{where}:{node.lineno}: the lock is taken without the guard')
        for child in ast.iter_child_nodes(node):
            visit(child, guarded, where)

    visit(train, False, 'Train')
    return found


GUARDED = '''
class Train:
    def _guard(self):
        with self._locked():
            pass
    def ok(self):
        with self._guard(1, 2, "x") as held:
            if held:
                self.client.post_comment(1, 2, "x")
                drop_entry(self.repo, 1)
                self.git("push", "origin")
'''
# The write sites of HEAD (0de7e414), which drafted on a stale observation: the lock, then the writes.
HEAD_SHAPE = '''
class Train:
    def to_draft(self):
        with self._locked():
            self.client.post_comment(self.repo, 1, "x")
            self.client.edit_label(self.repo, 1, "q", add=False)
            self.client.mark_draft(self.repo, 1)
        drop_entry(self.repo, 1)
    def label_gone(self):
        drop_entry(self.repo, 1)
'''


class GuardLintTests(unittest.TestCase):
    """Every write in `Train` goes through `_guard`; the lint is proved on the code it must reject."""

    def test_the_train_has_no_write_outside_the_guard(self):
        self.assertEqual([], guard_violations(Path(merge_train.__file__).read_text(encoding='utf-8')))

    def test_the_lint_accepts_the_guarded_shape_and_rejects_head_s(self):
        self.assertEqual([], guard_violations(GUARDED))
        found = guard_violations(HEAD_SHAPE)
        self.assertEqual(6, len(found), found)
        self.assertEqual(['to_draft:4: the lock is taken without the guard'], found[:1])
        self.assertTrue(all('outside `with self._guard' in line for line in found[1:]), found)
        self.assertEqual(['post_comment', 'edit_label', 'mark_draft', 'drop_entry', 'drop_entry'],
                         [line.split(': ')[1].split(' ')[0] for line in found[1:]])

    def test_the_lint_sees_each_kind_of_write_and_each_way_around_the_guard(self):
        cases = {
            'a comment': 'self.client.post_comment(1, 2, "x")',
            'a label': 'self.client.edit_label(1, 2, "q", add=False)',
            'a Draft': 'self.client.mark_draft(1, 2)',
            'a merge': 'self.client.merge_pr(1, 2, "h")',
            'a push': 'self.git("push", "--quiet", "origin", "x")',
            'a saved entry': 'save_entry(self.repo, 1, {})',
            'a dropped entry': 'merge_train.drop_entry(self.repo, 1)',
        }
        for name, write in cases.items():
            with self.subTest(write=name):
                self.assertEqual(1, len(guard_violations(f'class Train:\n    def f(self):\n        {write}\n')))
                self.assertEqual([], guard_violations(
                    f'class Train:\n    def f(self):\n        with self._guard(1, 2, "x") as held:\n            {write}\n'))
                # After the block, in a helper called from it, or in a closure defined inside it: not guarded.
                self.assertEqual(1, len(guard_violations(
                    'class Train:\n    def f(self):\n        with self._guard(1, 2, "x") as held:\n            pass\n'
                    f'        {write}\n')))
                self.assertEqual(1, len(guard_violations(
                    'class Train:\n    def f(self):\n        with self._guard(1, 2, "x") as held:\n'
                    f'            later = lambda: {write}\n')))
                self.assertEqual(1, len(guard_violations(
                    'class Train:\n    def f(self):\n        with self._guard(1, 2, "x") as held:\n'
                    f'            def later():\n                {write}\n')))
        self.assertEqual([], guard_violations(
            'class Train:\n    def f(self):\n        self.git("fetch", "origin")\n        self.client.pr_view(1, 2)\n'))

    def test_the_lint_rejects_a_second_lock_and_a_lock_taken_without_the_guard(self):
        nested = ('class Train:\n    def f(self):\n        with self._guard(1, 2, "a") as held:\n'
                  '            with self._guard(1, 2, "b") as again:\n                pass\n')
        self.assertEqual(['f:4: a guard inside a guard'], guard_violations(nested))
        bare = 'class Train:\n    def f(self):\n        with self._locked():\n            pass\n'
        self.assertEqual(['f:3: the lock is taken without the guard'], guard_violations(bare))


if __name__ == '__main__':
    unittest.main()
