"""The consumers' side of the Ready signal: `review_gate.ready_signal_gate` and the actor that calls it.

A Ready PR says "quality is already mergeable", and only pr-ready's gate and issue-to-pr's mark_ready.py check
that claim before they sign the PR (`_shared/scripts/ready_signal.py`). The actor acts on a Ready PR only when
the signal is valid, writes NOTHING to one that has none, and lets a signal bound to an earlier HEAD carry when
`review_covers` says the new HEAD covers it: a pure import of the base (what the merge train's integration commit
is) or a delta that touches only the base manifest's `evidence_only_paths`; a push that changes any other file of
the PR's own commits does not carry.

The GitHub side is the real-Git fake of test_merge_train.py (a bare `origin`, the developer's pushes, the train's
own integration commit), so the relation under which a signal carries is the real `review_covers` on real commits;
the signal's state is the shared `ready_signal_world` model. Every refusal test asserts the reason it was refused
for and, for the actor, the recorded writes: none. Each is paired with a passing control (AGENTS.md 5.12).
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'scripts'))
import apply_decision  # noqa: E402
import merge_train  # noqa: E402
import review_gate  # noqa: E402
from gh_runtime import GitHubError  # noqa: E402
from scan_stub import CleanScan  # noqa: E402
from signal_cases import LABEL, OTHER, RECOVERY, VIEWER, Worlds  # noqa: E402
from test_merge_train import MANIFEST, PENDING, REPO, DeliveryTests, git, rw  # noqa: E402
from test_merge_train_infra import ActorHarness  # noqa: E402
import ready_signal  # noqa: E402

setUpModule, tearDownModule = CleanScan.up, CleanScan.down

class GateTests(DeliveryTests):
    """`review_gate.ready_signal_gate` over real Git."""

    def judged(self, head=None):
        """What `evaluate` returns for a PR it would let through, at `head` (the PR's HEAD by default)."""
        return {'decision': 'MERGE', 'head_sha': head or self.gh.head(42), 'base_sha': self.fork,
                'live_base_sha': self.gh.branch_head(REPO, 'main'), 'base_name': 'main',
                'reasons': ['Independent review, tests, CI, comments, dependencies and merge rules clear']}

    def ask(self, gate=None, view=None):
        gate = self.judged() if gate is None else gate
        return gate, review_gate.ready_signal_gate(self.gh, REPO, 42, gate, view)

    def refused(self, gate=None, view=None):
        """`ask`, for a PR the gate must refuse: the refusal is asserted to be one before it is read."""
        gate, refusal = self.ask(gate, view)
        self.assertIsInstance(refusal, str, 'the signal gate must refuse this PR')
        return gate, refusal

    def test_a_valid_signal_passes_and_the_gate_is_left_as_it_was(self):
        # The producers are spelled out: a consumer that treats one of them differently (the hand-made `maintainer`
        # signal of a PR that predates the check included) must fail here, whatever PRODUCERS says.
        for producer in ('pr-ready', 'issue-to-pr', 'maintainer'):
            with self.subTest(producer):
                self.setUp()
                self.sign(producer=producer)
                gate, refusal = self.ask()
                self.assertIsNone(refusal)
                self.assertEqual(('MERGE', ['Independent review, tests, CI, comments, dependencies and merge rules clear']),
                                 (gate['decision'], gate['reasons']))
                self.assertEqual(('valid', self.reviewed, producer),
                                 tuple(gate['ready_signal'][k] for k in ('state', 'marker_head', 'producer')))
                self.assertNotIn('carried', gate['ready_signal'])
                self.assertNotIn('underlying', gate)
                self.assertEqual([], self.gh.writes)

    def test_it_reads_the_pr_the_account_and_one_timeline(self):
        self.sign()
        gate = self.judged()
        before = len(self.gh.calls)
        self.ask(gate)
        self.assertEqual(['pr_view', 'timeline_events', 'viewer_login'], sorted(self.gh.calls[before:]))

    def test_every_state_without_a_valid_signal_is_a_refusal_that_names_why_and_the_way_back(self):
        for name, (builder, state, fragment) in Worlds.CASES.items():
            with self.subTest(name):
                self.setUp()
                world = getattr(Worlds, builder)(self.reviewed)
                self.gh.signals[42] = world
                expected = ready_signal.assess(self.reviewed, world.view_labels(), world.s['events'], VIEWER)
                self.assertEqual(state, expected.state)           # the oracle is what the shared module says
                gate, refusal = self.refused()
                self.assertIn(f'{state}: {expected.reason}', refusal)
                self.assertIn(fragment, refusal)
                for needle in (*RECOVERY, LABEL, self.reviewed[:12], 'Nothing was changed'):
                    self.assertIn(needle, refusal)
                self.assertEqual(('WAITING', 'transient', False, [refusal]),
                                 (gate['decision'], gate['wait_kind'], gate['person_handoff'], gate['reasons']))
                self.assertEqual(('MERGE', ['Independent review, tests, CI, comments, dependencies and merge rules clear']),
                                 (gate['underlying']['decision'], gate['underlying']['reasons']))
                self.assertEqual(state, gate['ready_signal']['state'])
                self.assertEqual([], self.gh.writes, 'the gate reads, it never writes')

    def test_a_label_the_view_shows_but_the_timeline_does_not_is_inconsistent(self):
        # GitHub's read lag: the PR view is ahead of the timeline. The control below shows the same PR with the
        # label in both places passes.
        world = Worlds.world(self.reviewed)
        world.ready()
        world.comment(ready_signal.marker_comment(self.reviewed, ready_signal.PR_READY))
        self.gh.signals[42] = world
        shown = dict(self.gh.pr_view(REPO, 42), labels=[{'name': LABEL}])
        gate, refusal = self.refused(view=shown)
        self.assertIn('inconsistent: the PR shows the', refusal)
        self.assertIn('its timeline has no event for it', refusal)
        world.label()
        gate, refusal = self.ask(view=dict(shown))
        self.assertIsNone(refusal)

    def test_a_view_the_caller_holds_is_used_and_without_one_the_pr_is_read(self):
        self.sign()
        view = self.gh.pr_view(REPO, 42)
        reads = self.gh.counts['pr_view']
        self.assertIsNone(self.ask(view=view)[1])
        self.assertEqual(reads, self.gh.counts['pr_view'], 'the held view is the one that is judged')
        self.assertIsNone(self.ask()[1])
        self.assertEqual(reads + 1, self.gh.counts['pr_view'])
        gate, refusal = self.refused(view=dict(view, labels=[]))      # the signal is there, the view says no label
        self.assertEqual('absent', gate['ready_signal']['state'])
        self.assertIn(f'does not carry the {LABEL} label', refusal)

    # -- a signal for an earlier HEAD ---------------------------------------------------------------------
    def test_the_authors_merge_of_the_base_carries_the_signal(self):
        self.sign()
        live = self.advance_main()
        head = self.merge_main()
        self.assertEqual(f'{self.reviewed} {live}', git(self.origin, 'log', '-1', '--format=%P', head))
        gate, refusal = self.ask()
        self.assertIsNone(refusal)
        self.assertEqual(('stale', self.reviewed, 'pure-base-import'),
                         tuple(gate['ready_signal'].get(k) for k in ('state', 'marker_head', 'carried')))
        self.assertEqual('MERGE', gate['decision'])
        self.assertEqual([], self.gh.writes)

    def test_the_trains_own_integration_commit_carries_the_signal(self):
        # The case the carry exists for: the train integrates the live base into a queued PR and a later step
        # leaves the PR Ready at the integration commit, which no marker names.
        self.sign()
        self.queue()
        live = self.advance_main()
        self.gh.checks[42] = [[PENDING]]
        out = self.train(ci_timeout=5).run()
        self.assertEqual(['WAITING'], [r['outcome'] for r in out['results']], out)
        head = self.gh.head(42)
        self.assertEqual(f'{self.reviewed} {live}', git(self.origin, 'log', '-1', '--format=%P', head), 'the train pushed it')
        gate, refusal = self.ask()
        self.assertIsNone(refusal)
        self.assertEqual(('stale', 'pure-base-import'), (gate['ready_signal']['state'], gate['ready_signal']['carried']))

    def test_a_push_that_changes_the_prs_own_commits_is_not_carried(self):
        self.sign()
        head = self.push_to_pr()
        gate, refusal = self.refused()
        self.assertIn(f'the signal was written for HEAD {self.reviewed[:12]}, the PR HEAD is {head[:12]}', refusal)
        self.assertIn('the PR changed since in more than a base import', refusal)
        for needle in (*RECOVERY, 'Nothing was changed'):
            self.assertIn(needle, refusal)
        self.assertEqual(('WAITING', 'transient', False), (gate['decision'], gate['wait_kind'], gate['person_handoff']))
        self.assertEqual('stale', gate['ready_signal']['state'])
        self.assertNotIn('carried', gate['ready_signal'])
        # Control: signed again at that HEAD (Draft, pr-ready, Ready) it passes.
        self.setUp()
        self.push_to_pr()
        self.sign(self.gh.head(42))
        self.assertIsNone(self.ask()[1])

    def test_a_push_that_touches_only_evidence_only_paths_is_carried_and_a_code_push_on_top_is_not(self):
        # `review_covers` accepts a second kind of delta besides a pure import of the base: every file changed
        # since is one of the base manifest's `evidence_only_paths` (here `docs/evidence/**`). It is the one coverage
        # with no `method` in its record, so the gate says `carried: evidence-only`. Nothing else in this workflow
        # resets a receipt, a review or target evidence over such a delta either (AGENTS.md 1.5).
        self.gh.manifest = MANIFEST
        self.sign()
        evidence = self.push_to_pr('docs/evidence/feat/x.md', 'a sanitized record\n')
        gate, refusal = self.ask()
        self.assertIsNone(refusal)
        self.assertEqual(('stale', self.reviewed, 'evidence-only'),
                         tuple(gate['ready_signal'].get(k) for k in ('state', 'marker_head', 'carried')))
        self.assertEqual('MERGE', gate['decision'])
        self.assertNotIn('underlying', gate)
        self.assertEqual([], self.gh.writes)
        # Trigger: the same PR with a code push on top. The delta since the signed HEAD now holds a file outside
        # `evidence_only_paths`, and the PR is refused for that file only.
        code = self.push_to_pr('pkg/z.go', 'package z\n')
        gate, refusal = self.refused()
        self.assertIn(f'the signal was written for HEAD {self.reviewed[:12]}, the PR HEAD is {code[:12]}', refusal)
        self.assertIn('the PR changed since in more than a base import', refusal)
        self.assertIn('pkg/z.go', refusal)
        self.assertNotIn('docs/evidence/feat/x.md', refusal)
        for needle in (*RECOVERY, 'Nothing was changed'):
            self.assertIn(needle, refusal)
        self.assertEqual(('WAITING', 'transient', False), (gate['decision'], gate['wait_kind'], gate['person_handoff']))
        self.assertEqual('stale', gate['ready_signal']['state'])
        self.assertNotIn('carried', gate['ready_signal'])
        self.assertEqual([], self.gh.writes)
        # The same two files in ONE commit are refused too: the delta is judged file by file, not commit by commit.
        self.setUp()
        self.gh.manifest = MANIFEST
        self.sign()
        self.write('docs/evidence/feat/x.md', 'a sanitized record\n')
        self.push_to_pr('pkg/z.go', 'package z\n')
        self.assertIn('pkg/z.go', self.refused()[1])
        # Control: the manifest is what decides. Without `evidence_only_paths` the same evidence file is a change
        # to the PR's own commits like any other.
        self.setUp()
        self.sign()
        self.push_to_pr('docs/evidence/feat/x.md', 'a sanitized record\n')
        gate, refusal = self.refused()
        self.assertIn('no evidence_only_paths declared on the base branch', refusal)
        self.assertNotIn('carried', gate['ready_signal'])

    def test_a_merge_that_drops_the_bases_change_is_not_carried(self):
        # `review_covers` is reused as it is: it also refuses a merge of the base that keeps the PR's side.
        self.sign()
        self.advance_main('docs/x.md')
        self.merge_main_keeping_ours()
        gate, refusal = self.refused()
        self.assertIn('base change not carried into HEAD: docs/x.md', refusal)
        self.assertEqual('WAITING', gate['decision'])

    def test_a_stale_signal_cannot_carry_without_a_live_base(self):
        self.sign()
        self.advance_main()
        self.merge_main()
        gate = self.judged()
        del gate['live_base_sha']
        gate, refusal = self.refused(gate)
        self.assertIn('the gate has no live base to show that the new HEAD covers it', refusal)

    def test_only_a_stale_signal_is_ever_carried(self):
        # The same pure import, but the signal is of an earlier epoch or by another account: nothing carries it.
        for name in ('label by another account', 'earlier Ready epoch', 'marker by another account'):
            with self.subTest(name):
                self.setUp()
                self.gh.signals[42] = getattr(Worlds, Worlds.CASES[name][0])(self.reviewed)
                self.advance_main()
                self.merge_main()
                before = list(self.gh.calls)
                gate, refusal = self.ask()
                self.assertEqual(Worlds.CASES[name][1], gate['ready_signal']['state'])
                self.assertIsNotNone(refusal)
                self.assertEqual([], [c for c in self.gh.calls[len(before):] if c in ('compare', 'merge_base', 'file_at')],
                                 'review_covers is asked only about a stale signal')

    # -- fail closed ----------------------------------------------------------------------------------------
    def test_a_read_that_fails_is_a_transient_refusal_that_says_to_run_again(self):
        for call in ('pr_view', 'viewer_login', 'timeline_events'):
            with self.subTest(call):
                self.setUp()
                self.sign()
                self.gh.failing[call] = GitHubError(f'gh {call} failed (1): HTTP 502')
                gate, refusal = self.refused(self.judged())
                self.assertIn('Unable to verify the Ready signal', refusal)
                self.assertIn(f'gh {call} failed', refusal)
                self.assertIn('run again', refusal)
                self.assertNotIn('Draft', refusal, 'nothing is known about the signal: no recovery through Draft')
                self.assertEqual(('WAITING', 'transient', False), (gate['decision'], gate['wait_kind'], gate['person_handoff']))

    def test_a_failure_while_asking_whether_the_head_is_covered_is_a_refusal_too(self):
        for call in ('merge_base', 'file_at', 'tree_entries'):
            with self.subTest(call):
                self.setUp()
                self.sign()
                self.advance_main()
                self.merge_main()
                self.gh.failing[call] = GitHubError(f'gh {call} failed (1): HTTP 502')
                gate, refusal = self.refused()
                self.assertIn('Unable to verify the Ready signal', refusal)
                self.assertIn(f'gh {call} failed', refusal)
                self.assertEqual('transient', gate['wait_kind'])

    def test_a_timeline_entry_of_an_unexpected_shape_is_a_refusal_not_a_crash(self):
        world = self.sign()
        world.s['events'].append({'event': 'commented', 'user': 'not an object', 'body': 'a comment'})
        gate, refusal = self.refused()
        self.assertIn('Unable to verify the Ready signal', refusal)
        self.assertIn('has a malformed user', refusal)
        self.assertEqual('transient', gate['wait_kind'])

    def test_a_head_that_moved_since_the_gate_is_refused_before_the_signal_is_read(self):
        self.sign()
        gate = self.judged()
        moved = self.push_to_pr()
        before = len(self.gh.calls)
        gate, refusal = self.refused(gate)
        self.assertIn(f'the PR HEAD changed from {self.reviewed[:12]} to {moved[:12]} after the gate judged it', refusal)
        self.assertIn('run again', refusal)
        self.assertEqual(['pr_view'], self.gh.calls[before:], 'the signal is not read for a PR that is not the one judged')

    def test_what_to_do_comes_before_why_because_the_pr_loop_keeps_the_first_600_characters(self):
        # pr_loop_result.write_result cuts a reason to 600 characters, and what the pr-loop shows its user is that
        # reason: the way back must be inside it however long the why is (a stale signal's reason lists the
        # paths that changed, a read failure carries GitHub's error text, up to 500 characters).
        keep, seen = 600, []
        for name, (builder, _, _) in Worlds.CASES.items():
            self.setUp()
            self.gh.signals[42] = getattr(Worlds, builder)(self.reviewed)
            seen.append((name, self.refused()[1], RECOVERY[0]))
        self.setUp()
        self.sign()
        self.push_to_pr()
        seen.append(('a push that changes the PR', self.refused()[1], RECOVERY[0]))
        self.setUp()
        self.sign()
        self.gh.failing['timeline_events'] = GitHubError('gh api repos/acme/demo/issues/42/timeline failed (1): ' + 'HTTP 502 ' * 60)
        seen.append(('a long read failure', self.refused(self.judged())[1], 'run again'))
        for name, refusal, way_back in seen:
            with self.subTest(name):
                self.assertIn(way_back, refusal[:keep])
                self.assertIn('nothing was changed', refusal[:keep].lower())
        self.assertGreater(len(seen[-1][1]), keep, 'premise: the why of this one is longer than what the pr-loop keeps')

    def test_the_gate_the_train_runs_reads_no_signal(self):
        # `evaluate` is the gate of the merge train's own integration commits: it must not ask for a signal
        # (nothing signed this PR here: the control for a PR queued before the signal existed).
        gate = review_gate.evaluate(REPO, 42, self.evidence(), client=self.gh, worktree=self.consumer)
        self.assertEqual('MERGE', gate['decision'], gate['reasons'])
        self.assertEqual([], [c for c in self.gh.calls if c in ('timeline_events', 'viewer_login')])
        self.assertNotIn('ready_signal', gate)


class ActorTests(ActorHarness):
    """The real actor (`apply_decision.perform`, the real gate) against the same fake."""

    def setUp(self):
        super().setUp()   # ActorHarness signs the PR at its reviewed HEAD
        for name, fake in (('post_comment', self.gh.post_comment), ('issue_comments', lambda repo, number: []),
                           ('viewer_login', lambda repo: VIEWER)):
            patch = mock.patch.object(apply_decision, name, fake)   # the needs-person hand-off's own calls
            patch.start()
            self.addCleanup(patch.stop)

    def dry_run(self, evidence=None):
        return apply_decision.perform(REPO, 42, evidence or self.evidence(), 'merge', False,
                                      worktree=self.consumer, sleep=self.sleep)

    def assertUntouched(self, out):
        """The recorded writes are none: nothing on GitHub, nothing saved for the train."""
        self.assertEqual([], self.gh.writes)
        self.assertEqual([], self.runs, 'no `gh pr comment` / `gh pr ready --undo`')
        self.assertEqual([], self.gh.comments)
        self.assertEqual({}, self.gh.labels)
        self.assertIsNone(merge_train.load_entry(REPO, 42))
        self.assertFalse(out['executed'])
        self.assertIsNone(out['verified_remote_state'])
        for key in ('handoff', 'comment_posted', 'enqueued', 'warnings', 'error'):
            self.assertNotIn(key, out)

    def test_a_signalled_pr_is_enqueued_and_the_signal_is_read_before_the_writes(self):
        out = self.act()
        self.assertEqual('ENQUEUED', out['outcome'], out)
        self.assertEqual(2, self.gh.calls.count('timeline_events'),
                         'once after the gate, once on the view taken right before the action')
        self.assertEqual(('valid', self.reviewed, 'pr-ready'),
                         tuple(out['gate']['ready_signal'][k] for k in ('state', 'marker_head', 'producer')))
        self.assertIn(LABEL, [label['name'] for label in self.gh.pr_view(REPO, 42)['labels']],
                      'the label stays: the merge train owns the PR now, and it needs no signal')

    def refused(self, out, fragment, underlying):
        self.assertEqual(('WAITING', 'transient', False), (out['outcome'], out.get('wait_kind'), out['gate'].get('person_handoff')))
        refusal = out['gate']['reasons'][0]
        self.assertEqual([refusal], out['gate']['reasons'])
        self.assertIn(fragment, refusal)
        for needle in RECOVERY:
            self.assertIn(needle, refusal)
        self.assertEqual(underlying, out['gate'].get('underlying', {}).get('decision'))
        self.assertUntouched(out)

    def test_a_pr_without_a_valid_signal_is_not_queued_and_nothing_is_written(self):
        for name, (builder, state, fragment) in Worlds.CASES.items():
            with self.subTest(signal=name):
                self.setUp()
                self.gh.signals[42] = getattr(Worlds, builder)(self.reviewed)
                self.refused(self.act(), fragment, 'MERGE')

    def test_a_pr_without_a_valid_signal_is_not_drafted_commented_or_handed_off_either(self):
        # The gate's other decisions: the Draft conversion and its comment, the needs-person comment and label
        # and the label release are all writes, and a PR nobody verified gets none of them.
        decisions = {
            'DRAFT': (lambda: None, self.blocked_evidence, 'DRAFT'),
            'WAITING for a person': (lambda: self.gh.prs[42].update(review='CHANGES_REQUESTED'), self.evidence, 'WAITING'),
            'WAITING for CI': (lambda: self.gh.checks.update({42: [[PENDING]]}), self.evidence, 'WAITING'),
        }
        for decision, (arrange, evidence, underlying) in decisions.items():
            with self.subTest(decision):
                self.setUp()
                arrange()
                self.gh.signals[42] = Worlds.never_signed(self.reviewed)
                self.refused(self.act(evidence()), f'does not carry the {LABEL} label', underlying)

    def test_the_same_decisions_on_a_signalled_pr_are_acted_on(self):
        # The controls of the two tests above: with the signal, the Draft is made and the hand-off is written.
        out = self.act(self.blocked_evidence())
        self.assertEqual(('DRAFT-BLOCKED', True), (out['outcome'], out['executed']))
        self.setUp()
        self.gh.prs[42].update(review='CHANGES_REQUESTED')
        out = self.act()
        self.assertEqual(('WAITING', 'person', True), (out['outcome'], out['wait_kind'], out['gate']['person_handoff']))
        self.assertEqual([('comment', 42), ('label+', 42)], self.gh.writes, 'the hand-off: its comment, then its label')

    def test_a_dry_run_reports_the_refusal_not_the_decision_it_would_have_made(self):
        self.assertEqual('DRY_RUN_MERGE', self.dry_run()['outcome'], 'control: a signalled PR')
        self.setUp()
        self.gh.signals[42] = Worlds.never_signed(self.reviewed)
        out = self.dry_run()
        self.assertEqual(('WAITING', 'transient'), (out['outcome'], out.get('wait_kind')))
        self.assertIn(f'does not carry the {LABEL} label', out['gate']['reasons'][0])
        self.assertUntouched(out)

    def test_the_authors_merge_of_the_base_carries_the_signal_to_the_queue(self):
        live = self.advance_main()
        head = self.merge_main()
        out = self.act()                       # the review names the earlier HEAD; the gate covers it by the import
        self.assertEqual('ENQUEUED', out['outcome'], out)
        self.assertEqual(('stale', 'pure-base-import'),
                         (out['gate']['ready_signal']['state'], out['gate']['ready_signal'].get('carried')))
        self.assertEqual(head, merge_train.load_entry(REPO, 42)['enqueued_head'])
        self.assertEqual(live, self.gh.branch_head(REPO, 'main'))

    def test_a_push_after_the_signal_is_not_carried_even_when_the_new_head_was_reviewed(self):
        head = self.push_to_pr()
        out = self.act(self.evidence(head))    # a fresh independent review of the new HEAD: the gate says MERGE
        self.assertEqual('WAITING', out['outcome'])
        self.assertEqual('MERGE', out['gate'].get('underlying', {}).get('decision'), 'only the signal stands in the way')
        self.assertIn(f'the signal was written for HEAD {self.reviewed[:12]}, the PR HEAD is {head[:12]}',
                      out['gate']['reasons'][0])
        self.assertIn('more than a base import', out['gate']['reasons'][0])
        self.assertUntouched(out)
        # Control: the PR goes through Draft and is signed again at that HEAD: it is queued.
        world = self.gh.signal(42)
        world.to_draft()
        world.ready()
        world.signal(head)
        out = self.act(self.evidence(head))
        self.assertEqual('ENQUEUED', out['outcome'], out)

    # -- the signal is read again right before the action ----------------------------------------------------
    def at_view(self, number, action):
        """Run `action` as the `number`-th `pr view` is read: GitHub changes between two reads."""
        real = self.gh.outage

        def outage(name):
            real(name)
            if name == 'pr_view' and self.gh.counts['pr_view'] == number:
                action()
        self.gh.outage = outage

    def test_a_label_removed_after_the_first_look_stops_the_action(self):
        # Reads: the gate's two views, the first look (3rd), the view before the action (4th).
        self.at_view(4, lambda: self.gh.signal(42).label(OTHER, add=False))
        out = self.act()
        self.assertEqual(('WAITING', 'transient'), (out['outcome'], out.get('wait_kind')))
        self.assertIn(f'does not carry the {LABEL} label', out['gate']['reasons'][0])
        self.assertEqual(2, self.gh.calls.count('timeline_events'), 'the refusal is the second look')
        self.assertUntouched(out)

    def test_a_new_ready_round_after_the_first_look_stops_the_action(self):
        def drafted_and_ready_again():
            self.gh.signal(42).to_draft()
            self.gh.signal(42).ready()
        self.at_view(4, drafted_and_ready_again)
        out = self.act()
        self.assertEqual('WAITING', out['outcome'])
        self.assertIn('stale-epoch', out['gate']['reasons'][0])
        self.assertUntouched(out)

    def test_a_head_that_moves_before_the_first_look_waits_without_a_write(self):
        self.at_view(3, self.push_to_pr)
        out = self.act()
        self.assertEqual(('WAITING', 'transient'), (out['outcome'], out.get('wait_kind')))
        self.assertIn('after the gate judged it', out['gate']['reasons'][0])
        self.assertIn('run again', out['gate']['reasons'][0])
        self.assertUntouched(out)

    # -- the Draft path takes the label off, after the Draft is confirmed ---------------------------------------
    def labels(self):
        return [label['name'] for label in self.gh.pr_view(REPO, 42)['labels']]

    def test_a_draft_takes_the_ready_label_off_after_the_comment_and_the_draft(self):
        out = self.act(self.blocked_evidence())
        self.assertEqual(('DRAFT-BLOCKED', True, 'released'), (out['outcome'], out['executed'], out.get('ready_label')))
        self.assertEqual([('comment', 42), ('draft', 42), ('ready-label-', 42)], self.gh.writes)
        self.assertNotIn(LABEL, self.labels())
        self.assertNotIn('warnings', out)

    def test_the_label_goes_only_after_the_draft_was_read_back(self):
        self.gh.lag['draft'] = 3               # the PR shows the Draft only at the 4th read after the conversion
        out = self.act(self.blocked_evidence())
        self.assertEqual('DRAFT-BLOCKED', out['outcome'], out)
        self.assertEqual([apply_decision.READ_INTERVAL] * 3, self.sleeps)
        after_the_conversion = [c for c in self.gh.calls[self.gh.calls.index('mark_draft'):]
                                if c in ('mark_draft', 'pr_view', 'edit_label')]
        self.assertEqual(['mark_draft', 'pr_view', 'pr_view', 'pr_view', 'pr_view', 'edit_label'], after_the_conversion,
                         'the three stale reads and the one that showed the Draft come before the removal')
        self.assertNotIn(LABEL, self.labels())

    def test_a_draft_that_is_never_confirmed_keeps_the_label(self):
        self.gh.lag['draft'] = 10 ** 6
        out = self.act(self.blocked_evidence())
        self.assertEqual('ERROR', out['outcome'])
        self.assertIn('Draft state was not confirmed', out['error'])
        self.assertEqual([('comment', 42), ('draft', 42)], self.gh.writes, 'no label write: the PR is not known to be a Draft')
        self.assertIn(LABEL, self.labels())

    def test_a_label_that_cannot_be_removed_is_a_warning_and_not_retried(self):
        self.gh.failing_labels[LABEL] = GitHubError('gh pr edit failed (1): HTTP 502')
        out = self.act(self.blocked_evidence())
        self.assertEqual(('DRAFT-BLOCKED', True), (out['outcome'], out['executed']))
        self.assertNotIn('error', out)
        self.assertEqual(1, len(out.get('warnings', [])), out)
        for needle in (f'The `{LABEL}` label could not be removed', 'HTTP 502', 'pr-ready removes it before'):
            self.assertIn(needle, out['warnings'][0])
        self.assertNotIn('ready_label', out)
        self.assertEqual(1, self.gh.counts['edit_label'], 'one attempt')
        self.assertIn(LABEL, self.labels())

    def test_enqueueing_leaves_the_ready_label_alone(self):
        out = self.act()
        self.assertEqual('ENQUEUED', out['outcome'])
        self.assertEqual([('label+', 42), ('comment', 42)], self.gh.writes)


if __name__ == '__main__':
    unittest.main()
