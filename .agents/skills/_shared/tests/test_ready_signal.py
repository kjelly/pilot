"""The pr-ready-verified signal (`_shared/scripts/ready_signal.py`): every state of `assess` with a pass and a
trigger case that asserts the REASON (AGENTS.md 5.12), the marker's strictness, the render -> assess round trip
(5.7), the real timeline capture of kjelly/pilot#419 (5.6), `prepare` and `write` over a recording client (order,
bound, errors), and the guard that keeps the two literals in one file.

Events are built by `ready_signal_world.World` in the shapes of the reduced real captures; nothing here reaches
GitHub and no test sleeps (`sleep` is injected).
"""
from __future__ import annotations

import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ready_signal_world as rw  # noqa: E402  (puts _shared/scripts on sys.path)
import ready_signal as rs  # noqa: E402

SKILLS = HERE.parents[1]
REPO_ROOT = SKILLS.parents[1]
H = "a" * 40
OLD = "b" * 40
VIEWER, OTHER = rw.VIEWER, rw.OTHER


def signed(head=H, producer=rs.PR_READY, **kw):
    """A Draft made Ready and signed by the viewer at `head` (the PR's HEAD is `head`)."""
    world = rw.World(head=head, **kw)
    world.signed_ready(producer=producer)
    return world


def assess(world, head=None, viewer=VIEWER):
    return rs.assess(head or world.s["head"], world.view_labels(), world.s["events"], viewer)


class MarkerTests(unittest.TestCase):
    def test_the_producers_are_these_three(self):
        self.assertEqual(("pr-ready", "issue-to-pr", "maintainer"), rs.PRODUCERS)
        self.assertEqual("pr-ready-verified", rs.LABEL)

    def test_every_producer_renders_a_marker_the_regex_reads_back(self):
        for producer in rs.PRODUCERS:
            with self.subTest(producer):
                line = rs.marker_line(H, producer)
                self.assertEqual(f"<!-- pr-ready:verified head={H} by={producer} -->", line)
                self.assertEqual([(H, producer)], rs.MARKER.findall(line))
                self.assertEqual([(H, producer)], rs.MARKER.findall(rs.marker_comment(H, producer)))

    def test_the_renderer_writes_the_head_lowercase_so_the_regex_reads_it_back(self):
        for producer in rs.PRODUCERS:
            self.assertEqual(rs.marker_line(H, producer), rs.marker_line(H.upper(), producer))
            self.assertEqual([(H, producer)], rs.MARKER.findall(rs.marker_comment(H.upper(), producer)))
        with self.assertRaises(rs.SignalError):
            rs.marker_comment("main", rs.PR_READY)

    def test_an_unknown_producer_is_refused_by_the_renderer_and_the_regex(self):
        for producer in ("pr-reviewer", "PR-READY", "", "pr-ready ", "maintainers", None):
            with self.subTest(producer=producer):
                with self.assertRaises(ValueError):
                    rs.marker_comment(H, producer)
                with self.assertRaises(ValueError):
                    rs.marker_line(H, producer)
        self.assertIsNone(rs.MARKER.search(f"<!-- pr-ready:verified head={H} by=pr-reviewer -->"))

    def test_the_regex_is_strict(self):
        good = f"<!-- pr-ready:verified head={H} by=pr-ready -->"
        self.assertTrue(rs.MARKER.search(good))
        near_misses = {
            "uppercase hex": good.replace(H, "A" * 40),
            "39 hex digits": good.replace(H, "a" * 39),
            "41 hex digits": good.replace(H, "a" * 41),
            "non-hex": good.replace(H, "g" * 40),
            "no head": good.replace(f"head={H} ", ""),
            "other producer": good.replace("by=pr-ready", "by=someone"),
            "no producer": good.replace(" by=pr-ready", ""),
            "producer prefix only": good.replace("by=pr-ready", "by=pr"),
            "double space": good.replace("head=", " head="),
            "other word": good.replace("verified", "approved"),
            "other tool": good.replace("pr-ready:verified", "pr-review-merge:needs-person"),
            "unterminated": good[:-4],
            "plain text": f"head={H} by=pr-ready",
        }
        for name, text in near_misses.items():
            with self.subTest(name):
                self.assertIsNone(rs.MARKER.search(text), text)

    def test_the_comment_tells_a_person_what_the_signal_is_and_ends_with_the_marker(self):
        text = rs.marker_comment(H, rs.ISSUE_TO_PR)
        self.assertTrue(text.endswith(rs.marker_line(H, rs.ISSUE_TO_PR) + "\n"))
        self.assertEqual(1, len(rs.MARKER.findall(text)), "the explanation must not contain a second marker")
        for needle in (f"`{H}`", "`issue-to-pr`", f"`{rs.LABEL}`", "stale", "Draft", "not a human approval"):
            self.assertIn(needle, text)

    def test_the_comment_round_trips_through_assess(self):
        # 5.7: the renderer and the reader are two places; both meet in a signal that reads back as valid.
        for producer in rs.PRODUCERS:
            with self.subTest(producer):
                world = rw.World(head=H)
                world.ready()
                world.comment(rs.marker_comment(H, producer))
                world.label()
                result = assess(world)
                self.assertEqual(("valid", H, producer), (result.state, result.marker_head, result.producer))


class AssessTests(unittest.TestCase):
    def check(self, result, state, reason=None, *, marker=None, producer=None):
        self.assertEqual(state, result.state, result.reason)
        if reason is not None:
            self.assertEqual(reason, result.reason)
        self.assertEqual((marker, producer), (result.marker_head, result.producer))
        self.assertEqual(state == "valid", result.valid)

    # -- valid ----------------------------------------------------------------------------------------------
    def test_a_producers_signal_is_valid(self):
        for producer in rs.PRODUCERS:
            with self.subTest(producer):
                result = assess(signed(producer=producer))
                self.check(result, "valid", f"pr-ready-verified was added by {VIEWER} after the last Ready transition "
                                            f"and the signal comment names HEAD {H[:12]}", marker=H, producer=producer)
                self.assertEqual(H, result.head)

    def test_a_label_removed_and_added_again_after_the_ready_transition_is_valid(self):
        # The control of test_the_labels_last_event_being_a_removal_is_inconsistent.
        world = signed()
        world.label(add=False)
        world.label()
        self.check(assess(world), "valid", marker=H, producer=rs.PR_READY)

    # -- absent -------------------------------------------------------------------------------------------
    def test_a_pr_that_was_never_a_draft_is_absent_whatever_it_carries(self):
        world = rw.World()
        world.signal()  # a label and a marker, but no ready_for_review event (created Ready, or events lost)
        self.check(assess(world), "absent", "no Ready transition from Draft on the PR's timeline")
        self.check(rs.assess(H, [], [], VIEWER), "absent", "no Ready transition from Draft on the PR's timeline")

    def test_label_missing(self):
        # The view has no label: absent, although the timeline carries a complete signal.
        world = signed()
        self.check(rs.assess(H, [], world.s["events"], VIEWER), "absent",
                   "the PR does not carry the pr-ready-verified label")
        other = [{"id": "x", "name": "needs-person", "description": "", "color": "ededed"}]
        self.check(rs.assess(H, other, world.s["events"], VIEWER), "absent",
                   "the PR does not carry the pr-ready-verified label")

    def test_a_marker_comment_before_the_ready_transition_does_not_count(self):
        # Rule 6: the marker is from an earlier epoch; the label is new.
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(H, rs.PR_READY))
        world.to_draft()
        world.ready()
        world.label()
        self.check(assess(world), "absent", f"no signal comment by {VIEWER} after the PR's last Ready transition")

    def test_a_label_without_any_marker_comment_is_absent(self):
        world = rw.World()
        world.ready()
        world.label()
        world.comment("looks good to me")
        self.check(assess(world), "absent", f"no signal comment by {VIEWER} after the PR's last Ready transition")

    def test_marker_other_login(self):
        # A marker by another account is ignored: the label alone (by the viewer) is not a signal.
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(H, rs.PR_READY), actor=OTHER)
        world.label()
        self.check(assess(world), "absent", f"no signal comment by {VIEWER} after the PR's last Ready transition")
        # Control: the same events with the marker by the viewer are valid.
        control = rw.World()
        control.ready()
        control.comment(rs.marker_comment(H, rs.PR_READY))
        control.label()
        self.assertEqual("valid", assess(control).state)

    def test_another_accounts_newer_marker_cannot_replace_the_viewers(self):
        world = signed()
        world.comment(rs.marker_comment(OLD, rs.PR_READY), actor=OTHER)
        self.check(assess(world), "valid", marker=H, producer=rs.PR_READY)

    # -- inconsistent -------------------------------------------------------------------------------------
    def test_a_draft_conversion_after_the_ready_transition_is_inconsistent(self):
        world = signed()
        world.to_draft()
        self.check(assess(world), "inconsistent", "the PR was converted to Draft after its last Ready transition")

    def test_a_label_the_view_shows_but_the_timeline_does_not_is_inconsistent(self):
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(H, rs.PR_READY))
        labels = [{"id": "x", "name": rs.LABEL, "description": "", "color": "1d76db"}]
        self.check(rs.assess(H, labels, world.s["events"], VIEWER), "inconsistent",
                   "the PR shows the pr-ready-verified label but its timeline has no event for it")

    def test_the_labels_last_event_being_a_removal_is_inconsistent(self):
        world = signed()
        labels = world.view_labels()
        world.label(add=False)
        self.check(rs.assess(H, labels, world.s["events"], VIEWER), "inconsistent",
                   "the PR shows the pr-ready-verified label but its last label event is a removal")

    # -- stale-epoch --------------------------------------------------------------------------------------
    def test_stale_epoch(self):
        # Signed, converted to Draft (the label stays), made Ready again: the label predates the Ready transition.
        world = signed()
        world.to_draft()
        world.ready()
        self.check(assess(world), "stale-epoch", "the pr-ready-verified label was added before the PR's last "
                                                 "Ready transition")
        # Control: a fresh signal after the new Ready transition is valid.
        world.comment(rs.marker_comment(H, rs.PR_READY))
        world.label(add=False)
        world.label()
        self.assertEqual("valid", assess(world).state)

    def test_a_label_added_in_the_same_epoch_as_the_ready_transition_is_not_stale(self):
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(H, rs.PR_READY))
        world.label()
        self.assertEqual("valid", assess(world).state)

    # -- untrusted ----------------------------------------------------------------------------------------
    def test_label_untrusted(self):
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(H, rs.PR_READY))
        world.label(actor=OTHER)
        self.check(assess(world), "untrusted", f"the pr-ready-verified label was added by {OTHER}, not by the "
                                               f"authenticated account {VIEWER}")
        # The same events are valid for a viewer that IS the account that added the label and wrote the marker.
        world2 = rw.World()
        world2.ready()
        world2.comment(rs.marker_comment(H, rs.PR_READY), actor=OTHER)
        world2.label(actor=OTHER)
        self.assertEqual("valid", assess(world2, viewer=OTHER).state)
        self.assertEqual("untrusted", assess(world2, viewer=VIEWER).state)

    def test_a_label_by_a_deleted_account_is_untrusted(self):
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(H, rs.PR_READY))
        world.label()
        world.s["events"][-1]["actor"] = None  # GitHub's null actor of a deleted user
        self.check(assess(world), "untrusted", f"the pr-ready-verified label was added by an unknown account, not by "
                                               f"the authenticated account {VIEWER}")

    # -- stale --------------------------------------------------------------------------------------------
    def test_stale_head(self):
        # The PR was pushed after the signal: the marker names the old HEAD.
        world = signed(head=OLD)
        self.check(rs.assess(H, world.view_labels(), world.s["events"], VIEWER), "stale",
                   f"the signal was written for HEAD {OLD[:12]}, the PR HEAD is {H[:12]}", marker=OLD,
                   producer=rs.PR_READY)
        # Control: the same events at the HEAD they name are valid.
        self.assertEqual("valid", assess(world, head=OLD).state)

    def test_the_newest_marker_wins(self):
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(OLD, rs.PR_READY))
        world.comment(rs.marker_comment(H, rs.MAINTAINER))
        world.label()
        self.check(assess(world, head=H), "valid", marker=H, producer=rs.MAINTAINER)
        reverse = rw.World()
        reverse.ready()
        reverse.comment(rs.marker_comment(H, rs.PR_READY))
        reverse.comment(rs.marker_comment(OLD, rs.PR_READY))
        reverse.label()
        self.check(assess(reverse, head=H), "stale", marker=OLD, producer=rs.PR_READY)

    def test_the_last_marker_of_one_comment_wins_over_its_earlier_ones(self):
        world = rw.World()
        world.ready()
        world.comment(rs.marker_line(OLD, rs.PR_READY) + "\n" + rs.marker_line(H, rs.ISSUE_TO_PR))
        world.label()
        self.check(assess(world, head=H), "valid", marker=H, producer=rs.ISSUE_TO_PR)

    def test_a_malformed_marker_line_is_no_marker(self):
        world = rw.World()
        world.ready()
        world.comment(f"<!-- pr-ready:verified head={H.upper()} by=pr-ready -->")
        world.label()
        self.check(assess(world), "absent", f"no signal comment by {VIEWER} after the PR's last Ready transition")

    # -- malformed input fails closed -----------------------------------------------------------------------
    def test_a_relevant_event_with_a_malformed_shape_raises(self):
        base = signed()
        cases = {
            "an entry that is no object": lambda ev: ev.insert(1, "ready_for_review"),
            "an entry without an event name": lambda ev: ev.insert(1, {"id": 1}),
            "an event name that is no string": lambda ev: ev.insert(1, {"event": 5}),
            "a labeled event without a label": lambda ev: ev.insert(1, {"event": "labeled", "actor": rw.account(VIEWER)}),
            "a labeled event whose label is no object": lambda ev: ev.insert(1, {"event": "unlabeled", "label": "x"}),
            "a labeled event whose label name is no string": lambda ev: ev.insert(
                1, {"event": "labeled", "label": {"name": None}}),
            "our label's event with a malformed actor": lambda ev: ev[-1].update(actor="kjelly"),
            "our label's event with an actor without a login": lambda ev: ev[-1].update(actor={"id": 1}),
            "the viewer's comment without a string body": lambda ev: ev[-2].update(body=None),
            "a comment whose user is no object": lambda ev: ev.insert(1, {"event": "commented", "user": "kjelly",
                                                                         "body": "x"}),
        }
        for name, break_it in cases.items():
            with self.subTest(name):
                events = copy.deepcopy(base.s["events"])
                break_it(events)
                with self.assertRaises(rs.SignalError):
                    rs.assess(H, base.view_labels(), events, VIEWER)

    def test_irrelevant_malformed_events_are_not_errors(self):
        # Only what the signal reads must be well formed: another label's actor, another account's comment body,
        # event kinds the signal does not look at.
        world = signed()
        events = copy.deepcopy(world.s["events"])
        events.insert(1, {"event": "labeled", "label": {"name": "needs-person"}, "actor": "garbage"})
        events.insert(2, {"event": "commented", "user": {"login": OTHER}, "body": None})
        events.insert(3, {"event": "committed", "author": {"name": "x"}})
        events.insert(4, {"event": "something-new", "anything": [1, 2]})
        events.insert(5, {"event": "commented", "user": None, "body": 7})
        self.assertEqual("valid", rs.assess(H, world.view_labels(), events, VIEWER).state)

    def test_malformed_arguments_raise(self):
        world = signed()
        labels, events = world.view_labels(), world.s["events"]
        for name, args in {
            "a HEAD that is no SHA": ("main", labels, events, VIEWER),
            "no HEAD": (None, labels, events, VIEWER),
            "a short HEAD": ("a" * 39, labels, events, VIEWER),
            "no viewer": (H, labels, events, ""),
            "a viewer that is no string": (H, labels, events, None),
            "labels that are no list": (H, None, events, VIEWER),
            "a label that is no object": (H, ["pr-ready-verified"], events, VIEWER),
            "a label without a name": (H, [{"id": "x"}], events, VIEWER),
            "a timeline that is no list": (H, labels, {"events": []}, VIEWER),
        }.items():
            with self.subTest(name), self.assertRaises(rs.SignalError):
                rs.assess(*args)

    def test_the_head_is_compared_lowercase(self):
        world = signed()
        self.assertEqual("valid", assess(world, head=H.upper()).state)

    def test_assess_is_pure(self):
        world = signed()
        labels, events = world.view_labels(), world.s["events"]
        before = copy.deepcopy((labels, events))
        self.assertEqual(rs.assess(H, labels, events, VIEWER), rs.assess(H, labels, events, VIEWER))
        self.assertEqual(before, (labels, events))

    def test_every_state_is_reachable_and_listed(self):
        reached = {
            assess(signed()).state,
            assess(rw.World()).state,
            rs.assess(H, signed(head=OLD).view_labels(), signed(head=OLD).s["events"], VIEWER).state,
        }
        stale_epoch = signed()
        stale_epoch.to_draft()
        stale_epoch.ready()
        reached.add(assess(stale_epoch).state)
        untrusted = rw.World()
        untrusted.ready()
        untrusted.label(actor=OTHER)
        reached.add(assess(untrusted).state)
        inconsistent = signed()
        inconsistent.to_draft()
        reached.add(assess(inconsistent).state)
        self.assertEqual(set(rs.STATES), reached)


class RealTimelineTests(unittest.TestCase):
    """The captured timeline of the merged kjelly/pilot#419, as `gh api --paginate --slurp` returned it (reduced)."""

    capture = rw.FIXTURES["timeline"]["pr_419_paged"]
    pages = json.loads(capture["stdout"])
    events = [event for page in pages for event in page]

    def test_the_capture_is_a_real_multi_page_answer_with_the_events_the_signal_reads(self):
        self.assertGreaterEqual(len(self.pages), 3)
        self.assertEqual(8, len(self.events))
        self.assertEqual(["ready_for_review", "commented", "convert_to_draft", "commented", "ready_for_review",
                          "labeled", "commented", "unlabeled"], [e["event"] for e in self.events])
        self.assertEqual({"ready_for_review", "convert_to_draft", "labeled", "unlabeled", "commented"},
                         {e["event"] for e in self.events})
        for event in self.events:
            self.assertEqual(VIEWER, event["actor"]["login"])
            if event["event"] == "commented":
                self.assertEqual(VIEWER, event["user"]["login"])
                self.assertIsInstance(event["body"], str)

    def sign_after(self, index):
        """The capture's events with a signal (comment, label) inserted after position `index`, built from the real
        events' own shapes: the real `commented` and `labeled` events with the signal's content."""
        comment = copy.deepcopy(next(e for e in self.events if e["event"] == "commented"))
        comment.update(id=1, body=rs.marker_comment(H, rs.PR_READY))
        label = copy.deepcopy(next(e for e in self.events if e["event"] == "labeled"))
        label.update(id=2)
        label["label"]["name"] = rs.LABEL
        events = copy.deepcopy(self.events)
        events[index + 1:index + 1] = [comment, label]
        return events

    def labels(self, *names):
        return [{"id": "x", "name": n, "description": "", "color": "ededed"} for n in names]

    def test_without_our_label_the_real_timeline_is_absent_and_the_merge_queue_label_does_not_count(self):
        result = rs.assess(H, self.labels(), self.events, VIEWER)
        self.assertEqual(("absent", "the PR does not carry the pr-ready-verified label"), (result.state, result.reason))
        self.assertEqual("absent", rs.assess(H, self.labels("merge-queue"), self.events, VIEWER).state)

    def test_a_label_the_real_timeline_has_no_event_for_is_inconsistent(self):
        self.assertEqual("inconsistent", rs.assess(H, self.labels(rs.LABEL), self.events, VIEWER).state)

    def test_a_signal_after_the_real_last_ready_transition_is_valid(self):
        events = self.sign_after(len(self.events) - 1)
        self.assertEqual("valid", rs.assess(H, self.labels(rs.LABEL), events, VIEWER).state)
        # And only for the account that wrote it.
        self.assertEqual("untrusted", rs.assess(H, self.labels(rs.LABEL), events, OTHER).state)

    def test_a_signal_before_the_real_last_ready_transition_is_stale_epoch(self):
        # After the first ready_for_review and its comment: the label predates the second Ready transition.
        events = self.sign_after(1)
        self.assertEqual("stale-epoch", rs.assess(H, self.labels(rs.LABEL), events, VIEWER).state)

    def test_the_real_draft_conversion_after_a_ready_transition_is_inconsistent(self):
        events = self.events[:3]  # ready_for_review, commented, convert_to_draft
        self.assertEqual("convert_to_draft", events[-1]["event"])
        self.assertEqual("inconsistent", rs.assess(H, self.labels(rs.LABEL), events, VIEWER).state)

    def test_the_real_events_survive_a_json_round_trip_unchanged(self):
        self.assertEqual(self.events, json.loads(json.dumps(self.events)))

    def test_the_models_view_labels_have_the_captured_gh_pr_view_shape(self):
        # What `gh pr view --json labels` printed for a labelled PR (fixtures labels.pr_view); the model's labels are
        # built the same way, from the label's own capture, so the fake executables print the real shape.
        captured = json.loads(rw.FIXTURES["labels"]["pr_view"]["stdout"])["labels"][0]
        world = rw.World()
        world.ready()
        world.label()
        (label,) = world.view_labels()
        self.assertEqual(set(captured), set(label))
        self.assertEqual({k: type(v) for k, v in captured.items()}, {k: type(v) for k, v in label.items()})
        self.assertEqual(rw.LABEL_CAPTURE["node_id"], label["id"])


class PrepareTests(unittest.TestCase):
    def run_prepare(self, world, *, sleeps=None):
        client = rw.Client(world)
        slept = [] if sleeps is None else sleeps
        return rs.prepare(client, client.Repo.parse("acme/repo"), 7, sleep=slept.append)

    def test_a_missing_label_stops_before_anything_else(self):
        world = rw.World().label_state("missing")
        with self.assertRaises(rs.SignalError) as raised:
            self.run_prepare(world)
        self.assertIn("the repository has no pr-ready-verified label", str(raised.exception))
        self.assertIn("never creates labels", str(raised.exception))
        self.assertEqual(["label-exists"], world.calls())

    def test_a_failing_label_lookup_is_an_error_not_a_missing_label(self):
        world = rw.World().label_state("error")
        client = rw.Client(world)
        with self.assertRaises(client.GitHubError):
            self.run_prepare(world)
        self.assertEqual(["label-exists"], world.calls())

    def test_a_clean_draft_returns_the_viewer_and_removes_nothing(self):
        world = rw.World()
        self.assertEqual(VIEWER, self.run_prepare(world))
        self.assertEqual(["label-exists", "user", "pr-view"], world.calls())

    def test_a_stale_label_is_removed_from_the_draft_and_the_removal_confirmed(self):
        world = signed()
        world.to_draft()  # the label stays on the Draft
        self.assertEqual([rs.LABEL], world.label_names())
        sleeps = []
        self.assertEqual(VIEWER, self.run_prepare(world, sleeps=sleeps))
        self.assertEqual(["label-exists", "user", "pr-view", "remove-label", "pr-view"], world.calls())
        self.assertEqual([], world.label_names())
        self.assertEqual([], sleeps)
        # The unlabeled event is the newest label event: the label a producer adds after Ready is a new event.
        self.assertEqual("unlabeled", [e for e in world.s["events"] if e["event"] in ("labeled", "unlabeled")][-1]["event"])

    def test_the_removal_is_confirmed_within_the_bound_and_not_beyond_it(self):
        for lag, ok in ((rs.READ_TRIES - 1, True), (rs.READ_TRIES, False)):
            with self.subTest(lag=lag):
                world = signed()
                world.to_draft()
                world.s["flags"]["remove_lag"] = lag
                sleeps = []
                if ok:
                    self.run_prepare(world, sleeps=sleeps)
                else:
                    with self.assertRaises(rs.SignalError) as raised:
                        self.run_prepare(world, sleeps=sleeps)
                    self.assertIn(f"still shows after {rs.READ_TRIES} reads", str(raised.exception))
                # One read before the removal plus READ_TRIES confirmations at most, an interval between two reads.
                self.assertEqual(1 + min(lag + 1, rs.READ_TRIES), world.calls().count("pr-view"))
                self.assertEqual([rs.READ_INTERVAL] * (min(lag + 1, rs.READ_TRIES) - 1), sleeps)

    def test_a_failing_removal_is_an_error_and_the_label_stays(self):
        world = signed().fail("remove-label")
        world.to_draft()
        client = rw.Client(world)
        with self.assertRaises(client.GitHubError):
            self.run_prepare(world)
        self.assertEqual([rs.LABEL], world.label_names())

    def test_a_signed_ready_pr_is_never_unsigned(self):
        world = signed()
        with self.assertRaises(rs.SignalError) as raised:
            self.run_prepare(world)
        self.assertIn("is not a Draft", str(raised.exception))
        self.assertNotIn("remove-label", world.calls())
        self.assertEqual([rs.LABEL], world.label_names())


class WriteTests(unittest.TestCase):
    def run_write(self, world, *, head=H, producer=rs.PR_READY, viewer=VIEWER, sleeps=None):
        client = rw.Client(world)
        slept = [] if sleeps is None else sleeps
        return rs.write(client, client.Repo.parse("acme/repo"), 7, head, producer, viewer, sleep=slept.append)

    def ready_world(self):
        world = rw.World(head=H)
        world.ready()
        return world

    def test_the_comment_comes_first_the_label_last_and_the_read_back_after_both(self):
        world = self.ready_world()
        result = self.run_write(world)
        self.assertEqual(["comment", "add-label", "pr-view", "timeline"], world.calls())
        self.assertEqual(("valid", H, rs.PR_READY), (result.state, result.marker_head, result.producer))
        events = world.s["events"][1:]
        self.assertEqual(["commented", "labeled"], [e["event"] for e in events])
        self.assertEqual(rs.marker_comment(H, rs.PR_READY), events[0]["body"])
        self.assertEqual(rs.LABEL, events[1]["label"]["name"])
        self.assertEqual((VIEWER, VIEWER), (events[0]["user"]["login"], events[1]["actor"]["login"]))

    def test_every_producer_can_write_and_is_read_back_as_itself(self):
        for producer in rs.PRODUCERS:
            with self.subTest(producer):
                result = self.run_write(self.ready_world(), producer=producer)
                self.assertEqual((True, producer), (result.valid, result.producer))

    def test_a_failing_comment_leaves_no_label(self):
        world = self.ready_world().fail("comment")
        client = rw.Client(world)
        with self.assertRaises(client.GitHubError):
            self.run_write(world)
        self.assertEqual(["comment"], world.calls())
        self.assertEqual([], world.label_names())

    def test_a_failing_label_leaves_a_comment_that_alone_is_no_signal(self):
        world = self.ready_world().fail("add-label")
        client = rw.Client(world)
        with self.assertRaises(client.GitHubError):
            self.run_write(world)
        self.assertEqual(["comment", "add-label"], world.calls())
        self.assertEqual("absent", assess(world).state)

    def test_the_read_back_waits_for_a_lagging_label_within_the_bound(self):
        world = self.ready_world()
        world.s["flags"]["lag"] = rs.READ_TRIES - 1
        sleeps = []
        result = self.run_write(world, sleeps=sleeps)
        self.assertTrue(result.valid)
        self.assertEqual(rs.READ_TRIES, world.calls().count("timeline"))
        self.assertEqual([rs.READ_INTERVAL] * (rs.READ_TRIES - 1), sleeps)

    def test_a_signal_that_never_reads_back_is_an_error_after_exactly_the_bound(self):
        world = self.ready_world()
        world.s["flags"]["lag"] = rs.READ_TRIES
        sleeps = []
        with self.assertRaises(rs.SignalError) as raised:
            self.run_write(world, sleeps=sleeps)
        self.assertEqual(rs.READ_TRIES, world.calls().count("timeline"))
        self.assertEqual([rs.READ_INTERVAL] * (rs.READ_TRIES - 1), sleeps)
        message = str(raised.exception)
        self.assertIn(f"HEAD {H[:12]} was written but does not read back as valid after {rs.READ_TRIES} reads", message)
        self.assertIn("last: absent: the PR does not carry the pr-ready-verified label", message)

    def test_the_signal_is_confirmed_for_the_head_that_was_verified(self):
        # The PR was pushed between the verification and the write: the marker names the old HEAD and every
        # consumer says stale, so the write does not claim success.
        world = self.ready_world()
        world.s["head"] = OLD
        with self.assertRaises(rs.SignalError) as raised:
            self.run_write(world, head=H)
        self.assertIn(f"last: stale: the signal was written for HEAD {H[:12]}, the PR HEAD is {OLD[:12]}",
                      str(raised.exception))

    def test_a_viewer_that_is_not_the_signing_account_is_refused(self):
        with self.assertRaises(rs.SignalError) as raised:
            self.run_write(self.ready_world(), viewer=OTHER)
        self.assertIn("last: untrusted", str(raised.exception))

    def test_a_malformed_timeline_is_an_immediate_error_not_a_retry(self):
        world = self.ready_world()
        world.s["events"].append({"id": 1})
        sleeps = []
        with self.assertRaises(rs.SignalError) as raised:
            self.run_write(world, sleeps=sleeps)
        self.assertIn("is not an event object", str(raised.exception))
        self.assertEqual([], sleeps)
        self.assertEqual(1, world.calls().count("timeline"))

    def test_a_failing_read_back_is_the_clients_error(self):
        world = self.ready_world().fail("timeline")
        client = rw.Client(world)
        with self.assertRaises(client.GitHubError):
            self.run_write(world)

    def test_bad_arguments_are_refused_before_any_call(self):
        for kwargs, error in (({"producer": "someone"}, ValueError), ({"head": "main"}, rs.SignalError),
                              ({"head": None}, rs.SignalError)):
            with self.subTest(kwargs):
                world = self.ready_world()
                with self.assertRaises(error):
                    self.run_write(world, **kwargs)
                self.assertEqual([], world.calls())

    def test_an_uppercase_head_is_written_lowercase(self):
        world = self.ready_world()
        self.assertTrue(self.run_write(world, head=H.upper()).valid)
        self.assertIn(f"head={H} ", world.s["events"][1]["body"])


class ProducerPlacementTests(unittest.TestCase):
    def test_prepare_and_write_compose_the_way_a_producer_calls_them(self):
        # prepare on the Draft, the Ready transition, write on the Ready PR: the sequence both producers run.
        world = rw.World(head=H)
        client = rw.Client(world)
        repo = client.Repo.parse("acme/repo")
        viewer = rs.prepare(client, repo, 7, sleep=lambda _s: None)
        world.ready()
        self.assertEqual("valid", rs.write(client, repo, 7, H, rs.ISSUE_TO_PR, viewer, sleep=lambda _s: None).state)
        self.assertEqual("valid", assess(world).state)

    def test_a_second_epoch_removes_the_first_epochs_label_before_signing_again(self):
        world = signed()
        world.to_draft()
        client = rw.Client(world)
        repo = client.Repo.parse("acme/repo")
        viewer = rs.prepare(client, repo, 7, sleep=lambda _s: None)
        world.ready()
        self.assertEqual("absent", assess(world).state)  # the first epoch's label is gone; the new one comes with write
        self.assertEqual("valid", rs.write(client, repo, 7, H, rs.PR_READY, viewer, sleep=lambda _s: None).state)


class LiteralGuardTests(unittest.TestCase):
    """The label name and the marker prefix live in ready_signal.py only; everything else imports them (5.7)."""

    LITERALS = ("pr-ready-verified", "pr-ready:verified")
    HOME = SKILLS / "_shared" / "scripts" / "ready_signal.py"

    @staticmethod
    def scanned(root):
        files = sorted(root.glob(".agents/skills/*/scripts/**/*.py")) + sorted(root.glob("scripts/*.py"))
        return [f for f in files if "__pycache__" not in f.parts]

    @classmethod
    def offenders(cls, root):
        return [str(f.relative_to(root)) for f in cls.scanned(root)
                if f.name != "ready_signal.py" and any(lit in f.read_text(encoding="utf-8") for lit in cls.LITERALS)]

    def test_the_literals_appear_in_ready_signal_py_only(self):
        self.assertEqual([], self.offenders(REPO_ROOT))

    def test_the_scan_covers_the_producers_the_consumers_and_the_runner(self):
        names = {f.relative_to(REPO_ROOT).as_posix() for f in self.scanned(REPO_ROOT)}
        for needed in (".agents/skills/_shared/scripts/ready_signal.py", ".agents/skills/pr-ready/scripts/pr_gate.py",
                       ".agents/skills/issue-to-pr/scripts/mark_ready.py",
                       ".agents/skills/pr-review-merge/scripts/gh_runtime.py", "scripts/pr_loop.py"):
            self.assertIn(needed, names)

    def test_the_home_file_has_both_literals(self):
        text = self.HOME.read_text(encoding="utf-8")
        for literal in self.LITERALS:
            self.assertIn(literal, text)

    def test_a_duplicated_literal_in_a_consumer_is_reported_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, text in {".agents/skills/_shared/scripts/ready_signal.py": 'LABEL = "pr-ready-verified"\n',
                              ".agents/skills/pr-review-merge/scripts/list_ready.py": "from ready_signal import LABEL\n",
                              ".agents/skills/pr-review-merge/scripts/apply_decision.py": 'x = "pr-ready-verified"\n',
                              ".agents/skills/pr-ready/scripts/pr_gate.py": 'm = "<!-- pr-ready:verified"\n',
                              "scripts/pr_loop.py": "pass\n"}.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            self.assertEqual([".agents/skills/pr-ready/scripts/pr_gate.py",
                              ".agents/skills/pr-review-merge/scripts/apply_decision.py"], self.offenders(root))

    def test_the_marker_text_in_the_comment_is_built_from_the_one_source(self):
        # The renderer and the regex are two spellings of one marker: changing the prefix in one breaks this.
        self.assertTrue(re.fullmatch(rs.MARKER.pattern, rs.marker_line(H, rs.PR_READY)))


if __name__ == "__main__":
    unittest.main()
