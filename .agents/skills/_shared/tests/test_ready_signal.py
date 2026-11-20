"""The pr-ready-verified signal (`_shared/scripts/ready_signal.py`): every state of `assess` with a pass and a
trigger case that asserts the REASON (AGENTS.md 5.12), the marker's strictness, the render -> assess round trip
(5.7), the real timeline capture of kjelly/pilot#419 (5.6), `prepare` and `write` over a recording client (order,
bound, errors), the binding of a signal to the ONE Ready transition it certifies (the marker's `ready=` field, the
epoch check that comes before the HEAD check, `write` identifying the transition against the baseline `prepare`
took, and a Draft -> Ready cycle injected at every point between `gh pr ready` and the end of `write`), and the guard
that keeps the two literals in one file.

Events are built by `ready_signal_world.World` in the shapes of the reduced real captures; nothing here reaches
GitHub and no test sleeps (`sleep` is injected).
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ready_signal_world as rw  # noqa: E402  (puts _shared/scripts on sys.path)
import ready_signal as rs  # noqa: E402

SKILLS = HERE.parents[1]
REPO_ROOT = SKILLS.parents[1]
H = "a" * 40
OLD = "b" * 40
VIEWER, OTHER = rw.VIEWER, rw.OTHER
R = rw.REAL_LAST_READY  # a real ready_for_review event id (kjelly/pilot#419) for a marker that needs one


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
                line = rs.marker_line(H, producer, R)
                self.assertEqual(f"<!-- pr-ready:verified head={H} ready={R} by={producer} -->", line)
                self.assertEqual([(H, str(R), producer)], rs.MARKER.findall(line))
                self.assertEqual([(H, str(R), producer)], rs.MARKER.findall(rs.marker_comment(H, producer, R)))

    def test_the_renderer_writes_the_head_lowercase_so_the_regex_reads_it_back(self):
        for producer in rs.PRODUCERS:
            self.assertEqual(rs.marker_line(H, producer, R), rs.marker_line(H.upper(), producer, R))
            self.assertEqual([(H, str(R), producer)], rs.MARKER.findall(rs.marker_comment(H.upper(), producer, R)))
        with self.assertRaises(rs.SignalError):
            rs.marker_comment("main", rs.PR_READY, R)

    def test_an_unknown_producer_is_refused_by_the_renderer_and_the_regex(self):
        for producer in ("pr-reviewer", "PR-READY", "", "pr-ready ", "maintainers", None):
            with self.subTest(producer=producer):
                with self.assertRaises(ValueError):
                    rs.marker_comment(H, producer, R)
                with self.assertRaises(ValueError):
                    rs.marker_line(H, producer, R)
        self.assertIsNone(rs.MARKER.search(f"<!-- pr-ready:verified head={H} ready={R} by=pr-reviewer -->"))

    def test_the_regex_is_strict(self):
        good = f"<!-- pr-ready:verified head={H} ready={R} by=pr-ready -->"
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
            "plain text": f"head={H} ready={R} by=pr-ready",
            "no ready": good.replace(f" ready={R}", ""),
        }
        for name, text in near_misses.items():
            with self.subTest(name):
                self.assertIsNone(rs.MARKER.search(text), text)

    def test_the_ready_field_is_required_and_strict(self):
        # The field binds a signal to ONE Ready transition: a marker without it, or with anything but the decimal
        # id of an event, is no marker at all (fail closed: an old-format marker certifies no transition).
        def marker(ready=None, *, order="head ready by"):
            fields = {"head": f"head={H}", "ready": f"ready={ready}", "by": "by=pr-ready"}
            parts = [fields[name] for name in order.split() if name != "ready" or ready is not None]
            return "<!-- pr-ready:verified " + " ".join(parts) + " -->"

        self.assertEqual([(H, "1", "pr-ready")], rs.MARKER.findall(marker(1)))
        self.assertEqual([(H, "9" * 20, "pr-ready")], rs.MARKER.findall(marker("9" * 20)))
        near_misses = {
            "no ready field (the old format)": marker(),
            "zero": marker(0),
            "a leading zero": marker("01"),
            "negative": marker(-1),
            "an exponent": marker("1e5"),
            "a decimal point": marker("1.5"),
            "a plus sign": marker("+1"),
            "empty": marker(""),
            "a space": marker("1 2"),
            "hex digits": marker("0x1f"),
            "21 digits": marker("1" * 21),
            "ready after by": marker(R, order="head by ready"),
            "ready before head": marker(R, order="ready head by"),
            "two spaces before ready": marker(R).replace(" ready=", "  ready="),
            "an upper-case key": marker(R).replace("ready=", "READY="),
        }
        for name, text in near_misses.items():
            with self.subTest(name):
                self.assertIsNone(rs.MARKER.search(text), text)

    def test_the_renderer_refuses_a_ready_that_is_not_a_positive_event_id(self):
        for bad in (None, 0, -1, True, False, "36750750751", 1.0, 36750750751.0, 10 ** 20, b"1", [1]):
            with self.subTest(ready=bad):
                with self.assertRaises(rs.SignalError):
                    rs.marker_line(H, rs.PR_READY, bad)
                with self.assertRaises(rs.SignalError):
                    rs.marker_comment(H, rs.PR_READY, bad)
        for ok in (1, 10 ** 20 - 1):  # the bounds the regex accepts
            self.assertEqual([(H, str(ok), "pr-ready")], rs.MARKER.findall(rs.marker_line(H, rs.PR_READY, ok)))
        with self.assertRaises(TypeError):  # there is no default: a producer must name the transition
            rs.marker_comment(H, rs.PR_READY)
        with self.assertRaises(TypeError):
            rs.marker_line(H, rs.PR_READY)

    def test_the_comment_tells_a_person_what_the_signal_is_and_ends_with_the_marker(self):
        text = rs.marker_comment(H, rs.ISSUE_TO_PR, R)
        self.assertTrue(text.endswith(rs.marker_line(H, rs.ISSUE_TO_PR, R) + "\n"))
        self.assertEqual(1, len(rs.MARKER.findall(text)), "the explanation must not contain a second marker")
        for needle in (f"`{H}`", "`issue-to-pr`", f"`{rs.LABEL}`", "stale", "Draft", "not a human approval",
                       f"Verified Ready transition: `{R}`",
                       "A later Ready transition, even at the same HEAD, ends it"):
            self.assertIn(needle, text)

    def test_the_comment_round_trips_through_assess(self):
        # 5.7: the renderer and the reader are two places; both meet in a signal that reads back as valid.
        for producer in rs.PRODUCERS:
            with self.subTest(producer):
                world = rw.World(head=H)
                world.ready()
                world.comment(rs.marker_comment(H, producer, world.latest_ready()))
                world.label()
                result = assess(world)
                self.assertEqual(("valid", H, producer), (result.state, result.marker_head, result.producer))
                self.assertEqual((world.latest_ready(),) * 2, (result.marker_ready, result.ready_event))


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
        world.signal(ready=R)  # a label and a marker, but no ready_for_review event (created Ready, or events lost)
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
        world.comment(rs.marker_comment(H, rs.PR_READY, world.latest_ready()))
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
        world.comment(rs.marker_comment(H, rs.PR_READY, world.latest_ready()), actor=OTHER)
        world.label()
        self.check(assess(world), "absent", f"no signal comment by {VIEWER} after the PR's last Ready transition")
        # Control: the same events with the marker by the viewer are valid.
        control = rw.World()
        control.ready()
        control.comment(rs.marker_comment(H, rs.PR_READY, control.latest_ready()))
        control.label()
        self.assertEqual("valid", assess(control).state)

    def test_another_accounts_newer_marker_cannot_replace_the_viewers(self):
        world = signed()
        world.comment(rs.marker_comment(OLD, rs.PR_READY, world.latest_ready()), actor=OTHER)
        self.check(assess(world), "valid", marker=H, producer=rs.PR_READY)

    # -- inconsistent -------------------------------------------------------------------------------------
    def test_a_draft_conversion_after_the_ready_transition_is_inconsistent(self):
        world = signed()
        world.to_draft()
        self.check(assess(world), "inconsistent", "the PR was converted to Draft after its last Ready transition")

    def test_a_label_the_view_shows_but_the_timeline_does_not_is_inconsistent(self):
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(H, rs.PR_READY, world.latest_ready()))
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
        world.comment(rs.marker_comment(H, rs.PR_READY, world.latest_ready()))
        world.label(add=False)
        world.label()
        self.assertEqual("valid", assess(world).state)

    def test_a_label_added_in_the_same_epoch_as_the_ready_transition_is_not_stale(self):
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(H, rs.PR_READY, world.latest_ready()))
        world.label()
        self.assertEqual("valid", assess(world).state)

    # -- untrusted ----------------------------------------------------------------------------------------
    def test_label_untrusted(self):
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(H, rs.PR_READY, world.latest_ready()))
        world.label(actor=OTHER)
        self.check(assess(world), "untrusted", f"the pr-ready-verified label was added by {OTHER}, not by the "
                                               f"authenticated account {VIEWER}")
        # The same events are valid for a viewer that IS the account that added the label and wrote the marker.
        world2 = rw.World()
        world2.ready()
        world2.comment(rs.marker_comment(H, rs.PR_READY, world2.latest_ready()), actor=OTHER)
        world2.label(actor=OTHER)
        self.assertEqual("valid", assess(world2, viewer=OTHER).state)
        self.assertEqual("untrusted", assess(world2, viewer=VIEWER).state)

    def test_a_label_by_a_deleted_account_is_untrusted(self):
        world = rw.World()
        world.ready()
        world.comment(rs.marker_comment(H, rs.PR_READY, world.latest_ready()))
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
        world.comment(rs.marker_comment(OLD, rs.PR_READY, world.latest_ready()))
        world.comment(rs.marker_comment(H, rs.MAINTAINER, world.latest_ready()))
        world.label()
        self.check(assess(world, head=H), "valid", marker=H, producer=rs.MAINTAINER)
        reverse = rw.World()
        reverse.ready()
        reverse.comment(rs.marker_comment(H, rs.PR_READY, reverse.latest_ready()))
        reverse.comment(rs.marker_comment(OLD, rs.PR_READY, reverse.latest_ready()))
        reverse.label()
        self.check(assess(reverse, head=H), "stale", marker=OLD, producer=rs.PR_READY)

    def test_the_last_marker_of_one_comment_wins_over_its_earlier_ones(self):
        world = rw.World()
        world.ready()
        # (Since R2 a signal comment starts with the producer's heading; without it neither marker would count.)
        world.comment(rs.SIGNAL_HEADING + "\n\n" + rs.marker_line(OLD, rs.PR_READY, world.latest_ready()) + "\n"
                      + rs.marker_line(H, rs.ISSUE_TO_PR, world.latest_ready()))
        world.label()
        self.check(assess(world, head=H), "valid", marker=H, producer=rs.ISSUE_TO_PR)

    def test_the_newest_marker_wins_across_ready_transitions(self):
        # Two markers after the last Ready transition, one for it and one for an earlier transition: the newest one
        # decides, in either order. (An older-epoch marker is never a fallback for a newer one.)
        for order, state in ((("last", "first"), "stale-epoch"), (("first", "last"), "valid")):
            with self.subTest(order=order):
                world = rw.World()
                world.ready()
                first = world.latest_ready()
                world.to_draft()
                world.ready()
                last = world.latest_ready()
                for which in order:
                    world.comment(rs.marker_comment(H, rs.PR_READY, {"first": first, "last": last}[which]))
                world.label()
                result = assess(world)
                self.check(result, state, marker=H, producer=rs.PR_READY)
                self.assertEqual({"first": first, "last": last}[order[-1]], result.marker_ready)

    def test_a_signal_for_an_earlier_ready_transition_is_stale_epoch(self):
        # The finding: the marker certifies a Ready transition that is not the PR's last one. The PR is at the HEAD
        # the marker names and everything else is right, so only the transition makes it not valid.
        world = rw.World()
        world.ready()
        first = world.latest_ready()
        world.to_draft()
        world.ready()
        last = world.latest_ready()
        world.comment(rs.marker_comment(H, rs.PR_READY, first))
        world.label()
        result = assess(world)
        self.check(result, "stale-epoch", f"the signal comment certifies Ready transition {first}, but the PR's last "
                                          f"Ready transition is {last}", marker=H, producer=rs.PR_READY)
        self.assertEqual((first, last), (result.marker_ready, result.ready_event))
        # Control: the same events with the marker for the last transition are valid.
        control = rw.World()
        control.ready()
        control.to_draft()
        control.ready()
        control.comment(rs.marker_comment(H, rs.PR_READY, control.latest_ready()))
        control.label()
        self.assertEqual("valid", assess(control).state)

    def test_the_epoch_is_checked_before_the_head(self):
        # A consumer carries a `stale` signal (a base import or an evidence-only change moved the HEAD) but never a
        # `stale-epoch` one. Draft, push, Ready: the marker is for the old HEAD AND the old Ready transition; it must
        # read stale-epoch, not stale.
        world = rw.World(head=OLD)
        world.ready()
        first = world.latest_ready()
        world.to_draft()
        world.s["head"] = H
        world.ready()
        world.comment(rs.marker_comment(OLD, rs.PR_READY, first))
        world.label()
        result = assess(world)
        self.check(result, "stale-epoch", marker=OLD, producer=rs.PR_READY)
        self.assertIn("certifies Ready transition", result.reason)
        # Control: the same events with the marker for the CURRENT Ready transition differ only by the HEAD: stale.
        control = rw.World(head=OLD)
        control.ready()
        control.to_draft()
        control.s["head"] = H
        control.ready()
        control.comment(rs.marker_comment(OLD, rs.PR_READY, control.latest_ready()))
        control.label()
        self.check(assess(control), "stale", marker=OLD, producer=rs.PR_READY)

    def test_a_marker_without_the_ready_field_is_no_marker(self):
        # The format before the transition was part of the signal certifies nothing: no marker, so absent.
        world = rw.World()
        world.ready()
        old_format = f"{rs.SIGNAL_HEADING}\n\n<!-- pr-ready:verified head={H} by=pr-ready -->"
        world.comment(old_format)
        world.label()
        self.check(assess(world), "absent", f"no signal comment by {VIEWER} after the PR's last Ready transition")
        # The newest marker wins, and an old-format one never hides a valid one before it.
        world.comment(rs.marker_comment(H, rs.PR_READY, world.latest_ready()))
        self.check(assess(world), "valid", marker=H, producer=rs.PR_READY)
        world.comment(old_format)
        self.check(assess(world), "valid", marker=H, producer=rs.PR_READY)

    # -- which comments are signal comments (R2) -------------------------------------------------------------------
    # The viewer's comments are not all the producer's: `needs_person.comment_text` lists up to 40 gate reasons and
    # paths in a comment the viewer posts after the Ready transition, and anyone can quote a marker in a comment of
    # their own account. Only the structure `marker_comment` renders counts: the heading as the first non-empty line and
    # the marker, as a whole, as the last one.
    def quoted(self, world, body):
        """`body` as a viewer comment after a push made the signed PR stale (HEAD H -> OLD), and what `assess` says."""
        world.s["head"] = OLD
        world.comment(body)
        return assess(world)

    def test_a_comment_that_only_quotes_a_marker_for_the_new_head_leaves_a_pushed_pr_stale(self):
        # The reproduction: a legitimately signed PR gets a push (stale at OLD); a viewer comment that quotes the
        # marker for (OLD, the same Ready transition) must not turn it valid.
        world = signed()
        world.s["head"] = OLD
        self.check(assess(world), "stale", marker=H, producer=rs.PR_READY)
        quoted = rs.marker_line(OLD, rs.PR_READY, world.latest_ready())
        world.comment(f"gate reasons:\n- both sides changed paths: {quoted}\n- more")
        self.check(assess(world), "stale", marker=H, producer=rs.PR_READY)

    def test_only_the_structure_of_a_producers_comment_counts(self):
        world = signed()
        ready = world.latest_ready()
        marker = rs.marker_line(OLD, rs.PR_READY, ready)
        text = rs.marker_comment(OLD, rs.PR_READY, ready)
        cases = {
            "the marker is the last line, the first line is something else (a needs-person comment)":
                f"## A person is needed\n\n- reason: x\n{marker}",
            "the heading and a marker that is not the last non-empty line": f"{rs.SIGNAL_HEADING}\n\n{marker}\nthanks",
            "a marker inside a fenced block": f"{rs.SIGNAL_HEADING}\n\n```\n{marker}\n```",
            "text after the marker on its line": f"{rs.SIGNAL_HEADING}\n\n{marker} (see above)",
            "text before the marker on its line": f"{rs.SIGNAL_HEADING}\n\nsigned: {marker}",
            "the marker quoted in a reply": f"{rs.SIGNAL_HEADING}\n\n> {marker}",
            "the heading quoted in a reply": f"> {rs.SIGNAL_HEADING}\n\n{marker}",
            "a heading of another level": f"# Ready for Review: verified\n\n{marker}",
            "the heading with more text on its line": f"{rs.SIGNAL_HEADING} (again)\n\n{marker}",
            "a bare marker": marker,
            "the heading and no marker": rs.SIGNAL_HEADING,
            "the whole producer comment quoted with a prefix": "\n".join("> " + line for line in text.splitlines()),
        }
        for name, body in cases.items():
            with self.subTest(name):
                self.check(self.quoted(copy.deepcopy(world), body), "stale", marker=H, producer=rs.PR_READY)

    def test_two_markers_in_one_comment_only_the_last_line_counts(self):
        world = signed()
        ready = world.latest_ready()
        good, other = rs.marker_line(H, rs.PR_READY, ready), rs.marker_line(OLD, rs.MAINTAINER, ready)
        # The signed PR is at H: the last line decides, the line above it is ignored (not "the first marker found").
        both = copy.deepcopy(world)
        both.comment(f"{rs.SIGNAL_HEADING}\n\n{other}\n{good}")
        self.check(assess(both), "valid", marker=H, producer=rs.PR_READY)
        flipped = copy.deepcopy(world)
        flipped.comment(f"{rs.SIGNAL_HEADING}\n\n{good}\n{other}")
        self.check(assess(flipped), "stale", marker=OLD, producer=rs.MAINTAINER)
        # A marker in the middle of the text never counts, whatever is last.
        middle = copy.deepcopy(world)
        middle.s["head"] = OLD
        middle.comment(f"{rs.SIGNAL_HEADING}\n\n{rs.marker_line(OLD, rs.PR_READY, ready)}\nand not a marker")
        self.check(assess(middle), "stale", marker=H, producer=rs.PR_READY)

    def test_a_producers_comment_and_a_hand_signed_one_count_in_every_line_ending(self):
        # The controls of the cases above: the real renderer's comment, the maintainer's, with CRLF endings, trailing
        # blank lines and trailing whitespace (the shapes GitHub stores for a comment typed in a browser).
        for producer in rs.PRODUCERS:
            for name, change in (("as rendered", lambda t: t),
                                 ("crlf", lambda t: t.replace("\n", "\r\n")),
                                 ("trailing blank lines", lambda t: t + "\n\n  \n"),
                                 ("surrounding whitespace", lambda t: "\n  " + t.rstrip("\n") + "   \n\n")):
                with self.subTest(producer=producer, shape=name):
                    world = rw.World(head=OLD)
                    world.ready()
                    ready = world.latest_ready()
                    world.comment(change(rs.marker_comment(OLD, producer, ready)))
                    world.label()
                    self.check(assess(world), "valid", marker=OLD, producer=producer)

    def test_the_signal_structure_is_parsed_by_one_function_that_assess_uses(self):
        # `signal_marker` is the one parser: what it reads is what `assess` reads.
        ready = R
        for producer in rs.PRODUCERS:
            body = rs.marker_comment(H, producer, ready)
            self.assertEqual((H, str(ready), producer), rs.signal_marker(body))
        self.assertIsNone(rs.signal_marker(rs.marker_line(H, rs.PR_READY, ready)))
        self.assertIsNone(rs.signal_marker(""))
        self.assertEqual(rs.SIGNAL_HEADING, rs.marker_comment(H, rs.PR_READY, ready).splitlines()[0])

    def test_the_id_of_another_event_never_matches_the_ready_transition(self):
        # The marker names an event id; the id of the Draft conversion, of a label event or of a comment (another id
        # space) is not the Ready transition's, whatever it is next to.
        world = rw.World()
        world.ready()
        ready = world.latest_ready()
        draft = world.to_draft()["id"]
        world.ready()
        last = world.latest_ready()
        labeled = world.label()["id"]
        commented = world.comment("x")["id"]
        for name, ident in {"first Ready": ready, "Draft": draft, "label": labeled, "comment": commented,
                            "unknown": last + 1000, "one more": last + 1, "one less": last - 1}.items():
            with self.subTest(name):
                bad = rw.World()
                bad.ready()
                bad.to_draft()
                bad.ready()
                bad.label()
                bad.comment(rs.marker_comment(H, rs.PR_READY, ident))
                self.check(assess(bad), "stale-epoch", marker=H, producer=rs.PR_READY)
        # Control: the id of the last Ready transition itself.
        good = rw.World()
        good.ready()
        good.to_draft()
        good.ready()
        good.label()
        good.comment(rs.marker_comment(H, rs.PR_READY, good.latest_ready()))
        self.assertEqual("valid", assess(good).state)

    def test_a_ready_event_without_a_positive_integer_id_raises(self):
        for name, mutate in {"a bool": lambda e: e.update(id=True), "a string": lambda e: e.update(id="36750750751"),
                             "zero": lambda e: e.update(id=0), "negative": lambda e: e.update(id=-5),
                             "a float": lambda e: e.update(id=1.5), "null": lambda e: e.update(id=None),
                             "missing": lambda e: e.pop("id")}.items():
            for where in ("the last Ready event", "an earlier Ready event"):
                with self.subTest(name, where=where):
                    world = rw.World()
                    world.ready()
                    world.to_draft()
                    world.signed_ready()
                    events = copy.deepcopy(world.s["events"])
                    mutate(events[-3] if where == "the last Ready event" else events[0])
                    with self.assertRaises(rs.SignalError) as raised:
                        rs.assess(H, world.view_labels(), events, VIEWER)
                    self.assertIn("no valid integer id", str(raised.exception))
        # The raise comes before any state: a PR without the label is `absent` for a good id and an error for a bad one.
        events = [{"event": "ready_for_review", "id": 0}]
        with self.assertRaises(rs.SignalError):
            rs.assess(H, [], events, VIEWER)
        self.assertEqual("absent", rs.assess(H, [], [{"event": "ready_for_review", "id": 1}], VIEWER).state)
        # Control: a Draft conversion without an id is not read for its id.
        events = [{"event": "ready_for_review", "id": 1}, {"event": "convert_to_draft"}]
        self.assertEqual("inconsistent", rs.assess(H, [], events, VIEWER).state)

    def test_the_last_ready_event_is_reported_in_every_state(self):
        def ready_event(world):
            return assess(world).ready_event

        valid = signed()
        stale_head = signed(head=OLD)
        stale_epoch = signed()
        stale_epoch.to_draft()
        stale_epoch.ready()
        untrusted = rw.World()
        untrusted.ready()
        untrusted.comment(rs.marker_comment(H, rs.PR_READY, untrusted.latest_ready()))
        untrusted.label(actor=OTHER)
        absent = rw.World()
        absent.ready()
        inconsistent = signed()
        inconsistent.to_draft()
        states = {}
        for name, world, head in (("valid", valid, H), ("stale", stale_head, H), ("stale-epoch", stale_epoch, H),
                                  ("untrusted", untrusted, H), ("absent", absent, H), ("inconsistent", inconsistent, H)):
            result = rs.assess(head, world.view_labels(), world.s["events"], VIEWER)
            states[name] = result.state
            self.assertEqual(world.latest_ready(), result.ready_event, name)
        self.assertEqual({name: name for name in states}, states)
        # No Ready transition at all: nothing to report.
        self.assertIsNone(assess(rw.World()).ready_event)

    def test_a_malformed_marker_line_is_no_marker(self):
        world = rw.World()
        world.ready()
        world.comment(f"<!-- pr-ready:verified head={H.upper()} ready={world.latest_ready()} by=pr-ready -->")
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

    def sign_after(self, index, ready=rw.REAL_LAST_READY):
        """The capture's events with a signal (comment, label) inserted after position `index`, built from the real
        events' own shapes: the real `commented` and `labeled` events with the signal's content. The marker
        certifies the Ready transition `ready` (a real event id)."""
        comment = copy.deepcopy(next(e for e in self.events if e["event"] == "commented"))
        comment.update(id=1, body=rs.marker_comment(H, rs.PR_READY, ready))
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
        result = rs.assess(H, self.labels(rs.LABEL), events, VIEWER)
        self.assertEqual(("valid", rw.REAL_LAST_READY, rw.REAL_LAST_READY), (result.state, result.marker_ready,
                                                                          result.ready_event))
        # And only for the account that wrote it.
        self.assertEqual("untrusted", rs.assess(H, self.labels(rs.LABEL), events, OTHER).state)

    def test_a_signal_before_the_real_last_ready_transition_is_stale_epoch(self):
        # After the first ready_for_review and its comment: the label predates the second Ready transition.
        events = self.sign_after(1, rw.REAL_FIRST_READY)
        result = rs.assess(H, self.labels(rs.LABEL), events, VIEWER)
        self.assertEqual("stale-epoch", result.state)
        self.assertIn("added before the PR's last Ready transition", result.reason)

    def test_only_the_real_last_ready_transitions_id_certifies_it(self):
        # The marker sits after the last Ready transition and the PR is at its HEAD. The id of the first Ready
        # transition, of the Draft conversion between them, of a real label event and of a real comment (another id
        # space: the comment's id is smaller than all event ids) are all other events than the last Ready: stale-epoch.
        events_after = len(self.events) - 1
        for name, ident in {"the first Ready transition": rw.REAL_FIRST_READY,
                            "the Draft conversion": rw.REAL_DRAFT, "a label event": rw.REAL_LABELED,
                            "a comment": rw.REAL_COMMENT}.items():
            with self.subTest(name):
                result = rs.assess(H, self.labels(rs.LABEL), self.sign_after(events_after, ident), VIEWER)
                self.assertEqual("stale-epoch", result.state, result.reason)
                self.assertEqual((ident, rw.REAL_LAST_READY), (result.marker_ready, result.ready_event))
                self.assertIn(f"certifies Ready transition {ident}, but the PR's last Ready transition is "
                              f"{rw.REAL_LAST_READY}", result.reason)
        # Control: the last Ready transition's own id.
        self.assertEqual("valid", rs.assess(H, self.labels(rs.LABEL), self.sign_after(events_after), VIEWER).state)

    def test_the_real_capture_ids_are_the_ones_the_model_names(self):
        by_event = {}
        for event in self.events:
            by_event.setdefault(event["event"], []).append(event["id"])
        self.assertEqual([rw.REAL_FIRST_READY, rw.REAL_LAST_READY], by_event["ready_for_review"])
        self.assertEqual([rw.REAL_DRAFT], by_event["convert_to_draft"])
        self.assertEqual([rw.REAL_LABELED], by_event["labeled"])
        self.assertIn(rw.REAL_COMMENT, by_event["commented"])

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

    def test_a_clean_draft_returns_the_baseline_and_removes_nothing(self):
        world = rw.World()
        self.assertEqual(rs.Baseline(VIEWER, frozenset()), self.run_prepare(world))
        # The timeline read is the last step: the baseline is what the Draft looks like right before Ready.
        self.assertEqual(["label-exists", "user", "pr-view", "timeline"], world.calls())

    def test_the_baseline_is_the_ready_and_draft_transitions_of_the_draft(self):
        world = rw.World()
        first = world.ready()
        world.comment("review", actor=OTHER)
        draft = world.to_draft()
        world.label(name="merge-queue")
        world.label(add=False, name="merge-queue")
        baseline = self.run_prepare(world)
        self.assertIsInstance(baseline, rs.Baseline)
        self.assertEqual(VIEWER, baseline.viewer)
        # Only Ready and Draft transitions, as (kind, event id): a comment or a label event is no transition.
        self.assertEqual(frozenset({("ready_for_review", first["id"]), ("convert_to_draft", draft["id"])}),
                         baseline.transitions)
        with self.assertRaises(Exception):  # frozen: what write compares against cannot be edited in place
            baseline.viewer = OTHER

    def test_the_baseline_is_read_after_the_stale_label_was_removed(self):
        world = signed()
        world.to_draft()
        baseline = self.run_prepare(world)
        self.assertEqual(["label-exists", "user", "pr-view", "remove-label", "pr-view", "timeline"], world.calls())
        self.assertEqual({"ready_for_review", "convert_to_draft"}, {kind for kind, _ in baseline.transitions})

    def test_a_failing_baseline_read_is_an_error_and_no_baseline(self):
        world = rw.World().fail("timeline")
        client = rw.Client(world)
        with self.assertRaises(client.GitHubError):
            self.run_prepare(world)
        self.assertEqual(["label-exists", "user", "pr-view", "timeline"], world.calls())

    def test_a_transition_without_an_integer_id_is_no_baseline(self):
        for kind in ("ready_for_review", "convert_to_draft"):
            for bad in (True, "7", 0, None):
                with self.subTest(kind=kind, id=bad):
                    world = rw.World()
                    world.add(kind).update(id=bad)
                    world.s["draft"] = True  # still a Draft: the refusal is about the id, not about a Ready PR
                    with self.assertRaises(rs.SignalError) as raised:
                        self.run_prepare(world)
                    self.assertIn("no valid integer id", str(raised.exception))

    def test_a_stale_label_is_removed_from_the_draft_and_the_removal_confirmed(self):
        world = signed()
        world.to_draft()  # the label stays on the Draft
        self.assertEqual([rs.LABEL], world.label_names())
        sleeps = []
        self.assertEqual(VIEWER, self.run_prepare(world, sleeps=sleeps).viewer)
        self.assertEqual(["label-exists", "user", "pr-view", "remove-label", "pr-view", "timeline"], world.calls())
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
    UNSET = object()

    def run_write(self, world, *, head=H, producer=rs.PR_READY, baseline=UNSET, sleeps=None, client=None):
        client = client or rw.Client(world)
        slept = [] if sleeps is None else sleeps
        baseline = rs.Baseline(VIEWER, frozenset()) if baseline is self.UNSET else baseline
        return rs.write(client, client.Repo.parse("acme/repo"), 7, head, producer, baseline, sleep=slept.append)

    def ready_world(self):
        world = rw.World(head=H)
        world.ready()
        return world

    def test_the_transition_is_identified_first_then_the_comment_the_label_and_the_read_back(self):
        world = self.ready_world()
        result = self.run_write(world)
        self.assertEqual(["timeline", "comment", "add-label", "pr-view", "timeline"], world.calls())
        self.assertEqual(("valid", H, rs.PR_READY), (result.state, result.marker_head, result.producer))
        ready = world.s["events"][0]["id"]
        self.assertEqual((ready, ready), (result.marker_ready, result.ready_event))
        events = world.s["events"][1:]
        self.assertEqual(["commented", "labeled"], [e["event"] for e in events])
        self.assertEqual(rs.marker_comment(H, rs.PR_READY, ready), events[0]["body"])
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
        self.assertEqual(["timeline", "comment"], world.calls())
        self.assertEqual([], world.label_names())

    def test_a_failing_label_leaves_a_comment_that_alone_is_no_signal(self):
        world = self.ready_world().fail("add-label")
        client = rw.Client(world)
        with self.assertRaises(client.GitHubError):
            self.run_write(world)
        self.assertEqual(["timeline", "comment", "add-label"], world.calls())
        self.assertEqual("absent", assess(world).state)

    def test_the_read_back_waits_for_a_lagging_label_within_the_bound(self):
        world = self.ready_world()
        world.s["flags"]["lag"] = rs.READ_TRIES - 1
        sleeps = []
        result = self.run_write(world, sleeps=sleeps)
        self.assertTrue(result.valid)
        self.assertEqual(1 + rs.READ_TRIES, world.calls().count("timeline"))  # the identify read and the read-back's
        self.assertEqual([rs.READ_INTERVAL] * (rs.READ_TRIES - 1), sleeps)

    def test_a_signal_that_never_reads_back_is_an_error_after_exactly_the_bound(self):
        world = self.ready_world()
        world.s["flags"]["lag"] = rs.READ_TRIES
        sleeps = []
        with self.assertRaises(rs.SignalError) as raised:
            self.run_write(world, sleeps=sleeps)
        self.assertEqual(1 + rs.READ_TRIES, world.calls().count("timeline"))
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
            self.run_write(self.ready_world(), baseline=rs.Baseline(OTHER, frozenset()))
        self.assertIn("last: untrusted", str(raised.exception))

    def test_a_malformed_timeline_before_anything_is_written_is_an_immediate_error_not_a_retry(self):
        world = self.ready_world()
        world.s["events"].append({"id": 1})
        sleeps = []
        with self.assertRaises(rs.SignalError) as raised:
            self.run_write(world, sleeps=sleeps)
        self.assertIn("is not an event object", str(raised.exception))
        self.assertEqual([], sleeps)
        self.assertEqual(["timeline"], world.calls())  # the identify read refused: nothing was written

    def test_a_malformed_timeline_at_the_read_back_is_an_immediate_error_not_a_retry(self):
        world = self.ready_world()
        client = FlakyTimeline(world, on_read=2, answer=lambda events: events + [{"id": 1}])
        sleeps = []
        with self.assertRaises(rs.SignalError) as raised:
            self.run_write(world, sleeps=sleeps, client=client)
        self.assertIn("is not an event object", str(raised.exception))
        self.assertEqual([], sleeps)
        self.assertEqual(["timeline", "comment", "add-label", "pr-view", "timeline"], world.calls())

    def test_a_failing_identify_read_writes_nothing(self):
        world = self.ready_world().fail("timeline")
        client = rw.Client(world)
        with self.assertRaises(client.GitHubError):
            self.run_write(world)
        self.assertEqual(["timeline"], world.calls())

    def test_a_failing_read_back_is_the_clients_error(self):
        world = self.ready_world()
        client = FlakyTimeline(world, on_read=2, answer=None)  # the read-back's timeline read fails
        with self.assertRaises(client.GitHubError):
            self.run_write(world, client=client)
        self.assertEqual(["timeline", "comment", "add-label", "pr-view", "timeline"], world.calls())

    def test_bad_arguments_are_refused_before_any_call(self):
        good = rs.Baseline(VIEWER, frozenset())
        for kwargs, error in (({"producer": "someone"}, ValueError), ({"head": "main"}, rs.SignalError),
                              ({"head": None}, rs.SignalError), ({"baseline": VIEWER}, ValueError),
                              ({"baseline": None}, ValueError), ({"baseline": (VIEWER, frozenset())}, ValueError),
                              ({"baseline": {"viewer": VIEWER, "transitions": frozenset()}}, ValueError)):
            with self.subTest(kwargs):
                world = self.ready_world()
                with self.assertRaises(error):
                    self.run_write(world, **{"baseline": good, **kwargs})
                self.assertEqual([], world.calls())
                self.assertEqual([], [e for e in world.s["events"] if e["event"] in ("commented", "labeled")])

    def test_an_uppercase_head_is_written_lowercase(self):
        world = self.ready_world()
        self.assertTrue(self.run_write(world, head=H.upper()).valid)
        self.assertIn(f"head={H} ", world.s["events"][1]["body"])


class FlakyTimeline(rw.Client):
    """A `Client` whose `on_read`-th timeline read is altered: `answer(events)` is returned instead of the events, or the
    read fails with the client's error when `answer` is None. The reads before it are the model's."""

    def __init__(self, world, *, on_read, answer):
        super().__init__(world)
        self.on_read, self.answer, self.reads = on_read, answer, 0

    def timeline_events(self, repo, number):
        self.reads += 1
        events = super().timeline_events(repo, number)
        if self.reads == self.on_read:
            if self.answer is None:
                raise self.GitHubError("injected failure of the read-back")
            return self.answer(events)
        return events


class ProducerPlacementTests(unittest.TestCase):
    def test_prepare_and_write_compose_the_way_a_producer_calls_them(self):
        # prepare on the Draft, the Ready transition, write on the Ready PR: the sequence both producers run.
        world = rw.World(head=H)
        client = rw.Client(world)
        repo = client.Repo.parse("acme/repo")
        baseline = rs.prepare(client, repo, 7, sleep=lambda _s: None)
        ready = world.ready()
        result = rs.write(client, repo, 7, H, rs.ISSUE_TO_PR, baseline, sleep=lambda _s: None)
        self.assertEqual(("valid", ready["id"]), (result.state, result.marker_ready))
        self.assertEqual("valid", assess(world).state)

    def test_a_second_epoch_removes_the_first_epochs_label_and_signs_only_the_new_ready_transition(self):
        world = signed()
        first = world.latest_ready()
        world.to_draft()
        client = rw.Client(world)
        repo = client.Repo.parse("acme/repo")
        baseline = rs.prepare(client, repo, 7, sleep=lambda _s: None)
        second = world.ready()["id"]
        self.assertEqual("absent", assess(world).state)  # the first epoch's label is gone; the new one comes with write
        result = rs.write(client, repo, 7, H, rs.PR_READY, baseline, sleep=lambda _s: None)
        self.assertEqual(("valid", second), (result.state, result.marker_ready))
        self.assertNotEqual(first, result.marker_ready)
        # The first epoch's signal comment is still there and certifies the first transition: it never counts again.
        bodies = [e["body"] for e in world.s["events"] if e["event"] == "commented"]
        self.assertEqual([first, second], [int(rs.MARKER.search(b).group(2)) for b in bodies])


class EpochInterleavingTests(unittest.TestCase):
    """A signal certifies the ONE Ready transition the producer verified (the module docstring). Somebody with write
    access (the maintainer uses the producers' account) converts the PR to Draft and makes it Ready again at each
    point between `gh pr ready` and the end of `write`, and nothing is signed for a transition nobody verified.

    The producer's steps are real: `prepare` on the Draft, `gh pr ready` (the model's `ready()`), `write`. The change in
    between is injected by `World.inject`, which runs it when the nth following operation starts, before its effect.
    Every case ends with what a consumer (`assess`) says about the PR afterwards.
    """

    def begin(self):
        """A Draft PR at H after `prepare`; returns (world, client, repo, baseline)."""
        world = rw.World(head=H)
        client = rw.Client(world)
        repo = client.Repo.parse("acme/repo")
        return world, client, repo, rs.prepare(client, repo, 7, sleep=lambda _s: None)

    @staticmethod
    def written(world):
        """The signal artefacts on the timeline: comments by the viewer and label events."""
        return [e["event"] for e in world.s["events"] if e["event"] in ("commented", "labeled", "unlabeled")]

    def write(self, world, client, repo, baseline, **kwargs):
        with rw.read_back_sleeps() as sleeps:
            try:
                result = rs.write(client, repo, 7, kwargs.get("head", H), rs.PR_READY, baseline)
                error = None
            except rs.SignalError as exc:
                result, error = None, exc
        return result, error, sleeps

    # -- before the identify read: two new Ready transitions ----------------------------------------------------
    def test_two_new_ready_transitions_at_the_identify_read_are_refused_and_nothing_is_written(self):
        world, client, repo, baseline = self.begin()
        world.ready()  # the transition the producer's `gh pr ready` made and its post-action check saw
        world.inject("timeline", 1, ["draft", "ready"])  # ... then somebody cycles the PR before write reads
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(result)
        self.assertIn("went through Draft and Ready again", str(error))
        self.assertIn("nothing was signed", str(error))
        self.assertEqual([], self.written(world))
        self.assertEqual([], world.label_names())
        self.assertEqual(["label-exists", "user", "pr-view", "timeline", "timeline"], world.calls())
        self.assertEqual([], sleeps)  # a refusal is final, not a lag to wait out
        # The PR is Ready (the second transition) with no signal: no consumer acts on it.
        self.assertEqual("absent", assess(world).state)

    def test_the_control_one_new_ready_transition_is_signed(self):
        world, client, repo, baseline = self.begin()
        first = world.ready()["id"]
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(error)
        self.assertEqual((True, first), (result.valid, result.marker_ready))
        self.assertEqual("valid", assess(world).state)

    def test_a_person_making_the_pr_ready_before_the_gates_ready_call_is_signed_as_that_transition(self):
        # ACCEPTED BEHAVIOUR, pinned (R3). `prepare` runs on the Draft; a person then makes the PR Ready; the gate's
        # `gh pr ready` that follows is a no-op (the PR is already Ready), so the timeline gets ONE new Ready transition
        # and it is the person's. `write` signs it: the gate's preflight (CI, review, mergeability at this HEAD) ran
        # before and its post-action verification runs after that call, and both cover exactly the HEAD the signal names,
        # so the signal says what it always says (this HEAD passed the gate and the PR is Ready at it). Refusing would
        # leave a Ready PR without a signal for a harmless reorder; a second transition (a cycle) is still refused.
        world, client, repo, baseline = self.begin()
        persons = world.ready()["id"]  # the person's click, between `prepare` and the gate's `gh pr ready`
        # the gate's `gh pr ready` on an already Ready PR changes nothing: no event is added
        ready_events = [e["id"] for e in world.s["events"] if e["event"] == "ready_for_review"]
        self.assertEqual([persons], ready_events)
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(error)
        self.assertEqual((True, persons), (result.valid, result.marker_ready))
        self.assertEqual(["comment", "add-label"], [c for c in world.calls() if c in ("comment", "add-label")])
        self.assertEqual("valid", assess(world).state)
        self.assertEqual([], sleeps)

    def test_a_draft_after_the_new_ready_transition_at_the_identify_read_is_refused_and_nothing_is_written(self):
        world, client, repo, baseline = self.begin()
        world.ready()
        world.inject("timeline", 1, ["draft"])
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(result)
        self.assertIn("was converted to Draft after Ready transition", str(error))
        self.assertEqual([], self.written(world))
        self.assertEqual([], sleeps)

    # -- before the comment: the finding ------------------------------------------------------------------------
    def test_a_cycle_before_the_comment_is_refused_without_waiting_and_no_consumer_acts_on_it(self):
        world, client, repo, baseline = self.begin()
        verified = world.ready()["id"]
        world.inject("comment", 1, ["draft", "ready"])  # between the identify read and the comment: the window
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(result)
        self.assertIn(f"Ready transition {verified} was superseded", str(error))
        self.assertEqual([], sleeps, "a superseded epoch can only get worse: no retry")
        # An exact read count: prepare's timeline, identify's, and ONE read-back (not READ_TRIES of them).
        self.assertEqual(["label-exists", "user", "pr-view", "timeline", "timeline", "comment", "add-label", "pr-view",
                          "timeline"], world.calls())
        result = assess(world)
        self.assertEqual("stale-epoch", result.state)  # not `stale`: a consumer must not carry it across a base import
        self.assertEqual((verified, world.latest_ready()), (result.marker_ready, result.ready_event))
        self.assertIn(f"certifies Ready transition {verified}, but the PR's last Ready transition is "
                      f"{world.latest_ready()}", result.reason)
        self.assertNotEqual(verified, world.latest_ready())

    def test_a_draft_push_ready_before_the_comment_is_stale_epoch_and_not_stale(self):
        # Draft, a push to H2, Ready: the producer refuses, and the signal it left (for H) reads stale-epoch at H2.
        # `stale` would be carried across a base import or an evidence-only change by the actor: stale-epoch is not.
        world, client, repo, baseline = self.begin()
        verified = world.ready()["id"]
        world.inject("comment", 1, ["draft", "head=" + OLD, "ready"])
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(result)
        self.assertEqual([], sleeps)
        state = assess(world, head=OLD)
        self.assertEqual("stale-epoch", state.state, state.reason)
        self.assertEqual((H, verified), (state.marker_head, state.marker_ready))
        # Control: the same push with NO new Ready transition is a stale signal (the actor's carry case).
        control, client2, repo2, baseline2 = self.begin()
        control.ready()
        control.inject("comment", 1, ["head=" + OLD])
        result, error, _ = self.write(control, client2, repo2, baseline2)
        self.assertIsNone(result)  # the write itself fails to confirm for the HEAD it verified ...
        self.assertEqual("stale", assess(control, head=OLD).state)  # ... and the signal it left is the carried kind

    # -- between the comment and the label ----------------------------------------------------------------------
    def test_a_cycle_between_the_comment_and_the_label_leaves_no_signal(self):
        world, client, repo, baseline = self.begin()
        verified = world.ready()["id"]
        world.inject("add-label", 1, ["draft", "ready"])
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(result)
        self.assertIn(f"Ready transition {verified} was superseded", str(error))
        self.assertEqual([], sleeps)
        # The comment is before the new Ready transition and the label after it: nothing counts.
        self.assertEqual(["commented", "labeled"], self.written(world))
        self.assertEqual("absent", assess(world).state)

    # -- between the label and the read-back --------------------------------------------------------------------
    def test_a_cycle_between_the_label_and_the_read_back_is_refused_and_reads_stale_epoch(self):
        world, client, repo, baseline = self.begin()
        world.ready()
        world.inject("pr-view", 1, ["draft", "ready"])  # the read-back's first read
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(result)
        self.assertIn("was superseded", str(error))
        self.assertEqual([], sleeps)
        self.assertEqual(["timeline", "comment", "add-label", "pr-view", "timeline"], world.calls()[4:])
        self.assertEqual("stale-epoch", assess(world).state)  # the label predates the new Ready transition

    # -- after the read-back ------------------------------------------------------------------------------------
    def test_a_cycle_after_the_read_back_does_not_undo_the_producers_success_but_ends_the_signal(self):
        world, client, repo, baseline = self.begin()
        world.ready()
        result, error, _ = self.write(world, client, repo, baseline)
        self.assertEqual((None, True), (error, result.valid))
        world.to_draft()
        world.ready()
        self.assertEqual("stale-epoch", assess(world).state)

    # -- the other shapes of "not exactly one new Ready transition" ----------------------------------------------
    def test_a_draft_alone_before_the_comment_is_refused(self):
        world, client, repo, baseline = self.begin()
        verified = world.ready()["id"]
        world.inject("comment", 1, ["draft"])
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(result)
        self.assertIn(f"Ready transition {verified} was superseded", str(error))
        self.assertEqual([], sleeps)
        self.assertEqual("inconsistent", assess(world).state)

    def test_no_new_ready_transition_is_refused_after_exactly_the_bound_and_nothing_is_written(self):
        world, client, repo, baseline = self.begin()  # the PR never became Ready on the timeline
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(result)
        self.assertIn(f"no Ready transition after the verified Draft shows on the timeline after {rs.READ_TRIES} "
                      "reads", str(error))
        self.assertEqual(rs.READ_TRIES, world.calls().count("timeline") - 1)  # minus prepare's
        self.assertEqual([rs.READ_INTERVAL] * (rs.READ_TRIES - 1), sleeps)
        self.assertEqual([], self.written(world))

    def test_a_ready_transition_that_shows_late_is_found_within_the_bound(self):
        for lag, ok in ((rs.READ_TRIES - 1, True), (rs.READ_TRIES, False)):
            with self.subTest(lag=lag):
                world, client, repo, baseline = self.begin()
                late = world.add("ready_for_review", lag=lag)["id"]
                result, error, sleeps = self.write(world, client, repo, baseline)
                reads = min(lag + 1, rs.READ_TRIES)
                self.assertEqual([rs.READ_INTERVAL] * (reads - 1), sleeps[:reads - 1])
                if ok:
                    self.assertIsNone(error)
                    self.assertEqual(late, result.marker_ready)
                else:
                    self.assertIsNone(result)
                    self.assertIn("no Ready transition", str(error))
                    self.assertEqual([], self.written(world))

    def test_an_older_draft_that_shows_late_is_not_a_cycle(self):
        # The baseline read missed an older Draft conversion (read lag); it shows at the identify read, positioned
        # BEFORE the Ready transition that was verified: tolerated, the Ready transition is the one.
        world = rw.World(head=H)
        world.ready()
        world.add("convert_to_draft", lag=1)  # the first (baseline) read does not show it
        client = rw.Client(world)
        repo = client.Repo.parse("acme/repo")
        baseline = rs.prepare(client, repo, 7, sleep=lambda _s: None)
        self.assertEqual(1, len(baseline.transitions))
        verified = world.ready()["id"]
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(error)
        self.assertEqual(verified, result.marker_ready)
        self.assertEqual([], sleeps)

    def test_a_lagging_label_is_waited_for_when_the_pr_has_an_earlier_history(self):
        # The control of the fail-fast: only a transition AFTER the certified one ends the wait. Earlier Ready and Draft
        # events (the PR's history, known to the baseline) are on the timeline of every read-back.
        world = rw.World(head=H)
        world.signed_ready()
        world.to_draft()
        client = rw.Client(world)
        repo = client.Repo.parse("acme/repo")
        baseline = rs.prepare(client, repo, 7, sleep=lambda _s: None)
        verified = world.ready()["id"]
        world.s["flags"]["lag"] = 2  # the label shows from the third read-back on
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(error)
        self.assertEqual(verified, result.marker_ready)
        self.assertEqual([rs.READ_INTERVAL] * 2, sleeps)

    def test_comment_and_label_events_after_the_ready_transition_are_not_candidates(self):
        world, client, repo, baseline = self.begin()
        verified = world.ready()["id"]
        world.comment("## Automated PR review: Draft", actor=OTHER)
        world.label(name="merge-queue")
        world.comment("## Merge train: enqueued")
        world.label(add=False, name="merge-queue")
        result, error, _ = self.write(world, client, repo, baseline)
        self.assertIsNone(error)
        self.assertEqual(verified, result.marker_ready)

    def test_a_valid_signal_for_another_transition_is_not_this_producers_success(self):
        # While the read-back runs another producer run (or a person) cycles the PR and signs the NEW Ready transition.
        # The consumers see a valid signal; the producer that verified the first transition must not report success.
        world, client, repo, baseline = self.begin()
        verified = world.ready()["id"]
        world.inject("pr-view", 1, ["draft", "ready", "sign"])
        result, error, sleeps = self.write(world, client, repo, baseline)
        self.assertIsNone(result)
        self.assertIn(f"Ready transition {verified} was superseded", str(error))
        self.assertEqual([], sleeps)
        other = assess(world)
        self.assertEqual("valid", other.state)  # the other transition's signal is a good one
        self.assertNotEqual(verified, other.marker_ready)

    def test_write_takes_the_baseline_and_not_the_viewer(self):
        world, client, repo, baseline = self.begin()
        world.ready()
        calls = list(world.calls())
        for bad in (VIEWER, None, (VIEWER, baseline.transitions)):
            with self.assertRaises(ValueError):
                rs.write(client, repo, 7, H, rs.PR_READY, bad, sleep=lambda _s: None)
        self.assertEqual(calls, world.calls())

    def test_a_baseline_that_misses_the_history_refuses_instead_of_guessing(self):
        # The control of the "latest Ready at write time" shortcut: a PR with history, a baseline that does not know it.
        world = rw.World(head=H)
        world.signed_ready()
        world.to_draft()
        client = rw.Client(world)
        repo = client.Repo.parse("acme/repo")
        real = rs.prepare(client, repo, 7, sleep=lambda _s: None)
        self.assertEqual(2, len(real.transitions))
        new = world.ready()["id"]
        empty = rs.Baseline(VIEWER, frozenset())
        result, error, _ = self.write(world, client, repo, empty)
        self.assertIsNone(result)
        self.assertIn("went through Draft and Ready again", str(error))
        # With the real baseline the same PR signs exactly the new transition.
        result, error, _ = self.write(world, client, repo, real)
        self.assertIsNone(error)
        self.assertEqual(new, result.marker_ready)


class InjectionHookTests(unittest.TestCase):
    """The model's own gate: `World.inject` runs its actions when the nth following operation starts, BEFORE that
    operation's effect, through both adapters, and not before or after (the interleaving tests rely on it)."""

    def test_the_client_runs_the_actions_before_the_effect_of_the_nth_operation_only(self):
        world = rw.World(head=H)
        world.ready()
        world.inject("comment", 2, ["draft", "head=" + OLD, "ready"])
        client = rw.Client(world)
        repo = client.Repo.parse("acme/repo")
        client.post_comment(repo, 7, "first")
        self.assertEqual(["ready_for_review", "commented"], [e["event"] for e in world.s["events"]])
        client.pr_view(repo, 7)  # another operation is not the comment
        self.assertEqual(H, world.s["head"])
        client.post_comment(repo, 7, "second")
        self.assertEqual(["ready_for_review", "commented", "convert_to_draft", "ready_for_review", "commented"],
                         [e["event"] for e in world.s["events"]], "the cycle is between the first comment and the second")
        self.assertEqual("second", world.s["events"][-1]["body"])
        self.assertEqual(OLD, world.s["head"])
        client.post_comment(repo, 7, "third")  # a hook runs once
        self.assertEqual(6, len(world.s["events"]))
        self.assertEqual(["comment", "pr-view", "comment", "comment"], world.calls(), "actions are not operations")

    def test_nth_counts_from_the_call_to_inject(self):
        world = rw.World(head=H)
        client = rw.Client(world)
        repo = client.Repo.parse("acme/repo")
        client.timeline_events(repo, 7)
        client.timeline_events(repo, 7)
        world.inject("timeline", 1, ["ready"])  # the NEXT timeline read, not the first one of the world's life
        self.assertEqual([], world.s["events"])
        client.timeline_events(repo, 7)
        self.assertEqual(["ready_for_review"], [e["event"] for e in world.s["events"]])

    def test_the_fake_gh_adapter_runs_the_same_hook_before_its_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            body = state / "body.md"
            body.write_text("a comment", encoding="utf-8")
            world = rw.World(head=H)
            world.ready()
            world.inject("comment", 1, ["draft", "ready"]).inject("timeline", 1, ["head=" + OLD])
            world.save(state)
            self.assertEqual(0, rw.handle(["pr", "comment", "7", "--body-file", str(body)], state))
            after = rw.World.load(state)
            self.assertEqual(["ready_for_review", "convert_to_draft", "ready_for_review", "commented"],
                             [e["event"] for e in after.s["events"]])
            self.assertEqual(H, after.s["head"])
            rw.view_labels(state)  # a pr view is not a timeline read
            self.assertEqual(H, rw.World.load(state).s["head"])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, rw.handle(["api", "--paginate", "--slurp", "repos/acme/repo/issues/7/timeline?per_page=100"],
                                              state))
            self.assertEqual(OLD, rw.World.load(state).s["head"])
            self.assertEqual(["comment", "pr-view", "timeline"], rw.calls(state))

    def test_an_unknown_action_is_refused_when_it_is_registered(self):
        for bad in ([], ["nothing"], ["head"], ["READY"]):
            with self.subTest(actions=bad), self.assertRaises(AssertionError):
                rw.World().inject("comment", 1, bad)
        with self.assertRaises(AssertionError):
            rw.World().inject("comment", 0, ["ready"])


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
        self.assertTrue(re.fullmatch(rs.MARKER.pattern, rs.marker_line(H, rs.PR_READY, R)))

    OPENER = "<!-- pr-ready:verified"
    FIELDS = ("head=", "ready=", "by=")

    @staticmethod
    def documents(root):
        """Every Markdown file under `.agents/` plus the root README: the documents that spell the marker."""
        return sorted(root.glob(".agents/**/*.md")) + sorted(root.glob("README.md"))

    @classmethod
    def misspelt(cls, text):
        """The marker spellings in `text` that do not name `head=`, `ready=` and `by=` in that order before `-->`."""
        found, at = [], text.find(cls.OPENER)
        while at != -1:
            end = text.find("-->", at)
            spelling = text[at:end] if end != -1 and end - at <= 400 else text[at:at + 120]
            places = [spelling.find(field) for field in cls.FIELDS]
            if end == -1 or end - at > 400 or -1 in places or places != sorted(places):
                found.append(" ".join(spelling.split()))
            at = text.find(cls.OPENER, at + len(cls.OPENER))
        return found

    @classmethod
    def mentions(cls, root):
        return {f.relative_to(root).as_posix(): f.read_text(encoding="utf-8").count(cls.OPENER)
                for f in cls.documents(root) if cls.OPENER in f.read_text(encoding="utf-8")}

    def test_docs_spell_the_marker_with_every_field(self):
        # The marker certifies a Ready transition: a document that still shows `head=` then `by=` teaches a hand-signer
        # (or a reader of the grammar) a marker that `ready_signal.MARKER` rejects.
        mentions = self.mentions(REPO_ROOT)
        self.assertTrue(mentions, "no document mentions the marker: the scan covers nothing")
        bad = {name: spellings for name in mentions
               if (spellings := self.misspelt((REPO_ROOT / name).read_text(encoding="utf-8")))}
        self.assertEqual({}, bad)

    def test_the_docs_guard_fails_on_the_old_grammar_and_passes_on_the_new_one(self):
        old = f"sign it: `{self.OPENER} head=<sha> by=maintainer -->`"
        self.assertEqual([f"{self.OPENER} head=<sha> by=maintainer"], self.misspelt(old))
        swapped = f"{self.OPENER} ready=<id> head=<sha> by=maintainer -->"
        self.assertEqual([f"{self.OPENER} ready=<id> head=<sha> by=maintainer"], self.misspelt(swapped))
        self.assertEqual([f"{self.OPENER} head=<sha> ready=<id>"], self.misspelt(f"{self.OPENER} head=<sha> ready=<id> -->"))
        self.assertEqual([], self.misspelt(f"{self.OPENER} head=<40 hex, lower> ready=<id> by=<producer> -->"))
        # One good and one old spelling in the same file: the old one is still found.
        both = f"`{self.OPENER} head=<h> ready=<id> by=x -->` and `{self.OPENER} head=<h> by=x -->`"
        self.assertEqual([f"{self.OPENER} head=<h> by=x"], self.misspelt(both))
        # An opener with no closing `-->` is a refusal too.
        self.assertEqual(1, len(self.misspelt(f"{self.OPENER} head=<h> ready=<id> by=x")))

    def test_the_docs_guard_scans_the_skill_documents_and_the_readme(self):
        names = set(self.mentions(REPO_ROOT))
        for needed in (".agents/skills/pr-ready/README.md", ".agents/skills/pr-ready/SKILL.md",
                       ".agents/skills/issue-to-pr/SKILL.md", ".agents/skills/pr-review-merge/SKILL.md"):
            self.assertIn(needed, names)


class ModelImportCostTests(unittest.TestCase):
    """A fake `gh` is a new interpreter per call, with no bytecode cache, and imports the model on the calls that need
    it: what the model imports at the top is a cost of each of them. `unittest.mock` and `ready_signal` (with its
    `dataclasses`) there made a fake call take 60 ms instead of 23 and the pr-ready suite twice as long."""

    HEAVY = ("unittest.mock", "asyncio", "dataclasses", "ready_signal")

    def test_importing_the_model_leaves_the_heavy_modules_to_the_functions_that_need_them(self):
        code = (f"import sys; sys.path.insert(0, {str(HERE)!r}); import ready_signal_world; "
                f"print(sorted(m for m in {self.HEAVY!r} if m in sys.modules))")
        done = subprocess.run([sys.executable, "-S", "-c", code], capture_output=True, text=True, check=True)
        self.assertEqual("[]", done.stdout.strip())
        # The control: the same probe sees them once a function that needs them has run.
        code = code.replace("import ready_signal_world;", "import ready_signal_world; ready_signal_world.production();")
        done = subprocess.run([sys.executable, "-S", "-c", code], capture_output=True, text=True, check=True)
        self.assertIn("'ready_signal'", done.stdout)

    def test_the_names_read_as_attributes_are_still_the_production_module_and_its_label(self):
        self.assertIs(rs, rw.ready_signal)
        self.assertEqual(rs.LABEL, rw.LABEL)
        world = rw.World(head=H)
        world.signed_ready()  # no producer named: pr-ready's
        self.assertEqual(rs.PR_READY, assess(world).producer)
        with self.assertRaises(AttributeError):
            rw.nothing_of_the_kind


class ReadBackSleepsTests(unittest.TestCase):
    """`rw.read_back_sleeps` records the waits of the read-back and nothing else. `subprocess` waits for a child that
    is still running with `time.sleep` calls of its own (1 ms, 2 ms, ... up to its timeout), and a fake `gh` that is
    still exiting when its pipe closes costs the parent one: a recording by a global patch of `time.sleep` took them
    in, and the tests of the exact waits failed whenever the machine was busy."""

    @staticmethod
    def wait_for_a_running_child():
        child = subprocess.Popen([sys.executable, "-S", "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE)
        try:
            child.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            pass
        else:
            raise AssertionError("the child ended on its own")
        finally:
            child.communicate()

    def test_the_polling_of_subprocess_is_not_a_wait_of_the_read_back(self):
        with rw.read_back_sleeps() as sleeps:
            self.wait_for_a_running_child()
            rs.time.sleep(rs.READ_INTERVAL)
        self.assertEqual([rs.READ_INTERVAL], sleeps)
        self.assertIs(time, rs.time, "the module has its own `time` back")

    def test_the_control_a_global_patch_of_time_sleep_records_the_polling(self):
        with mock.patch("time.sleep") as sleep:
            self.wait_for_a_running_child()
            rs.time.sleep(rs.READ_INTERVAL)
        recorded = [call.args[0] for call in sleep.call_args_list]
        self.assertEqual(rs.READ_INTERVAL, recorded[-1])
        self.assertGreater(len(recorded), 2, "subprocess polled for the running child")
        self.assertLess(max(recorded[:-1]), 1, "short polls, none of them a wait of the read-back")

    def test_a_module_that_is_not_loaded_is_not_imported_for_the_recording(self):
        with mock.patch.dict(sys.modules):
            del sys.modules["ready_signal"]
            with rw.read_back_sleeps() as sleeps:
                self.assertNotIn("ready_signal", sys.modules)
            self.assertEqual([], sleeps)


if __name__ == "__main__":
    unittest.main()
