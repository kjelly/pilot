"""Test helper (not a test module): the ways a Ready PR can lack a valid signal, as ready_signal_world models.

Each builder returns the PR's `ready_signal_world.World` with the signal written for `head` by the account the
fakes run as (`prm-bot`, the fake `api user`); `CASES` names the state `ready_signal.assess` gives it and a
fragment of its reason. The oracle for a case is that module (`ready_signal.assess`), not this file.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Appended: _shared/tests has a test_secret_scan of its own, which must not shadow this directory's under discovery.
sys.path.append(str(Path(__file__).resolve().parents[2] / "_shared" / "tests"))
import ready_signal_world as rw  # noqa: E402
import ready_signal  # noqa: E402

VIEWER, OTHER = "prm-bot", rw.OTHER
LABEL = ready_signal.LABEL
# What a refusal tells the owner of the PR (the first words of review_gate.RECOVERY).
RECOVERY = ("Convert the PR to Draft and run `pr-ready` again",)


class Worlds:
    @staticmethod
    def world(head):
        return rw.World(head=head, viewer=VIEWER)

    @classmethod
    def valid(cls, head):
        world = cls.world(head)
        world.signed_ready()
        return world

    @classmethod
    def never_signed(cls, head):
        world = cls.world(head)
        world.ready()
        return world

    @classmethod
    def created_ready(cls, head):
        world = cls.world(head)      # a marker and a label, but the PR never was a Draft: no Ready transition
        world.signal(head, ready=rw.REAL_LAST_READY)
        return world

    @classmethod
    def label_by_another_account(cls, head):
        world = cls.world(head)
        world.ready()
        world.comment(ready_signal.marker_comment(head, ready_signal.PR_READY, world.latest_ready()))
        world.label(OTHER)
        return world

    @classmethod
    def marker_by_another_account(cls, head):
        world = cls.world(head)
        world.ready()
        world.comment(ready_signal.marker_comment(head, ready_signal.PR_READY, world.latest_ready()), OTHER)
        world.label()
        return world

    @classmethod
    def earlier_ready_epoch(cls, head):
        world = cls.world(head)      # signed, drafted, Ready again: the label was left on the Draft
        world.ready()
        world.signal(head)
        world.to_draft()
        world.ready()
        return world

    @classmethod
    def newer_ready_after_the_signal(cls, head):
        world = cls.world(head)      # the finding: the comment and the label are for a Ready transition that is not the last
        world.ready()
        first = world.latest_ready()
        world.to_draft()
        world.ready()
        world.signal(head, ready=first)
        return world

    @classmethod
    def draft_push_ready(cls, head):
        world = cls.world("c" * 40)  # signed at an earlier HEAD, Draft, a push (to `head`), Ready again, then the signal
        world.ready()
        first = world.latest_ready()
        world.to_draft()
        world.s["head"] = head
        world.ready()
        world.signal("c" * 40, ready=first)
        return world

    @classmethod
    def back_to_draft(cls, head):
        world = cls.world(head)
        world.ready()
        world.signal(head)
        world.to_draft()
        return world

    # name -> (builder, the state of `assess`, a fragment of its reason)
    CASES = {
        "no label": ("never_signed", "absent", f"does not carry the {LABEL} label"),
        "created Ready": ("created_ready", "absent", "no Ready transition from Draft"),
        "label by another account": ("label_by_another_account", "untrusted", f"was added by {OTHER}"),
        "marker by another account": ("marker_by_another_account", "absent", f"no signal comment by {VIEWER}"),
        "earlier Ready epoch": ("earlier_ready_epoch", "stale-epoch", "before the PR's last Ready transition"),
        "newer Ready after the signal": ("newer_ready_after_the_signal", "stale-epoch", "certifies Ready transition"),
        "Draft, base-import push, Ready": ("draft_push_ready", "stale-epoch", "certifies Ready transition"),
        "back to Draft": ("back_to_draft", "inconsistent", "converted to Draft after its last Ready transition"),
    }
