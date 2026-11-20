#!/usr/bin/env python3
"""The `pr-ready-verified` signal: proof that a Ready PR got there through a verified Draft -> Ready step.

A PR that is Ready for Review says "quality is already mergeable". Nothing used to tie that claim to the
gate that verifies it: a person clicking "Ready for review", or a script that ran `gh pr ready` without the
gate, produced the same state, and every consumer (pr-review-merge, scripts/pr_loop.py) acted on it. The
producers (pr-ready's pr_gate.py, issue-to-pr's mark_ready.py) now sign a Ready PR AFTER their post-action
verification succeeded, with two artefacts: a comment ending in a marker line that names the verified HEAD
and the producer, and the label `pr-ready-verified` (the commit point: it is added last). The consumers act
on a Ready PR only when `assess` says `valid`.

The signal is read from ONE timeline (label events, Ready/Draft transitions and comments share one order)
and trusts nothing a stranger can write:

  1. R is the latest `ready_for_review` event. None: `absent`. A `convert_to_draft` after R: `inconsistent`.
  2. The PR view has no label: `absent`.
  3. The last label event for the label is a removal, or there is none (the view is ahead of the
     timeline: GitHub read lag): `inconsistent`.
  4. The label was added before R (it was left on the PR while it was a Draft): `stale-epoch`.
  5. The label was added by another account than the viewer: `untrusted`.
  6. Only markers written by the viewer after R count; the newest wins. None: `absent`.
  7. The marker names another HEAD than the PR's: `stale`; otherwise `valid`.
  8. A relevant event with a malformed shape raises `SignalError` (fail closed).

The viewer is the login `gh` is authenticated as. Producer and consumer must authenticate as the same
account, otherwise every signal is refused. `maintainer` is the honest provenance of a signal a person
wrote by hand for a Ready PR that predates this check. A PR that was created Ready (never a Draft) has no
`ready_for_review` event and is ignored by design.

Standard library only. The functions that talk to GitHub take an injected `client` with the interface of
`pr-review-merge/scripts/gh_runtime.py` (`label_exists`, `viewer_login`, `pr_view`, `timeline_events`,
`edit_label`, `post_comment`), so tests never need the network.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Sequence

LABEL = "pr-ready-verified"
PR_READY, ISSUE_TO_PR, MAINTAINER = "pr-ready", "issue-to-pr", "maintainer"
PRODUCERS = (PR_READY, ISSUE_TO_PR, MAINTAINER)
# Strict on purpose: a full lowercase SHA, one of the producers, exactly this spacing. The alternation is built
# from PRODUCERS so a producer exists in one place.
MARKER = re.compile(r"<!-- pr-ready:verified head=([0-9a-f]{40}) by=("
                    + "|".join(re.escape(producer) for producer in PRODUCERS) + r") -->")
SHA = re.compile(r"[0-9a-f]{40}")

STATES = ("valid", "absent", "stale", "stale-epoch", "untrusted", "inconsistent")

# `write` and `prepare` re-read GitHub until it shows what they wrote (or removed): a write is visible to a
# following read after a short delay, not always at once. READ_TRIES reads, READ_INTERVAL seconds apart, bound
# the wait (25 s); a signal that cannot be confirmed in that time is reported, never assumed.
READ_TRIES = 6
READ_INTERVAL = 5.0


class SignalError(ValueError):
    """The signal cannot be written, removed, confirmed or read: a refusal, never a pass. A `ValueError` so
    the consumers' existing `except (GitHubError, ValueError)` handling covers it."""


@dataclass(frozen=True)
class Assessment:
    """What the timeline says about the signal of one PR at one HEAD.

    `head` is the PR HEAD that was assessed, `marker_head` and `producer` come from the marker that decided
    the answer (None while no marker was reached).
    """
    state: str
    reason: str
    head: str
    marker_head: str | None = None
    producer: str | None = None

    @property
    def valid(self) -> bool:
        return self.state == "valid"


def marker_line(head: str, producer: str) -> str:
    """The marker as it ends a signal comment; `MARKER` matches exactly this (the head is written lowercase)."""
    _check_producer(producer)
    return f"<!-- pr-ready:verified head={_check_head(head)} by={producer} -->"


def marker_comment(head: str, producer: str) -> str:
    """The comment a producer posts after a verified Ready transition: a short text for people, then the marker."""
    line = marker_line(head, producer)
    head = _check_head(head)
    return ("## Ready for Review: verified\n\n"
            f"Verified HEAD: `{head}`  \n"
            f"Verified by: `{producer}`\n\n"
            "The PR was a Draft, passed the Ready gate for exactly this commit, was converted to Ready for Review "
            "and the post-action check confirmed it is still Ready at this HEAD. The label "
            f"`{LABEL}` was added after this comment: automation that acts on Ready PRs "
            "(pr-review-merge, scripts/pr_loop.py) acts only on a PR that carries it.\n\n"
            "The signal is bound to this HEAD. A push that changes the PR's own commits makes it stale: it stays "
            "on the PR but no longer counts. Converting the PR to Draft ends it. To make a PR actionable again, "
            "convert it to Draft and run `pr-ready` again.\n\n"
            "This comment is an automated technical record, not a human approval.\n"
            f"{line}\n")


def _check_producer(producer: Any) -> None:
    if producer not in PRODUCERS:
        raise ValueError(f"unknown ready-signal producer {producer!r}; expected one of {', '.join(PRODUCERS)}")


def _check_head(head: Any) -> str:
    if not isinstance(head, str) or not SHA.fullmatch(head.lower()):
        raise SignalError(f"a PR HEAD must be a full 40-hex commit SHA, got {head!r}")
    return head.lower()


def _label_names(labels: Any) -> list[str]:
    """The label names of a `gh pr view --json labels` list; any other shape is an error, not "no labels"."""
    if not isinstance(labels, (list, tuple)):
        raise SignalError("the PR's labels are missing or malformed")
    names = []
    for item in labels:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise SignalError("a PR label entry is malformed")
        names.append(item["name"])
    return names


def _login(event: dict[str, Any], key: str, index: int) -> str | None:
    """The login in `event[key]`: None for a missing or null account (a deleted user), an error for any other shape."""
    account = event.get(key)
    if account is None:
        return None
    if not isinstance(account, dict) or not isinstance(account.get("login"), str) or not account["login"]:
        raise SignalError(f"timeline entry {index} ({event.get('event')}) has a malformed {key}")
    return account["login"]


def assess(head: str, labels: Sequence[dict[str, Any]], events: Sequence[dict[str, Any]], viewer: str) -> Assessment:
    """The state of the signal of a PR at `head`, from its view's labels and its whole timeline. Pure: no I/O.

    `events` is the full timeline, oldest first (`gh_runtime.timeline_events`). Event order, not time stamps,
    decides "before" and "after": GitHub stamps events with whole seconds.
    """
    head = _check_head(head)
    if not isinstance(viewer, str) or not viewer:
        raise SignalError("the authenticated account (viewer) is unknown")
    names = _label_names(labels)
    if not isinstance(events, (list, tuple)):
        raise SignalError("the PR's timeline is missing or malformed")

    ready_at = draft_at = None
    label_event: tuple[int, str, str | None] | None = None  # (position, "labeled" | "unlabeled", actor)
    viewer_comments: list[tuple[int, str]] = []  # (position, body) of the viewer's comments
    for index, event in enumerate(events):
        if not isinstance(event, dict) or not isinstance(event.get("event"), str):
            raise SignalError(f"timeline entry {index} is not an event object")
        kind = event["event"]
        if kind == "ready_for_review":
            ready_at = index
        elif kind == "convert_to_draft":
            draft_at = index
        elif kind in ("labeled", "unlabeled"):
            label = event.get("label")
            if not isinstance(label, dict) or not isinstance(label.get("name"), str):
                raise SignalError(f"timeline entry {index} ({kind}) has a malformed label")
            if label["name"] == LABEL:
                label_event = (index, kind, _login(event, "actor", index))
        elif kind == "commented":
            if _login(event, "user", index) == viewer:
                if not isinstance(event.get("body"), str):
                    raise SignalError(f"timeline entry {index} (commented) has a malformed body")
                viewer_comments.append((index, event["body"]))

    def result(state: str, reason: str, marker: tuple[str, str] | None = None) -> Assessment:
        return Assessment(state, reason, head, marker[0] if marker else None, marker[1] if marker else None)

    if ready_at is None:
        return result("absent", "no Ready transition from Draft on the PR's timeline")
    if draft_at is not None and draft_at > ready_at:
        return result("inconsistent", "the PR was converted to Draft after its last Ready transition")
    if LABEL not in names:
        return result("absent", f"the PR does not carry the {LABEL} label")
    if label_event is None:
        return result("inconsistent", f"the PR shows the {LABEL} label but its timeline has no event for it")
    position, kind, actor = label_event
    if kind != "labeled":
        return result("inconsistent", f"the PR shows the {LABEL} label but its last label event is a removal")
    if position < ready_at:
        return result("stale-epoch", f"the {LABEL} label was added before the PR's last Ready transition")
    if actor != viewer:
        return result("untrusted", f"the {LABEL} label was added by {actor or 'an unknown account'}, "
                                   f"not by the authenticated account {viewer}")
    marker = None
    for index, body in viewer_comments:
        if index > ready_at:
            found = MARKER.findall(body)
            if found:
                marker = found[-1]
    if marker is None:
        return result("absent", f"no signal comment by {viewer} after the PR's last Ready transition")
    if marker[0] != head:
        return result("stale", f"the signal was written for HEAD {marker[0][:12]}, the PR HEAD is {head[:12]}", marker)
    return result("valid", f"{LABEL} was added by {viewer} after the last Ready transition and the signal "
                           f"comment names HEAD {head[:12]}", marker)


def prepare(client: Any, repo: Any, number: int, sleep: Callable[[float], None] | None = None) -> str:
    """Before a producer runs `gh pr ready`: the label exists, and no stale label stays on the Draft. Returns the viewer.

    The label must have been created by a maintainer (never here: no code in this repository creates, edits or
    deletes labels). A label left on the PR from an earlier Ready epoch is removed from the Draft, and the removal
    is confirmed by re-reading the PR (bounded), so that the label added after the Ready transition is a new event
    that every consumer can order after it. Any failure raises `SignalError` (or the client's own error): the
    producer must not invoke Ready.
    """
    if not client.label_exists(repo, LABEL):
        raise SignalError(f"the repository has no {LABEL} label; a maintainer must create it once "
                          "(this tool never creates labels)")
    viewer = client.viewer_login(repo)
    view = client.pr_view(repo, number)
    if view.get("isDraft") is not True:
        raise SignalError(f"PR #{number} is not a Draft; a signal is only removed from a Draft before Ready")
    if LABEL not in _label_names(view.get("labels")):
        return viewer
    client.edit_label(repo, number, LABEL, add=False)
    for attempt in range(READ_TRIES):
        if LABEL not in _label_names(client.pr_view(repo, number).get("labels")):
            return viewer
        if attempt < READ_TRIES - 1:
            (sleep or time.sleep)(READ_INTERVAL)
    raise SignalError(f"a stale {LABEL} label was removed from PR #{number} but it still shows after "
                      f"{READ_TRIES} reads")


def write(client: Any, repo: Any, number: int, head: str, producer: str, viewer: str,
          sleep: Callable[[float], None] | None = None) -> Assessment:
    """After a producer verified a Ready PR: post the marker comment, add the label, confirm it reads as valid.

    The comment comes first and the label last: the label is the commit point, so a consumer never sees a label
    without the comment that names the verified HEAD. The read-back asks for the same `assess` every consumer
    uses, at this HEAD, until it says `valid` or READ_TRIES reads are spent. Raises `SignalError` (or the
    client's own error) when the signal was not written or cannot be confirmed. `sleep` is injected by tests; the
    default is `time.sleep`, looked up when it is called.
    """
    _check_producer(producer)
    head = _check_head(head)
    client.post_comment(repo, number, marker_comment(head, producer))
    client.edit_label(repo, number, LABEL, add=True)
    seen = "nothing was read"
    for attempt in range(READ_TRIES):
        view = client.pr_view(repo, number)
        last = assess(view.get("headRefOid"), view.get("labels"), client.timeline_events(repo, number), viewer)
        if last.valid and last.marker_head == head:
            return last
        seen = f"{last.state}: {last.reason}"
        if attempt < READ_TRIES - 1:
            (sleep or time.sleep)(READ_INTERVAL)
    raise SignalError(f"the signal for HEAD {head[:12]} was written but does not read back as valid after "
                      f"{READ_TRIES} reads (last: {seen})")
