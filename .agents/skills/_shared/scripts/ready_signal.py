#!/usr/bin/env python3
"""The `pr-ready-verified` signal: proof that a Ready PR got there through a verified Draft -> Ready step.

A PR that is Ready for Review says "quality is already mergeable". Nothing used to tie that claim to the
gate that verifies it: a person clicking "Ready for review", or a script that ran `gh pr ready` without the
gate, produced the same state, and every consumer (pr-review-merge, scripts/pr_loop.py) acted on it. The
producers (pr-ready's pr_gate.py, issue-to-pr's mark_ready.py) now sign a Ready PR AFTER their post-action
verification succeeded, with two artefacts: a comment ending in a marker line that names the verified HEAD, the
ONE Ready transition it certifies (the id of its `ready_for_review` timeline event) and the producer, and the
label `pr-ready-verified` (the commit point: it is added last). The consumers act on a Ready PR only when
`assess` says `valid`.

A signal certifies exactly one Ready transition, not a HEAD in general. GitHub has no conditional write, so the
producer cannot make "verify, then sign" atomic: anybody with write access (the maintainer uses the account the
automation runs as) can convert the PR to Draft and make it Ready again, at the same HEAD, between `gh pr ready`
and the comment. A signal that named only the HEAD would then be valid for a Ready transition that no gate
verified. So the signal names the transition, `write` takes it from the timeline relative to what `prepare`
saw on the Draft (never "the latest Ready at write time"), and the reader checks that it is still the PR's
latest Ready transition at every read.

The signal is read from ONE timeline (label events, Ready/Draft transitions and comments share one order)
and trusts nothing a stranger can write:

  1. R is the latest `ready_for_review` event. None: `absent`. A `convert_to_draft` after R: `inconsistent`.
  2. The PR view has no label: `absent`.
  3. The last label event for the label is a removal, or there is none (the view is ahead of the
     timeline: GitHub read lag): `inconsistent`.
  4. The label was added before R (it was left on the PR while it was a Draft): `stale-epoch`.
  5. The label was added by another account than the viewer: `untrusted`.
  6. Only markers written by the viewer after R count; the newest wins. None (an old-format marker, one
     without `ready=`, is none): `absent`.
  7. The marker certifies another Ready transition than R: `stale-epoch`. This is checked BEFORE the HEAD,
     so a signal for an earlier Ready transition is never `stale` (the consumers carry a `stale` signal
     across a base import or an evidence-only change; a signal for a Ready transition nobody verified must
     not be carried).
  8. The marker names another HEAD than the PR's: `stale`; otherwise `valid`.
  9. A relevant event with a malformed shape raises `SignalError` (fail closed); a `ready_for_review` event
     whose `id` is not a positive integer is one.

The viewer is the login `gh` is authenticated as. Producer and consumer must authenticate as the same
account, otherwise every signal is refused. `maintainer` is the honest provenance of a signal a person
wrote by hand for a Ready PR that predates this check. A PR that was created Ready (never a Draft) has no
`ready_for_review` event and is ignored by design. A marker without the `ready=` field (the format before the
transition was part of the signal) is never accepted: no signal of that format was ever in use.

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
# Strict on purpose: a full lowercase SHA, the decimal id of the certified `ready_for_review` event (positive, no
# leading zero, at most 20 digits: a GitHub event id is a 64-bit integer), one of the producers, exactly this
# spacing and this field order. The alternation is built from PRODUCERS so a producer exists in one place.
MARKER = re.compile(r"<!-- pr-ready:verified head=([0-9a-f]{40}) ready=([1-9][0-9]{0,19}) by=("
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

    `head` is the PR HEAD that was assessed, `marker_head`, `marker_ready` (the Ready transition the marker
    certifies) and `producer` come from the marker that decided the answer (None while no marker was reached).
    `ready_event` is the id of the PR's latest `ready_for_review` event in EVERY state (None when it has none):
    what a person signing by hand needs to name.
    """
    state: str
    reason: str
    head: str
    marker_head: str | None = None
    producer: str | None = None
    marker_ready: int | None = None
    ready_event: int | None = None

    @property
    def valid(self) -> bool:
        return self.state == "valid"


def marker_line(head: str, producer: str, ready: int) -> str:
    """The marker as it ends a signal comment; `MARKER` matches exactly this (the head is written lowercase).

    `ready` is the id of the `ready_for_review` timeline event the signal certifies; it has no default.
    """
    _check_producer(producer)
    return f"<!-- pr-ready:verified head={_check_head(head)} ready={_check_ready(ready)} by={producer} -->"


def marker_comment(head: str, producer: str, ready: int) -> str:
    """The comment a producer posts after a verified Ready transition: a short text for people, then the marker."""
    line = marker_line(head, producer, ready)
    head = _check_head(head)
    return ("## Ready for Review: verified\n\n"
            f"Verified HEAD: `{head}`  \n"
            f"Verified Ready transition: `{ready}`  \n"
            f"Verified by: `{producer}`\n\n"
            "The PR was a Draft, passed the Ready gate for exactly this commit, was converted to Ready for Review "
            "and the post-action check confirmed it is still Ready at this HEAD. The label "
            f"`{LABEL}` was added after this comment: automation that acts on Ready PRs "
            "(pr-review-merge, scripts/pr_loop.py) acts only on a PR that carries it.\n\n"
            "The signal is bound to this HEAD and to this Ready transition. A push that changes the PR's own "
            "commits makes it stale: it stays on the PR but no longer counts. A later Ready transition, even at "
            "the same HEAD, ends it, and so does converting the PR to Draft. To make a PR actionable again, "
            "convert it to Draft and run `pr-ready` again.\n\n"
            "This comment is an automated technical record, not a human approval.\n"
            f"{line}\n")


def _check_producer(producer: Any) -> None:
    if producer not in PRODUCERS:
        raise ValueError(f"unknown ready-signal producer {producer!r}; expected one of {', '.join(PRODUCERS)}")


def _check_ready(ready: Any) -> int:
    """`ready` as a Ready transition id: an int (never a bool) with 0 < ready < 10**20, else a refusal."""
    if isinstance(ready, bool) or not isinstance(ready, int) or not 0 < ready < 10 ** 20:
        raise SignalError(f"a Ready transition must be a positive event id below 10**20, got {ready!r}")
    return ready


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


def _event_id(event: dict[str, Any], index: int) -> int:
    """The id of a timeline event the signal depends on: a positive integer (never a bool), else an error."""
    value = event.get("id")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SignalError(f"timeline entry {index} ({event.get('event')}) has no valid integer id")
    return value


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

    ready_at = draft_at = ready_id = None
    label_event: tuple[int, str, str | None] | None = None  # (position, "labeled" | "unlabeled", actor)
    viewer_comments: list[tuple[int, str]] = []  # (position, body) of the viewer's comments
    for index, event in enumerate(events):
        if not isinstance(event, dict) or not isinstance(event.get("event"), str):
            raise SignalError(f"timeline entry {index} is not an event object")
        kind = event["event"]
        if kind == "ready_for_review":
            ready_at, ready_id = index, _event_id(event, index)
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

    def result(state: str, reason: str, marker: tuple[str, str, str] | None = None) -> Assessment:
        return Assessment(state, reason, head, marker[0] if marker else None, marker[2] if marker else None,
                          int(marker[1]) if marker else None, ready_id)

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
    if int(marker[1]) != ready_id:
        # Before the HEAD: a signal for an earlier Ready transition must never read as `stale` (carried by consumers).
        return result("stale-epoch", f"the signal comment certifies Ready transition {marker[1]}, but the PR's last "
                                     f"Ready transition is {ready_id}", marker)
    if marker[0] != head:
        return result("stale", f"the signal was written for HEAD {marker[0][:12]}, the PR HEAD is {head[:12]}", marker)
    return result("valid", f"{LABEL} was added by {viewer} after the last Ready transition and the signal "
                           f"comment names HEAD {head[:12]}", marker)


READY, DRAFT = "ready_for_review", "convert_to_draft"


@dataclass(frozen=True)
class Baseline:
    """What `prepare` saw on the Draft, handed to `write`: the viewer (the account that signs) and every Ready and
    Draft transition (`(kind, event id)`) that was on the timeline when the PR was a Draft with its stale label gone.
    `write` identifies the Ready transition that the verification observed as the one that is NOT in here."""
    viewer: str
    transitions: frozenset


def _transitions(events: Any) -> list[tuple[int, str, int]]:
    """`(position, kind, id)` of every Ready and Draft transition of a timeline, oldest first; a malformed timeline is an error."""
    if not isinstance(events, (list, tuple)):
        raise SignalError("the PR's timeline is missing or malformed")
    found = []
    for index, event in enumerate(events):
        if not isinstance(event, dict) or not isinstance(event.get("event"), str):
            raise SignalError(f"timeline entry {index} is not an event object")
        if event["event"] in (READY, DRAFT):
            found.append((index, event["event"], _event_id(event, index)))
    return found


def prepare(client: Any, repo: Any, number: int, sleep: Callable[[float], None] | None = None) -> Baseline:
    """Before a producer runs `gh pr ready`: the label exists, and no stale label stays on the Draft. Returns the `Baseline`.

    The label must have been created by a maintainer (never here: no code in this repository creates, edits or
    deletes labels). A label left on the PR from an earlier Ready epoch is removed from the Draft, and the removal
    is confirmed by re-reading the PR (bounded), so that the label added after the Ready transition is a new event
    that every consumer can order after it. The last step is a read of the timeline: its Ready and Draft transitions
    are the baseline against which `write` identifies the Ready transition that this producer verified. Any failure
    raises `SignalError` (or the client's own error): the producer must not invoke Ready.
    """
    if not client.label_exists(repo, LABEL):
        raise SignalError(f"the repository has no {LABEL} label; a maintainer must create it once "
                          "(this tool never creates labels)")
    viewer = client.viewer_login(repo)
    view = client.pr_view(repo, number)
    if view.get("isDraft") is not True:
        raise SignalError(f"PR #{number} is not a Draft; a signal is only removed from a Draft before Ready")

    def baseline() -> Baseline:
        known = frozenset((kind, ident) for _, kind, ident in _transitions(client.timeline_events(repo, number)))
        return Baseline(viewer, known)

    if LABEL not in _label_names(view.get("labels")):
        return baseline()
    client.edit_label(repo, number, LABEL, add=False)
    for attempt in range(READ_TRIES):
        if LABEL not in _label_names(client.pr_view(repo, number).get("labels")):
            return baseline()
        if attempt < READ_TRIES - 1:
            (sleep or time.sleep)(READ_INTERVAL)
    raise SignalError(f"a stale {LABEL} label was removed from PR #{number} but it still shows after "
                      f"{READ_TRIES} reads")


def _identify(client: Any, repo: Any, number: int, baseline: Baseline, sleep: Callable[[float], None] | None) -> int:
    """The id of the Ready transition the producer verified: the ONE `ready_for_review` event that is not in the
    baseline and has no Draft conversion after it. Reads the timeline up to READ_TRIES times (a new event is
    visible after a short delay); refuses, writing nothing, when it is not exactly that one event.

    Why this is the transition the verification observed: Ready and Draft events are append-only, the baseline was
    read while the PR was a Draft, and the producer's own post-action read found it Ready afterwards. Exactly one
    new Ready transition with no Draft after it is therefore the one that read observed; a second new Ready
    transition means somebody cycled the PR and the producer cannot tell which one it verified. "The latest Ready at
    write time" is NOT this: it would name the cycle's Ready. Events of other kinds (comments, labels) are no
    candidates; an older Draft that shows late is positioned before the Ready and does not matter.
    """
    for attempt in range(READ_TRIES):
        new = [(at, kind, ident) for at, kind, ident in _transitions(client.timeline_events(repo, number))
               if (kind, ident) not in baseline.transitions]
        readies = [(at, ident) for at, kind, ident in new if kind == READY]
        if len(readies) > 1:
            raise SignalError("the PR went through Draft and Ready again after the verified Ready transition (new "
                              "Ready transitions " + ", ".join(str(ident) for _, ident in readies) + "); "
                              "nothing was signed")
        if readies:
            at, ident = readies[0]
            if any(kind == DRAFT and later > at for later, kind, _ in new):
                raise SignalError(f"the PR was converted to Draft after Ready transition {ident}; nothing was signed")
            return ident
        if attempt < READ_TRIES - 1:
            (sleep or time.sleep)(READ_INTERVAL)
    raise SignalError(f"no Ready transition after the verified Draft shows on the timeline after {READ_TRIES} "
                      "reads; nothing was signed")


def write(client: Any, repo: Any, number: int, head: str, producer: str, baseline: Baseline,
          sleep: Callable[[float], None] | None = None) -> Assessment:
    """After a producer verified a Ready PR: identify the Ready transition, post the marker comment, add the label,
    confirm it reads as valid.

    `baseline` is what `prepare` returned. The Ready transition that the marker certifies is identified from the
    timeline relative to it (`_identify`); when it cannot be identified exactly, nothing is written. The comment
    comes first and the label last: the label is the commit point, so a consumer never sees a label without the
    comment that names the verified HEAD and transition. The read-back asks for the same `assess` every consumer
    uses, at this HEAD, until it says `valid` for this very transition or READ_TRIES reads are spent; a Ready or
    Draft transition after the certified one ends the wait at once (it can only get worse). Nothing is deleted on
    a refusal: a signal for a transition that is no longer the latest is inert, and the next `prepare` removes
    its label from the Draft. Raises `SignalError` (or the client's own error) when the signal was not written
    or cannot be confirmed. `sleep` is injected by tests; the default is `time.sleep`, looked up when it is called.
    """
    if not isinstance(baseline, Baseline):
        raise ValueError("write needs the Baseline that prepare returned (not the viewer)")
    _check_producer(producer)
    head = _check_head(head)
    ready = _identify(client, repo, number, baseline, sleep)
    client.post_comment(repo, number, marker_comment(head, producer, ready))
    client.edit_label(repo, number, LABEL, add=True)
    seen = "nothing was read"
    for attempt in range(READ_TRIES):
        view = client.pr_view(repo, number)
        events = client.timeline_events(repo, number)
        last = assess(view.get("headRefOid"), view.get("labels"), events, baseline.viewer)
        if last.valid and last.marker_head == head and last.marker_ready == ready:
            return last
        seen = f"{last.state}: {last.reason}"
        moved = _transitions(events)
        ours = next((at for at, kind, ident in moved if kind == READY and ident == ready), None)
        if ours is not None and any(at > ours for at, _, _ in moved):
            raise SignalError(f"Ready transition {ready} was superseded while the signal was written ({seen}); "
                              "the signal is inert")
        if attempt < READ_TRIES - 1:
            (sleep or time.sleep)(READ_INTERVAL)
    raise SignalError(f"the signal for HEAD {head[:12]} was written but does not read back as valid after "
                      f"{READ_TRIES} reads (last: {seen})")
