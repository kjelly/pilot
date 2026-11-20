"""Test support for the pr-ready-verified signal: one PR's signal-relevant GitHub state and two ways to talk to it.

`World` models what the signal reads and writes (the PR's timeline, labels, Draft state, HEAD) in the shapes of
the reduced real captures in `pr-review-merge/tests/fixtures/github_api.json` (AGENTS.md 5.6): event objects as
`gh api .../timeline` prints them, labels as `gh pr view --json labels` prints them, the label and `user` answers
verbatim. It has two adapters over the same model:

  * `Client`: an in-process object with the interface of `gh_runtime` that `ready_signal` takes injected;
  * `handle`: what a fake `gh` EXECUTABLE answers for the signal's calls (label, user, timeline, comment, edit),
    keeping the state in `<state dir>/signal-world.json`, so that `pr_gate.py` and `mark_ready.py` run for real
    against it. The fake executables call `handle` for a call they do not answer themselves and, for `gh pr ready`
    and `gh pr view`, `note_ready` and `view_labels`.

Every operation is logged in order (`calls`), which is how tests assert "the label is added after the comment".
A change of the PR that happens BETWEEN two of those operations (somebody converts it to Draft and makes it Ready
again, pushes a commit) is injected with `World.inject(op, nth, actions)`: the actions run when the nth following
operation `op` starts, before its effect, in both adapters (the hook sits in `World.log`, which both call first).
Failures are injected through `World.fail(...)` / `World.label_state(...)` and the read lag of a write through
`World.flags["lag"]` (an added label) / `["remove_lag"]` (a removed one) / `["ready_lag"]` (the Ready transition a fake
`gh pr ready` makes) or `World.add(..., lag=N)`: an event added
with lag N is invisible to the first N reads of the kind that shows it, so a read-back that needs N + 1 reads is
expressible without sleeping.
"""
from __future__ import annotations

import contextlib
import copy
import json
import sys
import types
from pathlib import Path
from typing import Any, Iterator, Sequence

# A fake `gh` executable imports this file on the calls that need the model, each one a new Python process with no
# bytecode cache (`PYTHONDONTWRITEBYTECODE=1`): every import at the top is paid again by each of those calls. With
# `unittest.mock` and `ready_signal` (and its `dataclasses`) imported here a fake `gh` call took 60 ms instead of 23, so
# those two are imported by the one function that needs each (`mark_ready_signal`, `production`).

SKILLS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SKILLS / "_shared" / "scripts"))

FIXTURES = json.loads((SKILLS / "pr-review-merge" / "tests" / "fixtures" / "github_api.json").read_text())
VIEWER_CAPTURE = json.loads(FIXTURES["user"]["ok"]["stdout"])
VIEWER = VIEWER_CAPTURE["login"]
OTHER = "someone-else"
ACCOUNTS = {VIEWER: VIEWER_CAPTURE["id"], OTHER: 1001}
# Event ids of the real timeline of kjelly/pilot#419 (fixtures timeline.pr_419_paged): its two Ready transitions,
# the Draft conversion between them, a label event and a comment (comments live in another id space).
REAL_FIRST_READY, REAL_DRAFT, REAL_LAST_READY = 36743658899, 36744735929, 36750750751
REAL_LABELED, REAL_COMMENT = 36752270477, 7035591012
LABEL_CAPTURE = json.loads(FIXTURES["labels"]["exists"]["stdout"])
STATE_FILE = "signal-world.json"
EVENT_NAMES = ("ready_for_review", "convert_to_draft", "labeled", "unlabeled", "commented")


def production() -> Any:
    """`ready_signal`, the module whose view of GitHub this model stands for, imported when first needed."""
    import ready_signal
    return ready_signal


def __getattr__(name: str) -> Any:
    """PEP 562: `ready_signal` and `LABEL` of this module are those of `production()`."""
    if name == "ready_signal":
        return production()
    if name == "LABEL":
        return production().LABEL
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


@contextlib.contextmanager
def read_back_sleeps() -> Iterator[list[float]]:
    """Yields the list in which the waits of `ready_signal`'s read-back are recorded (and none of them is slept).

    The recording is local to that module, the one in `sys.modules` that the code under test uses: its name `time`
    stands for an object that has only `sleep`. A patch of the global `time.sleep` records every sleep of the process,
    and `subprocess.run(timeout=...)` sleeps 1 ms, 2 ms ... while a child it has read to the end of is still exiting:
    under load that was thousands of sleeps among the five of the read-back, and a test of the exact waits failed
    whenever the machine was busy. A test that removed the module from `sys.modules` (to make its loading fail) has no
    read-back to record: it gets an empty list, and the module is not imported again here."""
    from unittest import mock  # see the comment under the imports
    sleeps: list[float] = []
    module = sys.modules.get("ready_signal")
    if module is None:
        yield sleeps
        return
    with mock.patch.object(module, "time", types.SimpleNamespace(sleep=sleeps.append)):
        yield sleeps


def account(login: str) -> dict[str, Any]:
    return {"login": login, "id": ACCOUNTS.get(login, 1002), "type": "User", "site_admin": False}


class World:
    """The state; `s` is plain JSON so a fake executable can keep it between its invocations."""

    def __init__(self, *, head: str = "a" * 40, draft: bool = True, viewer: str = VIEWER, number: int = 7) -> None:
        self.s: dict[str, Any] = {"viewer": viewer, "head": head, "draft": draft, "number": number, "events": [],
                                  "pending": [], "seq": 0, "flags": {}, "log": []}

    # -- persistence for the executable adapter -------------------------------------------------------------
    @classmethod
    def load(cls, state: Path) -> "World":
        world = cls()
        path = Path(state) / STATE_FILE
        if path.exists():
            world.s = json.loads(path.read_text())
        return world

    def save(self, state: Path) -> None:
        (Path(state) / STATE_FILE).write_text(json.dumps(self.s))

    # -- building the timeline ----------------------------------------------------------------------------
    def add(self, kind: str, actor: str | None = None, *, label: str | None = None, body: str | None = None,
            lag: int = 0, lag_on: str = "timeline") -> dict[str, Any]:
        """Append an event in the shape of the real captures; `lag` N hides it from the first N reads of kind
        `lag_on` ("timeline" or "pr-view": the read that ticks it closer to visible)."""
        assert kind in EVENT_NAMES, kind
        self.s["seq"] += 1
        n = self.s["seq"]
        who = actor or self.s["viewer"]
        event: dict[str, Any] = {"id": 36700000000 + n, "event": kind,
                                 "created_at": f"2026-11-20T09:{n // 60:02d}:{n % 60:02d}Z", "actor": account(who)}
        if kind in ("labeled", "unlabeled"):
            event["label"] = {"name": label, "color": LABEL_CAPTURE["color"]}
        if kind == "commented":
            event["user"] = account(who)
            event["body"] = body
        if lag:
            self.s["pending"].append([lag, event, lag_on])
        else:
            self.s["events"].append(event)
        if kind == "ready_for_review":
            self.s["draft"] = False
        if kind == "convert_to_draft":
            self.s["draft"] = True
        return event

    def ready(self, actor: str | None = None) -> dict[str, Any]:
        return self.add("ready_for_review", actor)

    def to_draft(self, actor: str | None = None) -> dict[str, Any]:
        return self.add("convert_to_draft", actor)

    def label(self, actor: str | None = None, *, add: bool = True, name: str | None = None, lag: int = 0,
              lag_on: str = "timeline") -> dict[str, Any]:
        """A label event; the signal's label unless `name` says another."""
        return self.add("labeled" if add else "unlabeled", actor, label=name or production().LABEL,
                        lag=lag, lag_on=lag_on)

    def comment(self, body: str, actor: str | None = None) -> dict[str, Any]:
        return self.add("commented", actor, body=body)

    def latest_ready(self) -> int:
        """The id of the PR's latest `ready_for_review` event on the visible timeline."""
        ids = [event["id"] for event in self.s["events"] if event["event"] == "ready_for_review"]
        assert ids, "the timeline has no ready_for_review event: name the transition with signal(ready=<event id>)"
        return ids[-1]

    def signal(self, head: str | None = None, producer: str | None = None, actor: str | None = None,
               ready: int | None = None) -> None:
        """A complete signal as a producer writes it (`pr-ready` unless `producer` says another): the marker comment,
        then the label. The marker certifies the Ready transition `ready`, the PR's latest one unless named (a
        timeline without a Ready event needs it named)."""
        module = production()
        ready = self.latest_ready() if ready is None else ready
        self.comment(module.marker_comment(head or self.s["head"], producer or module.PR_READY, ready), actor)
        self.label(actor)

    def signed_ready(self, producer: str | None = None, actor: str | None = None) -> None:
        """Draft -> Ready, then a complete signal: what a producer leaves behind."""
        self.ready(actor)
        self.signal(producer=producer, actor=actor)

    # -- reading it ---------------------------------------------------------------------------------------
    def label_names(self) -> list[str]:
        state: dict[str, bool] = {}
        for event in self.s["events"]:
            if event.get("event") in ("labeled", "unlabeled"):
                state[event["label"]["name"]] = event["event"] == "labeled"
        return [name for name, present in state.items() if present]

    def view_labels(self) -> list[dict[str, str]]:
        """The labels as `gh pr view --json labels` prints them (`id` is the label's node id: fixtures labels.pr_view)."""
        return [{"id": LABEL_CAPTURE["node_id"], "name": name, "description": LABEL_CAPTURE["description"],
                 "color": LABEL_CAPTURE["color"]} for name in self.label_names()]

    def _tick(self, kind: str) -> None:
        """A read of `kind` happened: pending (lagging) events waiting for that kind of read get one closer to visible."""
        still = []
        for entry in self.s["pending"]:
            if entry[2] == kind:
                entry[0] -= 1
            if entry[0] <= 0:
                self.s["events"].append(entry[1])
            else:
                still.append(entry)
        self.s["pending"] = still

    def view(self) -> dict[str, Any]:
        """The PR view as read now; the read then ticks the events that lag behind PR views."""
        shown = {"number": self.s["number"], "isDraft": self.s["draft"], "headRefOid": self.s["head"],
                 "labels": self.view_labels()}
        self._tick("pr-view")
        return shown

    def timeline(self) -> list[dict[str, Any]]:
        """The visible timeline as read now; the read then ticks the events that lag behind timeline reads."""
        snapshot = copy.deepcopy(self.s["events"])
        self._tick("timeline")
        return snapshot

    def log(self, op: str) -> None:
        """An operation starts: record it, then run the injected actions that are due before its effect."""
        self.s["log"].append(op)
        counts = self.s["flags"].setdefault("count", {})
        counts[op] = counts.get(op, 0) + 1
        for hook in self.s["flags"].get("inject", []):
            if hook["op"] == op and hook["at"] == counts[op]:
                self._act(hook["actions"])

    def inject(self, op: str, nth: int, actions: Sequence[str]) -> "World":
        """Run `actions` when the `nth` operation `op` from now on (1 = the next one) starts, before its effect: "draft"
        (the viewer converts the PR to Draft), "ready" (makes it Ready), "head=<sha>" (pushes a commit) and "sign" (a
        complete signal for the latest Ready transition, as another producer run leaves it). The actions are not
        operations: they are not in `calls()`."""
        assert nth >= 1 and actions and all(a in ("draft", "ready", "sign") or a.startswith("head=") for a in actions), actions
        at = self.s["flags"].get("count", {}).get(op, 0) + nth
        self.s["flags"].setdefault("inject", []).append({"op": op, "at": at, "actions": list(actions)})
        return self

    def _act(self, actions: Sequence[str]) -> None:
        for action in actions:
            if action == "draft":
                self.to_draft()
            elif action == "ready":
                self.ready()
            elif action == "sign":
                self.signal()
            else:
                self.s["head"] = action.removeprefix("head=")

    def calls(self) -> list[str]:
        return list(self.s["log"])

    def fails(self, op: str) -> bool:
        return op in self.s["flags"].get("fail", [])

    def fail(self, *ops: str) -> "World":
        self.s["flags"].setdefault("fail", []).extend(ops)
        return self

    def lag_for(self, add: bool) -> dict[str, Any]:
        """Keyword arguments of `label` that make a write lag as the flags say: an added label is late for
        the timeline reads (`lag`), a removed one for the PR-view reads (`remove_lag`)."""
        if add:
            return {"lag": self.s["flags"].get("lag", 0), "lag_on": "timeline"}
        return {"lag": self.s["flags"].get("remove_lag", 0), "lag_on": "pr-view"}

    def label_state(self, state: str) -> "World":
        """How the repository answers for the label: "missing" (the real 404) or "error" (a server error)."""
        self.s["flags"]["label"] = state
        return self


class Client:
    """The `gh_runtime` interface `ready_signal` takes, over a `World`."""

    def __init__(self, world: World) -> None:
        sys.path.insert(0, str(SKILLS / "pr-review-merge" / "scripts"))
        try:
            import gh_runtime
        finally:
            sys.path.pop(0)
        self.Repo, self.GitHubError = gh_runtime.Repo, gh_runtime.GitHubError
        self.world = world

    def _down(self, op: str) -> None:
        self.world.log(op)
        if self.world.fails(op):
            raise self.GitHubError(f"injected failure of {op}")

    def label_exists(self, repo: Any, label: str) -> bool:
        self.world.log("label-exists")
        state = self.world.s["flags"].get("label")
        if state == "error":
            raise self.GitHubError("injected failure of label-exists")
        return state != "missing" and label == production().LABEL

    def viewer_login(self, repo: Any) -> str:
        self._down("user")
        return self.world.s["viewer"]

    def pr_view(self, repo: Any, number: int) -> dict[str, Any]:
        self._down("pr-view")
        return self.world.view()

    def timeline_events(self, repo: Any, number: int) -> list[dict[str, Any]]:
        self._down("timeline")
        return self.world.timeline()

    def edit_label(self, repo: Any, number: int, label: str, *, add: bool) -> None:
        op = "add-label" if add else "remove-label"
        self._down(op)
        self.world.label(None, add=add, name=label, **self.world.lag_for(add))

    def post_comment(self, repo: Any, number: int, body: str) -> None:
        self._down("comment")
        self.world.comment(body)


def mark_ready_signal(mark_ready: Any, world: World) -> Any:
    """A patch that gives `mark_ready` (issue-to-pr's script module) the shared signal module and a `Client` over `world`
    instead of loading `gh_runtime`, which would run the real `gh`. Every test that gets mark_ready as far as the
    Ready transition needs it."""
    from unittest import mock  # see the comment under the imports
    return mock.patch.object(mark_ready, "signal_runtime", return_value=(production(), Client(world)))


def pr_ready_executor(world: World, calls: list[list[str]]) -> Any:
    """A `mark_ready.execute` side effect: records the argv in `calls` and makes the world's PR Ready, as `gh pr ready` does."""
    def execute(argv: list[str], cwd: Any) -> str:
        calls.append(argv)
        world.log("ready")
        world.ready()
        return ""
    return execute


# ---- the fake `gh` executable's side -----------------------------------------------------------------------

def _reply(stdout: str = "", stderr: str = "", rc: int = 0) -> int:
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    return rc


def handle(args: list[str], state: Path) -> int | None:
    """The exit status of a fake `gh` for a signal call it answers (output already written), or None for any other call."""
    world = World.load(state)
    flags = world.s["flags"]
    code: int | None = None
    if args[:1] == ["api"] and args[-1] == "user":
        world.log("user")
        code = _reply(**({"stderr": "HTTP 502: Bad Gateway\n", "rc": 1} if world.fails("user")
                         else {"stdout": FIXTURES["user"]["ok"]["stdout"]}))
    elif args[:1] == ["api"] and "/labels/" in args[-1]:
        world.log("label-exists")
        capture = FIXTURES["labels"]
        if flags.get("label") == "error":
            code = _reply(stderr="HTTP 502: Bad Gateway\n", rc=1)
        elif flags.get("label") == "missing" or not args[-1].endswith("/labels/" + production().LABEL):
            code = _reply(capture["missing"]["stdout"], capture["missing"]["stderr"], capture["missing"]["rc"])
        else:
            code = _reply(capture["exists"]["stdout"])
    elif args[:1] == ["api"] and args[-1].split("?")[0].endswith("/timeline") and "--slurp" in args:
        world.log("timeline")
        code = _reply(stderr="HTTP 502: Bad Gateway\n", rc=1) if world.fails("timeline") \
            else _reply(json.dumps([world.timeline()]))
    elif args[:2] == ["pr", "comment"]:
        world.log("comment")
        if world.fails("comment"):
            code = _reply(stderr="HTTP 502: Bad Gateway\n", rc=1)
        else:
            world.comment(Path(args[args.index("--body-file") + 1]).read_text())
            code = 0
    elif args[:2] == ["pr", "edit"]:
        add = "--add-label" in args
        flag = "--add-label" if add else "--remove-label"
        op = "add-label" if add else "remove-label"
        world.log(op)
        if world.fails(op):
            code = _reply(stderr="HTTP 502: Bad Gateway\n", rc=1)
        else:
            world.label(None, add=add, name=args[args.index(flag) + 1], **world.lag_for(add))
            code = 0
    if code is not None:
        world.save(state)
    return code


def note_ready(state: Path) -> None:
    """The fake `gh pr ready` ran: log it and record the ready_for_review event."""
    world = World.load(state)
    world.log("ready")
    # `flags["ready_lag"]` N: the new event is invisible to the first N timeline reads (a Ready that shows late).
    world.add("ready_for_review", lag=world.s["flags"].get("ready_lag", 0))
    world.save(state)


def view_labels(state: Path) -> list[dict[str, str]]:
    """What the fake `gh pr view` prints as `labels`; the read is logged and ticks the events that lag behind it."""
    world = World.load(state)
    world.log("pr-view")
    labels = world.view()["labels"]
    world.save(state)
    return labels


def calls(state: Path) -> list[str]:
    return World.load(state).calls()
