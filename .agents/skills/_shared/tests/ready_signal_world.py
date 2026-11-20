"""Test support for the pr-ready-verified signal: one PR's signal-relevant GitHub state and two ways to talk to it.

`World` models what the signal reads and writes (the PR's timeline, labels, Draft state, HEAD) in the shapes of
the reduced real captures in `pr-review-merge/tests/fixtures/github_api.json` (AGENTS.md 5.6): event objects as
`gh api .../timeline` prints them, labels as `gh pr view --json labels` prints them, the label and `user` answers
verbatim. It has two adapters over the same model:

  * `Client`: an in-process object with the interface of `gh_runtime` that `ready_signal` takes injected;
  * `handle`: what a fake `gh` EXECUTABLE answers for the signal's calls (label, user, timeline, comment, edit),
    keeping the state in `<state dir>/signal-world.json`, so that `pr_gate.py` and `mark_ready.py` run for real
    against it. The fake executables call `handle` first and, for `gh pr ready` and `gh pr view`, `note_ready`
    and `view_labels`.

Every operation is logged in order (`calls`), which is how tests assert "the label is added after the comment".
Failures are injected through `World.fail(...)` / `World.label_state(...)` and the read lag of a write through
`World.flags["lag"]` (an added label) / `["remove_lag"]` (a removed one) or `World.add(..., lag=N)`: an event added
with lag N is invisible to the first N reads of the kind that shows it, so a read-back that needs N + 1 reads is
expressible without sleeping.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any
from unittest import mock

SKILLS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SKILLS / "_shared" / "scripts"))
import ready_signal  # noqa: E402

FIXTURES = json.loads((SKILLS / "pr-review-merge" / "tests" / "fixtures" / "github_api.json").read_text())
LABEL = ready_signal.LABEL
VIEWER_CAPTURE = json.loads(FIXTURES["user"]["ok"]["stdout"])
VIEWER = VIEWER_CAPTURE["login"]
OTHER = "someone-else"
ACCOUNTS = {VIEWER: VIEWER_CAPTURE["id"], OTHER: 1001}
LABEL_CAPTURE = json.loads(FIXTURES["labels"]["exists"]["stdout"])
STATE_FILE = "signal-world.json"
EVENT_NAMES = ("ready_for_review", "convert_to_draft", "labeled", "unlabeled", "commented")


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

    def label(self, actor: str | None = None, *, add: bool = True, name: str = LABEL, lag: int = 0,
              lag_on: str = "timeline") -> dict[str, Any]:
        return self.add("labeled" if add else "unlabeled", actor, label=name, lag=lag, lag_on=lag_on)

    def comment(self, body: str, actor: str | None = None) -> dict[str, Any]:
        return self.add("commented", actor, body=body)

    def signal(self, head: str | None = None, producer: str = ready_signal.PR_READY, actor: str | None = None) -> None:
        """A complete signal as a producer writes it: the marker comment, then the label."""
        self.comment(ready_signal.marker_comment(head or self.s["head"], producer), actor)
        self.label(actor)

    def signed_ready(self, producer: str = ready_signal.PR_READY, actor: str | None = None) -> None:
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
        self.s["log"].append(op)

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
        return state != "missing" and label == LABEL

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
    return mock.patch.object(mark_ready, "signal_runtime", return_value=(ready_signal, Client(world)))


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
        elif flags.get("label") == "missing" or not args[-1].endswith("/labels/" + LABEL):
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
    world.ready()
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
