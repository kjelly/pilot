#!/usr/bin/env python3
"""Publish a single completion result for an optional pr-loop task (scripts/pr_loop.py)."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


SHA = re.compile(r"[0-9a-fA-F]{40}")
OUTCOMES = {
    "draft": {"READY", "DRAFT-BLOCKED", "WAIT-INTERRUPTED", "ERROR"},
    "ready": {"DRAFT", "ENQUEUED", "MERGED", "WAITING", "SKIP", "ERROR"},
}
TASK_KEYS = {"version", "repo", "pr", "phase", "nonce", "start_head"}
# A task lives at <checkout>/TASK_DIR/<nonce>/task.json; its result is written beside it. scripts/pr_loop.py
# imports TASK_DIR, so the directory is named here once.
TASK_DIR = ".pr-loop"
NONCE = re.compile(r"[0-9a-f]{32}")
# Read-only compatibility with a driver written before TASK_DIR existed; nothing in Pilot writes this layout.
# Remove it when no driver does.
LEGACY_TASK_DIR, LEGACY_TASK_PREFIX = ".tmux-ai-pr", "tmux-ai-pr-"
LAYOUT = f"expected the absolute path of <checkout>/{TASK_DIR}/<nonce>/task.json"


def load_task(path: Path, repo: str, pr: int, phase: str) -> dict[str, Any]:
    """Bind the task to the invocation before a gate may change remote state."""
    if not path.is_absolute() or path.name != "task.json":
        raise ValueError(LAYOUT)
    neutral = path.parent.parent.name == TASK_DIR and NONCE.fullmatch(path.parent.name) is not None
    legacy = path.parent.parent.name == LEGACY_TASK_DIR and path.parent.name.startswith(LEGACY_TASK_PREFIX)
    if not neutral and not legacy:
        raise ValueError(LAYOUT)
    with path.open("rb") as source:
        data = source.read(4097)
    if len(data) > 4096:
        raise ValueError("pr-loop task is too large")
    task = json.loads(data)
    if not isinstance(task, dict) or task.keys() != TASK_KEYS or \
       type(task["version"]) is not int or task["version"] != 1 or \
       not isinstance(task["repo"], str) or task["repo"].casefold() != repo.casefold() or \
       type(task["pr"]) is not int or task["pr"] != pr or pr <= 0 or \
       task["phase"] != phase or phase not in OUTCOMES or \
       not isinstance(task["nonce"], str) or not NONCE.fullmatch(task["nonce"]) or \
       not isinstance(task["start_head"], str) or not SHA.fullmatch(task["start_head"]):
        raise ValueError("pr-loop task does not match this PR invocation")
    if neutral and task["nonce"] != path.parent.name:
        raise ValueError("pr-loop task nonce does not match its directory")
    return task


def write_result(path: Path, task: dict[str, Any], *, outcome: str, head: str,
                 reason: str, wait_kind: str = "", person_handoff: bool = False) -> None:
    if outcome not in OUTCOMES[task["phase"]] or not SHA.fullmatch(head):
        raise ValueError("invalid pr-loop result outcome or HEAD")
    if wait_kind not in ("", "person", "transient") or \
       (outcome != "WAITING" and (wait_kind or person_handoff)) or \
       (person_handoff and wait_kind != "person"):
        raise ValueError("invalid pr-loop waiting hand-off")
    clean = " ".join("".join(char if char.isprintable() else " " for char in reason).split())
    data = json.dumps({**task, "head_sha": head.lower(), "outcome": outcome, "reason": clean[:600],
                       "wait_kind": wait_kind, "person_handoff": person_handoff}, ensure_ascii=False) + "\n"
    target = path.with_name("result.json")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent) as temporary:
        temporary.write(data)
        temporary.flush()
        try:
            # An existing result belongs to an already finished invocation.
            os.link(temporary.name, target)
        except FileExistsError:
            if target.read_text(encoding="utf-8") != data:
                raise ValueError("this pr-loop task already has a different result") from None


def publish_gate_result(path: Path, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Normalize the existing gate/actor report without changing its exit or mutation."""
    gate = result.get("gate") or {}
    outcome = result.get("status") or result.get("outcome")
    if task["phase"] == "ready" and outcome == "DRAFT-BLOCKED":
        outcome = "DRAFT"
    if outcome not in OUTCOMES[task["phase"]]:
        return  # CI progress and dry-run output are not completion results.
    reasons = result.get("errors") or gate.get("reasons") or []
    reason = result.get("error") or (str(reasons[0]) if reasons else result.get("message") or outcome)
    head = result.get("head_sha") or gate.get("head_sha") or task["start_head"]
    try:
        write_result(path, task, outcome=outcome, head=head, reason=reason,
                     wait_kind=(result.get("wait_kind") or "") if outcome == "WAITING" else "",
                     person_handoff=outcome == "WAITING" and gate.get("person_handoff") is True)
    except (OSError, TypeError, ValueError) as exc:
        print(f"pr-loop result could not be published: {exc}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--phase", choices=tuple(OUTCOMES), required=True)
    parser.add_argument("--head", required=True, help="Current PR HEAD verified against GitHub")
    parser.add_argument("--outcome", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--wait-kind", choices=("person", "transient"), default="")
    parser.add_argument("--person-handoff", action="store_true")
    args = parser.parse_args()
    try:
        task = load_task(args.task, args.repo, args.pr, args.phase)
        write_result(args.task, task, outcome=args.outcome, head=args.head, reason=args.reason,
                     wait_kind=args.wait_kind, person_handoff=args.person_handoff)
        return 0
    except (OSError, ValueError) as exc:
        parser.exit(2, f"pr-loop result: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
