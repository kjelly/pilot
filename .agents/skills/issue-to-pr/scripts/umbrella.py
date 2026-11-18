#!/usr/bin/env python3
"""Does an Issue belong to issue-to-pr's umbrella mode? Read-only.

    umbrella.py resolve --repo OWNER/REPO --issue N

An umbrella is an Issue that issue-batch-planner's file_umbrella.py filed: its body has exactly one line
`issue-batch-planner batch: <12 hex>` and exactly one line `issue-batch-planner issues: <n> <n> ...`.
N is the umbrella U when its own body has the batch line; otherwise U is N's parent when the parent is an
Issue of the same repository whose body has it. Anything else, including an ordinary GitHub parent, is
single-Issue mode and changes nothing.

The sub-issues are U's sub-issues on GitHub now: the open ones are the work, the closed ones are listed.
Every sub-issue, open or closed, must be on the member line and every member must be a sub-issue, so an
umbrella whose linking stopped part-way (file_umbrella.py exit 3) is never taken for the whole batch.

Exit 0: {"mode": "single" | "umbrella", ...}. Exit 2: refused, including any failed or malformed read.
Nothing here writes, so there is no other exit code.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any, Callable

sys.dont_write_bytecode = True

REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
VIEW_FIELDS = "number,state,url,body,parent,subIssues"
BATCH_PREFIX = "issue-batch-planner batch:"
MEMBERS_PREFIX = "issue-batch-planner issues:"
BATCH_LINE = re.compile(r"issue-batch-planner batch: ([0-9a-f]{12})\Z")
MEMBERS_LINE = re.compile(r"issue-batch-planner issues: ([1-9][0-9]{0,9}(?: [1-9][0-9]{0,9})*)\Z")
MAX_OPEN_SUB_ISSUES = 4


class UmbrellaRefused(RuntimeError):
    """The Issue cannot be resolved; nothing may proceed on it in either mode until a person looks."""


def gh_view(repo: str, number: int) -> Any:
    """`gh issue view N --json VIEW_FIELDS`, parsed. A failed or non-JSON read is a refusal."""
    try:
        p = subprocess.run(["gh", "issue", "view", str(number), "-R", repo, "--json", VIEW_FIELDS],
                           capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UmbrellaRefused(f"gh issue view {number} did not run: {exc}") from exc
    if p.returncode:
        raise UmbrellaRefused(f"gh issue view {number} failed: {(p.stderr or p.stdout).strip()[:300]}")
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise UmbrellaRefused(f"gh issue view {number} did not return JSON: {exc}") from exc


def checked_view(fetch: Callable[[int], Any], number: int) -> dict[str, Any]:
    v = fetch(number)
    subs = v.get("subIssues") if isinstance(v, dict) else None
    if (not isinstance(v, dict) or v.get("number") != number or not isinstance(v.get("state"), str)
            or not isinstance(v.get("url"), str) or not isinstance(v.get("body"), (str, type(None)))
            or not isinstance(v.get("parent"), (dict, type(None))) or not isinstance(subs, dict)
            or not isinstance(subs.get("nodes"), list) or type(subs.get("totalCount")) is not int):
        raise UmbrellaRefused(f"unexpected gh issue view shape for #{number}")
    return v


def issue_url(repo: str, number: Any) -> str:
    return f"https://github.com/{repo}/issues/{number}".lower()


def lines_with(body: str | None, prefix: str) -> list[str]:
    return [line for line in (body or "").splitlines() if line.startswith(prefix)]


def is_umbrella(body: str | None) -> bool:
    return bool(lines_with(body, BATCH_PREFIX))


def parse_umbrella(repo: str, u: dict[str, Any]) -> dict[str, Any]:
    """The batch, open and closed sub-issues of umbrella `u`, or UmbrellaRefused naming what is wrong."""
    number = u["number"]
    if u["state"] != "OPEN":
        raise UmbrellaRefused(f"umbrella #{number} is {u['state']}; its batch is no longer open work")
    batch_lines = lines_with(u["body"], BATCH_PREFIX)
    found = BATCH_LINE.fullmatch(batch_lines[0]) if len(batch_lines) == 1 else None
    if found is None:
        raise UmbrellaRefused(f"umbrella #{number} must have exactly one well-formed `{BATCH_PREFIX}` line, "
                              f"found {len(batch_lines)}")
    member_lines = lines_with(u["body"], MEMBERS_PREFIX)
    listed = MEMBERS_LINE.fullmatch(member_lines[0]) if len(member_lines) == 1 else None
    if listed is None:
        raise UmbrellaRefused(f"umbrella #{number} must have exactly one well-formed `{MEMBERS_PREFIX}` line, "
                              f"found {len(member_lines)}; an umbrella filed before it existed needs its body "
                              "updated (file_umbrella.py --update-body)")
    members = [int(x) for x in listed.group(1).split()]
    if len(set(members)) != len(members):
        raise UmbrellaRefused(f"umbrella #{number} lists a member twice")
    nodes, total = u["subIssues"]["nodes"], u["subIssues"]["totalCount"]
    if total != len(nodes):
        raise UmbrellaRefused(f"umbrella #{number} reports {total} sub-issues but lists {len(nodes)}; "
                              "the list is incomplete")
    open_, closed = [], []
    for node in nodes:
        if not isinstance(node, dict) or type(node.get("number")) is not int or not isinstance(node.get("url"), str):
            raise UmbrellaRefused(f"umbrella #{number} has a malformed sub-issue entry")
        if node["url"].lower() != issue_url(repo, node["number"]):
            raise UmbrellaRefused(f"umbrella #{number} has a sub-issue in another repository: {node['url']}")
        if node.get("state") == "OPEN":
            open_.append(node["number"])
        elif node.get("state") == "CLOSED":
            closed.append(node["number"])
        else:
            raise UmbrellaRefused(f"sub-issue #{node['number']} has an unknown state {node.get('state')!r}")
    if set(open_ + closed) != set(members) or len(open_ + closed) != len(members):
        raise UmbrellaRefused(f"umbrella #{number}'s sub-issues {sorted(open_ + closed)} are not its members "
                              f"{sorted(members)}: the linking stopped part-way or someone changed it; finish it "
                              "with file_umbrella.py (exit 0) or ask a person")
    if not 1 <= len(open_) <= MAX_OPEN_SUB_ISSUES:
        raise UmbrellaRefused(f"umbrella #{number} has {len(open_)} open sub-issues; umbrella mode takes 1 to "
                              f"{MAX_OPEN_SUB_ISSUES}")
    return {"umbrella": number, "umbrella_url": u["url"], "batch_id": found.group(1),
            "sub_issues": sorted(open_), "closed_sub_issues": sorted(closed)}


def resolve(repo: str, number: int, fetch: Callable[[int], Any] | None = None) -> dict[str, Any]:
    """`{"mode": "single"}` or `{"mode": "umbrella", "umbrella", "batch_id", "sub_issues", ...}` for Issue
    `number`. `fetch(n)` returns `gh issue view n --json VIEW_FIELDS` (default: gh itself)."""
    if not REPO.fullmatch(repo) or type(number) is not int or number < 1:
        raise UmbrellaRefused("--repo must be OWNER/REPO and --issue a positive number")
    get = fetch or (lambda n: gh_view(repo, n))
    v = checked_view(get, number)
    u = None
    if is_umbrella(v["body"]):
        u = v
    elif v["parent"] is not None:
        parent = v["parent"]
        same_repo = type(parent.get("number")) is int and isinstance(parent.get("url"), str) \
            and parent["url"].lower() == issue_url(repo, parent["number"])
        if same_repo:
            pv = checked_view(get, parent["number"])
            if is_umbrella(pv["body"]):
                u = pv
    if u is None:
        return {"mode": "single", "issue": number}
    result = parse_umbrella(repo, u)
    members = result["sub_issues"] + result["closed_sub_issues"]
    if number != u["number"] and number not in members:
        raise UmbrellaRefused(f"#{number} is not a member of umbrella #{u['number']}")
    return {"mode": "umbrella", "issue": number, "redirected": number != u["number"], **result}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("resolve")
    r.add_argument("--repo", required=True)
    r.add_argument("--issue", required=True, type=int)
    args = ap.parse_args(argv)
    try:
        result, code = resolve(args.repo, args.issue), 0
    except UmbrellaRefused as exc:
        result, code = {"status": "REFUSED", "issue": args.issue, "error": str(exc)}, 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
