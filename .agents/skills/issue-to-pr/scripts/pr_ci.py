#!/usr/bin/env python3
"""Verify CI check status against a specific PR HEAD, Draft or Ready (optionally poll for completion)."""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from typing import Any

# Running from the skill snapshot must not add __pycache__ there: `skill_snapshot.py verify`
# counts any added file and would STOP every later step. Set before the first sibling import.
sys.dont_write_bytecode = True
from issue_gate import GateError, command

# `gh pr checks --required` on a branch without required checks (no branch protection or ruleset
# requiring any) exits 1 with nothing on stdout and, on stderr, exactly this line (gh 2.103.3):
#   no required checks reported on the 'chore/pr-ready-dispute-review-comments' branch\n
# Case-sensitive and anchored: a failing required check named "no required checks reported" arrives
# as JSON on stdout and must stay a failure. pr-ready's pr_gate.py has the same constant and rule
# (pr-ready/tests/test_required_checks_parity.py keeps the two identical).
NO_REQUIRED_CHECKS = re.compile(r"no required checks reported on the '[^\n]+' branch\n?")


def checks(repo: str, number: int, required: bool) -> list[dict[str, Any]]:
    cmd = ["gh", "pr", "checks", str(number), "-R", repo, "--json", "name,state,bucket,link"]
    if required:
        cmd.append("--required")
    # gh may return 1 for failed and 8 for pending even while JSON is valid.
    found = command(cmd, allow_nonzero_json=True, empty_if=NO_REQUIRED_CHECKS if required else None)
    if not isinstance(found, list) or any(not isinstance(x, dict) for x in found):
        raise GateError("Unusable GitHub checks JSON")
    return found


def classify(items: list[dict[str, Any]]) -> str:
    if not items:
        return "NONE"
    if any(x.get("bucket") in ("fail", "cancel") or x.get("state") in ("FAILURE", "ERROR", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED") for x in items):
        return "FAIL"
    # A job skipped by design (e.g. a publish/promote job that only runs on main) is neither a
    # failure nor pending. It does not block, but it never counts as verification either: at least
    # one check must really pass, so a run where everything was skipped stays unconfirmed.
    if any(x.get("bucket") not in ("pass", "skipping") for x in items):
        return "PENDING_OR_SKIPPED"
    if not any(x.get("bucket") == "pass" for x in items):
        return "PENDING_OR_SKIPPED"
    return "PASS"


def inspect(repo: str, number: int, sha: str) -> dict:
    p = command(["gh", "pr", "view", str(number), "-R", repo,
                 "--json", "number,state,isDraft,headRefOid,url"])
    if not isinstance(p, dict) or p.get("number") != number or p.get("state") != "OPEN":
        return {"status": "PR_NOT_OPEN", "pr": number}
    if p.get("headRefOid") != sha:
        return {"status": "STALE_HEAD", "pr": number, "observed_head_sha": p.get("headRefOid")}
    all_items, required_items = checks(repo, number, False), checks(repo, number, True)
    all_result, required_result = classify(all_items), classify(required_items)
    if all_result == "NONE":
        status = "NO_CI_OBSERVED"
    elif all_result == "FAIL" or required_result == "FAIL":
        status = "CI_FAILED"
    elif all_result == "PASS" and required_result in ("NONE", "PASS"):
        status = "CI_PASSED"
    else:
        status = "CI_PENDING"
    return {"status": status, "pr": number, "url": p.get("url"), "head_sha": sha, "draft": p.get("isDraft"),
            "checks": [{"name": x.get("name"), "state": x.get("state"), "bucket": x.get("bucket")}
                       for x in all_items],
            "required_checks": [{"name": x.get("name"), "state": x.get("state"), "bucket": x.get("bucket")}
                                for x in required_items]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--head-sha", required=True)
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--interval", type=int, default=15)
    o = ap.parse_args(argv)
    if o.timeout < 0 or o.interval < 1:
        ap.error("Invalid timeout/interval")
    deadline = time.monotonic() + o.timeout
    while True:
        try:
            result = inspect(o.repo, o.pr, o.head_sha)
        except GateError as exc:
            result = {"status": "CI_UNKNOWN", "pr": o.pr, "blockers": [str(exc)]}
        if not o.watch or result["status"] not in ("CI_PENDING", "NO_CI_OBSERVED") or time.monotonic() >= deadline:
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["status"] == "CI_PASSED" else (3 if result["status"] in ("CI_PENDING", "NO_CI_OBSERVED") else 2)
        time.sleep(min(o.interval, max(0.0, deadline - time.monotonic())))


if __name__ == "__main__":
    sys.exit(main())
