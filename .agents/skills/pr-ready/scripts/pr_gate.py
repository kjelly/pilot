#!/usr/bin/env python3
"""Fail-closed GitHub Draft PR Ready gate. Standard library + gh CLI only.

This script verifies GitHub facts and HEAD-bound, agent-supplied quality evidence.
It cannot prove the truth of a reviewer's semantic assessment; do not fabricate it.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SHA = re.compile(r"^[0-9a-fA-F]{40}$")


class GateError(RuntimeError):
    pass


def cmd(argv: list[str], *, allow_nonzero_json: bool = False) -> Any:
    try:
        p = subprocess.run(argv, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise GateError(f"Cannot execute {argv[0]}: {exc}") from exc
    if p.returncode and not allow_nonzero_json:
        raise GateError(f"{' '.join(argv[:4])}: exit {p.returncode}: {(p.stderr or p.stdout).strip()[:700]}")
    try:
        val = json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(f"Invalid/missing JSON from {argv[0]} (exit {p.returncode}): {(p.stderr or p.stdout).strip()[:700]}") from exc
    return val


def gh_pr(repo: str, pr: int) -> dict[str, Any]:
    fields = "number,url,title,isDraft,state,headRefOid,headRefName,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup"
    value = cmd(["gh", "pr", "view", str(pr), "-R", repo, "--json", fields])
    if not isinstance(value, dict):
        raise GateError("Expected a GitHub PR JSON object")
    return value


def gh_checks(repo: str, pr: int, *, required: bool) -> list[dict[str, Any]]:
    args = ["gh", "pr", "checks", str(pr), "-R", repo, "--json", "name,state,bucket,link"]
    if required:
        args.append("--required")
    # gh pr checks may exit 1 for failures or 8 for pending checks while still
    # producing valid JSON. We must evaluate individual check buckets.
    checks = cmd(args, allow_nonzero_json=True)
    if not isinstance(checks, list):
        raise GateError("Expected a GitHub check list")
    if not all(isinstance(x, dict) for x in checks):
        raise GateError("Malformed check list")
    return checks


THREAD_QUERY = """
query($owner:String!,$repo:String!,$number:Int!,$cursor:String) {
  repository(owner:$owner,name:$repo) {
    pullRequest(number:$number) {
      reviewThreads(first:100,after:$cursor) {
        nodes { id isResolved isOutdated }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""


def gh_threads(repo: str, pr: int) -> list[dict[str, Any]]:
    if len(repo.split("/")) != 2:
        raise GateError("--repo must be OWNER/REPO")
    owner, name = repo.split("/", 1)
    cursor: str | None = None
    pages = 0
    threads: list[dict[str, Any]] = []
    while True:
        argv = ["gh", "api", "graphql", "-f", f"query={THREAD_QUERY}", "-f", f"owner={owner}",
                "-f", f"repo={name}", "-F", f"number={pr}"]
        if cursor:
            argv.extend(["-f", f"cursor={cursor}"])
        payload = cmd(argv)
        if not isinstance(payload, dict) or payload.get("errors"):
            raise GateError(f"GraphQL review threads query failed: {str(payload.get('errors'))[:300]}")
        try:
            connection = payload["data"]["repository"]["pullRequest"]["reviewThreads"]
            nodes, page = connection["nodes"], connection["pageInfo"]
            if not isinstance(nodes, list) or not isinstance(page["hasNextPage"], bool):
                raise ValueError("invalid threads page")
            threads.extend(nodes)
        except (KeyError, TypeError, ValueError) as exc:
            raise GateError(f"Cannot retrieve complete PR review threads: {exc}") from exc
        pages += 1
        if not page["hasNextPage"]:
            break
        new_cursor = page.get("endCursor")
        if not new_cursor or new_cursor == cursor or pages >= 100:
            raise GateError("Review thread pagination incomplete")
        cursor = new_cursor
    return threads


@dataclass
class Snapshot:
    pr: dict[str, Any]
    checks: list[dict[str, Any]]
    required_checks: list[dict[str, Any]]
    threads: list[dict[str, Any]]


def fetch_snapshot(repo: str, pr: int) -> Snapshot:
    return Snapshot(
        pr=gh_pr(repo, pr),
        checks=gh_checks(repo, pr, required=False),
        required_checks=gh_checks(repo, pr, required=True),
        threads=gh_threads(repo, pr),
    )


def check_local(worktree: Path) -> tuple[str, str, list[str]]:
    if not worktree.is_dir():
        raise GateError(f"Worktree does not exist: {worktree}")

    def git(*arguments: str) -> str:
        p = subprocess.run(["git", "-C", str(worktree), *arguments], capture_output=True, text=True)
        if p.returncode:
            raise GateError(f"git {' '.join(arguments)} failed: {p.stderr.strip()[:400]}")
        return p.stdout.strip()

    sha = git("rev-parse", "HEAD")
    branch = git("symbolic-ref", "--quiet", "--short", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=all")
    # Local validation evidence should live in .pr-ready/ and remain untracked.
    changes = []
    for line in status.splitlines():
        path = line[3:].strip().strip('"')
        if path == ".pr-ready" or path.startswith(".pr-ready/"):
            continue
        changes.append(line)
    tracked_evidence = git("ls-files", "--", ".pr-ready")
    if tracked_evidence:
        changes.append("Tracked .pr-ready/ files must be untracked and removed from the PR")
    return sha, branch, changes


def fail_bool(section: dict[str, Any], key: str, errors: list[str]) -> None:
    if section.get(key) is not True:
        errors.append(f"assessment.{key} is not attested true")


def validate_validation(value: Any, sha: str, errors: list[str], log_base: Path | None = None) -> None:
    if not isinstance(value, dict):
        errors.append("local_validation missing or malformed")
        return
    for category in ("tests", "lint", "static_analysis"):
        checks = value.get(category)
        if isinstance(checks, dict) and "not_applicable" in checks:
            reason = checks["not_applicable"]
            if not isinstance(reason, str) or len(reason.strip()) < 25:
                errors.append(f"local_validation.{category} requires a specific not-applicable reason")
            continue
        if not isinstance(checks, list) or not checks:
            errors.append(f"local_validation.{category} needs a passed check or justified not_applicable")
            continue
        for i, item in enumerate(checks):
            loc = f"local_validation.{category}[{i}]"
            if not isinstance(item, dict):
                errors.append(f"{loc} malformed")
                continue
            if not isinstance(item.get("command"), str) or not item["command"].strip():
                errors.append(f"{loc} has no command")
            if type(item.get("exit_code")) is not int or item["exit_code"] != 0:
                errors.append(f"{loc} did not pass")
            if item.get("head_sha") != sha:
                errors.append(f"{loc} stale/missing SHA")
            logfile = item.get("log")
            if not isinstance(logfile, str) or not logfile.strip():
                errors.append(f"{loc} lacks a log artifact")
            elif log_base is not None:
                try:
                    root = log_base.resolve(strict=True)
                    target = Path(logfile)
                    target = (target if target.is_absolute() else root / target).resolve(strict=True)
                    if not target.is_relative_to(root) or not target.is_file():
                        errors.append(f"{loc} log artifact must be an existing file inside its PR worktree")
                except OSError:
                    errors.append(f"{loc} log artifact missing/unreadable: {logfile}")
            if item.get("head_unchanged") is False:
                errors.append(f"{loc} executed while HEAD was changing")


def evaluate(s: Snapshot, evidence: dict[str, Any], *, repo: str, number: int,
             local: tuple[str, str, list[str]] | None = None,
             log_base: Path | None = None) -> list[str]:
    errs: list[str] = []
    pr = s.pr
    sha = pr.get("headRefOid")
    if pr.get("number") != number:
        errs.append("GitHub PR number mismatch")
    if pr.get("state") != "OPEN":
        errs.append("PR is not OPEN")
    if pr.get("isDraft") is not True:
        errs.append("PR is not currently Draft")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        errs.append("GitHub PR head SHA unavailable/invalid")
    if not isinstance(pr.get("headRefName"), str) or not pr["headRefName"]:
        errs.append("GitHub PR head branch unknown")
    if pr.get("mergeable") != "MERGEABLE":
        errs.append(f"Mergeability not confirmed clean: {pr.get('mergeable')}")
    # Do not block merely because a human CHANGES_REQUESTED review remains:
    # technical comments may have been addressed, while human re-approval is
    # explicitly *not* a prerequisite for Draft -> Ready for Review.
    # Unresolved material objections are checked via review threads and the
    # independent review's HEAD-specific assessment below.

    if evidence.get("schema_version") != 1 or evidence.get("repo") != repo or evidence.get("pr") != number:
        errs.append("Evidence schema/repo/PR identity mismatch")
    if evidence.get("head_sha") != sha:
        errs.append("Evidence SHA does not match latest GitHub PR HEAD")

    a = evidence.get("assessment")
    if not isinstance(a, dict):
        errs.append("assessment missing")
    else:
        for key in ("acceptance_criteria_passed", "root_cause_fixed", "architecture_sound",
                    "description_matches_code", "dependencies_resolved", "major_review_comments_resolved",
                    "related_ci_failures_resolved"):
            fail_bool(a, key, errs)
        if not isinstance(a.get("rationale"), str) or len(a["rationale"].strip()) < 30:
            errs.append("assessment.rationale missing meaningful supporting detail")

    r = evidence.get("independent_review")
    if not isinstance(r, dict):
        errs.append("independent_review missing")
    else:
        if r.get("agent") != "pr-reviewer":
            errs.append("Independent pr-reviewer agent is not identified")
        if r.get("head_sha") != sha:
            errs.append("Independent reviewer result stale for current HEAD")
        if r.get("status") != "PASS" or r.get("blocking_findings") != []:
            errs.append("Independent review has not passed / still has blocking findings")
        if not isinstance(r.get("report"), str) or len(r["report"].strip()) < 12:
            errs.append("Independent review needs a report reference/summary")

    validate_validation(evidence.get("local_validation"), sha, errs, log_base=log_base)

    if local:
        local_sha, local_branch, dirty = local
        if local_sha != sha:
            errs.append("Local worktree HEAD differs from remote PR HEAD")
        if local_branch != pr.get("headRefName"):
            errs.append("Local worktree is not on the original PR branch")
        if dirty:
            errs.append(f"Local worktree has uncommitted/untracked edits: {dirty[:4]}")

    if not s.checks:
        errs.append("No CI checks visible; cannot verify required/related checks (fail closed)")
    required_names: set[str] = set()
    for c in s.required_checks:
        name = c.get("name")
        if not isinstance(name, str) or not name:
            errs.append("Required check missing name")
            continue
        required_names.add(name)
        if c.get("bucket") != "pass":
            errs.append(f"Required GitHub check not passing: {name} ({c.get('state')}, {c.get('bucket')})")

    observed_names: set[str] = set()
    unrelated = evidence.get("unrelated_failing_checks", [])
    if not isinstance(unrelated, list):
        errs.append("unrelated_failing_checks malformed")
        unrelated = []
    exemptions = {}
    for item in unrelated:
        if isinstance(item, dict) and isinstance(item.get("name"), str) \
                and isinstance(item.get("reason"), str) and len(item["reason"].strip()) >= 30 \
                and item.get("reviewer_confirmed") is True:
            exemptions[item["name"]] = item
        else:
            errs.append("Invalid unrelated GitHub check exemption (needs exact name, reason, reviewer_confirmed)")

    for c in s.checks:
        name, bucket = c.get("name"), c.get("bucket")
        if not isinstance(name, str) or not name:
            errs.append("Unnamed GitHub CI check")
            continue
        observed_names.add(name)
        if name in required_names and bucket != "pass":
            errs.append(f"Required GitHub check not successful: {name}")
        elif bucket == "pass":
            continue
        elif name not in required_names and bucket == "skipping":
            # GitHub regards a *non-required* neutral/skip as nonblocking.
            continue
        elif bucket in ("fail", "cancel", "pending", "skipping") and name in exemptions and name not in required_names:
            continue
        else:
            errs.append(f"Nonpassing GitHub check: {name} ({c.get('state')}, {bucket})")

    for name in required_names - observed_names:
        errs.append(f"Required GitHub check missing from full check rollup: {name}")
    for name in exemptions.keys() - observed_names:
        errs.append(f"Claimed unrelated check does not exist on HEAD: {name}")

    allowed_threads = evidence.get("unresolved_nonblocking_threads", [])
    if not isinstance(allowed_threads, list):
        errs.append("unresolved_nonblocking_threads malformed")
        allowed_threads = []
    allowed: dict[str, dict[str, Any]] = {}
    for item in allowed_threads:
        if not isinstance(item, dict) or item.get("severity") not in ("P3", "P4") \
                or not isinstance(item.get("id"), str) or not isinstance(item.get("reason"), str) \
                or len(item["reason"].strip()) < 20 or item.get("reviewer_confirmed") is not True:
            errs.append("Invalid unresolved nonblocking thread exemption")
        else:
            allowed[item["id"]] = item
    unresolved_ids: set[str] = set()
    for t in s.threads:
        if not isinstance(t, dict) or not isinstance(t.get("isResolved"), bool):
            errs.append("Unknown review thread state")
            continue
        if not t["isResolved"]:
            thread_id = t.get("id")
            if not isinstance(thread_id, str):
                errs.append("Review thread missing ID")
            else:
                unresolved_ids.add(thread_id)
                if thread_id not in allowed:
                    errs.append(f"Unresolved GitHub review thread: {thread_id}")
    for thread_id in allowed.keys() - unresolved_ids:
        errs.append(f"Thread exemption not an unresolved thread on HEAD: {thread_id}")
    return errs


def json_line(result: dict[str, Any], *, compact: bool) -> None:
    print(json.dumps(result, ensure_ascii=False, indent=None if compact else 2))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="OWNER/REPO")
    parser.add_argument("--pr", type=int, required=True, help="Existing PR number")
    parser.add_argument("--evidence", type=Path, required=True, help="HEAD-specific evidence JSON")
    parser.add_argument("--worktree", type=Path, help="Original PR-branch worktree; verify clean and HEAD")
    parser.add_argument("--ready", action="store_true", help="Execute 'gh pr ready' only after all gates pass")
    parser.add_argument("--compact", action="store_true", help="One-line JSON output")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo) or args.pr <= 0:
        parser.error("--repo must be OWNER/REPO and --pr must be positive")
    if args.ready and not args.worktree:
        parser.error("--ready requires --worktree to verify branch/clean tree")

    try:
        evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
        if not isinstance(evidence, dict):
            raise GateError("Evidence JSON must be an object")
        before = fetch_snapshot(args.repo, args.pr)
        local = check_local(args.worktree) if args.worktree else None
        errors = evaluate(before, evidence, repo=args.repo, number=args.pr, local=local,
                          log_base=args.worktree)
        if errors:
            json_line({"status": "DRAFT-BLOCKED", "pr": before.pr.get("url"),
                       "head_sha": before.pr.get("headRefOid"), "errors": errors}, compact=args.compact)
            return 2
        if not args.ready:
            json_line({"status": "GATE-PASS", "pr": before.pr.get("url"),
                       "head_sha": before.pr.get("headRefOid"),
                       "message": "Use --ready after final review to transition Draft -> Ready for Review"}, compact=args.compact)
            return 0

        # Re-read GitHub and the worktree immediately before the irreversible
        # lifecycle change. Any change causes us to refuse rather than guessing.
        latest = fetch_snapshot(args.repo, args.pr)
        errors = evaluate(latest, evidence, repo=args.repo, number=args.pr,
                          local=check_local(args.worktree), log_base=args.worktree)
        if errors:
            json_line({"status": "DRAFT-BLOCKED", "errors": errors}, compact=args.compact)
            return 2
        action = subprocess.run(["gh", "pr", "ready", str(args.pr), "-R", args.repo],
                                capture_output=True, text=True, check=False)
        if action.returncode:
            raise GateError(f"gh pr ready failed: {(action.stderr or action.stdout).strip()[:700]}")
        after = gh_pr(args.repo, args.pr)
        if after.get("isDraft") is not False or after.get("headRefOid") != evidence["head_sha"]:
            raise GateError("PR state/HEAD changed during Ready transition; status requires reevaluation")
        json_line({"status": "READY", "pr": after.get("url"), "head_sha": after["headRefOid"],
                   "message": "Ready for Review; no merge performed"}, compact=args.compact)
        return 0
    except (GateError, OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
        json_line({"status": "DRAFT-BLOCKED", "errors": [str(exc)]}, compact=args.compact)
        return 2


if __name__ == "__main__":
    sys.exit(main())
