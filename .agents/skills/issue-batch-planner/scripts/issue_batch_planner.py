#!/usr/bin/env python3
"""Issue Batch Planner: read-only grouping of a repository's open Issues (see ../SKILL.md).

Subcommands: collect, shortlist, validate, render, diff. Exit 0 on success and 2 on any refusal or
error; a failure never leaves output that looks complete. Every external command goes through
run_readonly(), which accepts only the read-only command forms checked in _readonly_problem().
Issue titles, bodies and comments are untrusted data: nothing derived from them except Issue
numbers ever reaches a command line, and bodies and comments are never written to disk.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
EXIT_OK = 0
EXIT_FAIL = 2

REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CLASS_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
BRANCH_REF_RE = re.compile(r"refs/heads/[A-Za-z0-9._/-]+\Z")
GITHUB_URL_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")

# The only `gh ... list` field sets the runner accepts.
ISSUE_FIELDS = ("number,title,url,labels,body,comments,createdAt,updatedAt,"
                "blockedBy,parent,subIssues,closedByPullRequestsReferences")
PR_FIELDS = "number,url,isDraft,headRefName,body,closingIssuesReferences,files"
# The only `git grep` pattern the runner accepts: test definitions in the base tree. Names an Issue
# mentions are matched against this list in memory, never passed to git.
TEST_DEF_PATTERN = r"func Test[A-Za-z0-9_]*|def test_[A-Za-z0-9_]*"

ISSUE_STATUSES = ("EXISTING_PR", "BLOCKED_BY", "NEEDS_DECISION", "ALREADY_RESOLVED_REVIEW",
                  "INSUFFICIENT_EVIDENCE", "UNASSIGNED")
PROPOSAL_CLASSIFICATIONS = ("MERGE_CANDIDATE", "RELATED_SEPARATE", "INSUFFICIENT_EVIDENCE")
COVERAGES = ("fully_addressable", "partial_only", "undecided")
EVIDENCE_KINDS = ("issue", "code", "pr", "commit")
REF_STATES = ("OPEN", "CLOSED", "MERGED")
MIN_BATCH, MAX_BATCH = 2, 4


class PlannerError(RuntimeError):
    """A refusal or failure; the command exits 2 and writes nothing that looks complete."""


# --------------------------------------------------------------------------- read-only runner

@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: str
    stderr: str


def _readonly_problem(argv: Any) -> str | None:
    """None when argv is one of the read-only command forms, else why it is refused."""
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        return "argv must be a non-empty list of strings"
    if argv in (["gh", "--version"], ["git", "--version"]):
        return None
    if argv[0] == "gh":
        rest = argv[1:]
        if (len(rest) == 5 and rest[:2] == ["repo", "view"] and REPO_RE.fullmatch(rest[2])
                and rest[3:] == ["--json", "defaultBranchRef"]):
            return None
        if (len(rest) == 10 and rest[:2] in (["issue", "list"], ["pr", "list"]) and rest[2] == "-R"
                and REPO_RE.fullmatch(rest[3]) and rest[4:6] == ["--state", "open"] and rest[6] == "--limit"
                and rest[7].isdigit() and rest[8] == "--json"
                and rest[9] == (ISSUE_FIELDS if rest[0] == "issue" else PR_FIELDS)):
            return None
        return "gh command is not one of the read-only forms"
    if argv[0] == "git":
        if (len(argv) == 4 and argv[1] == "ls-remote" and GITHUB_URL_RE.fullmatch(argv[2])
                and BRANCH_REF_RE.fullmatch(argv[3]) and ".." not in argv[3]):
            return None
        if len(argv) >= 4 and argv[1] == "-C" and argv[2]:
            sub = argv[3:]
            if len(sub) == 3 and sub[:2] == ["cat-file", "-e"] and re.fullmatch(r"[0-9a-f]{40}\^\{commit\}", sub[2]):
                return None
            if len(sub) == 5 and sub[:4] == ["ls-tree", "-r", "-z", "--name-only"] and SHA_RE.fullmatch(sub[4]):
                return None
            if (len(sub) == 9 and sub[:5] == ["grep", "-h", "-o", "-E", TEST_DEF_PATTERN]
                    and SHA_RE.fullmatch(sub[5]) and sub[6:] == ["--", "*.go", "*.py"]):
                return None
            if sub == ["rev-parse", "--show-toplevel"]:
                return None
            if len(sub) == 4 and sub[:3] == ["check-ignore", "-q", "--"]:
                return None
        return "git command is not one of the read-only forms"
    return f"{argv[0]!r} is not an allowed program"


def run_readonly(argv: list[str], *, timeout: int = 300) -> Result:
    """Run one read-only command. The only place in this script that starts a process."""
    problem = _readonly_problem(argv)
    if problem:
        raise PlannerError(f"refused {argv[:3]!r}: {problem}")
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlannerError(f"{argv[0]} {argv[1]} failed to run: {exc}") from exc
    return Result(p.returncode, p.stdout, p.stderr)


# --------------------------------------------------------------------------- shapes

class ListOf:
    def __init__(self, item: Any) -> None:
        self.item = item


class Opt:
    def __init__(self, inner: Any) -> None:
        self.inner = inner


def leaf(pred: Callable[[Any], bool], desc: str) -> tuple[Callable[[Any], bool], str]:
    return pred, desc


POS_INT = leaf(lambda v: type(v) is int and v >= 1, "a positive integer")
NON_NEG_INT = leaf(lambda v: type(v) is int and v >= 0, "a non-negative integer")
BOOL = leaf(lambda v: type(v) is bool, "a boolean")
STR = leaf(lambda v: isinstance(v, str), "a string")
TEXT = leaf(lambda v: isinstance(v, str) and len(v.strip()) >= 3, "a non-empty string")
FULL_SHA = leaf(lambda v: isinstance(v, str) and bool(SHA_RE.fullmatch(v)), "a full lowercase 40-hex SHA")
REPO = leaf(lambda v: isinstance(v, str) and bool(REPO_RE.fullmatch(v)), "OWNER/REPO")
SCHEMA_ONE = leaf(lambda v: v == SCHEMA_VERSION and type(v) is int, f"schema_version {SCHEMA_VERSION}")


def shape_errors(value: Any, spec: Any, where: str) -> list[str]:
    """Every deviation of `value` from `spec`: an exact-key object (dict), ListOf, Opt or a leaf."""
    if isinstance(spec, dict):
        if not isinstance(value, dict):
            return [f"{where}: expected an object"]
        errors = [f"{where}.{k}: missing" for k in spec if k not in value]
        errors += [f"{where}.{k}: unknown field" for k in value if k not in spec]
        for key, sub in spec.items():
            if key in value:
                errors += shape_errors(value[key], sub, f"{where}.{key}")
        return errors
    if isinstance(spec, ListOf):
        if not isinstance(value, list):
            return [f"{where}: expected a list"]
        errors = []
        for i, item in enumerate(value):
            errors += shape_errors(item, spec.item, f"{where}[{i}]")
        return errors
    if isinstance(spec, Opt):
        return [] if value is None else shape_errors(value, spec.inner, where)
    pred, desc = spec
    return [] if pred(value) else [f"{where}: expected {desc}"]


REF_SHAPE = {"number": POS_INT, "state": leaf(lambda v: v in REF_STATES, "OPEN, CLOSED or MERGED")}
SOURCE_SHAPE = {"count": NON_NEG_INT, "limit": POS_INT, "complete": BOOL}
SNAPSHOT_ISSUE_SHAPE = {
    "number": POS_INT, "title": STR, "url": STR, "labels": ListOf(STR),
    "blocked_by": ListOf(REF_SHAPE), "parent": Opt(POS_INT), "sub_issues": ListOf(POS_INT),
    "closed_by_prs": ListOf(REF_SHAPE), "comments_count": NON_NEG_INT, "comments_complete": BOOL,
    "referenced_paths": ListOf(STR), "referenced_issues": ListOf(POS_INT), "referenced_tests": ListOf(STR),
}
SNAPSHOT_PR_SHAPE = {
    "number": POS_INT, "url": STR, "is_draft": BOOL, "closing_issues": ListOf(POS_INT),
    "body_closing_issues": ListOf(POS_INT), "files": ListOf(STR), "files_complete": BOOL,
}
SNAPSHOT_SHAPE = {
    "schema_version": SCHEMA_ONE, "repository": REPO,
    "base": {"branch": TEXT, "sha": FULL_SHA}, "collected_at": TEXT,
    "sources": {"issues": SOURCE_SHAPE, "pull_requests": SOURCE_SHAPE},
    "issues": ListOf(SNAPSHOT_ISSUE_SHAPE), "pull_requests": ListOf(SNAPSHOT_PR_SHAPE),
}
EVIDENCE_SHAPE = {
    "kind": leaf(lambda v: v in EVIDENCE_KINDS, "one of " + ", ".join(EVIDENCE_KINDS)),
    "url": Opt(STR), "path": Opt(STR), "ref_sha": Opt(FULL_SHA), "summary": TEXT,
}
BATCH_SHAPE = {
    "issue_numbers": ListOf(POS_INT), "primary_issue": Opt(POS_INT),
    "classification": leaf(lambda v: v in PROPOSAL_CLASSIFICATIONS, "one of " + ", ".join(PROPOSAL_CLASSIFICATIONS)),
    "root_cause_class": leaf(lambda v: isinstance(v, str) and bool(CLASS_RE.fullmatch(v)), "a kebab-case class label"),
    "invariant": TEXT, "evidence": ListOf(EVIDENCE_SHAPE),
    "pair_compatibility": ListOf({"issues": ListOf(POS_INT), "evidence": TEXT}),
    "acceptance_by_issue": ListOf({"issue": POS_INT,
                                   "coverage": leaf(lambda v: v in COVERAGES, "one of " + ", ".join(COVERAGES)),
                                   "validation": TEXT}),
    "blockers": ListOf(TEXT), "existing_prs": ListOf(POS_INT),
    "human_approval_required": leaf(lambda v: v is True, "true"),
}
PROPOSALS_SHAPE = {
    "schema_version": SCHEMA_ONE,
    "snapshot_sha256": leaf(lambda v: isinstance(v, str) and bool(SHA256_RE.fullmatch(v)), "a sha256 hex digest"),
    "base_sha": FULL_SHA, "batches": ListOf(BATCH_SHAPE),
    "issue_statuses": ListOf({"number": POS_INT,
                              "status": leaf(lambda v: v in ISSUE_STATUSES, "one of " + ", ".join(ISSUE_STATUSES)),
                              "reason": TEXT}),
}


# --------------------------------------------------------------------------- files

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path, what: str) -> tuple[Any, bytes]:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PlannerError(f"cannot read {what} {path}: {exc}") from exc
    try:
        return json.loads(data.decode("utf-8")), data
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlannerError(f"{what} {path} is not valid JSON: {exc}") from exc


def snapshot_problems(snapshot: Any) -> list[str]:
    """Shape and internal consistency of snapshot.json."""
    errors = shape_errors(snapshot, SNAPSHOT_SHAPE, "snapshot")
    if errors:
        return errors
    for key, items in (("issues", snapshot["issues"]), ("pull_requests", snapshot["pull_requests"])):
        numbers = [item["number"] for item in items]
        if len(numbers) != len(set(numbers)):
            errors.append(f"snapshot.{key}: duplicate numbers")
        if snapshot["sources"][key]["count"] != len(items):
            errors.append(f"snapshot.sources.{key}.count does not match the {len(items)} listed")
    return errors


def load_snapshot(path: Path) -> tuple[dict[str, Any], str]:
    """(snapshot, sha256 of its bytes); PlannerError on any shape problem."""
    snapshot, data = read_json(path, "snapshot")
    errors = snapshot_problems(snapshot)
    if errors:
        raise PlannerError("invalid snapshot: " + "; ".join(errors[:20]))
    return snapshot, sha256_bytes(data)


def snapshot_complete(snapshot: dict[str, Any]) -> bool:
    return (snapshot["sources"]["issues"]["complete"] and snapshot["sources"]["pull_requests"]["complete"]
            and all(i["comments_complete"] for i in snapshot["issues"])
            and all(p["files_complete"] for p in snapshot["pull_requests"]))


# --------------------------------------------------------------------------- per-Issue facts

def issue_facts(snapshot: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Deterministic per-Issue facts: hard status (or None when groupable), open closing PRs, open
    blockers, and open PRs that change a path the Issue references without closing it."""
    prs = snapshot["pull_requests"]
    facts: dict[int, dict[str, Any]] = {}
    for issue in snapshot["issues"]:
        n = issue["number"]
        closing = {pr["number"] for pr in prs if n in pr["closing_issues"] or n in pr["body_closing_issues"]}
        closing |= {ref["number"] for ref in issue["closed_by_prs"] if ref["state"] == "OPEN"}
        blockers = sorted(ref["number"] for ref in issue["blocked_by"] if ref["state"] == "OPEN")
        paths = set(issue["referenced_paths"])
        overlapping = sorted(pr["number"] for pr in prs if pr["number"] not in closing and paths & set(pr["files"]))
        labels = set(issue["labels"])
        if closing:
            status, reason = "EXISTING_PR", "open PR " + ", ".join(f"#{x}" for x in sorted(closing)) + " closes it"
        elif blockers:
            status, reason = "BLOCKED_BY", "blocked by open " + ", ".join(f"#{x}" for x in blockers)
        elif "needs-decision" in labels:
            status, reason = "NEEDS_DECISION", "labelled needs-decision"
        elif "likely-resolved" in labels:
            status, reason = "ALREADY_RESOLVED_REVIEW", "labelled likely-resolved; confirm through the existing-PR disposition"
        elif issue["sub_issues"]:
            status, reason = "UNASSIGNED", "umbrella Issue (has sub-issues); not fixable by itself"
        else:
            status, reason = None, ""
        facts[n] = {"status": status, "reason": reason, "open_prs": sorted(closing),
                    "blocked_by": blockers, "overlapping_prs": overlapping}
    return facts


# --------------------------------------------------------------------------- validate

def proposals_problems(snapshot: dict[str, Any], snapshot_sha: str, proposals: Any,
                       base_tree: set[str]) -> list[str]:
    """Every reason the agent-written proposals cannot be accepted for this snapshot."""
    errors = shape_errors(proposals, PROPOSALS_SHAPE, "proposals")
    if errors:
        return errors
    if not snapshot_complete(snapshot):
        errors.append("snapshot is incomplete; proposals cannot be REVIEWED against it")
    if proposals["snapshot_sha256"] != snapshot_sha:
        errors.append("proposals.snapshot_sha256 does not match snapshot.json")
    base_sha = snapshot["base"]["sha"]
    if proposals["base_sha"] != base_sha:
        errors.append("proposals.base_sha does not match the snapshot's base")
    facts = issue_facts(snapshot)
    seen: dict[int, int] = {}
    merge_members: dict[int, int] = {}
    for b, batch in enumerate(proposals["batches"]):
        where = f"batches[{b}]"
        members = batch["issue_numbers"]
        for n in members:
            seen[n] = seen.get(n, 0) + 1
            fact = facts.get(n)
            if fact is None:
                errors.append(f"{where}: #{n} is not an open Issue of the snapshot")
            elif fact["status"] is not None:
                errors.append(f"{where}: #{n} is {fact['status']} ({fact['reason']}); report it in "
                              "issue_statuses, not in a batch")
        if len(set(members)) != len(members):
            errors.append(f"{where}: an Issue is listed twice")
        if not MIN_BATCH <= len(set(members)) <= MAX_BATCH:
            errors.append(f"{where}: a batch has {MIN_BATCH} to {MAX_BATCH} Issues, not {len(set(members))}")
        if not batch["evidence"]:
            errors.append(f"{where}: evidence is empty")
        for e, ev in enumerate(batch["evidence"]):
            if ev["kind"] == "code":
                if ev["ref_sha"] != base_sha:
                    errors.append(f"{where}.evidence[{e}]: code evidence must be at the base SHA {base_sha}")
                if not ev["path"] or ev["path"] not in base_tree:
                    errors.append(f"{where}.evidence[{e}]: {ev['path']!r} is not a file in the base tree")
            elif not ev["url"]:
                errors.append(f"{where}.evidence[{e}]: {ev['kind']} evidence needs a url")
        if batch["classification"] != "MERGE_CANDIDATE":
            continue
        for n in members:
            merge_members[n] = merge_members.get(n, 0) + 1
            fact = facts.get(n)
            if fact:
                missing = sorted(set(fact["overlapping_prs"]) - set(batch["existing_prs"]))
                if missing:
                    errors.append(f"{where}: #{n} overlaps open PR(s) {missing}; list them in existing_prs")
        if batch["primary_issue"] not in members:
            errors.append(f"{where}: primary_issue must be one of the batch's Issues")
        pairs = {tuple(sorted(p["issues"])) for p in batch["pair_compatibility"] if len(set(p["issues"])) == 2}
        for pair in combinations(sorted(set(members)), 2):
            if pair not in pairs:
                errors.append(f"{where}: pair_compatibility lacks #{pair[0]} and #{pair[1]}")
        covered = [a["issue"] for a in batch["acceptance_by_issue"]]
        if sorted(covered) != sorted(set(members)):
            errors.append(f"{where}: acceptance_by_issue must cover each Issue of the batch exactly once")
    for n, count in merge_members.items():
        if count > 1:
            errors.append(f"#{n} is in {count} MERGE_CANDIDATE batches")
    for s, entry in enumerate(proposals["issue_statuses"]):
        n = entry["number"]
        seen[n] = seen.get(n, 0) + 1
        fact = facts.get(n)
        if fact is None:
            errors.append(f"issue_statuses[{s}]: #{n} is not an open Issue of the snapshot")
        elif fact["status"] is not None and entry["status"] != fact["status"]:
            errors.append(f"issue_statuses[{s}]: #{n} is {fact['status']} ({fact['reason']}), not {entry['status']}")
    for n in sorted(facts):
        if seen.get(n, 0) != 1:
            errors.append(f"#{n} appears {seen.get(n, 0)} times; every open Issue appears exactly once")
    return errors


def ensure_commit(repo_dir: Path, sha: str) -> None:
    r = run_readonly(["git", "-C", str(repo_dir), "cat-file", "-e", f"{sha}^{{commit}}"])
    if r.returncode != 0:
        raise PlannerError(f"{sha} is not a commit in {repo_dir}; fetch the default branch first")


def base_tree_paths(repo_dir: Path, sha: str) -> set[str]:
    ensure_commit(repo_dir, sha)
    r = run_readonly(["git", "-C", str(repo_dir), "ls-tree", "-r", "-z", "--name-only", sha])
    if r.returncode != 0:
        raise PlannerError(f"git ls-tree {sha} failed: {r.stderr.strip()[:300]}")
    return {p for p in r.stdout.split("\0") if p}


def cmd_validate(args: argparse.Namespace) -> int:
    snapshot, digest = load_snapshot(args.snapshot)
    proposals, _ = read_json(args.proposals, "proposals")
    tree = base_tree_paths(args.repo_dir, snapshot["base"]["sha"])
    errors = proposals_problems(snapshot, digest, proposals, tree)
    result = {"status": "INVALID" if errors else "VALID", "errors": errors}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return EXIT_FAIL if errors else EXIT_OK


def cmd_not_implemented(args: argparse.Namespace) -> int:
    raise PlannerError(f"{args.command} is not implemented yet")


# --------------------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="check agent-written proposals.json against snapshot.json")
    v.add_argument("--snapshot", required=True, type=Path)
    v.add_argument("--proposals", required=True, type=Path)
    v.add_argument("--repo-dir", required=True, type=Path)
    v.set_defaults(func=cmd_validate)
    for name in ("collect", "shortlist", "render", "diff"):
        p = sub.add_parser(name, help="not implemented yet")
        p.set_defaults(func=cmd_not_implemented)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PlannerError as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
