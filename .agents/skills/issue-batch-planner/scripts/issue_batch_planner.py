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
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
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
PR_FIELDS = "number,url,isDraft,headRefName,body,closingIssuesReferences,files,changedFiles"
# The only `git grep` pattern the runner accepts: test definitions in the base tree. Names an Issue
# mentions are matched against this list in memory, never passed to git.
TEST_DEF_PATTERN = r"func Test[A-Za-z0-9_]*|def test_[A-Za-z0-9_]*"

ISSUE_STATUSES = ("EXISTING_PR", "BLOCKED_BY", "NEEDS_DECISION", "ALREADY_RESOLVED_REVIEW",
                  "INSUFFICIENT_EVIDENCE", "UNASSIGNED")
PROPOSAL_CLASSIFICATIONS = ("MERGE_CANDIDATE", "RELATED_SEPARATE", "INSUFFICIENT_EVIDENCE")
COVERAGES = ("fully_addressable", "partial_only", "undecided")
EVIDENCE_KINDS = ("issue", "code", "pr", "commit")
# blocked_by carries GitHub's Issue state (OPEN/CLOSED). closedByPullRequestsReferences carries no state:
# collect marks a same-repository PR OPEN or NOT_OPEN against the complete open-PR list, and a PR of another
# repository UNKNOWN. OPEN and UNKNOWN both block grouping (fail closed).
REF_STATES = ("OPEN", "CLOSED", "NOT_OPEN", "UNKNOWN")
BLOCKING_REF_STATES = ("OPEN", "UNKNOWN")
MIN_BATCH, MAX_BATCH = 2, 4
DEFAULT_LIMIT = 1000
# `gh issue list --json comments` returns at most 100 comments per Issue (2026-11-16: two cli/cli
# Issues with more than 120 comments came back with exactly 100). At the cap the Issue is incomplete.
GH_COMMENT_CAP = 100
# Path prefixes an Issue may reference; anything else in the text is ignored.
PATH_RE = re.compile(r"(?<![\w./-])((?:playbooks|cmd|internal|contracts|\.agents|docs/verification|group_vars|scripts)"
                     r"/[\w./-]*[\w-])")
TEST_NAME_RE = re.compile(r"\b(Test[A-Z]\w*|test_\w+)\b")
TEST_DEF_NAME_RE = re.compile(r"(?:func |def )(\w+)")
TITLE_TOKEN_RE = re.compile(r"[a-z0-9]+")
# shortlist weights: ranking only, never a verdict (references/classification-rubric.md).
STRONG_WEIGHTS = {"shared_paths": 25, "cross_reference": 10, "shared_tests": 20}
WEAK_WEIGHTS = {"shared_area_label": 10, "similar_title": 5}
PAIR_THRESHOLD = 30
TITLE_JACCARD = 0.3


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


REF_SHAPE = {"number": POS_INT, "state": leaf(lambda v: v in REF_STATES, "one of " + ", ".join(REF_STATES)),
             "url": STR}
SOURCE_SHAPE = {"count": NON_NEG_INT, "limit": POS_INT, "complete": BOOL}
SNAPSHOT_ISSUE_SHAPE = {
    "number": POS_INT, "title": STR, "url": STR, "labels": ListOf(STR),
    "blocked_by": ListOf(REF_SHAPE), "relations_complete": BOOL, "parent": Opt(POS_INT),
    "sub_issue_count": NON_NEG_INT,
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
            and all(i["comments_complete"] and i["relations_complete"] for i in snapshot["issues"])
            and all(p["files_complete"] for p in snapshot["pull_requests"]))


# --------------------------------------------------------------------------- per-Issue facts

def issue_facts(snapshot: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Deterministic per-Issue facts: hard status (or None when groupable), open closing PRs, open
    blockers, and open PRs that change a path the Issue references without closing it."""
    prs = snapshot["pull_requests"]
    own = f"https://github.com/{snapshot['repository']}/"

    def name(ref: dict[str, Any]) -> str:
        return f"#{ref['number']}" if ref["url"].lower().startswith(own.lower()) else ref["url"]

    facts: dict[int, dict[str, Any]] = {}
    for issue in snapshot["issues"]:
        n = issue["number"]
        closing_refs = {f"#{pr['number']}" for pr in prs if n in pr["closing_issues"] or n in pr["body_closing_issues"]}
        closing_refs |= {name(ref) for ref in issue["closed_by_prs"] if ref["state"] in BLOCKING_REF_STATES}
        closing = sorted(int(x[1:]) for x in closing_refs if x.startswith("#"))
        blocker_refs = sorted({name(ref) for ref in issue["blocked_by"] if ref["state"] in BLOCKING_REF_STATES})
        paths = set(issue["referenced_paths"])
        overlapping = sorted(pr["number"] for pr in prs if pr["number"] not in closing and paths & set(pr["files"]))
        labels = set(issue["labels"])
        if closing_refs:
            status, reason = "EXISTING_PR", "open or unverifiable PR " + ", ".join(sorted(closing_refs)) + " closes it"
        elif blocker_refs:
            status, reason = "BLOCKED_BY", "blocked by open " + ", ".join(blocker_refs)
        elif "needs-decision" in labels:
            status, reason = "NEEDS_DECISION", "labelled needs-decision"
        elif "likely-resolved" in labels:
            status, reason = "ALREADY_RESOLVED_REVIEW", "labelled likely-resolved; confirm through the existing-PR disposition"
        elif issue["sub_issue_count"]:
            status, reason = "UNASSIGNED", "umbrella Issue (has sub-issues); not fixable by itself"
        else:
            status, reason = None, ""
        facts[n] = {"status": status, "reason": reason, "open_prs": closing,
                    "blocked_by": blocker_refs, "overlapping_prs": overlapping}
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


# --------------------------------------------------------------------------- output files

def dumps(obj: Any) -> str:
    """Deterministic JSON: sorted keys, two-space indent, trailing newline."""
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def prepare_out_dir(path: Path, *, refuse_existing: tuple[str, ...] | None = None) -> Path:
    """An output directory outside any Git work tree or ignored by it, created if missing. By default it
    must be empty; with `refuse_existing`, it may hold earlier steps' files but none of those names."""
    out = Path(os.path.abspath(Path(path).expanduser()))
    if out.exists() and not out.is_dir():
        raise PlannerError(f"--out-dir {out} is not a directory")
    if refuse_existing is None and out.exists() and any(out.iterdir()):
        raise PlannerError(f"--out-dir {out} must be an empty directory or not exist")
    for name in refuse_existing or ():
        if (out / name).exists():
            raise PlannerError(f"{out / name} already exists; render into a new directory")
    probe = out
    while not probe.exists():
        probe = probe.parent
    top = run_readonly(["git", "-C", str(probe), "rev-parse", "--show-toplevel"])
    if top.returncode == 0 and top.stdout.strip():
        ignored = run_readonly(["git", "-C", top.stdout.strip(), "check-ignore", "-q", "--", str(out)])
        if ignored.returncode != 0:
            raise PlannerError(f"--out-dir {out} is inside the work tree {top.stdout.strip()} and not ignored; "
                               "use an ignored path such as .verification/issue-batch-planner/<date>")
    out.mkdir(parents=True, exist_ok=True)
    return out


def write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- collect

_ISSUE_GATE: Any = None


def issue_gate() -> Any:
    """issue-to-pr's issue_gate.py, loaded by path: its closes_issue() is the one closing-keyword rule."""
    global _ISSUE_GATE
    if _ISSUE_GATE is None:
        path = Path(__file__).resolve().parents[2] / "issue-to-pr" / "scripts" / "issue_gate.py"
        spec = importlib.util.spec_from_file_location("pilot_issue_gate", path)
        if spec is None or spec.loader is None or not path.is_file():
            raise PlannerError(f"issue-to-pr's issue_gate.py is missing: {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules.setdefault("pilot_issue_gate", module)
        spec.loader.exec_module(module)
        _ISSUE_GATE = module
    return _ISSUE_GATE


def _gh_json(argv: list[str], what: str) -> Any:
    r = run_readonly(argv)
    if r.returncode != 0:
        raise PlannerError(f"{what} failed: {(r.stderr or r.stdout).strip()[:300]}")
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError as exc:
        raise PlannerError(f"{what} did not return JSON: {exc}") from exc


def _need(obj: Any, keys: tuple[str, ...], what: str) -> dict[str, Any]:
    if not isinstance(obj, dict) or any(k not in obj for k in keys):
        raise PlannerError(f"unexpected {what} shape from gh (needs {', '.join(keys)})")
    return obj


def base_commit(repo: str, repo_dir: Path) -> tuple[str, str]:
    view = _need(_gh_json(["gh", "repo", "view", repo, "--json", "defaultBranchRef"], "gh repo view"),
                 ("defaultBranchRef",), "repo view")
    branch = view["defaultBranchRef"].get("name") if isinstance(view["defaultBranchRef"], dict) else None
    if not isinstance(branch, str) or not BRANCH_REF_RE.fullmatch(f"refs/heads/{branch}"):
        raise PlannerError(f"unexpected default branch {branch!r}")
    r = run_readonly(["git", "ls-remote", f"https://github.com/{repo}", f"refs/heads/{branch}"])
    lines = [line.split("\t") for line in r.stdout.splitlines() if line.strip()]
    if r.returncode != 0 or len(lines) != 1 or len(lines[0]) != 2 or not SHA_RE.fullmatch(lines[0][0]) \
            or lines[0][1] != f"refs/heads/{branch}":
        raise PlannerError(f"cannot resolve refs/heads/{branch} of {repo}: {(r.stderr or r.stdout).strip()[:200]}")
    sha = lines[0][0]
    ensure_commit(repo_dir, sha)
    return branch, sha


def base_test_names(repo_dir: Path, sha: str) -> set[str]:
    r = run_readonly(["git", "-C", str(repo_dir), "grep", "-h", "-o", "-E", TEST_DEF_PATTERN, sha,
                      "--", "*.go", "*.py"])
    if r.returncode == 1 and not r.stdout:
        return set()
    if r.returncode != 0:
        raise PlannerError(f"git grep for test definitions failed: {r.stderr.strip()[:200]}")
    return {m.group(1) for line in r.stdout.splitlines() for m in [TEST_DEF_NAME_RE.match(line)] if m}


def _issue_refs(text: str, repo: str, own: int) -> set[int]:
    found = {int(m) for m in re.findall(r"(?<![\w/#&])#([1-9][0-9]{0,6})\b", text)}
    found |= {int(m) for m in re.findall(re.escape(f"https://github.com/{repo}/issues/") + r"([1-9][0-9]{0,6})\b",
                                         text, re.IGNORECASE)}
    found.discard(own)
    return found


def _ref(node: Any, repo: str, kind: str, open_prs: set[int] | None) -> dict[str, Any]:
    node = _need(node, ("number", "url"), kind)
    if type(node["number"]) is not int or not isinstance(node["url"], str):
        raise PlannerError(f"unexpected {kind} entry from gh")
    if open_prs is None:  # an Issue relation: GitHub's own state
        state = node.get("state")
        if state not in ("OPEN", "CLOSED"):
            raise PlannerError(f"unexpected {kind} state {state!r}")
    elif node["url"].lower() == f"https://github.com/{repo}/pull/{node['number']}".lower():
        state = "OPEN" if node["number"] in open_prs else "NOT_OPEN"
    else:
        state = "UNKNOWN"
    return {"number": node["number"], "state": state, "url": node["url"]}


def build_snapshot(repo: str, branch: str, sha: str, raw_issues: Any, raw_prs: Any, limit: int,
                   tree: set[str], tests: set[str], collected_at: str) -> dict[str, Any]:
    """snapshot.json from `gh issue list` / `gh pr list` output. Issue bodies and comments are read
    here and dropped: only derived paths, Issue numbers and test names are kept."""
    if not isinstance(raw_issues, list) or not isinstance(raw_prs, list):
        raise PlannerError("gh list output is not a JSON list")
    gate = issue_gate()
    issue_numbers = []
    for raw in raw_issues:
        _need(raw, ("number",), "issue")
        issue_numbers.append(raw["number"])
    prs = []
    open_pr_numbers = set()
    for raw in raw_prs:
        raw = _need(raw, ("number", "url", "isDraft", "body", "closingIssuesReferences", "files", "changedFiles"), "pr")
        if type(raw["number"]) is not int or not isinstance(raw["files"], list) or type(raw["changedFiles"]) is not int:
            raise PlannerError("unexpected pr field types from gh")
        open_pr_numbers.add(raw["number"])
        body = raw["body"] if isinstance(raw["body"], str) else ""
        closing = sorted({c["number"] for c in raw["closingIssuesReferences"]
                          if _need(c, ("number", "url"), "closing reference")["url"].lower()
                          == f"https://github.com/{repo}/issues/{c['number']}".lower()})
        files = sorted({_need(f, ("path",), "pr file")["path"] for f in raw["files"]})
        prs.append({"number": raw["number"], "url": raw["url"], "is_draft": bool(raw["isDraft"]),
                    "closing_issues": closing,
                    "body_closing_issues": sorted(n for n in issue_numbers if gate.closes_issue(body, repo, n)),
                    "files": files, "files_complete": len(raw["files"]) == raw["changedFiles"]})
    issues = []
    for raw in raw_issues:
        raw = _need(raw, ("number", "title", "url", "labels", "body", "comments", "blockedBy", "parent",
                          "subIssues", "closedByPullRequestsReferences"), "issue")
        comments = raw["comments"] if isinstance(raw["comments"], list) else None
        blocked = _need(raw["blockedBy"], ("nodes", "totalCount"), "blockedBy")
        subs = _need(raw["subIssues"], ("totalCount",), "subIssues")
        if comments is None or not isinstance(blocked["nodes"], list) or type(subs["totalCount"]) is not int:
            raise PlannerError("unexpected issue field types from gh")
        texts = [raw["body"] if isinstance(raw["body"], str) else ""]
        texts += [c.get("body") or "" for c in comments if isinstance(c, dict)]
        text = "\n".join(texts)
        parent = raw["parent"]
        issues.append({
            "number": raw["number"], "title": str(raw["title"]), "url": str(raw["url"]),
            "labels": sorted({_need(label, ("name",), "label")["name"] for label in raw["labels"]}),
            "blocked_by": sorted((_ref(b, repo, "blockedBy", None) for b in blocked["nodes"]),
                                 key=lambda r: (r["url"], r["number"])),
            "relations_complete": len(blocked["nodes"]) == blocked["totalCount"],
            "parent": _need(parent, ("number",), "parent")["number"] if parent else None,
            "sub_issue_count": subs["totalCount"],
            "closed_by_prs": sorted((_ref(c, repo, "closedByPullRequestsReferences", open_pr_numbers)
                                     for c in raw["closedByPullRequestsReferences"]),
                                    key=lambda r: (r["url"], r["number"])),
            "comments_count": len(comments), "comments_complete": len(comments) < GH_COMMENT_CAP,
            "referenced_paths": sorted({m for m in PATH_RE.findall(text) if m in tree}),
            "referenced_issues": sorted(_issue_refs(text, repo, raw["number"])),
            "referenced_tests": sorted({m for m in TEST_NAME_RE.findall(text) if m in tests}),
        })
    issues.sort(key=lambda i: i["number"])
    prs.sort(key=lambda p: p["number"])
    snapshot = {
        "schema_version": SCHEMA_VERSION, "repository": repo, "base": {"branch": branch, "sha": sha},
        "collected_at": collected_at,
        "sources": {"issues": {"count": len(issues), "limit": limit, "complete": len(raw_issues) < limit},
                    "pull_requests": {"count": len(prs), "limit": limit, "complete": len(raw_prs) < limit}},
        "issues": issues, "pull_requests": prs,
    }
    errors = snapshot_problems(snapshot)
    if errors:
        raise PlannerError("collected data does not fit the snapshot shape: " + "; ".join(errors[:10]))
    return snapshot


def cmd_collect(args: argparse.Namespace) -> int:
    if not REPO_RE.fullmatch(args.repo):
        raise PlannerError("--repo must be OWNER/REPO")
    if args.limit < 1:
        raise PlannerError("--limit must be positive")
    started = now_iso()
    out = prepare_out_dir(args.out_dir)
    repo_dir = Path(os.path.abspath(args.repo_dir))
    branch, sha = base_commit(args.repo, repo_dir)
    tree = base_tree_paths(repo_dir, sha)
    tests = base_test_names(repo_dir, sha)
    limit = str(args.limit)
    raw_issues = _gh_json(["gh", "issue", "list", "-R", args.repo, "--state", "open", "--limit", limit,
                           "--json", ISSUE_FIELDS], "gh issue list")
    raw_prs = _gh_json(["gh", "pr", "list", "-R", args.repo, "--state", "open", "--limit", limit,
                        "--json", PR_FIELDS], "gh pr list")
    snapshot = build_snapshot(args.repo, branch, sha, raw_issues, raw_prs, args.limit, tree, tests, now_iso())
    write_atomic(out / "snapshot.json", dumps(snapshot))
    complete = snapshot_complete(snapshot)
    status = "COMPLETE" if complete else "INCOMPLETE"
    write_atomic(out / "run-metadata.json", dumps({
        "command": "collect", "started_at": started, "finished_at": now_iso(), "status": status,
        "gh_version": run_readonly(["gh", "--version"]).stdout.splitlines()[:1],
        "git_version": run_readonly(["git", "--version"]).stdout.strip()}))
    print(dumps({"status": status, "snapshot": str(out / "snapshot.json"), "base_sha": sha,
                 "issues": len(snapshot["issues"]), "pull_requests": len(snapshot["pull_requests"])}), end="")
    return EXIT_OK if complete else EXIT_FAIL


# --------------------------------------------------------------------------- shortlist

def _title_tokens(title: str) -> set[str]:
    return {t for t in TITLE_TOKEN_RE.findall(title.lower()) if len(t) >= 3}


def pair_features(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    paths = sorted(set(a["referenced_paths"]) & set(b["referenced_paths"]))
    tests = sorted(set(a["referenced_tests"]) & set(b["referenced_tests"]))
    cross = a["number"] in b["referenced_issues"] or b["number"] in a["referenced_issues"]
    areas = sorted({x for x in a["labels"] if x.startswith("area:")} & set(b["labels"]))
    ta, tb = _title_tokens(a["title"]), _title_tokens(b["title"])
    jaccard = len(ta & tb) / len(ta | tb) if ta | tb else 0.0
    signals = {"shared_paths": bool(paths), "cross_reference": cross, "shared_tests": bool(tests),
               "shared_area_label": bool(areas), "similar_title": jaccard >= TITLE_JACCARD}
    weights = {**STRONG_WEIGHTS, **WEAK_WEIGHTS}
    score = sum(weights[k] for k, on in signals.items() if on)
    strong = any(signals[k] for k in STRONG_WEIGHTS)
    return {"issues": sorted([a["number"], b["number"]]), "score": score, "candidate": strong and score >= PAIR_THRESHOLD,
            "shared_paths": paths, "shared_tests": tests, "cross_reference": cross, "shared_area_labels": areas,
            "title_jaccard": round(jaccard, 3)}


def batch_id(root_cause_class: str, numbers: list[int]) -> str:
    return hashlib.sha256(f"{root_cause_class}|{','.join(str(n) for n in sorted(numbers))}".encode()).hexdigest()[:12]


def shortlist(snapshot: dict[str, Any]) -> dict[str, Any]:
    """candidates.json: per-Issue status, scored pairs and non-transitive heuristic groups. Depends only on
    the snapshot's content, not its order or collection time."""
    facts = issue_facts(snapshot)
    by_number = {i["number"]: i for i in snapshot["issues"]}
    eligible = sorted(n for n, f in facts.items() if f["status"] is None)
    pairs = []
    for x, y in combinations(eligible, 2):
        f = pair_features(by_number[x], by_number[y])
        if f["shared_paths"] or f["shared_tests"] or f["cross_reference"]:  # weak-only pairs are noise
            pairs.append(f)
    pairs.sort(key=lambda p: (-p["score"], p["issues"]))
    linked = {tuple(p["issues"]) for p in pairs if p["candidate"]}
    score_of = {tuple(p["issues"]): p["score"] for p in pairs}
    member_of: dict[int, list[int]] = {}
    groups: list[list[int]] = []
    for p in pairs:
        if not p["candidate"]:
            continue
        a, b = p["issues"]
        ga, gb = member_of.get(a), member_of.get(b)
        if ga is None and gb is None:
            group = [a, b]
            groups.append(group)
            member_of[a] = member_of[b] = group
            continue
        if ga is not None and gb is not None:
            continue
        group, new = (ga, b) if ga is not None else (gb, a)
        if len(group) < MAX_BATCH and all(tuple(sorted((m, new))) in linked for m in group):
            group.append(new)
            member_of[new] = group
    out_groups = []
    for g in groups:
        members = sorted(g)
        out_groups.append({"batch_id": batch_id("heuristic", members), "classification": "HEURISTIC_CANDIDATE",
                           "issue_numbers": members,
                           "score": sum(score_of[pair] for pair in combinations(members, 2))})
    out_groups.sort(key=lambda g: (-g["score"], g["issue_numbers"]))
    grouped = {n for g in out_groups for n in g["issue_numbers"]}
    return {
        "schema_version": SCHEMA_VERSION, "repository": snapshot["repository"], "base_sha": snapshot["base"]["sha"],
        "complete": snapshot_complete(snapshot),
        "issue_numbers": sorted(by_number),
        "issue_statuses": [{"number": n, "status": facts[n]["status"] or "ELIGIBLE", "reason": facts[n]["reason"],
                            "open_prs": facts[n]["open_prs"], "blocked_by": facts[n]["blocked_by"],
                            "overlapping_prs": facts[n]["overlapping_prs"]} for n in sorted(facts)],
        "pairs": pairs, "groups": out_groups,
        "unassigned": [n for n in eligible if n not in grouped],
    }


def cmd_shortlist(args: argparse.Namespace) -> int:
    snapshot, _ = load_snapshot(args.snapshot)
    out = Path(os.path.abspath(args.out))
    if out.exists():
        raise PlannerError(f"--out {out} already exists")
    if not out.parent.is_dir():
        raise PlannerError(f"--out directory {out.parent} does not exist")
    candidates = shortlist(snapshot)
    write_atomic(out, dumps(candidates))
    print(dumps({"status": "COMPLETE" if candidates["complete"] else "INCOMPLETE",
                 "groups": len(candidates["groups"]), "pairs": len(candidates["pairs"])}), end="")
    return EXIT_OK if candidates["complete"] else EXIT_FAIL


# --------------------------------------------------------------------------- render

REPORTED = ("REVIEWED", "HEURISTIC_ONLY")
REPORT_STATUSES = REPORTED + ("INCOMPLETE", "BLOCKED")
HEURISTIC_WARNING = "Not reviewed against the code: do not use these groups as a basis for a batch fix."
_SECRET_SCAN: Any = None


def secret_scan() -> Any:
    """The repository's shared secret scanner (_shared/scripts/secret_scan.py), loaded by path."""
    global _SECRET_SCAN
    if _SECRET_SCAN is None:
        path = Path(__file__).resolve().parents[2] / "_shared" / "scripts" / "secret_scan.py"
        spec = importlib.util.spec_from_file_location("pilot_secret_scan", path)
        if spec is None or spec.loader is None or not path.is_file():
            raise PlannerError(f"the shared secret scanner is missing: {path}")
        module = sys.modules.get("pilot_secret_scan") or importlib.util.module_from_spec(spec)
        if "pilot_secret_scan" not in sys.modules:
            sys.modules["pilot_secret_scan"] = module
            spec.loader.exec_module(module)
        _SECRET_SCAN = module
    return _SECRET_SCAN


def _strings(obj: Any, where: str = "report") -> list[tuple[str, str]]:
    if isinstance(obj, str):
        return [(where, obj)]
    if isinstance(obj, dict):
        return [x for k in sorted(obj) for x in _strings(obj[k], f"{where}.{k}")]
    if isinstance(obj, list):
        return [x for i, v in enumerate(obj) for x in _strings(v, f"{where}[{i}]")]
    return []


def secret_findings(report: dict[str, Any]) -> list[dict[str, str]]:
    """Value-free findings (field and class) over every string of the report."""
    scanner = secret_scan()
    return [{"field": where, "class": f.cls} for where, text in _strings(report) for f in scanner.scan_text(where, text)]


def report_content_sha256(report: dict[str, Any]) -> str:
    body = {k: v for k, v in report.items() if k not in ("content_sha256", "collected_at")}
    return sha256_bytes(dumps(body).encode("utf-8"))


def _batch_out(batch: dict[str, Any]) -> dict[str, Any]:
    members = sorted(set(batch["issue_numbers"]))
    return {
        "batch_id": batch_id(batch["root_cause_class"], members), "classification": batch["classification"],
        "issue_numbers": members, "primary_issue": batch["primary_issue"],
        "root_cause_class": batch["root_cause_class"], "invariant": batch["invariant"],
        "evidence": [{k: ev[k] for k in ("kind", "url", "path", "ref_sha", "summary")} for ev in batch["evidence"]],
        "pair_compatibility": sorted(({"issues": sorted(p["issues"]), "evidence": p["evidence"]}
                                      for p in batch["pair_compatibility"]), key=lambda p: p["issues"]),
        "acceptance_by_issue": sorted(({k: a[k] for k in ("issue", "coverage", "validation")}
                                       for a in batch["acceptance_by_issue"]), key=lambda a: a["issue"]),
        "all_fully_addressable": all(a["coverage"] == "fully_addressable" for a in batch["acceptance_by_issue"]),
        "blockers": list(batch["blockers"]), "existing_prs": sorted(set(batch["existing_prs"])),
        "human_approval_required": True,
    }


def build_report(snapshot: dict[str, Any], candidates: dict[str, Any], proposals: dict[str, Any] | None) -> dict[str, Any]:
    """report.json: whitelisted fields only. Every open Issue appears exactly once in `issues`."""
    by_number = {i["number"]: i for i in snapshot["issues"]}
    facts = issue_facts(snapshot)
    complete = snapshot_complete(snapshot)
    issue_rows: dict[int, dict[str, Any]] = {}
    batches: list[dict[str, Any]] = []
    if proposals is not None:
        status = "REVIEWED" if complete else "INCOMPLETE"
        for batch in proposals["batches"]:
            out = _batch_out(batch)
            batches.append(out)
            for n in out["issue_numbers"]:
                issue_rows[n] = {"status": out["classification"], "batch_id": out["batch_id"], "reason": out["invariant"]}
        for entry in proposals["issue_statuses"]:
            issue_rows[entry["number"]] = {"status": entry["status"], "batch_id": None, "reason": entry["reason"]}
        heuristic: list[dict[str, Any]] = []
    else:
        status = "HEURISTIC_ONLY" if complete else "INCOMPLETE"
        heuristic = [{k: g[k] for k in ("batch_id", "classification", "issue_numbers", "score")} for g in candidates["groups"]]
        for g in heuristic:
            for n in g["issue_numbers"]:
                issue_rows[n] = {"status": "HEURISTIC_CANDIDATE", "batch_id": g["batch_id"], "reason": "heuristic group"}
        for entry in candidates["issue_statuses"]:
            if entry["number"] not in issue_rows:
                st = entry["status"] if entry["status"] != "ELIGIBLE" else "UNASSIGNED"
                issue_rows[entry["number"]] = {"status": st, "batch_id": None,
                                               "reason": entry["reason"] or "no related Issue found"}
    issues = [{"number": n, "title": by_number[n]["title"], "url": by_number[n]["url"], **issue_rows[n],
               "open_prs": facts[n]["open_prs"], "overlapping_prs": facts[n]["overlapping_prs"]}
              for n in sorted(issue_rows) if n in by_number]
    missing = sorted(set(by_number) - set(issue_rows))
    if missing or len(issues) != len(by_number):
        raise PlannerError(f"open Issues missing from the report: {missing}")
    report = {
        "schema_version": SCHEMA_VERSION, "repository": snapshot["repository"], "status": status,
        "base": snapshot["base"], "collected_at": snapshot["collected_at"], "snapshot_complete": complete,
        "counts": {"issues": len(by_number), "pull_requests": len(snapshot["pull_requests"]),
                   "merge_candidates": sum(b["classification"] == "MERGE_CANDIDATE" for b in batches),
                   "heuristic_groups": len(heuristic)},
        "batches": sorted(batches, key=lambda b: (b["classification"] != "MERGE_CANDIDATE", b["issue_numbers"])),
        "heuristic_groups": heuristic, "issues": issues,
        "warnings": [HEURISTIC_WARNING] if status == "HEURISTIC_ONLY" else
                    (["The snapshot is incomplete: this report cannot be used as a basis for a batch fix."]
                     if status == "INCOMPLETE" else []),
    }
    report["content_sha256"] = report_content_sha256(report)
    return report


def render_markdown(report: dict[str, Any]) -> str:
    def ref(n: int) -> str:
        return f"#{n}"

    lines = [f"# Issue batch report: {report['repository']}", "",
             f"- Status: **{report['status']}**",
             f"- Base: `{report['base']['branch']}` @ `{report['base']['sha']}`; data collected {report['collected_at']}",
             f"- Open Issues: {report['counts']['issues']}; open PRs: {report['counts']['pull_requests']}; "
             f"data complete: {'yes' if report['snapshot_complete'] else 'no'}",
             "- Every batch needs your approval; nothing here authorizes work.", ""]
    for w in report["warnings"]:
        lines += [f"> **{w}**", ""]
    merge = [b for b in report["batches"] if b["classification"] == "MERGE_CANDIDATE"]
    other = [b for b in report["batches"] if b["classification"] != "MERGE_CANDIDATE"]
    lines += ["## Suggested batches", ""]
    if not merge:
        lines += ["None.", ""]
    for b in merge:
        others = [n for n in b["issue_numbers"] if n != b["primary_issue"]]
        lines += [f"### `{b['batch_id']}`: {b['root_cause_class']}", "",
                  f"- Primary: {ref(b['primary_issue'])} (`issue-to-pr` fixes it with `Fixes`); "
                  f"related: {', '.join(ref(n) for n in others)} (`Refs` only, closed after the merge)",
                  f"- Invariant: {b['invariant']}",
                  "- Evidence: " + "; ".join(f"{e['kind']} {e['path'] or e['url']}: {e['summary']}" for e in b["evidence"]),
                  "- Per Issue: " + "; ".join(f"{ref(a['issue'])} {a['coverage']} ({a['validation']})"
                                              for a in b["acceptance_by_issue"]),
                  "- Pairs: " + "; ".join(f"{ref(p['issues'][0])}+{ref(p['issues'][1])}: {p['evidence']}"
                                          for p in b["pair_compatibility"])]
        if not b["all_fully_addressable"]:
            lines.append("- Not every Issue is fully addressable: keep the others open after the merge.")
        if b["existing_prs"] or b["blockers"]:
            lines.append("- Blockers: " + "; ".join([*(f"open PR {ref(n)}" for n in b["existing_prs"]), *b["blockers"]]))
        lines.append("")
    lines += ["## Not suggested for a shared fix", ""]
    lines += [f"- `{b['batch_id']}` {b['classification']}: {', '.join(ref(n) for n in b['issue_numbers'])}: {b['invariant']}"
              for b in other] or ["None."]
    lines.append("")
    if report["heuristic_groups"]:
        lines += ["## Unreviewed heuristic groups", ""]
        lines += [f"- `{g['batch_id']}` score {g['score']}: {', '.join(ref(n) for n in g['issue_numbers'])}"
                  for g in report["heuristic_groups"]]
        lines.append("")
    sections = (("Already covered by an open PR", ("EXISTING_PR",)),
                ("Needs a decision or blocked", ("NEEDS_DECISION", "BLOCKED_BY")),
                ("Possibly resolved: confirm through the existing-PR disposition", ("ALREADY_RESOLVED_REVIEW",)),
                ("Insufficient evidence", ("INSUFFICIENT_EVIDENCE",)),
                ("Not grouped", ("UNASSIGNED",)))
    for title, statuses in sections:
        rows = [i for i in report["issues"] if i["status"] in statuses]
        if rows:
            lines += [f"## {title}", ""]
            lines += [f"- {ref(i['number'])} {i['title']}: {i['reason']}" for i in rows]
            lines.append("")
    lines += ["## Limits", "",
              "- Groups come from shared paths, tests and cross-references; a missing link means no group, not "
              "proof of independence.",
              "- Issue text is untrusted and was never executed; bodies and comments are not stored.", ""]
    return "\n".join(lines)


def load_candidates(path: Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    candidates, _ = read_json(path, "candidates")
    if (not isinstance(candidates, dict) or candidates.get("schema_version") != SCHEMA_VERSION
            or candidates.get("repository") != snapshot["repository"]
            or candidates.get("base_sha") != snapshot["base"]["sha"]
            or candidates.get("issue_numbers") != sorted(i["number"] for i in snapshot["issues"])):
        raise PlannerError("candidates.json does not belong to this snapshot (repository, base or Issues differ)")
    if not all(isinstance(candidates.get(k), list) for k in ("issue_statuses", "groups", "pairs")):
        raise PlannerError("candidates.json is malformed")
    expected = shortlist(snapshot)
    if candidates != expected:
        raise PlannerError("candidates.json differs from a fresh shortlist of this snapshot; re-run shortlist")
    return candidates


def cmd_render(args: argparse.Namespace) -> int:
    snapshot, digest = load_snapshot(args.snapshot)
    candidates = load_candidates(args.candidates, snapshot)
    out = prepare_out_dir(args.out_dir, refuse_existing=("report.json", "report.md", "render-diagnostics.json"))
    proposals = None
    if args.proposals is not None:
        if args.repo_dir is None:
            raise PlannerError("--proposals needs --repo-dir to check code evidence against the base tree")
        proposals, _ = read_json(args.proposals, "proposals")
        errors = proposals_problems(snapshot, digest, proposals, base_tree_paths(args.repo_dir, snapshot["base"]["sha"]))
        if errors:
            write_atomic(out / "render-diagnostics.json", dumps({"status": "BLOCKED", "errors": errors}))
            print(dumps({"status": "BLOCKED", "reason": "proposals failed validation", "errors": len(errors)}), end="")
            return EXIT_FAIL
    report = build_report(snapshot, candidates, proposals)
    findings = secret_findings(report)
    if findings:
        write_atomic(out / "render-diagnostics.json", dumps({"status": "BLOCKED", "secret_findings": findings}))
        print(dumps({"status": "BLOCKED", "reason": "secret-shaped text", "findings": len(findings)}), end="")
        return EXIT_FAIL
    write_atomic(out / "report.json", dumps(report))
    write_atomic(out / "report.md", render_markdown(report))
    print(dumps({"status": report["status"], "report": str(out / "report.md"), "counts": report["counts"]}), end="")
    return EXIT_OK if report["status"] in REPORTED else EXIT_FAIL


# --------------------------------------------------------------------------- diff

def _report_batches(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = report["batches"] if report["status"] == "REVIEWED" else report["heuristic_groups"]
    return {b["batch_id"]: b for b in items}


def _usable_report(report: Any) -> bool:
    return (isinstance(report, dict) and report.get("schema_version") == SCHEMA_VERSION
            and report.get("status") in REPORTED and report.get("snapshot_complete") is True
            and isinstance(report.get("issues"), list) and isinstance(report.get("batches"), list)
            and isinstance(report.get("heuristic_groups"), list)
            and report.get("content_sha256") == report_content_sha256(report))


def diff_reports(previous: Any, current: dict[str, Any]) -> dict[str, Any]:
    if not _usable_report(current):
        raise PlannerError("the current report is not a complete REVIEWED or HEURISTIC_ONLY report")
    if not _usable_report(previous):
        return {"status": "NO_BASELINE", "reason": "the previous report is missing, incomplete, blocked or altered"}
    old, new = _report_batches(previous), _report_batches(current)
    retired = sorted(set(old) - set(new))

    def jaccard(a: list[int], b: list[int]) -> float:
        return len(set(a) & set(b)) / len(set(a) | set(b))

    new_batches = []
    for bid in sorted(set(new) - set(old)):
        best_id, best = None, 0.0
        for r in retired:  # ascending, so a tie keeps the smaller batch_id
            score = jaccard(new[bid]["issue_numbers"], old[r]["issue_numbers"])
            if score > best:
                best_id, best = r, score
        new_batches.append({"batch_id": bid, "issue_numbers": new[bid]["issue_numbers"],
                            "supersedes": best_id if best >= 0.5 else None})
    old_status = {i["number"]: i["status"] for i in previous["issues"]}
    hard = ("EXISTING_PR", "BLOCKED_BY", "NEEDS_DECISION", "ALREADY_RESOLVED_REVIEW")
    return {
        "status": "COMPARED", "previous": previous["content_sha256"], "current": current["content_sha256"],
        "new_batches": new_batches,
        "retired_batches": [{"batch_id": r, "issue_numbers": old[r]["issue_numbers"]} for r in retired],
        "changed_classification": [{"batch_id": b, "from": old[b]["classification"], "to": new[b]["classification"]}
                                   for b in sorted(set(old) & set(new))
                                   if old[b]["classification"] != new[b]["classification"]],
        "newly_blocked": [i["number"] for i in current["issues"]
                          if i["status"] in hard and old_status.get(i["number"]) not in hard],
        "issues_closed": sorted(set(old_status) - {i["number"] for i in current["issues"]}),
    }


def cmd_diff(args: argparse.Namespace) -> int:
    current, _ = read_json(args.current, "current report")
    try:
        previous, _ = read_json(args.previous, "previous report")
    except PlannerError:
        previous = None
    out = Path(os.path.abspath(args.out))
    if out.exists():
        raise PlannerError(f"--out {out} already exists")
    result = diff_reports(previous, current)
    write_atomic(out, dumps(result))
    print(dumps({k: (len(v) if isinstance(v, list) else v) for k, v in result.items()}), end="")
    return EXIT_OK


# --------------------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="check agent-written proposals.json against snapshot.json")
    v.add_argument("--snapshot", required=True, type=Path)
    v.add_argument("--proposals", required=True, type=Path)
    v.add_argument("--repo-dir", required=True, type=Path)
    v.set_defaults(func=cmd_validate)
    c = sub.add_parser("collect", help="read open Issues and PRs into snapshot.json (read-only)")
    c.add_argument("--repo", required=True)
    c.add_argument("--repo-dir", required=True, type=Path)
    c.add_argument("--out-dir", required=True, type=Path)
    c.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    c.set_defaults(func=cmd_collect)
    s = sub.add_parser("shortlist", help="per-Issue status and heuristic groups from snapshot.json")
    s.add_argument("--snapshot", required=True, type=Path)
    s.add_argument("--out", required=True, type=Path)
    s.set_defaults(func=cmd_shortlist)
    r = sub.add_parser("render", help="report.json and report.md from snapshot, candidates and optional proposals")
    r.add_argument("--snapshot", required=True, type=Path)
    r.add_argument("--candidates", required=True, type=Path)
    r.add_argument("--proposals", type=Path)
    r.add_argument("--repo-dir", type=Path)
    r.add_argument("--out-dir", required=True, type=Path)
    r.set_defaults(func=cmd_render)
    d = sub.add_parser("diff", help="compare two report.json files")
    d.add_argument("--previous", required=True, type=Path)
    d.add_argument("--current", required=True, type=Path)
    d.add_argument("--out", required=True, type=Path)
    d.set_defaults(func=cmd_diff)
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
