#!/usr/bin/env python3
"""Fail-closed GitHub Draft PR Ready gate. Standard library + gh CLI only.

This script verifies GitHub facts and HEAD-bound, agent-supplied quality evidence.
It cannot prove the truth of a reviewer's semantic assessment; do not fabricate it.
"""
from __future__ import annotations

import argparse
import importlib.util
import hashlib
import math
import signal
import time
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

SHA = re.compile(r"^[0-9a-fA-F]{40}$")


class GateError(RuntimeError):
    pass


def cmd(argv: list[str], *, allow_nonzero_json: bool = False, empty_if: re.Pattern[str] | None = None) -> Any:
    """Run argv and parse its stdout as JSON. `empty_if` is the one tolerated failure: exit 1 with
    nothing on stdout and stderr that is exactly that message means "empty list". It is never matched
    against stdout, so a valid JSON answer is always parsed, and never as a substring of other output."""
    try:
        p = subprocess.run(argv, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise GateError(f"Cannot execute {argv[0]}: {exc}") from exc
    if empty_if is not None and p.returncode == 1 and not p.stdout.strip() and empty_if.fullmatch(p.stderr):
        return []
    if p.returncode and (not allow_nonzero_json or p.returncode not in (1, 8)):
        raise GateError(f"{' '.join(argv[:4])}: exit {p.returncode}: {(p.stderr or p.stdout).strip()[:700]}")
    try:
        val = json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(f"Invalid/missing JSON from {argv[0]} (exit {p.returncode}): {(p.stderr or p.stdout).strip()[:700]}") from exc
    return val


def gh_pr(repo: str, pr: int) -> dict[str, Any]:
    fields = "number,url,title,body,isDraft,state,headRefOid,headRefName,baseRefOid,baseRefName,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup"
    value = cmd(["gh", "pr", "view", str(pr), "-R", repo, "--json", fields])
    if not isinstance(value, dict):
        raise GateError("Expected a GitHub PR JSON object")
    return value


REPO_EVIDENCE_PATH = Path(__file__).resolve().parents[2] / "issue-to-pr" / "scripts" / "repo_evidence.py"


def load_repo_evidence() -> Any:
    """issue-to-pr's repo_evidence.py, loaded by path from the sibling skill.

    Both gates read the base branch's `.github/pr-evidence.json` the same way, so a receipt or
    review taken at an ancestor of HEAD is accepted here exactly when issue_gate.py would
    accept it: every file changed since matches `evidence_only_paths`. Missing module means
    no reuse (strict SHA binding), never a crash.
    """
    name = "pr_ready_repo_evidence"
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(name, REPO_EVIDENCE_PATH)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def evidence_context(worktree: Path | None, head: Any, base_name: Any, remote: str) -> Any:
    """repo_evidence.Context for this gate run, or None when reuse cannot be checked.

    None keeps the strict rule (every receipt and the review must name HEAD). The context is
    only ever built from the verified checkout and the PR's base branch as fetched from
    `remote`; a base ref missing locally yields a context with no patterns, which accepts
    nothing but HEAD.
    """
    if worktree is None or not isinstance(head, str) or not SHA.fullmatch(head):
        return None
    if not isinstance(base_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]*", base_name) or ".." in base_name:
        return None
    module = load_repo_evidence()
    if module is None:
        return None
    try:
        return module.Context.load(worktree, head, f"refs/remotes/{remote}/{base_name}")
    except (OSError, RuntimeError, ValueError):
        return None


def covers_head(ctx: Any, value: Any, sha: Any, label: str) -> bool:
    """Evidence taken at `value` covers HEAD: same SHA, or only evidence-only files changed since."""
    return value == sha or (ctx is not None and ctx.accepts(value, label))


def stale_detail(ctx: Any, value: Any) -> str:
    if ctx is None or not isinstance(value, str):
        return ""
    try:
        return " (" + ctx.stale_reason(value) + ")"
    except (OSError, RuntimeError, ValueError):
        return ""


def target_evidence_errors(pr: dict[str, Any], evidence: dict[str, Any], repo: str) -> list[str]:
    """Use the same base-manifest/target-run verifier as the final merge gate.

    This does not relax this workflow's HEAD-bound local receipts or independent
    review. All three workflows ship together in this repository.
    """
    scripts = Path(__file__).resolve().parents[2] / "pr-review-merge" / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        name = "pr_ready_target_gate"
        module = sys.modules.get(name)
        if module is None:
            spec = importlib.util.spec_from_file_location(name, scripts / "review_gate.py")
            if spec is None or spec.loader is None:
                raise ImportError("target evidence verifier unavailable")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
        head, base = pr.get("headRefOid"), pr.get("baseRefOid")
        if not isinstance(head, str) or not SHA.fullmatch(head) or not isinstance(base, str) or not SHA.fullmatch(base):
            return ["Current HEAD/base SHA unavailable for target evidence validation"]
        import gh_runtime
        gaps, _ = module.check_target_validation(gh_runtime, gh_runtime.Repo.parse(repo), head, base, evidence,
                                                base_name=pr.get("baseRefName"))
        return gaps
    except (ImportError, OSError, ValueError, KeyError, RuntimeError) as exc:
        return [f"Target evidence validation unavailable: {exc}"]
    finally:
        sys.path.pop(0)


# `gh pr checks --required` on a branch without required checks (no branch protection or ruleset
# requiring any) exits 1 with nothing on stdout and, on stderr, exactly this line (gh 2.103.3):
#   no required checks reported on the 'chore/pr-ready-dispute-review-comments' branch\n
# Case-sensitive and anchored: a failing required check named "no required checks reported" arrives
# as JSON on stdout and must stay a failure.
NO_REQUIRED_CHECKS = re.compile(r"no required checks reported on the '[^\n]+' branch\n?")


def gh_checks(repo: str, pr: int, *, required: bool) -> list[dict[str, Any]]:
    args = ["gh", "pr", "checks", str(pr), "-R", repo, "--json", "name,state,bucket,link"]
    if required:
        args.append("--required")
    # gh pr checks may exit 1 for failures or 8 for pending checks while still
    # producing valid JSON. We must evaluate individual check buckets.
    checks = cmd(args, allow_nonzero_json=True, empty_if=NO_REQUIRED_CHECKS if required else None)
    if not isinstance(checks, list):
        raise GateError("Expected a GitHub check list")
    if not all(isinstance(x, dict) for x in checks):
        raise GateError("Malformed check list")
    return checks


def gh_workflow_runs(repo: str, head: Any) -> list[dict[str, Any]]:
    """Read every Actions run for this exact head, including delayed/dependent jobs.

    An empty, complete response is valid for repositories using external checks. gh follows
    Link pagination; total_count prevents an incomplete/truncated result becoming green.
    """
    if not isinstance(head, str) or not SHA.fullmatch(head):
        raise GateError("Cannot query workflow runs without a valid current HEAD")
    pages = cmd(["gh", "api", f"repos/{repo}/actions/runs?head_sha={head}&per_page=100",
                 "--paginate", "--slurp"])
    if not isinstance(pages, list) or not pages:
        raise GateError("Missing/malformed workflow run pages")
    runs = []
    total = None
    for page in pages:
        if not isinstance(page, dict) or type(page.get("total_count")) is not int \
                or page["total_count"] < 0 or not isinstance(page.get("workflow_runs"), list):
            raise GateError("Missing/malformed workflow run metadata")
        if total is not None and page["total_count"] != total:
            raise GateError("Workflow run pagination changed; requery before resuming")
        total = page["total_count"]
        runs.extend(page["workflow_runs"])
    if len(runs) != total:
        raise GateError("Incomplete workflow run pagination (total_count mismatch)")
    return runs


CONNECTION_QUERY = """
query($owner:String!,$repo:String!,$number:Int!,$cursor:String) {
  repository(owner:$owner,name:$repo) {
    pullRequest(number:$number) {
      %s(first:100,after:$cursor) {
        nodes { %s }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

# PR connections the gate reads: field -> (node fields, label for errors).
# Thread comments let the gate check that a disputed thread's reply is still
# its newest comment; conversation comments and reviews are only fetched when
# the evidence disputes a review comment.
CONNECTIONS = {
    "reviewThreads": ("id isResolved isOutdated "
                      "comments(first:100) { nodes { url createdAt updatedAt body } pageInfo { hasNextPage } }",
                      "review threads"),
    "comments": ("url createdAt updatedAt body", "conversation comments"),
    "reviews": ("url createdAt updatedAt body state", "reviews"),
}


def gh_connection(repo: str, pr: int, field: str) -> list[dict[str, Any]]:
    if len(repo.split("/")) != 2:
        raise GateError("--repo must be OWNER/REPO")
    owner, name = repo.split("/", 1)
    node_fields, label = CONNECTIONS[field]
    query = CONNECTION_QUERY % (field, node_fields)
    cursor: str | None = None
    pages = 0
    items: list[dict[str, Any]] = []
    while True:
        argv = ["gh", "api", "graphql", "-f", f"query={query}", "-f", f"owner={owner}",
                "-f", f"repo={name}", "-F", f"number={pr}"]
        if cursor:
            argv.extend(["-f", f"cursor={cursor}"])
        payload = cmd(argv)
        if not isinstance(payload, dict) or payload.get("errors"):
            raise GateError(f"GraphQL {label} query failed: {str(payload)[:300]}")
        try:
            connection = payload["data"]["repository"]["pullRequest"][field]
            nodes, page = connection["nodes"], connection["pageInfo"]
            if not isinstance(nodes, list) or not isinstance(page["hasNextPage"], bool):
                raise ValueError(f"invalid {label} page")
            items.extend(nodes)
        except (KeyError, TypeError, ValueError) as exc:
            raise GateError(f"Cannot retrieve complete PR {label}: {exc}") from exc
        pages += 1
        if not page["hasNextPage"]:
            break
        new_cursor = page.get("endCursor")
        if not new_cursor or new_cursor == cursor or pages >= 100:
            raise GateError(f"PR {label} pagination incomplete")
        cursor = new_cursor
    return items


def gh_threads(repo: str, pr: int) -> list[dict[str, Any]]:
    return gh_connection(repo, pr, "reviewThreads")


@dataclass
class Snapshot:
    pr: dict[str, Any]
    checks: list[dict[str, Any]]
    required_checks: list[dict[str, Any]]
    threads: list[dict[str, Any]]
    # None means "not fetched": only needed to verify disputed review comments.
    comments: list[dict[str, Any]] | None = None
    reviews: list[dict[str, Any]] | None = None
    workflow_runs: list[dict[str, Any]] | None = None


def fetch_snapshot(repo: str, pr: int, *, conversation: bool = False, workflows: bool = False) -> Snapshot:
    view = gh_pr(repo, pr)
    return Snapshot(
        pr=view,
        checks=gh_checks(repo, pr, required=False),
        required_checks=gh_checks(repo, pr, required=True),
        threads=gh_threads(repo, pr),
        comments=gh_connection(repo, pr, "comments") if conversation else None,
        reviews=gh_connection(repo, pr, "reviews") if conversation else None,
        workflow_runs=gh_workflow_runs(repo, view.get("headRefOid")) if workflows else None,
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


def validate_validation(value: Any, sha: str, errors: list[str], log_base: Path | None = None,
                        ctx: Any = None) -> None:
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
            if not covers_head(ctx, item.get("head_sha"), sha, loc):
                errors.append(f"{loc} stale/missing SHA{stale_detail(ctx, item.get('head_sha'))}")
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


DISPUTE_DISPOSITIONS = ("invalid", "needs_evidence", "nonblocking")


def check_disputes(s: Snapshot, evidence: dict[str, Any], sha: Any, errors: list[str]) -> None:
    """Verify each review comment the PR does not act on was answered on GitHub.

    The gate cannot judge whether the dispute is right; it checks that the
    disputed comment is on this PR, that a later reply exists where the
    commenter will see it (same thread, or a conversation comment linking the
    disputed URL), that nobody has written in the thread since, and that the
    independent reviewer confirmed the dispute on the current HEAD.
    """
    items = evidence.get("disputed_review_comments", [])
    if not isinstance(items, list):
        errors.append("disputed_review_comments malformed")
        return
    if not items:
        return
    if s.comments is None or s.reviews is None:
        errors.append("PR conversation comments/reviews not fetched; cannot verify disputed review comments")
        return

    # url -> (where, createdAt, body); where is "thread:<id>", "conversation" or "review".
    index: dict[str, tuple[str, str, str | None]] = {}
    newest: dict[str, str] = {}
    incomplete: set[str] = set()
    for t in s.threads:
        conn = t.get("comments") if isinstance(t, dict) else None
        if not isinstance(conn, dict) or not isinstance(conn.get("nodes"), list) \
                or not isinstance(t.get("id"), str):
            continue
        where = "thread:" + t["id"]
        page = conn.get("pageInfo")
        if not isinstance(page, dict) or page.get("hasNextPage") is not False:
            incomplete.add(where)
        latest: tuple[str, str] | None = None
        for c in conn["nodes"]:
            if isinstance(c, dict) and isinstance(c.get("url"), str) and isinstance(c.get("createdAt"), str):
                index[c["url"]] = (where, c["createdAt"], None)
                if latest is None or c["createdAt"] >= latest[0]:
                    latest = (c["createdAt"], c["url"])
        if latest:
            newest[where] = latest[1]
    for where, nodes in (("conversation", s.comments), ("review", s.reviews)):
        for c in nodes:
            if isinstance(c, dict) and isinstance(c.get("url"), str) and isinstance(c.get("createdAt"), str):
                body = c.get("body") if isinstance(c.get("body"), str) else None
                index[c["url"]] = (where, c["createdAt"], body)

    for i, item in enumerate(items):
        loc = f"disputed_review_comments[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{loc} malformed")
            continue
        disposition = item.get("disposition")
        if disposition not in DISPUTE_DISPOSITIONS:
            errors.append(f"{loc}.disposition must be one of {', '.join(DISPUTE_DISPOSITIONS)}")
        elif disposition == "nonblocking" and item.get("severity") not in ("P3", "P4"):
            errors.append(f"{loc} nonblocking dispute needs severity P3 or P4")
        for key, minimum in (("claim", 20), ("counter_evidence", 30)):
            if not isinstance(item.get(key), str) or len(item[key].strip()) < minimum:
                errors.append(f"{loc}.{key} missing or lacks specific detail")
        if item.get("head_sha") != sha:
            errors.append(f"{loc} stale/missing SHA")
        if item.get("reviewer_confirmed") is not True:
            errors.append(f"{loc} not confirmed by the independent reviewer")
        source, reply = item.get("source_url"), item.get("reply_url")
        if not isinstance(source, str) or not isinstance(reply, str):
            errors.append(f"{loc} needs source_url and reply_url")
            continue
        src, rep = index.get(source), index.get(reply)
        if src is None:
            errors.append(f"{loc}.source_url is not a review comment on this PR: {source}")
        if rep is None:
            errors.append(f"{loc}.reply_url is not a comment on this PR: {reply}")
        if src is None or rep is None:
            continue
        if rep[1] <= src[1]:
            errors.append(f"{loc} reply was not posted after the disputed comment")
        if src[0].startswith("thread:"):
            if rep[0] != src[0]:
                errors.append(f"{loc} reply must be in the disputed comment's review thread")
            elif src[0] in incomplete:
                errors.append(f"{loc} review thread comments incomplete; cannot verify the reply is the newest")
            elif newest.get(src[0]) != reply:
                errors.append(f"{loc} review thread has comments after the reply; triage them again")
        elif rep[0] != "conversation":
            errors.append(f"{loc} reply to a conversation comment or review must be a PR conversation comment")
        elif source not in (rep[2] or ""):
            errors.append(f"{loc} reply does not link the disputed comment ({source})")


@dataclass
class CIResult:
    errors: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)


def valid_check(value: Any) -> bool:
    # gh exposes CheckRunState and StatusState through one state field.
    states = {"ACTION_REQUIRED", "CANCELLED", "COMPLETED", "ERROR", "EXPECTED", "FAILURE",
              "IN_PROGRESS", "NEUTRAL", "PENDING", "QUEUED", "REQUESTED", "SKIPPED",
              "STALE", "STARTUP_FAILURE", "SUCCESS", "TIMED_OUT", "WAITING"}
    return (isinstance(value, dict) and isinstance(value.get("name"), str)
            and bool(value["name"].strip()) and isinstance(value.get("state"), str)
            and isinstance(value.get("bucket"), str) and value["state"] in states
            and value.get("bucket") in {"pass", "fail", "pending", "cancel", "skipping"})


def classify_ci(s: Snapshot, evidence: dict[str, Any]) -> CIResult:
    """Separate actual pending checks from blockers; exemptions never hide pending."""
    result = CIResult()
    if not s.checks:
        result.errors.append("No CI checks visible; cannot verify required/related checks (fail closed)")
    required_names: set[str] = set()
    for c in s.required_checks:
        if not valid_check(c):
            result.errors.append("Malformed/unknown required GitHub check metadata")
            continue
        name = c.get("name")
        if not isinstance(name, str) or not name:
            result.errors.append("Required check missing name")
            continue
        required_names.add(name)
        if c.get("bucket") == "pending":
            result.pending.append(f"Required GitHub check not passing: {name} ({c.get('state')}, pending)")
        elif c.get("bucket") != "pass":
            result.errors.append(f"Required GitHub check not passing: {name} ({c.get('state')}, {c.get('bucket')})")

    observed_names: set[str] = set()
    unrelated = evidence.get("unrelated_failing_checks", [])
    if not isinstance(unrelated, list):
        result.errors.append("unrelated_failing_checks malformed")
        unrelated = []
    exemptions = {}
    for item in unrelated:
        if isinstance(item, dict) and isinstance(item.get("name"), str) \
                and isinstance(item.get("reason"), str) and len(item["reason"].strip()) >= 30 \
                and item.get("reviewer_confirmed") is True:
            exemptions[item["name"]] = item
        else:
            result.errors.append("Invalid unrelated GitHub check exemption (needs exact name, reason, reviewer_confirmed)")

    for c in s.checks:
        if not valid_check(c):
            result.errors.append("Malformed/unknown GitHub check metadata")
            continue
        name, bucket = c.get("name"), c.get("bucket")
        if not isinstance(name, str) or not name:
            result.errors.append("Unnamed GitHub CI check")
            continue
        observed_names.add(name)
        if bucket == "pending":
            result.pending.append(f"Nonpassing GitHub check: {name} ({c.get('state')}, {bucket})")
        elif name in required_names and bucket != "pass":
            result.errors.append(f"Required GitHub check not successful: {name}")
        elif bucket == "pass":
            continue
        elif name not in required_names and bucket == "skipping":
            # GitHub regards a *non-required* neutral/skip as nonblocking.
            continue
        elif bucket in ("fail", "cancel", "skipping") and name in exemptions and name not in required_names:
            continue
        else:
            result.errors.append(f"Nonpassing GitHub check: {name} ({c.get('state')}, {bucket})")

    for name in required_names - observed_names:
        result.errors.append(f"Required GitHub check missing from full check rollup: {name}")
    for name in exemptions.keys() - observed_names:
        result.errors.append(f"Claimed unrelated check does not exist on HEAD: {name}")

    return result


WORKFLOW_ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}
WORKFLOW_CONCLUSIONS = {"success", "failure", "neutral", "cancelled", "skipped", "timed_out",
                        "action_required", "stale", "startup_failure"}
WORKFLOW_IDENTITY = ("id", "workflow_id", "head_sha", "head_branch", "event", "path",
                     "run_number", "created_at", "check_suite_id")


def workflow_identity(run: Any, head: str) -> dict[str, Any]:
    if not isinstance(run, dict):
        raise GateError("Malformed workflow run")
    for key in ("id", "workflow_id", "run_attempt", "run_number", "check_suite_id"):
        if type(run.get(key)) is not int or run[key] <= 0:
            raise GateError(f"Missing/malformed workflow run {key}")
    for key in ("head_branch", "event", "path", "created_at", "updated_at"):
        if not isinstance(run.get(key), str) or not run[key].strip():
            raise GateError(f"Missing/malformed workflow run {key}")
    if run.get("head_sha") != head:
        raise GateError("Workflow run is not bound to current HEAD")
    if "conclusion" not in run:
        raise GateError("Missing workflow run conclusion metadata")
    for key in ("created_at", "updated_at"):
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", run[key]):
            raise GateError(f"Malformed workflow run {key}")
    status, conclusion = run.get("status"), run.get("conclusion")
    if not isinstance(status, str) or status not in WORKFLOW_ACTIVE | {"completed"}:
        raise GateError("Unknown/missing workflow run status")
    if status == "completed":
        if not isinstance(conclusion, str) or conclusion not in WORKFLOW_CONCLUSIONS:
            raise GateError("Unknown/missing completed workflow conclusion")
    elif conclusion is not None:
        raise GateError("Active workflow run has unexpected conclusion")
    return {key: run[key] for key in WORKFLOW_IDENTITY}


@dataclass
class WorkflowHistory:
    identities: dict[int, dict[str, Any]] = field(default_factory=dict)
    attempts: dict[int, int] = field(default_factory=dict)
    active: set[tuple[int, int]] = field(default_factory=set)
    states: list[dict[str, Any]] = field(default_factory=list)

    def inspect(self, snapshot: Snapshot, repo: str) -> CIResult:
        """Settlement is independent of check quality/exemptions. Never lose an active run.

        Run identities stay pinned. A new run or higher attempt is observed conservatively;
        if a rerun supersedes a previously active attempt, query that exact old attempt until
        it is verifiably completed. Historical failed conclusions are not new quality gates:
        current visible/required checks retain their existing terminal exemption policy.
        """
        if snapshot.workflow_runs is None:
            raise GateError("Workflow lifecycle metadata not fetched")
        head = snapshot.pr.get("headRefOid")
        latest = {}
        for run in snapshot.workflow_runs:
            identity = workflow_identity(run, head)
            run_id = run["id"]
            if run_id in latest:
                raise GateError("Duplicate workflow run in paginated response")
            if run_id in self.identities and identity != self.identities[run_id]:
                raise GateError("Workflow run identity/metadata changed during wait")
            if run["run_attempt"] < self.attempts.get(run_id, 0):
                raise GateError("Workflow run attempt regressed during wait")
            latest[run_id] = run
        if self.identities.keys() - latest.keys():
            raise GateError("Previously observed workflow run disappeared; cannot prove settlement")
        observed = list(latest.values())
        for run_id, attempt in sorted(self.active):
            if latest[run_id]["run_attempt"] == attempt:
                continue
            previous = cmd(["gh", "api", f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}"])
            if workflow_identity(previous, head) != self.identities[run_id] \
                    or previous["run_attempt"] != attempt:
                raise GateError("Historical active workflow attempt identity changed")
            observed.append(previous)
        result = CIResult()
        self.states = []
        for run in observed:
            run_id, attempt = run["id"], run["run_attempt"]
            key = run_id, attempt
            self.states.append({k: run[k] for k in ("id", "workflow_id", "run_attempt", "status", "conclusion", "path")})
            if run["status"] in WORKFLOW_ACTIVE:
                self.active.add(key)
                result.pending.append(f"Active GitHub workflow run: {run_id} attempt {attempt} ({run['status']})")
            else:
                self.active.discard(key)
        for run_id, run in latest.items():
            self.identities[run_id] = workflow_identity(run, head)
            self.attempts[run_id] = run["run_attempt"]
        return result


def evaluate(s: Snapshot, evidence: dict[str, Any], *, repo: str, number: int,
             local: tuple[str, str, list[str]] | None = None,
             log_base: Path | None = None, ctx: Any = None, allow_pending: bool = False) -> list[str]:
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
        if not covers_head(ctx, r.get("head_sha"), sha, "independent_review"):
            errs.append("Independent reviewer result stale for current HEAD" + stale_detail(ctx, r.get("head_sha")))
        if r.get("status") != "PASS" or r.get("blocking_findings") != []:
            errs.append("Independent review has not passed / still has blocking findings")
        if not isinstance(r.get("report"), str) or len(r["report"].strip()) < 12:
            errs.append("Independent review needs a report reference/summary")

    validate_validation(evidence.get("local_validation"), sha, errs, log_base=log_base, ctx=ctx)
    if ctx is not None:
        errs.extend(ctx.errors)

    if local:
        local_sha, local_branch, dirty = local
        if local_sha != sha:
            errs.append("Local worktree HEAD differs from remote PR HEAD")
        if local_branch != pr.get("headRefName"):
            errs.append("Local worktree is not on the original PR branch")
        if dirty:
            errs.append(f"Local worktree has uncommitted/untracked edits: {dirty[:4]}")

    ci = classify_ci(s, evidence)
    errs.extend(ci.errors)
    if not allow_pending:
        errs.extend(ci.pending)

    # Every thread must be resolved: pr-review-merge returns a PR with any unresolved
    # thread to Draft, so a Ready PR with one would only bounce back. A P3/P4 thread
    # is answered and resolved like any disputed comment (disposition nonblocking).
    if evidence.get("unresolved_nonblocking_threads"):
        errs.append("unresolved_nonblocking_threads is no longer accepted: reply to the thread, resolve it "
                    "and record it in disputed_review_comments (disposition nonblocking)")
    for t in s.threads:
        if not isinstance(t, dict) or not isinstance(t.get("isResolved"), bool):
            errs.append("Unknown review thread state")
            continue
        if not t["isResolved"]:
            thread_id = t.get("id")
            if not isinstance(thread_id, str):
                errs.append("Review thread missing ID")
            else:
                errs.append(f"Unresolved GitHub review thread: {thread_id} (fix or dispute it, then resolve it)")
    check_disputes(s, evidence, sha, errs)
    return errs


class WaitStopped(GateError):
    pass


def file_pin(path: Path) -> tuple[str, str]:
    target = path.resolve(strict=True)
    if not target.is_file():
        raise GateError(f"Wait artifact is not a file: {path}")
    return str(target), hashlib.sha256(target.read_bytes()).hexdigest()


def artifact_pins(evidence_path: Path, evidence: dict[str, Any], root: Path) -> dict[str, tuple[str, str]]:
    """Pin evidence bytes and local files it references, including excluded .pr-ready logs.

    A report may remain a legacy inline summary. Path-shaped report references must exist;
    a report that existed when waiting began cannot disappear or change into a summary.
    """
    paths = {str(evidence_path.absolute())}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"log", "report", "artifact", "receipt"} and isinstance(item, str) and item:
                    path = Path(item)
                    path = path if path.is_absolute() else root / path
                    if path.is_file() or key == "log" or item.startswith((".", "/")) \
                            or (" " not in item and "://" not in item
                                and ("/" in item or Path(item).suffix in {".md", ".json", ".log", ".txt"})):
                        paths.add(str(path.absolute()))
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(evidence)
    return {path: file_pin(Path(path)) for path in sorted(paths)}


def fetched_base(worktree: Path, remote: str, base: str) -> str | None:
    p = subprocess.run(["git", "-C", str(worktree), "rev-parse", "--verify",
                        f"refs/remotes/{remote}/{base}"], capture_output=True, text=True)
    if p.returncode:
        # A missing fetched base keeps the existing strict HEAD-only policy.
        return None
    return p.stdout.strip()


def review_pin(s: Snapshot) -> str:
    """Fail closed on incomplete review content, even when no dispute was recorded."""
    for label, nodes in (("comments", s.comments), ("reviews", s.reviews)):
        if not isinstance(nodes, list):
            raise GateError(f"Wait requires complete PR {label}")
        for node in nodes:
            if not isinstance(node, dict) or any(not isinstance(node.get(key), str)
                                               for key in ("url", "createdAt", "updatedAt", "body")):
                raise GateError(f"Wait requires complete PR {label} content")
    for thread in s.threads:
        conn = thread.get("comments") if isinstance(thread, dict) else None
        if not isinstance(conn, dict) or not isinstance(conn.get("pageInfo"), dict) \
                or conn["pageInfo"].get("hasNextPage") is not False \
                or not isinstance(conn.get("nodes"), list):
            raise GateError("Wait requires complete review thread comments")
        for node in conn["nodes"]:
            if not isinstance(node, dict) or any(not isinstance(node.get(key), str)
                                               for key in ("url", "createdAt", "updatedAt", "body")):
                raise GateError("Wait requires complete review thread content")
    return json.dumps([s.threads, s.comments, s.reviews], sort_keys=True)


@dataclass
class WaitPins:
    identity: dict[str, Any]
    reviews: str
    artifacts: dict[str, tuple[str, str]]
    base: str | None

    @classmethod
    def capture(cls, s: Snapshot, evidence_path: Path, evidence: dict[str, Any],
                root: Path, remote: str) -> WaitPins:
        keys = ("number", "url", "headRefOid", "headRefName", "baseRefOid", "baseRefName", "title", "body")
        if any(not isinstance(s.pr.get(key), str) for key in keys if key != "number"):
            raise GateError("Wait requires complete PR identity/title/body")
        if not SHA.fullmatch(s.pr["baseRefOid"]):
            raise GateError("Wait requires a valid base SHA")
        return cls({key: s.pr[key] for key in keys}, review_pin(s),
                   artifact_pins(evidence_path, evidence, root),
                   fetched_base(root, remote, s.pr["baseRefName"]))

    def verify(self, s: Snapshot, evidence_path: Path, evidence: dict[str, Any],
               root: Path, remote: str) -> list[str]:
        errors = []
        for key, value in self.identity.items():
            if s.pr.get(key) != value:
                errors.append(f"Wait pin changed: PR {key}; revalidate evidence/review")
        if review_pin(s) != self.reviews:
            errors.append("Wait pin changed: PR review/comment content; triage again")
        if artifact_pins(evidence_path, evidence, root) != self.artifacts:
            errors.append("Wait pin changed: evidence/report/log artifact bytes or paths")
        if fetched_base(root, remote, self.identity["baseRefName"]) != self.base:
            errors.append("Wait pin changed: fetched base policy ref")
        return errors


def json_line(result: dict[str, Any], *, compact: bool) -> None:
    print(json.dumps(result, ensure_ascii=False, indent=None if compact else 2), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="OWNER/REPO")
    parser.add_argument("--pr", type=int, required=True, help="Existing PR number")
    parser.add_argument("--evidence", type=Path, required=True, help="HEAD-specific evidence JSON")
    parser.add_argument("--worktree", type=Path, help="Original PR-branch worktree; verify clean and HEAD")
    parser.add_argument("--ready", action="store_true", help="Execute 'gh pr ready' only after all gates pass")
    parser.add_argument("--wait", action="store_true", help="Keep polling actual pending CI; with --ready transition automatically")
    parser.add_argument("--poll-interval", type=float, default=30, help="Wait poll interval in seconds, >0 and <=60 (default 30)")
    parser.add_argument("--wait-timeout", type=float, help="Explicit optional wait limit in seconds; default waits until settled or cancelled")
    parser.add_argument("--compact", action="store_true", help="One-line JSON output")
    parser.add_argument("--base-remote", default="origin",
                        help="Remote whose fetched base branch carries .github/pr-evidence.json (default origin)")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo) or args.pr <= 0:
        parser.error("--repo must be OWNER/REPO and --pr must be positive")
    if (args.ready or args.wait) and not args.worktree:
        parser.error("--ready/--wait requires --worktree to verify branch/clean tree")
    if not math.isfinite(args.poll_interval) or not 0 < args.poll_interval <= 60:
        parser.error("--poll-interval must be >0 and <=60 seconds")
    if args.wait_timeout is not None and (not args.wait or not math.isfinite(args.wait_timeout) or args.wait_timeout <= 0):
        parser.error("--wait-timeout requires --wait and a positive finite duration")

    status_path = args.worktree.resolve() / ".pr-ready" / str(args.pr) / "wait-status.json" if args.wait else None
    started = time.monotonic()
    polls = 0
    pins = None
    ready_invoked = False
    handlers = {}
    workflows = WorkflowHistory() if args.wait else None

    def emit(result: dict[str, Any]) -> None:
        if status_path is not None:
            result.update(pr_number=args.pr, elapsed_seconds=round(time.monotonic() - started, 3),
                          polls=polls, ready_invoked=ready_invoked)
            if workflows is not None:
                result["workflow_runs"] = workflows.states
            if pins is not None:
                result["head_sha"] = pins.identity["headRefOid"]
                result["pinned_artifacts"] = pins.artifacts
                result["pinned_branch"] = pins.identity["headRefName"]
                result["pinned_base_sha"] = pins.identity["baseRefOid"]
                result["pinned_fetched_base"] = pins.base
                result["pinned_review_sha256"] = hashlib.sha256(pins.reviews.encode()).hexdigest()
                result["pinned_pr_sha256"] = hashlib.sha256(json.dumps(pins.identity, sort_keys=True).encode()).hexdigest()
            status_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = status_path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            temporary.replace(status_path)
        json_line(result, compact=args.compact)

    def deadline() -> None:
        if args.wait_timeout is not None and time.monotonic() - started >= args.wait_timeout:
            raise WaitStopped("Explicit wait timeout reached; Draft retained unless ready_invoked is true")

    def interrupted(signum: int, _frame: Any) -> None:
        raise WaitStopped(f"Wait interrupted by {signal.Signals(signum).name}; requery before resuming")

    try:
        if args.wait:
            for sig in (signal.SIGINT, signal.SIGTERM):
                handlers[sig] = signal.signal(sig, interrupted)
        evidence_bytes = args.evidence.read_bytes()
        evidence = json.loads(evidence_bytes)
        if not isinstance(evidence, dict):
            raise GateError("Evidence JSON must be an object")
        conversation = args.wait or bool(evidence.get("disputed_review_comments"))

        def inspect(snapshot: Snapshot) -> tuple[list[str], list[str], list[Any]]:
            local = check_local(args.worktree) if args.worktree else None
            ctx = evidence_context(args.worktree, snapshot.pr.get("headRefOid"), snapshot.pr.get("baseRefName"),
                                   args.base_remote)
            errors = evaluate(snapshot, evidence, repo=args.repo, number=args.pr, local=local,
                              log_base=args.worktree, ctx=ctx, allow_pending=args.wait)
            errors.extend(target_evidence_errors(snapshot.pr, evidence, args.repo))
            pending = classify_ci(snapshot, evidence).pending
            if workflows is not None:
                lifecycle = workflows.inspect(snapshot, args.repo)
                errors.extend(lifecycle.errors)
                pending.extend(lifecycle.pending)
            if pins is not None:
                errors.extend(pins.verify(snapshot, args.evidence, evidence, args.worktree, args.base_remote))
            return errors, pending, list(ctx.accepted) if ctx is not None else []

        while True:
            deadline()
            before = fetch_snapshot(args.repo, args.pr, conversation=conversation, workflows=args.wait)
            polls += 1
            if args.wait and pins is None:
                pins = WaitPins.capture(before, args.evidence, evidence, args.worktree, args.base_remote)
                if pins.artifacts[str(args.evidence.absolute())][1] != hashlib.sha256(evidence_bytes).hexdigest():
                    raise GateError("Evidence bytes changed during initial wait preflight")
            errors, pending, reuse = inspect(before)
            if errors:
                emit({"status": "DRAFT-BLOCKED", "pr": before.pr.get("url"),
                      "head_sha": before.pr.get("headRefOid"), "errors": errors})
                return 2
            deadline()
            if not pending and not args.ready:
                emit({"status": "GATE-PASS", "pr": before.pr.get("url"),
                      "head_sha": before.pr.get("headRefOid"), "receipt_reuse": reuse,
                      "message": "Use --ready after final review to transition Draft -> Ready for Review"})
                return 0
            if not pending:
                # Fresh final preflight, including all wait pins. CI may become pending again.
                latest = fetch_snapshot(args.repo, args.pr, conversation=conversation, workflows=args.wait)
                errors, pending, reuse = inspect(latest)
                if errors:
                    emit({"status": "DRAFT-BLOCKED", "errors": errors})
                    return 2
                deadline()
                if not pending:
                    ready_invoked = True
                    action = subprocess.run(["gh", "pr", "ready", str(args.pr), "-R", args.repo],
                                            capture_output=True, text=True, check=False)
                    if action.returncode:
                        raise GateError(f"gh pr ready failed: {(action.stderr or action.stdout).strip()[:700]}")
                    after = fetch_snapshot(args.repo, args.pr, conversation=True, workflows=True) if args.wait else None
                    after_pr = after.pr if after is not None else gh_pr(args.repo, args.pr)
                    if after_pr.get("isDraft") is not False or after_pr.get("headRefOid") != evidence["head_sha"]:
                        raise GateError("PR state/HEAD changed during Ready transition; status requires reevaluation")
                    if pins is not None:
                        errors = pins.verify(after, args.evidence, evidence, args.worktree, args.base_remote)
                        sha, branch, dirty = check_local(args.worktree)
                        if sha != pins.identity["headRefOid"] or branch != pins.identity["headRefName"] or dirty:
                            errors.append("Local worktree changed during Ready transition")
                        ci = classify_ci(after, evidence)
                        errors.extend(ci.errors + ci.pending)
                        lifecycle = workflows.inspect(after, args.repo)
                        errors.extend(lifecycle.errors + lifecycle.pending)
                        if errors:
                            raise GateError("Ready invoked but post-action verification failed: " + "; ".join(errors))
                    emit({"status": "READY", "pr": after_pr.get("url"), "head_sha": after_pr["headRefOid"],
                          "receipt_reuse": reuse, "message": "Ready for Review; no merge performed"})
                    return 0
            if not args.wait:
                # inspect() normally rejects pending outside wait mode.
                raise GateError("Pending CI prevents Ready")
            emit({"status": "WAITING-CI", "pr": before.pr.get("url"), "pending_checks": pending,
                  "message": "HEAD/review/evidence pins valid; waiting for CI before final gate"})
            delay = args.poll_interval
            if args.wait_timeout is not None:
                delay = min(delay, max(0, args.wait_timeout - (time.monotonic() - started)))
            time.sleep(delay)
    except WaitStopped as exc:
        emit({"status": "WAIT-INTERRUPTED", "errors": [str(exc)]})
        return 2
    except (GateError, OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
        emit({"status": "DRAFT-BLOCKED", "errors": [str(exc)]})
        return 2
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
