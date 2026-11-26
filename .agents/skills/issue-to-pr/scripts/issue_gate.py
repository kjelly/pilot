#!/usr/bin/env python3
"""Fail-closed Issue→PR quality gate: SHA-bound local checks + GitHub duplicate screening.

Stage 'local' checks pre-push readiness. Stage 'pushed' additionally checks that
remote head exists and is identical. The gate cannot prove semantic correctness.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Running from the skill snapshot must not add __pycache__ there: `skill_snapshot.py verify`
# counts any added file and would STOP every later step. Set before the first sibling import.
sys.dont_write_bytecode = True
import repo_evidence  # noqa: E402
import umbrella as umbrella_mode  # noqa: E402

# `bounded_run` lives in the `_shared` bundle directory: it goes on the import path LAST and only when absent (a caller
# may have put its own directories first and pop index 0 afterwards, as pr_gate.merge_gate_modules does).
_SHARED_SCRIPTS = str(Path(__file__).resolve().parents[2] / "_shared" / "scripts")
if _SHARED_SCRIPTS not in sys.path:
    sys.path.append(_SHARED_SCRIPTS)
import bounded_run  # noqa: E402  (every command below goes through it: tests/test_bounded_run_lint.py)

# Seconds one command may run, read when the command starts (the tests patch them); SIGKILL for a group that ignores
# SIGTERM follows up to bounded_run.KILL_AFTER + DRAIN later. A command that outlives its limit is a GateError that names
# it: nothing it printed is used, and no caller can read it as an answer (a "no", an absent branch, an empty list).
GH_TIMEOUT = 75
GIT_TIMEOUT = 60
REMOTE_TIMEOUT = 75  # `git ls-remote` goes over the network, like `gh`

SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
ALLOWED_CATEGORIES = {"regression", "unit", "integration", "lint", "static-analysis", "security", "build", "other"}


class GateError(RuntimeError):
    pass


SECRET_SCAN_PATH = Path(__file__).resolve().parents[2] / "_shared" / "scripts" / "secret_scan.py"


def load_secret_scan() -> Any:
    """The shared secret scanner, loaded by path from the `_shared` bundle directory.

    One module name for all three gates, so a process that runs several of them loads it once. A
    scanner that cannot be loaded is a refusal, never a skipped check (GateError).
    """
    name = "pilot_secret_scan"
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(name, SECRET_SCAN_PATH)
    if spec is None or spec.loader is None or not SECRET_SCAN_PATH.is_file():
        raise GateError(f"the shared secret scanner is missing: {SECRET_SCAN_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # a scanner that does not load must refuse, whatever the reason
        sys.modules.pop(name, None)
        raise GateError(f"the shared secret scanner cannot be loaded ({type(exc).__name__})") from None
    return module


def check_secrets(worktree: Path, base_ref: str, head: str,
                  secret_files: Sequence[Path] = ()) -> tuple[list[str], dict[str, Any]]:
    """Blockers and a value-free summary from scanning EVERY commit of base..head.

    History counts, not just HEAD: a later commit that scrubs a value does not remove it from the
    earlier one. Nothing here is skipped for evidence-only paths, and nothing printed holds a value.
    """
    try:
        scanner = load_secret_scan()
    except GateError as exc:
        return [f"Secret scan unavailable: {exc}"], {"status": "ERROR"}
    try:
        known = scanner.load_secret_files([str(p) for p in secret_files], worktree)
    except ValueError as exc:  # SecretScanError
        return [f"Secret scan refused its --secret-file input: {exc}"], {"status": "ERROR"}
    result = scanner.scan_range(worktree, base_ref, head, known=known)
    return scanner.refusal_messages(result), result.summary()


def bounded(argv: list[str], *, limit: float, label: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """`argv` run through bounded_run.run with `limit` seconds, stdin closed. A command that exited is judged by its exit
    code, whatever something it started does with its output. One that did not finish in time has its whole process
    group ended and is a GateError that names it (`label`), the limit and how it was ended: never a CompletedProcess, so
    that `allow_nonzero_json` and `empty_if` cannot be handed a made-up exit code and a half-written answer."""
    try:
        return bounded_run.run(argv, limit=limit, cwd=cwd)
    except bounded_run.Timeout as exc:
        raise GateError(f"{label} timed out after {exc.timeout:g} s and its process group was ended ({exc.ended})") from None


def command(argv: list[str], *, cwd: Path | None = None, allow_nonzero_json: bool = False,
            empty_if: re.Pattern[str] | None = None) -> Any:
    """Run argv and parse its stdout as JSON. `empty_if` is the one tolerated failure: exit 1 with
    nothing on stdout and stderr that is exactly that message means "empty list". It is never matched
    against stdout, so a valid JSON answer is always parsed, and never as a substring of other output.
    A command that outlives GH_TIMEOUT is a GateError (see `bounded`)."""
    try:
        p = bounded(argv, limit=GH_TIMEOUT, label=" ".join(argv[:4]), cwd=cwd)
    except OSError as exc:
        raise GateError(f"Missing executable {argv[0]}: {exc}") from exc
    if empty_if is not None and p.returncode == 1 and not p.stdout.strip() and empty_if.fullmatch(p.stderr):
        return []
    if p.returncode and not allow_nonzero_json:
        raise GateError(f"{argv[:4]} failed: {(p.stderr or p.stdout).strip()[:500]}")
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(f"Invalid JSON from {argv[:3]}: {(p.stderr or p.stdout).strip()[:500]}") from exc


def git(worktree: Path, *args: str) -> str:
    try:
        p = bounded(["git", "-C", str(worktree), *args], limit=GIT_TIMEOUT, label=f"git {' '.join(args[:4])}")
    except OSError as exc:
        raise GateError(f"Cannot execute git: {exc}") from exc
    if p.returncode:
        raise GateError(f"git {args[:2]}: {p.stderr.strip()[:500]}")
    return p.stdout.strip()


def git_answer(worktree: Path, *args: str) -> bool:
    """A git yes/no command (`merge-base --is-ancestor`): exit 0 is True, exit 1 is False. Any other
    exit is an error, never read as "no" (`git()` cannot tell the two apart), and so is a git that
    outlives GIT_TIMEOUT."""
    try:
        p = bounded(["git", "-C", str(worktree), *args], limit=GIT_TIMEOUT, label=f"git {' '.join(args[:4])}")
    except OSError as exc:
        raise GateError(f"Cannot execute git: {exc}") from exc
    if p.returncode in (0, 1):
        return p.returncode == 0
    raise GateError(f"git {args[:2]}: {p.stderr.strip()[:500]}")


def check_git(worktree: Path) -> tuple[str, str, list[str]]:
    try:
        if not worktree.is_dir():
            raise GateError(f"Missing worktree: {worktree}")
        sha = git(worktree, "rev-parse", "--verify", "HEAD")
        branch = git(worktree, "symbolic-ref", "--quiet", "--short", "HEAD")
        changed = git(worktree, "status", "--porcelain=v1", "--untracked-files=all").splitlines()
        if not SHA.fullmatch(sha):
            raise GateError("HEAD is not a 40-digit git SHA")
        return sha, branch, changed
    except OSError as exc:
        raise GateError(str(exc)) from exc


def nontrivial(value: Any, length: int = 12) -> bool:
    return isinstance(value, str) and len(value.strip()) >= length


def valid_path(reference: Any, *, directory: Path, errors: list[str], label: str) -> Path | None:
    if not isinstance(reference, str) or not reference.strip():
        errors.append(f"{label}: path missing")
        return None
    candidate = Path(reference).expanduser()
    try:
        directory = directory.resolve(strict=True)
        candidate = (candidate if candidate.is_absolute() else directory / candidate).resolve(strict=True)
        if not candidate.is_relative_to(directory) or not candidate.is_file():
            errors.append(f"{label}: artifact must be a regular file under evidence directory")
            return None
        return candidate
    except (OSError, RuntimeError):
        errors.append(f"{label}: artifact missing or unreadable: {reference}")
        return None


def covers_head(ctx: "repo_evidence.Context | None", value: Any, sha: str, label: str) -> bool:
    """Evidence taken at `value` covers HEAD: same SHA, or only evidence-only files changed since."""
    return value == sha or (ctx is not None and ctx.accepts(value, label))


def check_evidence(evidence: dict[str, Any], *, repo: str, issue: int, sha: str,
                   branch: str, base: str, evidence_dir: Path,
                   ctx: "repo_evidence.Context | None" = None) -> list[str]:
    errors: list[str] = []
    for key, value in {"schema_version": 1, "repo": repo, "issue": issue,
                       "head_sha": sha, "head_branch": branch, "base_branch": base}.items():
        if evidence.get(key) != value:
            errors.append(f"evidence.{key} mismatch")
    if not nontrivial(evidence.get("root_cause"), 20):
        errors.append("root_cause lacks evidence-rich diagnosis")
    deps = evidence.get("dependencies")
    if not isinstance(deps, dict) or deps.get("status") != "resolved" or not nontrivial(deps.get("evidence"), 15):
        errors.append("Issue dependencies have not been positively assessed/resolved")
    criteria = evidence.get("acceptance_criteria")
    errors.extend(criteria_problems(criteria, "acceptance_criteria"))
    checks = evidence.get("checks")
    categories: set[str] = set()
    if not isinstance(checks, list) or not checks:
        errors.append("At least one HEAD-bound validation receipt required")
    else:
        for i, item in enumerate(checks):
            label = f"checks[{i}]"
            if not isinstance(item, dict) or item.get("category") not in ALLOWED_CATEGORIES:
                errors.append(f"{label}: invalid category")
                continue
            category = item["category"]
            categories.add(category)
            receipt_path = valid_path(item.get("receipt"), directory=evidence_dir, errors=errors, label=label)
            if receipt_path is None:
                continue
            try:
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"{label}: invalid receipt: {exc}")
                continue
            if not isinstance(receipt, dict):
                errors.append(f"{label}: receipt must be object")
                continue
            if receipt.get("schema_version") != 1 or not covers_head(ctx, receipt.get("head_sha"), sha, label):
                errors.append(f"{label}: stale or malformed receipt/HEAD")
            if receipt.get("status") != "pass" or type(receipt.get("exit_code")) is not int or receipt["exit_code"] != 0:
                errors.append(f"{label}: check did not pass")
            for field in ("head_unchanged", "clean_before", "clean_after"):
                if receipt.get(field) is not True:
                    errors.append(f"{label}: receipt.{field} is not true")
            for field in ("started_at", "finished_at", "command"):
                if not nontrivial(receipt.get(field), 5):
                    errors.append(f"{label}: no {field}")
            valid_path(receipt.get("log"), directory=evidence_dir, errors=errors, label=f"{label}.log")
    if "regression" not in categories:
        errors.append("Regression test receipt required")
    for field, category in (("lint", "lint"), ("static_analysis", "static-analysis")):
        item = evidence.get(field)
        if not isinstance(item, dict):
            errors.append(f"{field}: missing")
        elif item.get("status") == "pass":
            if category not in categories:
                errors.append(f"{field}: pass requires a {category} receipt")
            if not nontrivial(item.get("evidence")):
                errors.append(f"{field}: explanation missing")
        elif item.get("status") == "not-applicable":
            if not nontrivial(item.get("reason"), 25):
                errors.append(f"{field}: not-applicable requires specific repository-based reason")
        else:
            errors.append(f"{field}: must pass or explicitly document not-applicable")
    review = evidence.get("review")
    if not isinstance(review, dict):
        errors.append("Independent review missing")
    else:
        if review.get("agent") != "issue-reviewer" or review.get("independent") is not True:
            errors.append("Independent issue-reviewer review not attested")
        if not covers_head(ctx, review.get("head_sha"), sha, "review"):
            errors.append("Reviewer judgment is for another HEAD")
        if review.get("status") != "pass" or not nontrivial(review.get("summary"), 15):
            errors.append("Independent review did not pass / missing findings rationale")
        findings = review.get("findings")
        if not isinstance(findings, list):
            errors.append("review.findings must be a list")
        else:
            for f in findings:
                if not isinstance(f, dict) or f.get("severity") not in ("P0", "P1", "P2", "P3", "P4") or f.get("status") not in ("open", "resolved"):
                    errors.append("Reviewer finding malformed")
                elif f.get("origin") not in (None, "introduced", "aggravated", "pre-existing"):
                    errors.append("Reviewer finding has an invalid origin")
                elif f.get("origin") == "pre-existing" and f["severity"] in ("P0", "P1", "P2"):
                    errors.append("Pre-existing findings are capped at P3 (references/severity.md): re-rate and report as follow-up")
                elif f["severity"] in ("P0", "P1", "P2") and f["status"] == "open":
                    errors.append(f"Unresolved blocking review finding: {f.get('description', f['severity'])}")
    if ctx is not None:
        errors.extend(ctx.check_required(evidence.get("repo_required_evidence")))
    if "umbrella" in evidence:
        # Umbrella mode: the resolution rules apply to each sub-issue; U's own resolution follows them.
        errors.extend(umbrella_structure_problems(evidence, issue=issue))
    else:
        errors.extend(resolution_problems(evidence, "evidence"))
    return errors


def criteria_problems(criteria: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    """Each acceptance criterion is met, with a concrete criterion and evidence."""
    if not isinstance(criteria, list) or (not criteria and not allow_empty):
        return [f"{label}: acceptance criteria absent" if label != "acceptance_criteria" else "Acceptance criteria absent"]
    return [f"{label}[{i}] lacks PASS and concrete evidence" for i, item in enumerate(criteria)
            if not isinstance(item, dict) or item.get("met") is not True or not nontrivial(item.get("criterion"), 8)
            or not nontrivial(item.get("evidence"), 10)]


def resolution_problems(item: dict[str, Any], label: str) -> list[str]:
    """`issue_resolution` of an Issue (the evidence itself, or one umbrella sub-issue) against its
    `disputed_issue_claims`. `fixes` is the default when the key is absent: the PR body then closes it."""
    resolution = item.get("issue_resolution", "fixes")
    if resolution not in ISSUE_RESOLUTIONS:
        return [resolution_problem(resolution) if label == "evidence" else f"{label}: {resolution_problem(resolution)}"]
    where = "" if label == "evidence" else f"{label}: "
    if resolution == "partial" and not item.get("disputed_issue_claims"):
        return [f"{where}issue_resolution 'partial' needs the disputed_issue_claims that stay open"]
    if resolution == "fixes":
        # The converse (references/issue-claims.md "Whole-Issue outcomes"): a claim that stays open
        # after merge must not ride on a closing keyword. any(), not all(): one open claim is enough.
        items = item.get("disputed_issue_claims")
        still_open = [f"disputed_issue_claims[{i}] ({c['disposition']})"
                      for i, c in enumerate(items if isinstance(items, list) else [])
                      if isinstance(c, dict) and leaves_issue_open(c)]
        if still_open:
            return [f"{where}issue_resolution is 'fixes' (the default when absent), but " + ", ".join(still_open)
                    + " stays open after merge: set issue_resolution 'partial' (Refs #N), or for an "
                    "out_of_scope claim record the follow-up Issue in follow_up_issue_url"]
    return []


# ----------------------------------------------------------------------------- umbrella mode

BATCH_ID = re.compile(r"[0-9a-f]{12}\Z")


def umbrella_entries(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """The well-formed sub-issue entries (`issue` a positive int); malformed ones are reported by
    umbrella_structure_problems and ignored everywhere else."""
    u = evidence.get("umbrella")
    subs = u.get("sub_issues") if isinstance(u, dict) else None
    return [s for s in subs if isinstance(s, dict) and type(s.get("issue")) is int and s["issue"] > 0] \
        if isinstance(subs, list) else []


def sub_issue_resolutions(evidence: dict[str, Any]) -> dict[int, str]:
    """{sub-issue: issue_resolution} of the well-formed entries (`fixes` when absent)."""
    return {s["issue"]: s.get("issue_resolution", "fixes") for s in umbrella_entries(evidence)}


def umbrella_structure_problems(evidence: dict[str, Any], *, issue: int) -> list[str]:
    """Structure of `umbrella` (references/evidence-contract.md): per-sub-issue acceptance, resolution and
    reviewer verdict, and decision 8: U is `fixes` exactly when every sub-issue is. No GitHub reads."""
    u = evidence["umbrella"]
    if not isinstance(u, dict):
        return ["umbrella must be an object"]
    errors: list[str] = []
    if not isinstance(u.get("batch_id"), str) or not BATCH_ID.fullmatch(u["batch_id"]):
        errors.append("umbrella.batch_id must be the 12-hex batch id of the umbrella's marker line")
    subs = u.get("sub_issues")
    if not isinstance(subs, list) or not subs:
        errors.append("umbrella.sub_issues must list every open sub-issue")
        subs = []
    seen: set[int] = set()
    for i, s in enumerate(subs):
        label = f"umbrella.sub_issues[{i}]"
        if not isinstance(s, dict) or type(s.get("issue")) is not int or s["issue"] < 1:
            errors.append(f"{label} must be an object with a positive integer issue")
            continue
        label = f"umbrella sub-issue #{s['issue']}"
        if s["issue"] in seen or s["issue"] == issue:
            errors.append(f"{label} is listed twice or is the umbrella itself")
        seen.add(s["issue"])
        partial = s.get("issue_resolution", "fixes") == "partial"
        # A partial sub-issue lists only what this PR delivers for it; the rest is its disputed claims.
        errors.extend(criteria_problems(s.get("acceptance_criteria"), f"{label}.acceptance_criteria",
                                        allow_empty=partial))
        if not isinstance(s.get("disputed_issue_claims", []), list):
            errors.append(f"{label}.disputed_issue_claims malformed")
        else:
            errors.extend(resolution_problems(s, label))
        if s.get("reviewer_confirmed") is not True:
            errors.append(f"{label} not confirmed by the independent reviewer (reviewer_confirmed)")
    if evidence.get("disputed_issue_claims"):
        errors.append("umbrella mode: disputed claims belong to the sub-issue they are about "
                      "(umbrella.sub_issues[].disputed_issue_claims); the umbrella's own list must be empty")
    resolution = evidence.get("issue_resolution", "fixes")
    entries = umbrella_entries(evidence)
    expected = "fixes" if entries and all(s.get("issue_resolution", "fixes") == "fixes" for s in entries) else "partial"
    if resolution not in ISSUE_RESOLUTIONS:
        errors.append(resolution_problem(resolution))
    elif resolution != expected:
        errors.append(f"umbrella #{issue}: issue_resolution must be '{expected}' (it is 'fixes' exactly when every "
                      f"sub-issue is 'fixes'), not '{resolution}'")
    return errors


def gh_umbrella_view(repo: str, number: int) -> Any:
    return command(["gh", "issue", "view", str(number), "-R", repo, "--json", umbrella_mode.VIEW_FIELDS])


def resolve_umbrella(repo: str, issue: int) -> dict[str, Any]:
    """umbrella.py's resolution of `issue`, reading GitHub through command(). Any refusal is a GateError."""
    try:
        return umbrella_mode.resolve(repo, issue, lambda n: gh_umbrella_view(repo, n))
    except umbrella_mode.UmbrellaRefused as exc:
        raise GateError(f"umbrella: {exc}") from exc


def check_umbrella_github(evidence: dict[str, Any], *, repo: str, issue: int, branch: str, sha: str,
                          own_pr: int | None, ctx: "repo_evidence.Context | None") -> list[str]:
    """GitHub side of umbrella mode, fail closed: U resolves to itself with the same batch, the evidence
    covers exactly U's open sub-issues, each sub-issue is open with no other closing PR, and each one's
    disputed claims were answered on that sub-issue's own thread."""
    errors: list[str] = []
    try:
        resolved = resolve_umbrella(repo, issue)
    except GateError as exc:
        return [str(exc)]
    if resolved["mode"] != "umbrella" or resolved["umbrella"] != issue:
        return [f"evidence has `umbrella`, but #{issue} is not a planner umbrella (umbrella.py resolves it to "
                f"{resolved.get('umbrella', 'single mode')}); run the gate with the umbrella's number"]
    u = evidence["umbrella"]
    if isinstance(u, dict) and u.get("batch_id") != resolved["batch_id"]:
        errors.append(f"umbrella.batch_id is not #{issue}'s batch {resolved['batch_id']}")
    listed = {s["issue"] for s in umbrella_entries(evidence)}
    if listed != set(resolved["sub_issues"]):
        errors.append(f"umbrella.sub_issues {sorted(listed)} are not #{issue}'s open sub-issues "
                      f"{resolved['sub_issues']} on GitHub")
    for s in umbrella_entries(evidence):
        c = s["issue"]
        try:
            errors.extend(f"sub-issue #{c}: {e}" for e in gh_issue_and_duplicates(repo, c, branch, own_pr))
        except GateError as exc:
            errors.append(f"sub-issue #{c}: GitHub duplicate/issue validation unavailable: {exc}")
        if isinstance(s.get("disputed_issue_claims"), list) and s["disputed_issue_claims"]:
            thread = None
            try:
                thread = gh_issue_thread(repo, c)
            except GateError as exc:
                errors.append(f"sub-issue #{c}: GitHub Issue comments unavailable: {exc}")
            errors.extend(f"sub-issue #{c}: {e}" for e in
                          check_disputed_claims(s, thread, repo=repo, issue=c, sha=sha, ctx=ctx))
            errors.extend(f"sub-issue #{c}: {e}" for e in check_follow_ups(s, repo=repo, issue=c))
    return errors


# The similar-defect scan (references/similar-defect-scan.md) is checked in advisory mode: its problems
# are reported under info["similar_defect_scan"] and never block. Making them blockers is a deliberate,
# separate change of this constant, decided by the repository's owner, not part of an Issue fix.
SIMILAR_SCAN_ENFORCED = False
SCAN_CLASS = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
SCAN_CLASSIFICATIONS = ("same-invariant-in-scope", "shared-choke-point", "false-positive",
                        "separate-defect", "dependent-or-overlapping", "unconfirmed")
SCAN_MUST_RESOLVE = ("same-invariant-in-scope", "shared-choke-point")


def _scan_int(value: Any, minimum: int) -> bool:
    return type(value) is int and value >= minimum


def _scan_problems(scan: Any, *, repo: str, issue: int, worktree: Path, sha: str,
                   merge_base: str | None, ctx: "repo_evidence.Context | None") -> list[str]:
    """Structural and provenance problems of `similar_defect_scan`; empty means none were found.
    It cannot judge whether the search was sufficient or the fix correct."""
    label = "similar_defect_scan"
    if not isinstance(scan, dict):
        return [f"{label} must be an object"]
    problems: list[str] = []
    status, kind = scan.get("status"), scan.get("issue_kind")
    if status not in ("complete", "not-applicable"):
        problems.append(f"{label}.status must be complete or not-applicable")
    if kind not in ("bug", "non-bug"):
        problems.append(f"{label}.issue_kind must be bug or non-bug")
    reviewer = scan.get("reviewer")
    if not isinstance(reviewer, dict) or reviewer.get("confirmed") is not True:
        problems.append(f"{label}.reviewer.confirmed must be true (the independent Reviewer's verdict)")
    elif not covers_head(ctx, reviewer.get("head_sha"), sha, f"{label}.reviewer"):
        problems.append(f"{label}.reviewer.head_sha is for another HEAD")
    if status == "not-applicable":
        if kind == "bug":
            problems.append(f"{label}: a bug Issue cannot be not-applicable; run the scan")
        if not nontrivial(scan.get("reason"), 25):
            problems.append(f"{label}: not-applicable needs a specific reason")
        return problems
    if not isinstance(scan.get("class"), str) or not SCAN_CLASS.fullmatch(scan["class"]):
        problems.append(f"{label}.class must be a short kebab-case label")
    if not nontrivial(scan.get("invariant")):
        problems.append(f"{label}.invariant lacks a concrete statement")
    base_sha = scan.get("base_sha")
    if not isinstance(base_sha, str) or not SHA.fullmatch(base_sha):
        problems.append(f"{label}.base_sha must be a full 40-hex SHA")
    elif not git_answer(worktree, "merge-base", "--is-ancestor", base_sha, sha):
        problems.append(f"{label}.base_sha {base_sha} is not an ancestor of HEAD")
    queries = scan.get("queries")
    hits: dict[str, int] = {}
    if not isinstance(queries, list) or not queries:
        problems.append(f"{label}.queries must list the searches")
        queries = []
    for i, q in enumerate(queries):
        where = f"{label}.queries[{i}]"
        if not isinstance(q, dict) or not isinstance(q.get("id"), str) or not q["id"].strip():
            problems.append(f"{where}: needs an id")
            continue
        if q["id"] in hits:
            problems.append(f"{where}: duplicate id {q['id']!r}")
            continue
        if q.get("kind") not in ("git-grep", "family"):
            problems.append(f"{where}: kind must be git-grep or family")
        if not isinstance(q.get("scope"), str) or not q["scope"].strip():
            problems.append(f"{where}: scope missing")
        if not nontrivial(q.get("pattern" if q.get("kind") == "git-grep" else "description"), 3):
            problems.append(f"{where}: a git-grep query needs its pattern, a family query its description")
        if not _scan_int(q.get("hits"), 0):
            problems.append(f"{where}: hits must be a non-negative integer")
        hits[q["id"]] = q.get("hits") if _scan_int(q.get("hits"), 0) else 0
    if not any(isinstance(q, dict) and q.get("kind") == "git-grep" and q.get("scope") == "repo" for q in queries):
        problems.append(f"{label}: needs a repository-wide git-grep query (scope: repo)")
    if not any(isinstance(q, dict) and q.get("kind") == "family" for q in queries):
        problems.append(f"{label}: needs an execution-family query (kind: family)")
    candidates = scan.get("candidates")
    if not isinstance(candidates, list):
        problems.append(f"{label}.candidates must be a list")
        candidates = []
    accounted = dict.fromkeys(hits, 0)
    for i, c in enumerate(candidates):
        where = f"{label}.candidates[{i}]"
        if not isinstance(c, dict):
            problems.append(f"{where}: must be an object")
            continue
        if not isinstance(c.get("location"), str) or not c["location"].strip():
            problems.append(f"{where}: location missing")
        ids = c.get("query_ids")
        # isinstance first: the file is agent-written JSON, and `x in hits` raises on a list or object.
        named = [x for x in ids if isinstance(x, str) and x in hits] if isinstance(ids, list) else []
        if not isinstance(ids, list) or not ids or len(named) != len(ids):
            problems.append(f"{where}: query_ids must be a non-empty list of listed query ids (strings)")
        if not _scan_int(c.get("hits"), 1):
            problems.append(f"{where}: hits must be a positive integer")
        else:
            for x in set(named):
                accounted[x] += c["hits"]
        cls = c.get("classification")
        if cls not in SCAN_CLASSIFICATIONS:
            problems.append(f"{where}: unknown classification {cls!r}")
        elif cls == "unconfirmed":
            problems.append(f"{where}: unconfirmed candidate; investigate it before the scan is complete")
        elif cls in SCAN_MUST_RESOLVE and c.get("resolved") is not True:
            problems.append(f"{where}: {cls} must be fixed in this change (resolved: true)")
        elif cls == "separate-defect" and c.get("follow_up_issue_url") is None:
            problems.append(f"{where}: separate-defect needs follow_up_issue_url")
        for field in ("follow_up_issue_url", "related_issue_url"):
            _, problem = follow_up_number(c, repo, issue, field)
            if problem:
                problems.append(f"{where}: {problem}")
        if not nontrivial(c.get("evidence"), 10):
            problems.append(f"{where}: evidence missing")
    for qid, total in hits.items():
        if accounted[qid] != total:
            problems.append(f"{label}: query {qid!r} has {total} hits but its candidates account for "
                            f"{accounted[qid]}; classify every hit")
    risk = scan.get("recurrence_risk")
    if risk not in ("yes", "no"):
        problems.append(f"{label}.recurrence_risk must be yes or no")
    elif risk == "yes":
        guard = scan.get("guard")
        path = guard.get("path") if isinstance(guard, dict) else None
        if not isinstance(guard, dict) or guard.get("status") not in ("added", "existing"):
            problems.append(f"{label}.guard.status must be added or existing when recurrence_risk is yes")
        elif not isinstance(path, str) or not path.strip() or path.startswith("/") or ".." in path.split("/"):
            problems.append(f"{label}.guard.path must be a repository-relative path")
        else:
            listed = git(worktree, "ls-tree", sha, "--", path)
            if not listed or listed.split(None, 3)[1:2] != ["blob"] or listed.split("\t", 1)[-1] != path:
                problems.append(f"{label}.guard.path {path} is not a file at HEAD")
            elif guard["status"] == "added":
                if merge_base is None:
                    problems.append(f"{label}.guard: cannot tell whether {path} changed (no merge-base)")
                elif path not in git(worktree, "diff", "--name-only", "-z", merge_base, sha).split("\0"):
                    problems.append(f"{label}.guard.path {path} is 'added' but unchanged on this branch")
        if isinstance(guard, dict) and not nontrivial(guard.get("negative_control"), 20):
            problems.append(f"{label}.guard.negative_control must say why the guard fails on base")
    return problems


def similar_scan_report(evidence: dict[str, Any], *, repo: str, issue: int, worktree: Path, sha: str,
                        merge_base: str | None, ctx: "repo_evidence.Context | None") -> dict[str, Any]:
    """`{"enforced", "status": pass|warn|missing, "problems"}` for references/similar-defect-scan.md.
    A git failure is a problem, never a silent pass. So is any other exception: in advisory mode the
    field must never stop the gate, and enforced, the problem blocks like every other one. The shape
    checks in _scan_problems come first; tests require that no case of their type matrix lands here."""
    if "similar_defect_scan" not in evidence:
        problems = ["similar_defect_scan is absent (references/similar-defect-scan.md)"]
        return {"enforced": SIMILAR_SCAN_ENFORCED, "status": "missing", "problems": problems}
    try:
        problems = _scan_problems(evidence["similar_defect_scan"], repo=repo, issue=issue, worktree=worktree,
                                  sha=sha, merge_base=merge_base, ctx=ctx)
    except GateError as exc:
        problems = [f"similar_defect_scan could not be checked: {exc}"]
    except Exception as exc:  # noqa: BLE001 -- reported as a problem, never a pass
        problems = [f"similar_defect_scan could not be checked (internal error {type(exc).__name__}: {exc})"]
    return {"enforced": SIMILAR_SCAN_ENFORCED, "status": "warn" if problems else "pass", "problems": problems}


ISSUE_RESOLUTIONS = ("fixes", "partial")
DISPUTE_DISPOSITIONS = ("invalid", "needs_evidence", "out_of_scope")


def resolution_problem(resolution: Any) -> str:
    return f"issue_resolution must be 'fixes' or 'partial' (exactly, lower case), not {json.dumps(resolution)}"


def leaves_issue_open(item: dict[str, Any]) -> bool:
    """True if this dispute keeps part of the Issue open after merge: `needs_evidence` always does,
    `out_of_scope` unless it carries a follow_up_issue_url (whether that is valid is checked
    separately). An `invalid` claim, answered with evidence, does not."""
    if item.get("disposition") == "needs_evidence":
        return True
    return item.get("disposition") == "out_of_scope" and item.get("follow_up_issue_url") is None


def follow_up_number(item: dict[str, Any], repo: str, issue: int,
                     field: str = "follow_up_issue_url") -> tuple[int | None, str | None]:
    """The Issue number named by `item[field]` (default `follow_up_issue_url`), or an error message.

    Only `https://github.com/<this repo>/issues/<M>` (repo compared case-insensitively) with M
    different from this Issue is accepted; (None, None) when the field is absent.
    """
    url = item.get(field)
    if url is None:
        return None, None
    # At most 10 digits (GitHub numbers are 32-bit), so int() never sees an oversized literal.
    found = re.fullmatch(re.escape(f"https://github.com/{repo}/issues/") + r"([1-9][0-9]{0,9})",
                         url, re.IGNORECASE) if isinstance(url, str) else None
    if found is None:
        return None, f"{field} must be https://github.com/{repo}/issues/<number>"
    if int(found.group(1)) == issue:
        return None, f"{field} must be a different Issue than #{issue}"
    return int(found.group(1)), None


def gh_issue_thread(repo: str, issue: int) -> dict[str, Any]:
    """The Issue's URL, creation time and every comment (gh pages through all of them)."""
    value = command(["gh", "issue", "view", str(issue), "-R", repo, "--json", "number,url,createdAt,comments"])
    if not isinstance(value, dict) or value.get("number") != issue or not isinstance(value.get("comments"), list):
        raise GateError("Issue comments unavailable")
    return value


def check_disputed_claims(evidence: dict[str, Any], thread: dict[str, Any] | None, *, repo: str,
                          issue: int, sha: str, ctx: "repo_evidence.Context | None" = None) -> list[str]:
    """Verify each Issue claim the PR does not act on was answered on the Issue.

    The gate cannot judge whether the dispute is right; it checks that the claim's
    source is this Issue or one of its comments, that a later comment on the Issue
    answers it (linking the source comment when the claim came from a comment, and the
    follow-up Issue of an out_of_scope claim), and that the independent reviewer
    confirmed it for the current HEAD. That the follow-up Issue exists is `check_follow_ups`.
    """
    items = evidence.get("disputed_issue_claims", [])
    if not isinstance(items, list):
        return ["disputed_issue_claims malformed"]
    if not items:
        return []
    if thread is None:
        return ["Issue comments not fetched; cannot verify disputed Issue claims"]
    errors: list[str] = []
    issue_url = thread.get("url")
    comments: dict[str, tuple[str, str]] = {}
    for c in thread.get("comments") or []:
        if isinstance(c, dict) and isinstance(c.get("url"), str) and isinstance(c.get("createdAt"), str):
            comments[c["url"]] = (c["createdAt"], c.get("body") if isinstance(c.get("body"), str) else "")
    for i, item in enumerate(items):
        label = f"disputed_issue_claims[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{label} malformed")
            continue
        if item.get("disposition") not in DISPUTE_DISPOSITIONS:
            errors.append(f"{label}.disposition must be one of {', '.join(DISPUTE_DISPOSITIONS)}")
        follow_up = None
        if item.get("follow_up_issue_url") is not None:
            if item.get("disposition") != "out_of_scope":
                errors.append(f"{label}.follow_up_issue_url only applies to an out_of_scope claim")
            else:
                number, problem = follow_up_number(item, repo, issue)
                follow_up = item["follow_up_issue_url"] if number is not None else None
                if problem:
                    errors.append(f"{label}.{problem}")
        for key, minimum in (("claim", 20), ("counter_evidence", 30)):
            if not nontrivial(item.get(key), minimum):
                errors.append(f"{label}.{key} missing or lacks specific detail")
        if not covers_head(ctx, item.get("head_sha"), sha, label):
            errors.append(f"{label} is for another HEAD")
        if item.get("reviewer_confirmed") is not True:
            errors.append(f"{label} not confirmed by the independent reviewer")
        source, reply = item.get("source_url"), item.get("reply_url")
        if not isinstance(source, str) or not isinstance(reply, str):
            errors.append(f"{label} needs source_url and reply_url")
            continue
        if source == issue_url and isinstance(thread.get("createdAt"), str):
            source_time: str | None = thread["createdAt"]
        else:
            source_time = comments[source][0] if source in comments else None
        if source_time is None:
            errors.append(f"{label}.source_url is not this Issue or one of its comments: {source}")
        if reply not in comments:
            errors.append(f"{label}.reply_url is not a comment on this Issue: {reply}")
            continue
        if source_time is not None and comments[reply][0] <= source_time:
            errors.append(f"{label} reply was not posted after the disputed claim")
        if source != issue_url and source not in comments[reply][1]:
            errors.append(f"{label} reply does not link the disputed comment ({source})")
        if follow_up and not re.search(re.escape(follow_up) + r"(?!\w)", comments[reply][1], re.IGNORECASE):
            errors.append(f"{label} reply does not link the follow-up Issue ({follow_up})")
    return errors


def gh_follow_up_issue(repo: str, number: int) -> None:
    """Raise GateError unless `number` is an Issue (not a PR) of `repo`; read-only. Open or closed."""
    value = command(["gh", "issue", "view", str(number), "-R", repo, "--json", "number,url"])
    # `gh issue view` also resolves a PR number, answering with its /pull/ URL: the URL tells them apart.
    if (not isinstance(value, dict) or value.get("number") != number or not isinstance(value.get("url"), str)
            or not re.fullmatch(re.escape(f"https://github.com/{repo}/issues/{number}"), value["url"], re.IGNORECASE)):
        raise GateError(f"#{number} is not an Issue of {repo}: {str(value)[:200]}")


def check_follow_ups(evidence: dict[str, Any], *, repo: str, issue: int) -> list[str]:
    """Confirm every follow-up Issue named by an out_of_scope claim exists. gh is only called for
    a well-formed follow_up_issue_url; a failed lookup is an error, never a pass."""
    errors: list[str] = []
    items = evidence.get("disputed_issue_claims")
    for i, item in enumerate(items if isinstance(items, list) else []):
        if not isinstance(item, dict) or item.get("disposition") != "out_of_scope":
            continue
        number, _ = follow_up_number(item, repo, issue)
        if number is None:
            continue
        try:
            gh_follow_up_issue(repo, number)
        except GateError as exc:
            errors.append(f"disputed_issue_claims[{i}].follow_up_issue_url cannot be verified: {exc}")
    return errors


def _strip_code(text: str) -> str:
    """Drop fenced code blocks, inline code spans and HTML comments: GitHub does not treat a
    closing keyword inside them as a closing reference, so quoting "`Fixes #N`" is not a claim."""
    text = re.sub(r"(?s)(`{3,}|~{3,}).*?(?:\1|\Z)", " ", text)
    text = re.sub(r"(?s)<!--.*?-->", " ", text)
    return re.sub(r"(`+)[^`\n]*?\1", " ", text)


def closes_issue(body: str, repo: str, issue: int) -> bool:
    """True if `body` has a GitHub closing keyword for the Issue outside code."""
    mention = re.compile(
        r"(?<![A-Za-z0-9])(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s+(?:"
        + re.escape(repo) + r"#|https://github\.com/" + re.escape(repo) + r"/issues/|#)" + str(issue)
        + r"\b", re.IGNORECASE)
    return bool(mention.search(_strip_code(body)))


def references_issue(body: str, repo: str, issue: int) -> bool:
    """True if `body` mentions the Issue (#N, OWNER/REPO#N or its URL) outside code."""
    mention = re.compile(
        r"(?:(?<![\w&])|" + re.escape(repo) + r")#" + str(issue) + r"\b|https://github\.com/"
        + re.escape(repo) + r"/issues/" + str(issue) + r"\b", re.IGNORECASE)
    return bool(mention.search(_strip_code(body)))


def gh_issue_and_duplicates(repo: str, issue: int, branch: str, own_pr: int | None = None) -> list[str]:
    """Screen the Issue for duplicate PRs. ``own_pr`` is this Issue's own, already-created PR
    (used when re-running the gate before Draft -> Ready); it is never counted as a duplicate."""
    errors: list[str] = []
    value = command(["gh", "issue", "view", str(issue), "-R", repo,
                     "--json", "number,state,url,closedByPullRequestsReferences"])
    if not isinstance(value, dict) or value.get("number") != issue or value.get("state") != "OPEN":
        errors.append("GitHub issue not OPEN/identity mismatch")
    linked = value.get("closedByPullRequestsReferences")
    if not isinstance(linked, list):
        errors.append("Linked PR status unavailable")
    else:
        linked = [x for x in linked if not (own_pr is not None and isinstance(x, dict) and x.get("number") == own_pr)]
        if linked:
            errors.append("GitHub issue already has a linked closing PR: " + ", ".join(str(x.get("url", x)) for x in linked[:3]))
    branch_prs = command(["gh", "pr", "list", "-R", repo, "--state", "all", "--head", branch,
                          "--limit", "100", "--json", "number,url,headRefName,state"])
    if not isinstance(branch_prs, list):
        errors.append("Branch PR query unavailable")
    else:
        others = [x for x in branch_prs if not (own_pr is not None and isinstance(x, dict) and x.get("number") == own_pr)]
        if others:
            errors.append("Existing PR uses issue branch: " + ", ".join(str(x.get("url", x)) for x in others[:3]))
    open_prs = command(["gh", "pr", "list", "-R", repo, "--state", "open", "--limit", "500",
                        "--json", "number,url,headRefName,body,closingIssuesReferences"])
    if not isinstance(open_prs, list):
        errors.append("Open PR duplicate search unavailable")
    else:
        if len(open_prs) >= 500:
            errors.append("Open PR list hit 500 result cap; cannot exhaustively screen duplicates")
        # Catch closing references even if GitHub does not yet register the closing relationship.
        # Only a closing keyword (Fixes/Closes/Resolves ...) makes another PR a duplicate: a plain
        # "#N" / "Related: #N" / "see #N" in its body is a cross-reference, not a competing fix.
        for pr in open_prs:
            if not isinstance(pr, dict):
                errors.append("Malformed GitHub PR response")
                continue
            closing = pr.get("closingIssuesReferences")
            linked_issue = isinstance(closing, list) and any(
                isinstance(x, dict) and (x.get("url") == f"https://github.com/{repo}/issues/{issue}" or
                                              (x.get("number") == issue and
                                               (x.get("repository") or {}).get("nameWithOwner", repo) == repo))
                for x in closing)
            if own_pr is not None and pr.get("number") == own_pr:
                continue
            if linked_issue or closes_issue(pr.get("body") or "", repo, issue):
                errors.append(f"Potential duplicate PR already references Issue #{issue}: {pr.get('url')}")
    return errors


def remote_head(worktree: Path, remote: str, branch: str) -> str | None:
    """The remote's SHA of `branch`; None only when git says the branch is not there (exit 2). A `git ls-remote` that
    outlives REMOTE_TIMEOUT (a network that stalls) is a GateError, never None: "absent" is an answer, a timeout is not."""
    try:
        p = bounded(["git", "-C", str(worktree), "ls-remote", "--exit-code", remote, f"refs/heads/{branch}"],
                    limit=REMOTE_TIMEOUT, label=f"git ls-remote refs/heads/{branch}")
    except OSError as exc:
        raise GateError(f"Remote check failed: {exc}") from exc
    if p.returncode == 2:
        return None
    if p.returncode != 0:
        raise GateError(f"Remote branch query failed: {p.stderr.strip()[:400]}")
    entries = p.stdout.strip().splitlines()
    if len(entries) != 1:
        raise GateError(f"Remote branch resolution ambiguous for {branch}")
    return entries[0].split()[0]


def remote_identity(worktree: Path, remote: str, repo: str) -> bool:
    url = git(worktree, "remote", "get-url", remote)
    # Hosted GitHub HTTPS/SSH. Prevent a reviewed change from pushing to an unrelated origin.
    suffix = re.escape(repo)
    return bool(re.fullmatch(rf"(?:https?://[^/]+/|ssh://[^/]+/|git@[^:]+:){suffix}(?:\.git)?/?", url, re.I))


def evaluate(*, repo: str, issue: int, worktree: Path, evidence_path: Path,
             stage: str = "local", remote: str = "origin",
             own_pr: int | None = None,
             secret_files: Sequence[Path] = ()) -> tuple[list[str], dict[str, Any]]:
    if not REPO.fullmatch(repo) or issue < 1:
        raise GateError("Repo must be OWNER/REPO and issue must be positive")
    evidence_path = evidence_path.expanduser().resolve(strict=True)
    worktree = worktree.resolve(strict=True)
    if evidence_path.is_relative_to(worktree):
        raise GateError("Evidence files must be outside the worktree")
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"Could not parse evidence JSON: {exc}") from exc
    if not isinstance(evidence, dict):
        raise GateError("Evidence must be a JSON object")
    sha, branch, status = check_git(worktree)
    errors = []
    if status:
        errors.append(f"Dirty git worktree: {status[:3]}")
    base = evidence.get("base_branch")
    if not isinstance(base, str) or not re.fullmatch(r"[A-Za-z0-9_.\-/]+", base):
        errors.append("Invalid or unspecified base branch")
        base = ""
    if not branch or branch == base or branch in ("main", "master"):
        errors.append("Issue must use a dedicated non-base branch")
    secret_summary: dict[str, Any] = {"status": "NOT_RUN", "reason": "no valid base branch"}
    merge_base: str | None = None
    if base:
        try:
            common = git(worktree, "merge-base", f"refs/remotes/{remote}/{base}", "HEAD")
            if not SHA.fullmatch(common):
                errors.append("Cannot establish commit ancestry against remote base")
            else:
                merge_base = common
                if git(worktree, "rev-list", "--count", f"{common}..HEAD") == "0":
                    errors.append("No Issue-specific commits relative to base")
        except GateError as exc:
            errors.append(str(exc))
        # Every commit of the branch, right where its base is established: a value that a later commit
        # replaces is still in the earlier one, and pushing publishes both.
        blockers, secret_summary = check_secrets(worktree, f"refs/remotes/{remote}/{base}", sha, secret_files)
        errors.extend(blockers)
    ctx = repo_evidence.Context.load(worktree, sha, f"refs/remotes/{remote}/{base}" if base else None)
    errors.extend(check_evidence(evidence, repo=repo, issue=issue, sha=sha,
                                 branch=branch, base=base, evidence_dir=evidence_path.parent, ctx=ctx))
    scan_report = similar_scan_report(evidence, repo=repo, issue=issue, worktree=worktree, sha=sha,
                                      merge_base=merge_base, ctx=ctx)
    if SIMILAR_SCAN_ENFORCED:
        errors.extend(scan_report["problems"])
    if evidence.get("disputed_issue_claims"):
        thread = None
        try:
            thread = gh_issue_thread(repo, issue)
        except GateError as exc:
            errors.append(f"GitHub Issue comments unavailable: {exc}")
        errors.extend(check_disputed_claims(evidence, thread, repo=repo, issue=issue, sha=sha, ctx=ctx))
        errors.extend(check_follow_ups(evidence, repo=repo, issue=issue))
    if "umbrella" in evidence:
        errors.extend(check_umbrella_github(evidence, repo=repo, issue=issue, branch=branch, sha=sha,
                                            own_pr=own_pr, ctx=ctx))
    try:
        if not remote_identity(worktree, remote, repo):
            errors.append(f"Git remote '{remote}' does not identify {repo} (forks require manual handling)")
    except GateError as exc:
        errors.append(str(exc))
    if stage == "pushed":
        try:
            pushed = remote_head(worktree, remote, branch)
            if pushed != sha:
                errors.append(f"Remote branch HEAD ({pushed}) differs from validated HEAD ({sha})")
        except GateError as exc:
            errors.append(str(exc))
    try:
        errors.extend(gh_issue_and_duplicates(repo, issue, branch, own_pr))
    except GateError as exc:
        errors.append(f"GitHub duplicate/issue validation unavailable: {exc}")
    info = {"repo": repo, "issue": issue, "head_sha": sha, "branch": branch, "stage": stage,
            "issue_resolution": evidence.get("issue_resolution", "fixes"),
            "repo_evidence": ctx.report(), "secret_scan": secret_summary,
            "similar_defect_scan": scan_report}
    if "umbrella" in evidence:
        # Each sub-issue's resolution decides its own `Fixes #c` / `Refs #c` (create_pr.py, mark_ready.py).
        info["umbrella"] = {"umbrella": issue, "sub_issues": [
            {"issue": c, "issue_resolution": r} for c, r in sorted(sub_issue_resolutions(evidence).items())]}
    return errors, info


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--issue", required=True, type=int)
    ap.add_argument("--worktree", required=True, type=Path)
    ap.add_argument("--evidence", required=True, type=Path)
    ap.add_argument("--stage", choices=["local", "pushed"], default="local")
    ap.add_argument("--remote", default="origin")
    ap.add_argument("--own-pr", type=int, default=None,
                    help="This Issue's own already-created PR number; never counted as a duplicate (Draft -> Ready re-check)")
    ap.add_argument("--secret-file", action="append", default=[], type=Path, metavar="FILE",
                    help="File OUTSIDE the repository with one secret value per line (8+ bytes each) that must "
                         "appear in no commit, message or path of the branch. Repeatable. Values are never printed.")
    opt = ap.parse_args(argv)
    try:
        errors, info = evaluate(repo=opt.repo, issue=opt.issue, worktree=opt.worktree,
                                evidence_path=opt.evidence, stage=opt.stage, remote=opt.remote,
                                own_pr=opt.own_pr, secret_files=opt.secret_file)
    except (GateError, OSError) as exc:
        errors, info = [str(exc)], {"repo": opt.repo, "issue": opt.issue}
    value = {"status": "BLOCKED" if errors else "GATE-PASS", **info, "blockers": errors}
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
