#!/usr/bin/env python3
"""Fail-closed Issue→PR quality gate: SHA-bound local checks + GitHub duplicate screening.

Stage 'local' checks pre-push readiness. Stage 'pushed' additionally checks that
remote head exists and is identical. The gate cannot prove semantic correctness.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import repo_evidence  # noqa: E402

SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
ALLOWED_CATEGORIES = {"regression", "unit", "integration", "lint", "static-analysis", "security", "build", "other"}


class GateError(RuntimeError):
    pass


def command(argv: list[str], *, cwd: Path | None = None, allow_nonzero_json: bool = False,
            empty_if: str | None = None) -> Any:
    try:
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise GateError(f"Missing executable {argv[0]}: {exc}") from exc
    if empty_if and p.returncode and empty_if in f"{p.stdout}\n{p.stderr}".lower():
        return []
    if p.returncode and not allow_nonzero_json:
        raise GateError(f"{argv[:4]} failed: {(p.stderr or p.stdout).strip()[:500]}")
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(f"Invalid JSON from {argv[:3]}: {(p.stderr or p.stdout).strip()[:500]}") from exc


def git(worktree: Path, *args: str) -> str:
    try:
        p = subprocess.run(["git", "-C", str(worktree), *args], capture_output=True, text=True)
    except OSError as exc:
        raise GateError(f"Cannot execute git: {exc}") from exc
    if p.returncode:
        raise GateError(f"git {args[:2]}: {p.stderr.strip()[:500]}")
    return p.stdout.strip()


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
    if not isinstance(criteria, list) or not criteria:
        errors.append("Acceptance criteria absent")
    else:
        for i, item in enumerate(criteria):
            if not isinstance(item, dict) or item.get("met") is not True or not nontrivial(item.get("criterion"), 8) or not nontrivial(item.get("evidence"), 10):
                errors.append(f"acceptance_criteria[{i}] lacks PASS and concrete evidence")
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
    return errors


def _strip_code(text: str) -> str:
    """Drop fenced code blocks, inline code spans and HTML comments: GitHub does not treat a
    closing keyword inside them as a closing reference, so quoting "`Fixes #N`" is not a claim."""
    text = re.sub(r"(?s)(`{3,}|~{3,}).*?(?:\1|\Z)", " ", text)
    text = re.sub(r"(?s)<!--.*?-->", " ", text)
    return re.sub(r"(`+)[^`\n]*?\1", " ", text)


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
        mention = re.compile(
            r"(?<![A-Za-z0-9])(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s+(?:"
            + re.escape(repo) + r"#|https://github\.com/" + re.escape(repo) + r"/issues/|#)" + str(issue)
            + r"\b", re.IGNORECASE)
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
            if linked_issue or mention.search(_strip_code(pr.get("body") or "")):
                errors.append(f"Potential duplicate PR already references Issue #{issue}: {pr.get('url')}")
    return errors


def remote_head(worktree: Path, remote: str, branch: str) -> str | None:
    try:
        p = subprocess.run(["git", "-C", str(worktree), "ls-remote", "--exit-code", remote,
                            f"refs/heads/{branch}"], capture_output=True, text=True)
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
             own_pr: int | None = None) -> tuple[list[str], dict[str, Any]]:
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
    if base:
        try:
            common = git(worktree, "merge-base", f"refs/remotes/{remote}/{base}", "HEAD")
            if not SHA.fullmatch(common):
                errors.append("Cannot establish commit ancestry against remote base")
            elif git(worktree, "rev-list", "--count", f"{common}..HEAD") == "0":
                errors.append("No Issue-specific commits relative to base")
        except GateError as exc:
            errors.append(str(exc))
    ctx = repo_evidence.Context.load(worktree, sha, f"refs/remotes/{remote}/{base}" if base else None)
    errors.extend(check_evidence(evidence, repo=repo, issue=issue, sha=sha,
                                 branch=branch, base=base, evidence_dir=evidence_path.parent, ctx=ctx))
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
    return errors, {"repo": repo, "issue": issue, "head_sha": sha, "branch": branch, "stage": stage,
                    "repo_evidence": ctx.report()}


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
    opt = ap.parse_args(argv)
    try:
        errors, info = evaluate(repo=opt.repo, issue=opt.issue, worktree=opt.worktree,
                                evidence_path=opt.evidence, stage=opt.stage, remote=opt.remote,
                                own_pr=opt.own_pr)
    except (GateError, OSError) as exc:
        errors, info = [str(exc)], {"repo": opt.repo, "issue": opt.issue}
    value = {"status": "BLOCKED" if errors else "GATE-PASS", **info, "blockers": errors}
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
