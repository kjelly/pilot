#!/usr/bin/env python3
"""Read-only, fail-closed GitHub pull-request review quality gate."""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
from typing import Any
from gh_runtime import GitHubError, Repo, branch_rules, current_repo, pr_checks, pr_view, unresolved_threads

COVERAGE = ("requirements", "correctness", "architecture", "security", "concurrency",
            "edge_cases", "semantic_regression", "tests")
SHA = re.compile(r"^[0-9a-fA-F]{40}$")


def _sha(s: Any) -> bool:
    return isinstance(s, str) and bool(SHA.fullmatch(s))


def _test_assessment(tests: Any, expected_head: str) -> tuple[list[str], list[str], bool]:
    defects: list[str] = []
    gaps: list[str] = []
    has_pass = False
    if not isinstance(tests, list) or not tests:
        gaps.append("Reviewer supplied no test assessment")
        return defects, gaps, False
    for test in tests:
        if not isinstance(test, dict) or not isinstance(test.get("name"), str) or not test["name"].strip():
            gaps.append("Invalid reviewer test entry")
            continue
        name, status = test["name"], test.get("status")
        if not isinstance(test.get("sha"), str) or test["sha"].lower() != expected_head.lower():
            gaps.append(f"Test evidence is not bound to current PR HEAD: {name}")
        if status == "FAIL":
            defects.append(f"Test failed: {name}: {test.get('evidence', 'no link provided')}")
        elif status == "PASS":
            if isinstance(test.get("evidence"), str) and test["evidence"].strip():
                has_pass = True
            else:
                gaps.append(f"Passed test has no evidence: {name}")
        elif status == "SKIPPED":
            if not isinstance(test.get("reason"), str) or len(test["reason"].strip()) < 12:
                gaps.append(f"Skipped test lacks specific rationale: {name}")
        else:
            gaps.append(f"Unknown test status for {name}")
    return defects, gaps, has_pass


def evaluate(repo: Repo, number: int, evidence: dict[str, Any], *, client: Any = None) -> dict[str, Any]:
    # Importing from the module allows replacing a client during tests.
    if client is None:
        import gh_runtime as client
    result: dict[str, Any] = {"repository": repo.raw, "pr": number, "decision": "WAITING",
                               "reasons": [], "head_sha": None, "base_sha": None, "url": None,
                               "checks": {"passed": 0, "failed": 0, "pending": 0, "skipped": 0},
                               "unresolved_threads": None, "merge_queue": None}
    reasons: list[str] = result["reasons"]
    try:
        view = client.pr_view(repo, number)
    except (GitHubError, ValueError, KeyError) as exc:
        reasons.append(f"Unable to inspect PR: {exc}")
        return result
    result.update({"url": view.get("url"), "head_sha": view.get("headRefOid"),
                   "base_sha": view.get("baseRefOid")})
    if view.get("state") != "OPEN" or view.get("isDraft") is True:
        result["decision"] = "SKIP"
        reasons.append("PR is not an open non-draft PR")
        return result
    if view.get("isDraft") is not False or not _sha(result["head_sha"]) or not _sha(result["base_sha"]):
        reasons.append("Invalid PR state or missing HEAD/Base SHA")
        return result

    # Stale review evidence must never drive a destructive operation.
    if not isinstance(evidence, dict) or evidence.get("schema_version") != 1 or \
       not isinstance(evidence.get("repo"), str) or evidence["repo"].lower() != repo.raw.lower() or evidence.get("pr") != number:
        reasons.append("Missing/invalid review evidence, repository, or PR number")
        return result
    if not isinstance(evidence.get("head_sha"), str) or not isinstance(evidence.get("base_sha"), str) or \
       evidence["head_sha"].lower() != result["head_sha"].lower() or \
       evidence["base_sha"].lower() != result["base_sha"].lower():
        reasons.append("Stale review evidence: reviewed HEAD/Base does not match GitHub")
        return result
    if evidence.get("reviewer_id") != "prm-reviewer" or evidence.get("independent") is not True:
        reasons.append("An independent prm-reviewer review is required")
        return result

    defects: list[str] = []
    missing: list[str] = []
    findings = evidence.get("findings")
    if not isinstance(findings, list):
        missing.append("Reviewer findings array missing")
        findings = []
    for finding in findings:
        if not isinstance(finding, dict):
            missing.append("Invalid finding object")
            continue
        sev = finding.get("severity")
        if sev not in ("P0", "P1", "P2", "P3"):
            missing.append("Invalid finding severity")
            continue
        if not all(isinstance(finding.get(key), str) and finding[key].strip()
                   for key in ("path", "reason", "recommendation")):
            missing.append("Finding requires a file/path, reason and remediation")
            continue
        loc = f"{finding['path']}:{finding.get('line', '?')}"
        if sev in ("P0", "P1", "P2") or finding.get("blocking") is True:
            defects.append(f"{sev} {loc}: {finding['reason']} | Fix: {finding['recommendation']}")
    test_defects, test_gaps, tested = _test_assessment(evidence.get("tests"), result["head_sha"])
    defects.extend(test_defects)
    missing.extend(test_gaps)
    if evidence.get("verdict") == "BLOCK" and not defects:
        missing.append("BLOCK verdict needs a specific finding or failed test")
    elif evidence.get("verdict") not in ("PASS", "BLOCK", "NEEDS_MORE_EVIDENCE"):
        missing.append("Invalid reviewer verdict")
    if evidence.get("verdict") == "NEEDS_MORE_EVIDENCE":
        missing.append("Reviewer requested further evidence")
    if evidence.get("verdict") == "PASS" and defects:
        # Contradictory result: preserve confirmed concrete blocker, not a false PASS.
        pass
    coverage = evidence.get("coverage")
    if not isinstance(coverage, dict) or any(coverage.get(area) is not True for area in COVERAGE):
        missing.append("Reviewer coverage incomplete: " + ", ".join(
            area for area in COVERAGE if not isinstance(coverage, dict) or coverage.get(area) is not True))
    if not isinstance(evidence.get("summary"), str) or len(evidence["summary"].strip()) < 20:
        missing.append("Reviewer summary insufficient")
    deps = evidence.get("dependencies")
    if not isinstance(deps, dict) or deps.get("resolved") is not True or \
       not isinstance(deps.get("evidence"), str) or len(deps["evidence"].strip()) < 12:
        missing.append("Unresolved/unverified inter-PR dependencies")

    # Live remote evidence: failures are recorded as WAITING instead of inferred success.
    try:
        checks = client.pr_checks(repo, number)
    except (GitHubError, ValueError, KeyError) as exc:
        missing.append(f"CI state unavailable: {exc}")
        checks = None
    if checks is not None:
        if not checks:
            rationale = evidence.get("no_ci_rationale")
            if not isinstance(rationale, str) or len(rationale.strip()) < 20 or not tested:
                missing.append("No GitHub CI: requires a concrete no-CI rationale and passing test evidence")
        for check in checks:
            bucket = check.get("bucket")
            name = check.get("name") or "unnamed check"
            if bucket == "pass":
                result["checks"]["passed"] += 1
            elif bucket == "skipping":
                result["checks"]["skipped"] += 1
            elif bucket in ("fail", "cancel"):
                result["checks"]["failed"] += 1
                defects.append(f"GitHub CI check {name} is {bucket}: {check.get('link', '')}")
            elif bucket == "pending":
                result["checks"]["pending"] += 1
                missing.append(f"GitHub CI check pending: {name}")
            else:
                missing.append(f"Unknown GitHub CI check bucket {bucket!r}: {name}")
    try:
        nthreads = client.unresolved_threads(repo, number)
        result["unresolved_threads"] = nthreads
        if nthreads:
            defects.append(f"Unresolved GitHub review threads: {nthreads} (triage/resolve first)")
    except (GitHubError, ValueError, KeyError) as exc:
        missing.append(f"Cannot verify review threads: {exc}")

    try:
        base = view.get("baseRefName")
        if not isinstance(base, str) or not base:
            raise GitHubError("Missing base branch name")
        rules = client.branch_rules(repo, base)
        result["merge_queue"] = any(rule["type"] == "merge_queue" for rule in rules)
        if result["merge_queue"]:
            missing.append("Base branch requires merge queue; no unattended queue/auto-merge")
        if checks is not None and not checks and any(rule["type"] == "required_status_checks" for rule in rules):
            missing.append("Branch requires status checks, but GitHub returned no completed checks")
        for rule in rules:
            if rule["type"] == "pull_request":
                parameters = rule.get("parameters") or {}
                count = parameters.get("required_approving_review_count", 0)
                if isinstance(count, int) and count > 0 and view.get("reviewDecision") != "APPROVED":
                    missing.append("Branch rules require reviewer approval")
    except (GitHubError, ValueError, KeyError) as exc:
        missing.append(f"Unable to verify active branch rules: {exc}")

    decision = view.get("reviewDecision")
    if decision == "CHANGES_REQUESTED":
        defects.append("GitHub reviewDecision is CHANGES_REQUESTED")
    elif decision == "REVIEW_REQUIRED":
        missing.append("Human approval required by repository rules")
    elif decision not in ("APPROVED", None, ""):
        missing.append(f"Unrecognized GitHub reviewDecision: {decision!r}")

    mergeable = view.get("mergeable")
    state = view.get("mergeStateStatus")
    if mergeable == "CONFLICTING" or state == "DIRTY":
        defects.append("Merge conflict requires branch repair")
    elif mergeable != "MERGEABLE":
        missing.append(f"Mergeability unknown/not mergeable: {mergeable!r}")
    if state != "CLEAN":
        # UNSTABLE may be due to CI failures handled above; all other states require renewed proof.
        missing.append(f"Merge state is not CLEAN: {state!r}")
    if view.get("autoMergeRequest") is not None:
        missing.append("PR already has auto-merge configured; do not modify silently")

    # Cross-check HEAD/Base *after* external API calls: no live state changes during review.
    try:
        second = client.pr_view(repo, number)
        if second.get("state") != "OPEN" or second.get("isDraft") is not False or \
            second.get("headRefOid") != result["head_sha"] or second.get("baseRefOid") != result["base_sha"]:
            missing.append("PR HEAD/Base/state changed during live gate")
    except (GitHubError, ValueError, KeyError) as exc:
        missing.append(f"Could not recheck PR version: {exc}")

    # Confirmed blocker is actionable only if evidence is current and API state is known.
    # An independent review with incomplete coverage can still supply *positive* blocking evidence.
    if defects:
        result["decision"] = "DRAFT"
        reasons.extend(defects)
        if missing:
            reasons.extend("Also awaiting: " + gap for gap in missing)
    elif missing:
        reasons.extend(missing)
    elif evidence.get("verdict") == "PASS":
        result["decision"] = "MERGE"
        reasons.append("Independent review, tests, CI, comments, dependencies and merge rules clear")
    else:
        reasons.append("Reviewer did not issue a PASS verdict")
    return result


def load_evidence(path: str) -> dict[str, Any]:
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Unable to read JSON evidence: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("Evidence JSON must be an object")
    return obj


def resolve_repo(raw: str | None) -> Repo:
    return Repo.parse(raw) if raw else current_repo()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="OWNER/REPO; defaults to current repository")
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    try:
        if args.pr <= 0:
            raise ValueError("PR number must be positive")
        result = evaluate(resolve_repo(args.repo), args.pr, load_evidence(args.evidence))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["decision"] == "MERGE" else 1
    except (ValueError, GitHubError) as exc:
        print(json.dumps({"decision": "WAITING", "reasons": [str(exc)]}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
