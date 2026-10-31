#!/usr/bin/env python3
"""Read-only, fail-closed GitHub pull-request review quality gate."""
from __future__ import annotations
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any
from gh_runtime import GitHubError, Repo, branch_rules, current_repo, pr_checks, pr_view, unresolved_threads

COVERAGE = ("requirements", "correctness", "architecture", "security", "concurrency",
            "edge_cases", "semantic_regression", "tests")
SHA = re.compile(r"^[0-9a-fA-F]{40}$")
SEVERITIES = ("P0", "P1", "P2", "P3", "P4")
TARGET_DECISIONS = ("required", "not-needed", "blocked")
# Same floor as issue-to-pr's `not-applicable` reason and `unrelated_failing_checks`.
TARGET_REASON_MIN = 30
REPO_EVIDENCE_PATH = Path(__file__).resolve().parents[2] / "issue-to-pr" / "scripts" / "repo_evidence.py"


def _load_repo_evidence() -> Any:
    """issue-to-pr's repo_evidence.py, loaded by path from the sibling skill.

    Both gates must read `.github/pr-evidence.json` the same way: one manifest schema, one
    glob dialect, one evidence-only delta rule. The skills ship together in this repository
    (`.claude/skills/*` are symlinks into `.agents/skills/`), so the sibling is always there.
    """
    name = "issue_to_pr_repo_evidence"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, REPO_EVIDENCE_PATH)
    if spec is None or spec.loader is None or not REPO_EVIDENCE_PATH.is_file():
        raise ImportError(f"pr-review-merge needs {REPO_EVIDENCE_PATH} (the issue-to-pr skill)")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


repo_evidence = _load_repo_evidence()


class RemoteContext(repo_evidence.Context):
    """repo_evidence.Context whose delta comes from GitHub's compare API, not a local checkout.

    `accepts`, `stale_reason` and `report` are issue-to-pr's: evidence taken at R covers HEAD
    when R is HEAD, or an ancestor and every file changed since matches the base manifest's
    evidence-only globs (`evidence_only_paths` plus each `artifact_glob`).
    """

    def __init__(self, client: Any, repo: Repo, head: str, manifest: dict[str, Any]):
        super().__init__(None, head, manifest, [], [])
        self.client, self.repo = client, repo

    def delta_files(self, sha: str) -> list[str] | None:
        if sha in self._cache:
            return self._cache[sha]
        result = None
        if isinstance(sha, str) and repo_evidence.SHA.fullmatch(sha):
            cmp = self.client.compare(self.repo, sha, self.head)
            if cmp is not None and cmp["ancestor"]:
                result = list(cmp["files"])
        self._cache[sha] = result
        return result


def _safe_relative(path: Any) -> bool:
    return isinstance(path, str) and bool(path.strip()) and not path.startswith("/") \
        and ".." not in path.split("/") and "\\" not in path


def _manifest_errors(manifest: Any) -> list[str]:
    """issue-to-pr's validation plus `required_paths`, a key only this gate reads."""
    errors = repo_evidence.validate_manifest(manifest)
    if errors:
        return errors
    for i, item in enumerate(manifest.get("required_evidence", [])):
        paths = item.get("required_paths", [])
        if not isinstance(paths, list) or not all(_safe_relative(p) for p in paths):
            errors.append(f"required_evidence[{i}].required_paths must be a list of repository-relative globs")
    return errors


def _names_revision(text: str, rev: str) -> bool:
    """The record names `rev`: the full SHA or an abbreviation of at least 7 hex digits."""
    return any(rev.startswith(token.lower())
               for token in re.findall(r"(?<![0-9A-Za-z])[0-9a-fA-F]{7,40}(?![0-9A-Za-z])", text))


def check_target_validation(client: Any, repo: Repo, head: str, base: str,
                            evidence: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    """Gaps that keep the PR from MERGE under the base branch's `.github/pr-evidence.json`.

    The manifest is read at the PR's base SHA, never the head, so a PR cannot weaken its own
    requirement. No manifest means no requirement. Every gap is a WAITING reason: a missing
    record is a DRAFT only through the reviewer's blocking P1 finding.
    """
    path = repo_evidence.MANIFEST_PATH
    head, base = head.lower(), base.lower()
    report: dict[str, Any] = {"manifest": "unreadable", "read_at": base}
    try:
        raw = client.file_at(repo, path, base)
    except (GitHubError, ValueError, KeyError) as exc:
        return [f"Cannot read {path} at base {base[:12]}: {exc}"], report
    if raw is None:
        report["manifest"] = "absent"
        return [], report
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        report["manifest"] = "invalid"
        return [f"{path} at base {base[:12]} is not valid JSON: {exc}"], report
    errors = _manifest_errors(manifest)
    if errors:
        report["manifest"] = "invalid"
        return [f"{path} at base {base[:12]}: {e}" for e in errors], report
    ctx = RemoteContext(client, repo, head, manifest)
    report["manifest"] = "loaded"
    tv = evidence.get("target_validation")
    gaps = _check_record(client, repo, head, base, ctx, tv)
    report.update(ctx.report(), decision=tv.get("decision") if isinstance(tv, dict) else None)
    return gaps, report


def _check_record(client: Any, repo: Repo, head: str, base: str, ctx: Any, tv: Any) -> list[str]:
    required = list(ctx.required.values())
    if not required:
        return []
    if len(required) > 1:
        return [f"{repo_evidence.MANIFEST_PATH} requires {len(required)} records "
                f"({', '.join(sorted(ctx.required))}); target_validation records one, so a person decides"]
    item = required[0]
    need = f"The base branch requires the '{item['id']}' record ({item['source']})"
    if not isinstance(tv, dict):
        return [f"{need}; target_validation is missing or not an object"]
    decision, reason = tv.get("decision"), tv.get("reason")
    if decision not in TARGET_DECISIONS:
        return [f"target_validation.decision must be one of {', '.join(TARGET_DECISIONS)}, got {decision!r}"]
    if not isinstance(reason, str) or len(reason.strip()) < TARGET_REASON_MIN:
        return [f"target_validation.reason must state why it is {decision} ({TARGET_REASON_MIN}+ characters)"]
    if decision == "blocked":
        return [f"{need}; target validation is blocked: {reason.strip()[:300]}"]
    if decision == "not-needed":
        patterns = [repo_evidence.glob_regex(p) for p in item.get("required_paths", [])]
        if not patterns:
            return []
        try:
            cmp = client.compare(repo, base, head)
        except (GitHubError, ValueError, KeyError) as exc:
            return [f"target_validation is not-needed, but the PR's changed files cannot be listed: {exc}"]
        if cmp is None:
            return ["target_validation is not-needed, but GitHub could not compare the PR's base and HEAD"]
        hits = sorted({p for p in cmp["files"] if any(rx.match(p) for rx in patterns)})
        if hits:
            return [f"{need}: target_validation says not-needed, but the PR changes {', '.join(hits[:5])}, "
                    f"which the manifest's required_paths always cover"]
        return []
    gaps: list[str] = []
    rev, art = tv.get("tested_revision"), tv.get("artifact")
    glob = item.get("artifact_glob")
    if not isinstance(rev, str) or not repo_evidence.SHA.fullmatch(rev.lower()):
        gaps.append(f"{need}; tested_revision must be the full 40-hex SHA of the tested candidate, got {rev!r}")
        rev = None
    else:
        rev = rev.lower()
        try:
            if not ctx.accepts(rev, "target_validation"):
                gaps.append(f"{need}; the run at {rev[:12]} does not cover HEAD {head[:12]} ({ctx.stale_reason(rev)})")
        except (GitHubError, ValueError, KeyError) as exc:
            gaps.append(f"{need}; cannot verify that the run at {rev[:12]} covers HEAD: {exc}")
    if not _safe_relative(art):
        gaps.append(f"{need}; target_validation.artifact must be a repository-relative path, got {art!r}")
        return gaps
    if glob and not repo_evidence.glob_regex(glob).match(art):
        gaps.append(f"{need}; artifact {art} is outside the required location {glob}")
        return gaps
    try:
        content = client.file_at(repo, art, head)
    except (GitHubError, ValueError, KeyError) as exc:
        return gaps + [f"{need}; cannot read artifact {art} at HEAD: {exc}"]
    if content is None:
        gaps.append(f"{need}; artifact {art} is not committed at HEAD {head[:12]}")
    elif rev and not _names_revision(content.decode("utf-8", "replace"), rev):
        gaps.append(f"{need}; artifact {art} does not name the tested revision {rev[:12]}")
    return gaps


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
                               "unresolved_threads": None, "merge_queue": None, "target_validation": None}
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
    # A reply disputing an earlier finding is a conversation comment or an inline
    # reply on this PR (pr-ready's references/review-comments.md).
    reply_url = re.compile(rf"https://github\.com/{re.escape(repo.raw)}/pull/{number}"
                           r"#(?:issuecomment-|discussion_r)\d+", re.IGNORECASE)
    repeated_disputes = 0
    findings = evidence.get("findings")
    if not isinstance(findings, list):
        missing.append("Reviewer findings array missing")
        findings = []
    for finding in findings:
        if not isinstance(finding, dict):
            missing.append("Invalid finding object")
            continue
        sev = finding.get("severity")
        if sev not in SEVERITIES:
            missing.append("Invalid finding severity")
            continue
        if not all(isinstance(finding.get(key), str) and finding[key].strip()
                   for key in ("path", "reason", "recommendation")):
            missing.append("Finding requires a file/path, reason and remediation")
            continue
        loc = f"{finding['path']}:{finding.get('line', '?')}"
        if sev in ("P0", "P1", "P2") or finding.get("blocking") is True:
            text = f"{sev} {loc}: {finding['reason']} | Fix: {finding['recommendation']}"
            disputed = finding.get("disputed_reply_url")
            if disputed is not None:
                # The finding repeats a claim already disputed on the PR. Only new
                # evidence sends it back to Draft; otherwise two reviewers disagree
                # and a person decides, instead of another Draft/Ready round.
                if not isinstance(disputed, str) or not reply_url.fullmatch(disputed):
                    missing.append(f"{sev} {loc}: disputed_reply_url is not a comment on this PR: {disputed!r}")
                    continue
                new = finding.get("new_evidence")
                if not isinstance(new, str) or len(new.strip()) < 30:
                    repeated_disputes += 1
                    missing.append(f"{text} | Repeats the claim disputed in {disputed} without new evidence; "
                                   "a person decides between the finding and the dispute")
                    continue
                text += f" | Disputed in {disputed}; new evidence: {new.strip()}"
            defects.append(text)
    test_defects, test_gaps, tested = _test_assessment(evidence.get("tests"), result["head_sha"])
    defects.extend(test_defects)
    missing.extend(test_gaps)
    if evidence.get("verdict") == "BLOCK" and not defects and not repeated_disputes:
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

    # A failing check the reviewer confirmed unrelated to this PR (for example the
    # same failure on the base branch) is not something the PR can fix: it keeps the
    # PR Ready and WAITING for a rerun instead of sending it back to Draft, which
    # pr-ready would undo with the same exemption. It never allows a merge.
    unrelated: dict[str, dict[str, Any]] = {}
    items = evidence.get("unrelated_failing_checks", [])
    if not isinstance(items, list):
        missing.append("unrelated_failing_checks malformed")
        items = []
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"] \
                and isinstance(item.get("reason"), str) and len(item["reason"].strip()) >= 30 \
                and item.get("reviewer_confirmed") is True:
            unrelated[item["name"]] = item
        else:
            missing.append("Invalid unrelated_failing_checks entry (needs exact name, reason, reviewer_confirmed)")

    # Actual-run record the base branch's .github/pr-evidence.json mandates: gaps are WAITING.
    target_gaps, result["target_validation"] = check_target_validation(
        client, repo, result["head_sha"], result["base_sha"], evidence)
    missing.extend(target_gaps)

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
                if name in unrelated:
                    missing.append(f"GitHub CI check {name} is {bucket}, unrelated to this PR per the reviewer "
                                   f"({unrelated[name]['reason'].strip()[:300]}); rerun it once the cause is fixed: "
                                   f"{check.get('link', '')}")
                else:
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
        # pr-ready marks a PR Ready once the requested changes are fixed or disputed,
        # without waiting for the reviewer to re-approve; drafting it again would only
        # restart that loop. Objections still open come back as reviewer findings.
        missing.append("GitHub reviewDecision is CHANGES_REQUESTED: waiting for that reviewer to re-review")
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
