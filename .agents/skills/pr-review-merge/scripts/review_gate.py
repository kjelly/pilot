#!/usr/bin/env python3
"""Read-only, fail-closed GitHub pull-request review quality gate."""
from __future__ import annotations
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence

# Running from the skill snapshot must not add __pycache__ there: `skill_snapshot.py verify`
# counts any added file and would STOP every later step. Set before the first sibling import.
sys.dont_write_bytecode = True
from gh_runtime import CompareLimitError, GitHubError, Repo, branch_rules, current_repo, pr_checks, pr_view, unresolved_threads

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

SECRET_SCAN_PATH = Path(__file__).resolve().parents[2] / "_shared" / "scripts" / "secret_scan.py"


def _load_secret_scan() -> Any:
    """The shared secret scanner, loaded by path from the `_shared` bundle directory (the module name
    is shared with the other two gates). Raises ImportError when it is missing or does not load."""
    name = "pilot_secret_scan"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SECRET_SCAN_PATH)
    if spec is None or spec.loader is None or not SECRET_SCAN_PATH.is_file():
        raise ImportError(f"the shared secret scanner is missing: {SECRET_SCAN_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # a scanner that does not load must hold the PR, whatever the reason
        sys.modules.pop(name, None)
        raise ImportError(f"the shared secret scanner cannot be loaded ({type(exc).__name__})") from None
    return module


def check_secrets(worktree: Any, base: str, head: str,
                  secret_files: Sequence[Any] = ()) -> tuple[list[str], list[str], dict[str, Any]]:
    """(defects, missing, summary) from scanning EVERY commit of base..head in a local checkout.

    A finding is a defect (DRAFT): a secret in any commit of the PR is a leaked secret, even when HEAD
    no longer has it. A scan that could not cover the whole range (no checkout, an object that is not
    there, a scanner that does not load, an unusable --secret-file) is `missing` (WAITING): the gate
    never calls an unscanned PR clean. Nothing returned holds a value.
    """
    if worktree is None:
        return [], ["Secret scan unavailable: pass --worktree <a checkout of this repository that holds the PR's "
                    "commits (git fetch them first)> so every commit of the PR can be scanned"], {"status": "NOT_RUN"}
    try:
        scanner = _load_secret_scan()
    except ImportError as exc:
        return [], [f"Secret scan unavailable: {exc}"], {"status": "ERROR"}
    try:
        known = scanner.load_secret_files([str(p) for p in secret_files], worktree)
    except ValueError as exc:  # SecretScanError
        return [], [f"Secret scan refused its --secret-file input: {exc}"], {"status": "ERROR"}
    result = scanner.scan_range(worktree, base.lower(), head.lower(), known=known)
    return scanner.finding_messages(result), scanner.error_messages(result), result.summary()


class RemoteContext(repo_evidence.Context):
    """repo_evidence.Context whose delta comes from GitHub's compare API, not a local checkout.

    `accepts`, `stale_reason` and `report` are issue-to-pr's: evidence taken at R covers HEAD
    when R is HEAD, or an ancestor and every file changed since matches the base manifest's
    evidence-only globs (`evidence_only_paths` plus each `artifact_glob`).
    """

    def __init__(self, client: Any, repo: Repo, head: str, manifest: dict[str, Any], base: str,
                 base_name: str | None = None, *, integrated_base: bool = False):
        super().__init__(None, head, manifest, [], [], base, integrated_base=integrated_base)
        self.client, self.repo = client, repo
        self.base_name = base_name

    def base_revision(self) -> str:
        if not self.base_name:
            raise ValueError("Live base branch name unavailable for target reuse")
        live = self.client.branch_head(self.repo, self.base_name)
        # Integrated mode takes the merge base with the live tip itself, so lagging PR metadata
        # cannot stand in for the base; the strict mode still refuses it.
        if not self.integrated_base and live != self.base_ref:
            raise ValueError("PR base metadata is stale; independent review base must match live base")
        return live

    def merge_base_of(self, a: str, b: str) -> str | None:
        return self.client.merge_base(self.repo, a, b)

    def comparison(self, base: str, head: str) -> dict[str, Any] | None:
        return self.client.compare(self.repo, base, head)

    def tree_entries(self, revision: str) -> dict[str, tuple[str, str]]:
        return self.client.tree_entries(self.repo, revision)

    def read_file(self, revision: str, path: str) -> bytes | None:
        return self.client.file_at(self.repo, path, revision)

    def commit_tree(self, revision: str) -> str | None:
        return self.client.commit_tree(self.repo, revision)

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


def _names_revision(text: str, rev: str) -> bool:
    """The record names `rev`: the full SHA or an abbreviation of at least 7 hex digits."""
    return any(rev.startswith(token.lower())
               for token in re.findall(r"(?<![0-9A-Za-z])[0-9a-fA-F]{7,40}(?![0-9A-Za-z])", text))


def read_manifest(client: Any, repo: Repo, base: str) -> tuple[dict[str, Any] | None, list[str], dict[str, Any]]:
    """`.github/pr-evidence.json` at the base commit: (manifest or None, errors, report)."""
    path = repo_evidence.MANIFEST_PATH
    base = base.lower()
    report: dict[str, Any] = {"manifest": "unreadable", "read_at": base}
    try:
        raw = client.file_at(repo, path, base)
    except (GitHubError, ValueError, KeyError) as exc:
        return None, [f"Cannot read {path} at base {base[:12]}: {exc}"], report
    if raw is None:
        report["manifest"] = "absent"
        return None, [], report
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        report["manifest"] = "invalid"
        return None, [f"{path} at base {base[:12]} is not valid JSON: {exc}"], report
    errors = repo_evidence.validate_manifest(manifest)
    if errors:
        report["manifest"] = "invalid"
        return None, [f"{path} at base {base[:12]}: {e}" for e in errors], report
    report["manifest"] = "loaded"
    return manifest, [], report


def check_target_validation(client: Any, repo: Repo, head: str, base: str,
                            evidence: dict[str, Any], *, base_name: str | None = None,
                            integrated_base: bool = False,
                            infra: list[str] | None = None) -> tuple[list[str], dict[str, Any]]:
    """Gaps that keep the PR from MERGE under the base branch's `.github/pr-evidence.json`.

    The manifest is read at the PR's base SHA, never the head, so a PR cannot weaken its own
    requirement. No manifest means no requirement. Every gap is a WAITING reason: a missing
    record is a DRAFT only through the reviewer's blocking P1 finding.

    A failure to READ or COMPARE (the manifest or a file at a revision cannot be read or parsed,
    the changed files cannot be listed, GitHub fails) says nothing about the record. With `infra`
    given, those messages go into it and `gaps` holds only what the record itself lacks; without
    it every message is a gap, as before. The merge train must not Draft a PR for the former.
    """
    head, base = head.lower(), base.lower()
    manifest, errors, report = read_manifest(client, repo, base)
    if errors or manifest is None:
        # `unreadable` (the API failed) and `invalid` (the base manifest does not parse) are both the
        # base branch's or GitHub's state, never a defect of this PR's record.
        if infra is not None and errors:
            infra.extend(errors)
            return [], report
        return errors, report
    ctx = RemoteContext(client, repo, head, manifest, base, base_name, integrated_base=integrated_base)
    report["manifest"] = "loaded"
    tv = evidence.get("target_validation")
    unverified: set[str] = set()
    gaps = _check_record(client, repo, head, base, ctx, tv, unverified)
    report.update(ctx.report(), decision=tv.get("decision") if isinstance(tv, dict) else None)
    if infra is not None:
        infra.extend(g for g in gaps if g in unverified)
        gaps = [g for g in gaps if g not in unverified]
    return gaps, report


def _check_record(client: Any, repo: Repo, head: str, base: str, ctx: Any, tv: Any,
                  unverified: set[str] | None = None) -> list[str]:
    """The record's gaps. `unverified` collects the messages that are read/compare/API failures."""
    unverified = set() if unverified is None else unverified

    def failure(message: str) -> str:
        unverified.add(message)
        return message

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
            return [failure(f"target_validation is not-needed, but the PR's changed files cannot be listed: {exc}")]
        if cmp is None:
            return [failure("target_validation is not-needed, but GitHub could not compare the PR's base and HEAD")]
        hits = sorted({p for p in cmp["files"] if any(rx.match(p) for rx in patterns)})
        if hits:
            return [f"{need}: target_validation says not-needed, but the PR changes {', '.join(hits[:5])}, "
                    f"which the manifest's required_paths always cover"]
        return []
    gaps: list[str] = []
    if tv.get("target_reuse") is not None and item.get("kind") != "target-run":
        return [f"{need}; target_reuse requires kind: target-run on the base manifest"]
    rev, art = tv.get("tested_revision"), tv.get("artifact")
    glob = item.get("artifact_glob")
    if not isinstance(rev, str) or not repo_evidence.SHA.fullmatch(rev.lower()):
        gaps.append(f"{need}; tested_revision must be the full 40-hex SHA of the tested candidate, got {rev!r}")
        rev = None
    else:
        rev = rev.lower()
        try:
            if not ctx.accepts_target(rev, "target_validation", tv.get("target_reuse"), art, item["id"]):
                gaps.append(f"{need}; the run at {rev[:12]} does not cover HEAD {head[:12]} ({ctx.target_stale_reason(rev)})")
        except (GitHubError, ValueError, KeyError) as exc:
            gaps.append(failure(f"{need}; cannot verify that the run at {rev[:12]} covers HEAD: {exc}"))
    if not _safe_relative(art):
        gaps.append(f"{need}; target_validation.artifact must be a repository-relative path, got {art!r}")
        return gaps
    if glob and not repo_evidence.glob_regex(glob).match(art):
        gaps.append(f"{need}; artifact {art} is outside the required location {glob}")
        return gaps
    try:
        content = client.file_at(repo, art, head)
    except (GitHubError, ValueError, KeyError) as exc:
        return gaps + [failure(f"{need}; cannot read artifact {art} at HEAD: {exc}")]
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
            gaps.append(f"Test evidence is not bound to the reviewed HEAD: {name}")
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


def check_base_alignment(client: Any, repo: Repo, number: int, view: dict[str, Any]) -> dict[str, Any]:
    """Require the live base tip in HEAD; confirm an operational Draft reason with fresh reads."""
    base_name = view.get("baseRefName")
    if not isinstance(base_name, str) or not base_name:
        raise GitHubError("Live base branch name unavailable")
    head, base = view.get("headRefOid"), view.get("baseRefOid")
    if not _sha(head) or not _sha(base):
        raise GitHubError("Invalid PR HEAD/Base SHA")
    live_base = client.branch_head(repo, base_name)
    if not _sha(live_base):
        raise GitHubError("Invalid live base branch SHA")
    mismatch = live_base != base
    behind = False
    if not mismatch:
        ancestor = client.is_ancestor(repo, live_base, head)
        if type(ancestor) is not bool:
            raise GitHubError("Base ancestry unavailable")
        behind = not ancestor
    if mismatch or behind:
        confirm = client.pr_view(repo, number)
        if any(confirm.get(k) != view.get(k) for k in
               ("state", "isDraft", "headRefOid", "baseRefOid", "baseRefName")) or \
                client.branch_head(repo, base_name) != live_base:
            raise GitHubError("PR/base branch changed while confirming base alignment; retry live gate")
    elif client.branch_head(repo, base_name) != live_base:
        raise GitHubError("Live base branch changed during ancestry verification; retry live gate")
    return {"base_name": base_name, "live_base_sha": live_base,
            "base_mismatch": mismatch, "base_behind": behind}


def train_alignment(client: Any, repo: Repo, number: int, view: dict[str, Any]) -> dict[str, Any]:
    """How the PR stands against the live base, for the merge train (kjelly/pilot#307).

    `alignment` is `aligned` (HEAD contains the live tip; lagging PR Base metadata alone is GitHub's
    to refresh), `train` (behind, but GitHub's test merge is clean and no file changed on both sides
    since the merge base: the train merges the live tip in and the review still covers the PR's
    content), `conflict`/`overlap` (a person or `pr-ready` must integrate and re-review), or
    `unknown` (GitHub has not computed mergeability, an API read failed, or a side changed too many
    files to list). `unknown_reason` says which kind: `transient` (retry later: mergeability not
    computed, an API failure) or `needs-person` (GitHub cut the file list: only a person can integrate).
    """
    out = check_base_alignment(client, repo, number, view)
    head, live = view["headRefOid"], out["live_base_sha"]
    contained = client.is_ancestor(repo, live, head) if out["base_mismatch"] else not out["base_behind"]
    if type(contained) is not bool:
        raise GitHubError("Base ancestry unavailable")
    out.update(base_behind=not contained, overlap=[])
    if contained:
        out["alignment"] = "aligned"
        return out
    mergeable = view.get("mergeable")
    if mergeable == "CONFLICTING" or view.get("mergeStateStatus") == "DIRTY":
        out["alignment"] = "conflict"
        return out
    if mergeable != "MERGEABLE":
        out["alignment"], out["unknown_reason"] = "unknown", "transient"
        out["alignment_detail"] = f"GitHub mergeability against the live base is {mergeable!r}"
        return out
    try:
        pr_side = client.compare(repo, live, head)
        base_side = client.compare(repo, head, live)
    except CompareLimitError as exc:
        out["alignment"], out["unknown_reason"] = "unknown", "needs-person"
        out["alignment_detail"] = f"cannot list the files changed since the merge base: {exc}"
        return out
    except (GitHubError, ValueError, KeyError) as exc:
        out["alignment"], out["unknown_reason"] = "unknown", "transient"
        out["alignment_detail"] = f"cannot list the files changed since the merge base: {exc}"
        return out
    if not pr_side or not base_side:
        out["alignment"], out["unknown_reason"] = "unknown", "transient"
        out["alignment_detail"] = "GitHub could not compare the PR head and the live base"
        return out
    out["overlap"] = sorted(set(pr_side["files"]) & set(base_side["files"]))
    out["alignment"] = "overlap" if out["overlap"] else "train"
    return out


def review_covers(client: Any, repo: Repo, reviewed: Any, head: str, live_base: str,
                  base_name: str) -> tuple[dict[str, Any] | None, str]:
    """(reuse record, "") when a review taken at `reviewed` covers `head`: the same commit, or every
    change since is evidence-only or a pure import from the base (the merge train's integration
    commit); otherwise (None, reason). Uses the base manifest's evidence-only paths when present.

    A (None, reason) is a verdict about the review. Failing to find out (GitHub fails, the base
    manifest cannot be read or parsed) says nothing about it and raises GitHubError instead: a caller
    must not treat an outage as a stale review."""
    if not isinstance(reviewed, str) or not SHA.fullmatch(reviewed):
        return None, "reviewed HEAD is not a full SHA"
    reviewed = reviewed.lower()
    if reviewed == head:
        return {"method": "same-head"}, ""
    manifest, errors, _ = read_manifest(client, repo, live_base)
    if errors:
        raise GitHubError("cannot verify the delta since the review: " + "; ".join(errors))
    ctx = RemoteContext(client, repo, head, manifest or {"schema_version": 1}, live_base, base_name,
                        integrated_base=True)
    try:
        if ctx.accepts_pure_import(reviewed, "review"):
            return ctx.accepted[-1], ""
        return None, ctx.review_stale_reason(reviewed)
    except (ValueError, KeyError) as exc:
        raise GitHubError(f"cannot verify the delta since the review: {exc}") from exc


class WaitKinds:
    """Which WAITING reasons resolve by themselves, for the merge train (kjelly/pilot#307).

    A WAITING gate means either "look again later" or "a person has to act". The train keeps the
    first kind enqueued and stops the run (nothing it does changes the answer); it takes the second
    kind out of the queue with the reasons, so one PR waiting for a person cannot hold up every later
    PR. A reason is `transient` only when it is registered as such at the place that emits it: CI that
    is pending, a base or PR that moved during the gate, mergeability or merge state GitHub has not
    computed, an API/infrastructure failure, a secret scan that could not run. `derived` reasons (the
    merge state of a PR that waits for something else) decide nothing alone. Every other reason, one
    nobody registered included, needs a person."""

    def __init__(self) -> None:
        self.transient: set[str] = set()
        self.derived: set[str] = set()

    def later(self, reason: str) -> str:
        self.transient.add(reason)
        return reason

    def secondary(self, reason: str) -> str:
        self.derived.add(reason)
        return reason

    def kind(self, reasons: Sequence[str]) -> str:
        """`transient` when at least one reason is and every other is transient or derived."""
        if any(r not in self.transient and r not in self.derived for r in reasons):
            return "person"
        return "transient" if any(r in self.transient for r in reasons) else "person"


def evaluate(repo: Repo, number: int, evidence: dict[str, Any], *, client: Any = None,
             worktree: Any = None, secret_files: Sequence[Any] = ()) -> dict[str, Any]:
    """The live gate. A WAITING result also carries `wait_kind`: `transient` or `person` (WaitKinds)."""
    kinds = WaitKinds()
    result = _evaluate(repo, number, evidence, client, worktree, secret_files, kinds)
    if result["decision"] == "WAITING":
        result["wait_kind"] = kinds.kind(result["reasons"])
    return result


def _evaluate(repo: Repo, number: int, evidence: dict[str, Any], client: Any, worktree: Any,
              secret_files: Sequence[Any], kinds: WaitKinds) -> dict[str, Any]:
    # Importing from the module allows replacing a client during tests.
    if client is None:
        import gh_runtime as client
    result: dict[str, Any] = {"repository": repo.raw, "pr": number, "decision": "WAITING",
                               "reasons": [], "head_sha": None, "base_sha": None, "url": None,
                               "checks": {"passed": 0, "failed": 0, "pending": 0, "skipped": 0},
                               "unresolved_threads": None, "merge_queue": None, "target_validation": None,
                               "secret_scan": None}
    reasons: list[str] = result["reasons"]
    try:
        view = client.pr_view(repo, number)
    except (GitHubError, ValueError, KeyError) as exc:
        reasons.append(kinds.later(f"Unable to inspect PR: {exc}"))
        return result
    result.update({"url": view.get("url"), "head_sha": view.get("headRefOid"),
                   "base_sha": view.get("baseRefOid")})
    if view.get("state") != "OPEN" or view.get("isDraft") is True:
        result["decision"] = "SKIP"
        reasons.append("PR is not an open non-draft PR")
        return result
    if view.get("isDraft") is not False or not _sha(result["head_sha"]) or not _sha(result["base_sha"]):
        reasons.append(kinds.later("Invalid PR state or missing HEAD/Base SHA"))
        return result

    # Operational hand-off: metadata equality alone does not prove HEAD includes main. A PR behind the
    # live base that the merge train can integrate (clean test merge, no file changed on both sides)
    # stays Ready: the train merges the live tip in, waits for CI and merges (kjelly/pilot#307).
    try:
        result.update(train_alignment(client, repo, number, view))
        base_name, live_base = view["baseRefName"], result["live_base_sha"]
        result["needs_alignment"] = result["alignment"] == "train"
        if result["alignment"] in ("conflict", "overlap"):
            result["decision"] = "DRAFT"
            detail = (f"PR HEAD {result['head_sha']} does not include live {base_name} SHA {live_base}, and "
                      + ("GitHub reports a merge conflict with it. " if result["alignment"] == "conflict" else
                         "both sides changed " + ", ".join(result["overlap"][:5]) + " since the merge base. "))
            reasons.append(
                detail + "The merge train cannot integrate it: use pr-ready to integrate the verified latest base, "
                "then rerun affected validation/CI and independent review on the updated HEAD/Base before Ready.")
            return result
        if result["alignment"] == "unknown":
            reason = (f"PR HEAD does not include live {base_name} SHA {live_base} and the merge train "
                      f"cannot classify it yet: {result.get('alignment_detail', 'unknown')}")
            reasons.append(kinds.later(reason) if result.get("unknown_reason") == "transient" else reason)
            return result
    except (GitHubError, ValueError, KeyError) as exc:
        reasons.append(kinds.later(f"Unable to verify live base branch: {exc}"))
        return result

    # Stale review evidence must never drive a destructive operation.
    if not isinstance(evidence, dict) or evidence.get("schema_version") != 1 or \
       not isinstance(evidence.get("repo"), str) or evidence["repo"].lower() != repo.raw.lower() or evidence.get("pr") != number:
        reasons.append("Missing/invalid review evidence, repository, or PR number")
        return result
    if not isinstance(evidence.get("head_sha"), str) or not isinstance(evidence.get("base_sha"), str) or \
            not SHA.fullmatch(evidence["head_sha"]) or not SHA.fullmatch(evidence["base_sha"]):
        reasons.append("Stale review evidence: reviewed HEAD/Base missing or not full SHAs")
        return result
    reviewed_head, reviewed_base = evidence["head_sha"].lower(), evidence["base_sha"].lower()
    try:
        # The reviewed base must be on the base branch: the PR's Base then, or an ancestor of the live tip.
        base_known = reviewed_base in (result["base_sha"].lower(), live_base) or \
            client.is_ancestor(repo, reviewed_base, live_base) is True
        reuse, why = review_covers(client, repo, reviewed_head, result["head_sha"].lower(), live_base, base_name) \
            if base_known else (None, f"reviewed Base {reviewed_base[:12]} is not on live {base_name}")
    except (GitHubError, ValueError, KeyError) as exc:
        # Not a verdict about the review: GitHub (or the base manifest) could not be read.
        reasons.append(kinds.later(f"Unable to verify that the review covers HEAD: cannot verify the reviewed Base: {exc}"))
        return result
    if reuse is None:
        reasons.append(f"Stale review evidence: reviewed HEAD/Base does not cover GitHub HEAD ({why})")
        return result
    if reuse.get("method") != "same-head":
        result["review_reuse"] = reuse
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
    # Reviewer tests ran on the reviewed HEAD; after a pure base import CI on HEAD covers the integration.
    test_defects, test_gaps, tested = _test_assessment(evidence.get("tests"), reviewed_head)
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
    target_infra: list[str] = []
    target_gaps, result["target_validation"] = check_target_validation(
        client, repo, result["head_sha"], live_base, evidence, base_name=view.get("baseRefName"),
        integrated_base=True, infra=target_infra)
    missing.extend(target_gaps)
    missing.extend(kinds.later(message) for message in target_infra)

    # Every commit of the PR, scanned locally by the PR's own SHAs. A leaked secret is a DRAFT even when
    # HEAD no longer has it; a scan that could not run is WAITING, never a pass.
    secret_defects, secret_gaps, result["secret_scan"] = check_secrets(
        worktree, result["base_sha"], result["head_sha"], secret_files)
    defects.extend(secret_defects)
    # A scan that could not run is the environment's problem (no checkout, an object not fetched yet).
    missing.extend(kinds.later(message) for message in secret_gaps)

    # Live remote evidence: failures are recorded as WAITING instead of inferred success.
    try:
        checks = client.pr_checks(repo, number)
    except (GitHubError, ValueError, KeyError) as exc:
        missing.append(kinds.later(f"CI state unavailable: {exc}"))
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
                missing.append(kinds.later(f"GitHub CI check pending: {name}"))
            else:
                missing.append(f"Unknown GitHub CI check bucket {bucket!r}: {name}")
    try:
        nthreads = client.unresolved_threads(repo, number)
        result["unresolved_threads"] = nthreads
        if nthreads:
            defects.append(f"Unresolved GitHub review threads: {nthreads} (triage/resolve first)")
    except (GitHubError, ValueError, KeyError) as exc:
        missing.append(kinds.later(f"Cannot verify review threads: {exc}"))

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
        missing.append(kinds.later(f"Unable to verify active branch rules: {exc}"))

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
        text = f"Mergeability unknown/not mergeable: {mergeable!r}"
        missing.append(kinds.later(text) if mergeable in (None, "", "UNKNOWN") else text)
    if state != "CLEAN":
        # UNSTABLE may be due to CI failures handled above; all other states require renewed proof.
        # UNKNOWN/BEHIND settle by themselves; the rest (BLOCKED, UNSTABLE, ...) only say that something
        # else is wrong, so they are never the reason alone for a PR to stay enqueued.
        text = f"Merge state is not CLEAN: {state!r}"
        missing.append(kinds.later(text) if state in (None, "", "UNKNOWN", "BEHIND") else kinds.secondary(text))
    if view.get("autoMergeRequest") is not None:
        missing.append("PR already has auto-merge configured; do not modify silently")

    # Cross-check HEAD/Base *after* external API calls: no live state changes during review.
    try:
        second = client.pr_view(repo, number)
        if second.get("state") != "OPEN" or second.get("isDraft") is not False or \
            second.get("headRefOid") != result["head_sha"] or second.get("baseRefOid") != result["base_sha"] or \
            second.get("baseRefName") != result["base_name"]:
            reasons.append(kinds.later("PR HEAD/Base/branch/state changed during live gate"))
            return result
        if client.branch_head(repo, base_name) != live_base:
            reasons.append(kinds.later("Live base branch changed during gate; rerun to classify current base state"))
            return result
    except (GitHubError, ValueError, KeyError) as exc:
        reasons.append(kinds.later(f"Could not recheck PR version: {exc}"))
        return result

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
    parser.add_argument("--worktree", type=Path,
                        help="Checkout of this repository that holds the PR's commits: every commit of "
                             "baseRefOid..headRefOid is scanned for secrets (without it the gate WAITs)")
    parser.add_argument("--secret-file", action="append", default=[], type=Path, metavar="FILE",
                        help="File OUTSIDE the repository with one secret value per line (8+ bytes each) that must "
                             "appear in no commit, message or path of the PR. Repeatable. Values are never printed.")
    args = parser.parse_args()
    try:
        if args.pr <= 0:
            raise ValueError("PR number must be positive")
        result = evaluate(resolve_repo(args.repo), args.pr, load_evidence(args.evidence),
                          worktree=args.worktree, secret_files=args.secret_file)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["decision"] == "MERGE" else 1
    except (ValueError, GitHubError) as exc:
        print(json.dumps({"decision": "WAITING", "reasons": [str(exc)]}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
