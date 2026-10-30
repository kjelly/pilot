#!/usr/bin/env python3
"""Repository-declared evidence rules shared by the quality gates.

Two things only the repository can know, read from a manifest on the **base branch**
(`.github/pr-evidence.json`, never from the PR head, so a PR cannot grant itself exemptions):

* `evidence_only_paths` — globs of files that hold evidence, not behaviour (for example
  `qa/evidence/**`). A check receipt or review taken at commit R stays valid for HEAD when
  every file that changed between R and HEAD matches these globs. Default: none (strict).
* `required_evidence` — evidence the repository demands for every change (for example a
  real-VM run), each with an `id`, a `source` and an optional `artifact_glob` where the
  committed artifact must live. Those globs are also treated as evidence-only paths.

The evidence JSON then carries `repo_required_evidence`: one entry per required id.

    {"id": "e2e-run", "status": "pass", "head_sha": "<commit that was run>",
     "artifact": "qa/evidence/x/2026-10-28.md", "summary": "..."}      # committed file
    {"id": "coverage", "status": "pass", "head_sha": "<commit>", "url": "https://ci.example/run/123",
     "summary": "..."}                                                # evidence kept elsewhere
    {"id": "e2e-run", "status": "not-applicable", "reason": "...", "reviewer_confirmed": true}

Run `python3 repo_evidence.py --worktree WT --base-ref origin/main` to print the manifest as the
gate sees it.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

MANIFEST_PATH = ".github/pr-evidence.json"
SHA = re.compile(r"[0-9a-f]{40}\Z")
ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
# A glob that matches every path of any one group exempts all code of a language or all build
# files, which would defeat SHA binding. Evidence globs must be narrower than that.
PROBES = (("a.go", "cmd/main.go", "internal/x/y_test.go"), ("a.py", "src/lib/z.py"),
          ("a.ts", "web/src/x.ts", "lib/x.js"), ("a.rs", "src/lib.rs"), ("A.java", "src/main/B.java"),
          ("a.sh", "scripts/x.sh"), ("a.yml", "playbooks/x.yml"), ("Makefile", "go.mod", "package.json"))


def glob_regex(pattern: str) -> re.Pattern[str]:
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z")


def check_glob(pattern: Any, label: str) -> str | None:
    if not isinstance(pattern, str) or not pattern.strip():
        return f"{label}: glob must be a non-empty string"
    if pattern.startswith("/") or ".." in pattern.split("/"):
        return f"{label}: glob {pattern!r} must be relative and stay inside the repository"
    rx = glob_regex(pattern)
    if any(all(rx.match(p) for p in group) for group in PROBES):
        return f"{label}: glob {pattern!r} covers all code or all build files and would defeat SHA binding"
    return None


def git(worktree: Path, *args: str) -> tuple[int, str]:
    try:
        p = subprocess.run(["git", "-C", str(worktree), *args], capture_output=True, text=True, check=False)
    except OSError:
        return 127, ""
    return p.returncode, p.stdout


def validate_manifest(data: Any) -> list[str]:
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        return [f"{MANIFEST_PATH}: must be an object with schema_version 1"]
    errors: list[str] = []
    only = data.get("evidence_only_paths", [])
    if not isinstance(only, list):
        errors.append("evidence_only_paths must be a list")
    else:
        errors += [e for i, p in enumerate(only) if (e := check_glob(p, f"evidence_only_paths[{i}]"))]
    required = data.get("required_evidence", [])
    if not isinstance(required, list):
        return errors + ["required_evidence must be a list"]
    seen: set[str] = set()
    for i, item in enumerate(required):
        label = f"required_evidence[{i}]"
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not ID.fullmatch(item["id"]):
            errors.append(f"{label}: needs an id like 'e2e-run'")
            continue
        if item["id"] in seen:
            errors.append(f"{label}: duplicate id {item['id']}")
        seen.add(item["id"])
        if not isinstance(item.get("source"), str) or not item["source"].strip():
            errors.append(f"{label}: source (where the repository mandates it) is required")
        if "artifact_glob" in item and (e := check_glob(item["artifact_glob"], f"{label}.artifact_glob")):
            errors.append(e)
    return errors


class Context:
    """Evidence rules for one gate run at a fixed HEAD."""

    def __init__(self, worktree: Path, head: str, manifest: dict[str, Any] | None,
                 errors: list[str], warnings: list[str]):
        self.worktree, self.head, self.manifest = worktree, head, manifest
        self.errors, self.warnings = errors, warnings
        self.accepted: list[dict[str, Any]] = []
        self._cache: dict[str, list[str] | None] = {}
        manifest = manifest or {}
        self.required = {r["id"]: r for r in manifest.get("required_evidence", [])}
        globs = list(manifest.get("evidence_only_paths", []))
        globs += [r["artifact_glob"] for r in self.required.values() if "artifact_glob" in r]
        self.patterns = [glob_regex(g) for g in globs]

    @classmethod
    def load(cls, worktree: Path, head: str, base_ref: str | None) -> "Context":
        errors: list[str] = []
        warnings: list[str] = []
        manifest = None
        if not base_ref:
            warnings.append("No base ref given; repository evidence rules not loaded (strict SHA binding applies)")
        else:
            rc, _ = git(worktree, "rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}")
            if rc:
                warnings.append(f"Base ref {base_ref} not found locally (run git fetch); repository evidence rules not loaded")
            else:
                rc, text = git(worktree, "show", f"{base_ref}:{MANIFEST_PATH}")
                if rc:
                    warnings.append(f"No {MANIFEST_PATH} on {base_ref}: repository-mandated evidence is NOT machine-checked. "
                                    "List what AGENTS.md/CONTRIBUTING require and get the user's confirmation.")
                else:
                    try:
                        manifest = json.loads(text)
                    except json.JSONDecodeError as exc:
                        errors.append(f"{MANIFEST_PATH} on {base_ref} is not valid JSON: {exc}")
                    else:
                        bad = validate_manifest(manifest)
                        if bad:
                            errors += [f"{MANIFEST_PATH} on {base_ref}: {e}" for e in bad]
                            manifest = None
        return cls(worktree, head, manifest, errors, warnings)

    def delta_files(self, sha: str) -> list[str] | None:
        """Files changed from `sha` to HEAD, or None when `sha` is not an ancestor."""
        if sha in self._cache:
            return self._cache[sha]
        result = None
        if SHA.fullmatch(sha):
            rc, _ = git(self.worktree, "merge-base", "--is-ancestor", sha, self.head)
            if rc == 0:
                rc, out = git(self.worktree, "diff", "--name-only", "--no-renames", "-z", f"{sha}..{self.head}")
                if rc == 0:
                    result = [p for p in out.split("\0") if p]
        self._cache[sha] = result
        return result

    def accepts(self, sha: Any, label: str) -> bool:
        """True if evidence taken at `sha` still covers HEAD."""
        if sha == self.head:
            return True
        if not isinstance(sha, str) or not self.patterns:
            return False
        changed = self.delta_files(sha)
        if changed is None or any(not any(rx.match(p) for rx in self.patterns) for p in changed):
            return False
        self.accepted.append({"label": label, "from": sha, "head": self.head, "changed": changed})
        return True

    def stale_reason(self, sha: Any) -> str:
        if not self.patterns:
            return "no evidence_only_paths declared on the base branch"
        changed = self.delta_files(sha) if isinstance(sha, str) else None
        if changed is None:
            return "SHA is not an ancestor of HEAD"
        outside = [p for p in changed if not any(rx.match(p) for rx in self.patterns)]
        return "files outside evidence_only_paths changed: " + ", ".join(outside[:5])

    def check_required(self, entries: Any) -> list[str]:
        errors = list(self.errors)
        if entries is None:
            entries = []
        if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
            return errors + ["repo_required_evidence must be a list of objects"]
        by_id: dict[str, list[dict[str, Any]]] = {}
        for e in entries:
            by_id.setdefault(str(e.get("id")), []).append(e)
        for rid in self.required:
            if rid not in by_id:
                errors.append(f"Repository-required evidence '{rid}' missing "
                              f"({self.required[rid].get('source')}); add it to repo_required_evidence")
        for rid, items in by_id.items():
            if len(items) > 1:
                errors.append(f"repo_required_evidence '{rid}' listed more than once")
            glob = self.required.get(rid, {}).get("artifact_glob")
            errors += self._check_entry(rid, items[0], glob)
        return errors

    def _check_entry(self, rid: str, entry: dict[str, Any], glob: str | None) -> list[str]:
        label = f"repo_required_evidence[{rid}]"
        status = entry.get("status")
        if status == "not-applicable":
            reason = entry.get("reason")
            if not isinstance(reason, str) or len(reason.strip()) < 30 or entry.get("reviewer_confirmed") is not True:
                return [f"{label}: not-applicable needs a specific reason (30+ chars) and reviewer_confirmed true"]
            return []
        if status != "pass":
            return [f"{label}: status must be 'pass' or 'not-applicable'"]
        errors: list[str] = []
        sha = entry.get("head_sha")
        if not self.accepts(sha, label):
            errors.append(f"{label}: run was taken at {str(sha)[:12]}, not HEAD ({self.stale_reason(sha)})")
        summary = entry.get("summary")
        if not isinstance(summary, str) or len(summary.strip()) < 20:
            errors.append(f"{label}: summary of what was observed is required")
        art, url = entry.get("artifact"), entry.get("url")
        if art is None and glob is None and url is not None:
            # Evidence kept outside the repository (CI run, test-management system, wiki).
            if not isinstance(url, str) or not re.fullmatch(r"https://[^\s]+", url):
                errors.append(f"{label}: url must be an https:// link")
        elif not isinstance(art, str) or not art.strip() or art.startswith("/") or ".." in art.split("/"):
            errors.append(f"{label}: artifact must be a repository-relative path"
                          + ("" if glob else " (or give an https:// url when the evidence lives outside the repository)"))
        else:
            rc, kind = git(self.worktree, "cat-file", "-t", f"{self.head}:{art}")
            if rc or kind.strip() != "blob":
                errors.append(f"{label}: artifact {art} is not committed at HEAD (commit the evidence file)")
            if glob and not glob_regex(glob).match(art):
                errors.append(f"{label}: artifact {art} is outside the required location {glob}")
        return errors

    def report(self) -> dict[str, Any]:
        return {"manifest_loaded": self.manifest is not None,
                "required": sorted(self.required),
                "delta_accepted": self.accepted,
                "warnings": self.warnings}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--worktree", type=Path, required=True)
    ap.add_argument("--base-ref", required=True, help="e.g. origin/main")
    a = ap.parse_args()
    rc, head = git(a.worktree, "rev-parse", "HEAD")
    ctx = Context.load(a.worktree, head.strip(), a.base_ref)
    print(json.dumps({"manifest": ctx.manifest, "errors": ctx.errors, **ctx.report()}, indent=2))
    return 2 if ctx.errors else 0


if __name__ == "__main__":
    sys.exit(main())
