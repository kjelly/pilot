#!/usr/bin/env python3
"""Select conservative PR validation and check every planned job's result.

Only agent skills and accompanying design/evidence Markdown have a fast path.
Everything else (including runtime specs, Go tests, CI and dependencies) is full.
Read the frozen merge's real parents, never an API file listing or moving ref.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ci_reuse", ROOT / "scripts/ci-validation-reuse.py")
reuse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reuse)

HEAVY_JOBS = {
    "test", "go-test-results", "playbook-lint", "playbook-integration",
    "root-tests", "thanos-retention", "lint", "pilot-mcp-cross", "mcp-remote", "image",
}
RESULT_JOBS = HEAVY_JOBS | {"changes", "skills", "ci-receipt"}


def path_kind(path):
    parts = PurePosixPath(path).parts
    if not path or path.startswith("/") or ".." in parts:
        return "full"
    if path.startswith((".agents/skills/", ".claude/skills/", ".claude/agents/")):
        return "skills"
    if path.endswith(".md") and path.startswith(("docs/superpowers/plans/", "docs/superpowers/specs/", "docs/evidence/")):
        return "docs"
    return "full"


def classify(paths):
    kinds = {path_kind(path) for path in paths}
    if not kinds or "full" in kinds:
        return "full"
    return "skills" if "skills" in kinds else "docs"


def select(event, env):
    ctx = reuse.context(event, env)
    # No rename inference: both the removed and added paths must be harmless.
    raw = reuse.git("diff", "--name-only", "--no-renames", "-z", ctx["base_sha"], ctx["tested_merge_sha"])
    paths = [path.decode("utf-8", errors="strict") for path in raw.split(b"\0") if path]
    return classify(paths), paths


def check_results(needs, profile, evidence_only, receipt_required):
    if profile not in {"full", "skills", "docs"} or evidence_only not in {"true", "false"}:
        raise ValueError("missing or invalid selection outputs")
    if not isinstance(needs, dict) or set(needs) != RESULT_JOBS:
        raise ValueError("result job set differs from the validation contract")
    full = profile == "full" and evidence_only == "false"
    for name in sorted(RESULT_JOBS):
        expected = "success"
        if name in HEAVY_JOBS:
            expected = "success" if full else "skipped"
        elif name == "ci-receipt":
            expected = "success" if full and receipt_required else "skipped"
        if needs[name].get("result") != expected:
            raise ValueError(f"{name}: expected {expected}, got {needs[name].get('result')}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-results", action="store_true")
    args = parser.parse_args()
    event = {}
    if args.check_results:
        try:
            receipt = os.environ["RECEIPT_REQUIRED"]
            if receipt not in {"true", "false"}:
                raise ValueError("missing or invalid receipt requirement")
            check_results(json.loads(os.environ["NEEDS_JSON"]), os.environ["CI_PROFILE"],
                          os.environ["EVIDENCE_ONLY"], receipt == "true")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            print(f"CI validation failed: {exc}", file=sys.stderr)
            return 1
        print("All jobs match the selected CI validation plan.")
        return 0
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        profile, paths = select(event, os.environ)
        reason = "all changed paths belong to the narrow allowlist" if profile != "full" else "runtime, shared, unknown or empty changes"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        profile, paths, reason = "full", [], "unavailable or untrusted PR context/history"
    print(f"profile={profile}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as out:
            # Do not interpolate filenames (untrusted Markdown) into the summary.
            out.write(f"CI impact selection: **{profile}** ({len(paths)} changed paths; {reason}).\n")
            out.write("Full: all runtime tests and image. Skills: skill tests, layout and YAML checks. "
                      "Docs: layout and YAML checks. Pushes, dispatches, forks and unknown paths run full CI.\n")
            if profile != "full":
                out.write("Skipped because the changed inputs are outside runtime/build dependencies: "
                          + ", ".join(sorted(HEAVY_JOBS | {"ci-receipt"})) + ".\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
