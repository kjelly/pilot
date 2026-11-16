#!/usr/bin/env python3
"""Compare agent effort levels from the `agent_runs` record of pr-ready evidence files.

Standard library only; read-only. Usage:

    effort_report.py [EVIDENCE.json ...]        # default: .pr-ready/*/evidence.json under the cwd

Evidence files live under each checkout's ignored `.pr-ready/`, so run it once per checkout or pass
paths from several checkouts to pool them. Output is a JSON report on stdout:

- `by_role`: runs, distinct PRs and the reported P0-P2 findings per (role, model, effort).
- `pr_cohorts`: PRs grouped by the effort of their `pr-coder` runs (the A/B question: does a lower
  Coder effort cost more reviewer rounds or more P0-P2 findings?), with mean reviewer rounds and
  mean P0-P2 findings per PR. A PR whose Coder runs used several efforts is its own `mixed` cohort.
- `missing_agent_runs`: evidence files with no `agent_runs`, which the comparison cannot use.
- `invalid`: files that could not be read, or whose `agent_runs` is malformed (the same shape check
  `pr_gate.py` applies).

It reports facts only; it does not decide which effort is better. Small cohorts say little: read
`prs` before reading the means.
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

BLOCKING = ("P0", "P1", "P2")


def gate_module() -> Any:
    spec = importlib.util.spec_from_file_location("pr_gate_for_report", Path(__file__).with_name("pr_gate.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def blocking(run: dict[str, Any]) -> int:
    return sum((run.get("findings") or {}).get(sev, 0) for sev in BLOCKING)


def load(paths: list[str], agent_run_errors: Any) -> tuple[dict[str, list[dict[str, Any]]], list[str], list[Any]]:
    """Return ({evidence path: runs}, files without agent_runs, invalid entries)."""
    usable: dict[str, list[dict[str, Any]]] = {}
    missing: list[str] = []
    invalid: list[Any] = []
    for path in paths:
        try:
            evidence = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            invalid.append({"file": path, "errors": [f"unreadable: {exc}"]})
            continue
        runs = evidence.get("agent_runs") if isinstance(evidence, dict) else None
        if runs is None:
            missing.append(path)
            continue
        errors = agent_run_errors(runs)
        if errors:
            invalid.append({"file": path, "errors": errors})
            continue
        usable[path] = runs
    return usable, missing, invalid


def report(usable: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    roles: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(lambda: {"runs": 0, "files": set(), "blocking": 0})
    for path, runs in usable.items():
        for run in runs:
            row = roles[(run["role"], run["model"], run["effort"])]
            row["runs"] += 1
            row["files"].add(path)
            row["blocking"] += blocking(run)
    by_role = [{"role": role, "model": model, "effort": effort, "runs": row["runs"], "prs": len(row["files"]),
                "reviewer_blocking_findings": row["blocking"] if role == "pr-reviewer" else None}
               for (role, model, effort), row in sorted(roles.items())]

    cohorts: dict[str, list[dict[str, int]]] = defaultdict(list)
    for runs in usable.values():
        efforts = {r["effort"] for r in runs if r["role"] == "pr-coder"}
        if not efforts:
            continue
        reviews = [r for r in runs if r["role"] == "pr-reviewer"]
        cohorts["mixed" if len(efforts) > 1 else next(iter(efforts))].append(
            {"reviewer_rounds": len(reviews), "blocking_findings": sum(blocking(r) for r in reviews)})
    pr_cohorts = [{"coder_effort": effort, "prs": len(prs),
                   "mean_reviewer_rounds": round(sum(p["reviewer_rounds"] for p in prs) / len(prs), 2),
                   "mean_blocking_findings": round(sum(p["blocking_findings"] for p in prs) / len(prs), 2)}
                  for effort, prs in sorted(cohorts.items())]
    return {"by_role": by_role, "pr_cohorts": pr_cohorts}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evidence", nargs="*", help="evidence JSON files (default: .pr-ready/*/evidence.json)")
    args = ap.parse_args(argv)
    paths = args.evidence or sorted(glob.glob(".pr-ready/*/evidence.json"))
    if not paths:
        print("no evidence files found", file=sys.stderr)
        return 1
    usable, missing, invalid = load(paths, gate_module().agent_run_errors)
    out = report(usable)
    out["missing_agent_runs"] = missing
    out["invalid"] = invalid
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    print()
    return 2 if invalid else 0


if __name__ == "__main__":
    raise SystemExit(main())
