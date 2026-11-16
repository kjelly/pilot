"""Shared loaders for the Issue Batch Planner tests (not a test module)."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import issue_batch_planner as planner  # noqa: E402

SYNTHETIC = HERE / "fixtures" / "synthetic"
BASE_SHA = "a" * 40
BASE_TREE = {"playbooks/apply/a.yml", "playbooks/apply/b.yml", "internal/x/y.go"}


def synthetic(name: str) -> dict:
    """A fresh deep copy of fixtures/synthetic/<name>.json."""
    return copy.deepcopy(json.loads((SYNTHETIC / f"{name}.json").read_text(encoding="utf-8")))


def snapshot_bytes(snapshot: dict) -> bytes:
    return (json.dumps(snapshot, indent=2, sort_keys=True) + "\n").encode("utf-8")

CAPTURED = HERE / "fixtures" / "captured"


def captured_text(name: str) -> str:
    return (CAPTURED / f"{name}.json").read_text(encoding="utf-8")


def make_issue(n: int, *, title: str = "", labels=(), paths=(), refs=(), tests=(), blocked=(),
               closed_by=(), sub_issue_count: int = 0) -> dict:
    """A snapshot Issue entry with sensible defaults, for shortlist tests."""
    return {"number": n, "title": title or f"Issue {n}", "url": f"https://github.com/OWNER/REPO/issues/{n}",
            "labels": sorted(labels),
            "blocked_by": [{"number": b, "state": "OPEN", "url": f"https://github.com/OWNER/REPO/issues/{b}"}
                           for b in blocked],
            "relations_complete": True, "parent": None, "sub_issue_count": sub_issue_count,
            "closed_by_prs": [{"number": c, "state": "OPEN", "url": f"https://github.com/OWNER/REPO/pull/{c}"}
                              for c in closed_by],
            "comments_count": 0, "comments_complete": True, "referenced_paths": sorted(paths),
            "referenced_issues": sorted(refs), "referenced_tests": sorted(tests)}


def make_snapshot(issues: list, prs: list = ()) -> dict:
    return {"schema_version": 1, "repository": "OWNER/REPO", "base": {"branch": "main", "sha": BASE_SHA},
            "collected_at": "2026-11-16T00:00:00Z",
            "sources": {"issues": {"count": len(issues), "limit": 1000, "complete": True},
                        "pull_requests": {"count": len(prs), "limit": 1000, "complete": True}},
            "issues": list(issues), "pull_requests": list(prs)}
