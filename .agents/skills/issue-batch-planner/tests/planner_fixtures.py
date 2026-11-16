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
