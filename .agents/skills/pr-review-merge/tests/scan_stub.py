"""Test helpers (not a test module): take the secret scan out of tests that are about something else.

The gate WAITs when it cannot scan the PR's commits, so a test that drives `evaluate()` with fake SHAs and
a fake client replaces the scan with a clean one. Tests about the scan itself (test_secret_scan.py) never
use this: they run the real scanner against a real repository with `--worktree`.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import review_gate  # noqa: E402

CLEAN = ([], [], {"status": "CLEAN", "commits_scanned": 0, "findings": 0})


def clean_scan():
    """A started patch: review_gate.check_secrets answers CLEAN. Stop it with .stop()."""
    patcher = mock.patch.object(review_gate, "check_secrets", return_value=CLEAN)
    patcher.start()
    return patcher


class CleanScan:
    """Mixin for a module: `setUpModule = CleanScan.up; tearDownModule = CleanScan.down`."""

    patcher = None

    @classmethod
    def up(cls):
        cls.patcher = clean_scan()

    @classmethod
    def down(cls):
        cls.patcher.stop()
