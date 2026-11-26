"""Run one of the gate scripts as `__main__` with the secret scan replaced by a clean one (test helper).

    python scan_stub_runner.py <script.py> <args...>

For the end-to-end tests whose PR has fake SHAs (the fixture gh answers for commits that do not exist in
any repository). The tests that exercise the scan call the scripts directly, with a real repository.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import scan_stub  # noqa: E402  (puts ../scripts first on sys.path and imports review_gate)

if __name__ == "__main__":
    script = Path(sys.argv[1])
    scan_stub.clean_scan()
    sys.argv = [str(script), *sys.argv[2:]]
    # Import the script as a module (not run_path): apply_decision and review_gate then share the one
    # review_gate module whose scan was replaced.
    module = importlib.import_module(script.stem)
    # PRM_TEST_READ_INTERVAL: the seconds the actor waits between two reads of a write GitHub shows late (a
    # test of the bound on those reads must not take them).
    if "PRM_TEST_READ_INTERVAL" in os.environ and hasattr(module, "READ_INTERVAL"):
        module.READ_INTERVAL = float(os.environ["PRM_TEST_READ_INTERVAL"])
    sys.exit(module.main())
