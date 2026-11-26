"""Installs the in-run recorder of what the issue-to-pr suite reads (kjelly/pilot#430).

Sorts first, so every other test module of the suite is imported with the recorder in place. The end-of-suite check is
test_zzz_suite_reads_issue_to_pr.py; both are explained in .agents/skills/_shared/tests/suite_reads.py.
"""
import importlib.util
import sys
from pathlib import Path

PATH = Path(__file__).resolve().parents[2] / "_shared" / "tests" / "suite_reads.py"
suite_reads = sys.modules.get("suite_reads")
if suite_reads is None:
    spec = importlib.util.spec_from_file_location("suite_reads", PATH)
    suite_reads = importlib.util.module_from_spec(spec)
    sys.modules["suite_reads"] = suite_reads
    spec.loader.exec_module(suite_reads)
suite_reads.install()
