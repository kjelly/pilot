"""End of the issue-batch-planner suite: what its run read, against what its derivation names (kjelly/pilot#430).

Sorts last. The recorder (installed by test_000_suite_reads_issue_batch_planner.py) and the check are explained in
.agents/skills/_shared/tests/suite_reads.py.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

PATH = Path(__file__).resolve().parents[2] / "_shared" / "tests" / "suite_reads.py"
suite_reads = sys.modules.get("suite_reads")
if suite_reads is None:
    spec = importlib.util.spec_from_file_location("suite_reads", PATH)
    suite_reads = importlib.util.module_from_spec(spec)
    sys.modules["suite_reads"] = suite_reads
    spec.loader.exec_module(suite_reads)


class SuiteReadsTests(suite_reads.EndOfSuiteChecks, unittest.TestCase):
    SUITE = "issue-batch-planner"
    THIS_MODULE = __name__
    THIS_FILE = __file__


if __name__ == "__main__":
    unittest.main()
