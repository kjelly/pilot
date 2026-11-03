import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

path = Path(__file__).resolve().parents[1] / 'scripts/create_issue.py'
spec = importlib.util.spec_from_file_location('create_issue', path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class CreateTests(unittest.TestCase):
    def run_case(self, outputs):
        argv = ['create_issue', '--repo', 'o/r', '--title', 'x', '--body-file', 'b', '--label', 'bug']
        with patch('sys.argv', argv), patch.object(m, 'gh', side_effect=outputs) as gh:
            return m.main(), gh.call_count

    def test_success(self):
        pages = json.dumps([[{'name':'bug'}], [{'name':'enhancement'}]])
        result, count = self.run_case([pages, 'https://github.com/o/r/issues/1', json.dumps({'url':'https://github.com/o/r/issues/1','labels':[{'name':'bug'}]})])
        self.assertEqual((result, count), (0, 3))

    def test_unknown_fails_before_creation(self):
        self.assertEqual(self.run_case([json.dumps([[{'name':'other'}]])]), (1, 1))

    def test_uncertain_create_never_retries(self):
        self.assertEqual(self.run_case([json.dumps([[{'name':'bug'}]]), RuntimeError('timeout')]), (2, 2))

    def test_dropped_label_fails_verification(self):
        self.assertEqual(self.run_case([json.dumps([[{'name':'bug'}]]), 'https://github.com/o/r/issues/1', json.dumps({'url':'https://github.com/o/r/issues/1','labels':[]})]), (3, 3))

if __name__ == '__main__': unittest.main()
