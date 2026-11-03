import csv
import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

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

    def test_selected_labels_reach_cli_literally(self):
        cases = [
            (['bug'], ['bug']),
            (['a,b'], ['"a,b"']),
            (['a"b'], ['"a""b"']),
            (['bug', 'a,b', 'a"b'], ['bug', '"a,b"', '"a""b"']),
        ]
        for labels, encoded in cases:
            with self.subTest(labels=labels):
                flags = [arg for label in labels for arg in ['--label', label]]
                argv = ['create_issue', '--repo', 'o/r', '--title', 'x', '--body-file', 'b', *flags]
                url = 'https://github.com/o/r/issues/1'
                names = [{'name': label} for label in labels]
                outputs = [json.dumps([names]), url, json.dumps({'url': url, 'labels': names})]
                responses = [SimpleNamespace(returncode=0, stdout=value, stderr='') for value in outputs]
                with patch('sys.argv', argv), patch.object(m.subprocess, 'run', side_effect=responses) as run:
                    self.assertEqual(m.main(), 0)
                self.assertEqual(run.call_count, 3)
                expected_flags = [arg for value in encoded for arg in ['--label', value]]
                self.assertEqual(run.call_args_list[1], call(
                    ['gh', 'issue', 'create', '--repo', 'o/r', '--title', 'x', '--body-file', 'b', *expected_flags],
                    text=True, capture_output=True))
                actual_flags = run.call_args_list[1].args[0][9:]
                decoded = [name for value in actual_flags[1::2] for name in next(csv.reader([value], strict=True))]
                self.assertEqual(decoded, labels)

    def test_unknown_fails_before_creation(self):
        self.assertEqual(self.run_case([json.dumps([[{'name':'other'}]])]), (1, 1))

    def test_uncertain_create_never_retries(self):
        self.assertEqual(self.run_case([json.dumps([[{'name':'bug'}]]), RuntimeError('timeout')]), (2, 2))

    def test_dropped_label_fails_verification(self):
        self.assertEqual(self.run_case([json.dumps([[{'name':'bug'}]]), 'https://github.com/o/r/issues/1', json.dumps({'url':'https://github.com/o/r/issues/1','labels':[]})]), (3, 3))

if __name__ == '__main__': unittest.main()
