import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SKILL = ROOT / '.agents/skills/issue-filing/SKILL.md'

class FilingContractTests(unittest.TestCase):
    def test_required_filing_guards_are_documented(self):
        text = SKILL.read_text()
        for fragment in ('current labels', 'descriptions', 'paginate',
                         'search for duplicates', 'same repository', 'read back',
                         'permissions', 'uncertain response', 'Do not create or rename'):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)

    def test_repo_and_trec_reference_contract(self):
        path = '.agents/skills/issue-filing/SKILL.md'
        self.assertIn(path, (ROOT / 'AGENTS.md').read_text())
        self.assertIn(path, (ROOT / '.agents/skills/pilot-trec-verification/references/filing-policy.md').read_text())

if __name__ == '__main__':
    unittest.main()
