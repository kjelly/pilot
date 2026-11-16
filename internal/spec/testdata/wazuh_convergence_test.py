"""Real-Ansible controls for the retained-agent reinstall tasks' changed_when.

Both tasks are always-tagged (explicit interrupted-agent recovery runs under any
--tags), so a changed_when that is literally true makes every recovery re-run
report changed (kjelly/pilot#189, TestRegression_AlwaysTaggedTasksConverge). The
expressions are read from the real task files and evaluated by real Ansible against
captured output:

* apt: summaries captured from `LC_ALL=C apt-get -s ...` on apt 3.2.0 (Ubuntu 26.04),
  package list trimmed. A downgrade summary could not be captured on that host.
* dnf: MODELED text (no dnf on the capture host). The expression only recognises the
  documented "Nothing to do." and fails safe: any other output stays changed.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml

import wazuh_hermetic  # noqa: F401  (tripwire: no harness may touch real host state)

REPO = Path(__file__).resolve().parents[3]

APT_REINSTALL = """Reading package lists...
Building dependency tree...
Reading state information...
0 upgraded, 0 newly installed, 1 reinstalled, 0 to remove and 27 not upgraded.
Inst bash [5.3-2ubuntu1] (5.3-2ubuntu1 Ubuntu:26.04/resolute [amd64])
Conf bash (5.3-2ubuntu1 Ubuntu:26.04/resolute [amd64])
"""
APT_NOTHING_TO_DO = """Reading package lists...
Building dependency tree...
Reading state information...
bash is already the newest version (5.3-2ubuntu1).
0 upgraded, 0 newly installed, 0 to remove and 27 not upgraded.
"""
APT_UPGRADE = """Reading package lists...
2 upgraded, 0 newly installed, 0 to remove and 25 not upgraded.
"""
APT_DOWNGRADE_MODELED = "0 upgraded, 0 newly installed, 1 downgraded, 0 to remove and 0 not upgraded.\n"
DNF_NOTHING_TO_DO = "Last metadata expiration check: 0:01:02 ago.\nNothing to do.\nComplete!\n"
DNF_REINSTALLED_MODELED = ("Dependencies resolved.\nReinstalling:\n wazuh-agent x86_64 4.14.1-1 @commandline\n"
                           "Transaction Summary\nReinstall  1 Package\nReinstalled:\n  wazuh-agent-4.14.1-1.x86_64\nComplete!\n")


def find_task(items, suffix):
    for task in items or []:
        if str(task.get('name', '')).endswith(suffix):
            return task
        for section in ('block', 'rescue', 'always'):
            found = find_task(task.get(section), suffix)
            if found:
                return found
    return None


def recap_changed(output):
    match = re.search(r'localhost\s*:\s*ok=\d+\s+changed=(\d+)', output)
    if not match:
        raise AssertionError('no PLAY RECAP in ansible output:\n' + output)
    return int(match.group(1))


class RetainedReinstallConvergenceTests(unittest.TestCase):
    def changed(self, filename, suffix, stdout):
        """changed count of the real task's changed_when over this exact stdout."""
        task = find_task(yaml.safe_load((REPO / filename).read_text()), suffix)
        self.assertIsNotNone(task, suffix)
        self.assertNotEqual(str(task['changed_when']).strip(), 'true', 'literal changed_when: true is the defect')
        register = task['register']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'output.txt').write_text(stdout)
            play = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False, 'tasks': [{
                'name': 'real changed_when over captured output',
                'ansible.builtin.command': {'argv': ['cat', str(root / 'output.txt')]},
                'register': register, 'changed_when': task['changed_when']}]}]
            (root / 'play.yml').write_text(yaml.safe_dump(play))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(root / 'play.yml')],
                                    capture_output=True, text=True, timeout=120,
                                    env=dict(__import__('os').environ, ANSIBLE_LOCAL_TEMP=str(root / 'local'),
                                             ANSIBLE_REMOTE_TMP=str(root / 'remote'), PYTHONDONTWRITEBYTECODE='1'))
            self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
            return recap_changed(result.stdout)

    APT = ('playbooks/apply/tasks/apt-package-install.yml', 'force only the retained owned recovery package')
    RPM = ('playbooks/apply/tasks/wazuh-agent-recover.yml', 'Reinstall the retained signed old RPM agent')

    def test_apt_reinstall_reports_changed_only_when_apt_did_something(self):
        # Should NOT report changed: apt found nothing to do (real capture).
        self.assertEqual(self.changed(*self.APT, APT_NOTHING_TO_DO), 0)
        # Should report changed: a real reinstall, an upgrade, a downgrade summary,
        # output nobody recognises, and no output at all (fail safe).
        for name, text in (('reinstall', APT_REINSTALL), ('upgrade', APT_UPGRADE), ('downgrade', APT_DOWNGRADE_MODELED),
                           ('unfamiliar', 'E: something unexpected happened\n'), ('empty', '')):
            with self.subTest(case=name):
                self.assertEqual(self.changed(*self.APT, text), 1)

    def test_rpm_reinstall_reports_changed_only_when_dnf_did_something(self):
        self.assertEqual(self.changed(*self.RPM, DNF_NOTHING_TO_DO), 0)
        for name, text in (('reinstalled', DNF_REINSTALLED_MODELED), ('unfamiliar', 'Error: unexpected\n'), ('empty', '')):
            with self.subTest(case=name):
                self.assertEqual(self.changed(*self.RPM, text), 1)

    def test_expressions_are_not_literal_true_anywhere_in_the_recovery_path(self):
        for filename, suffix in (self.APT, self.RPM):
            task = find_task(yaml.safe_load((REPO / filename).read_text()), suffix)
            self.assertIn('register', task)
            self.assertNotIn(str(task['changed_when']).strip().lower(), ('true', 'yes', '1'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
