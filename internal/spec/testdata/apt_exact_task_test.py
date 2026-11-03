"""Run the production APT selection/Jinja/include graph in real Ansible.

Only package_facts, the final package mutation and the separately tested native
artifact-verifier task are substituted. Fake apt-cache/apt-get record actual
argv. This harness does not claim native APT, signatures or VM installation.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import yaml


REPO = Path(__file__).resolve().parents[3]


class ExactTaskTests(unittest.TestCase):
    def run_case(self, installed, versions=None, stage=False, cache_error=False, held=False, packages=None):
        with tempfile.TemporaryDirectory(prefix='pilot-apt-exact-') as temporary:
            root = Path(temporary)
            tasks = root / 'tasks'
            tasks.mkdir()
            for source in (REPO / 'playbooks/apply/tasks').glob('apt-*.yml'):
                shutil.copy2(source, tasks / source.name)
            filename = tasks / 'apt-package-install.yml'
            graph = yaml.safe_load(filename.read_text())
            def rewrite(items):
                for task in items:
                    if 'ansible.builtin.package_facts' in task:
                        task.pop('ansible.builtin.package_facts')
                        task['ansible.builtin.set_fact'] = {'ansible_facts': {'packages': installed}}
                    if 'ansible.builtin.apt' in task:
                        task.pop('ansible.builtin.apt')
                        task['ansible.builtin.command'] = {'argv': ['apt-harness-install', '{{ _pilot_apt_missing | to_json }}']}
                    if task['name'].endswith('verify staged exact package identity and metadata SHA256'):
                        task.pop('ansible.builtin.script')
                        task['ansible.builtin.debug'] = {'msg': 'native artifact validation has an independent behavioral test'}
                    for block in ('block', 'rescue', 'always'):
                        if block in task:
                            rewrite(task[block])
            rewrite(graph)
            filename.write_text(yaml.safe_dump(graph, sort_keys=False))
            tools = root / 'bin'
            tools.mkdir()
            log = root / 'commands.jsonl'
            executable = tools / 'native'
            executable.write_text('''#!/usr/bin/env python3
import json,os,sys
name=os.path.basename(sys.argv[0]); args=sys.argv[1:]
with open(os.environ['PILOT_APT_HARNESS_LOG'],'a') as out: out.write(json.dumps([name]+args)+'\\n')
if name=='apt-cache':
 if os.environ.get('PILOT_APT_HARNESS_CACHE_ERROR')=='1':
  print('Package: partial-metadata'); sys.exit(100)
 if args[0]=='show': print('Package: wazuh-agent\\nVersion: 4.14.9-1\\nArchitecture: amd64')
 else: print('wazuh-agent:\\n  Candidate: 4.14.9-1')
if name=='apt-get' and os.environ.get('PILOT_APT_HARNESS_HELD')=='1':
 print('E: Held packages were changed and -y was used without --allow-change-held-packages.',file=sys.stderr); sys.exit(100)
''')
            executable.chmod(0o755)
            for name in ('apt-cache', 'apt-get', 'apt-harness-install'):
                (tools / name).symlink_to(executable)
            inputs = {'pilot_apt_packages': packages or ['wazuh-agent'],
                      'pilot_apt_component': 'exact-version-harness',
                      'pilot_apt_policy': 'tolerant' if stage else 'offline',
                      'pilot_apt_stage_only': stage}
            if versions is not None:
                inputs['pilot_apt_versions'] = versions
            playbook = root / 'test.yml'
            playbook.write_text(yaml.safe_dump([{'hosts': 'localhost', 'connection': 'local',
                                               'gather_facts': False, 'vars': inputs,
                                               'tasks': [{'ansible.builtin.include_tasks': str(filename)}]}]))
            config = root / 'ansible.cfg'
            config.write_text('[defaults]\nfact_caching=memory\nretry_files_enabled=false\n')
            environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                               ANSIBLE_LOCAL_TEMP=str(root / 'local'), ANSIBLE_REMOTE_TEMP=str(root / 'remote'),
                               ANSIBLE_CACHE_PLUGIN='memory', ANSIBLE_CONFIG=str(config),
                               PILOT_APT_HARNESS_LOG=str(log),
                               PILOT_APT_HARNESS_CACHE_ERROR='1' if cache_error else '0',
                               PILOT_APT_HARNESS_HELD='1' if held else '0')
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook)],
                                    cwd=root, env=environment, capture_output=True, text=True, timeout=90)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def test_plain_and_exact_present_are_noop(self):
        installed = {'wazuh-agent': [{'version': '4.14.9-1', 'arch': 'amd64'}]}
        for versions in (None, {'wazuh-agent': '4.14.9-1'}):
            result, calls = self.run_case(installed, versions)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(calls, [])

    def test_exact_upgrade_uses_frozen_spec_in_query_and_install(self):
        installed = {'wazuh-agent': [{'version': '4.14.1-1', 'arch': 'amd64'}]}
        result, calls = self.run_case(installed, {'wazuh-agent': '4.14.9-1'})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(['apt-cache', 'show', 'wazuh-agent=4.14.9-1'], calls)
        self.assertIn(['apt-harness-install', '["wazuh-agent=4.14.9-1"]'], calls)

    def test_multiarch_satisfaction_is_architecture_specific(self):
        installed = {'wazuh-agent': [{'version': '4.14.9-1', 'arch': 'amd64'},
                                      {'version': '4.14.6-1', 'arch': 'i386'}]}
        result, calls = self.run_case(installed, {'wazuh-agent:amd64': '4.14.9-1'}, packages=['wazuh-agent:amd64'])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, [])
        result, calls = self.run_case(installed, {'wazuh-agent:i386': '4.14.9-1'}, packages=['wazuh-agent:i386'])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(['apt-harness-install', '["wazuh-agent:i386=4.14.9-1"]'], calls)

    def test_partial_metadata_with_error_never_installs(self):
        result, calls = self.run_case({}, {'wazuh-agent': '4.14.9-1'}, cache_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('apt_cache_insufficient_offline', result.stdout)
        self.assertFalse(any(call[0] == 'apt-harness-install' for call in calls))

    def test_stage_reinstalls_download_only_and_never_mutates(self):
        installed = {'wazuh-agent': [{'version': '4.14.9-1', 'arch': 'amd64'}]}
        result, calls = self.run_case(installed, {'wazuh-agent': '4.14.9-1'}, stage=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        downloads = [call for call in calls if call[0] == 'apt-get']
        self.assertEqual(len(downloads), 1)
        self.assertIn('--download-only', downloads[0])
        self.assertIn('--reinstall', downloads[0])
        self.assertIn('wazuh-agent=4.14.9-1', downloads[0])
        self.assertIn('APT::Get::AllowUnauthenticated=false', downloads[0])
        self.assertFalse(any(call[0] == 'apt-harness-install' for call in calls))

    def test_held_staging_failure_is_not_install_authority(self):
        result, calls = self.run_case({}, {'wazuh-agent': '4.14.9-1'}, stage=True, held=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('staging failed', result.stdout)
        self.assertFalse(any(call[0] == 'apt-harness-install' for call in calls))


if __name__ == '__main__':
    unittest.main(verbosity=2)
