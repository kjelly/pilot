"""Run the production APT selection/Jinja/include graph in real Ansible.

Only package_facts, the final package mutation and the separately tested native
artifact/cache path verifier tasks are substituted. Fake apt-cache/apt-get record actual
argv. This harness does not claim native APT, signatures or VM installation.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import yaml


REPO = Path(__file__).resolve().parents[3]
FILES = REPO / 'playbooks/apply/files'
spec = importlib.util.spec_from_file_location('apt_exact_stage', FILES / 'apt-exact-stage.py')
apt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apt)

# Kept in lockstep with the shipped task text: the harness rewrites these tasks,
# and a rename must fail loudly instead of silently un-substituting a task.
SCRIPT_TASKS = ('verify staged exact package identity and metadata SHA256',
                'validate exact-version output paths before downloading',
                'validate exact-version cache paths before any installer')


class ExactTaskTests(unittest.TestCase):
    def run_case(self, installed, versions=None, stage=False, cache_error=False, held=False, packages=None, cache_refusal=False,
                 owner=False, owner_refusal=False, retained=False, force_recovery=False, installer_failure=False):
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
                        params = task.pop('ansible.builtin.apt')
                        task['ansible.builtin.command'] = {'argv': ['apt-harness-install', '{{ _pilot_apt_missing | to_json }}'] +
                            ([params['deb'], params['allow_change_held_packages'], params['allow_downgrade']] if retained else [])}
                    command = task.get('ansible.builtin.command', {})
                    if command.get('argv', [''])[0] == '/usr/local/sbin/pilot-wazuh-transaction':
                        command['argv'][0] = 'harness-wazuh-policy'
                    if task['name'].endswith(('verify staged exact package identity and metadata SHA256',
                                              'validate exact-version output paths before downloading',
                                              'validate exact-version cache paths before any installer',
                                              'verify private recovery authority and artifact')):
                        task.pop('ansible.builtin.script')
                        if cache_refusal and 'validate exact-version' in task['name']:
                            task['ansible.builtin.fail'] = {'msg': 'controlled cache boundary refusal'}
                        else:
                            task['ansible.builtin.debug'] = {'msg': 'native artifact/cache validation has an independent behavioral test'}
                    for block in ('block', 'rescue', 'always'):
                        if block in task:
                            rewrite(task[block])
            rewrite(graph)
            filename.write_text(yaml.safe_dump(graph, sort_keys=False))
            download = tasks / 'apt-download-probe.yml'
            download_graph = yaml.safe_load(download.read_text())
            rewrite(download_graph)
            download.write_text(yaml.safe_dump(download_graph, sort_keys=False))
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
if name=='harness-wazuh-policy' and os.environ.get('PILOT_APT_HARNESS_OWNER_REFUSAL')=='1':
 print('controlled wrong-owner/phase refusal',file=sys.stderr); sys.exit(1)
if name=='apt-get' and os.environ.get('PILOT_APT_HARNESS_INSTALL_FAILURE')=='1' and '--no-download' in args:
 print('controlled owned reinstall failure',file=sys.stderr); sys.exit(100)
if name=='apt-get' and os.environ.get('PILOT_APT_HARNESS_HELD')=='1' and '--allow-change-held-packages' not in args:
 print('E: Held packages were changed and -y was used without --allow-change-held-packages.',file=sys.stderr); sys.exit(100)
''')
            executable.chmod(0o755)
            for name in ('apt-cache', 'apt-get', 'apt-harness-install', 'harness-wazuh-policy'):
                (tools / name).symlink_to(executable)
            inputs = {'pilot_apt_packages': packages or ['wazuh-agent'],
                      'pilot_apt_component': 'exact-version-harness',
                      'pilot_apt_policy': 'tolerant' if stage else 'offline',
                      'pilot_apt_stage_only': stage}
            if versions is not None:
                inputs['pilot_apt_versions'] = versions
            if owner:
                inputs['pilot_apt_wazuh_owner'] = 'd' * 32
            if retained:
                inputs['pilot_apt_recovery_artifact' if force_recovery else 'pilot_apt_installation_artifact'] = '/private/wazuh-agent_' + versions['wazuh-agent'] + '_amd64.deb'
            if force_recovery:
                inputs.update(pilot_apt_reinstall_retained=True, pilot_apt_allow_downgrade=True, pilot_apt_policy_rc_d=101)
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
            environment['PILOT_APT_HARNESS_OWNER_REFUSAL'] = '1' if owner_refusal else '0'
            environment['PILOT_APT_HARNESS_INSTALL_FAILURE'] = '1' if installer_failure else '0'
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook)],
                                    cwd=root, env=environment, capture_output=True, text=True, timeout=90)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def installs(self, calls):
        return [call for call in calls if call[0] == 'apt-module']

    def test_plain_and_exact_present_are_noop(self):
        installed = {'wazuh-agent': [{'version': '4.14.9-1', 'arch': 'amd64'}]}
        for versions in (None, {'wazuh-agent': '4.14.9-1'}):
            result, calls = self.run_case(installed, versions)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(calls, [])

    def test_an_exact_request_never_changes_an_installed_other_version(self):
        for installed_version, requested in (('4.14.1-1', '4.14.9-1'), ('4.14.9-1', '4.14.1-1'), ('4.14.9-1', '4.14.9-2')):
            result, calls = self.run_case({'wazuh-agent': [{'version': installed_version, 'arch': 'amd64'}]},
                                          {'wazuh-agent': requested}, policy='tolerant')
            self.assertNotEqual(result.returncode, 0, installed_version + ' -> ' + requested)
            self.assertIn('never changes an installed package version', result.stdout)
            self.assertEqual(calls, [], 'a version change must fail before any query, download or install')

    def test_a_plain_install_keeps_the_unmodified_framework_behavior(self):
        result, calls = self.run_case({}, None, policy='tolerant', packages=['auditd'])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([call[:2] for call in calls if call[0] == 'apt-cache'], [['apt-cache', 'policy']])
        probes = [call for call in calls if call[0] == 'apt-get']
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0][-3:], ['install', '--download-only', 'auditd'])
        self.assertIn('APT::Get::AllowUnauthenticated=false', probes[0])
        self.assertEqual(self.installs(calls), [['apt-module', ['auditd'], 'present', None]])
        self.assertFalse(any(call[0] == 'harness-script' for call in calls), 'no exact verification for an unversioned install')

    def test_a_fresh_exact_install_uses_the_frozen_spec_in_query_and_install(self):
        result, calls = self.run_case({}, {'wazuh-agent': '4.14.9-1'})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(['apt-cache', 'show', 'wazuh-agent=4.14.9-1'], calls)
        self.assertNotIn(['apt-cache', 'policy', 'wazuh-agent=4.14.9-1'], calls)
        self.assertEqual(self.installs(calls), [['apt-module', ['wazuh-agent=4.14.9-1'], 'present', None]])

    def test_the_service_start_policy_reaches_only_the_install(self):
        result, calls = self.run_case({}, {'wazuh-agent': '4.14.9-1'}, policy_rc_d=101)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.installs(calls), [['apt-module', ['wazuh-agent=4.14.9-1'], 'present', 101]])

    def test_exact_staging_is_validated_downloaded_verified_and_only_then_installed(self):
        source = '/etc/apt/sources.list.d/wazuh.list'
        result, calls = self.run_case({}, {'wazuh-agent': '4.14.9-1'}, policy='tolerant', source=source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        order = [call[0] + (':' + call[1] if call[0] == 'harness-script' else '') for call in calls]
        self.assertEqual(order, ['harness-script:preflight', 'apt-cache', 'harness-script:preflight', 'apt-get',
                                 'harness-script:verify', 'apt-module'])
        download = calls[order.index('apt-get')]
        self.assertEqual(download[-3:], ['install', '--download-only', 'wazuh-agent=4.14.9-1'])
        self.assertIn('APT::Get::AllowUnauthenticated=false', download)
        verify = calls[order.index('harness-script:verify')][2]
        self.assertIn('{"wazuh-agent": "4.14.9-1"}', verify)
        self.assertIn('--wazuh-source ' + source, verify, 'the payload must be bound to the declared official source')
        self.assertEqual(calls[order.index('harness-script:preflight')][2], '../files/apt-exact-stage.py --cache-preflight')

    def test_without_a_declared_source_no_source_binding_is_requested(self):
        result, calls = self.run_case({}, {'wazuh-agent': '4.14.9-1'}, policy='tolerant')
        verify = next(call for call in calls if call[:2] == ['harness-script', 'verify'])[2]
        self.assertNotIn('--wazuh-source', verify)

    def test_cache_scope_failure_precedes_any_exact_download_or_install(self):
        result, calls = self.run_case({'wazuh-agent': [{'version': '4.14.1-1', 'arch': 'amd64'}]},
                                      {'wazuh-agent': '4.14.9-1'}, stage=True, cache_refusal=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('controlled cache boundary refusal', result.stdout)
        self.assertFalse(any(call[0] in ('apt-get', 'apt-harness-install') for call in calls))

    def test_exact_upgrade_uses_frozen_spec_in_query_and_install(self):
        installed = {'wazuh-agent': [{'version': '4.14.1-1', 'arch': 'amd64'}]}
        result, calls = self.run_case(installed, {'wazuh-agent': '4.14.9-1'})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(['apt-cache', 'show', 'wazuh-agent=4.14.9-1'], calls)
        self.assertIn(['apt-harness-install', '["wazuh-agent=4.14.9-1"]'], calls)

    def test_a_failed_download_never_becomes_install_authority(self):
        result, calls = self.run_case({}, {'wazuh-agent': '4.14.9-1'}, policy='tolerant', download_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('staging failed; no package mutation was attempted', result.stdout)
        self.assertFalse(self.installs(calls))
        self.assertFalse(any(call[:2] == ['harness-script', 'verify'] for call in calls), 'nothing was staged to verify')

    def test_a_failed_identity_or_checksum_verification_never_installs(self):
        result, calls = self.run_case({}, {'wazuh-agent': '4.14.9-1'}, policy='tolerant', verify_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(call[:2] == ['harness-script', 'verify'] for call in calls))
        self.assertFalse(self.installs(calls))

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

    def test_owned_held_stage_authorizes_only_exact_version_and_refusal_precedes_download(self):
        for refused in (False, True):
            result, calls = self.run_case({'wazuh-agent': [{'version': '4.14.1-1', 'arch': 'amd64'}]},
                                          {'wazuh-agent': '4.14.9-1'}, stage=True, held=True,
                                          owner=True, owner_refusal=refused)
            self.assertEqual(result.returncode == 0, not refused, result.stdout + result.stderr)
            policy = [call for call in calls if call[:2] == ['harness-wazuh-policy', 'agent-apt-plan']]
            self.assertEqual(len(policy), 1)
            self.assertIn('--stage', policy[0]); self.assertIn('4.14.9-1', policy[0])
            downloads = [call for call in calls if call[0] == 'apt-get']
            self.assertEqual(bool(downloads), not refused)
            if downloads: self.assertIn('--allow-change-held-packages', downloads[0])
            self.assertFalse(any(call[0] == 'apt-harness-install' for call in calls))

    def test_retained_target_uses_deb_without_resolving_repository_again(self):
        for refused in (False, True):
            result, calls = self.run_case({'wazuh-agent': [{'version': '4.14.1-1', 'arch': 'amd64'}]},
                                          {'wazuh-agent': '4.14.9-1'}, owner=True, retained=True, owner_refusal=refused)
            self.assertEqual(result.returncode == 0, not refused, result.stdout + result.stderr)
            self.assertFalse(any(call[0] in ('apt-get', 'apt-cache') for call in calls))
            policy = next(call for call in calls if call[:2] == ['harness-wazuh-policy', 'agent-apt-plan'])
            self.assertIn('/private/wazuh-agent_4.14.9-1_amd64.deb', policy); self.assertNotIn('--stage', policy)
            installs = [call for call in calls if call[0] == 'apt-harness-install']
            self.assertEqual(bool(installs), not refused)
            if installs:
                self.assertEqual(installs[0][2:], ['/private/wazuh-agent_4.14.9-1_amd64.deb', 'True', 'False'])

    def test_same_version_recovery_reinstalls_and_always_restores_owned_policy_hook(self):
        for failed in (False, True):
            result, calls = self.run_case({'wazuh-agent': [{'version': '4.14.1-1', 'arch': 'amd64'}]},
                                          {'wazuh-agent': '4.14.1-1'}, owner=True, retained=True,
                                          force_recovery=True, installer_failure=failed)
            self.assertEqual(result.returncode == 0, not failed, result.stdout + result.stderr)
            installs = [call for call in calls if call[0] == 'apt-get']
            self.assertEqual(len(installs), 1)
            for token in ('--no-download', '--reinstall', '--allow-change-held-packages', '--allow-downgrades',
                          'APT::Get::AllowUnauthenticated=false', '/private/wazuh-agent_4.14.1-1_amd64.deb', 'Dir::Cache::archives=/private/'):
                self.assertIn(token, installs[0])
            actions = [call[1] for call in calls if call[0] == 'harness-wazuh-policy']
            self.assertEqual(actions, ['agent-apt-plan', 'agent-hook-prepare', 'agent-hook-cleanup'])
            self.assertEqual(calls[-1][1], 'agent-hook-cleanup', 'installer failure must not strand global policy')
            self.assertFalse(any(call[0] in ('apt-cache', 'apt-harness-install') for call in calls))

    def test_invalid_exact_requirements_are_refused_before_any_command(self):
        for versions in ({'wazuh-agent': 'latest'}, {'wazuh-agent': '4.14.9-1; rm -rf /'}, {'wazuh agent': '4.14.9-1'},
                         {'other-package': '1'}):
            result, calls = self.run_case({}, versions, policy='tolerant')
            self.assertNotEqual(result.returncode, 0, str(versions))
            self.assertEqual(calls, [], str(versions))

    def test_the_included_script_path_exists_next_to_the_task_files(self):
        # The tasks name ../files/apt-exact-stage.py relative to tasks/: it must be a real file there.
        self.assertTrue((REPO / 'playbooks/apply/tasks/../files/apt-exact-stage.py').is_file())


class ExactArtifactTests(unittest.TestCase):
    """The shipped verifier against modeled apt-cache/dpkg output."""

    def test_metadata_sha256_and_package_identity_are_both_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / 'wazuh-agent_4.14.9-1_amd64.deb'
            artifact.write_bytes(b'authenticated package bytes')
            checksum = hashlib.sha256(artifact.read_bytes()).hexdigest()
            original = apt.run
            identity = ['wazuh-agent', '4.14.9-1', 'amd64']
            conflicting_payload = False

            def command(argv):
                if argv[0] == 'dpkg':
                    return 'amd64\n'
                if argv[0] == 'apt-cache':
                    record = '\n'.join(['Package: wazuh-agent', 'Version: 4.14.9-1', 'Architecture: amd64',
                                        'Filename: pool/' + artifact.name, 'SHA256: ' + checksum])
                    return record + ('\n\n' + record.replace(checksum, 'a' * 64) if conflicting_payload else '')
                return '\n'.join(identity)
            apt.run = command
            try:
                self.assertEqual(apt.verify({'wazuh-agent': '4.14.9-1'}, root)[0]['sha256'], checksum)
                conflicting_payload = True
                with self.assertRaisesRegex(ValueError, 'ambiguous authenticated'):
                    apt.verify({'wazuh-agent': '4.14.9-1'}, root)
                conflicting_payload = False
                identity[1] = '4.14.10-1'
                with self.assertRaises(ValueError):
                    apt.verify({'wazuh-agent': '4.14.9-1'}, root)
                identity[1] = '4.14.9-1'
                artifact.write_bytes(b'tampered package bytes')
                with self.assertRaises(ValueError):
                    apt.verify({'wazuh-agent': '4.14.9-1'}, root)
                artifact.unlink()
                with self.assertRaises(ValueError):
                    apt.verify({'wazuh-agent': '4.14.9-1'}, root)
            finally:
                apt.run = original

    def test_the_cache_must_be_plain_and_alias_free(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'cache'
            root.mkdir(mode=0o755)
            self.assertEqual(apt.validate_cache(root), root)
            (root / 'good.deb').write_bytes(b'x')
            self.assertEqual(apt.validate_cache(root), root)
            outside = Path(temp) / 'outside.deb'
            outside.write_bytes(b'x')
            (root / 'alias.deb').symlink_to(outside)
            with self.assertRaises(ValueError):
                apt.validate_cache(root)
            (root / 'alias.deb').unlink()
            os.link(outside, root / 'hard.deb')
            with self.assertRaises(ValueError):
                apt.validate_cache(root)
            (root / 'hard.deb').unlink()
            root.chmod(0o777)
            try:
                with self.assertRaises(ValueError):
                    apt.validate_cache(root)
            finally:
                root.chmod(0o755)
            link = Path(temp) / 'link'
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                apt.validate_cache(link)

    def test_only_the_wazuh_agent_can_be_bound_to_the_official_source(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'wazuh.list'
            source.write_text('deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n')
            source.chmod(0o644)
            with self.assertRaises((ValueError, ImportError)):
                apt.verify_wazuh_source({'auditd': '1'}, str(source))
            for text in ('deb https://packages.wazuh.com/4.x/apt/ stable main\n',
                         'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://evil.example/4.x/apt/ stable main\n',
                         'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\ndeb http://evil/ x y\n'):
                source.write_text(text)
                with self.assertRaises((ValueError, ImportError)):
                    apt.verify_wazuh_source({'wazuh-agent': '4.14.9-1'}, str(source))


if __name__ == '__main__':
    unittest.main(verbosity=2)
