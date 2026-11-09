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
                'validate exact-version cache paths before any installer',
                'verify private recovery authority and artifact')


class ExactTaskTests(unittest.TestCase):
    def run_case(self, installed, versions=None, policy=None, stage=False, cache_error=False, held=False, packages=None,
                 cache_refusal=False, owner=False, owner_refusal=False, retained=False, force_recovery=False,
                 installer_failure=False, download_failure=False, verify_failure=False, source=None, policy_rc_d=None):
        """One harness for both contracts: A's exact-install flow and B's retained/owned/held flows.

        The package mutation is a harness module that receives exactly the parameters the real apt module would
        (omit included) and logs them; apt-cache/apt-get/the Wazuh coordinator are recording fakes.
        """
        with tempfile.TemporaryDirectory(prefix='pilot-apt-exact-') as temporary:
            root = Path(temporary)
            tasks = root / 'tasks'
            tasks.mkdir()
            for source_file in (REPO / 'playbooks/apply/tasks').glob('apt-*.yml'):
                shutil.copy2(source_file, tasks / source_file.name)
            filename = tasks / 'apt-package-install.yml'
            substituted = []

            def rewrite(items):
                for task in items:
                    if 'ansible.builtin.package_facts' in task:
                        task.pop('ansible.builtin.package_facts')
                        task['ansible.builtin.set_fact'] = {'ansible_facts': {'packages': installed}}
                    if 'ansible.builtin.apt' in task:
                        task['harness_apt'] = task.pop('ansible.builtin.apt')
                    command = task.get('ansible.builtin.command', {})
                    if command.get('argv', [''])[0] == '/usr/local/sbin/pilot-wazuh-transaction':
                        command['argv'][0] = 'harness-wazuh-policy'
                    if 'ansible.builtin.script' in task:
                        name = task['name']
                        if not name.endswith(SCRIPT_TASKS):
                            raise AssertionError('unexpected script task: ' + name)
                        substituted.append(name)
                        script = task.pop('ansible.builtin.script')['cmd']
                        if cache_refusal and 'validate exact-version' in name:
                            task['ansible.builtin.fail'] = {'msg': 'controlled cache boundary refusal'}
                        else:
                            kind = 'verify' if 'verify staged' in name else 'recovery' if 'recovery authority' in name else 'preflight'
                            task['ansible.builtin.command'] = {'argv': ['harness-script', kind, script]}
                    for block in ('block', 'rescue', 'always'):
                        if block in task:
                            rewrite(task[block])
            for name in ('apt-package-install.yml', 'apt-download-probe.yml'):
                path = tasks / name
                graph = yaml.safe_load(path.read_text())
                rewrite(graph)
                path.write_text(yaml.safe_dump(graph, sort_keys=False))
            self.assertTrue(substituted, 'the harness substituted no script task')
            tools = root / 'bin'
            tools.mkdir()
            log = root / 'commands.jsonl'
            library = root / 'library'
            library.mkdir()
            (library / 'harness_apt.py').write_text('''#!/usr/bin/python3
import json, os
from ansible.module_utils.basic import AnsibleModule
module = AnsibleModule(argument_spec=dict(
    name=dict(type='raw'), deb=dict(), state=dict(), policy_rc_d=dict(type='int'),
    allow_downgrade=dict(type='bool'), allow_change_held_packages=dict(type='bool'),
    force_apt_get=dict(type='bool'), install_recommends=dict(type='bool'), fail_on_autoremove=dict(type='bool')))
p = module.params
with open(os.environ['PILOT_APT_HARNESS_LOG'], 'a') as out:
    out.write(json.dumps(['apt-module', p['name'], p['state'], p['policy_rc_d'], p['deb'],
                          p['allow_change_held_packages'], p['allow_downgrade']]) + '\\n')
module.exit_json(changed=True)
''')
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
if name=='harness-script' and args[0]=='verify' and os.environ.get('PILOT_APT_HARNESS_VERIFY_FAILURE')=='1':
 print('exact staged Debian package verification failed',file=sys.stderr); sys.exit(1)
if name=='apt-get' and os.environ.get('PILOT_APT_HARNESS_DOWNLOAD_FAILURE')=='1':
 print('E: Unable to correct problems, you have held broken packages.',file=sys.stderr); sys.exit(100)
if name=='apt-get' and os.environ.get('PILOT_APT_HARNESS_INSTALL_FAILURE')=='1' and '--no-download' in args:
 print('controlled owned reinstall failure',file=sys.stderr); sys.exit(100)
if name=='apt-get' and os.environ.get('PILOT_APT_HARNESS_HELD')=='1' and '--allow-change-held-packages' not in args:
 print('E: Held packages were changed and -y was used without --allow-change-held-packages.',file=sys.stderr); sys.exit(100)
''')
            executable.chmod(0o755)
            for name in ('apt-cache', 'apt-get', 'harness-script', 'harness-wazuh-policy'):
                (tools / name).symlink_to(executable)
            inputs = {'pilot_apt_packages': packages or ['wazuh-agent'],
                      'pilot_apt_component': 'exact-version-harness',
                      'pilot_apt_policy': policy or ('tolerant' if stage else 'offline'),
                      'pilot_apt_stage_only': stage}
            if versions is not None:
                inputs['pilot_apt_versions'] = versions
            if source:
                inputs['pilot_apt_wazuh_source'] = source
            if policy_rc_d is not None:
                inputs['pilot_apt_policy_rc_d'] = policy_rc_d
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
            flags = {'CACHE_ERROR': cache_error, 'HELD': held, 'OWNER_REFUSAL': owner_refusal, 'INSTALL_FAILURE': installer_failure,
                     'DOWNLOAD_FAILURE': download_failure, 'VERIFY_FAILURE': verify_failure}
            environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                               ANSIBLE_LOCAL_TEMP=str(root / 'local'), ANSIBLE_REMOTE_TEMP=str(root / 'remote'),
                               ANSIBLE_CACHE_PLUGIN='memory', ANSIBLE_CONFIG=str(config),
                               ANSIBLE_LIBRARY=str(library), PILOT_APT_HARNESS_LOG=str(log),
                               **{'PILOT_APT_HARNESS_' + key: '1' if value else '0' for key, value in flags.items()})
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook)],
                                    cwd=root, env=environment, capture_output=True, text=True, timeout=90)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def installs(self, calls):
        """A's view of the package mutation: [module, names, state, policy_rc_d]."""
        return [call[:4] for call in calls if call[0] == 'apt-module']

    def records(self, calls):
        """Every parameter the apt module received: [module, names, state, policy_rc_d, deb, held, downgrade]."""
        return [call for call in calls if call[0] == 'apt-module']

    def test_plain_and_exact_present_are_noop(self):
        installed = {'wazuh-agent': [{'version': '4.14.9-1', 'arch': 'amd64'}]}
        for versions in (None, {'wazuh-agent': '4.14.9-1'}):
            result, calls = self.run_case(installed, versions)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(calls, [])

    def test_an_exact_request_replaces_an_installed_other_version_only_by_the_exact_spec_and_never_downgrades_unopted(self):
        # B contract (replaces A's "never changes an installed version"): a different installed version is
        # replaced only by installing exactly the requested package=version, and the module is told not to
        # downgrade or touch held packages unless the caller explicitly opted in.
        for installed_version, requested in (('4.14.1-1', '4.14.9-1'), ('4.14.9-1', '4.14.1-1'), ('4.14.9-1', '4.14.9-2')):
            result, calls = self.run_case({'wazuh-agent': [{'version': installed_version, 'arch': 'amd64'}]},
                                          {'wazuh-agent': requested}, policy='tolerant')
            self.assertEqual(result.returncode, 0, installed_version + ' -> ' + requested + result.stdout + result.stderr)
            records = self.records(calls)
            self.assertEqual(len(records), 1, installed_version + ' -> ' + requested)
            self.assertEqual(records[0][:4], ['apt-module', ['wazuh-agent=' + requested], 'present', None])
            self.assertEqual((records[0][5], records[0][6]), (False, False), 'no held-package change or downgrade without opt-in')
            self.assertFalse(any(call[1:2] == ['remove'] for call in calls))
        # The same version already installed is still a no-op.
        result, calls = self.run_case({'wazuh-agent': [{'version': '4.14.9-1', 'arch': 'amd64'}]},
                                      {'wazuh-agent': '4.14.9-1'}, policy='tolerant')
        self.assertEqual((result.returncode, self.installs(calls)), (0, []))

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
        self.assertFalse(any(call[0] == 'apt-get' for call in calls) or self.installs(calls))

    def test_exact_upgrade_uses_frozen_spec_in_query_and_install(self):
        installed = {'wazuh-agent': [{'version': '4.14.1-1', 'arch': 'amd64'}]}
        result, calls = self.run_case(installed, {'wazuh-agent': '4.14.9-1'})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(['apt-cache', 'show', 'wazuh-agent=4.14.9-1'], calls)
        self.assertEqual(self.installs(calls), [['apt-module', ['wazuh-agent=4.14.9-1'], 'present', None]])

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
        self.assertEqual(self.installs(calls), [['apt-module', ['wazuh-agent:i386=4.14.9-1'], 'present', None]])

    def test_partial_metadata_with_error_never_installs(self):
        result, calls = self.run_case({}, {'wazuh-agent': '4.14.9-1'}, cache_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('apt_cache_insufficient_offline', result.stdout)
        self.assertFalse(self.installs(calls))

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
        self.assertFalse(self.installs(calls))

    def test_held_staging_failure_is_not_install_authority(self):
        result, calls = self.run_case({}, {'wazuh-agent': '4.14.9-1'}, stage=True, held=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('staging failed', result.stdout)
        self.assertFalse(self.installs(calls))

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
            self.assertFalse(self.installs(calls))

    def test_retained_target_uses_deb_without_resolving_repository_again(self):
        for refused in (False, True):
            result, calls = self.run_case({'wazuh-agent': [{'version': '4.14.1-1', 'arch': 'amd64'}]},
                                          {'wazuh-agent': '4.14.9-1'}, owner=True, retained=True, owner_refusal=refused)
            self.assertEqual(result.returncode == 0, not refused, result.stdout + result.stderr)
            self.assertFalse(any(call[0] in ('apt-get', 'apt-cache') for call in calls))
            policy = next(call for call in calls if call[:2] == ['harness-wazuh-policy', 'agent-apt-plan'])
            self.assertIn('/private/wazuh-agent_4.14.9-1_amd64.deb', policy); self.assertNotIn('--stage', policy)
            installs = self.records(calls)
            self.assertEqual(bool(installs), not refused)
            if installs:
                # name is omitted for a retained .deb; deb, allow_change_held_packages, allow_downgrade follow.
                self.assertEqual(installs[0][1:2] + installs[0][4:], [None, '/private/wazuh-agent_4.14.9-1_amd64.deb', True, False])

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
            self.assertFalse(any(call[0] == 'apt-cache' for call in calls) or self.installs(calls))

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
