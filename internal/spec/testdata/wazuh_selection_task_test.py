"""Real Ansible package/config selection graph; native boundary is explicit.

All production dynamic includes/apply tags are retained, including shared APT,
upgrade, guard, recovery and alias resolution. Native package/signature/service
observations use the adjacent backend model; ordinary file modules and private
snapshot/tar restoration are real. This is not native VM acceptance.
"""
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
SOURCE = REPO / 'playbooks/apply'
s = importlib.util.spec_from_file_location('selection_library', SOURCE / 'files/wazuh-transaction.py')
W = importlib.util.module_from_spec(s); s.loader.exec_module(W)
mounts = W.MountTable; W.MountTable = lambda: mounts('1 0 8:1 / / rw - ext4 /dev/synthetic rw\n')

def metadata(path):
    data = path.stat()
    return {'bytes': path.read_bytes().hex(), 'mode': data.st_mode & 0o7777, 'uid': data.st_uid, 'gid': data.st_gid,
            'mtime_ns': data.st_mtime_ns, 'xattrs': W.ClosedCapture.attrs(path)}

class SelectionGraphTests(unittest.TestCase):
    def graph(self, family='Debian', installed='4.14.1-1', flags=(), prepared=True, upgrade=False,
              manager='4.14.1', managed=True, requested='', fail_verify=False, fault=None,
              foreign_source=False, foreign_policy=False, inherited=False, old_snapshot=False, fail_commit=False, recovery=False):
        with tempfile.TemporaryDirectory(prefix='i244-selection-') as temporary:
            root = Path(temporary); data = root / 'data'; data.mkdir()
            paths = {'config': str(data / 'ossec.conf'), 'hosts': str(data / 'hosts')}
            Path(paths['config']).write_text('<ossec_config>\n<address>prior-manager</address>\n</ossec_config>\n<!-- OPERATOR FIM SENTINEL -->\n<!-- BEGIN ANSIBLE MANAGED BLOCK (wazuh-fim-apply.yml FIM whodata) -->\n<ossec_config><syscheck><directories>/operator-sentinel</directories></syscheck></ossec_config>\n<!-- END ANSIBLE MANAGED BLOCK (wazuh-fim-apply.yml FIM whodata) -->\n')
            Path(paths['hosts']).write_text('127.0.0.1 localhost\n10.20.30.40 wazuh-manager\n# HOST SENTINEL\n')
            keys = data / 'client.keys'; keys.write_text('001 localhost any SYNTHETIC_KEY\n')
            for value in paths.values():
                path = Path(value); path.chmod(0o640); os.setxattr(path, 'user.issue244', b'original ACL/xattr sentinel')
            ledger = root / 'ledger'; events_file = root / 'events.jsonl'; state_file = root / 'state.json'
            state = {'installed': installed, 'protected': bool(installed), 'protected_version': installed,
                     'key': prepared, 'repo': 'foreign' if foreign_source else 'official' if prepared else '',
                     'foreign_policy': foreign_policy, 'staged': [],
                     'services': {'wazuh-agent': {'active': bool(installed), 'enabled': 'enabled', 'generation': 40},
                                  'auditd': {'active': True, 'enabled': 'enabled', 'generation': 50}}}
            state_file.write_text(json.dumps(state)); actor = W.HostWriter(ledger)
            if recovery:
                actor.claim('9' * 32, 'agent')
                transaction = W.Transaction('agent', root=ledger)
                item = transaction.begin('9' * 32, {'installed': '4.14.1-1', 'package': '4.14.9-1', 'manager_host': 'localhost',
                                                   'previous_protected': True, 'original': {key: Path(value).read_text() for key, value in paths.items()}})
                transaction.write(item, 'installing')
                for value in paths.values(): Path(value).write_text('CHANGED UPGRADE DATA\n')
            if old_snapshot:
                actor.claim('9' * 32, 'agent')
                snapshot = W.ConfigSnapshots('9' * 32, 'f' * 32, root=ledger, paths=paths)
                snapshot.save('config', W.ConfigSnapshots.FILES['config'])
                Path(paths['config']).write_text('PREVIOUS OPERATION PARTIAL CONFIG\n')
            before = {name: metadata(Path(value)) for name, value in paths.items()}
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'library': str(SOURCE / 'files/wazuh-transaction.py'), 'root': str(ledger),
                                             'state': str(state_file), 'events': str(events_file), 'paths': paths,
                                             'manager': manager, 'fail_verify': fail_verify, 'fail_commit': fail_commit,
                                             'fault_resource': fault[0] if fault else ''}))
            worker = REPO / 'internal/spec/testdata/wazuh_selection_backend.py'
            tasks = root / 'tasks'; tasks.mkdir()
            for pattern in ('apt-*.yml', 'wazuh-agent-*.yml', 'resolve-hosts-alias-target.yml'):
                for source in (SOURCE / 'tasks').glob(pattern): shutil.copy2(source, tasks / source.name)
            play = yaml.safe_load((SOURCE / 'wazuh-fim-apply.yml').read_text())[0]
            play.update(connection='local', become=False, gather_facts=False)
            play['vars'].update(target_group='all', ansible_os_family=family, ansible_architecture='x86_64',
                                ansible_distribution='Ubuntu' if family == 'Debian' else 'AlmaLinux',
                                ansible_distribution_version='24.04' if family == 'Debian' else '9.8',
                                wazuh_ossec_conf=paths['config'], wazuh_client_keys=str(keys), wazuh_upgrade=upgrade)
            if managed: play['vars'].update(wazuh_manager_host='localhost', wazuh_manager_inventory_host='localhost')
            if requested: play['vars']['wazuh_version'] = requested
            if old_snapshot: play['vars'].update(wazuh_writer_resume_owner='9' * 32, wazuh_confirm_previous_operation_stopped=True)
            if recovery:
                play['vars'].update(wazuh_writer_resume_owner='9' * 32, wazuh_confirm_previous_operation_stopped=True,
                                    wazuh_recovery_owner='9' * 32)
            packages = {}
            if installed: packages['wazuh-agent'] = [{'version': installed, 'arch': 'amd64'}]
            if prepared: packages['auditd'] = [{'version': '1', 'arch': 'amd64'}]
            def replace(task, action, extra=None, payload=None):
                for key in list(task):
                    if '.' in key: del task[key]
                argv = ['python3', str(worker), str(settings), action]
                if extra: argv += extra
                if payload is not None:
                    task.setdefault('vars', {})['_wv_native_payload'] = payload
                    argv += ['--payload', '{{ _wv_native_payload | to_json }}']
                task['ansible.builtin.command'] = {'argv': argv}
                task.setdefault('changed_when', False)
                if 'until' in task: task['until'] = task['register'] + ' is succeeded'
            def rewrite(items):
                for task in items:
                    for field in ('block', 'rescue', 'always'):
                        if field in task: rewrite(task[field])
                    if 'ansible.builtin.include_tasks' in task:
                        include = task['ansible.builtin.include_tasks']
                        name = include if isinstance(include, str) else include['file']
                        if isinstance(include, str): task['ansible.builtin.include_tasks'] = str(tasks / Path(name).name)
                        else: include['file'] = str(tasks / Path(name).name)
                    elif 'ansible.builtin.script' in task:
                        script = task['ansible.builtin.script']['cmd']
                        if 'wazuh-transaction.py' in script:
                            tail = script.split('wazuh-transaction.py', 1)[1]
                            del task['ansible.builtin.script']
                            task['ansible.builtin.command'] = {'cmd': 'python3 ' + str(worker) + ' ' + str(settings) + ' ' + tail}
                        elif '--cache-preflight' in script:
                            replace(task, 'metadata')
                        else:
                            replace(task, 'artifact-proof', ['--version-map', '{{ _pilot_apt_versions | default({}) | to_json }}'])
                    elif 'ansible.builtin.package_facts' in task:
                        del task['ansible.builtin.package_facts']; task['ansible.builtin.set_fact'] = {'ansible_facts': {'packages': packages}}
                    elif 'ansible.builtin.command' in task:
                        command = task['ansible.builtin.command']
                        if isinstance(command, dict) and command.get('argv', [''])[0] == '/usr/local/sbin/pilot-wazuh-transaction':
                            command['argv'] = ['python3', str(worker), str(settings)] + command['argv'][1:]
                        elif task['name'].startswith('Allocate an independent owner'): pass
                        elif task.get('register') == 'hosts_alias_dns_lookup': pass
                        else: replace(task, 'native-probe', payload=command if isinstance(command, dict) else {'argv': []})
                    elif 'ansible.builtin.apt' in task:
                        replace(task, 'package-install', ['--packages', '{{ pilot_apt_packages | to_json }}'])
                    elif 'ansible.builtin.dnf' in task:
                        params = task['ansible.builtin.dnf']; replace(task, 'package-install', ['--packages', '{{ _wv_native_payload.name | to_json }}'], payload=params)
                    elif 'ansible.builtin.systemd' in task: replace(task, 'service-module', payload=task['ansible.builtin.systemd'])
                    elif 'ansible.builtin.shell' in task: replace(task, 'source', ['--family', family], {'kind': 'key'})
                    elif 'ansible.builtin.yum_repository' in task: replace(task, 'source', ['--family', family], {'kind': 'repo'})
                    elif 'ansible.builtin.copy' in task:
                        params = task['ansible.builtin.copy']; dest = params.get('dest', '')
                        if dest == '/etc/apt/sources.list.d/wazuh.list': replace(task, 'source', ['--family', family], {'kind': 'repo'})
                        else: replace(task, 'metadata')
                    elif 'ansible.builtin.file' in task: replace(task, 'metadata')
                    elif 'ansible.builtin.stat' in task: task['ansible.builtin.stat']['path'] = str(keys)
                    elif 'ansible.builtin.lineinfile' in task and task['ansible.builtin.lineinfile'].get('path') == '/etc/hosts':
                        task['ansible.builtin.lineinfile']['path'] = paths['hosts']
                    # The actual selected config modules remain real except for
                    # explicit before/partial failure injection at their boundary.
                    if fault:
                        module = task.get('ansible.builtin.blockinfile') or task.get('ansible.builtin.lineinfile')
                        if module and module.get('path') in (paths['hosts'] if fault[0] == 'hosts' else '{{ wazuh_ossec_conf }}',):
                            replace(task, 'fault-' + fault[1]); task['changed_when'] = False
            rewrite(play['pre_tasks']); rewrite(play['tasks'])
            for filename in tasks.glob('*.yml'):
                content = yaml.safe_load(filename.read_text()); rewrite(content); filename.write_text(yaml.safe_dump(content, sort_keys=False))
            filename = root / 'play.yml'; filename.write_text(yaml.safe_dump([play], sort_keys=False))
            if inherited:
                wrapper = root / 'wrapper.yml'; wrapper.write_text(yaml.safe_dump([{'ansible.builtin.import_playbook': 'play.yml', 'tags': ['wazuh-fim']}]))
                filename = wrapper
            config = root / 'ansible.cfg'; config.write_text('[defaults]\nfact_caching=memory\nretry_files_enabled=false\n')
            env = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_LOCAL_TEMP=str(root / 'local'), ANSIBLE_REMOTE_TEMP=str(root / 'remote'), ANSIBLE_CACHE_PLUGIN='memory')
            run = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(filename), *flags], cwd=root, env=env, capture_output=True, text=True, timeout=120)
            events = [json.loads(line) for line in events_file.read_text().splitlines()] if events_file.exists() else []
            state = json.loads(state_file.read_text()); state['ownership'] = actor.inspect()
            state['before'] = before; state['after'] = {name: metadata(Path(value)) for name, value in paths.items()}
            return run, events, state

    def assert_ok(self, result, events, state):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIsNone(state['ownership']['writer'])
        self.assertEqual(state['ownership']['journals'], [])

    def test_fresh_package_family_full_C1_C2_and_prepared_foreign_source_both_backends(self):
        for family in ('Debian', 'RedHat'):
            for tags, prepared, foreign in ((None, False, False), ('C1', False, False), ('C2', False, False), ('C2', True, True)):
                with self.subTest(family=family, tags=tags, prepared=prepared, foreign=foreign):
                    result, events, state = self.graph(family, '', flags=('--tags', tags) if tags else (), prepared=prepared, foreign_source=foreign)
                    self.assert_ok(result, events, state)
                    self.assertEqual(state['installed'], '4.14.1-1'); self.assertTrue(state['protected'])
                    actions = [e['action'] for e in events]
                    self.assertLess(actions.index('agent-check'), actions.index('install-agent'))
                    self.assertLess(actions.index('artifact-provenance'), actions.index('install-agent'))
                    self.assertLess(actions.index('install-agent'), actions.index('protected'))
                    self.assertLess(actions.index('protected'), actions.index('writer-release'))
                    if tags: self.assertNotIn('agent-verify', actions, 'package proof must not require C10 active service')

    def test_compatible_family_retains_package_and_C10_is_observer_both_backends(self):
        for family in ('Debian', 'RedHat'):
            for tags in (None, 'C1', 'C2', 'C10'):
                with self.subTest(family=family, tags=tags):
                    result, events, state = self.graph(family, flags=('--tags', tags) if tags else ())
                    self.assert_ok(result, events, state)
                    actions = [e['action'] for e in events]
                    self.assertNotIn('install-agent', actions); self.assertNotIn('agent-reserve', actions)
                    self.assertEqual('protected' in actions, tags != 'C10')
                    if tags == 'C10': self.assertEqual(state['before'], state['after'])

    def test_C2_refusals_precede_package_guard_reservation_with_exact_reasons(self):
        cases = [dict(installed='4.14.9-1', manager='4.14.1', reason='installed Wazuh agent is newer'),
                 dict(installed='', requested='4.14.9', manager='4.14.1', reason='requested Wazuh agent is newer'),
                 dict(requested='4.14.9', manager='4.14.9', managed=False, upgrade=True, reason='requires an observed manager'),
                 dict(requested='4.14.9', manager='4.14.9', reason='requires wazuh_upgrade=true'),
                 dict(foreign_policy=True, reason='foreign ownership')]
        for family in ('Debian', 'RedHat'):
            for case in cases:
                with self.subTest(family=family, case=case):
                    inputs = dict(case); reason = inputs.pop('reason')
                    result, events, state = self.graph(family, flags=('--tags', 'C2'), **inputs)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(any(reason in event.get('reason', '') for event in events), events)
                    self.assertFalse(any(e['action'] in ('install-agent', 'protected', 'agent-reserve') for e in events))
                    self.assertIsNone(state['ownership']['writer'])

    def test_upgrade_finalizes_when_optional_rows_are_skipped(self):
        for family in ('Debian', 'RedHat'):
            for flags in (('--tags', 'C1'), ('--tags', 'C2'), ('--skip-tags', 'C10'), ('--skip-tags', 'C7')):
                with self.subTest(family=family, flags=flags):
                    result, events, state = self.graph(family, flags=flags, manager='4.14.9', requested='4.14.9', upgrade=True)
                    actions = [e['action'] for e in events]
                    self.assertIn('agent-commit', actions, 'reserved package family must select its commit proof')
                    self.assert_ok(result, events, state)
                    self.assertTrue(state['protected']); self.assertEqual(state['installed'], '4.14.9-1')
                    self.assertLess(actions.index('agent-reserve'), actions.index('install-agent'))
                    self.assertLess(actions.index('protected'), actions.index('agent-commit'))

    def test_pure_failed_C10_and_resumed_old_snapshot_never_modify_domain_state(self):
        for old_snapshot in (False, True):
            result, events, state = self.graph(flags=('--tags', 'C10'), fail_verify=True, old_snapshot=old_snapshot)
            self.assertNotEqual(result.returncode, 0); self.assertEqual(state['before'], state['after'])
            self.assertFalse(any(e['action'] in ('install-agent', 'protected', 'agent-config-save', 'agent-config-restore', 'service') for e in events))
            self.assertEqual(state['services']['wazuh-agent']['generation'], 40)
            self.assertEqual(state['services']['auditd']['generation'], 50)
            self.assertIsNone(state['ownership']['writer'])

    def test_mixed_failure_restores_only_selected_files_and_metadata(self):
        for tags, resource in (('C5,C10', 'config'), ('C7,C10', 'hosts')):
            for fault in (None, (resource, 'before'), (resource, 'partial')):
                with self.subTest(tags=tags, fault=fault):
                    result, events, state = self.graph(flags=('--tags', tags), fail_verify=not fault, fault=fault)
                    self.assertNotEqual(result.returncode, 0); self.assertEqual(state['before'], state['after'])
                    restored = next(e for e in events if e['action'] == 'ordinary-restored')
                    self.assertEqual(restored['restored'], [] if fault and fault[1] == 'before' else [resource])
                    self.assertEqual(restored['services'], [])
                    self.assertFalse(any(e['action'] == 'service' for e in events))
                    self.assertIsNone(state['ownership']['writer'])

    def test_selected_service_failure_restores_availability_without_touching_audit_identity(self):
        result, events, state = self.graph(flags=('--tags', 'C3,C5,C10'), fail_verify=True)
        self.assertNotEqual(result.returncode, 0); self.assertEqual(state['before'], state['after'])
        self.assertTrue(state['services']['wazuh-agent']['active']); self.assertEqual(state['services']['wazuh-agent']['enabled'], 'enabled')
        self.assertEqual(state['services']['auditd']['generation'], 50)

    def test_skip_family_and_check_mode_have_no_unmatched_package_mutator(self):
        for family in ('Debian', 'RedHat'):
            for flags in (('--tags', 'C2', '--skip-tags', 'C1'), ('--tags', 'C1', '--skip-tags', 'C2'), ('--tags', 'C10'), ('--tags', 'C2', '--check'), ('--tags', 'C10', '--check')):
                with self.subTest(family=family, flags=flags):
                    result, events, state = self.graph(family, '', flags=flags, prepared=False)
                    self.assertEqual(result.returncode == 0, '--check' in flags, result.stdout + result.stderr)
                    self.assertFalse(any(e['action'] in ('install-agent', 'protected', 'agent-reserve', 'agent-verify') for e in events))
                    self.assertIsNone(state['ownership']['writer'])

    def test_component_inherited_selection_and_owned_recovery_keep_nested_graph(self):
        result, events, state = self.graph(installed='', flags=('--tags', 'wazuh-fim'), inherited=True)
        self.assert_ok(result, events, state); self.assertTrue(state['protected'])
        for family in ('Debian', 'RedHat'):
            result, events, state = self.graph(family, flags=('--tags', 'C2'), manager='4.14.9', requested='4.14.9', upgrade=True, fail_commit=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(any(e['action'] == 'agent-recovery-commit' for e in events), events)
            self.assertEqual(state['installed'], '4.14.1-1'); self.assertTrue(state['protected'])
            self.assertIsNone(state['ownership']['writer']); self.assertEqual(state['ownership']['journals'], [])

    def test_explicit_recovery_runs_complete_always_include_under_C10_selector(self):
        for family in ('Debian', 'RedHat'):
            with self.subTest(family=family):
                result, events, state = self.graph(family, installed='4.14.9-1', manager='4.14.9', recovery=True, flags=('--tags', 'C10'))
                self.assert_ok(result, events, state)
                actions = [event['action'] for event in events]
                self.assertEqual(actions[0], 'writer-resume'); self.assertIn('agent-recovery-commit', actions)
                self.assertNotIn('agent-protect', actions); self.assertNotIn('agent-check', actions)
                self.assertEqual(state['installed'], '4.14.1-1'); self.assertTrue(state['protected'])
                self.assertIn('OPERATOR FIM SENTINEL', bytes.fromhex(state['after']['config']['bytes']).decode())

if __name__ == '__main__': unittest.main(verbosity=2)
