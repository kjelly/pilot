"""Real Ansible package/config selection graph; native boundary is explicit.

All production dynamic includes/apply tags are retained, including shared APT,
upgrade, guard, recovery and alias resolution. Native package/signature/service
observations use the adjacent backend model; ordinary file modules and private
snapshot/tar restoration are real. This is not native VM acceptance.
"""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import tempfile
import unittest
import yaml

REPO = Path(__file__).resolve().parents[3]
SOURCE = REPO / 'playbooks/apply'
s = importlib.util.spec_from_file_location('selection_library', SOURCE / 'files/wazuh-transaction.py')
W = importlib.util.module_from_spec(s); s.loader.exec_module(W)
mounts = W.MountTable; W.MountTable = lambda: mounts('1 0 8:1 / / rw - ext4 /dev/synthetic rw\n')

OWN_BLOCK = '<!-- BEGIN ANSIBLE MANAGED BLOCK (wazuh-fim-apply.yml FIM whodata) -->'
# Effects that change the host: a refusal must never reach one. (The writer claim/release is bookkeeping under the
# host-wide owner and is asserted separately through the ownership state.)
MUTATORS = ('install-agent', 'protected', 'source-ready', 'install-prerequisite', 'service', 'install-coordinator',
            'artifact-provenance', 'agent-protect', 'agent-rpm-fresh')


def metadata(path):
    data = path.stat()
    return {'bytes': path.read_bytes().hex(), 'mode': data.st_mode & 0o7777, 'uid': data.st_uid, 'gid': data.st_gid,
            'mtime_ns': data.st_mtime_ns, 'xattrs': W.ClosedCapture.attrs(path)}

class SelectionGraphTests(unittest.TestCase):
    def graph(self, family='Debian', installed='4.14.1-1', flags=(), prepared=True, upgrade=False,
              manager='4.14.1', managed=True, requested='', fail_verify=False, fault=None,
              foreign_source=False, foreign_policy=False, inherited=False, old_snapshot=False, fail_commit=False, recovery=False,
              manager_error=False, enrollment_host='localhost', manager_address='127.0.0.1', preview_fresh_manager=False,
              extra_vars=None, protected=None, native_preference=None, drift_preference=False, real_guard=False,
              prior_block=True):
        with tempfile.TemporaryDirectory(prefix='i244-selection-') as temporary:
            root = Path(temporary); data = root / 'data'; data.mkdir()
            paths = {'config': str(data / 'ossec.conf'), 'hosts': str(data / 'hosts')}
            Path(paths['config']).write_text('<ossec_config>\n<address>prior-manager</address>\n</ossec_config>\n<!-- OPERATOR FIM SENTINEL -->\n' + (
                '<!-- BEGIN ANSIBLE MANAGED BLOCK (wazuh-fim-apply.yml FIM whodata) -->\n<ossec_config><syscheck><directories>/operator-sentinel</directories></syscheck></ossec_config>\n<!-- END ANSIBLE MANAGED BLOCK (wazuh-fim-apply.yml FIM whodata) -->\n' if prior_block else ''))
            Path(paths['hosts']).write_text('127.0.0.1 localhost\n' + ('10.20.30.40 wazuh-manager\n' if prior_block else '') + '# HOST SENTINEL\n')
            preference = root / 'pilot-wazuh-agent'
            if native_preference is not None:
                preference.write_text(native_preference); preference.chmod(0o644)
            keys = data / 'client.keys'; keys.write_text('001 localhost any SYNTHETIC_KEY\n')
            for value in paths.values():
                path = Path(value); path.chmod(0o640); os.setxattr(path, 'user.issue244', b'original ACL/xattr sentinel')
            ledger = root / 'ledger'; events_file = root / 'events.jsonl'; state_file = root / 'state.json'
            state = {'installed': installed, 'protected': bool(installed) if protected is None else protected, 'protected_version': installed,
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
                                             'preference': str(preference), 'manager_error': manager_error,
                                             'drift_preference': drift_preference, 'real_guard': real_guard,
                                             'fault_resource': fault[0] if fault else ''}))
            worker = REPO / 'internal/spec/testdata/wazuh_selection_backend.py'
            tasks = root / 'tasks'; tasks.mkdir()
            for pattern in ('apt-*.yml', 'wazuh-agent-*.yml', 'wazuh-endpoint-resolve.yml', 'resolve-hosts-alias-target.yml'):
                for source in (SOURCE / 'tasks').glob(pattern): shutil.copy2(source, tasks / source.name)
            (root/'files').mkdir();shutil.copy2(SOURCE/'files/wazuh-endpoint.py',root/'files/wazuh-endpoint.py')
            play = yaml.safe_load((SOURCE / 'wazuh-fim-apply.yml').read_text())[0]
            play.update(connection='local', become=False, gather_facts=False)
            play['vars'].update(target_group='all', ansible_os_family=family, ansible_architecture='x86_64',
                                ansible_distribution='Ubuntu' if family == 'Debian' else 'AlmaLinux',
                                ansible_distribution_version='24.04' if family == 'Debian' else '9.8',
                                wazuh_ossec_conf=paths['config'], wazuh_client_keys=str(keys), wazuh_upgrade=upgrade)
            if managed: play['vars'].update(wazuh_manager_host=enrollment_host, wazuh_manager_inventory_host='localhost')
            if requested: play['vars']['wazuh_version'] = requested
            play['vars'].update(extra_vars or {})
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
                        elif 'wazuh-endpoint.py' in script: pass
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
                        elif dest == '/etc/apt/preferences.d/pilot-wazuh-agent' and real_guard:
                            params['dest'] = str(preference)  # the real preference text lands where the real guard reads it
                            # The harness runs unprivileged: only ownership is dropped, content and mode stay real.
                            params.pop('owner', None); params.pop('group', None)
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
            inventory=root/'inventory.yml'
            host_vars = {'ansible_connection': 'local', 'ansible_host': manager_address}
            if preview_fresh_manager:
                host_vars.update(pilot_wazuh_manager_install_planned=True, pilot_wazuh_manager_preview_fresh=True)
            inventory.write_text(yaml.safe_dump({'all':{'hosts':{'localhost': host_vars},'children':
                {'wazuh-manager':{'hosts':{'localhost':{}}}} if managed else {}}}))
            run = subprocess.run(['ansible-playbook', '-i', str(inventory), str(filename), *flags], cwd=root, env=env, capture_output=True, text=True, timeout=120)
            events = [json.loads(line) for line in events_file.read_text().splitlines()] if events_file.exists() else []
            state = json.loads(state_file.read_text()); state['ownership'] = actor.inspect()
            state['before'] = before; state['after'] = {name: metadata(Path(value)) for name, value in paths.items()}
            state['config'] = Path(paths['config']).read_text(); state['hosts'] = Path(paths['hosts']).read_text()
            state['preference'] = preference.read_text() if preference.exists() else None
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
                    self.assertEqual('agent-protect' in actions, tags != 'C10')  # the call is selected; its effect is reported only when it changed the guard
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
        # A failure INSIDE the configuration block rolls back exactly the selected resource (and C10 never runs).
        for tags, resource in (('C5,C10', 'config'), ('C7,C10', 'hosts')):
            for fault in ((resource, 'before'), (resource, 'partial')):
                with self.subTest(tags=tags, fault=fault):
                    result, events, state = self.graph(flags=('--tags', tags), fault=fault)
                    self.assertNotEqual(result.returncode, 0); self.assertEqual(state['before'], state['after'])
                    restored = next(e for e in events if e['action'] == 'ordinary-restored')
                    self.assertEqual(restored['restored'], [] if fault[1] == 'before' else [resource])
                    self.assertEqual(restored['services'], [])
                    self.assertFalse(any(e['action'] == 'service' for e in events))
                    self.assertNotIn('agent-verify', [e['action'] for e in events], 'C10 must not run after a failed configuration')
                    self.assertIsNone(state['ownership']['writer'])

    def test_a_verifier_only_failure_in_a_mixed_run_keeps_the_applied_selected_files(self):
        # Contract (part A native-run finding, kept over the earlier part-B behavior): a failed C10 is a
        # failed run, never a rollback of configuration that was applied correctly in the same run.
        for tags, resource in (('C5,C10', 'config'), ('C7,C10', 'hosts')):
            with self.subTest(tags=tags):
                result, events, state = self.graph(flags=('--tags', tags), fail_verify=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotEqual(state['before'], state['after'], 'the correctly applied ' + resource + ' must stay in place')
                self.assertFalse(any(e['action'] in ('ordinary-restored', 'agent-config-restore') for e in events), events)
                self.assertIn('agent-verify', [e['action'] for e in events])
                self.assertIsNone(state['ownership']['writer'], 'the writer is still released exactly')

    def test_a_selected_service_verification_failure_keeps_the_applied_services_and_audit_identity(self):
        result, events, state = self.graph(flags=('--tags', 'C3,C5,C10'), fail_verify=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(e['action'] in ('ordinary-restored', 'agent-config-restore') for e in events), events)
        self.assertNotEqual(state['before'], state['after'])
        self.assertTrue(state['services']['wazuh-agent']['active']); self.assertEqual(state['services']['wazuh-agent']['enabled'], 'enabled')
        self.assertEqual(state['services']['auditd']['generation'], 50)
        self.assertIsNone(state['ownership']['writer'])

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

    # ------------------------------------------------------------------------------------------------
    # Issue #244 part A's agent selection / failure-authority invariants, run against the production play
    # as it is shaped now (host-writer block, owner-carrying coordinator calls). They use the real Debian
    # package guard over a private preference file (real_guard) and A's fresh-config fixture (no prior block).
    # What B changed on purpose is asserted in B's terms: the host-wide writer is claimed and released around
    # every run (so "no coordinator state" becomes "no writer or journal left behind"), and refusal texts that B's
    # coordinator words differently.
    # ------------------------------------------------------------------------------------------------
    WRITER_BOOKKEEPING = ('writer-claim', 'writer-release', 'metadata')

    @staticmethod
    def actions(events):
        return [event['action'] for event in events]

    def agraph(self, *args, **kwargs):
        kwargs.setdefault('real_guard', True)
        kwargs.setdefault('prior_block', False)
        return self.graph(*args, **kwargs)

    def graphs(self, cases):
        """Run independent graphs concurrently (each has its own directory, state and ansible-playbook)."""
        with ThreadPoolExecutor(max_workers=4) as pool:
            return list(pool.map(lambda case: self.agraph(*case[0], **case[1]), cases))

    def assert_run_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_refused_unchanged(self, events, state):
        self.assertFalse([a for a in self.actions(events) if a in MUTATORS], events)
        self.assertEqual(state['before'], state['after'], 'configuration and hosts must be untouched')
        self.assertIsNone(state['ownership']['writer'], 'the host-wide writer is released after a refusal')
        self.assertEqual(state['ownership']['journals'], [], 'a refusal leaves no transaction behind')
        self.assertIsNone(state['preference'])

    def test_a_fresh_exact_agent_is_installed_after_its_checks_and_protected_for_both_backends(self):
        grid = [(family, tags) for family in ('Debian', 'RedHat') for tags in (None, 'C1', 'C2')]
        # prepared=False: the play itself must establish the official repository and key for every selection
        # that installs (the model refuses an install from a repository the play did not set up).
        runs = self.graphs([((family, ''), {'flags': ('--tags', tags) if tags else (), 'prepared': False}) for family, tags in grid])
        for (family, tags), (result, events, state) in zip(grid, runs):
            with self.subTest(family=family, tags=tags):
                self.assert_run_ok(result)
                self.assertEqual((state['installed'], state['protected']), ('4.14.1-1', True))
                actions = self.actions(events)
                self.assertLess(actions.index('agent-check'), actions.index('source-ready'))
                self.assertLess(actions.index('agent-policy-check'), actions.index('source-ready'))
                self.assertLess(actions.index('artifact-provenance'), actions.index('install-agent'))
                self.assertLess(actions.index('install-agent'), actions.index('agent-protect'))
                body = [a for a in actions if a != 'writer-release']
                if tags:
                    self.assertNotIn('agent-verify', actions, 'package proof must not require the C10 active service')
                else:
                    self.assertEqual(body[-1], 'agent-verify', 'C10 verifies after every selected step')
                if family == 'Debian':
                    self.assertIn('Pin: version 4.14.1-1\nPin-Priority: 1000', state['preference'])
                    self.assertIn('Pin: version *\nPin-Priority: -1', state['preference'])

    def test_the_fresh_version_follows_the_manager_or_the_request_never_the_repository(self):
        grid = (('4.14.9', '', '4.14.9-1'), ('4.14.9', '4.14.6', '4.14.6-1'), ('4.14.6', '4.14.6', '4.14.6-1'))
        runs = self.graphs([(('Debian', ''), {'manager': manager, 'requested': requested}) for manager, requested, _ in grid]
                           + [(('Debian', ''), {'managed': False})])
        for (manager, requested, installed), (result, events, state) in zip(grid, runs):
            self.assert_run_ok(result)
            self.assertEqual(state['installed'], installed, (manager, requested))
            self.assertEqual([e['version'] for e in events if e['action'] == 'artifact-provenance'], [installed])
        result, events, state = runs[-1]
        self.assert_run_ok(result)
        self.assertEqual(state['installed'], '4.14.1-1', 'with no manager the default release is installed')
        self.assertNotIn('manager-version', self.actions(events))

    def test_a_compatible_agent_is_retained_and_C10_is_a_pure_observer_for_both_backends_with_the_real_guard(self):
        grid = [(family, tags) for family in ('Debian', 'RedHat') for tags in (None, 'C1', 'C2', 'C10')]
        # An agent that earlier runs left unprotected (the common field state) is protected by
        # any apply that selects package work; C10 alone only observes an already protected one.
        runs = self.graphs([((family, '4.14.6-1'), {'manager': '4.14.9', 'protected': tags == 'C10',
                                                      'flags': ('--tags', tags) if tags else ()}) for family, tags in grid])
        for (family, tags), (result, events, state) in zip(grid, runs):
            with self.subTest(family=family, tags=tags):
                self.assert_run_ok(result)
                actions = self.actions(events)
                self.assertNotIn('install-agent', actions)
                self.assertNotIn('agent-reserve', actions, 'retaining a compatible agent opens no upgrade transaction')
                self.assertEqual(state['installed'], '4.14.6-1')
                self.assertEqual('agent-protect' in actions, tags != 'C10')
                self.assertTrue(state['protected'])
                if tags == 'C10':
                    self.assertEqual(state['before'], state['after'])
                    self.assertIn('agent-verify', actions)
                else:
                    self.assertEqual(state['config'].count(OWN_BLOCK), 1 if tags is None else 0)

    def test_an_already_protected_agent_is_not_protected_twice(self):
        result, events, state = self.agraph('Debian', '4.14.1-1', protected=True)
        self.assert_run_ok(result)
        self.assertIn('agent-protect', self.actions(events))
        self.assertNotIn('protected', self.actions(events), 'the native hold already exists; nothing to change')
        self.assertIn('failed=0', result.stdout)

    def test_protection_reports_a_change_exactly_when_it_changed_the_native_guard(self):
        # The production changed_when expression runs over the coordinator's output.
        grid = [(family, protected) for family in ('Debian', 'RedHat') for protected in (False, True)]
        runs = self.graphs([((family, '4.14.1-1'), {'protected': protected, 'flags': ('--tags', 'C1')}) for family, protected in grid])
        for (family, protected), (result, events, state) in zip(grid, runs):
            with self.subTest(family=family, already_protected=protected):
                self.assert_run_ok(result)
                status = re.search(r'TASK \[Protect the installed version[^\]]*\] \*+\n(\w+):', result.stdout)
                self.assertIsNotNone(status, result.stdout)
                self.assertEqual(status.group(1), 'ok' if protected else 'changed')

    def test_every_refusal_is_typed_visible_and_precedes_any_mutation_before_the_writer_is_released(self):
        cases = {
            'agent newer than manager': (dict(installed='4.14.9-1', manager='4.14.1'), 'installed Wazuh agent is newer than the observed manager'),
            'fresh request newer than manager': (dict(installed='', requested='4.14.9', manager='4.14.1'), 'requested Wazuh agent is newer than the observed manager'),
            # B contract: an upgrade is refused unless wazuh_upgrade=true and the target is 4.14.9.
            'agent upgrade': (dict(installed='4.14.6-1', requested='4.14.9', manager='4.14.9'), 'agent upgrade requires wazuh_upgrade=true and target 4.14.9'),
            'agent downgrade': (dict(installed='4.14.9-1', requested='4.14.6', manager='4.14.9'), 'Wazuh agent downgrade refused'),
            'foreign EL policy': (dict(foreign_policy=True, installed=''), 'foreign ownership'),
            'manager not observable': (dict(manager_error=True), 'operation failed: docker rc=1'),
            'unknown installed build': (dict(installed='4.14.9-rc1', manager='4.14.9'), 'unknown installed Wazuh agent package version'),
        }
        grid = [(name, family) for name in cases for family in ('Debian', 'RedHat') if not (name == 'foreign EL policy' and family == 'Debian')]
        runs = self.graphs([((family,), cases[name][0]) for name, family in grid])
        for (name, family), (result, events, state) in zip(grid, runs):
            inputs, reason = cases[name]
            with self.subTest(case=name, family=family):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(reason, result.stdout, 'the typed reason must be visible without no_log')
                self.assertIn('"error_kind": "refused"', result.stdout.replace('\\"', '"'))
                self.assert_refused_unchanged(events, state)

    def test_an_unsupported_platform_or_release_input_is_refused_before_any_package_or_configuration_change(self):
        cases = (({'ansible_architecture': 'aarch64'}, 'supports only Debian/RedHat packages on x86_64'),
                 ({'ansible_os_family': 'Suse'}, 'supports only Debian/RedHat packages on x86_64'),
                 ({'wazuh_version': '5.0.0'}, 'exact stable 4.14.x'), ({'wazuh_version': '4.14'}, 'exact stable 4.14.x'),
                 ({'wazuh_version': 'latest'}, 'exact stable 4.14.x'))
        runs = self.graphs([(('Debian', ''), {'extra_vars': extra}) for extra, _ in cases])
        for (extra, reason), (result, events, state) in zip(cases, runs):
            with self.subTest(extra=extra):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(reason, result.stdout)
                # B claims the host-wide writer first; nothing else (no coordinator observation, no mutation) may run.
                self.assertEqual([a for a in self.actions(events) if a not in self.WRITER_BOOKKEEPING], [],
                                 'no coordinator action may run before the input gate')
                self.assertEqual(state['before'], state['after'])
                self.assertIsNone(state['ownership']['writer'])

    def test_a_foreign_apt_preference_is_refused_before_any_repository_or_package_change(self):
        foreign = 'Package: *\nPin: release a=foreign\nPin-Priority: 900\n'
        result, events, state = self.agraph('Debian', '', native_preference=foreign)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('foreign ownership at the managed APT preference path', result.stdout)
        self.assertFalse([a for a in self.actions(events) if a in MUTATORS], events)
        self.assertEqual(state['before'], state['after'])
        self.assertEqual(state['preference'], foreign, 'foreign content is never overwritten')
        self.assertIsNone(state['ownership']['writer'])

    def test_a_foreign_preference_that_appears_after_the_first_check_is_refused_before_the_pin_is_written(self):
        foreign = 'Package: *\nPin: release a=foreign\nPin-Priority: 900\n'
        result, events, state = self.agraph('Debian', '', drift_preference=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('foreign ownership at the managed APT preference path', result.stdout)
        self.assertNotIn('agent-protect', self.actions(events), 'nothing may be protected under foreign policy')
        self.assertEqual(state['preference'], foreign, 'foreign content is never overwritten')

    def test_enrollment_without_one_exact_inventory_manager_is_refused_before_any_change(self):
        result, events, state = self.agraph('Debian', '', managed=True, extra_vars={'wazuh_manager_inventory_host': 'not-in-inventory'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Enrollment requires one exact inventory manager', result.stdout)
        self.assert_refused_unchanged(events, state)
        result, events, state = self.agraph('Debian', '', enrollment_host='unknown.example.test')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse([a for a in self.actions(events) if a in MUTATORS], events)
        self.assertEqual(state['before'], state['after'])

    def test_the_hosts_pin_is_the_address_bound_to_the_observed_inventory_manager(self):
        result, events, state = self.agraph('Debian', '4.14.1-1', manager_address='192.0.2.15')
        self.assert_run_ok(result)
        self.assertIn('192.0.2.15\twazuh-manager', state['hosts'])
        self.assertIn('manager-version', self.actions(events))

    def test_a_failed_C10_fails_the_run_without_reverting_correct_configuration(self):
        result, events, state = self.agraph('Debian', '4.14.1-1', fail_verify=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('controlled stable C10 failure', result.stdout)
        self.assertEqual(state['config'].count(OWN_BLOCK), 1, 'verification failure must not roll the FIM block back')
        self.assertIn('wazuh-manager', state['hosts'])

    def test_a_failure_inside_the_configuration_block_still_rolls_back_through_the_existing_rescue(self):
        for resource, fault in (('config', 'before'), ('config', 'partial'), ('hosts', 'partial')):
            with self.subTest(resource=resource, fault=fault):
                result, events, state = self.agraph('Debian', '4.14.1-1', fault=(resource, fault))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(state['config'].count(OWN_BLOCK), 0, 'the managed FIM block must be reverted')
                self.assertNotIn('\twazuh-manager', state['hosts'])
                self.assertNotIn('agent-verify', self.actions(events), 'C10 must not run after a failed configuration')

    def test_check_mode_reads_only_and_changes_nothing_for_a_fresh_host(self):
        runs = self.graphs([((family, ''), {'flags': ('--check',), 'prepared': False}) for family in ('Debian', 'RedHat')])
        for family, (result, events, state) in zip(('Debian', 'RedHat'), runs):
            with self.subTest(family=family):
                self.assert_run_ok(result)
                # B claims and releases the host-wide writer even for a preview (spec: preview may create the
                # authorized writer/lock); every other action is a read-only observation.
                self.assertEqual(sorted({a for a in self.actions(events)} - set(self.WRITER_BOOKKEEPING)),
                                 ['agent-check', 'agent-policy-check', 'manager-version'])
                self.assertEqual(state['before'], state['after'])
                self.assertIsNone(state['ownership']['writer'])
                self.assertEqual(state['ownership']['journals'], [], 'a preview leaves no transaction behind')

    def test_a_manager_that_the_same_check_run_only_previews_is_not_observed_but_a_real_run_observes_it(self):
        result, events, state = self.agraph('Debian', '', flags=('--check',), preview_fresh_manager=True, prepared=False)
        self.assert_run_ok(result)
        self.assertNotIn('manager-version', self.actions(events))
        self.assertEqual(state['plan']['manager'], '', 'the deferred preview plans against no manager')
        result, events, state = self.agraph('Debian', '', preview_fresh_manager=True)
        self.assert_run_ok(result)
        self.assertIn('manager-version', self.actions(events))
        self.assertEqual(state['plan']['manager'], '4.14.1')

    def test_a_fresh_agent_requires_its_install_tasks_to_be_selected(self):
        grid = [(family, flags) for family in ('Debian', 'RedHat') for flags in (
            ('--tags', 'C2', '--skip-tags', 'C1'), ('--tags', 'C1', '--skip-tags', 'C2'), ('--tags', 'C10'), ('--tags', 'C5'))]
        runs = self.graphs([((family, ''), {'flags': flags, 'prepared': False}) for family, flags in grid])
        for (family, flags), (result, events, state) in zip(grid, runs):
            with self.subTest(family=family, flags=flags):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('require C1/C2 package installation to be selected', result.stdout)
                self.assertFalse([a for a in self.actions(events) if a in MUTATORS], events)
                self.assertEqual(state['before'], state['after'])

    def test_component_inherited_selection_keeps_the_nested_graph(self):
        result, events, state = self.agraph(installed='', flags=('--tags', 'wazuh-fim'), inherited=True)
        self.assert_run_ok(result)
        self.assertEqual((state['installed'], state['protected']), ('4.14.1-1', True))

    def test_a_preselected_source_that_is_not_official_never_authorizes_an_install(self):
        for family in ('Debian', 'RedHat'):
            result, events, state = self.agraph(family, '', prepared=True, foreign_source=True, flags=('--tags', 'C2'))
            self.assertEqual(state['installed'], '4.14.1-1')
            # The graph itself re-establishes the official source before replacing any package.
            self.assertLess(self.actions(events).index('source-ready'), self.actions(events).index('install-agent'))


if __name__ == '__main__': unittest.main(verbosity=2)
