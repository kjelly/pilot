"""Real Ansible agent selection/failure-authority graph; the native boundary is explicit.

The production wazuh-fim play runs under real Ansible with every production include,
apply tag, gate and rescue retained (shared APT framework, pin task, endpoint
resolver). The version coordinator's code runs for real over a modeled dpkg/rpm/
apt-mark/systemctl (see wazuh_selection_backend.py); package managers, repository
sources, services and the manager observation are modeled. This is not native VM
acceptance.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import yaml

REPO = Path(__file__).resolve().parents[3]
SOURCE = REPO / 'playbooks/apply'
WORKER = REPO / 'internal/spec/testdata/wazuh_selection_backend.py'
OWN_BLOCK = '<!-- BEGIN ANSIBLE MANAGED BLOCK (wazuh-fim-apply.yml FIM whodata) -->'
MUTATORS = ('install-agent', 'protected', 'source-ready', 'install-prerequisite', 'service', 'install-coordinator',
            'artifact-provenance', 'agent-protect', 'agent-rpm-fresh')


def metadata(path):
    data = path.stat()
    return {'bytes': path.read_bytes().hex(), 'mode': data.st_mode & 0o7777}


def picked(play, name):
    """The production task with this name, wherever it sits in pre_tasks/tasks/blocks."""
    def walk(items):
        for task in items:
            if task.get('name') == name:
                return task
            for field in ('block', 'rescue', 'always'):
                if field in task:
                    found = walk(task[field])
                    if found:
                        return found
    for section in ('pre_tasks', 'tasks'):
        found = walk(play.get(section, []))
        if found:
            return found
    raise AssertionError('missing production task: ' + name)


class SelectionGraphTests(unittest.TestCase):
    def graph(self, family='Debian', installed='4.14.1-1', flags=(), prepared=True, manager='4.14.1', managed=True,
              requested='', fail_verify=False, fault=None, foreign_source=False, foreign_policy=False, inherited=False,
              manager_error=False, enrollment_host='localhost', manager_address='127.0.0.1', preview_fresh_manager=False,
              extra_vars=None, protected=None, native_preference=None, drift_preference=False):
        with tempfile.TemporaryDirectory(prefix='i244a-selection-') as temporary:
            root = Path(temporary); data = root / 'data'; data.mkdir()
            paths = {'config': str(data / 'ossec.conf'), 'hosts': str(data / 'hosts')}
            Path(paths['config']).write_text('<ossec_config>\n<address>prior-manager</address>\n</ossec_config>\n<!-- OPERATOR FIM SENTINEL -->\n')
            Path(paths['hosts']).write_text('127.0.0.1 localhost\n# HOST SENTINEL\n')
            keys = data / 'client.keys'; keys.write_text('001 localhost any SYNTHETIC_KEY\n')
            preference = root / 'pilot-wazuh-agent'
            if native_preference is not None:
                preference.write_text(native_preference); preference.chmod(0o644)
            events_file = root / 'events.jsonl'; state_file = root / 'state.json'
            state = {'installed': installed, 'protected': bool(installed) if protected is None else protected,
                     'protected_version': installed, 'key': prepared,
                     'repo': 'foreign' if foreign_source else 'official' if prepared else '',
                     'foreign_policy': foreign_policy,
                     'services': {'wazuh-agent': {'active': bool(installed), 'enabled': 'enabled', 'generation': 40},
                                  'auditd': {'active': True, 'enabled': 'enabled', 'generation': 50}}}
            state_file.write_text(json.dumps(state))
            before = {name: metadata(Path(value)) for name, value in paths.items()}
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'library': str(SOURCE / 'files/wazuh-transaction.py'), 'root': str(root / 'ledger'),
                                             'state': str(state_file), 'events': str(events_file), 'paths': paths,
                                             'preference': str(preference), 'manager': manager, 'manager_error': manager_error,
                                             'drift_preference': drift_preference,
                                             'fail_verify': fail_verify, 'fault_resource': fault[0] if fault else ''}))
            tasks = root / 'tasks'; tasks.mkdir()
            for pattern in ('apt-*.yml', 'wazuh-agent-*.yml', 'wazuh-endpoint-resolve.yml', 'resolve-hosts-alias-target.yml'):
                for source in (SOURCE / 'tasks').glob(pattern):
                    shutil.copy2(source, tasks / source.name)
            (root / 'files').mkdir(); shutil.copy2(SOURCE / 'files/wazuh-endpoint.py', root / 'files/wazuh-endpoint.py')
            # The production script tasks run through the REAL ScriptModule (argument rendering, shell splitting,
            # failure reporting): the file it ships is a forwarder to the backend that drives the real coordinator.
            (root / 'files/wazuh-transaction.py').write_text(
                'import os, sys\nos.execv(sys.executable, [sys.executable, %r, %r, *sys.argv[1:]])\n' % (str(WORKER), str(settings)))
            play = yaml.safe_load((SOURCE / 'wazuh-fim-apply.yml').read_text())[0]
            play.update(connection='local', become=False, gather_facts=False)
            play['vars'].update(target_group='all', ansible_os_family=family, ansible_architecture='x86_64',
                                ansible_distribution='Ubuntu' if family == 'Debian' else 'AlmaLinux',
                                wazuh_ossec_conf=paths['config'], wazuh_client_keys=str(keys))
            if managed:
                play['vars'].update(wazuh_manager_host=enrollment_host, wazuh_manager_inventory_host='localhost')
            if requested:
                play['vars']['wazuh_version'] = requested
            play['vars'].update(extra_vars or {})
            packages = {}
            if installed:
                packages['wazuh-agent'] = [{'version': installed, 'arch': 'amd64'}]
            if prepared:
                packages['auditd'] = [{'version': '1', 'arch': 'amd64'}]

            def replace(task, action, extra=None, payload=None):
                for key in list(task):
                    if '.' in key:
                        del task[key]
                argv = ['python3', str(WORKER), str(settings), action]
                if extra:
                    argv += extra
                if payload is not None:
                    task.setdefault('vars', {})['_wv_native_payload'] = payload
                    argv += ['--payload', '{{ _wv_native_payload | to_json }}']
                task['ansible.builtin.command'] = {'argv': argv}
                task.setdefault('changed_when', False)
                if 'until' in task:
                    task['until'] = task['register'] + ' is succeeded'

            def rewrite(items):
                for task in items:
                    for field in ('block', 'rescue', 'always'):
                        if field in task:
                            rewrite(task[field])
                    if 'ansible.builtin.include_tasks' in task:
                        include = task['ansible.builtin.include_tasks']
                        name = include if isinstance(include, str) else include['file']
                        if isinstance(include, str):
                            task['ansible.builtin.include_tasks'] = str(tasks / Path(name).name)
                        else:
                            include['file'] = str(tasks / Path(name).name)
                    elif 'ansible.builtin.script' in task:
                        script = task['ansible.builtin.script']['cmd']
                        if 'wazuh-transaction.py' in script or 'wazuh-endpoint.py' in script:
                            pass
                        elif '--cache-preflight' in script:
                            replace(task, 'metadata')
                        else:
                            replace(task, 'artifact-proof', ['--version-map', '{{ _pilot_apt_versions | default({}) | to_json }}'])
                    elif 'ansible.builtin.package_facts' in task:
                        del task['ansible.builtin.package_facts']; task['ansible.builtin.set_fact'] = {'ansible_facts': {'packages': packages}}
                    elif 'ansible.builtin.command' in task:
                        command = task['ansible.builtin.command']
                        if isinstance(command, dict) and command.get('argv', [''])[0] == '/usr/local/sbin/pilot-wazuh-transaction':
                            command['argv'] = ['python3', str(WORKER), str(settings)] + command['argv'][1:]
                        elif task['name'].startswith("Allocate this run's private-stage token"):
                            pass
                        elif task.get('register') == 'hosts_alias_dns_lookup':
                            pass
                        else:
                            replace(task, 'native-probe', payload=command if isinstance(command, dict) else {'argv': []})
                    elif 'ansible.builtin.apt' in task:
                        replace(task, 'package-install', ['--packages', '{{ pilot_apt_missing | default(_pilot_apt_missing) | to_json }}'])
                    elif 'ansible.builtin.dnf' in task:
                        params = task['ansible.builtin.dnf']
                        replace(task, 'package-install', ['--packages', '{{ _wv_native_payload.name | to_json }}'], payload=params)
                    elif 'ansible.builtin.systemd' in task:
                        replace(task, 'service-module', payload=task['ansible.builtin.systemd'])
                    elif 'ansible.builtin.shell' in task:
                        replace(task, 'source', ['--family', family], {'kind': 'key'})
                    elif 'ansible.builtin.yum_repository' in task:
                        replace(task, 'source', ['--family', family], {'kind': 'repo'})
                    elif 'ansible.builtin.copy' in task:
                        params = task['ansible.builtin.copy']; dest = params.get('dest', '')
                        if dest == '/etc/apt/sources.list.d/wazuh.list':
                            replace(task, 'source', ['--family', family], {'kind': 'repo'})
                        elif dest == '/etc/apt/preferences.d/pilot-wazuh-agent':
                            # The real preference text lands in the preference file the real guard reads.
                            params['dest'] = str(preference)
                            # The harness runs unprivileged: only ownership is dropped, content and mode stay real.
                            params.pop('owner'); params.pop('group')
                        elif dest == '/usr/local/sbin/pilot-wazuh-transaction':
                            replace(task, 'install-coordinator')
                        else:
                            replace(task, 'metadata')
                    elif 'ansible.builtin.file' in task:
                        replace(task, 'metadata')
                    elif 'ansible.builtin.stat' in task:
                        task['ansible.builtin.stat']['path'] = str(keys)
                    elif 'ansible.builtin.lineinfile' in task and task['ansible.builtin.lineinfile'].get('path') == '/etc/hosts':
                        task['ansible.builtin.lineinfile']['path'] = paths['hosts']
                    # The selected config modules stay real except for explicit
                    # before/partial failure injection at their boundary.
                    if fault:
                        module = task.get('ansible.builtin.blockinfile') or task.get('ansible.builtin.lineinfile')
                        if module and module.get('path') in (paths['hosts'] if fault[0] == 'hosts' else '{{ wazuh_ossec_conf }}',):
                            replace(task, 'fault-' + fault[1])
                            task['changed_when'] = False
            rewrite(play['pre_tasks']); rewrite(play['tasks'])
            for filename in tasks.glob('*.yml'):
                content = yaml.safe_load(filename.read_text()); rewrite(content); filename.write_text(yaml.safe_dump(content, sort_keys=False))
            filename = root / 'play.yml'; filename.write_text(yaml.safe_dump([play], sort_keys=False))
            if inherited:
                wrapper = root / 'wrapper.yml'
                wrapper.write_text(yaml.safe_dump([{'ansible.builtin.import_playbook': 'play.yml', 'tags': ['wazuh-fim']}]))
                filename = wrapper
            config = root / 'ansible.cfg'; config.write_text('[defaults]\nfact_caching=memory\nretry_files_enabled=false\n')
            env = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_LOCAL_TEMP=str(root / 'local'),
                       ANSIBLE_REMOTE_TEMP=str(root / 'remote'), ANSIBLE_CACHE_PLUGIN='memory')
            host_vars = {'ansible_connection': 'local', 'ansible_host': manager_address}
            if preview_fresh_manager:
                host_vars.update(pilot_wazuh_manager_install_planned=True, pilot_wazuh_manager_preview_fresh=True)
            inventory = root / 'inventory.yml'
            inventory.write_text(yaml.safe_dump({'all': {'hosts': {'localhost': host_vars},
                                                           'children': {'wazuh-manager': {'hosts': {'localhost': {}}}} if managed else {}}}))
            run = subprocess.run(['ansible-playbook', '-i', str(inventory), str(filename), *flags], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=180)
            events = [json.loads(line) for line in events_file.read_text().splitlines()] if events_file.exists() else []
            state = json.loads(state_file.read_text())
            state['before'] = before; state['after'] = {name: metadata(Path(value)) for name, value in paths.items()}
            state['ledger_created'] = (root / 'ledger').exists()
            state['preference'] = preference.read_text() if preference.exists() else None
            state['hosts'] = Path(paths['hosts']).read_text(); state['config'] = Path(paths['config']).read_text()
            return run, events, state

    def graphs(self, cases):
        """Run independent graphs concurrently (each has its own directory, state and ansible-playbook)."""
        with ThreadPoolExecutor(max_workers=4) as pool:
            return list(pool.map(lambda case: self.graph(*case[0], **case[1]), cases))

    @staticmethod
    def actions(events):
        return [event['action'] for event in events]

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_unchanged(self, events, state):
        self.assertFalse([a for a in self.actions(events) if a in MUTATORS], events)
        self.assertEqual(state['before'], state['after'], 'configuration and hosts must be untouched')
        self.assertFalse(state['ledger_created'], 'a refusal creates no coordinator state')
        self.assertIsNone(state['preference'])

    def test_a_fresh_exact_agent_is_installed_after_its_checks_and_protected_for_both_backends(self):
        grid = [(family, tags) for family in ('Debian', 'RedHat') for tags in (None, 'C1', 'C2')]
        # prepared=False: the play itself must establish the official repository and key for every selection
        # that installs (the model refuses an install from a repository the play did not set up).
        runs = self.graphs([((family, ''), {'flags': ('--tags', tags) if tags else (), 'prepared': False}) for family, tags in grid])
        for (family, tags), (result, events, state) in zip(grid, runs):
            with self.subTest(family=family, tags=tags):
                self.assert_ok(result)
                self.assertEqual((state['installed'], state['protected']), ('4.14.1-1', True))
                actions = self.actions(events)
                self.assertLess(actions.index('agent-check'), actions.index('source-ready'))
                self.assertLess(actions.index('agent-policy-check'), actions.index('source-ready'))
                self.assertLess(actions.index('artifact-provenance'), actions.index('install-agent'))
                self.assertLess(actions.index('install-agent'), actions.index('agent-protect'))
                if tags:
                    self.assertNotIn('agent-verify', actions, 'package proof must not require the C10 active service')
                else:
                    self.assertEqual(actions[-1], 'agent-verify', 'C10 verifies after every selected step')
                if family == 'Debian':
                    self.assertIn('Pin: version 4.14.1-1\nPin-Priority: 1000', state['preference'])
                    self.assertIn('Pin: version *\nPin-Priority: -1', state['preference'])

    def test_the_fresh_version_follows_the_manager_or_the_request_never_the_repository(self):
        grid = (('4.14.9', '', '4.14.9-1'), ('4.14.9', '4.14.6', '4.14.6-1'), ('4.14.6', '4.14.6', '4.14.6-1'))
        runs = self.graphs([(('Debian', ''), {'manager': manager, 'requested': requested}) for manager, requested, _ in grid]
                           + [(('Debian', ''), {'managed': False})])
        for (manager, requested, installed), (result, events, state) in zip(grid, runs):
            self.assert_ok(result)
            self.assertEqual(state['installed'], installed, (manager, requested))
            self.assertEqual([e['version'] for e in events if e['action'] == 'artifact-provenance'], [installed])
        result, events, state = runs[-1]
        self.assert_ok(result)
        self.assertEqual(state['installed'], '4.14.1-1', 'with no manager the default release is installed')
        self.assertNotIn('manager-version', self.actions(events))

    def test_a_compatible_agent_is_retained_and_C10_is_a_pure_observer_for_both_backends(self):
        grid = [(family, tags) for family in ('Debian', 'RedHat') for tags in (None, 'C1', 'C2', 'C10')]
        # An agent that earlier runs left unprotected (the common field state) is protected by
        # any apply that selects package work; C10 alone only observes an already protected one.
        runs = self.graphs([((family, '4.14.6-1'), {'manager': '4.14.9', 'protected': tags == 'C10',
                                                      'flags': ('--tags', tags) if tags else ()}) for family, tags in grid])
        for (family, tags), (result, events, state) in zip(grid, runs):
            with self.subTest(family=family, tags=tags):
                self.assert_ok(result)
                actions = self.actions(events)
                self.assertNotIn('install-agent', actions)
                self.assertEqual(state['installed'], '4.14.6-1')
                self.assertEqual('agent-protect' in actions, tags != 'C10')
                self.assertTrue(state['protected'])
                if tags == 'C10':
                    self.assertEqual(state['before'], state['after'])
                    self.assertIn('agent-verify', actions)
                else:
                    self.assertEqual(state['config'].count(OWN_BLOCK), 1 if tags is None else 0)

    def test_an_already_protected_agent_is_not_protected_twice(self):
        result, events, state = self.graph('Debian', '4.14.1-1', protected=True)
        self.assert_ok(result)
        self.assertIn('agent-protect', self.actions(events))
        self.assertNotIn('protected', self.actions(events), 'the native hold already exists; nothing to change')
        self.assertIn('failed=0', result.stdout)

    def test_protection_reports_a_change_exactly_when_it_changed_the_native_guard(self):
        # The production changed_when expression runs over the real coordinator's output.
        grid = [(family, protected) for family in ('Debian', 'RedHat') for protected in (False, True)]
        runs = self.graphs([((family, '4.14.1-1'), {'protected': protected, 'flags': ('--tags', 'C1')}) for family, protected in grid])
        for (family, protected), (result, events, state) in zip(grid, runs):
            with self.subTest(family=family, already_protected=protected):
                self.assert_ok(result)
                status = re.search(r'TASK \[Protect the installed version[^\]]*\] \*+\n(\w+):', result.stdout)
                self.assertIsNotNone(status, result.stdout)
                self.assertEqual(status.group(1), 'ok' if protected else 'changed')

    def test_every_refusal_is_typed_visible_and_precedes_any_mutation(self):
        cases = {
            'agent newer than manager': (dict(installed='4.14.9-1', manager='4.14.1'), 'installed Wazuh agent is newer than the observed manager'),
            'fresh request newer than manager': (dict(installed='', requested='4.14.9', manager='4.14.1'), 'requested Wazuh agent is newer than the observed manager'),
            'agent upgrade': (dict(installed='4.14.6-1', requested='4.14.9', manager='4.14.9'), 'Wazuh agent upgrade is not supported by this version'),
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
                self.assert_unchanged(events, state)

    def test_an_unsupported_platform_or_release_input_is_refused_before_any_coordinator_call(self):
        cases = (({'ansible_architecture': 'aarch64'}, 'supports only Debian/RedHat packages on x86_64'),
                 ({'ansible_os_family': 'Suse'}, 'supports only Debian/RedHat packages on x86_64'),
                 ({'wazuh_version': '5.0.0'}, 'exact stable 4.14.x'), ({'wazuh_version': '4.14'}, 'exact stable 4.14.x'),
                 ({'wazuh_version': 'latest'}, 'exact stable 4.14.x'))
        runs = self.graphs([(('Debian', ''), {'extra_vars': extra}) for extra, _ in cases])
        for (extra, reason), (result, events, state) in zip(cases, runs):
            with self.subTest(extra=extra):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(reason, result.stdout)
                self.assertEqual(events, [], 'no coordinator action may run before the input gate')
                self.assertEqual(state['before'], state['after'])

    def test_a_foreign_apt_preference_is_refused_before_any_repository_or_package_change(self):
        result, events, state = self.graph('Debian', '', native_preference='Package: *\nPin: release a=foreign\nPin-Priority: 900\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('foreign ownership at the managed APT preference path', result.stdout)
        self.assertFalse([a for a in self.actions(events) if a in MUTATORS], events)
        self.assertEqual(state['before'], state['after'])
        self.assertEqual(state['preference'], 'Package: *\nPin: release a=foreign\nPin-Priority: 900\n', 'foreign content is never overwritten')

    def test_a_foreign_preference_that_appears_after_the_first_check_is_refused_before_the_pin_is_written(self):
        result, events, state = self.graph('Debian', '', drift_preference=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('foreign ownership at the managed APT preference path', result.stdout)
        self.assertNotIn('agent-protect', self.actions(events), 'nothing may be protected under foreign policy')
        self.assertEqual(state['preference'], 'Package: *\nPin: release a=foreign\nPin-Priority: 900\n', 'foreign content is never overwritten')

    def test_enrollment_without_one_exact_inventory_manager_is_refused_before_any_change(self):
        result, events, state = self.graph('Debian', '', managed=True, extra_vars={'wazuh_manager_inventory_host': 'not-in-inventory'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Enrollment requires one exact inventory manager', result.stdout)
        self.assert_unchanged(events, state)
        result, events, state = self.graph('Debian', '', enrollment_host='unknown.example.test')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse([a for a in self.actions(events) if a in MUTATORS], events)
        self.assertEqual(state['before'], state['after'])

    def test_the_hosts_pin_is_the_address_bound_to_the_observed_inventory_manager(self):
        result, events, state = self.graph('Debian', '4.14.1-1', manager_address='192.0.2.15')
        self.assert_ok(result)
        self.assertIn('192.0.2.15\twazuh-manager', state['hosts'])
        self.assertIn('manager-version', self.actions(events))

    def test_a_failed_C10_fails_the_run_without_reverting_correct_configuration(self):
        result, events, state = self.graph('Debian', '4.14.1-1', fail_verify=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('controlled stable C10 failure', result.stdout)
        self.assertEqual(state['config'].count(OWN_BLOCK), 1, 'verification failure must not roll the FIM block back')
        self.assertIn('wazuh-manager', state['hosts'])

    def test_a_failure_inside_the_configuration_block_still_rolls_back_through_the_existing_rescue(self):
        for resource, fault in (('config', 'before'), ('config', 'partial'), ('hosts', 'partial')):
            with self.subTest(resource=resource, fault=fault):
                result, events, state = self.graph('Debian', '4.14.1-1', fault=(resource, fault))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(state['config'].count(OWN_BLOCK), 0, 'the managed FIM block must be reverted')
                self.assertNotIn('\twazuh-manager', state['hosts'])
                self.assertNotIn('agent-verify', self.actions(events), 'C10 must not run after a failed configuration')

    def test_check_mode_reads_only_and_creates_nothing_for_a_fresh_host(self):
        runs = self.graphs([((family, ''), {'flags': ('--check',), 'prepared': False}) for family in ('Debian', 'RedHat')])
        for family, (result, events, state) in zip(('Debian', 'RedHat'), runs):
            with self.subTest(family=family):
                self.assert_ok(result)
                self.assertEqual(sorted(set(self.actions(events))), ['agent-check', 'agent-policy-check', 'manager-version'])
                self.assertEqual(state['before'], state['after'])
                self.assertFalse(state['ledger_created'])

    def test_a_manager_that_the_same_check_run_only_previews_is_not_observed_but_a_real_run_observes_it(self):
        result, events, state = self.graph('Debian', '', flags=('--check',), preview_fresh_manager=True, prepared=False)
        self.assert_ok(result)
        self.assertNotIn('manager-version', self.actions(events))
        self.assertEqual(state['plan']['manager'], '', 'the deferred preview plans against no manager')
        result, events, state = self.graph('Debian', '', preview_fresh_manager=True)
        self.assert_ok(result)
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
        result, events, state = self.graph(installed='', flags=('--tags', 'wazuh-fim'), inherited=True)
        self.assert_ok(result)
        self.assertEqual((state['installed'], state['protected']), ('4.14.1-1', True))

    def test_a_preselected_source_that_is_not_official_never_authorizes_an_install(self):
        for family in ('Debian', 'RedHat'):
            result, events, state = self.graph(family, '', prepared=True, foreign_source=True, flags=('--tags', 'C2'))
            self.assertEqual(state['installed'], '4.14.1-1')
            # The graph itself re-establishes the official source before replacing any package.
            self.assertLess(self.actions(events).index('source-ready'), self.actions(events).index('install-agent'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
