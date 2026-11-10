"""Real Ansible run of the production manager version gate.

The production tasks (input gates, defaulting, docker pre-flight, the owner-held
central inspect/execute entry point, the selection facts) are extracted by name from
wherever the play nests them and run unchanged under real Ansible; the coordinator's
`central` action runs for real over the modeled docker/Wazuh commands, after the
host-wide writer is claimed for the play's owner. A sentinel task after the gate stands for "the
stack would now be touched". Not native VM evidence.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import yaml

REPO = Path(__file__).resolve().parents[3]
SOURCE = REPO / 'playbooks/apply'
BACKEND = REPO / 'internal/spec/testdata/wazuh_manager_gate_backend.py'
NAMES = ('Gate: common and legacy Wazuh release inputs agree',
         'Resolve inventory-overridable defaults without shadowing group_vars/host_vars',
         'Gate: the effective Wazuh release is an exact stable 4.14.x',
         'Pre-flight: docker engine is up (spec docs/verification/docker.md)',
         'Inspect compatibility or execute the explicitly authorized central upgrade',
         "Reset this play's selected manager replacement plan",
         "Mark this run's selected Wazuh manager installation plan",
         'Record whether the central runtime probe was legitimately deferred',
         'Gate: a fresh central stack requires selected container installation tasks')


def walk(items):
    for task in items:
        yield task
        for section in ('block', 'rescue', 'always'):
            yield from walk(task.get(section, []))


def picked(play, name):
    # The production play nests its tasks under the host-writer block: find them wherever they are.
    for task in walk(play.get('pre_tasks', []) + play.get('tasks', [])):
        if task.get('name') == name:
            return task
    raise AssertionError('missing production task: ' + name)


class ManagerGateTests(unittest.TestCase):
    def run_gate(self, stack='present', stack_release='4.14.1', docker_up=True, inputs=None, flags=(), agents=None, stopped_daemon='', dashboard_release=None, indexer_release=None):
        with tempfile.TemporaryDirectory(prefix='wazuh-manager-gate-') as temporary:
            root = Path(temporary)
            play = yaml.safe_load((SOURCE / 'wazuh-manager-apply.yml').read_text())[0]
            events = root / 'events.jsonl'
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'library': str(SOURCE / 'files/wazuh-transaction.py'), 'events': str(events),
                                            'stack': stack, 'stack_release': stack_release, 'docker_up': docker_up,
                                            'agents': agents, 'stopped_daemon': stopped_daemon,
                                            'dashboard_release': dashboard_release, 'indexer_release': indexer_release}))
            (root / 'files').mkdir()
            (root / 'files/wazuh-transaction.py').write_text(
                'import os, sys\nos.execv(sys.executable, [sys.executable, %r, %r, *sys.argv[1:]])\n' % (str(BACKEND), str(settings)))
            tasks = []
            for name in NAMES:
                task = picked(play, name)
                if 'ansible.builtin.script' in task:
                    # Runs through the REAL ScriptModule; the shipped file is a forwarder to the backend.
                    self.assertIn('files/wazuh-transaction.py central', ' '.join(task['ansible.builtin.script']['cmd'].split()))
                elif task.get('register') == 'docker_pre':
                    del task['ansible.builtin.command']
                    task['ansible.builtin.command'] = {'argv': ['python3', str(BACKEND), str(settings), 'docker-info']}
                tasks.append(task)
            tasks.append({'name': 'a stack mutation would be reached here', 'ansible.builtin.command': {'argv': ['python3', str(BACKEND), str(settings), 'mutation']},
                          'changed_when': False, 'tags': ['always']})
            tasks.append({'name': 'record the effective facts', 'check_mode': False, 'tags': ['always'], 'ansible.builtin.copy': {
                'dest': str(root / 'facts.json'), 'mode': '0600',
                'content': "{{ {'docker_version': wazuh_docker_version, 'planned': pilot_wazuh_manager_install_planned, 'preview_fresh': pilot_wazuh_manager_preview_fresh} | to_json }}"}})
            values = {'stage': 'sandbox',
                      # Inputs the owner-held central entry point consumes; the real plays derive them earlier
                      # (writer claim, reader request, preview staging), which other harnesses cover.
                      'wazuh_writer_owner': 'd' * 32, 'wazuh_reader_checker_hash': '',
                      'wazuh_reader_request': {'selected': False, 'enabled': False, 'host': '', 'address': '', 'transport': 'tcp',
                                               'port': '514', 'peer': '', 'tls': {}, 'tools': {}},
                      'wazuh_reader_operation': {'stdout': 'e' * 32}, 'wazuh_preview_assets': {}}
            values.update(inputs or {})
            playbook = root / 'play.yml'
            playbook.write_text(yaml.safe_dump([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                                                'vars': values, 'tasks': tasks}], sort_keys=False))
            config = root / 'ansible.cfg'
            config.write_text('[defaults]\nfact_caching=memory\nretry_files_enabled=false\n')
            env = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_LOCAL_TEMP=str(root / 'local'),
                       ANSIBLE_REMOTE_TEMP=str(root / 'remote'), ANSIBLE_CACHE_PLUGIN='memory', ANSIBLE_NOCOLOR='1',
                       PYTHONDONTWRITEBYTECODE='1', PILOT_WAZUH_HERMETIC='enforce')
            run = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook), *flags], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=180)
            log = [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []
            facts = json.loads((root / 'facts.json').read_text()) if (root / 'facts.json').exists() else None
            return run, [e['action'] for e in log], [e['argv'] for e in log if e['action'] == 'docker'], facts

    def test_a_fresh_host_passes_and_pins_the_requested_release(self):
        run, actions, docker, facts = self.run_gate('absent', inputs={'wazuh_version': '4.14.6'})
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(facts, {'docker_version': '4.14.6', 'planned': True, 'preview_fresh': False})
        self.assertIn('mutation', actions)

    def test_the_default_release_and_the_legacy_variable_are_unchanged(self):
        run, actions, docker, facts = self.run_gate('absent')
        self.assertEqual((run.returncode, facts['docker_version']), (0, '4.14.1'), run.stdout)
        run, actions, docker, facts = self.run_gate('absent', inputs={'wazuh_docker_version': '4.14.6'})
        self.assertEqual((run.returncode, facts['docker_version']), (0, '4.14.6'), run.stdout)
        run, actions, docker, facts = self.run_gate('absent', inputs={'wazuh_docker_version': '4.14.6', 'wazuh_version': '4.14.6'})
        self.assertEqual((run.returncode, facts['docker_version']), (0, '4.14.6'), run.stdout)

    def test_an_existing_stack_at_the_requested_release_is_left_to_the_ordinary_apply(self):
        for inputs in ({}, {'wazuh_version': '4.14.1'}, {'wazuh_docker_version': '4.14.1'}):
            run, actions, docker, facts = self.run_gate('present', '4.14.1', inputs=inputs)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('mutation', actions)
            self.assertEqual(facts['planned'], True)

    def test_any_release_change_of_an_existing_stack_is_a_visible_typed_refusal_before_anything_else(self):
        # Agents are consistent with the requested release so the refusal under test is the release change itself
        # (a registered agent newer than the target is the separate, earlier typed refusal tested below).
        cases = ((('present', '4.14.1'), {'wazuh_version': '4.14.9'}, None),
                 (('present', '4.14.9'), {}, {'001': '4.14.1'}),
                 (('present', '4.14.1'), {'wazuh_docker_version': '4.14.9'}, None),
                 (('present', '4.14.6'), {'wazuh_version': '4.14.9'}, None))
        for (stack, release), inputs, agents in cases:
            for flags in ((), ('--check',)):
                with self.subTest(release=release, inputs=inputs, flags=flags):
                    run, actions, docker, facts = self.run_gate(stack, release, inputs=inputs, flags=flags, agents=agents)
                    self.assertNotEqual(run.returncode, 0)
                    self.assertIn('only explicit central 4.14.1 -> 4.14.9 upgrade is supported', run.stdout)
                    self.assertIn('error_kind', run.stdout)
                    self.assertNotIn('mutation', actions, 'no stack task may follow a refused gate')
                    self.assertIsNone(facts)
                    self.assertFalse([a for a in docker if a[1] in ('compose', 'pull', 'stop', 'rm', 'up')], docker)

    def test_upgrade_authorization_never_widens_the_supported_pair_or_allows_a_downgrade(self):
        # B contract: an explicit wazuh_upgrade authorizes only 4.14.1 -> 4.14.9 of an existing stack.
        for (stack, release), inputs, agents in ((('present', '4.14.6'), {'wazuh_version': '4.14.9'}, None),
                                                 (('present', '4.14.9'), {'wazuh_version': '4.14.1'}, {'001': '4.14.1'}),
                                                 (('present', '4.14.1'), {'wazuh_version': '4.14.6'}, None)):
            with self.subTest(release=release, inputs=inputs):
                run, actions, docker, facts = self.run_gate(stack, release, inputs=dict(inputs, wazuh_upgrade=True),
                                                            flags=('--tags', 'C1'), agents=agents)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn('only explicit central 4.14.1 -> 4.14.9 upgrade is supported', run.stdout)
                self.assertNotIn('mutation', actions)
                self.assertFalse([a for a in docker if a[1] in ('compose', 'pull', 'stop', 'rm', 'up')], docker)
        # A fresh host has nothing to upgrade: the authorization is simply unused.
        run, actions, docker, facts = self.run_gate('absent', inputs={'wazuh_version': '4.14.9', 'wazuh_upgrade': True},
                                                    flags=('--tags', 'C1'))
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(facts['docker_version'], '4.14.9')

    def test_a_non_boolean_upgrade_authorization_is_refused_before_any_docker_command(self):
        for value in ('yes', '1', 'maybe'):
            with self.subTest(wazuh_upgrade=value):
                run, actions, docker, facts = self.run_gate('present', '4.14.1', inputs={'wazuh_upgrade': value})
                self.assertNotEqual(run.returncode, 0)
                self.assertNotIn('docker-info', actions)
                self.assertEqual(docker, [])
                self.assertNotIn('mutation', actions)

    def test_conflicting_or_invalid_release_inputs_are_refused_before_any_docker_command(self):
        for inputs in ({'wazuh_version': '4.14.9', 'wazuh_docker_version': '4.14.1'}, {'wazuh_version': '5.0.0'},
                       {'wazuh_version': '4.14'}, {'wazuh_docker_version': 'latest'}, {'wazuh_version': '4.14.01'}):
            with self.subTest(inputs=inputs):
                run, actions, docker, facts = self.run_gate('absent', inputs=inputs)
                self.assertNotEqual(run.returncode, 0)
                self.assertNotIn('docker-info', actions)
                self.assertEqual(docker, [])
                self.assertNotIn('mutation', actions)

    def test_a_registered_agent_newer_than_the_manager_is_refused_before_the_stack_is_touched(self):
        run, actions, docker, facts = self.run_gate('present', '4.14.1', agents={'001': '4.14.1', '002': '4.14.9'})
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('a registered agent is newer than the central release', run.stdout)
        self.assertNotIn('mutation', actions)

    def test_a_downgrade_request_over_a_newer_registered_agent_is_a_visible_typed_refusal(self):
        for flags in ((), ('--check',)):
            run, actions, docker, facts = self.run_gate('present', '4.14.9', flags=flags)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('a registered agent is newer than the central release', run.stdout)
            self.assertIn('error_kind', run.stdout)
            self.assertNotIn('mutation', actions)

    def test_an_unhealthy_or_unidentifiable_stack_is_never_treated_as_absent(self):
        run, actions, docker, facts = self.run_gate('present', '4.14.1', stopped_daemon='remoted')
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('required manager native daemons are not healthy', run.stdout)
        self.assertNotIn('mutation', actions)

    def test_a_dashboard_or_indexer_on_another_release_refuses_the_gate_before_the_stack_is_touched(self):
        for knob, reason in (('dashboard_release', 'dashboard Wazuh plugin version probe failed'),
                             ('indexer_release', 'indexer effective Wazuh version probe failed')):
            run, actions, docker, facts = self.run_gate('present', '4.14.1', **{knob: '4.14.9'})
            self.assertNotEqual(run.returncode, 0, knob)
            self.assertIn(reason, run.stdout)
            self.assertNotIn('mutation', actions)
        # Accept case: the same stack with both components agreeing with the manager passes.
        run, actions, docker, facts = self.run_gate('present', '4.14.1', dashboard_release='4.14.1', indexer_release='4.14.1')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('mutation', actions)

    def test_a_missing_engine_fails_a_real_run_but_a_check_preview_defers_to_a_fresh_install(self):
        run, actions, docker, facts = self.run_gate('absent', docker_up=False)
        self.assertNotEqual(run.returncode, 0)
        self.assertNotIn('mutation', actions)
        run, actions, docker, facts = self.run_gate('absent', docker_up=False, flags=('--check',))
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(facts['preview_fresh'], True, 'the check-mode preview of a fresh host must be visible to the agents play')
        self.assertEqual([a for a in docker], [], 'no docker command runs without an engine')

    def test_the_gate_runs_under_every_tag_selection_and_a_fresh_stack_needs_its_install_tasks_selected(self):
        run, actions, docker, facts = self.run_gate('present', '4.14.1', flags=('--tags', 'C12'))
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('central', actions, 'the always-tagged gate runs even for a verification-only selection')
        self.assertEqual(facts['planned'], False, 'C12 alone selects no installation')
        run, actions, docker, facts = self.run_gate('present', '4.14.1', inputs={'wazuh_version': '4.14.9'}, flags=('--tags', 'C12'))
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('only explicit central 4.14.1 -> 4.14.9 upgrade is supported', run.stdout)
        run, actions, docker, facts = self.run_gate('absent', flags=('--tags', 'C12'))
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('Fresh Wazuh central tasks require C1/C2/C3 container installation to be selected', run.stdout)
        for tag in ('C1', 'C2', 'C3'):
            run, actions, docker, facts = self.run_gate('absent', flags=('--tags', tag))
            self.assertEqual(run.returncode, 0, (tag, run.stdout))
            self.assertEqual(facts['planned'], True)


class TopologyReceiverTests(unittest.TestCase):
    """The chain topology must make the manager's forwarding rows (C10/C11) applicable.

    Native finding D2: with no log receiver in the inventory the manager does not forward, so C10
    (siem-log-server pin) and C11 (host imfile reader) fail as not-applicable and `topology test --verify`
    has no row filter. The real manager tasks that decide this run over the inventory the topology renders.
    """
    TASKS = ('Gate: siem_forward_port is a TCP port number',
             'Resolve inventory-overridable defaults without shadowing group_vars/host_vars',
             'Resolve forwarding transport defaults under the Wazuh writer',
             "Auto-detect SIEM forward host from this inventory's log-server group",
             "Gate: siem_forward_port matches the inventory log-server's siem_receiver_tcp_port")

    def run_over(self, topology_text):
        topology = yaml.safe_load(topology_text)
        with tempfile.TemporaryDirectory(prefix='wazuh-topology-receiver-') as temporary:
            root = Path(temporary)
            hosts, children = {}, {}
            for number, node in enumerate(topology['nodes'], start=10):
                hosts[node['name']] = {'ansible_connection': 'local', 'ansible_host': '192.0.2.%d' % number}
                for group in node['groups']:
                    children.setdefault(group, {'hosts': {}})['hosts'][node['name']] = {}
            inventory = root / 'inventory.yml'
            inventory.write_text(yaml.safe_dump({'all': {'hosts': hosts, 'children': children}}))
            play = yaml.safe_load((SOURCE / 'wazuh-manager-apply.yml').read_text())[0]
            facts = root / 'facts.json'
            tasks = [dict(picked(play, name)) for name in self.TASKS]
            tasks.append({'name': 'record', 'check_mode': False, 'ansible.builtin.copy': {'dest': str(facts), 'mode': '0600',
                'content': "{{ {'host': siem_forward_host | default(''), 'enabled': siem_forwarding_enabled | bool} | to_json }}"}})
            values = dict(play['vars'], stage='sandbox', ansible_distribution='Ubuntu')
            playbook = root / 'play.yml'
            playbook.write_text(yaml.safe_dump([{'hosts': 'wazuh-manager', 'gather_facts': False, 'vars': values, 'tasks': tasks}], sort_keys=False))
            config = root / 'ansible.cfg'
            config.write_text('[defaults]\nfact_caching=memory\nretry_files_enabled=false\n')
            run = subprocess.run(['ansible-playbook', '-i', str(inventory), str(playbook)], cwd=root, capture_output=True, text=True, timeout=180,
                                 env=dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_LOCAL_TEMP=str(root / 'local'),
                                          ANSIBLE_REMOTE_TEMP=str(root / 'remote'), ANSIBLE_CACHE_PLUGIN='memory', ANSIBLE_NOCOLOR='1'))
            return run, json.loads(facts.read_text()) if facts.exists() else None, hosts

    def test_the_receiver_node_is_the_managers_forward_target_so_c10_and_c11_apply(self):
        text = (REPO / 'docs/topologies/wazuh-version-topology.yaml').read_text()
        run, facts, hosts = self.run_over(text)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(facts, {'host': hosts['wf244-deb']['ansible_host'], 'enabled': True})
        # The rows the receiver makes applicable are the manager's own forwarding rows: C10 pins this alias.
        play = yaml.safe_load((SOURCE / 'wazuh-manager-apply.yml').read_text())[0]
        spec = (REPO / 'docs/verification/wazuh-manager.md').read_text()
        rows = {line.split('|')[1].strip(): line for line in spec.splitlines() if re.match(r'\| C1[01] \|', line)}
        self.assertEqual(sorted(rows), ['C10', 'C11'])
        self.assertIn(play['vars']['siem_forward_alias'], rows['C10'])
        self.assertIn('pilot-wazuh-delivery local', rows['C11'])

    def test_a_topology_without_a_receiver_leaves_forwarding_off_which_is_why_the_chain_failed_natively(self):
        text = (REPO / 'docs/topologies/wazuh-version-topology.yaml').read_text()
        without = text.replace('groups: [sandbox, log-server, audit-log-forwarding, wazuh-fim]', 'groups: [sandbox, wazuh-fim]')
        self.assertNotEqual(without, text)
        run, facts, hosts = self.run_over(without)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(facts, {'host': '', 'enabled': False})


class BundleDownloadTests(unittest.TestCase):
    """D2 (native run 19cfe69b): the official bundle is fetched only when the ACTIVE project needs it.

    The production "check the active project" and "download" tasks run unchanged under real Ansible; the only
    substitution is the bundle URL, a file:// URL (the network leaf), so a download is observable on disk."""
    def run_steps(self, project_present, requested='4.14.9', check_mode=False):
        play = yaml.safe_load((SOURCE / 'wazuh-manager-apply.yml').read_text())[0]
        tasks = [picked(play, 'Step 3: Check whether the active project already exists (spec C1-C3)'),
                 picked(play, 'Step 3: Download the official wazuh-docker release bundle (spec C1-C3)')]
        with tempfile.TemporaryDirectory(prefix='wazuh-bundle-') as temporary:
            root = Path(temporary)
            # A controlled upgrade keeps the project directory of the OLD release (4.14.1) while the requested
            # release is the new one: the case that downloaded an unused second bundle.
            project = root / 'wazuh-docker-4.14.1/single-node'
            if project_present:
                project.mkdir(parents=True)
                (project / 'docker-compose.yml').write_text('services: {}\n')
            bundle = root / 'official-bundle.tar.gz'
            bundle.write_bytes(b'official bundle bytes')
            tasks[1] = dict(tasks[1])
            tasks[1]['ansible.builtin.get_url'] = dict(tasks[1]['ansible.builtin.get_url'], url='file://' + str(bundle))
            tarball = root / ('wazuh-docker-v' + requested + '.tar.gz')
            playbook = root / 'play.yml'
            playbook.write_text(yaml.safe_dump([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                'vars': {'wazuh_single_node_dir': str(project), 'wazuh_docker_tarball': str(tarball),
                         'wazuh_docker_version': requested}, 'tasks': tasks}], sort_keys=False))
            env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(root / 'local'), ANSIBLE_REMOTE_TEMP=str(root / 'remote'),
                       ANSIBLE_NOCOLOR='1', PYTHONDONTWRITEBYTECODE='1')
            run = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook), *(['--check'] if check_mode else [])],
                                 cwd=root, env=env, capture_output=True, text=True, timeout=120)
            recap = re.search(r'localhost\s*: ok=(\d+)\s+changed=(\d+)', run.stdout)
            return run, int(recap.group(2)) if recap else None, tarball.exists()

    def test_an_existing_active_project_means_no_download_and_no_change(self):
        run, changed, downloaded = self.run_steps(project_present=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual((changed, downloaded), (0, False), 'the identical rerun after an upgrade must not fetch a bundle')

    def test_a_missing_active_project_downloads_the_bundle(self):
        run, changed, downloaded = self.run_steps(project_present=False)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual((changed, downloaded), (1, True), 'a fresh host still needs the bundle for its project')

    def test_check_mode_never_downloads(self):
        for present in (True, False):
            with self.subTest(project_present=present):
                run, changed, downloaded = self.run_steps(project_present=present, check_mode=True)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertEqual((changed, downloaded), (0, False))


if __name__ == '__main__':
    unittest.main(verbosity=2)
