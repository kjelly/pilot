"""Real Ansible run of the production manager version gate.

The production tasks (input gates, defaulting, docker pre-flight, the central
coordinator gate, the selection facts) are extracted by name and run unchanged
under real Ansible; the coordinator's `central` action runs for real over the
modeled docker/Wazuh commands. A sentinel task after the gate stands for "the
stack would now be touched". Not native VM evidence.
"""
import json
import os
from pathlib import Path
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
         'Gate: an existing Wazuh central stack already runs the requested release',
         "Reset this play's selected manager installation plan",
         "Mark this run's selected Wazuh manager installation plan",
         'Record whether this check-mode preview covers a fresh central stack',
         'Gate: a fresh central stack requires selected container installation tasks')


def picked(play, name):
    for task in play['pre_tasks']:
        if task.get('name') == name:
            return task
    raise AssertionError('missing production task: ' + name)


class ManagerGateTests(unittest.TestCase):
    def run_gate(self, stack='present', stack_release='4.14.1', docker_up=True, inputs=None, flags=(), agents=None, stopped_daemon=''):
        with tempfile.TemporaryDirectory(prefix='wazuh-manager-gate-') as temporary:
            root = Path(temporary)
            play = yaml.safe_load((SOURCE / 'wazuh-manager-apply.yml').read_text())[0]
            events = root / 'events.jsonl'
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'library': str(SOURCE / 'files/wazuh-transaction.py'), 'events': str(events),
                                            'stack': stack, 'stack_release': stack_release, 'docker_up': docker_up,
                                            'agents': agents, 'stopped_daemon': stopped_daemon}))
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
            values = {'stage': 'sandbox'}
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
        cases = ((('present', '4.14.1'), {'wazuh_version': '4.14.9'}),
                 (('present', '4.14.9'), {}),
                 (('present', '4.14.1'), {'wazuh_docker_version': '4.14.9'}),
                 (('present', '4.14.6'), {'wazuh_version': '4.14.9'}))
        for (stack, release), inputs in cases:
            for flags in ((), ('--check',)):
                with self.subTest(release=release, inputs=inputs, flags=flags):
                    run, actions, docker, facts = self.run_gate(stack, release, inputs=inputs, flags=flags)
                    self.assertNotEqual(run.returncode, 0)
                    self.assertIn('central release change is not supported by this version', run.stdout)
                    self.assertIn('error_kind', run.stdout)
                    self.assertNotIn('mutation', actions, 'no stack task may follow a refused gate')
                    self.assertIsNone(facts)
                    self.assertFalse([a for a in docker if a[1] in ('compose', 'pull', 'stop', 'rm', 'up')], docker)

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

    def test_an_unhealthy_or_unidentifiable_stack_is_never_treated_as_absent(self):
        run, actions, docker, facts = self.run_gate('present', '4.14.1', stopped_daemon='remoted')
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('required manager native daemons are not healthy', run.stdout)
        self.assertNotIn('mutation', actions)

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
        self.assertIn('central release change is not supported', run.stdout)
        run, actions, docker, facts = self.run_gate('absent', flags=('--tags', 'C12'))
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('Fresh Wazuh central tasks require C1/C2/C3 container installation to be selected', run.stdout)
        for tag in ('C1', 'C2', 'C3'):
            run, actions, docker, facts = self.run_gate('absent', flags=('--tags', tag))
            self.assertEqual(run.returncode, 0, (tag, run.stdout))
            self.assertEqual(facts['planned'], True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
