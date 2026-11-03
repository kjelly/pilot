"""Execute the real Wazuh lifecycle/delegation graph using real Ansible.

Native package/Docker/config/service actions are explicit no-op substitutes.
Writer claim/resume/release and post-claim agent policy use the real production
Python library and real flock/files in a disposable directory. These tests
prove graph ordering, cleanup and optional-manager semantics, not daemon health.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml
import importlib.util


REPO = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('wazuh_owner_library', REPO / 'playbooks/apply/files/wazuh-transaction.py')
W = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(W)


WORKER = '''import argparse,importlib.util,json,sys,subprocess
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('action')
for field in ('owner','component','mode','family','manager','version','legacy','agent-id','agent-name','name'):
 p.add_argument('--'+field,default='')
for field in ('confirm-previous-stopped','upgrade','preview','recover','canary'):
 p.add_argument('--'+field,action='store_true')
a=p.parse_args(); settings=json.loads(Path(SETTINGS).read_text())
s=importlib.util.spec_from_file_location('production',settings['library']); w=importlib.util.module_from_spec(s); s.loader.exec_module(w)
host=w.HostWriter(settings['root'])
with open(settings['log'],'a') as out: out.write(json.dumps({'action':a.action,'owner':a.owner,'name':a.name})+'\\n')
class Native:
 def run(self,argv,**kwargs):
  package=settings['installed']
  return subprocess.CompletedProcess(argv,0,'install ok installed\\t'+package+'\\tamd64','') if package else subprocess.CompletedProcess(argv,1,'','dpkg-query: no packages found matching wazuh-agent\\n')
try:
 if a.action=='writer-claim': result=host.claim(a.owner,a.component,a.mode)
 elif a.action=='writer-resume': result=host.resume(a.owner,a.component,a.mode,a.confirm_previous_stopped)
 elif a.action=='writer-release': result=host.release(a.owner)
 elif a.action=='agent-check':
  if settings.get('policy_failure'): raise w.Refused('controlled policy refusal')
  result=w.Agent('Debian',root=settings['root'],runner=Native()).check(a.manager,a.version,a.upgrade,a.owner or None)
 elif a.action=='central':
  with host.guard(a.owner,'central'): result={'changed':settings['central_change'],'fresh':False,'directory':settings['project'],'version':'4.14.9'}
 elif a.action=='central-verify':
  with host.reader('central',a.owner or None): result={'pass':True}
 elif a.action=='native-mutation':
  marker=host.inspect()['writer']
  with host.guard(marker['owner'],settings['component']): result={'native_action_substituted':True}
 elif a.action=='controlled-recovery-failure': raise w.Refused('controlled recovery failure')
 else: raise w.Refused('unexpected delegated or native action: '+a.action)
 print(json.dumps(result))
except w.Refused as error:
 print(str(error)); sys.exit(1)
'''


class WriterTaskGraphTests(unittest.TestCase):
    def graph(self, role='wazuh-fim', scenario='normal', flags=(), installed='4.14.1-1'):
        with tempfile.TemporaryDirectory(prefix='pilot-wazuh-owner-') as temporary:
            root = Path(temporary)
            component = 'agent' if role == 'wazuh-fim' else 'central'
            ledger = root / 'ledger'
            owner = '9' * 32
            actor = W.HostWriter(ledger)
            if scenario in ('failed-claim', 'resume', 'wrong-resume', 'failed-recover'):
                actor.claim(owner, component)
            if scenario == 'failed-recover':
                W.atomic_json(ledger / 'agent-active.json', {'kind': 'agent', 'owner': owner, 'phase': 'installing'})
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'library': str(REPO / 'playbooks/apply/files/wazuh-transaction.py'),
                                            'root': str(ledger), 'log': str(root / 'events.jsonl'),
                                            'component': component, 'installed': installed,
                                            'central_change': scenario != 'central-normal',
                                            'project': str(root / 'project'), 'policy_failure': scenario == 'early-fail'}))
            worker = root / 'worker.py'
            worker.write_text('SETTINGS=' + repr(str(settings)) + '\n' + WORKER)
            play = yaml.safe_load((REPO / 'playbooks/apply' / (role + '-apply.yml')).read_text())[0]
            play.update(connection='local', become=False, gather_facts=False)
            play['vars'].update(target_group='all', ansible_os_family='Debian', ansible_architecture='x86_64',
                                ansible_distribution='Ubuntu', ansible_distribution_version='22.04',
                                ansible_distribution_major_version='22')
            if scenario in ('resume', 'wrong-resume', 'failed-recover'):
                play['vars'].update(wazuh_writer_resume_owner=owner if scenario != 'wrong-resume' else '8' * 32,
                                    wazuh_confirm_previous_operation_stopped=True)
            if scenario == 'failed-recover':
                play['vars']['wazuh_recovery_owner'] = owner
            def replace_action(task, action):
                for key in list(task):
                    if '.' in key:
                        del task[key]
                task['ansible.builtin.command'] = {'argv': ['python3', str(worker), action, '--name', task['name']]}
                task.setdefault('changed_when', False)
                if 'until' in task:
                    # Readiness is a declared native substitute, not a network
                    # probe. Retain the loop and task result gate using rc.
                    task['until'] = task['register'] + ' is succeeded'
            def rewrite(tasks):
                for task in tasks:
                    for key in ('block', 'rescue', 'always'):
                        if key in task:
                            rewrite(task[key])
                    if 'ansible.builtin.script' in task:
                        cmd = task['ansible.builtin.script']['cmd']
                        if 'wazuh-transaction.py' in cmd:
                            del task['ansible.builtin.script']
                            tail = cmd[cmd.index('wazuh-transaction.py') + len('wazuh-transaction.py'):]
                            task['ansible.builtin.command'] = {'cmd': 'python3 ' + str(worker) + ' ' + tail}
                        else:
                            replace_action(task, 'native-mutation')
                    elif 'ansible.builtin.command' in task:
                        command = task['ansible.builtin.command']
                        if isinstance(command, dict) and command.get('argv', [''])[0] == '/usr/local/sbin/pilot-wazuh-transaction':
                            command['argv'] = ['python3', str(worker)] + command['argv'][1:]
                        elif 'Allocate an independent owner' not in task['name']:
                            replace_action(task, 'native-mutation')
                    elif 'ansible.builtin.include_tasks' in task:
                        include = task['ansible.builtin.include_tasks']
                        filename = include if isinstance(include, str) else include['file']
                        action = 'controlled-recovery-failure' if scenario == 'failed-recover' and 'wazuh-agent-recover' in filename else 'native-mutation'
                        replace_action(task, action)
                    elif 'ansible.builtin.stat' in task:
                        task['ansible.builtin.stat']['path'] = str(root / 'absent-client.keys')
                    elif any('.' in key and key not in ('ansible.builtin.assert', 'ansible.builtin.debug',
                                                       'ansible.builtin.fail', 'ansible.builtin.meta',
                                                       'ansible.builtin.set_fact') for key in task):
                        replace_action(task, 'native-mutation')
            rewrite(play.get('pre_tasks', []))
            rewrite(play['tasks'])
            filename = root / 'play.yml'
            filename.write_text(yaml.safe_dump([play], sort_keys=False))
            config = root / 'ansible.cfg'
            config.write_text('[defaults]\nfact_caching=memory\nretry_files_enabled=false\n')
            env = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_LOCAL_TEMP=str(root / 'local'),
                       ANSIBLE_REMOTE_TEMP=str(root / 'remote'), ANSIBLE_CACHE_PLUGIN='memory')
            run = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(filename), *flags], env=env,
                                 cwd=root, text=True, capture_output=True, timeout=90)
            log = root / 'events.jsonl'
            events = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            state = actor.inspect()
            return run, events, state

    def test_actual_no_manager_graph_full_and_check_preserves_optional_enrollment(self):
        for installed, flags in (('4.14.1-1', ()), ('4.14.1-1', ('--check',)),
                                 ('4.14.1-1', ('--tags', 'C1')), ('4.14.1-1', ('--tags', 'C5')),
                                 ('', ()), ('', ('--check',))):
            result, events, state = self.graph(flags=flags, installed=installed)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIsNone(state['writer'])
            actions = [event['action'] for event in events]
            self.assertEqual(actions[0], 'writer-claim')
            self.assertLess(actions.index('writer-claim'), actions.index('agent-check'))
            self.assertEqual(actions[-1], 'writer-release')
            self.assertNotIn('manager-version', actions)

    def test_early_policy_failure_releases_only_its_completed_operation(self):
        result, events, state = self.graph(scenario='early-fail')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('controlled policy refusal', result.stdout)
        self.assertIsNone(state['writer'])
        self.assertEqual([item['action'] for item in events], ['writer-claim', 'agent-check', 'writer-release'])

    def test_standalone_C1_cannot_upgrade_retained_enrollment_without_manager_observation(self):
        result, events, state = self.graph(flags=('--tags', 'C1', '-e', 'wazuh_version=4.14.9',
                                                 '-e', 'wazuh_upgrade=true'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('controlled agent upgrade requires an observed manager version', result.stdout)
        self.assertIsNone(state['writer'])
        self.assertEqual([item['action'] for item in events], ['writer-claim', 'agent-check', 'writer-release'])

    def test_failed_claim_never_runs_mutators_or_releases_the_other_owner(self):
        result, events, state = self.graph(scenario='failed-claim')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([item['action'] for item in events], ['writer-claim'])
        self.assertEqual(state['writer']['owner'], '9' * 32)

    def test_same_owner_explicit_resume_and_wrong_owner(self):
        result, events, state = self.graph(scenario='resume')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(events[0]['action'], 'writer-resume')
        self.assertIsNone(state['writer'])
        result, events, state = self.graph(scenario='wrong-resume')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([item['action'] for item in events], ['writer-resume'])
        self.assertEqual(state['writer']['owner'], '9' * 32)

    def test_failed_recovery_retains_its_writer_and_component_journal(self):
        result, events, state = self.graph(scenario='failed-recover')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('controlled recovery failure', result.stdout)
        self.assertIn('unfinished component journal prevents writer release', result.stdout)
        self.assertEqual(state['writer']['owner'], '9' * 32)
        self.assertEqual(state['journals'][0]['owner'], '9' * 32)

    def test_completed_central_version_path_releases_before_end_host(self):
        result, events, state = self.graph(role='wazuh-manager')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([item['action'] for item in events][-2:], ['central', 'writer-release'])
        self.assertIsNone(state['writer'])

    def test_ordinary_central_config_and_final_proof_remain_under_writer(self):
        result, events, state = self.graph(role='wazuh-manager', scenario='central-normal')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        actions = [event['action'] for event in events]
        self.assertIn('native-mutation', actions[actions.index('central') + 1:])
        self.assertEqual(actions[-2:], ['central-verify', 'writer-release'])
        self.assertIsNone(state['writer'])

    def test_fresh_selection_refusal_keeps_ownership_through_early_exit(self):
        result, events, state = self.graph(installed='', flags=('--skip-tags', 'C1,C2'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Fresh Wazuh agent tasks require', result.stdout)
        self.assertIsNone(state['writer'])
        self.assertEqual([item['action'] for item in events], ['writer-claim', 'agent-check', 'writer-release'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
