"""Real inventory/resolver/ScriptModule binding; no product mutations."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import yaml

REPO=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('wazuh_endpoint',REPO/'playbooks/apply/files/wazuh-endpoint.py')
endpoint=importlib.util.module_from_spec(spec);spec.loader.exec_module(endpoint)


REPO = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('wazuh_endpoint', REPO / 'playbooks/apply/files/wazuh-endpoint.py')
endpoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(endpoint)

BINDING = ('Resolve the exact inventory manager used for native version observation',
           'Gate: native manager observation uses an inventory manager',
           'Bind enrollment to its unique trusted inventory manager',
           'Retain the manager transport bound before native observation',
           "Step 5b: Pin target is the address bound to the observed inventory manager (spec C7)")


def picked(play, name):
    def walk(items):
        for task in items:
            if task.get('name') == name:
                return task
            for field in ('block', 'rescue', 'always'):
                found = walk(task.get(field, []))
                if found:
                    return found
    for section in ('pre_tasks', 'tasks'):
        found = walk(play.get(section, []))
        if found:
            return found
    raise AssertionError('missing production task: ' + name)


class EndpointTests(unittest.TestCase):
    def test_identity_uses_inventory_evidence_and_canonical_numeric_transport(self):
        records = [{'name': 'manager-a', 'address': '192.0.2.15', 'fqdn': 'manager.example.test'}]
        for raw in ('manager-a', 'manager.example.test', 'MANAGER.Example.TEST', '192.0.2.15'):
            request = {'raw': raw, 'records': records, 'manager': 'manager-a'}
            chosen = endpoint.select(request)
            self.assertEqual(chosen['transport'], '192.0.2.15')
            self.assertEqual(endpoint.bind(dict(request, resolved='192.0.2.15'))['address'], '192.0.2.15')
        request = {'raw': '2001:0db8:0:0:0:0:0:15', 'records': [
            {'name': 'manager-a', 'address': '2001:db8::15', 'fqdn': 'manager.example.test'}], 'manager': 'manager-a'}
        self.assertEqual(endpoint.bind(dict(request, resolved='2001:db8::15'))['address'], '2001:db8::15')
        for raw, changes in (
            ('unknown.example.test', {}),
            ('MANAGER-A', {}),
            ('192.0.2.16', {}),
            ('manager.example.test', {'manager': 'manager-b'}),
            ('manager.example.test', {'records': records + [dict(records[0], name='manager-b')]}),
            ('manager.example.test', {'records': records + [dict(records[0], name='manager-b', fqdn='MANAGER.EXAMPLE.TEST')]}),
            ('manager-a', {'records': records + [{'name': 'manager-b', 'address': '192.0.2.15', 'fqdn': 'other.test'}]}),
        ):
            request = dict(raw=raw, records=records, manager='manager-a')
            request.update(changes)
            with self.subTest(raw=raw, changes=changes), self.assertRaises(ValueError):
                chosen = endpoint.select(request)
                endpoint.bind(dict(request, resolved=chosen['transport']))

    def test_dns_coincidence_cannot_authorize_an_unknown_manager_name(self):
        records = [{'name': 'manager-a', 'address': '192.0.2.15', 'fqdn': 'manager.example.test'}]
        request = {'raw': 'untrusted.example.test', 'records': records, 'manager': 'manager-a', 'resolved': '192.0.2.15'}
        with mock.patch.object(endpoint.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('192.0.2.15', 0))]) as dns:
            with self.assertRaisesRegex(ValueError, 'trusted inventory association'):
                endpoint.bind(request)
            dns.assert_not_called()

    def test_the_command_line_prints_only_a_bounded_failure_and_never_the_input(self):
        run = subprocess.run(['python3', str(REPO / 'playbooks/apply/files/wazuh-endpoint.py'), 'bind',
                              json.dumps({'raw': 'SECRET-HOST', 'records': [], 'manager': 'm', 'resolved': '192.0.2.1'})],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertNotIn('SECRET-HOST', run.stdout + run.stderr)
        self.assertEqual(json.loads(run.stdout), {'error': 'Wazuh endpoint identity is unknown, ambiguous or different'})

    def test_actual_ansible_include_binds_the_selected_manager_endpoint(self):
        fim = yaml.safe_load((REPO / 'playbooks/apply/wazuh-fim-apply.yml').read_text())[0]
        # This executes the exact production tasks, shared resolver and native
        # ScriptModule/shell. Only inventory data are synthetic.
        with tempfile.TemporaryDirectory(prefix='wazuh-endpoint-graph-') as temporary:
            root = Path(temporary); (root / 'tasks').mkdir(); (root / 'files').mkdir()
            for name in ('wazuh-endpoint-resolve.yml', 'resolve-hosts-alias-target.yml'):
                shutil.copy2(REPO / 'playbooks/apply/tasks' / name, root / 'tasks' / name)
            shutil.copy2(REPO / 'playbooks/apply/files/wazuh-endpoint.py', root / 'files/wazuh-endpoint.py')
            inventory = {'all': {'hosts': {'observer': {'ansible_connection': 'local'},
                'manager-a': {'ansible_host': '192.0.2.15', 'ansible_fqdn': 'manager.example.test'},
                'manager-b': {'ansible_host': '192.0.2.16', 'ansible_fqdn': 'other.example.test'},
                'manager-external': {'ansible_host': '192.0.2.17', 'ansible_fqdn': 'external.example.test'},
                'manager-six': {'ansible_host': '2001:db8::15', 'ansible_fqdn': 'six.example.test'},
                'manager-local': {'ansible_host': 'localhost', 'ansible_fqdn': 'local.example.test'},
                'manager-collision': {'ansible_host': '192.0.2.18', 'ansible_fqdn': 'MANAGER.EXAMPLE.TEST'}},
                'children': {'wazuh-manager': {'hosts': {'manager-a': {}, 'manager-b': {}}}}}}
            inv = root / 'inventory.yml'; inv.write_text(yaml.safe_dump(inventory))
            cases = [
                ('numeric', '192.0.2.15', 'manager-a', True, '192.0.2.15'),
                ('fqdn', 'manager.example.test', 'manager-a', True, '192.0.2.15'),
                ('mixed-case-fqdn', 'MANAGER.Example.TEST', 'manager-a', True, '192.0.2.15'),
                ('mixed-case-hostname', 'LOCALHOST', 'manager-local', True, '127.0.0.1'),
                ('normalized-collision', 'manager.example.test', 'manager-collision', False, None),
                ('opaque-key-case', 'MANAGER-A', 'manager-a', False, None),
                ('alias', 'manager-a', 'manager-a', True, '192.0.2.15'),
                ('outside-group-fqdn', 'external.example.test', 'manager-external', True, '192.0.2.17'),
                ('canonical-ipv6', '2001:0db8:0:0:0:0:0:15', 'manager-six', True, '2001:db8::15'),
                ('wrong-manager', 'manager.example.test', 'manager-b', False, None),
                ('wrong-address', '192.0.2.16', 'manager-a', False, None),
                ('unknown-name', 'unknown.example.test', 'manager-a', False, None),
            ]
            for check in (False, True):
                plays = []
                for name, raw, manager, success, address in cases:
                    result = root / (name + str(check) + '.json')
                    binding = [picked(fim, task) for task in BINDING]
                    plays.append({'hosts': 'observer', 'gather_facts': False,
                        'vars': {'wazuh_manager_host': raw, 'wazuh_manager_inventory_host': manager,
                                 'wazuh_enrollment_enabled': True, 'wazuh_manager_bound_address': ''},
                        'tasks': [{'ansible.builtin.set_fact': {'bound': False}},
                                  {'block': binding + [{'ansible.builtin.set_fact': {'bound': True}}],
                                   'rescue': [{'ansible.builtin.set_fact': {'bound': False}}]},
                                  {'ansible.builtin.copy': {'dest': str(result), 'mode': '0600',
                                   'content': "{{ {'bound': bound, 'address': hosts_alias_resolved_ip if bound else ''} | to_json }}"},
                                   'check_mode': False}]})
                play = root / ('check.yml' if check else 'apply.yml'); play.write_text(yaml.safe_dump(plays, sort_keys=False))
                run = subprocess.run(['ansible-playbook', '-i', str(inv), str(play), *(['--check'] if check else [])],
                    cwd=REPO, capture_output=True, text=True, timeout=150,
                    env=dict(os.environ, ANSIBLE_CONFIG=str(REPO / 'ansible.cfg'), ANSIBLE_CACHE_PLUGIN='memory',
                             ANSIBLE_LOCAL_TEMP=str(root / 'local'), ANSIBLE_REMOTE_TEMP=str(root / 'remote'),
                             ANSIBLE_NOCOLOR='1', PYTHONDONTWRITEBYTECODE='1'))
                self.assertEqual(run.returncode, 0, (run.stdout, run.stderr))
                for name, raw, manager, success, address in cases:
                    result = json.loads((root / (name + str(check) + '.json')).read_text())
                    self.assertEqual(result, {'bound': success, 'address': address if success else ''}, (name, check))


    def test_a_refused_binding_shows_only_its_typed_reason_through_the_real_script_module(self):
        # The resolver hides its helper runs (the argument is the inventory evidence) but must still say why a
        # binding was refused. Real ScriptModule, real production tasks, a real failing helper (rc 2).
        reason = 'Wazuh endpoint identity is unknown, ambiguous or different'
        with tempfile.TemporaryDirectory(prefix='wazuh-endpoint-reason-') as temporary:
            root = Path(temporary); (root / 'tasks').mkdir(); (root / 'files').mkdir()
            for name in ('wazuh-endpoint-resolve.yml', 'resolve-hosts-alias-target.yml'):
                shutil.copy2(REPO / 'playbooks/apply/tasks' / name, root / 'tasks' / name)
            shutil.copy2(REPO / 'playbooks/apply/files/wazuh-endpoint.py', root / 'files/wazuh-endpoint.py')
            inv = root / 'inventory.yml'
            inv.write_text(yaml.safe_dump({'all': {'hosts': {'observer': {'ansible_connection': 'local'},
                'manager-a': {'ansible_host': '192.0.2.15', 'ansible_fqdn': 'manager.example.test'}}}}))
            def run(raw, check=False):
                play = root / 'play.yml'
                play.write_text(yaml.safe_dump([{'hosts': 'observer', 'gather_facts': False,
                    'vars': {'wazuh_endpoint_value': raw, 'wazuh_endpoint_manager': 'manager-a', 'wazuh_endpoint_inventory': ['manager-a']},
                    'tasks': [{'ansible.builtin.include_tasks': {'file': 'tasks/wazuh-endpoint-resolve.yml', 'apply': {'tags': ['always']}}}]}]))
                return subprocess.run(['ansible-playbook', '-i', str(inv), str(play), *(['--check'] if check else [])], cwd=REPO,
                    capture_output=True, text=True, timeout=150,
                    env=dict(os.environ, ANSIBLE_CONFIG=str(REPO / 'ansible.cfg'), ANSIBLE_CACHE_PLUGIN='memory',
                             ANSIBLE_LOCAL_TEMP=str(root / 'local'), ANSIBLE_REMOTE_TEMP=str(root / 'remote'), ANSIBLE_NOCOLOR='1',
                             PYTHONDONTWRITEBYTECODE='1'))
            # Trigger: an association failure (an unknown NAME) and a binding failure (an external numeric
            # address that is not the inventory manager), in apply and in check mode.
            for raw, task in (('unknown.example.test', 'Refuse an endpoint the inventory does not vouch for'),
                              ('203.0.113.5', 'Refuse a transport that is not the unique inventory manager')):
                for check in (False, True):
                    with self.subTest(raw=raw, check=check):
                        result = run(raw, check)
                        self.assertNotEqual(result.returncode, 0)
                        shown = result.stdout + result.stderr
                        self.assertIn(reason, shown)
                        self.assertIn(task, shown, 'the refusal must come from the typed-reason task, not a censored helper run')
                        self.assertNotIn('the output has been hidden', shown.split(task, 1)[1].split('PLAY RECAP')[0])
                        # Nothing of the evidence leaks. (The shared resolver's own task titles name the address
                        # being resolved; that is not part of the refusal, so the check starts at the refusal task.)
                        refusal = shown.split('TASK [' + task, 1)[1]
                        for secret in (raw, '192.0.2.15', 'manager.example.test', '"records"', 'files/wazuh-endpoint.py'):
                            self.assertNotIn(secret, refusal, secret)
                        self.assertNotIn('"records"', shown)
            # Accept: the inventory manager binds, silently (the helper output stays censored).
            result = run('192.0.2.15')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('"records"', result.stdout)
            self.assertNotIn('FAILED!', result.stdout, 'no refusal task may fire for a bound manager')
            for task in ('Refuse an endpoint the inventory does not vouch for', 'Refuse a transport that is not the unique inventory manager'):
                self.assertRegex(result.stdout, r'TASK \[' + task + r'[^\n]*\n(?:skipping: \[observer\])', task)

    def test_a_helper_that_cannot_run_still_reports_a_bounded_generic_reason(self):
        # A helper that dies with traceback-like text on stdout and no typed error, in each of its two runs.
        # The first stub breaks `select`; the second answers `select` correctly and breaks `bind`.
        stubs = {
            'select': ('#!/usr/bin/env python3\nimport sys\nprint("Traceback SECRET_ARGUMENT_TEXT")\nsys.exit(1)\n', 'Wazuh endpoint association failed'),
            'bind': ('#!/usr/bin/env python3\nimport json, sys\nif sys.argv[1] == "select":\n    print(json.dumps({"transport": "192.0.2.15"}))\n'
                     '    sys.exit(0)\nprint("Traceback SECRET_ARGUMENT_TEXT")\nsys.exit(1)\n', 'Wazuh endpoint binding failed'),
        }
        for phase, (helper, expected) in stubs.items():
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(prefix='wazuh-endpoint-broken-') as temporary:
                root = Path(temporary); (root / 'tasks').mkdir(); (root / 'files').mkdir()
                for name in ('wazuh-endpoint-resolve.yml', 'resolve-hosts-alias-target.yml'):
                    shutil.copy2(REPO / 'playbooks/apply/tasks' / name, root / 'tasks' / name)
                (root / 'files/wazuh-endpoint.py').write_text(helper)
                inv = root / 'inventory.yml'
                inv.write_text(yaml.safe_dump({'all': {'hosts': {'observer': {'ansible_connection': 'local'}}}}))
                play = root / 'play.yml'
                play.write_text(yaml.safe_dump([{'hosts': 'observer', 'gather_facts': False,
                    'vars': {'wazuh_endpoint_value': '192.0.2.15', 'wazuh_endpoint_manager': '', 'wazuh_endpoint_inventory': []},
                    'tasks': [{'ansible.builtin.include_tasks': {'file': 'tasks/wazuh-endpoint-resolve.yml', 'apply': {'tags': ['always']}}}]}]))
                result = subprocess.run(['ansible-playbook', '-i', str(inv), str(play)], cwd=REPO, capture_output=True, text=True, timeout=150,
                    env=dict(os.environ, ANSIBLE_CONFIG=str(REPO / 'ansible.cfg'), ANSIBLE_CACHE_PLUGIN='memory',
                             ANSIBLE_LOCAL_TEMP=str(root / 'local'), ANSIBLE_REMOTE_TEMP=str(root / 'remote'), ANSIBLE_NOCOLOR='1'))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stdout)
                self.assertNotIn('SECRET_ARGUMENT_TEXT', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

    def test_actual_ansible_include_binds_selected_manager_receiver_and_preview(self):
        from wazuh_manager_script_args_test import picked
        fim=yaml.safe_load((REPO/'playbooks/apply/wazuh-fim-apply.yml').read_text())[0]
        # This executes the exact task include, shared resolver and native
        # ScriptModule/shell. Only inventory data are synthetic.
        with tempfile.TemporaryDirectory(prefix='wazuh-endpoint-graph-') as temporary:
            root=Path(temporary);(root/'tasks').mkdir();(root/'files').mkdir()
            for name in ('wazuh-endpoint-resolve.yml','resolve-hosts-alias-target.yml'):
                shutil.copy2(REPO/'playbooks/apply/tasks'/name,root/'tasks'/name)
            shutil.copy2(REPO/'playbooks/apply/files/wazuh-endpoint.py',root/'files/wazuh-endpoint.py')
            inventory={'all':{'hosts':{'observer':{'ansible_connection':'local'},
                'manager-a':{'ansible_host':'192.0.2.15','ansible_fqdn':'manager.example.test'},
                'manager-b':{'ansible_host':'192.0.2.16','ansible_fqdn':'other.example.test'},
                'manager-external':{'ansible_host':'192.0.2.17','ansible_fqdn':'external.example.test'},
                'manager-six':{'ansible_host':'2001:db8::15','ansible_fqdn':'six.example.test'},
                'manager-local':{'ansible_host':'localhost','ansible_fqdn':'local.example.test'},
                'manager-collision':{'ansible_host':'192.0.2.18','ansible_fqdn':'MANAGER.EXAMPLE.TEST'}},
                'children':{'wazuh-manager':{'hosts':{'manager-a':{},'manager-b':{}}}}}}
            inv=root/'inventory.yml';inv.write_text(yaml.safe_dump(inventory))
            cases=[
                ('numeric','192.0.2.15','manager-a',True,'192.0.2.15'),
                ('fqdn','manager.example.test','manager-a',True,'192.0.2.15'),
                ('mixed-case-fqdn','MANAGER.Example.TEST','manager-a',True,'192.0.2.15'),
                ('mixed-case-hostname','LOCALHOST','manager-local',True,'127.0.0.1'),
                ('normalized-collision','manager.example.test','manager-collision',False,None),
                ('opaque-key-case','MANAGER-A','manager-a',False,None),
                ('alias','manager-a','manager-a',True,'192.0.2.15'),
                ('outside-group-fqdn','external.example.test','manager-external',True,'192.0.2.17'),
                ('canonical-ipv6','2001:0db8:0:0:0:0:0:15','manager-six',True,'2001:db8::15'),
                ('wrong-manager','manager.example.test','manager-b',False,None),
                ('wrong-address','192.0.2.16','manager-a',False,None),
                ('unknown-name','unknown.example.test','manager-a',False,None),
                ('receiver-fqdn','manager.example.test','',True,'192.0.2.15'),
                ('receiver-alias','manager-a','',True,'192.0.2.15'),
                ('receiver-ip','192.0.2.15','',True,'192.0.2.15'),
            ]
            for check in (False,True):
                plays=[]
                for name,raw,manager,success,address in cases:
                    result=root/(name+str(check)+'.json')
                    include={'ansible.builtin.include_tasks':{'file':'tasks/wazuh-endpoint-resolve.yml',
                        'apply':{'tags':['always']}},'tags':['always']}
                    binding=[include]
                    if manager:
                        binding=[picked(fim,name) for name in (
                            'Resolve the exact inventory manager used for native version observation',
                            'Gate: native manager observation uses an inventory manager',
                            'Bind enrollment to its unique trusted inventory manager',
                            'Retain the manager transport bound before native observation',
                            'Step 5b: Resolve wazuh_manager_host for the /etc/hosts pin (spec C7)')]
                    plays.append({'hosts':'observer','gather_facts':False,
                        'vars':{'wazuh_manager_host':raw,'wazuh_manager_inventory_host':manager,
                                'wazuh_enrollment_enabled':True,
                                'wazuh_endpoint_value':raw,'wazuh_endpoint_manager':manager,
                                'wazuh_endpoint_inventory':['manager-a','manager-b']},
                        'tasks':[{'ansible.builtin.set_fact':{'bound':False}},
                            {'block':binding+[{'ansible.builtin.set_fact':{'bound':True}}],
                             'rescue':[{'ansible.builtin.set_fact':{'bound':False}}]},
                            {'ansible.builtin.copy':{'dest':str(result),'mode':'0600',
                             'content':"{{ {'bound':bound, 'address':wazuh_endpoint_address if bound else ''} | to_json }}"},
                             'check_mode':False}]})
                play=root/('check.yml' if check else 'apply.yml');play.write_text(yaml.safe_dump(plays,sort_keys=False))
                run=subprocess.run(['ansible-playbook','-i',str(inv),str(play),*(['--check'] if check else [])],
                    cwd=REPO,capture_output=True,text=True,timeout=150,
                    env=dict(os.environ,ANSIBLE_CONFIG=str(REPO/'ansible.cfg'),ANSIBLE_CACHE_PLUGIN='memory',
                        ANSIBLE_LOCAL_TEMP=str(root/'local'),ANSIBLE_REMOTE_TEMP=str(root/'remote'),
                        ANSIBLE_NOCOLOR='1',PYTHONDONTWRITEBYTECODE='1'))
                self.assertEqual(run.returncode,0,(run.stdout,run.stderr))
                for name,raw,manager,success,address in cases:
                    result=json.loads((root/(name+str(check)+'.json')).read_text())
                    self.assertEqual(result,{'bound':success,'address':address if success else ''},name)


    def test_actual_selected_receiver_request_reaches_script_with_bound_address(self):
        from wazuh_manager_script_args_test import picked, RECEIVER, OWNER
        import shlex
        source=yaml.safe_load((REPO/'playbooks/apply/wazuh-manager-apply.yml').read_text())[0]
        names=["Reset this play's actual forwarding selection",
               'Mark selected forwarding intent without granting container authority',
               "Reset this invocation's bound receiver transport",
               'Bind selected forwarding transport independently from TLS identity',
               'Retain the receiver address before version and receipt admission',
               'Build the secret-free selected reader request',
               "Reset this play's selected manager replacement plan",
               "Mark this run's selected Wazuh manager installation plan"]
        with tempfile.TemporaryDirectory(prefix='wazuh-endpoint-request-') as temporary:
            root=Path(temporary);(root/'tasks').mkdir();(root/'files').mkdir()
            for helper in ('wazuh-endpoint-resolve.yml','resolve-hosts-alias-target.yml'):
                shutil.copy2(REPO/'playbooks/apply/tasks'/helper,root/'tasks'/helper)
            shutil.copy2(REPO/'playbooks/apply/files/wazuh-endpoint.py',root/'files/wazuh-endpoint.py')
            receiver=root/'receiver.py';receiver.write_text(RECEIVER)
            inv=root/'inventory.yml';inv.write_text(yaml.safe_dump({'all':{'hosts':{
                'observer':{'ansible_connection':'local'},'receiver':{
                    'ansible_host':'192.0.2.15','ansible_fqdn':'receiver.example.test'}}}}))
            for tag,check,recover in (('C10',False,False),('C11',True,False),('C12',False,False),('C10',False,True)):
                command=picked(source,'Inspect compatibility or execute the explicitly authorized central upgrade')
                path=root/(tag+str(recover)+'.json')
                command['ansible.builtin.script']['cmd']=command['ansible.builtin.script']['cmd'].replace(
                    'files/wazuh-transaction.py',shlex.quote(str(receiver)),1)
                command['environment']={'WAZUH_ARGV_RECORD':str(path)}
                values={'siem_forwarding_enabled':True,'siem_forward_host':
                    'unused.invalid.test' if tag=='C12' or recover else 'receiver.example.test',
                    'siem_forward_transport':'tcp','siem_forward_port':514,
                    'wazuh_reader_tools':{},'wazuh_reader_checker_hash':'b'*64,
                    'wazuh_reader_operation':{'stdout':'d'*32},'wazuh_preview_assets':{'transport_fixture':True},
                    'wazuh_writer_owner':OWNER,'wazuh_docker_version':'4.14.9','wazuh_recover':recover,'docker_pre':{'rc':0}}
                play=root/(tag+str(recover)+'.yml');play.write_text(yaml.safe_dump([{
                    'hosts':'observer','gather_facts':False,'vars':values,
                    'tasks':[picked(source,name) for name in names]+[command]}],sort_keys=False))
                run=subprocess.run(['ansible-playbook','-i',str(inv),str(play),'--tags',tag,
                    *(['--check'] if check else [])],cwd=REPO,capture_output=True,text=True,timeout=90,
                    env=dict(os.environ,ANSIBLE_CONFIG=str(REPO/'ansible.cfg'),ANSIBLE_CACHE_PLUGIN='memory',
                             ANSIBLE_LOCAL_TEMP=str(root/'local'),ANSIBLE_REMOTE_TEMP=str(root/'remote')))
                self.assertEqual(run.returncode,0,(run.stdout,run.stderr))
                argv=json.loads(path.read_text())['argv']
                request=json.loads(argv[argv.index('--reader-desired-json')+1])
                self.assertEqual(request['host'],values['siem_forward_host'])
                self.assertEqual(request['selected'],tag!='C12')
                self.assertEqual(request['address'],'192.0.2.15' if tag!='C12' and not recover else '')
                self.assertEqual('--preview' in argv,check)
                self.assertEqual('--operation' in argv,check)
                if check:self.assertEqual(argv[argv.index('--operation')+1],'d'*32)
                self.assertEqual('--preview-tools-json' in argv,check)
                if check:self.assertEqual(json.loads(argv[argv.index('--preview-tools-json')+1]),{'transport_fixture':True})
                self.assertNotIn('--upgrade',argv,'C10/C11 cannot grant component upgrade authority')


if __name__=='__main__':unittest.main()
