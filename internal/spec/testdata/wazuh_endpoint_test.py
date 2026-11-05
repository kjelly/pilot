"""Real inventory/resolver/ScriptModule binding; no product mutations."""
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


if __name__ == '__main__':
    unittest.main()
