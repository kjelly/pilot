#!/usr/bin/env python3
"""Execute the exact setup script against a typed in-process IPA test seam.

This is behavioral harness evidence, not a native daemon or access claim.
Captured before-JSON metadata preserves the real tuple/bool attribute types;
scoped policy values below are explicit synthetic scenario inputs.
"""
import contextlib
import copy
import io
import json
from pathlib import Path
import runpy
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'playbooks/test/fixtures/files/gateway-scope-retirement-setup.py'
METADATA = json.loads((ROOT / 'scripts/testdata/freeipa-gateway-scope/native-authorization-types.json').read_text())


class NotFound(Exception):
    pass


class API:
    def __init__(self, native):
        self.native = native
        self.rules = {('hbacrule', 'allow_all'): {'ipaenabledflag': [True]}}
        self.mutations = []
        self.failure = None
        self.Command = self
        self.Backend = types.SimpleNamespace(rpcclient=types.SimpleNamespace(connect=lambda: None))
        self.descriptors = {}
        for record in METADATA['records']:
            for field, attribute in record['attributes'].items():
                self.descriptors[field] = attribute['native_type']

    def bootstrap(self, **options):
        pass

    def finalize(self):
        pass

    def result(self, rule):
        def represent(field, value):
            if type(value) is list and self.native:
                # The captured fields explicitly say tuple. Other synthetic
                # optional attributes use the same native tuple seam.
                descriptor = self.descriptors.get(field, {'type': 'tuple'})
                if descriptor['type'] != 'tuple':
                    raise AssertionError('capture no longer establishes native tuples')
                return tuple(value)
            return copy.deepcopy(value)
        return {field: represent(field, value) for field, value in rule.items()}

    def __getitem__(self, command):
        def call(name, **options):
            kind, operation = command.split('_', 1)
            key = kind, name
            if operation == 'show':
                if key not in self.rules:
                    raise NotFound()
                return {'result': self.result(self.rules[key])}
            self.mutations.append((command, name, copy.deepcopy(options)))
            if operation == 'add':
                self.rules[key] = {'ipaenabledflag': [True]}
                if kind == 'sudorule':
                    self.rules[key]['cmdcategory'] = [options['cmdcategory']]
            elif operation == 'add_user':
                self.rules[key].setdefault('memberuser_user', []).extend(options['user'])
            elif operation == 'add_host':
                self.rules[key].setdefault('memberhost_hostgroup', []).extend(options['hostgroup'])
            elif operation == 'add_service':
                self.rules[key].setdefault('memberservice_hbacsvc', []).extend(options['hbacsvc'])
            elif operation == 'add_option':
                self.rules[key].setdefault('ipasudoopt', []).append(options['ipasudoopt'])
            elif operation == 'disable':
                self.rules[key]['ipaenabledflag'] = [False]
            else:
                raise AssertionError('unmodeled native command: ' + command)
            failed = {'member': {'user': () if self.native else []}}
            if self.failure == command:
                failed['member']['user'] = (('pilotuser', 'injected native failure'),)
            return {'result': self.result(self.rules[key]), 'failed': failed}
        return call


def execute(api, source=None):
    ipalib = types.ModuleType('ipalib')
    ipalib.api, ipalib.errors = api, types.SimpleNamespace(NotFound=NotFound)
    stdout, stderr = io.StringIO(), io.StringIO()
    status = 0
    with mock.patch.dict(sys.modules, {'ipalib': ipalib}), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            if source is None:
                runpy.run_path(str(SCRIPT), run_name='__main__')
            else:
                exec(compile(source, str(SCRIPT), 'exec'), {'__name__': '__main__'})
        except SystemExit as error:
            status = error.code
    return status, stdout.getvalue(), stderr.getvalue()


class FixtureBehavior(unittest.TestCase):
    def converged(self, native=True):
        api = API(native)
        status, stdout, stderr = execute(api)
        self.assertEqual((0, ''), (status, stderr))
        self.assertTrue(json.loads(stdout)['changed'])
        return api

    def test_native_capture_preserves_exact_attribute_types(self):
        attributes = {field: attribute for record in METADATA['records']
                      for field, attribute in record['attributes'].items()}
        for field in ('memberhost_hostgroup', 'memberuser_user', 'cmdcategory'):
            self.assertEqual('tuple', attributes[field]['native_type']['type'])
            self.assertTrue(all(item['type'] == 'str' for item in attributes[field]['native_type']['items']))
        self.assertEqual('tuple', attributes['ipaenabledflag']['native_type']['type'])
        self.assertTrue(all(item['type'] == 'bool' for item in attributes['ipaenabledflag']['native_type']['items']))

    def test_lists_and_native_tuples_apply_then_rerun_without_mutation(self):
        for native in (False, True):
            with self.subTest(native=native):
                api = self.converged(native)
                self.assertEqual([False], api.rules['hbacrule', 'allow_all']['ipaenabledflag'])
                for kind, name in (('hbacrule', 'i227-owned-hbac'), ('sudorule', 'i227-owned-sudo')):
                    self.assertEqual(['pilotuser'], api.rules[kind, name]['memberuser_user'])
                    self.assertEqual(['pilot-target-i227-owned'], api.rules[kind, name]['memberhost_hostgroup'])
                self.assertEqual(['sshd', 'sudo'], api.rules['hbacrule', 'i227-owned-hbac']['memberservice_hbacsvc'])
                count = len(api.mutations)
                status, stdout, stderr = execute(api)
                self.assertEqual((0, ''), (status, stderr))
                self.assertEqual({'changed': False}, json.loads(stdout))
                self.assertEqual(count, len(api.mutations))

    def test_wrong_broad_extra_and_malformed_policy_values_fail_closed(self):
        variations = [
            ('hbacrule', 'memberhost_hostgroup', ['foreign'], 'unrelated/broad'),
            ('hbacrule', 'memberhost_hostgroup', ['pilot-target-i227-owned', 'foreign'], 'unrelated/broad'),
            ('hbacrule', 'memberuser_user', ['pilotuser', 'another-user'], 'unrelated/broad'),
            ('hbacrule', 'hostcategory', ['all'], 'unrelated/broad'),
            ('hbacrule', 'servicecategory', ['all'], 'unrelated/broad'),
            ('hbacrule', 'memberservice_hbacsvc', ['sshd', 'sudo', 'other'], 'unrelated services'),
            ('hbacrule', 'memberhost_hostgroup', 'pilot-target-i227-owned', 'invalid sequence/type'),
            ('hbacrule', 'memberuser_user', [1], 'invalid sequence/type'),
            ('sudorule', 'cmdcategory', ['other'], 'cmdcategory=all'),
        ]
        for kind, field, value, reason in variations:
            with self.subTest(kind=kind, field=field, value=value):
                api = self.converged()
                name = 'i227-owned-hbac' if kind == 'hbacrule' else 'i227-owned-sudo'
                api.rules[kind, name][field] = value
                count = len(api.mutations)
                status, stdout, stderr = execute(api)
                self.assertEqual(1, status)
                self.assertEqual('', stdout)
                self.assertIn(reason, stderr)
                self.assertEqual(count, len(api.mutations))

    def test_boolean_flags_require_one_actual_bool(self):
        for value in ([1], ['True'], ['False'], [True, False], [], True):
            with self.subTest(value=value):
                api = self.converged()
                api.rules['hbacrule', 'allow_all']['ipaenabledflag'] = value
                status, stdout, stderr = execute(api)
                self.assertEqual(1, status)
                self.assertEqual('', stdout)
                self.assertTrue('invalid sequence/type' in stderr or 'disable did not converge' in stderr)

    def test_nonempty_native_failure_field_is_not_swallowed(self):
        api = API(True)
        api.failure = 'hbacrule_add_user'
        status, stdout, stderr = execute(api)
        self.assertEqual(1, status)
        self.assertEqual('', stdout)
        self.assertIn('fixture IPA membership mutation failed: hbacrule_add_user', stderr)
        # The API may have mutated before reporting partial failure.
        self.assertEqual(['pilotuser'], api.rules['hbacrule', 'i227-owned-hbac']['memberuser_user'])
        api.failure = None
        status, stdout, stderr = execute(api)
        self.assertEqual((0, ''), (status, stderr))
        self.assertTrue(json.loads(stdout)['changed'])
        status, stdout, stderr = execute(api)
        self.assertEqual((0, ''), (status, stderr))
        self.assertFalse(json.loads(stdout)['changed'])

    def test_each_old_list_only_comparison_fails_its_native_counterexample(self):
        source = SCRIPT.read_text()
        mutations = [
            ("sequence(rule, 'cmdcategory') != ['all']", "rule.get('cmdcategory') != ['all']", 'cmdcategory=all'),
            ("sequence(rule, 'memberhost_hostgroup') != ['pilot-target-i227-owned']", "rule.get('memberhost_hostgroup') != ['pilot-target-i227-owned']", 'scope/user authorization did not converge'),
            ("sequence(rule, 'memberuser_user') != ['pilotuser']", "rule.get('memberuser_user') != ['pilotuser']", 'scope/user authorization did not converge'),
            ("sequence(allow_all, 'ipaenabledflag', bool) == [True]", "allow_all.get('ipaenabledflag') == [True]", 'allow_all disable did not converge'),
            ("sequence(show('hbacrule', 'allow_all'), 'ipaenabledflag', bool) != [False]", "show('hbacrule', 'allow_all').get('ipaenabledflag') != [False]", 'allow_all disable did not converge'),
        ]
        for anchor, replacement, reason in mutations:
            with self.subTest(anchor=anchor):
                self.assertEqual(1, source.count(anchor))
                status, stdout, stderr = execute(API(True), source.replace(anchor, replacement))
                self.assertEqual(1, status)
                self.assertEqual('', stdout)
                self.assertIn(reason, stderr)


if __name__ == '__main__':
    unittest.main()
