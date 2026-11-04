#!/usr/bin/env python3
"""Gateway lifecycle model/persistence tests; native IPA is a separate VM gate."""
import copy
import importlib.util
import json
import multiprocessing
import os
import re
import ast
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'playbooks/apply/files/freeipa-gateway-scope.py'
SPEC = importlib.util.spec_from_file_location('gateway_scope', SOURCE)
gateway = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gateway)

CAPTURES = json.loads((Path(__file__).parent / 'testdata/freeipa-gateway-scope/native-api.json').read_text())
SHORT_CAPTURE = json.loads((Path(__file__).parent / 'testdata/freeipa-gateway-scope/native-short-host.json').read_text())


def capture(command, raw=None, occurrence=0):
    entries = [entry for entry in CAPTURES if entry.get('command') == command
               and (raw is None or bool(entry['options'].get('raw')) == raw)]
    return copy.deepcopy(entries[occurrence]['result'])


class NotFound(Exception):
    pass


class NativeModel:
    """Typed state model using real IPA API envelopes, never a native-daemon claim.

    Native immutable IDs, attribute spelling, direct/indirect member fields,
    nested failure results and regex condition representations come from the
    disposable 2026-11-04 FreeIPA captures. Mutations update a separate model
    so assertions check effects rather than helper desired-state calculations.
    """
    def __init__(self):
        raw = capture('hostgroup_show', True, 1)['result']
        self.name = raw['cn'][0]
        self.group = raw
        self.hosts = set(capture('hostgroup_show', False, 1)['result']['member_host'])
        self.a = CAPTURES[[x.get('command') for x in CAPTURES].index('host_show')]['args'][0]
        self.b = next(iter(self.hosts - {self.a}))
        self.groups = {self.name: dict(raw=raw, hosts=self.hosts)}
        self.rules = {self.name: capture('automember_show', True, 0)['result']}
        native_ldap = next(x for x in CAPTURES if 'native_ldap_operation' in x)
        self.auto_id = ast.literal_eval(native_ldap['result'])[0][1]['entryUUID'][0].decode()
        self.rule_ids = {str(self.rules[self.name]['dn']): self.auto_id}
        self.mutations = []
        self.fail = None
        self.fail_after = None

    def __getitem__(self, command):
        def call(name, **options):
            if command.endswith('_show'):
                if command == 'host_show':
                    result = capture('host_show', False, 0)['result']
                    result['fqdn'] = [name]
                    result['memberof_hostgroup'] = [n for n, g in self.groups.items() if name in g['hosts']]
                    return {'result': result}
                if command == 'hostgroup_show':
                    if name not in self.groups:
                        raise NotFound()
                    group = self.groups[name]
                    result = copy.deepcopy(group['raw'])
                    if not options.get('raw'):
                        result = {k.lower(): v for k, v in result.items()}
                        result['member_host'] = sorted(group['hosts'])
                    return {'result': result}
                if name not in self.rules:
                    raise NotFound()
                return {'result': copy.deepcopy(self.rules[name])}
            if self.fail == command:
                raise RuntimeError('injected IPA failure before ' + command)
            self.mutations.append((command, name, copy.deepcopy(options)))
            if command in ('hostgroup_remove_member', 'hostgroup_add_member'):
                host = options['host'][0]
                if command == 'hostgroup_remove_member':
                    self.groups[name]['hosts'].remove(host)
                else:
                    self.groups[name]['hosts'].add(host)
                result = capture('hostgroup_remove_member', occurrence=0)
            elif command == 'automember_add_condition':
                key = next(k for k in options if k.endswith('regex'))
                self.rules[name].setdefault(key, []).extend('fqdn=' + item for item in options[key])
                result = capture('automember_add_condition', occurrence=0)
            elif command == 'automember_add':
                rule = capture('automember_show', True, 0)['result']
                rule['dn'] = 'cn=' + name + ',cn=hostgroup,cn=automember,cn=etc,dc=ipa227,dc=test'
                rule['automembertargetgroup'] = [self.groups[name]['raw']['dn']]
                rule.pop('automemberexclusiveregex', None)
                rule.pop('automemberinclusiveregex', None)
                self.rules[name] = rule
                self.rule_ids[str(rule['dn'])] = self.auto_id
                result = {'result': copy.deepcopy(rule)}
            elif command == 'automember_del':
                del self.rules[name]
                result = {'result': {}}
            else:
                raise AssertionError('unexpected model mutation: ' + command)
            if self.fail_after == command:
                raise RuntimeError('injected lost reply after ' + command)
            return result
        return call

    def rebuild(self, host):
        for name, rule in self.rules.items():
            matches = lambda key: any(re.search(regex.split('=', 1)[1], host)
                                      for regex in rule.get(key, []))
            if matches('automemberinclusiveregex') and not matches('automemberexclusiveregex'):
                self.groups[name]['hosts'].add(host)


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / 'state' / 'gateway-scopes.json')
        self.store = gateway.Store(self.path, 'ipa227.test', 'ipa.ipa227.test', False)
        self.model = NativeModel()
        self.state = self.store.empty()
        self.state['scopes'][self.model.name] = dict(group=self.model.name, scope='i227-capture',
            id=self.model.group['ipaUniqueID'][0], automember_id=self.model.auto_id)
        with self.store.locked():
            self.store.save(self.state)

    def helper(self):
        return gateway.Lifecycle(self.model, NotFound, self.store,
                                 lambda dn: self.model.rule_ids[dn])

    def short_helper(self, response=None, failure=None, short='keep'):
        model = self.model
        calls = []

        class API:
            def __getitem__(unused, command):
                original = model[command]

                def call(name, **options):
                    if command == 'host_show':
                        calls.append(name)
                        if name == short:
                            if failure is not None:
                                raise failure
                            return copy.deepcopy(response if response is not None else SHORT_CAPTURE['result'])
                    return original(name, **options)
                return call

        return gateway.Lifecycle(API(), NotFound, self.store, lambda dn: model.rule_ids[dn]), calls

    def test_native_short_identity_lists_and_tuples_publish_only_canonical_hosts(self):
        self.assertEqual('tuple', SHORT_CAPTURE['native_fqdn_type']['type'])
        for container in (list, tuple):
            with self.subTest(container=container):
                response = copy.deepcopy(SHORT_CAPTURE['result'])
                response['result']['fqdn'] = container(response['result']['fqdn'])
                helper, calls = self.short_helper(response)
                result = helper.publish(self.state, dict(scope='i227-capture', hosts=['KEEP', 'keep.ipa227.test', 'keep']), False)
                self.assertEqual({'keep.ipa227.test'}, self.model.hosts)
                self.assertEqual([], result['blocked'])
                self.assertIn('keep', calls)
                for command, name, options in self.model.mutations:
                    if command.startswith('hostgroup_') and 'host' in options:
                        self.assertTrue(all('.' in host for host in options['host']))

    def test_short_identity_failures_block_complete_batch_before_mutation(self):
        failures = [
            ({'result': {}}, None, 'no unique canonical FQDN'),
            ({'result': {'fqdn': 'keep.ipa227.test'}}, None, 'no unique canonical FQDN'),
            ({'result': {'fqdn': ['keep.ipa227.test', 'keep.other.test']}}, None, 'no unique canonical FQDN'),
            ({'result': {'fqdn': ['different.ipa227.test']}}, None, 'different resource'),
            ({'result': {'fqdn': ['keep..test']}}, None, 'canonical FQDN'),
            ({'result': {'fqdn': ['192.0.2.9']}}, None, 'transport IP'),
            (None, NotFound(), 'missing or ambiguous'),
            (None, RuntimeError('native discovery unavailable'), 'native discovery unavailable'),
        ]
        for response, failure, reason in failures:
            with self.subTest(reason=reason, response=response):
                helper, calls = self.short_helper(response, failure)
                before = Path(self.path).read_bytes()
                with self.assertRaisesRegex((ValueError, RuntimeError), reason):
                    helper.publish(self.state, dict(scope='i227-capture', hosts=[self.model.b, 'keep']), False)
                self.assertEqual([], self.model.mutations)
                self.assertEqual(before, Path(self.path).read_bytes())
        for value in ('192.0.2.9', '2001:db8::1', 'bad_host', 'keep..test', 'keep.ipa227.test..'):
            with self.subTest(value=value):
                helper, calls = self.short_helper()
                with self.assertRaises(ValueError):
                    helper.publish(self.state, dict(scope='i227-capture', hosts=[value]), False)
                self.assertEqual([], calls)
                self.assertEqual([], self.model.mutations)

    def test_canonical_retirement_filters_before_lookup_and_short_uses_exact_native_identity(self):
        self.state['retired'][self.model.a] = {'status': 'detached'}
        helper, calls = self.short_helper()
        desired, blocked = helper.resolve_host_identities([self.model.a.upper() + '.'], self.state['retired'])
        self.assertEqual(([], [self.model.a]), (desired, blocked))
        self.assertEqual([], calls)
        short = self.model.a.split('.')[0]
        # A native result for a genuinely different live same-short host is
        # not a retirement receipt for the old domain; basename is no oracle.
        other = short + '.other.test'
        helper, calls = self.short_helper({'result': {'fqdn': (other,)}}, short=short)
        self.assertEqual(([other], []), helper.resolve_host_identities([short], self.state['retired']))
        helper, calls = self.short_helper({'result': {'fqdn': (self.model.a,)}}, short=short)
        self.assertEqual(([], [self.model.a]), helper.resolve_host_identities([short], self.state['retired']))
        self.assertEqual([short], calls)

    def test_legacy_raw_short_rejection_negative_control(self):
        helper, calls = self.short_helper()
        def old_boundary(requested, retired):
            return sorted({gateway.fqdn(host) for host in requested} - set(retired)), []
        with mock.patch.object(helper, 'resolve_host_identities', side_effect=old_boundary):
            with self.assertRaisesRegex(ValueError, 'canonical FQDN'):
                helper.publish(self.state, dict(scope='i227-capture', hosts=['keep']), False)
        self.assertEqual([], self.model.mutations)

    def disable_helper(self):
        model = self.model

        class RuleOnlyAPI:
            def __getitem__(unused, command):
                original = model[command]

                def call(name, **options):
                    if (command not in ('hostgroup_show', 'automember_show', 'automember_del')
                            or (command == 'hostgroup_show' and not options.get('raw'))):
                        raise AssertionError('disable touched host/membership/exclusion API: ' + command)
                    return original(name, **options)
                return call
        return gateway.Lifecycle(RuleOnlyAPI(), NotFound, self.store, lambda dn: model.rule_ids[dn])

    def test_disable_is_rule_only_for_stale_malformed_and_ambiguous_inherited_hosts(self):
        self.state['retired'][self.model.a] = {'status': 'pending'}
        before_retired = copy.deepcopy(self.state['retired'])
        before_hosts = set(self.model.hosts)
        values = (['deleted.ipa227.test'], ['ambiguous'], ['192.0.2.7'], 'malformed', None, {'bad': True})
        for inherited in values:
            with self.subTest(inherited=inherited):
                rule = capture('automember_show', True, 0)['result']
                self.model.rules[self.model.name] = rule
                self.state['scopes'][self.model.name]['automember_id'] = self.model.auto_id
                self.model.mutations = []
                result = self.disable_helper().publish(self.state, self.publish('disable') | {'hosts': inherited}, False)
                self.assertTrue(result['changed'])
                self.assertNotIn(self.model.name, self.model.rules)
                self.assertEqual(['automember_del'], [command for command, name, options in self.model.mutations])
                self.assertEqual(before_hosts, self.model.hosts)
                self.assertEqual(before_retired, self.state['retired'])
                self.assertEqual(before_retired, self.persisted()['retired'])
                self.assertFalse(self.disable_helper().publish(self.state, self.publish('disable') | {'hosts': inherited}, False)['changed'])

    def test_disable_readonly_and_ownership_failures_never_touch_membership(self):
        before = Path(self.path).read_bytes()
        self.assertFalse(self.disable_helper().publish(self.state, self.publish('disable') | {'hosts': ['deleted.ipa227.test']}, True)['changed'])
        self.assertEqual(before, Path(self.path).read_bytes())
        self.assertEqual([], self.model.mutations)
        for kind in ('unknown', 'group-recreated', 'rule-recreated'):
            with self.subTest(kind=kind):
                state = copy.deepcopy(self.state)
                if kind == 'unknown':
                    state['scopes'] = {}
                elif kind == 'group-recreated':
                    state['scopes'][self.model.name]['id'] = '00000000-0000-0000-0000-000000000001'
                else:
                    state['scopes'][self.model.name]['automember_id'] = '00000000-0000-0000-0000-000000000002'
                with self.assertRaisesRegex(ValueError, 'unproven'):
                    self.disable_helper().publish(state, self.publish('disable') | {'hosts': ['deleted.ipa227.test']}, False)
                self.assertEqual([], self.model.mutations)
                self.assertIn(self.model.name, self.model.rules)

    def test_disable_exact_adoption_and_lost_delete_reply_retry(self):
        self.state['scopes'] = {}
        request = self.publish('disable', adopt_id=self.model.group['ipaUniqueID'][0], adopt_automember_id=self.model.auto_id)
        self.model.fail_after = 'automember_del'
        with self.assertRaisesRegex(RuntimeError, 'lost reply'):
            self.disable_helper().publish(self.state, request, False)
        self.assertNotIn(self.model.name, self.model.rules)
        self.assertIn('automember_id', self.persisted()['scopes'][self.model.name])
        self.model.fail_after = None
        self.state = self.persisted()
        self.assertTrue(self.disable_helper().publish(self.state, request, False)['changed'])
        self.assertNotIn('automember_id', self.persisted()['scopes'][self.model.name])
        self.assertFalse(self.disable_helper().publish(self.state, request, False)['changed'])

    def test_old_unconditional_resolver_breaks_rule_only_disable_negative_control(self):
        source = SOURCE.read_text()
        anchor = "        group = self.show('hostgroup', name, raw=True)\n        adopt = data.get('adopt_id', '').lower()"
        self.assertEqual(1, source.count(anchor))
        mutant = source.replace(anchor, "        self.resolve_host_identities(data.get('hosts', []), state['retired'])\n" + anchor)
        namespace = {'__name__': 'gateway_disable_negative_control'}
        exec(compile(mutant, str(SOURCE), 'exec'), namespace)
        helper, calls = self.short_helper(failure=NotFound(), short='deleted')
        old = namespace['Lifecycle'](helper.api, NotFound, self.store, helper.rule_id)
        with self.assertRaisesRegex(ValueError, 'legacy short host is missing or ambiguous'):
            old.publish(self.state, self.publish('disable') | {'hosts': ['deleted']}, False)
        self.assertEqual(['deleted'], calls)
        self.assertEqual([], self.model.mutations)
        self.assertIn(self.model.name, self.model.rules)

    def retirement(self):
        return {'retirements': [dict(fqdn=self.model.a, alias='retire', stage='sandbox',
                                    reason='operator approved', origin='test-plan')]}

    def publish(self, action='none', **changes):
        return dict(scope='i227-capture', hosts=[self.model.a, self.model.b], automember=action, **changes)

    def persisted(self):
        return json.loads(Path(self.path).read_text())

    def test_exact_detach_preserves_other_member_and_shared_group(self):
        raw = copy.deepcopy(self.model.group)
        self.helper().retire(self.state, self.retirement(), False)
        self.assertEqual({self.model.b}, self.model.hosts)
        self.assertEqual(raw, self.model.group)
        self.assertEqual('detached', self.persisted()['retired'][self.model.a]['status'])
        self.assertFalse(self.helper().retire(self.state, self.retirement(), False)['changed'])

    def test_unknown_prefix_membership_blocks_before_any_mutation(self):
        self.state['scopes'] = {}
        before = Path(self.path).read_bytes()
        with self.assertRaisesRegex(ValueError, 'unproven hostgroup'):
            self.helper().retire(self.state, self.retirement(), False)
        self.assertEqual([], self.model.mutations)
        self.assertEqual(before, Path(self.path).read_bytes())
        self.assertIn(self.model.a, self.model.hosts)

    def test_recreated_group_or_rule_cannot_reuse_ownership(self):
        for resource in ('group', 'rule'):
            with self.subTest(resource=resource):
                model = NativeModel()
                if resource == 'group':
                    model.group['ipaUniqueID'] = ['00000000-0000-0000-0000-000000000001']
                else:
                    model.rule_ids[str(model.rules[model.name]['dn'])] = '00000000-0000-0000-0000-000000000002'
                helper = gateway.Lifecycle(model, NotFound, self.store, lambda dn: model.rule_ids[dn])
                with self.assertRaisesRegex(ValueError, 'unproven'):
                    helper.retire(copy.deepcopy(self.state), self.retirement(), False)
                self.assertEqual([], model.mutations)

    def test_all_memberships_classified_before_first_removal(self):
        foreign = copy.deepcopy(self.model.group)
        foreign['cn'] = ['pilot-target-unproven']
        foreign['dn'] = 'cn=pilot-target-unproven,cn=hostgroups,cn=accounts,dc=ipa227,dc=test'
        foreign['ipaUniqueID'] = ['00000000-0000-0000-0000-000000000003']
        self.model.groups['pilot-target-unproven'] = dict(raw=foreign, hosts={self.model.a})
        with self.assertRaisesRegex(ValueError, 'unproven hostgroup'):
            self.helper().retire(self.state, self.retirement(), False)
        self.assertEqual([], self.model.mutations)
        self.assertIn(self.model.a, self.model.hosts)

    def test_global_barrier_covers_scope_with_no_current_membership(self):
        self.model.hosts.remove(self.model.a)
        self.model.rules[self.model.name]['automemberinclusiveregex'] = ['fqdn=.*']
        self.helper().retire(self.state, self.retirement(), False)
        self.model.rebuild(self.model.a)
        self.assertNotIn(self.model.a, self.model.hosts)
        self.model.rebuild(self.model.b)
        self.assertIn(self.model.b, self.model.hosts)

    def test_pending_barrier_survives_ipa_failure_and_lost_mutation_reply(self):
        for point in ('automember_add_condition', 'hostgroup_remove_member'):
            with self.subTest(point=point):
                self.setUp()
                self.model.fail_after = point
                with self.assertRaisesRegex(RuntimeError, 'lost reply'):
                    self.helper().retire(self.state, self.retirement(), False)
                self.assertEqual('pending', self.persisted()['retired'][self.model.a]['status'])
                self.model.fail_after = None
                self.state = self.persisted()
                self.helper().retire(self.state, self.retirement(), False)
                self.assertNotIn(self.model.a, self.model.hosts)
                self.assertIn(self.model.b, self.model.hosts)

    def test_later_publication_and_reenabled_auto_preserve_retirement(self):
        self.helper().retire(self.state, self.retirement(), False)
        self.helper().publish(self.state, self.publish('disable'), False)
        self.assertNotIn(self.model.name, self.model.rules)
        self.helper().publish(self.state, self.publish('enable'), False)
        self.model.rebuild(self.model.a)
        self.assertEqual({self.model.b}, self.model.hosts)
        self.assertFalse(self.helper().publish(self.state, self.publish('enable'), False)['changed'])

    def test_legacy_adoption_requires_exact_group_and_rule_ids(self):
        self.state['scopes'] = {}
        with self.assertRaisesRegex(ValueError, 'unproven gateway group'):
            self.helper().publish(self.state, self.publish(), False)
        with self.assertRaisesRegex(ValueError, 'unproven automember'):
            self.helper().publish(self.state, self.publish(adopt_id=self.model.group['ipaUniqueID'][0]), False)
        self.helper().publish(self.state, self.publish(adopt_id=self.model.group['ipaUniqueID'][0],
            adopt_automember_id=self.model.auto_id), False)
        self.assertEqual(self.model.auto_id, self.persisted()['scopes'][self.model.name]['automember_id'])

    def test_probe_error_and_foreign_auto_target_block_without_mutation(self):
        rule = self.model.rules[self.model.name]
        rule['automembertargetgroup'] = ['cn=foreign,cn=hostgroups,cn=accounts,dc=ipa227,dc=test']
        with self.assertRaisesRegex(ValueError, 'target differs'):
            self.helper().retire(self.state, self.retirement(), False)
        self.assertEqual([], self.model.mutations)

    def test_plan_is_readonly(self):
        before = Path(self.path).read_bytes()
        self.helper().retire(self.state, self.retirement(), True)
        self.helper().publish(self.state, self.publish(), True)
        self.assertEqual([], self.model.mutations)
        self.assertEqual(before, Path(self.path).read_bytes())

    def test_unmapped_absent_requires_mapping_before_scope_cleanup(self):
        request = dict(retirements=[], absent_hosts=[self.model.a], require_mappings=True)
        before = Path(self.path).read_bytes()
        with self.assertRaisesRegex(ValueError, 'exact authorized alias/FQDN/stage mapping'):
            self.helper().retire(self.state, request, True)
        self.assertEqual([], self.model.mutations)
        self.assertEqual(before, Path(self.path).read_bytes())

    def test_unmapped_absent_auto_potential_and_pending_work_need_mapping(self):
        self.model.hosts.remove(self.model.a)
        request = dict(retirements=[], absent_hosts=[self.model.a], require_mappings=True)
        self.model.rules[self.model.name]['automemberinclusiveregex'] = ['fqdn=.*']
        with self.assertRaisesRegex(ValueError, 'exact authorized alias/FQDN/stage mapping'):
            self.helper().retire(self.state, request, True)
        # The exact exclusion discharges this rule's re-add potential.
        self.model.rules[self.model.name]['automemberexclusiveregex'] = ['fqdn=^' + re.escape(self.model.a) + '$']
        self.helper().retire(self.state, request, True)
        self.state['retired'][self.model.a] = {'status': 'pending'}
        with self.assertRaisesRegex(ValueError, 'exact authorized alias/FQDN/stage mapping'):
            self.helper().retire(self.state, request, True)
        self.assertEqual([], self.model.mutations)

    def test_legacy_absent_without_gateway_work_keeps_existing_behavior(self):
        self.model.hosts.remove(self.model.a)
        del self.model.rules[self.model.name]
        request = dict(retirements=[], absent_hosts=[self.model.a], require_mappings=True)
        self.assertTrue(self.helper().retire(self.state, request, True)['ready'])
        self.assertEqual([], self.model.mutations)

    def test_absent_probe_cannot_implicitly_authorize_mutation(self):
        request = dict(retirements=[], absent_hosts=[self.model.a])
        with self.assertRaisesRegex(ValueError, 'exact authorized retirement mapping'):
            self.helper().retire(self.state, request, False)
        self.assertEqual([], self.model.mutations)


def hold_lock(path, ready, release):
    store = gateway.Store(path, 'ipa.test', 'ipa.ipa.test', False)
    with store.locked() as state:
        ready.set()
        release.wait(10)
        state['retired']['a.ipa.test'] = {'status': 'pending'}
        store.save(state)


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = str(Path(self.temporary.name) / 'state' / 'gateway-scopes.json')

    def store(self, readonly=False, domain='ipa.test'):
        return gateway.Store(self.path, domain, 'ipa.ipa.test', readonly)

    def test_readonly_missing_creates_nothing(self):
        with self.store(True).locked() as state:
            self.assertEqual({}, state['scopes'])
        self.assertFalse(Path(self.path).parent.exists())

    def test_roundtrip_binding_and_permissions(self):
        with self.store().locked() as state:
            state['retired']['a.ipa.test'] = {'status': 'pending'}
            self.store().save(state)
        self.assertEqual(0o600, os.stat(self.path).st_mode & 0o777)
        with self.store(True).locked() as state:
            self.assertEqual('pending', state['retired']['a.ipa.test']['status'])
        with self.assertRaisesRegex(ValueError, 'identity/schema'):
            with self.store(True, 'other.test').locked():
                pass

    def test_rejects_symlink_hardlink_and_foreign_permissions(self):
        for kind in ('symlink', 'hardlink', 'permissions'):
            with self.subTest(kind=kind):
                parent = Path(self.path).parent
                parent.mkdir(mode=0o700, exist_ok=True)
                source = parent / 'foreign'
                source.write_text(json.dumps(self.store().empty()))
                source.chmod(0o600)
                if kind == 'symlink':
                    os.symlink(source, self.path)
                elif kind == 'hardlink':
                    os.link(source, self.path)
                else:
                    Path(self.path).write_text(source.read_text())
                    Path(self.path).chmod(0o644)
                with self.assertRaises((ValueError, OSError)):
                    with self.store(True).locked():
                        pass
                Path(self.path).unlink()
                source.unlink()

    def test_directory_lock_serializes_probe_mutation_and_save(self):
        context = multiprocessing.get_context('fork')
        ready, release = context.Event(), context.Event()
        process = context.Process(target=hold_lock, args=(self.path, ready, release))
        process.start()
        self.addCleanup(lambda: process.kill() if process.is_alive() else None)
        self.assertTrue(ready.wait(5))
        # An independent process owns the physical directory lock, rather
        # than a process-local mutex or a path-name/PID claim.
        import fcntl
        descriptor = os.open(str(Path(self.path).parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        release.set()
        process.join(5)
        self.assertEqual(0, process.exitcode)
        with self.store(True).locked() as state:
            self.assertIn('a.ipa.test', state['retired'])


if __name__ == '__main__':
    unittest.main()
