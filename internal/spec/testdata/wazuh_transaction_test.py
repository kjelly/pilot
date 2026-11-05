"""Behavioral controls for the real Wazuh version coordinator (no host mutation).

The coordinator is imported and driven in-process. Native commands (dpkg, rpm,
apt, dnf, docker, systemctl) are an explicit model: they prove the policy, the
parsing and the ordering of the real code, not VM/native evidence. The private
filesystem, flock and file-policy code run for real in temporary directories.
"""
import wazuh_hermetic  # noqa: F401  (tripwire first: no harness may touch real host state)
from wazuh_models import Docker
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[3]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, REPO / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w = load('wazuh_transaction', 'playbooks/apply/files/wazuh-transaction.py')
HERMETIC_ROOT = wazuh_hermetic.sandbox(w)
ROOT_STARTED_ABSENT = not Path(w.ROOT).exists()

# No test creates host mounts. Feed the real mountinfo decoder an explicit
# disposable namespace, independent of the runner's sandbox/bind ancestry.
# Scope counterexamples replace this data, never the production validator.
RealMountTable = w.MountTable
MOUNT_NAMESPACE = {'text': '1 0 8:1 / / rw - ext4 /dev/synthetic rw\n'}
w.MountTable = lambda text=None: RealMountTable(MOUNT_NAMESPACE['text'] if text is None else text)


def package_row(version):
    return {'name': 'wazuh-agent', 'version': version, 'epoch': '0', 'arch': 'x86_64'}


class HermeticHarnessTests(unittest.TestCase):
    """The harnesses never reach real host state, even when run as root."""

    def test_the_tripwire_is_enforcing(self):
        self.assertEqual(wazuh_hermetic.MODE, 'enforce', 'PILOT_WAZUH_HERMETIC=record is for surveys only')

    def test_every_host_state_access_is_refused_before_it_reaches_the_host(self):
        for operation in (lambda: Path('/var/ossec/etc/client.keys').exists(),
                          lambda: open('/etc/hosts').read(),
                          lambda: os.stat('/etc/dnf/dnf.conf'),
                          lambda: os.listdir('/etc/apt/preferences.d'),
                          lambda: Path('/etc/apt/preferences.d/pilot-wazuh-agent').read_bytes(),
                          # Mutations of host state are refused too: as root they would succeed.
                          lambda: os.mkdir('/var/backups/pilot/hermetic-probe'),
                          lambda: Path('/etc/dnf/plugins/versionlock.list').write_text('x'),
                          lambda: os.rename('/tmp/definitely-absent', '/opt/pilot/probe')):
            with self.assertRaises(wazuh_hermetic.HostStateTouched):
                operation()
        # Control: ordinary temporary files are not host state.
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / 'x').write_text('ok')
            self.assertEqual((Path(temporary) / 'x').read_text(), 'ok')

    def test_default_coordinator_paths_are_redirected_to_a_private_tree(self):
        self.assertIsNone(wazuh_hermetic.offending(w.ROOT), 'ROOT still names real host state')
        self.assertTrue(str(w.ROOT).startswith(str(HERMETIC_ROOT)))
        self.assertTrue(ROOT_STARTED_ABSENT, 'ROOT must start absent like a bare host')

    def test_an_unredirected_native_policy_path_fails_loudly_instead_of_reading_the_host(self):
        # The guard's /etc/dnf constants are literals: a test that forgets to
        # point them at a temporary tree must trip, not read the runner's DNF.
        with self.assertRaises(wazuh_hermetic.HostStateTouched):
            w.PackageGuard('RedHat', Commands('RedHat')).dnf_context()
        with self.assertRaises(wazuh_hermetic.HostStateTouched):
            w.PackageGuard('Debian', Commands('Debian')).ownership()

    def test_modeled_absent_paths_never_reach_the_host(self):
        with wazuh_hermetic.absent('/etc/apt/preferences.d'):
            with self.assertRaises(FileNotFoundError):
                Path('/etc/apt/preferences.d/pilot-wazuh-agent').stat()
        with self.assertRaises(wazuh_hermetic.HostStateTouched):
            Path('/etc/apt/preferences.d/pilot-wazuh-agent').stat()


class TypedErrorContractTests(unittest.TestCase):
    """The failure is disclosed from a typed field only, so no_log is not needed.

    That is safe only while every Refused() message is a fixed literal. A single
    f-string or concatenation of tool output would put it on the user's screen.
    """

    @staticmethod
    def enclosing(tree):
        owner = {}

        def visit(node, name):
            for child in ast.iter_child_nodes(node):
                scope = name
                if isinstance(child, (ast.FunctionDef, ast.ClassDef)):
                    scope = child.name if not name else name + '.' + child.name
                owner[child] = scope
                visit(child, scope)
        visit(tree, '')
        return owner

    def test_every_refused_message_is_a_fixed_literal_or_a_reviewed_composition(self):
        tree = ast.parse((REPO / 'playbooks/apply/files/wazuh-transaction.py').read_text())
        owner = self.enclosing(tree)
        dynamic, literal = set(), 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'Refused':
                self.assertEqual(len(node.args), 1, 'Refused takes exactly one message (line %d)' % node.lineno)
                if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    literal += 1
                    self.assertRegex(node.args[0].value, r'^[ !#-\[\]-z|~]*$',
                                     'line %d: a fixed refusal must already be typed_error-clean' % node.lineno)
                else:
                    dynamic.add((owner[node], ast.unparse(node.args[0])))
        self.assertGreater(literal, 100, 'the scan must actually see the coordinator refusals')
        self.assertEqual(dynamic, {
            # label is a fixed operation name or argv[0]; the child's output is never appended.
            ('Runner.run', "'operation unavailable or timed out: ' + label"),
            ('Runner.run', "'operation failed: ' + label + ' rc=' + str(result.returncode)"),
        }, 'a new non-literal Refused message can carry tool output or secrets onto the screen')

    def test_typed_error_is_bounded_and_never_needs_escaping(self):
        pattern = re.compile('(?<="error": ")[^"]{1,300}(?=", "error_kind")')
        for text in ('plain text', 'quote " and backslash \\ end', 'unicode é中', 'new\nline\ttab', 'x' * 500,
                     "apostrophe ' ok", 'braces {} [] ok'):
            for kind in ('refused', 'native'):
                value = w.typed_error(kind, text)
                self.assertEqual(set(value), {'error', 'error_kind'})
                self.assertLessEqual(len(value['error']), 300)
                encoded = json.dumps(value)
                self.assertEqual(json.loads(encoded), value)
                # json.dumps() adds no escape sequence, so the strict pattern recovers it exactly.
                self.assertNotIn('\\', value['error'])
                self.assertFalse(set(value['error']) & set('{}"'), 'braces would reach Jinja')
                self.assertEqual(pattern.search(encoded).group(0), value['error'])
        with self.assertRaises(AssertionError):
            w.typed_error('anything-else', 'x')


class Commands:
    """Native dpkg/rpm and manager-registry model shared by the agent tests."""
    def __init__(self, family='Debian', installed='4.14.1-1'):
        self.family, self.installed = family, installed
        self.calls = []
        self.agent_release = '4.14.1'
        self.unknown = False

    def run(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        self.calls.append(argv)
        if argv[0] == 'dpkg-query':
            text, rc = ('install ok installed\t' + self.installed + '\tamd64', 0) if self.installed else ('', 1)
        elif argv[:2] == ['rpm', '-q']:
            text, rc = (self.installed + '\tx86_64', 0) if self.installed else ('package wazuh-agent is not installed\n', 1)
        elif '-l' in argv:
            text, rc = ('Wazuh agent_control. List of available agents:\n'
                        '   ID: 000, Name: wazuh.manager (server), IP: 127.0.0.1, Active/Local\n'
                        '   ID: 001, Name: synthetic, IP: any, Active\n', 0)
        elif '-i' in argv:
            text, rc = ('Wazuh agent_control. Agent information:\n   Agent ID:   001\n   Agent Name: synthetic\n'
                        '   Status:     Active\n   Client version:      ' + ('unknown' if self.unknown else 'Wazuh v' + self.agent_release) + '\n', 0)
        elif argv[0] == 'systemctl':
            text, rc = ('', 0) if argv[1] == 'is-active' else ('', 3)
        else:
            text, rc = '', 0
        if rc not in kwargs.get('allowed', (0,)):
            raise w.Refused('injected native probe failure')
        diagnostic = 'dpkg-query: no packages found matching wazuh-agent\n' if argv[0] == 'dpkg-query' and not self.installed else ''
        return subprocess.CompletedProcess(argv, rc, text, diagnostic)

    def json(self, argv, **kwargs):
        raise AssertionError(argv)


class PolicyTests(unittest.TestCase):
    def test_native_failure_does_not_echo_argv_or_tool_output(self):
        sentinel = 'PILOT_SYNTHETIC_SECRET_244'
        with self.assertRaises(w.Refused) as failure:
            w.Runner().run(['python3', '-c', 'import sys; print(sys.argv[1]); print(sys.argv[1],file=sys.stderr); sys.exit(1)', sentinel])
        self.assertNotIn(sentinel, str(failure.exception))

    def test_common_legacy_conflict_and_default(self):
        self.assertEqual(w.desired(), '4.14.1')
        self.assertEqual(w.desired('4.14.9'), '4.14.9')
        self.assertEqual(w.desired('', '4.14.6'), '4.14.6')
        self.assertEqual(w.desired('4.14.6', '4.14.6'), '4.14.6')
        with self.assertRaisesRegex(w.Refused, 'conflicts'):
            w.desired('4.14.9', '4.14.1')
        for invalid in ('5.0.0', '4.14', 'v4.14.1', '4.14.01', '4.14.1-1'):
            with self.assertRaises(w.Refused):
                w.desired(invalid)

    def test_a_compatible_installed_agent_is_kept_whatever_its_build_or_age(self):
        for installed, manager, requested in (('4.14.1-1', '4.14.1', ''), ('4.14.6-1', '4.14.9', ''),
                                              ('4.14.9-1', '4.14.9', ''), ('4.14.9-2', '4.14.9', '4.14.9'),
                                              ('4.14.6-1', '', ''), ('4.14.1-1', '4.14.9', '4.14.1')):
            plan = w.agent_plan(installed, manager, requested)
            self.assertEqual((plan['package'], plan['install']), (installed, False), (installed, manager, requested))
            self.assertEqual(plan['version'], installed.rsplit('-', 1)[0])

    def test_every_release_change_of_an_installed_agent_is_refused_with_its_reason(self):
        cases = ((('4.14.9-1', '4.14.1', ''), 'newer than the observed manager'),
                 (('4.14.9-1', '4.14.1', '4.14.1'), 'newer than the observed manager'),
                 (('4.14.6-1', '4.14.9', '4.14.9'), 'upgrade is not supported'),
                 (('4.14.6-1', '', '4.14.9'), 'upgrade is not supported'),
                 (('4.14.9-1', '4.14.9', '4.14.6'), 'downgrade'))
        for args, reason in cases:
            with self.assertRaisesRegex(w.Refused, reason, msg=str(args)):
                w.agent_plan(*args)

    def test_unknown_installed_or_manager_versions_never_pass(self):
        for installed in ('4.14.9-rc1', '5.0.0-1', '4.14.1', '4.14.09-1', '1:4.14.1-1', '4.14.1-0', '4.13.9-1'):
            with self.assertRaises(w.Refused, msg=installed):
                w.agent_plan(installed, '4.14.9')
        for manager in ('4.14', '5.0.0', '4.14.9-rc1', 'v4.14.9', '4.14.09'):
            with self.assertRaises(w.Refused, msg=manager):
                w.agent_plan('', manager)
        with self.assertRaises(w.Refused):
            w.agent_plan('', '', 'not-a-release')

    def test_a_fresh_install_is_exactly_the_requested_release_or_the_managers(self):
        self.assertEqual(w.agent_plan('', '4.14.9')['package'], '4.14.9-1')
        self.assertEqual(w.agent_plan('', '')['package'], '4.14.1-1')
        self.assertEqual(w.agent_plan('', '4.14.9', '4.14.6')['package'], '4.14.6-1')
        self.assertEqual(w.agent_plan('', '', '4.14.9')['package'], '4.14.9-1')
        plan = w.agent_plan('', '4.14.9')
        self.assertEqual((plan['install'], plan['installed'], plan['manager']), (True, '', '4.14.9'))
        with self.assertRaisesRegex(w.Refused, 'newer than the observed manager'):
            w.agent_plan('', '4.14.1', '4.14.9')

    def test_the_plan_is_a_pure_function_of_native_probes_for_both_backends(self):
        for family in ('Debian', 'RedHat'):
            for release in ('4.14.1-1', '4.14.9-1'):
                command = Commands(family, release)
                agent = w.Agent(family, runner=command, root=HERMETIC_ROOT / 'unused')
                self.assertEqual(agent.check('4.14.9')['package'], release)
                with self.assertRaisesRegex(w.Refused, 'newer'):
                    agent.check('4.14.0')
                self.assertTrue(any(call[0] == ('dpkg-query' if family == 'Debian' else 'rpm') for call in command.calls))
            self.assertEqual(w.Agent(family, runner=Commands(family, ''), root=HERMETIC_ROOT / 'unused').check('4.14.9')['package'], '4.14.9-1')


class BackendTests(unittest.TestCase):
    def test_native_held_dpkg_status_remains_an_installed_compatible_agent(self):
        class Native(Commands):
            def run(self, argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, 'hold ok installed\t4.14.1-1\tamd64', '')
        agent = w.Agent('Debian', runner=Native(), root=HERMETIC_ROOT / 'unused')
        self.assertEqual(agent.installed(), '4.14.1-1')
        self.assertEqual(agent.check('4.14.9')['package'], '4.14.1-1')

    def test_incomplete_dpkg_states_and_foreign_architectures_are_not_an_installed_agent(self):
        for text in ('install ok half-installed\t4.14.1-1\tamd64', 'deinstall ok config-files\t4.14.1-1\tamd64',
                     'install ok installed\t4.14.1-1\ti386', 'hold reinstreq installed\t4.14.1-1\tamd64', 'junk'):
            class Native(Commands):
                def run(self, argv, **kwargs):
                    return subprocess.CompletedProcess(argv, 0, text, '')
            with self.assertRaises(w.Refused, msg=text):
                w.Agent('Debian', runner=Native(), root=HERMETIC_ROOT / 'unused').installed()
        class Rpm(Commands):
            def run(self, argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, '4.14.1-1\taarch64', '')
        with self.assertRaisesRegex(w.Refused, 'architecture'):
            w.Agent('RedHat', runner=Rpm(), root=HERMETIC_ROOT / 'unused').installed()

    def test_known_absent_and_unknown_query_failure_are_distinct(self):
        for family in ('Debian', 'RedHat'):
            self.assertEqual(w.Agent(family, runner=Commands(family, ''), root=HERMETIC_ROOT / 'unused').installed(), '')
        class BadQuery(Commands):
            def run(self, argv, **kwargs):
                return subprocess.CompletedProcess(argv, 1, '', 'database query failed')
        with self.assertRaisesRegex(w.Refused, 'probe failed'):
            w.Agent('Debian', runner=BadQuery(), root=HERMETIC_ROOT / 'unused').installed()

    def test_probe_errors_never_become_fresh_installs(self):
        class Broken(Commands):
            def run(self, argv, **kwargs):
                if argv[0] == 'rpm':
                    return subprocess.CompletedProcess(argv, 1, 'rpmdb: query failed', '')
                raise w.Refused('query failed')
        for family in ('Debian', 'RedHat'):
            with self.assertRaises(w.Refused):
                w.Agent(family, runner=Broken(), root=HERMETIC_ROOT / 'unused').check('4.14.9')

    def test_unsupported_backend_is_refused(self):
        with self.assertRaises(w.Refused):
            w.Agent('Suse')


class NativeDebianGuardTests(unittest.TestCase):
    """APT hold is the effective guard; the preference is only an extra limit."""

    class Native:
        def __init__(self, installed='4.14.1-1', held=False, candidate='4.14.9-1'):
            self.installed, self.held, self.candidate, self.calls = installed, held, candidate, []

        def run(self, argv, **kwargs):
            argv = [str(a) for a in argv]
            self.calls.append(argv)
            if argv[0] == 'dpkg':
                text = 'wazuh-agent\t' + ('hold' if self.held else 'install') + '\n'
            elif argv[:2] == ['apt-mark', 'showhold']:
                text = 'unrelated-held\n' + ('wazuh-agent\n' if self.held else '')
            elif argv[:2] == ['apt-mark', 'hold']:
                self.held = True; text = ''
            elif argv[:2] == ['apt-cache', 'policy']:
                text = '  Installed: ' + self.installed + '\n  Candidate: ' + self.candidate + '\n'
            else:
                raise AssertionError(argv)
            return subprocess.CompletedProcess(argv, 0, text, '')

    def guard(self, native, folder):
        guard = w.PackageGuard('Debian', native, folder / 'private')
        guard.PREF = str(folder / 'pilot-wazuh-agent')
        return guard

    def test_verify_requires_the_native_hold_and_the_exact_installed_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            native = self.Native(held=True)
            guard = self.guard(native, Path(temporary))
            result = guard.verify('4.14.1-1')
            self.assertEqual(result['candidate'], '4.14.9-1', 'do not pretend APT priorities freeze the candidate')
            native.held = False
            with self.assertRaisesRegex(w.Refused, 'native APT hold'):
                guard.verify('4.14.1-1')
            native.held = True; native.installed = '4.14.6-1'
            with self.assertRaisesRegex(w.Refused, 'native APT hold'):
                guard.verify('4.14.1-1')
            with self.assertRaises(w.Refused):
                guard.verify('latest')

    def test_protect_holds_only_wazuh_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            native = self.Native()
            guard = self.guard(native, Path(temporary))
            first = guard.protect('4.14.1-1')
            self.assertTrue(first['changed'])
            self.assertEqual(first['guard'], 'apt-hold')
            self.assertEqual([c for c in native.calls if c[:2] == ['apt-mark', 'hold']], [['apt-mark', 'hold', 'wazuh-agent']])
            native.calls.clear()
            second = guard.protect('4.14.1-1')
            self.assertFalse(second['changed'], 'an already held package is not a change')
            self.assertFalse(any(c[:2] == ['apt-mark', 'hold'] for c in native.calls))
            self.assertFalse(any('unrelated-held' in argv for argv in native.calls))

    def test_dpkg_and_apt_mark_disagreement_refuses_instead_of_guessing(self):
        class Disagree(self.Native):
            def run(self, argv, **kwargs):
                if argv[:2] == ['apt-mark', 'showhold']:
                    return subprocess.CompletedProcess(argv, 0, '', '')
                return super().run(argv, **kwargs)
        with tempfile.TemporaryDirectory() as temporary:
            guard = self.guard(Disagree(held=True), Path(temporary))
            with self.assertRaisesRegex(w.Refused, 'disagree'):
                guard.verify('4.14.1-1')

    def test_a_foreign_preference_file_is_refused_before_any_hold(self):
        with tempfile.TemporaryDirectory() as temporary:
            native = self.Native()
            guard = self.guard(native, Path(temporary))
            owned = ('Package: wazuh-agent\nPin: version 4.14.1-1\nPin-Priority: 1000\n\n'
                     'Package: wazuh-agent\nPin: version *\nPin-Priority: -1\n')
            path = Path(guard.PREF)
            path.write_text(owned); path.chmod(0o644)
            self.assertTrue(guard.protect('4.14.1-1')['changed'])
            native.calls.clear(); native.held = False
            for text in (owned.replace('1000', '500'), 'Package: *\nPin: release a=foreign\nPin-Priority: 900\n',
                         owned.replace('4.14.1-1', 'latest')):
                path.write_text(text)
                with self.assertRaisesRegex(w.Refused, 'foreign ownership'):
                    guard.protect('4.14.1-1')
            self.assertFalse(any(c[:2] == ['apt-mark', 'hold'] for c in native.calls))
            path.chmod(0o666); path.write_text(owned)
            with self.assertRaisesRegex(w.Refused, 'permissions are unsafe'):
                guard.protect('4.14.1-1')


class DnfGuardTests(unittest.TestCase):
    """Global versionlock ownership with real files; the DNF resolver is modeled."""

    def tree(self, temporary, locks=None, plugin_enabled=True, plugins=True):
        folder = Path(temporary) / 'dnf'; (folder / 'plugins').mkdir(parents=True)
        main = folder / 'dnf.conf'; main.write_text('[main]\nplugins=' + ('1' if plugins else '0') + '\n'); main.chmod(0o644)
        plugin = folder / 'plugins/versionlock.conf'
        plugin.write_text('[main]\nenabled=' + ('1' if plugin_enabled else '0') + '\nlocklist=' + str(folder / 'plugins/versionlock.list') + '\n')
        plugin.chmod(0o644)
        if locks is not None:
            (folder / 'plugins/versionlock.list').write_text(locks); (folder / 'plugins/versionlock.list').chmod(0o644)
        guard = w.PackageGuard('RedHat', Commands('RedHat'), Path(temporary) / 'private')
        guard.MAIN, guard.PLUGIN, guard.LOCKS = str(main), str(plugin), str(folder / 'plugins/versionlock.list')
        self.plans = []
        def native(payload):
            self.plans.append(payload)
            if payload['action'] == 'names':
                # DNF's own NEVRA possibilities parser is modeled: a wazuh-agent glob names wazuh-agent.
                return [['wazuh-agent'] if pattern.startswith('wazuh-agent') else ['unrelated'] for pattern in payload['patterns']]
            return {'plugins': ['versionlock'], 'install': [], 'remove': []}
        guard.dnf_native = native
        return guard, folder

    def test_resolving_dnf_oracle_requires_loaded_plugin_exact_target_and_no_dependencies(self):
        plan = {'plugins': ['versionlock'], 'install': [package_row('4.14.1-1')], 'remove': []}
        w.PackageGuard.validate_dnf_plan(plan, '4.14.1-1')
        for broken in ({**plan, 'plugins': []}, {**plan, 'install': []},
                       {**plan, 'install': [package_row('4.14.1-1'), {**package_row('4.14.1-1'), 'name': 'foreign'}]},
                       {**plan, 'install': [package_row('4.14.9-1')]},
                       {**plan, 'remove': [{**package_row('4.14.1-1'), 'name': 'foreign'}]},
                       {**plan, 'install': [{**package_row('4.14.1-1'), 'epoch': '1'}]}):
            with self.assertRaises(w.Refused, msg=str(broken)):
                w.PackageGuard.validate_dnf_plan(broken, '4.14.1-1')
        with self.assertRaisesRegex(w.Refused, 'permits a replacement'):
            w.PackageGuard.validate_dnf_plan(plan, '4.14.1-1', unchanged=True)
        w.PackageGuard.validate_dnf_plan({'plugins': ['versionlock'], 'install': [], 'remove': []}, '4.14.1-1', unchanged=True)

    def test_protect_writes_only_the_owned_rule_preserves_foreign_rules_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            guard, folder = self.tree(temporary, locks='# operator\nunrelated-0:1-1.x86_64\n')
            first = guard.protect('4.14.1-1')
            self.assertTrue(first['changed']); self.assertEqual(first['guard'], 'dnf-global-versionlock')
            text = (folder / 'plugins/versionlock.list').read_text()
            self.assertEqual(text, '# operator\nunrelated-0:1-1.x86_64\n' + guard.BEGIN + 'wazuh-agent-0:4.14.1-1.x86_64\n' + guard.END)
            before = (folder / 'plugins/versionlock.list').read_bytes()
            second = guard.protect('4.14.1-1')
            self.assertFalse(second['changed'])
            self.assertEqual((folder / 'plugins/versionlock.list').read_bytes(), before)
            # The installed package moved (operator action): the owned rule follows it, foreign rules stay.
            third = guard.protect('4.14.6-1')
            self.assertTrue(third['changed'])
            self.assertIn('wazuh-agent-0:4.14.6-1.x86_64', (folder / 'plugins/versionlock.list').read_text())
            self.assertIn('unrelated-0:1-1.x86_64', (folder / 'plugins/versionlock.list').read_text())

    def test_verify_requires_the_exact_owned_rule_and_a_plan_that_replaces_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            guard, folder = self.tree(temporary, locks='')
            with self.assertRaisesRegex(w.Refused, 'differs from installed'):
                guard.verify('4.14.1-1')
            guard.protect('4.14.1-1')
            guard.verify('4.14.1-1')
            with self.assertRaisesRegex(w.Refused, 'differs from installed'):
                guard.verify('4.14.9-1')
            guard.dnf_native = lambda payload: {'plugins': ['versionlock'], 'install': [package_row('4.14.9-1')], 'remove': [package_row('4.14.1-1')]}
            with self.assertRaisesRegex(w.Refused, 'permits a replacement'):
                guard.verify('4.14.1-1')

    def test_prerequisite_refuses_latent_disabled_redirected_and_foreign_policy_before_any_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            guard, folder = self.tree(temporary)
            locks, plugin, main = folder / 'plugins/versionlock.list', folder / 'plugins/versionlock.conf', folder / 'dnf.conf'
            plugin.unlink()
            # Control: a host with no versionlock plugin and no rules may gain the dependency.
            self.assertFalse(guard.ownership()['plugin']['present'])
            locks.write_text('unrelated-0:1-1.x86_64\n'); locks.chmod(0o644)
            with self.assertRaisesRegex(w.Refused, 'activate latent global rules'):
                guard.ownership()
            locks.write_text('')
            for settings, error in (('[main]\nenabled=0\nlocklist=' + guard.LOCKS + '\n', 'disabled'),
                                    ('[main]\nenabled=1\nlocklist=/outside/rules\n', 'redirected')):
                plugin.write_text(settings); plugin.chmod(0o644)
                with self.assertRaisesRegex(w.Refused, error):
                    guard.ownership()
            plugin.write_text('[main]\nenabled=1\nlocklist=' + guard.LOCKS + '\n')
            locks.write_text('wazuh-agent-*\n')
            with self.assertRaisesRegex(w.Refused, 'foreign versionlock ownership'):
                guard.ownership()
            locks.write_text(guard.BEGIN + 'wazuh-agent-0:4.14.1-1.x86_64\n' + guard.BEGIN + guard.END)
            with self.assertRaisesRegex(w.Refused, 'ambiguous owned'):
                guard.ownership()
            locks.write_text(guard.BEGIN + 'wazuh-agent-0:4.14.1-1.x86_64\n' + guard.END)
            self.assertEqual(guard.ownership()['owned'], 'wazuh-agent-0:4.14.1-1.x86_64')
            locks.write_text(guard.BEGIN + 'wazuh-agent-0:5.0.0-1.x86_64\n' + guard.END)
            with self.assertRaisesRegex(w.Refused, 'unknown owned'):
                guard.ownership()
            locks.write_text('')
            main.write_text('[main]\nplugins=0\n')
            with self.assertRaisesRegex(w.Refused, 'plugins are disabled'):
                guard.ownership()
            main.write_text('[main]\nplugins=1\npluginconfpath=/redirected\n')
            with self.assertRaisesRegex(w.Refused, 'redirected or unknown'):
                guard.ownership()
            main.write_text('[main]\nplugins=1\ninstallroot=/mnt/image\n')
            with self.assertRaisesRegex(w.Refused, 'redirected or unknown'):
                guard.ownership()
            self.assertEqual(locks.read_text(), '', 'a refused policy never rewrites the foreign state')

    def test_an_unresolvable_foreign_rule_refuses_instead_of_being_assumed_unrelated(self):
        with tempfile.TemporaryDirectory() as temporary:
            guard, folder = self.tree(temporary, locks='something-odd\n')
            guard.dnf_native = lambda payload: [[]]
            with self.assertRaisesRegex(w.Refused, 'unknown foreign versionlock rule'):
                guard.ownership()
            guard.dnf_native = lambda payload: [['wazuh-agent']]
            with self.assertRaisesRegex(w.Refused, 'overlaps Wazuh'):
                guard.ownership()

    def test_rpm_provider_requires_official_hash_and_rejects_competing_same_nevra(self):
        official = {'repo': 'wazuh', 'url': 'https://packages.wazuh.com/4.x/yum/wazuh-agent.rpm',
                    'sha256': 'a' * 64, 'checksum_type': 'sha256', 'gpgcheck': True,
                    'gpgkey': ['https://packages.wazuh.com/key/GPG-KEY-WAZUH'],
                    'baseurl': ['https://packages.wazuh.com/4.x/yum/']}
        guard = w.PackageGuard('RedHat', Commands('RedHat'))
        records = [official]
        guard.dnf_native = lambda payload: records
        self.assertEqual(guard.official_rpm_provider({'config': 'private'}, '4.14.1-1')['sha256'], 'a' * 64)
        for records in ([{**official, 'repo': 'foreign'}],
                        [official, {**official, 'repo': 'foreign', 'sha256': 'b' * 64}],
                        [official, {**official, 'repo': 'foreign', 'sha256': 'invalid'}],
                        [{**official, 'gpgcheck': False}], [{**official, 'gpgkey': ['https://other/key']}],
                        [{**official, 'url': 'http://packages.wazuh.com/4.x/yum/x.rpm'}],
                        [{**official, 'url': 'https://packages.wazuh.com.evil/4.x/yum/x.rpm'}],
                        [{**official, 'baseurl': ['https://mirror.example/4.x/yum/']}], []):
            with self.assertRaises(w.Refused, msg=str(records)):
                guard.official_rpm_provider({'config': 'private'}, '4.14.1-1')


class RpmFixture:
    """Real private filesystem/scope; explicit native SELinux/RPM substitute.

    The model reproduces only the observed rpmdb_t/var_t failure and the
    vendor-key distinction. Actual native MAC and signature behavior is target
    evidence; these tests are not a VM acceptance receipt.
    """
    OWNER = 'e' * 32
    PACKAGE = '4.14.1-1'

    @contextlib.contextmanager
    def fixture(self, state='Enforcing'):
        test = self
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private'; w.private_dir(root)

            class Native:
                def __init__(native):
                    native.calls = []; native.contexts = {}; native.state = state
                    native.policy = 'system_u:object_r:rpm_var_lib_t:s0'
                    native.dbpath = '/var/lib/rpm'; native.failure = None
                    native.chcon_effect = 'type'; native.keys = ['gpg-pubkey-29111145-591cd381']
                    native.installed = ''; native.payload = b'official:' + test.PACKAGE.encode()
                    native.identity = test.PACKAGE

                def context(native, path):
                    return native.contexts.get(str(path), 'unconfined_u:object_r:var_t:s0')

                def run(native, argv, **kwargs):
                    argv = [str(value) for value in argv]; native.calls.append(argv); text = ''; rc = 0
                    if native.failure == argv[0]: raise w.Refused('injected missing/failed native tool: ' + argv[0])
                    if argv[0] == 'getenforce': text = native.state
                    elif argv[0] == 'matchpathcon': text = native.policy
                    elif argv[:2] == ['rpm', '--eval']: text = native.dbpath
                    elif argv[0] == 'chcon':
                        test.assertEqual(argv[1:3], ['--type=rpm_var_lib_t', '--'])
                        test.assertEqual(len(argv), 4, 'only the exact new directory may be labeled')
                        path = Path(argv[3]); test.assertEqual(list(path.iterdir()), [])
                        if native.chcon_effect == 'type':
                            parts = native.context(path).split(':', 3); parts[2] = 'rpm_var_lib_t'
                            native.contexts[str(path)] = ':'.join(parts)
                        elif native.chcon_effect == 'user':
                            native.contexts[str(path)] = 'system_u:object_r:rpm_var_lib_t:s0'
                    elif argv[0] == 'curl':
                        Path(argv[argv.index('--output') + 1]).write_bytes(b'HTTPS authenticated official public key fixture')
                    elif argv[0] == 'rpm' and '--dbpath' in argv:
                        db = Path(argv[argv.index('--dbpath') + 1])
                        if '--initdb' in argv:
                            if native.state == 'Enforcing' and native.context(db).split(':')[2] != 'rpm_var_lib_t':
                                raise w.Refused('modeled native rpmdb_t write denied on var_t')
                            for name in ('.rpm.lock', 'rpmdb.sqlite', 'rpmdb.sqlite-wal', 'rpmdb.sqlite-shm'):
                                child = db / name; child.write_bytes(b'private SQLite native fixture'); child.chmod(0o644)
                                native.contexts[str(child)] = native.context(db)
                        elif '--import' not in argv: text = '\n'.join(native.keys) + '\n'
                    elif argv[0] == 'rpmkeys':
                        if '--dbpath' in argv and not Path(argv[-1]).read_bytes().startswith(b'official:'):
                            text = 'RSA/SHA256 Signature, key ID b86b3716: NOKEY\n'; rc = 1
                        else: text = 'RSA/SHA256 Signature, key ID 29111145: OK\n'
                    elif argv[:2] == ['rpm', '-q']:
                        text = native.installed + '\tx86_64' if native.installed else 'package wazuh-agent is not installed'; rc = 0 if native.installed else 1
                    elif argv[:2] == ['rpm', '-qp']:
                        text = 'wazuh-agent\n' + native.identity + '\nx86_64'
                    elif argv[0] == 'dnf':
                        test.assertIn('--downloadonly', argv, 'the coordinator only stages; the playbook installs')
                        folder = Path(next(value.split('=', 1)[1] for value in argv if value.startswith('--downloaddir=')))
                        (folder / 'fresh.rpm').write_bytes(native.payload)
                    else: raise AssertionError(argv)
                    if rc not in kwargs.get('allowed', (0,)):
                        raise w.Refused('modeled native RPM signature NOKEY')
                    return subprocess.CompletedProcess(argv, rc, text, '')
            native = Native(); guard = w.PackageGuard('RedHat', native, root)
            original = w.os.getxattr

            def xattr(path, name, **kwargs):
                if name == 'security.selinux': return (native.context(path) + '\0').encode()
                return original(path, name, **kwargs)
            with mock.patch.object(w.os, 'getxattr', side_effect=xattr):
                yield root, native, guard


class PrivateRpmKeyringTests(RpmFixture, unittest.TestCase):
    def test_shared_builder_prepares_before_init_import_and_proves_native_children(self):
        for state in ('Enforcing', 'Permissive', 'Disabled'):
            with self.subTest(state=state), self.fixture(state) as (_, native, guard):
                ring = guard.official_rpm_keyring(self.OWNER)
                commands = [call[0] for call in native.calls]
                first_init = next(i for i, call in enumerate(native.calls) if '--initdb' in call)
                first_import = next(i for i, call in enumerate(native.calls) if '--import' in call)
                self.assertLess(first_init, first_import)
                if state == 'Disabled':
                    self.assertNotIn('chcon', commands); self.assertNotIn('matchpathcon', commands)
                    self.assertIsNone(ring['context'])
                else:
                    self.assertLess(commands.index('chcon'), first_init)
                    self.assertEqual(ring['context'], 'unconfined_u:object_r:rpm_var_lib_t:s0')
                    self.assertTrue(all(native.context(child) == ring['context'] for child in Path(ring['database']).iterdir()))
                self.assertEqual(ring['keys'], ['gpg-pubkey-29111145-591cd381'])
                self.assertTrue(all('--dbpath' in call for call in native.calls if '--import' in call))
                artifact = Path(ring['database']).parent / 'official.rpm'; artifact.write_bytes(b'official:4.14.1-1')
                guard.verify_official_rpm(artifact, {'sha256': w.digest(artifact)}, ring, self.OWNER)
                self.assertTrue(all('--dbpath' in call for call in native.calls if call[0] == 'rpmkeys'))

    def test_policy_state_tools_or_type_change_refuse_before_any_init_or_import(self):
        cases = [('state', 'unknown'), ('failure', 'getenforce'), ('failure', 'matchpathcon'),
                 ('failure', 'chcon'), ('policy', 'system_u:object_r:var_t:s0'), ('policy', 'bad context'),
                 ('dbpath', '/operator/redirected-db'), ('chcon_effect', 'ignored'), ('chcon_effect', 'user')]
        for field, value in cases:
            with self.subTest(field=field, value=value), self.fixture() as (_, native, guard):
                setattr(native, field, value)
                with self.assertRaises(w.Refused): guard.official_rpm_keyring(self.OWNER)
                self.assertFalse(any('--initdb' in call or '--import' in call for call in native.calls))

    def test_preparation_withdrawal_reproduces_enforcing_init_denial(self):
        with self.fixture() as (_, native, guard):
            with mock.patch.object(guard, 'prepare_rpm_keyring', return_value=None):
                with self.assertRaisesRegex(w.Refused, 'rpmdb_t write denied on var_t'):
                    guard.official_rpm_keyring(self.OWNER)
            self.assertTrue(any('--initdb' in call for call in native.calls))
            self.assertFalse(any('--import' in call for call in native.calls))

    def test_existing_or_nonempty_database_never_gains_relabel_authority(self):
        with self.fixture() as (root, native, guard):
            ring = guard.official_rpm_keyring(self.OWNER); native.calls.clear()
            with self.assertRaisesRegex(w.Refused, 'new empty'):
                guard.prepare_rpm_keyring(ring['database'], self.OWNER)
            self.assertFalse(any(call[0] == 'chcon' for call in native.calls))
            # An existing empty UUID collision is still refused before relabel.
            collision = Path(ring['database']).parent / ('official-keyring-' + 'a' * 32); collision.mkdir(mode=0o700)
            with mock.patch.object(w.uuid, 'uuid4', return_value=type('UUID', (), {'hex': 'a' * 32})()):
                with self.assertRaisesRegex(w.Refused, 'exclusive new'):
                    guard.official_rpm_keyring(self.OWNER)
            self.assertEqual(list(collision.iterdir()), [])
            self.assertFalse(any(call[0] == 'chcon' for call in native.calls))

    def test_retained_label_inventory_or_native_child_shape_drift_never_repairs_or_verifies_signature(self):
        cases = ('directory-label', 'child-label', 'missing-child', 'child-symlink', 'child-hardlink',
                 'unexpected-child', 'writable-child', 'extra-key', 'directory-symlink', 'foreign-owner', 'mount')
        for case in cases:
            with self.subTest(case=case), self.fixture() as (root, native, guard):
                ring = guard.official_rpm_keyring(self.OWNER); db = Path(ring['database'])
                artifact = db.parent / 'official.rpm'; artifact.write_bytes(b'official:4.14.1-1')
                native.calls.clear(); namespace = MOUNT_NAMESPACE['text']
                with contextlib.ExitStack() as stack:
                    if case == 'directory-label': native.contexts[str(db)] = 'unconfined_u:object_r:var_t:s0'
                    elif case == 'child-label': native.contexts[str(db / 'rpmdb.sqlite')] = 'unconfined_u:object_r:var_t:s0'
                    elif case == 'missing-child': (db / 'rpmdb.sqlite').unlink()
                    elif case == 'child-symlink':
                        (db / 'rpmdb.sqlite').unlink(); (db / 'rpmdb.sqlite').symlink_to(artifact)
                    elif case == 'child-hardlink': w.os.link(db / 'rpmdb.sqlite', db.parent / 'foreign-alias')
                    elif case == 'unexpected-child': (db / 'foreign').write_bytes(b'foreign')
                    elif case == 'writable-child': (db / 'rpmdb.sqlite').chmod(0o666)
                    elif case == 'extra-key': native.keys.append('gpg-pubkey-b86b3716-61e69f29')
                    elif case == 'directory-symlink':
                        moved = db.with_name('outside'); db.rename(moved); db.symlink_to(moved, target_is_directory=True)
                    elif case == 'foreign-owner': stack.enter_context(mock.patch.object(w.os, 'geteuid', return_value=w.os.geteuid() + 1))
                    else: MOUNT_NAMESPACE['text'] += f'2 1 8:1 / {db} rw - ext4 /dev/synthetic rw\n'
                    try:
                        with self.assertRaises(w.Refused):
                            guard.verify_official_rpm(artifact, {'sha256': w.digest(artifact)}, ring, self.OWNER)
                    finally: MOUNT_NAMESPACE['text'] = namespace
                self.assertFalse(any(call[0] in ('chcon', 'rpmkeys') or '--import' in call for call in native.calls))

    def test_retained_context_native_tool_failure_does_not_relabel_or_fall_back(self):
        for field, value in (('state', 'unknown'), ('policy', 'system_u:object_r:var_t:s0'),
                             ('failure', 'getenforce'), ('failure', 'matchpathcon')):
            with self.subTest(field=field, value=value), self.fixture() as (_, native, guard):
                ring = guard.official_rpm_keyring(self.OWNER)
                artifact = Path(ring['database']).parent / 'official.rpm'; artifact.write_bytes(b'official:4.14.1-1')
                native.calls.clear(); setattr(native, field, value)
                with self.assertRaises(w.Refused):
                    guard.verify_official_rpm(artifact, {'sha256': w.digest(artifact)}, ring, self.OWNER)
                self.assertFalse(any(call[0] in ('chcon', 'rpmkeys') or '--import' in call for call in native.calls))

    def test_vendor_only_signature_remains_required_even_for_matching_provider_hash(self):
        with self.fixture() as (_, native, guard):
            ring = guard.official_rpm_keyring(self.OWNER)
            artifact = Path(ring['database']).parent / 'foreign-alma.rpm'; artifact.write_bytes(b'foreign:3.1.5-8.el9')
            native.calls.clear()
            with self.assertRaisesRegex(w.Refused, 'NOKEY'):
                guard.verify_official_rpm(artifact, {'sha256': w.digest(artifact)}, ring, self.OWNER)
            self.assertEqual(len([call for call in native.calls if call[0] == 'rpmkeys']), 1)
            self.assertIn('--dbpath', native.calls[-1])
            with self.assertRaisesRegex(w.Refused, 'identity changed'):
                guard.verify_official_rpm(artifact, {'sha256': 'f' * 64}, ring, self.OWNER)

    def test_a_scope_or_owner_that_is_not_the_exact_private_directory_is_refused(self):
        with self.fixture() as (root, native, guard):
            for owner in ('../x', 'E' * 32, 'e' * 31, '', 'e' * 32 + '/..'):
                with self.assertRaises(w.Refused, msg=owner):
                    guard.official_rpm_keyring(owner)
            self.assertEqual(list(root.iterdir()), [], 'a refused owner must create nothing')
            self.assertEqual(native.calls, [])
            ring = guard.official_rpm_keyring(self.OWNER)
            with self.assertRaisesRegex(w.Refused, 'escaped its exact'):
                guard.verify_rpm_keyring(dict(ring, database=str(root)), self.OWNER)
            with self.assertRaisesRegex(w.Refused, 'invalid private RPM keyring owner'):
                guard.verify_rpm_keyring(ring, 'f' * 31)
            MOUNT_NAMESPACE['text'] = '1 0 8:1 /sub / rw - ext4 /dev/synthetic rw\n'
            try:
                with self.assertRaisesRegex(w.Refused, 'subtree or bind-mount'):
                    guard.verify_rpm_keyring(ring, self.OWNER)
            finally:
                MOUNT_NAMESPACE['text'] = '1 0 8:1 / / rw - ext4 /dev/synthetic rw\n'


class FreshRpmTests(RpmFixture, unittest.TestCase):
    """The signed exact fresh RPM: stage, bind to the official source and the vendor-only key."""

    def agent(self, root, native, official=True):
        guard = w.PackageGuard('RedHat', native, root)
        context = {'main': {'text': '[main]\nplugins=1\n', 'sha256': 'a' * 64},
                   'plugin': {'text': '[main]\nenabled=1\nlocklist=' + guard.LOCKS + '\n', 'sha256': 'b' * 64, 'present': True},
                   'locks': {'text': ''}, 'foreign': '', 'owned': None}
        guard.dnf_context = lambda dependency_optional=False: context
        self.plans = []

        def dnf(payload):
            self.plans.append(payload)
            if payload['action'] == 'providers':
                digest = hashlib.sha256(native.payload).hexdigest()
                url = 'https://packages.wazuh.com/4.x/yum/wazuh-agent-' + self.PACKAGE + '.x86_64.rpm'
                return [{'repo': 'wazuh' if official else 'foreign', 'url': url, 'checksum_type': 'sha256', 'sha256': digest,
                         'gpgcheck': True, 'gpgkey': ['https://packages.wazuh.com/key/GPG-KEY-WAZUH'],
                         'baseurl': ['https://packages.wazuh.com/4.x/yum/']}]
            return {'plugins': ['versionlock'], 'install': [package_row(payload['spec'].split(':', 1)[1].rsplit('.', 1)[0])], 'remove': []}
        guard.dnf_native = dnf
        agent = w.Agent('RedHat', runner=native, root=root)
        agent.guard = lambda: guard
        return agent, guard

    def plan(self):
        return w.agent_plan('', '4.14.1')

    def test_fresh_stage_returns_the_exact_verified_payload_and_only_downloads(self):
        with self.fixture() as (root, native, _):
            agent, guard = self.agent(root, native)
            staged = agent.fresh_rpm(self.OWNER, self.plan())
            self.assertEqual(w.digest(staged['package_path']), hashlib.sha256(native.payload).hexdigest())
            self.assertTrue(staged['package_path'].startswith(str(root / ('rpm-fresh-' + self.OWNER))))
            self.assertEqual(Path(staged['dnf_conf_file']).parent, root / ('agent-policy-' + self.OWNER))
            dnf = [call for call in native.calls if call[0] == 'dnf']
            self.assertEqual(len(dnf), 1)
            for token in ('--downloadonly', '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1', '--disableexcludes=wazuh',
                          'wazuh-agent-0:' + self.PACKAGE + '.x86_64'):
                self.assertIn(token, dnf[0])
            signatures = [call for call in native.calls if call[0] == 'rpmkeys']
            self.assertEqual(len(signatures), 1, 'the staged payload is checked once, against the private vendor-only key ring')
            self.assertIn('--dbpath', signatures[0]); self.assertEqual(signatures[0][-1], staged['package_path'])
            self.assertTrue(all('--dbpath' in call for call in native.calls if call[:2] == ['rpm', '--import']))
            commands = [call[0] for call in native.calls]
            self.assertLess(commands.index('chcon'), commands.index('dnf'))
            self.assertFalse(any(call[:2] == ['rpm', '-U'] or 'install' in call and '--downloadonly' not in call for call in native.calls))

    def test_every_binding_failure_refuses_before_a_package_is_offered_for_install(self):
        cases = {
            'a payload signed by another key': lambda native: setattr(native, 'payload', b'foreign:' + self.PACKAGE.encode()),
            'an RPM that is another package version': lambda native: setattr(native, 'identity', '4.14.9-1'),
            'a competing-provider source': None,
        }
        for name, break_it in cases.items():
            with self.subTest(name), self.fixture() as (root, native, _):
                agent, guard = self.agent(root, native, official=break_it is not None)
                if break_it:
                    break_it(native)
                with self.assertRaises(w.Refused):
                    agent.fresh_rpm(self.OWNER, self.plan())

    def test_a_payload_whose_hash_differs_from_the_authenticated_provider_is_not_selected(self):
        with self.fixture() as (root, native, _):
            agent, guard = self.agent(root, native)
            original = guard.dnf_native
            def dnf(payload):
                value = original(payload)
                if payload['action'] == 'providers':
                    value[0]['sha256'] = 'c' * 64
                return value
            guard.dnf_native = dnf
            with self.assertRaisesRegex(w.Refused, 'one exact official payload'):
                agent.fresh_rpm(self.OWNER, self.plan())

    def test_fresh_stage_is_refused_for_the_wrong_backend_installed_agent_or_plan_before_any_native_tool(self):
        with self.fixture() as (root, native, _):
            agent, _ = self.agent(root, native)
            for plan in ({**self.plan(), 'install': False}, {**self.plan(), 'package': '4.14.9-1'},
                         w.agent_plan('4.14.1-1', '4.14.1')):
                with self.assertRaisesRegex(w.Refused, 'current compatible fresh plan'):
                    agent.fresh_rpm(self.OWNER, plan)
            # A plan above the manager it names is not a compatible fresh plan either.
            with self.assertRaisesRegex(w.Refused, 'newer than the observed manager'):
                agent.fresh_rpm(self.OWNER, {**self.plan(), 'version': '4.14.9'})
            native.installed = '4.14.1-1'
            with self.assertRaisesRegex(w.Refused, 'current compatible fresh plan'):
                agent.fresh_rpm(self.OWNER, self.plan())
            self.assertFalse(any(call[0] in ('dnf', 'curl', 'chcon', 'rpmkeys') for call in native.calls))
            debian = w.Agent('Debian', runner=native, root=root)
            with self.assertRaises(w.Refused):
                debian.fresh_rpm(self.OWNER, self.plan())
            for owner in ('../escape', 'x' * 32, ''):
                with self.assertRaisesRegex(w.Refused, 'invalid private RPM stage owner'):
                    agent.fresh_rpm(owner, self.plan())
            self.assertFalse(any(path.name.startswith(('agent-policy-', 'rpm-fresh-')) for path in root.iterdir()))

    def test_a_stale_or_aliased_artifact_in_the_stage_directory_is_refused(self):
        with self.fixture() as (root, native, _):
            agent, _ = self.agent(root, native)
            folder = w.private_dir(root / ('rpm-fresh-' + self.OWNER))
            outside = root / 'outside.rpm'; outside.write_bytes(b'x')
            (folder / 'alias.rpm').symlink_to(outside)
            with self.assertRaises(w.Refused):
                agent.fresh_rpm(self.OWNER, self.plan())
            self.assertFalse(any(call[0] == 'dnf' for call in native.calls))


class ProtectionFlowTests(unittest.TestCase):
    """Agent.protect_package / verify through the real class, one native model per family."""

    def agent(self, native, folder):
        agent = w.Agent(native.family, runner=native, root=folder / 'private')
        return agent

    def test_protect_refuses_an_absent_package_and_takes_the_component_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            native = Commands('Debian', '')
            agent = self.agent(native, Path(temporary))
            locks = []
            real = w.bounded_flock

            @contextlib.contextmanager
            def recording(filename, **kwargs):
                locks.append(Path(filename).name)
                with real(filename, **kwargs):
                    yield
            with mock.patch.object(w, 'bounded_flock', recording):
                with self.assertRaisesRegex(w.Refused, 'absent'):
                    agent.protect_package()
            self.assertEqual(locks, ['agent.lock'])
            self.assertEqual(oct((Path(temporary) / 'private').stat().st_mode & 0o777), '0o700')

    def test_verify_reports_the_stable_native_release_pin_and_availability(self):
        with tempfile.TemporaryDirectory() as temporary:
            class Native(Commands):
                active, release, held = True, '4.14.1', True
                def run(inner, argv, **kwargs):
                    if argv[0] == '/var/ossec/bin/wazuh-control':
                        return subprocess.CompletedProcess(argv, 0, 'WAZUH_VERSION="v' + inner.release + '"\nWAZUH_REVISION="40100"\n', '')
                    if argv[:2] == ['systemctl', 'is-active']:
                        return subprocess.CompletedProcess(argv, 0 if inner.active else 3, '', '')
                    return super().run(argv, **kwargs)
            native = Native('Debian', '4.14.1-1')
            agent = self.agent(native, Path(temporary))
            guard = mock.Mock()
            guard.verify.return_value = {'guard': 'apt-hold'}
            agent.guard = lambda: guard
            self.assertEqual(agent.verify(), {'pass': True, 'version': '4.14.1', 'guard': 'apt-hold'})
            guard.verify.assert_called_once_with('4.14.1-1')
            native.release = '4.14.9'
            with self.assertRaisesRegex(w.Refused, 'release differ'):
                agent.verify()
            native.release = '4.14.1'; native.active = False
            with self.assertRaisesRegex(w.Refused, 'inactive'):
                agent.verify()
            native.active = True; guard.verify.side_effect = w.Refused('effective agent is not protected by its native APT hold')
            with self.assertRaisesRegex(w.Refused, 'native APT hold'):
                agent.verify()
            native.installed = ''
            with self.assertRaisesRegex(w.Refused, 'not installed'):
                agent.verify()
            self.assertFalse((Path(temporary) / 'private').exists(), 'a read-only verify creates nothing')

    def test_reads_take_no_lock_and_create_nothing_so_check_mode_is_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            native = Commands('RedHat', '4.14.1-1')
            agent = self.agent(native, Path(temporary))
            with mock.patch.object(w, 'bounded_flock', side_effect=AssertionError('a read must not lock')):
                agent.check('4.14.9')
                agent.check('')
                agent.guard = lambda: mock.Mock(ownership=lambda: {'plugin': {'present': False}})
                self.assertEqual(agent.policy_ownership(), {'checked': True, 'prerequisite_plugin_present': False})
            self.assertFalse((Path(temporary) / 'private').exists())

    def test_a_second_concurrent_mutator_is_refused_instead_of_interleaving(self):
        with tempfile.TemporaryDirectory() as temporary:
            agent = self.agent(Commands('Debian', '4.14.1-1'), Path(temporary))
            with agent.lock():
                with self.assertRaisesRegex(w.Refused, 'timed out'):
                    with w.bounded_flock(agent.root / 'agent.lock', timeout=0.1):
                        self.fail('the component lock must be exclusive')
            with agent.lock():
                pass


class CentralTests(unittest.TestCase):
    def central(self, release='4.14.1', agents=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        docker = Docker(w, root, release, agents)
        return w.Central(root=root / 'private', managed_root=docker.managed, runner=docker), docker

    def test_observe_manager_reports_the_native_effective_release_only(self):
        central, docker = self.central('4.14.6')
        self.assertEqual(central.observe_manager(), {'version': '4.14.6'})
        self.assertEqual(docker.calls[-1][:3], ['docker', 'exec', 'single-node-wazuh.manager-1'])
        for text in ('', 'WAZUH_VERSION="v5.0.0"\n', 'WAZUH_VERSION="v4.14.1"\nWAZUH_VERSION="v4.14.9"\n', 'WAZUH_VERSION="4.14.9-rc1"\n'):
            central.r.run = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, text, '')
            with self.assertRaisesRegex(w.Refused, 'unknown effective manager version'):
                central.observe_manager()
        def down(argv, **kwargs):
            raise w.Refused('operation failed: docker rc=1')
        central.r.run = down
        with self.assertRaises(w.Refused):
            central.observe_manager()

    def test_discovery_accepts_the_complete_healthy_stack_and_reports_its_release(self):
        central, docker = self.central()
        state = central.discover()
        self.assertEqual((state['version'], state['directory']), ('4.14.1', str(docker.project)))
        self.assertEqual(set(state['images']), set(w.SERVICES))

    def test_discovery_of_no_stack_is_absence_but_a_docker_failure_is_never_absence(self):
        central, docker = self.central()
        docker.drop = set(w.SERVICES)
        self.assertIsNone(central.discover())
        def broken(argv, **kwargs):
            raise w.Refused('operation failed: docker rc=1')
        central.r.run = broken
        with self.assertRaises(w.Refused):
            central.discover()

    def test_discovery_refuses_every_unidentifiable_or_unhealthy_stack(self):
        cases = {
            'partial stack': (lambda d: setattr(d, 'drop', {'wazuh.dashboard'}), 'partial Wazuh central stack'),
            'stopped component': (lambda d: d.containers[0]['State'].update(Running=False), 'not running'),
            'mixed releases': (lambda d: d.tags.update({'wazuh.dashboard': '4.14.9'}), 'mixed Wazuh releases'),
            'unknown release tag': (lambda d: d.tags.update({s: 'latest' for s in w.SERVICES}), 'official immutable release provenance'),
            'no official digest': (lambda d: setattr(d, 'repo_digests', False), 'official immutable release provenance'),
            'indexer unhealthy': (lambda d: setattr(d, 'indexer_status', 'red'), 'indexer health failed'),
            'manager daemon down': (lambda d: d.stopped_daemons.add('remoted'), 'daemons are not healthy'),
        }
        for name, (break_it, reason) in cases.items():
            with self.subTest(name):
                central, docker = self.central()
                break_it(docker)
                with self.assertRaisesRegex(w.Refused, reason):
                    central.discover()

    def test_discovery_refuses_a_native_release_that_disagrees_with_the_image_tag(self):
        central, docker = self.central()
        docker.release = '4.14.9'
        with self.assertRaisesRegex(w.Refused, 'effective version probe failed'):
            central.discover()

    def test_an_active_compose_project_outside_the_pilot_layout_is_refused(self):
        central, docker = self.central()
        central.managed_root = docker.managed.parent / 'elsewhere'
        with self.assertRaisesRegex(w.Refused, 'outside the pilot-owned single-node layout'):
            central.discover()
        central.managed_root = docker.managed
        wrong = docker.managed / 'wazuh-docker-4.14.1' / 'multi-node'
        wrong.mkdir(parents=True); (wrong / 'docker-compose.yml').write_text('services: {}\n')
        docker.project, docker.compose = wrong, wrong / 'docker-compose.yml'
        with self.assertRaisesRegex(w.Refused, 'outside the pilot-owned single-node layout'):
            central.discover()

    def test_gate_is_a_noop_on_an_absent_stack_so_a_fresh_install_pins_the_requested_release(self):
        central, docker = self.central()
        docker.drop = set(w.SERVICES)
        self.assertEqual(central.gate('4.14.6'), {'changed': False, 'fresh': True, 'version': '4.14.6'})

    def test_gate_accepts_an_existing_stack_only_at_exactly_the_requested_release(self):
        central, docker = self.central('4.14.1')
        result = central.gate('4.14.1')
        self.assertEqual(result, {'changed': False, 'fresh': False, 'version': '4.14.1', 'directory': str(docker.project)})

    def test_gate_refuses_any_release_change_before_looking_at_anything_that_could_mutate(self):
        for running, requested in (('4.14.1', '4.14.9'), ('4.14.9', '4.14.1'), ('4.14.6', '4.14.9'), ('4.14.9', '4.14.6')):
            with self.subTest(running=running, requested=requested):
                central, docker = self.central(running)
                with self.assertRaisesRegex(w.Refused, 'central release change is not supported'):
                    central.gate(requested)
                self.assertFalse(any(call[1] in ('compose', 'pull', 'stop', 'rm', 'run', 'up', 'restart', 'image') and call[:3] != ['docker', 'image', 'inspect']
                                     for call in docker.calls if call[0] == 'docker'), docker.calls)

    def test_gate_refuses_an_invalid_or_unsupported_target(self):
        central, _ = self.central()
        for target in ('', '5.0.0', '4.14', 'latest', '4.14.1-1'):
            with self.assertRaises(w.Refused, msg=target):
                central.gate(target)

    def test_gate_refuses_a_registered_agent_newer_than_the_running_manager(self):
        central, docker = self.central('4.14.1', agents={'001': '4.14.1', '002': '4.14.9'})
        with self.assertRaisesRegex(w.Refused, 'registered agent is newer than the central release'):
            central.gate('4.14.1')
        docker.agents['002'] = '4.14.1'
        central.gate('4.14.1')

    def test_gate_refuses_when_the_active_compose_directory_is_not_the_requested_releases(self):
        central, docker = self.central('4.14.1')
        other = docker.managed / 'wazuh-docker-4.14.9' / 'single-node'
        other.mkdir(parents=True); (other / 'docker-compose.yml').write_text('services: {}\n')
        docker.project, docker.compose = other, other / 'docker-compose.yml'
        with self.assertRaisesRegex(w.Refused, 'does not match the requested release'):
            central.gate('4.14.1')

    def test_registry_bounds_every_retained_agent_and_unknown_versions_are_refused(self):
        central, docker = self.central('4.14.1', agents={'001': '4.14.1', '002': '4.14.6'})
        self.assertEqual(central.check_agents('4.14.6'), {'001': '4.14.1', '002': '4.14.6'})
        with self.assertRaisesRegex(w.Refused, 'newer than the central release'):
            central.check_agents('4.14.1')
        docker.agents['002'] = 'unknown'
        with self.assertRaisesRegex(w.Refused, 'unknown retained agent version'):
            central.check_agents('4.14.9')
        docker.agents = {}
        self.assertEqual(central.check_agents('4.14.1'), {}, 'a registry with only the manager is valid')
        original = docker.run
        docker.run = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, 'garbage', '') if '-l' in argv else original(argv, **kwargs)
        with self.assertRaisesRegex(w.Refused, 'unknown or ambiguous manager agent registry'):
            central.check_agents('4.14.9')

    def test_verify_is_the_read_only_native_oracle_for_c12(self):
        central, docker = self.central('4.14.1', agents={'001': '4.14.1'})
        self.assertEqual(central.verify(), {'pass': True, 'version': '4.14.1'})
        docker.agents['001'] = '4.14.9'
        with self.assertRaisesRegex(w.Refused, 'newer than the central release'):
            central.verify()
        docker.agents['001'] = '4.14.1'; docker.drop = set(w.SERVICES)
        with self.assertRaisesRegex(w.Refused, 'central stack is absent'):
            central.verify()

    def test_central_reads_never_lock_or_create_state(self):
        central, docker = self.central()
        with mock.patch.object(w, 'bounded_flock', side_effect=AssertionError('a read must not lock')):
            central.observe_manager(); central.gate('4.14.1'); central.verify()
        self.assertFalse((docker.managed.parent / 'private').exists())
        for call in docker.calls:
            self.assertNotIn(call[1], ('compose', 'pull', 'stop', 'rm', 'up', 'restart'), call)


class CommandLineTests(unittest.TestCase):
    """The real entry point: arguments, exit status and the typed JSON a playbook consumes."""

    def invoke(self, *argv, stdin='', commands=None, family='Debian'):
        commands = commands or Commands(family)
        stdout = io.StringIO()
        with mock.patch.object(sys, 'argv', ['wazuh-transaction.py', *argv]), mock.patch.object(sys, 'stdin', io.StringIO(stdin)), \
                mock.patch.object(w, 'is_root', return_value=True), mock.patch.object(w, 'Runner', lambda: commands), \
                contextlib.redirect_stdout(stdout):
            status = w.main()
        return status, json.loads(stdout.getvalue())

    def test_agent_check_prints_the_plan_and_exits_zero(self):
        status, value = self.invoke('agent-check', '--family', 'Debian', '--manager', '4.14.9', '--version', '')
        self.assertEqual((status, value['package'], value['install']), (0, '4.14.1-1', False))
        status, value = self.invoke('agent-check', '--family', 'RedHat', '--manager', '4.14.9', commands=Commands('RedHat', ''))
        self.assertEqual((status, value['package'], value['install']), (0, '4.14.9-1', True))

    def test_a_refusal_is_a_nonzero_exit_with_only_the_typed_pair_on_stdout(self):
        status, value = self.invoke('agent-check', '--family', 'Debian', '--manager', '4.14.0')
        self.assertEqual(status, 1)
        self.assertEqual(set(value), {'error', 'error_kind'})
        self.assertEqual((value['error_kind'], value['error']), ('refused', 'installed Wazuh agent is newer than the observed manager'))
        status, value = self.invoke('agent-check', '--family', 'Debian', '--manager', '4.14.9', '--version', '4.14.6',
                                    commands=Commands('Debian', '4.14.9-1'))
        self.assertEqual((status, value['error']), (1, 'Wazuh agent downgrade refused'))
        status, value = self.invoke('agent-check', '--family', 'Debian', '--manager', '4.14.9', '--version', '4.14.9')
        self.assertEqual((status, value['error']), (1, 'Wazuh agent upgrade is not supported by this version'))
        status, value = self.invoke('central', '--version', '4.14.9', '--legacy', '4.14.1')
        self.assertEqual((status, value['error']), (1, 'wazuh_version conflicts with wazuh_docker_version'))

    def test_a_native_failure_is_typed_without_leaking_what_failed(self):
        class Broken(Commands):
            def run(self, argv, **kwargs):
                raise KeyError('SECRET_SENTINEL')
        status, value = self.invoke('agent-check', commands=Broken())
        self.assertEqual((status, value['error_kind']), (1, 'native'))
        self.assertNotIn('SECRET_SENTINEL', json.dumps(value))

    def test_central_actions_run_the_gate_and_the_c12_oracle(self):
        with tempfile.TemporaryDirectory() as temporary:
            docker = Docker(w, Path(temporary), '4.14.1')
            with mock.patch.object(w.Central, '__init__', lambda self, **kwargs: w.Transaction.__init__(self, 'central', runner=docker, root=Path(temporary) / 'p') or setattr(self, 'managed_root', docker.managed)):
                self.assertEqual(self.invoke('manager-version', commands=docker), (0, {'version': '4.14.1'}))
                self.assertEqual(self.invoke('central', '--version', '4.14.1', commands=docker)[1]['fresh'], False)
                self.assertEqual(self.invoke('central-verify', commands=docker), (0, {'pass': True, 'version': '4.14.1'}))
                status, value = self.invoke('central', '--version', '4.14.9', commands=docker)
                self.assertEqual((status, value['error']), (1, 'central release change is not supported by this version'))
                self.assertEqual(self.invoke('central', commands=docker)[0], 0, 'the default release is the shipped 4.14.1')

    def test_the_cli_refuses_to_run_unprivileged_and_unknown_actions(self):
        with mock.patch.object(sys, 'argv', ['x', 'agent-check']), mock.patch.object(w, 'is_root', return_value=False):
            with self.assertRaises(SystemExit) as stop, contextlib.redirect_stderr(io.StringIO()):
                w.main()
            self.assertEqual(stop.exception.code, 2)
        for action in ('agent-upgrade', 'writer-claim', 'central-recover'):
            with mock.patch.object(sys, 'argv', ['x', action]), mock.patch.object(w, 'is_root', return_value=True):
                with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                    w.main()

    def test_fresh_rpm_reads_its_plan_from_stdin_and_validates_the_owner(self):
        status, value = self.invoke('agent-rpm-fresh', '--family', 'RedHat', '--owner', '../x',
                                    stdin=json.dumps(w.agent_plan('', '4.14.1')), commands=Commands('RedHat', ''))
        self.assertEqual((status, value['error']), (1, 'invalid private RPM stage owner'))
        status, value = self.invoke('agent-rpm-fresh', '--family', 'RedHat', '--owner', 'a' * 32,
                                    stdin='{}', commands=Commands('RedHat', ''))
        self.assertEqual((status, value['error_kind']), (1, 'native'), 'a malformed plan is a typed native failure, not a traceback')


if __name__ == '__main__':
    unittest.main(verbosity=2)
