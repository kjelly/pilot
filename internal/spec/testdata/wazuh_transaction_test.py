"""Behavioral controls for the real Wazuh coordinator (no host mutation).

Native command harnesses are explicitly separate from VM/systemd evidence.
Cold-backup recovery tests use real GNU tar and actual changed filesystem data.
"""
"""Behavioral controls for the real Wazuh version coordinator (no host mutation).

The coordinator is imported and driven in-process. Native commands (dpkg, rpm,
apt, dnf, docker, systemctl) are an explicit model: they prove the policy, the
parsing and the ordering of the real code, not VM/native evidence. The private
filesystem, flock and file-policy code run for real in temporary directories.
"""
import wazuh_hermetic  # noqa: F401  (tripwire first: no harness may touch real host state)
from wazuh_models import Docker, capture
import ast
import errno
import hashlib
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
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
apt = load('apt_exact_stage', 'playbooks/apply/files/apt-exact-stage.py')
ROOT_STARTED_ABSENT = not Path(w.ROOT).exists()

# No test creates host mounts. Feed the real mountinfo decoder an explicit
# disposable namespace, independent of the runner's sandbox/bind ancestry.
# Scope counterexamples replace this data, never the production validator.
RealMountTable = w.MountTable
MOUNT_NAMESPACE = {'text': '1 0 8:1 / / rw - ext4 /dev/synthetic rw\n'}
w.MountTable = lambda text=None: RealMountTable(MOUNT_NAMESPACE['text'] if text is None else text)


# `rpmkeys -Kv <rpm>`: native captures from the part-A target run (rpm 4.16 on AlmaLinux 9, a real
# Wazuh 4.14.9 RPM; native-captures/rpmkeys-Kv.<case>.rc<N>.txt). The return code of each case is the
# captured one. Two things the captures pin down:
#   * a TAMPERED payload still prints `Header V3 RSA/SHA256 Signature, key ID 29111145: OK` on its first
#     line, so the coordinator's line-level `Signature.*: OK` assertion alone cannot refuse it: only rpm's
#     non-zero status does (rc 1);
#   * an UNSIGNED package exits 0 with digest lines only, so only the line-level assertion refuses it.
# The *-rc0 shapes below are NOT captures: they are the captured text with the return code forced to 0, to
# prove the line-level assertion independently of rc.
def rpmkeys_kv(name, path):
    rc = int(re.search(r'\.rc([0-9])\.txt$', name)[1])
    first, rest = capture(name).split('\n', 1)
    return path + ':\n' + rest, rc


RPMKEYS_KV = {
    'signed': lambda path: rpmkeys_kv('rpmkeys-Kv.signed.rc0.txt', path),
    'digest-only': lambda path: rpmkeys_kv('rpmkeys-Kv.unsigned.rc0.txt', path),
    'nokey': lambda path: rpmkeys_kv('rpmkeys-Kv.nokey.rc1.txt', path),
    'tampered': lambda path: rpmkeys_kv('rpmkeys-Kv.tampered.rc1.txt', path),
    'truncated': lambda path: rpmkeys_kv('rpmkeys-Kv.truncated.rc1.txt', path),
    'nokey-rc0': lambda path: (rpmkeys_kv('rpmkeys-Kv.nokey.rc1.txt', path)[0], 0),
    'tampered-rc0': lambda path: (rpmkeys_kv('rpmkeys-Kv.tampered.rc1.txt', path)[0], 0),
    'empty': lambda path: ('', 0),
}


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
                          lambda: Path('/var/spool/rsyslog/pilot-wazuh').exists(),
                          lambda: os.listdir('/etc/rsyslog.d'),
                          lambda: Path('/etc/apparmor.d/usr.sbin.rsyslogd').read_bytes(),
                          # Mutations of host state are refused too: as root they would succeed.
                          lambda: os.mkdir('/var/backups/pilot/hermetic-probe'),
                          lambda: Path('/etc/dnf/plugins/versionlock.list').write_text('x'),
                          lambda: Path('/usr/local/libexec/pilot-wazuh-heartbeat').write_text('x'),
                          lambda: os.rename('/tmp/definitely-absent', '/opt/pilot/probe')):
            with self.assertRaises(wazuh_hermetic.HostStateTouched):
                operation()
        # Control: ordinary temporary files are not host state.
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / 'x').write_text('ok')
            self.assertEqual((Path(temporary) / 'x').read_text(), 'ok')

    def test_default_coordinator_paths_are_redirected_to_a_private_tree(self):
        redirected = {'ROOT': w.ROOT, 'Reader.SPOOL': w.Reader.SPOOL, 'Reader.PROFILE': w.Reader.PROFILE,
                      'Reader.CONFIG': w.Reader.CONFIG, 'Reader.CHECKER': w.Reader.CHECKER,
                      'Reader.RSYSLOG': w.Reader.RSYSLOG}
        for name in ('POLICY', 'CONFIG', 'FEATURES', 'CACHE'):
            redirected['ReaderPrestart.' + name] = getattr(w.ReaderPrestart, name)
        for name, value in redirected.items():
            self.assertIsNone(wazuh_hermetic.offending(value), name + ' still names real host state')
            self.assertTrue(str(value).startswith(str(HERMETIC_ROOT)), name)
            if name == 'ROOT':
                self.assertTrue(ROOT_STARTED_ABSENT, 'ROOT must start absent like a bare host')
            else:
                self.assertFalse(Path(value).exists(), name + ' must start absent like a bare host')

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
        with wazuh_hermetic.absent('/var/spool/rsyslog'):
            with self.assertRaises(FileNotFoundError):
                Path('/var/spool/rsyslog/pilot-wazuh').stat()
        with self.assertRaises(wazuh_hermetic.HostStateTouched):
            Path('/var/spool/rsyslog/pilot-wazuh').stat()


class TypedErrorContractTests(unittest.TestCase):
    """The no_log-hidden coordinator failure is disclosed from a typed field only.

    That is safe only while every Refused() message is a fixed literal. A single
    f-string or concatenation of tool output would put it on the user's screen.
    """
    DELIVERY = REPO / 'playbooks/files/pilot-wazuh-delivery'
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
        source = (REPO / 'playbooks/apply/files/wazuh-transaction.py').read_text()
        tree = ast.parse(source)
        owner = self.enclosing(tree)
        dynamic = set()
        literal = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'Refused':
                self.assertEqual(len(node.args), 1, 'Refused takes exactly one message (line %d)' % node.lineno)
                if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    literal += 1
                    self.assertRegex(node.args[0].value, r'^[ !#-\[\]-z|~]*$',
                                     'line %d: a fixed refusal must already be typed_error-clean' % node.lineno)
                else:
                    dynamic.add((owner[node], ast.unparse(node.args[0])))
        self.assertGreater(literal, 500, 'the scan must actually see the coordinator refusals')
        self.assertEqual(dynamic, {
            # label is a fixed operation name or argv[0]; the child's output is never appended.
            ('Runner.run', "'operation unavailable or timed out: ' + label"),
            ('Runner.run', "'operation failed: ' + label + ' rc=' + str(result.returncode)"),
            # identifier is the registry's own numeric id (regex [0-9]+), cut to nine digits: no name, IP or text.
            ('Central.check_agents', "'unknown retained agent version in manager registry (agent ID ' + identifier[:9] + ')'"),
            ('Central.check_agents', "'a registered agent is newer than the central release (agent ID ' + identifier[:9] + ')'"),
            # Fixed ValueError literals of pilot-wazuh-delivery (TypedErrorContractTests below).
            ('preview_tools', 'str(exc)'), ('preview_tool', 'str(exc)'), ('preview_argv', 'str(exc)'),
        }, 'a new non-literal Refused message can carry tool output or secrets onto the screen')

    def test_every_delivery_value_error_is_a_fixed_literal(self):
        tree = ast.parse(self.DELIVERY.read_text())
        count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and getattr(node.exc.func, 'id', '') == 'ValueError':
                count += 1
                self.assertTrue(len(node.exc.args) == 1 and isinstance(node.exc.args[0], ast.Constant)
                                and isinstance(node.exc.args[0].value, str),
                                'ValueError at line %d is not a fixed literal' % node.lineno)
        self.assertGreater(count, 30)

    def test_coordinator_and_delivery_typed_errors_agree_and_never_need_escaping(self):
        delivery = runpy.run_path(str(self.DELIVERY))['typed_error']
        pattern = re.compile('(?<="error": ")[^"]{1,300}(?=", "error_kind")')
        for text in ('plain text', 'quote " and backslash \\ end', 'unicode \u00e9\u4e2d', 'new\nline\ttab', 'x' * 500,
                     "apostrophe ' ok", 'braces {} [] ok'):
            for kind in ('refused', 'native'):
                value = w.typed_error(kind, text)
                self.assertEqual(value, delivery(kind, text))
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
        with self.assertRaisesRegex(w.Refused, 'conflicts'):
            w.desired('4.14.9', '4.14.1')

    def test_installed_older_equal_newer_and_explicit_upgrade(self):
        for installed in ('4.14.1-1', '4.14.6-1', '4.14.9-1', '4.14.9-2'):
            plan = w.agent_plan(installed, '4.14.9')
            self.assertFalse(plan['change'])
            self.assertEqual(plan['package'], installed)
        with self.assertRaisesRegex(w.Refused, 'newer than the observed manager'):
            w.agent_plan('4.14.9-1', '4.14.1')
        with self.assertRaisesRegex(w.Refused, 'requires'):
            w.agent_plan('4.14.6-1', '4.14.9', '4.14.9')
        self.assertTrue(w.agent_plan('4.14.6-1', '4.14.9', '4.14.9', True)['change'])
        with self.assertRaisesRegex(w.Refused, 'downgrade'):
            w.agent_plan('4.14.9-1', '4.14.9', '4.14.6', True)

    def test_unknown_versions_and_candidate_bound(self):
        for invalid in ('', '4.14', '5.0.0', '4.14.9-rc1', 'v4.14.9', '4.14.09'):
            if invalid:
                with self.assertRaises(w.Refused):
                    w.agent_plan('', invalid)
        with self.assertRaises(w.Refused):
            w.agent_plan('4.14.9-rc1', '4.14.9')
        with self.assertRaisesRegex(w.Refused, 'newer'):
            w.agent_plan('', '4.14.1', '4.14.9')
        self.assertEqual(w.agent_plan('', '4.14.9')['package'], '4.14.9-1')

    def test_standalone_retention_and_fresh_install_do_not_authorize_unobserved_upgrade(self):
        for family in ('Debian', 'RedHat'):
            with tempfile.TemporaryDirectory() as temporary:
                agent = w.Agent(family, root=Path(temporary) / 'private', runner=Commands(family, '4.14.1-1'))
                self.assertFalse(agent.check('')['change'])
                with self.assertRaisesRegex(w.Refused, 'requires an observed manager version'):
                    agent.check('', '4.14.9', True)
        self.assertEqual(w.agent_plan('', '')['package'], '4.14.1-1')

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
                 (('4.14.6-1', '4.14.9', '4.14.9'), 'agent upgrade requires wazuh_upgrade=true and target 4.14.9'),
                 (('4.14.6-1', '', '4.14.9'), 'controlled agent upgrade requires an observed manager version'),
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


class NativePackageGuardTests(unittest.TestCase):
    def test_apt_hold_is_the_effective_guard_even_when_foreign_priority_changes_candidate(self):
        class Native:
            def __init__(self): self.held = True; self.calls = []
            def run(self, argv, **kwargs):
                self.calls.append(argv)
                if argv[0] == 'dpkg': text = 'wazuh-agent\t' + ('hold' if self.held else 'install') + '\n'
                elif argv[:2] == ['apt-mark', 'showhold']: text = 'unrelated-held\n' + ('wazuh-agent\n' if self.held else '')
                elif argv[:2] == ['apt-mark', 'hold']: self.held = True; text = ''
                elif argv[:2] == ['apt-cache', 'policy']: text = '  Installed: 4.14.1-1\n  Candidate: 4.14.9-1\n'
                else: raise AssertionError(argv)
                return subprocess.CompletedProcess(argv, 0, text, '')
        native = Native(); guard = w.PackageGuard('Debian', native)
        result = guard.verify('4.14.1-1')
        self.assertEqual(result['candidate'], '4.14.9-1', 'do not pretend APT priorities freeze the candidate')
        native.held = False
        with self.assertRaisesRegex(w.Refused, 'native APT hold'):
            guard.verify('4.14.1-1')
        # The policy ownership boundary is separately tested with real files.
        guard.ownership = lambda: {}
        guard.protect('4.14.1-1')
        self.assertIn(['apt-mark', 'hold', 'wazuh-agent'], native.calls)
        self.assertFalse(any('unrelated-held' in argv for argv in native.calls))

    def test_apt_scoped_plan_rejects_unrelated_packages_and_wrong_target(self):
        class Native:
            def __init__(self, output): self.output = output
            def run(self, argv, **kwargs):
                self.argv = argv
                return subprocess.CompletedProcess(argv, 0, self.output, '')
        good = 'Inst wazuh-agent [4.14.1-1] (4.14.9-1 native [amd64])\nConf wazuh-agent (4.14.9-1 native [amd64])\n'
        native = Native(good); guard = w.PackageGuard('Debian', native)
        self.assertTrue(guard.apt_plan('4.14.9-1')['authorized'])
        self.assertIn('--allow-change-held-packages', native.argv)
        for output in (good + 'Inst other-held (2 native [amd64])\n', good + 'Remv foreign [1]\n',
                       good.replace('4.14.9-1', '4.14.10-1'), ''):
            native.output = output
            with self.assertRaises(w.Refused): guard.apt_plan('4.14.9-1')
        native.output = good
        self.assertTrue(guard.apt_plan('4.14.9-1', '/private/wazuh-agent_4.14.9-1_amd64.deb')['authorized'])
        self.assertIn('Dir::Cache::archives=/private/', native.argv)
        self.assertIn('--no-download', native.argv)
        self.assertIn('APT::Keep-Downloaded-Packages=true', native.argv)
        with self.assertRaisesRegex(w.Refused, 'unsupported native APT cache basename'):
            guard.apt_plan('4.14.9-1', '/private/renamed.deb')

    def test_resolving_dnf_oracle_requires_loaded_plugin_exact_target_and_no_dependencies(self):
        package = {'name': 'wazuh-agent', 'version': '4.14.9-1', 'epoch': '0', 'arch': 'x86_64'}
        plan = {'plugins': ['versionlock'], 'install': [package], 'remove': []}
        w.PackageGuard.validate_dnf_plan(plan, '4.14.9-1')
        for broken in ({**plan, 'plugins': []}, {**plan, 'install': []},
                       {**plan, 'install': [package, {**package, 'name': 'foreign'}]},
                       {**plan, 'remove': [{**package, 'name': 'foreign'}]}):
            with self.assertRaises(w.Refused): w.PackageGuard.validate_dnf_plan(broken, '4.14.9-1')
        with self.assertRaisesRegex(w.Refused, 'permits a replacement'):
            w.PackageGuard.validate_dnf_plan(plan, '4.14.1-1', unchanged=True)

    def test_rpm_provider_requires_official_hash_and_rejects_competing_same_nevra(self):
        official = {'repo': 'wazuh', 'url': 'https://packages.wazuh.com/4.x/yum/wazuh-agent.rpm',
                    'sha256': 'a' * 64, 'checksum_type': 'sha256', 'gpgcheck': True,
                    'gpgkey': ['https://packages.wazuh.com/key/GPG-KEY-WAZUH'],
                    'baseurl': ['https://packages.wazuh.com/4.x/yum/']}
        guard = w.PackageGuard('RedHat', Commands('RedHat'))
        records = [official]
        guard.dnf_native = lambda payload: records
        self.assertEqual(guard.official_rpm_provider({'config': 'private'}, '4.14.9-1')['sha256'], 'a' * 64)
        for records in ([{**official, 'repo': 'foreign'}],
                        [official, {**official, 'repo': 'foreign', 'sha256': 'b' * 64}],
                        [official, {**official, 'repo': 'foreign', 'sha256': 'invalid'}],
                        [{**official, 'gpgcheck': False}], [{**official, 'gpgkey': ['https://other/key']}], []):
            with self.assertRaises(w.Refused): guard.official_rpm_provider({'config': 'private'}, '4.14.9-1')

    def test_dnf_prerequisite_refuses_latent_disabled_redirected_and_foreign_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); folder = root / 'dnf'; (folder / 'plugins').mkdir(parents=True)
            main = folder / 'dnf.conf'; main.write_text('[main]\nplugins=1\n'); main.chmod(0o644)
            plugin = folder / 'plugins/versionlock.conf'; locks = folder / 'plugins/versionlock.list'
            real_path = w.Path
            def path(value):
                value = str(value)
                return folder / value.removeprefix('/etc/dnf').lstrip('/') if value == '/etc/dnf' or value.startswith('/etc/dnf/') else real_path(value)
            guard = w.PackageGuard('RedHat', Commands('RedHat'), root / 'private')
            guard.dnf_native = lambda payload: [['wazuh-agent']] if payload['action'] == 'names' else None
            w.Path = path
            try:
                self.assertFalse(guard.ownership()['plugin']['present'])
                locks.write_text('unrelated-0:1-1.x86_64\n'); locks.chmod(0o644)
                with self.assertRaisesRegex(w.Refused, 'activate latent global rules'): guard.ownership()
                locks.write_text('')
                for settings, error in (('[main]\nenabled=0\nlocklist=/etc/dnf/plugins/versionlock.list\n', 'disabled'),
                                        ('[main]\nenabled=1\nlocklist=/outside/rules\n', 'redirected')):
                    plugin.write_text(settings); plugin.chmod(0o644)
                    with self.assertRaisesRegex(w.Refused, error): guard.ownership()
                plugin.write_text('[main]\nenabled=1\nlocklist=/etc/dnf/plugins/versionlock.list\n')
                locks.write_text('wazuh-agent-*\n')
                with self.assertRaisesRegex(w.Refused, 'foreign versionlock ownership'): guard.ownership()
                main.write_text('[main]\nplugins=0\n')
                with self.assertRaisesRegex(w.Refused, 'plugins are disabled'): guard.ownership()
            finally: w.Path = real_path

    def test_live_external_unix_endpoint_is_refused_without_guessing_reload(self):
        # Kernel socket/proc records are explicit fixtures; this sandbox does
        # not permit AF_UNIX bind. The ownership parser and gate stay real.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); proc = root / 'proc'; (proc / 'net').mkdir(parents=True)
            (proc / '123/fd').mkdir(parents=True)
            (proc / '123/fd/5').symlink_to('socket:[42]')
            (proc / '123/exe').symlink_to('/usr/bin/python3')
            source = root / 'state'; source.mkdir()
            records = proc / 'net/unix'
            records.write_text('Num RefCount Protocol Flags Type St Inode Path\n1: 1 0 0 0002 01 42 ' + str(source / 'audit') + '\n')
            real_path = w.Path
            def path(value):
                value = str(value)
                return proc / value.removeprefix('/proc').lstrip('/') if value == '/proc' or value.startswith('/proc/') else real_path(value)
            capture = {'nodes': {str(source / 'audit'): {'type': 'socket'}}}
            w.Path = path
            try:
                with self.assertRaisesRegex(w.Refused, 'live external agent endpoint'):
                    w.agent_socket_gate(capture)
                with self.assertRaisesRegex(w.Refused, 'remain active after quiescence'):
                    w.agent_socket_gate(capture, stopped=True)
                records.write_text('Num RefCount Protocol Flags Type St Inode Path\n')
                w.agent_socket_gate(capture, stopped=True)
            finally: w.Path = real_path


class NativeComposeControlTests(unittest.TestCase):
    """Real Compose parser/config hashing; no daemon, containers or network."""
    def test_version_only_graph_and_anchor_side_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            central = w.Central(root=directory / 'private')
            for anchored in (False, True):
                old = ('x-manager-image: &manager_image wazuh/wazuh-manager:4.14.1\n' if anchored else '')
                old += 'services:\n'
                for service in w.SERVICES:
                    old += '  ' + service + ':\n'
                    old += '    image: ' + ('*manager_image' if anchored and service == 'wazuh.manager'
                                             else 'wazuh/' + service.replace('.', '-') + ':4.14.1') + '\n'
                    if service == 'wazuh.manager':
                        old += '    environment:\n      NON_IMAGE_SETTING: ' + ('*manager_image' if anchored else 'preserved') + '\n'
                state = {'directory': str(directory), 'version': '4.14.1',
                         'images': {s: {'config_hash': central.service_hash(str(directory), old, s)} for s in w.SERVICES}}
                new = old.replace(':4.14.1', ':4.14.9')
                if anchored:
                    with self.assertRaisesRegex(w.Refused, 'outside image fields'):
                        central.validate_compose_transition(state, old, new, '4.14.9')
                else:
                    central.validate_compose_transition(state, old, new, '4.14.9')
                    self.assertEqual(set(state['target_config_hashes']), set(w.SERVICES))

    def test_pending_environment_edit_refuses_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            central = w.Central(root=Path(temporary) / 'private')
            original = 'services:\n' + ''.join('  ' + s + ':\n    image: wazuh/' + s.replace('.', '-') + ':4.14.1\n    environment:\n      SETTING: applied\n' for s in w.SERVICES)
            state = {'directory': temporary, 'version': '4.14.1',
                     'images': {s: {'config_hash': central.service_hash(temporary, original, s)} for s in w.SERVICES}}
            pending = original.replace('SETTING: applied', 'SETTING: unapplied')
            with self.assertRaisesRegex(w.Refused, 'differs from the running container'):
                central.validate_compose_transition(state, pending, pending.replace(':4.14.1', ':4.14.9'), '4.14.9')
            self.assertFalse(central.root.exists())


class DiscoveryFilesystemTests(unittest.TestCase):
    """Production discover call chain with real filesystem ownership aliases.

    Docker service facts are an explicit native-command harness. No discovery
    guard or health method is replaced, so removing the hardlink guard lets the
    alias case traverse every later check and incorrectly succeed.
    """
    def central(self, root):
        managed = root / 'managed'
        project = managed / 'wazuh-docker-4.14.1/single-node'
        project.mkdir(parents=True)
        compose = project / 'docker-compose.yml'
        compose.write_text('services: {}\n')
        docker = root / 'docker-data'
        containers, images, volumes = [], {}, {}
        for number, service in enumerate(w.SERVICES):
            identifier = 'container-' + str(number)
            image = 'sha256:' + str(number + 1) * 64
            name = 'single-node_volume_' + str(number)
            mount = docker / 'volumes' / name / '_data'
            mount.mkdir(parents=True)
            containers.append({'Id': identifier, 'Image': image, 'State': {'Running': True},
                               'Config': {'Image': 'wazuh/' + service.replace('.', '-') + ':4.14.1',
                                          'Labels': {'com.docker.compose.project': 'single-node',
                                                     'com.docker.compose.service': service,
                                                     'com.docker.compose.project.working_dir': str(project),
                                                     'com.docker.compose.project.config_files': str(compose),
                                                     'com.docker.compose.config-hash': 'a' * 64}},
                               'Mounts': [{'Type': 'volume', 'Name': name, 'Source': str(mount),
                                           'Destination': '/var/ossec/logs' if service == 'wazuh.manager' else '/data'}]})
            images[image] = {'Id': image, 'Size': 1024,
                             'RepoDigests': ['wazuh/' + service.replace('.', '-') + '@' + image]}
            volumes[name] = {'Driver': 'local', 'Options': None, 'Mountpoint': str(mount),
                              'Labels': {'com.docker.compose.project': 'single-node'}}
        class Native:
            def __init__(self):
                self.calls = []
            def run(self, argv, **kwargs):
                argv = [str(value) for value in argv]
                self.calls.append(argv)
                if argv[:2] == ['docker', 'info']:
                    text = str(docker) if '--format' in argv else ''
                elif argv[:2] == ['docker', 'ps']:
                    selected = [row['Id'] for row in containers]
                    if 'label=com.docker.compose.service=wazuh.manager' in argv:
                        selected = [row['Id'] for row in containers if row['Config']['Labels']['com.docker.compose.service']=='wazuh.manager']
                    if argv[-1].startswith('volume='):
                        selected = [row['Id'] for row in containers if row['Mounts'][0]['Name'] == argv[-1].split('=', 1)[1]]
                    text = '\n'.join(selected)
                elif argv[-1] == 'info':
                    text = 'WAZUH_VERSION="v4.14.1"\n'
                elif argv[-1] == 'status':
                    required = ('modulesd', 'logcollector', 'remoted', 'analysisd', 'execd', 'db', 'authd', 'apid')
                    text = '\n'.join('wazuh-' + name + ' is running...' for name in required) + '\nwazuh-clusterd not running...\n'
                    return subprocess.CompletedProcess(argv, 1, text, '')
                else:
                    raise AssertionError(argv)
                return subprocess.CompletedProcess(argv, 0, text, '')
            def json(self, argv, **kwargs):
                self.calls.append(list(argv))
                if argv[:2] == ['docker', 'inspect']:
                    return [row for row in containers if row['Id'] in argv[2:]]
                if argv[:3] == ['docker', 'image', 'inspect']:
                    return [images[argv[-1]]]
                if argv[:3] == ['docker', 'volume', 'inspect']:
                    return [volumes[argv[-1]]]
                if 'curl' in argv:
                    return {'status': 'green'}
                if argv[-1] in ('/usr/share/wazuh-dashboard/plugins/wazuh/package.json', '/usr/share/wazuh-indexer/VERSION.json'):
                    return {'version': '4.14.1'}
                raise AssertionError(argv)
        native = Native()
        return w.Central(root=root / 'private', managed_root=managed, runner=native), compose, native

    def test_normal_discovery_accepts_the_complete_control_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            central, _, _ = self.central(Path(temporary))
            self.assertEqual(central.discover()['version'], '4.14.1')

    def test_discovery_rejects_real_compose_hardlink_without_touching_outside_alias(self):
        import os
        for location in ('outside', 'inside-captured-project'):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                central, compose, native = self.central(root)
                alias = (root if location == 'outside' else compose.parent) / 'operator-unrelated.yml'
                os.link(compose, alias)
                original = alias.read_bytes()
                self.assertEqual(compose.stat().st_nlink, 2)
                with self.assertRaisesRegex(w.Refused, 'hardlink'):
                    central.discover()
                self.assertEqual(alias.read_bytes(), original)
                self.assertFalse(any(call[1] in ('stop', 'rm', 'compose') for call in native.calls))


class Commands:
    """Native dpkg/rpm model shared by the agent tests (rpm -q absent: native capture, rc 1 and the stdout text)."""
    def __init__(self, family='Debian', installed='4.14.6-1'):
        self.family, self.installed = family, installed
        self.calls = []
        self.agent_release = '4.14.9'
        self.unknown = False

    def run(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        self.calls.append(argv)
        if argv[0] == 'tar' or argv[0] == 'du':
            return w.Runner().run(argv, **kwargs)
        if argv[0] == 'dpkg-query':
            text, rc = ('install ok installed\t' + self.installed + '\tamd64', 0) if self.installed else ('', 1)
        elif argv[:2] == ['rpm', '-q']:
            text, rc = (self.installed + '\tx86_64', 0) if self.installed else ('package wazuh-agent is not installed\n', 1)
        elif '-l' in argv:
            text, rc = ('   ID: 000, Name: local (server)\n   ID: 001, Name: synthetic, Active\n', 0)
        elif '-i' in argv:
            text, rc = ('Agent ID: 001\nClient version: ' + ('unknown' if self.unknown else 'Wazuh v' + self.agent_release), 0)
        elif argv[0] == 'systemctl':
            text, rc = ('enabled', 0) if argv[1] == 'is-enabled' else ('', 3)
        else:
            text, rc = '', 0
        if rc not in kwargs.get('allowed', (0,)):
            raise w.Refused('injected native probe failure')
        diagnostic = 'dpkg-query: no packages found matching wazuh-agent\n' if argv[0] == 'dpkg-query' and not self.installed else ''
        return subprocess.CompletedProcess(argv, rc, text, diagnostic)

    def json(self, argv, **kwargs):
        self.calls.append([str(value) for value in argv])
        if argv[:3] == ['docker', 'image', 'inspect']:
            return [{'Id': 'sha256:new', 'RepoDigests': [str(argv[-1]).split(':')[0] + '@sha256:new']}]
        if argv[:2] == ['docker', 'inspect']:
            return [{'State': {'Running': False}}]
        raise AssertionError(argv)


class BackendTests(unittest.TestCase):

    def test_unsupported_backend_is_refused(self):
        with self.assertRaises(w.Refused):
            w.Agent('Suse')
    def test_native_held_dpkg_status_remains_an_installed_compatible_agent(self):
        class Native(Commands):
            def run(self, argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, 'hold ok installed\t4.14.1-1\tamd64', '')
        with tempfile.TemporaryDirectory() as temporary:
            # The journal path is fixed at construction: assigning agent.root
            # afterwards left it on the real host ledger.
            agent = w.Agent('Debian', runner=Native(), root=Path(temporary) / 'private')
            self.assertEqual(agent.installed(), '4.14.1-1')
            self.assertFalse(agent.check('4.14.9')['change'])

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
            native = Commands(family, '')
            self.assertEqual(w.Agent(family, runner=native).installed(), '')
        class BadQuery(Commands):
            def run(self, argv, **kwargs):
                return subprocess.CompletedProcess(argv, 1, '', 'database query failed')
        with self.assertRaisesRegex(w.Refused, 'probe failed'):
            w.Agent('Debian', runner=BadQuery()).installed()

    def test_both_package_backends_enforce_same_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            for family in ('Debian', 'RedHat'):
                for release in ('4.14.1-1', '4.14.9-1'):
                    command = Commands(family, release)
                    agent = w.Agent(family, runner=command, root=Path(temp) / family)
                    self.assertEqual(agent.check('4.14.9')['package'], release)
                    with self.assertRaisesRegex(w.Refused, 'newer'):
                        agent.check('4.14.0')
                    self.assertTrue(any(call[0] == ('dpkg-query' if family == 'Debian' else 'rpm') for call in command.calls))

    def test_probe_errors_never_become_fresh_installs(self):
        class Broken(Commands):
            def run(self, argv, **kwargs):
                if argv[0] == 'rpm':
                    return subprocess.CompletedProcess(argv, 1, 'rpmdb: query failed', '')
                raise w.Refused('query failed')
        for family in ('Debian', 'RedHat'):
            with self.assertRaises(w.Refused):
                w.Agent(family, runner=Broken()).installed()

    def test_registry_all_retained_agents_bound_target(self):
        command = Commands()
        central = w.Central(runner=command)
        with self.assertRaisesRegex(w.Refused, 'registered agent is newer than the central release'):
            central.check_agents('4.14.1')
        central.check_agents('4.14.9')
        command.unknown = True
        with self.assertRaisesRegex(w.Refused, 'unknown retained'):
            central.check_agents('4.14.9')


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
                # MODELED unless policy_text is the captured output (native-captures/apt-cache-policy.*).
                text = getattr(self, 'policy_text', None) or '  Installed: ' + self.installed + '\n  Candidate: ' + self.candidate + '\n'
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

    def test_the_captured_apt_policy_of_a_held_and_preferred_agent_verifies(self):
        # Native capture: with the hold and the version preference in place the candidate is the installed
        # version and newer repository versions carry priority -1 (a modeled foreign priority is the other
        # test above). The real text, not a rebuilt one, goes through the real parser.
        with tempfile.TemporaryDirectory() as temporary:
            native = self.Native(installed='4.14.1-1', held=True)
            native.policy_text = capture('apt-cache-policy.held-with-preference.rc0.txt')
            state = self.guard(native, Path(temporary)).apt_state()
            self.assertEqual((state['installed'], state['candidate'], state['held']), ('4.14.1-1', '4.14.1-1', True))
            self.assertEqual(self.guard(native, Path(temporary)).verify('4.14.1-1')['guard'], 'apt-hold')

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
                    native.rpmkeys = 'content'

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
                        scenario = native.rpmkeys
                        if scenario == 'content':
                            # Default: the payload decides, as a vendor-only key ring would.
                            official = Path(argv[-1]).read_bytes().startswith(b'official:')
                            scenario = 'signed' if official or '--dbpath' not in argv else 'nokey'
                        text, rc = RPMKEYS_KV[scenario](argv[-1])
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
                        # Exactly what Runner.run reports for a non-zero tool status.
                        raise w.Refused('operation failed: ' + (kwargs.get('operation') or argv[0]) + ' rc=' + str(rc))
                    return subprocess.CompletedProcess(argv, rc, text, '')
            native = Native(); guard = w.PackageGuard('RedHat', native, root)
            original = w.os.getxattr

            def xattr(path, name, **kwargs):
                if name == 'security.selinux': return (native.context(path) + '\0').encode()
                return original(path, name, **kwargs)
            with mock.patch.object(w.os, 'getxattr', side_effect=xattr):
                yield root, native, guard


class PrivateRpmKeyringTests(unittest.TestCase):
    """Real private filesystem/scope; explicit native SELinux/RPM substitute.

    The model reproduces only the observed rpmdb_t/var_t failure and vendor
    key distinction. The separate owned Alma probe supplies actual native MAC
    and signature evidence; these tests are not a VM acceptance receipt.
    """
    OWNER = 'e' * 32

    @contextlib.contextmanager
    def fixture(self, state='Enforcing'):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private'; w.private_dir(root)
            class Native:
                def __init__(native):
                    native.calls = []; native.contexts = {}; native.state = state
                    native.policy = 'system_u:object_r:rpm_var_lib_t:s0'
                    native.dbpath = '/var/lib/rpm'; native.failure = None
                    native.chcon_effect = 'type'; native.keys = ['gpg-pubkey-29111145-591cd381']
                    native.installed = '4.14.1-1'
                def context(native, path):
                    return native.contexts.get(str(path), 'unconfined_u:object_r:var_t:s0')
                def run(native, argv, **kwargs):
                    argv = [str(value) for value in argv]; native.calls.append(argv); text = ''; rc = 0
                    if native.failure == argv[0]: raise w.Refused('injected missing/failed native tool: ' + argv[0])
                    if argv[0] == 'getenforce': text = native.state
                    elif argv[0] == 'matchpathcon': text = native.policy
                    elif argv[:2] == ['rpm', '--eval']: text = native.dbpath
                    elif argv[0] == 'chcon':
                        self.assertEqual(argv[1:3], ['--type=rpm_var_lib_t', '--'])
                        self.assertEqual(len(argv), 4, 'only the exact new directory may be labeled')
                        path = Path(argv[3]); self.assertEqual(list(path.iterdir()), [])
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
                    elif argv[:2] == ['rpm', '-q']: text = native.installed + '\tx86_64' if native.installed else 'package wazuh-agent is not installed'; rc = 0 if native.installed else 1
                    elif argv[:2] == ['rpm', '-qp']:
                        text = 'wazuh-agent\n' + Path(argv[-1]).read_bytes().decode().split(':')[1] + '\nx86_64'
                    elif argv[0] == 'dnf':
                        folder = Path(next(value.split('=', 1)[1] for value in argv if value.startswith('--downloaddir=')))
                        (folder / 'fresh.rpm').write_bytes(b'official:4.14.9-1')
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
                artifact = Path(ring['database']).parent / 'official.rpm'; artifact.write_bytes(b'official:4.14.9-1')
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
                artifact = db.parent / 'official.rpm'; artifact.write_bytes(b'official:4.14.9-1')
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
                artifact = Path(ring['database']).parent / 'official.rpm'; artifact.write_bytes(b'official:4.14.9-1')
                native.calls.clear(); setattr(native, field, value)
                with self.assertRaises(w.Refused):
                    guard.verify_official_rpm(artifact, {'sha256': w.digest(artifact)}, ring, self.OWNER)
                self.assertFalse(any(call[0] in ('chcon', 'rpmkeys') or '--import' in call for call in native.calls))

    def test_actual_cold_and_recovery_entrypoints_refuse_label_drift_before_stop_or_data_restore(self):
        for boundary in ('cold', 'prepare-recovery', 'restore-state'):
            with self.subTest(boundary=boundary), RestoreScopeTests().agent('RedHat') as (agent, daemon, path, _):
                with self.fixture() as (_, native, _):
                    guard = w.PackageGuard('RedHat', native, agent.root)
                    ring = guard.official_rpm_keyring('d' * 32)
                    plan = w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True)
                    agent.reserve('d' * 32, plan)
                    item = agent.active(); item['policy_stage']['keyring'] = ring; agent.write(item, item['phase'])
                    harness = PackagePolicyHarness(daemon)
                    harness.verify_rpm_keyring = guard.verify_rpm_keyring
                    agent.guard = lambda: harness
                    if boundary != 'cold':
                        agent.cold_backup('d' * 32)
                        agent.authorize_install('d' * 32)
                        daemon.installed = '4.14.9-1'; daemon.active = True
                        if boundary == 'restore-state':
                            item = agent.active(); agent.write(item, 'recovering')
                    native.contexts[ring['database']] = 'unconfined_u:object_r:var_t:s0'
                    before = sum(call[:2] == ['systemctl', 'stop'] for call in daemon.calls)
                    phase = agent.active()['phase']
                    config = path('/var/ossec/etc/ossec.conf'); config.write_text('changed live state must not be restored on refusal')
                    action = {'cold': agent.cold_backup, 'prepare-recovery': agent.prepare_recovery,
                              'restore-state': agent.restore_state}[boundary]
                    with self.assertRaisesRegex(w.Refused, 'SELinux context drift'):
                        action('d' * 32)
                    self.assertEqual(agent.active()['phase'], phase, 'strong recovery journal must be retained')
                    self.assertEqual(sum(call[:2] == ['systemctl', 'stop'] for call in daemon.calls), before)
                    self.assertTrue(daemon.active)
                    self.assertEqual(config.read_text(), 'changed live state must not be restored on refusal')

    def test_vendor_only_signature_remains_required_even_for_matching_provider_hash(self):
        with self.fixture() as (_, native, guard):
            ring = guard.official_rpm_keyring(self.OWNER)
            artifact = Path(ring['database']).parent / 'foreign-alma.rpm'; artifact.write_bytes(b'foreign:3.1.5-8.el9')
            native.calls.clear()
            with self.assertRaisesRegex(w.Refused, 'NOKEY'):
                guard.verify_official_rpm(artifact, {'sha256': w.digest(artifact)}, ring, self.OWNER)
            self.assertEqual(len([call for call in native.calls if call[0] == 'rpmkeys']), 1)
            self.assertIn('--dbpath', native.calls[-1])

    def test_fresh_stage_admission_forward_and_recovery_share_private_verification(self):
        with self.fixture() as (root, native, guard):
            native.installed = ''
            guard.overlay = lambda owner, package, installed='': {'config': package}
            def provider(overlay, package):
                return {'sha256': __import__('hashlib').sha256(('official:' + package).encode()).hexdigest()}
            guard.official_rpm_provider = provider
            guard.verify_overlay = lambda overlay, owner: overlay['config']
            guard.snapshot = lambda: {'installed': native.installed}
            guard.artifact_plan = lambda overlay, owner, *args, **kwargs: overlay['config']
            agent = w.Agent('RedHat', runner=native, root=root); agent.guard = lambda: guard
            owner = self.OWNER; w.HostWriter(root).claim(owner, 'agent', 'apply')
            fresh = agent.fresh_rpm(owner, w.agent_plan('', '4.14.9'))
            self.assertEqual(w.digest(fresh['package_path']), provider({}, '4.14.9-1')['sha256'])
            self.assertTrue(any(call[0] == 'chcon' for call in native.calls))
            native.installed = '4.14.1-1'
            plan = w.agent_plan(native.installed, '4.14.9', '4.14.9', True)
            prepared = agent.prepare_policy_stage(owner, plan)
            stage = w.private_dir(root / 'rpm-stage')
            for package in (plan['installed'], plan['package']): (stage / (package + '.rpm')).write_bytes(('official:' + package).encode())
            packages = agent.package_archives(plan['installed'], plan['package'])
            item = {'owner': owner, 'installed': plan['installed'], 'package': plan['package'],
                    'backup': str(stage), 'policy_stage': prepared,
                    'packages': {release: {**value, 'path': str(value['path'])} for release, value in packages.items()}}
            for recovery in (False, True):
                item['phase'] = 'recovering' if recovery else 'installing'
                with mock.patch.object(agent, 'owned', return_value=item):
                    agent.authorize_rpm(owner, recovery=recovery)
            private_checks = [call for call in native.calls if call[0] == 'rpmkeys' and '--dbpath' in call]
            self.assertEqual(len(private_checks), 5, 'fresh + staged old/new + forward + recovery all require private signatures')
            native.contexts[prepared['keyring']['database']] = 'unconfined_u:object_r:var_t:s0'
            native.calls.clear()
            for entry in (lambda: agent.validate_packages(item), lambda: agent.authorize_rpm(owner),
                          lambda: agent.authorize_rpm(owner, recovery=True)):
                with mock.patch.object(agent, 'owned', return_value=item):
                    with self.assertRaisesRegex(w.Refused, 'SELinux context drift'): entry()
            self.assertFalse(any(call[0] in ('chcon', 'rpmkeys', 'systemctl', 'dnf') for call in native.calls))





class PackagePolicyHarness:
    """Native package-policy seam for filesystem/phase tests only.

    The real PackageGuard is tested separately, including native container
    resolving controls. Capture, tar, restoration and ownership stay real here.
    """
    nevra = staticmethod(w.PackageGuard.nevra)
    def __init__(self, native): self.native = native
    def snapshot(self): return {'installed': self.native.installed, 'held': False}
    def same_context(self, before, after): return before == after
    def ownership(self): return {}
    def protect(self, *args, **kwargs): return {}
    def verify(self, *args, **kwargs): return {}
    def restore_prior(self, *args, **kwargs): return None
    def overlay(self, owner, package, installed=''): return {'config': package}
    def official_rpm_provider(self, overlay, package): return {'synthetic': package}
    def official_rpm_keyring(self, owner): return {}
    def verify_overlay(self, overlay, owner): return overlay['config']
    def verify_official_rpm(self, *args): return None
    def verify_rpm_keyring(self, *args): return None
    def artifact_plan(self, overlay, owner, *args, **kwargs): return overlay['config']


class ManagerVersion(Commands):
    """Only the manager's native version probe, for tests about reading it."""
    def run(self, argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, 'WAZUH_VERSION="v4.14.1"\n', '')


class CommonWriterTests(unittest.TestCase):
    def test_all_writer_modes_and_roles_exclude_a_second_admitted_writer(self):
        for first in ('agent', 'central'):
            for mode in ('apply', 'recover', 'canary'):
                with self.subTest(first=first, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    writer = w.HostWriter(Path(temporary) / 'private')
                    writer.claim('1' * 32, first, mode)
                    for second in ('agent', 'central'):
                        with self.assertRaisesRegex(w.Refused, 'another Wazuh writer'):
                            writer.claim('2' * 32, second)
                    with self.assertRaisesRegex(w.Refused, 'another Wazuh writer'):
                        writer.claim('1' * 32, first)
                    with self.assertRaisesRegex(w.Refused, 'exact active owner'):
                        writer.release('2' * 32)
                    self.assertEqual(writer.inspect()['writer']['owner'], '1' * 32)
                    writer.release('1' * 32)

    def test_interrupted_resume_needs_exact_owner_confirmation_and_journal_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private'
            writer = w.HostWriter(root)
            writer.claim('3' * 32, 'agent')
            with self.assertRaisesRegex(w.Refused, 'confirmation'):
                writer.resume('3' * 32, 'agent')
            with self.assertRaisesRegex(w.Refused, 'does not match'):
                writer.resume('4' * 32, 'agent', confirmed=True)
            writer.resume('3' * 32, 'agent', confirmed=True)
            tx = w.Agent('Debian', root=root)
            with tx.lock(owner='3' * 32):
                item = tx.begin('3' * 32, {'secret': 'SYNTHETIC_PRIVATE_VALUE'})
            with self.assertRaisesRegex(w.Refused, 'unfinished component journal'):
                writer.release('3' * 32)
            self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', json.dumps(writer.inspect()))
            with self.assertRaisesRegex(w.Refused, 'exact host-wide'):
                tx.authorize_install('4' * 32)
            with tx.lock(owner='3' * 32):
                tx.finish(item, 'recovered-before-install')
            writer.release('3' * 32)

    def test_orphan_journal_attachment_requires_matching_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private'
            tx = w.Transaction('central', root=root)
            with tx.lock():
                item = tx.begin('5' * 32, {})
            writer = w.HostWriter(root)
            with self.assertRaisesRegex(w.Refused, 'unfinished component journal'):
                writer.claim('6' * 32, 'central')
            with self.assertRaisesRegex(w.Refused, 'does not belong'):
                writer.resume('6' * 32, 'central', 'recover', True)
            writer.resume('5' * 32, 'central', 'recover', True)
            with tx.lock(owner='5' * 32):
                tx.finish(item, 'recovered-before-switch')
            writer.release('5' * 32)

    def test_parallel_stable_manager_readers_and_agent_host_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private'
            w.private_dir(root)
            barrier = threading.Barrier(2)
            class Native(Commands):
                def run(self, argv, **kwargs):
                    barrier.wait(timeout=3)
                    return subprocess.CompletedProcess(argv, 0, 'WAZUH_VERSION="v4.14.9"\n', '')
            central = w.Central(root=root, runner=Native())
            for agent_writer in (False, True):
                if agent_writer:
                    w.HostWriter(root).claim('7' * 32, 'agent')
                with ThreadPoolExecutor(2) as pool:
                    results = list(pool.map(lambda _: central.observe_manager(), range(2)))
                self.assertEqual(results, [{'version': '4.14.9'}] * 2)
                if agent_writer:
                    w.HostWriter(root).release('7' * 32)
            w.HostWriter(root).claim('8' * 32, 'central')
            with self.assertRaisesRegex(w.Refused, 'active Wazuh writer'):
                central.observe_manager()
            w.HostWriter(root).release('8' * 32)

    def test_reader_finishes_before_writer_claim_then_new_read_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private'
            entered, finish = threading.Event(), threading.Event()
            class Native(Commands):
                def run(self, argv, **kwargs):
                    entered.set()
                    if not finish.wait(3):
                        raise AssertionError('reader barrier did not release')
                    return subprocess.CompletedProcess(argv, 0, 'WAZUH_VERSION="v4.14.1"\n', '')
            # The state root and its lock already exist (an earlier writer ran): a read holds the shared
            # lock, so the next claim waits for it. (With no state root a read holds nothing: see
            # test_a_read_on_a_host_without_state_never_adopts_a_concurrent_claim.)
            w.HostWriter(root).claim('1' * 32, 'central'); w.HostWriter(root).release('1' * 32)
            central = w.Central(root=root, runner=Native())
            writer = w.HostWriter(root)
            with ThreadPoolExecutor(2) as pool:
                read = pool.submit(central.observe_manager)
                self.assertTrue(entered.wait(3))
                claim = pool.submit(writer.claim, '9' * 32, 'central')
                with self.assertRaises(TimeoutError):
                    claim.result(timeout=0.1)
                finish.set()
                self.assertEqual(read.result(timeout=3), {'version': '4.14.1'})
                self.assertEqual(claim.result(timeout=3)['owner'], '9' * 32)
            with self.assertRaisesRegex(w.Refused, 'active Wazuh writer'):
                central.observe_manager()
            writer.release('9' * 32)


    def test_a_read_on_a_host_without_state_creates_nothing_and_never_adopts_a_concurrent_claim(self):
        # A's guarantee (a check-mode preview never writes) next to B's (a read never reports a
        # transaction's temporary state): with no state root there is no lock to hold, so the read
        # creates nothing and a root that appears while it runs makes it discard what it saw.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private'
            central = w.Central(root=root, runner=ManagerVersion())
            self.assertEqual(central.observe_manager(), {'version': '4.14.1'})
            self.assertFalse(root.exists(), 'a read must not create the state root, a lock or a journal')
            entered, finish = threading.Event(), threading.Event()
            class Native(Commands):
                def run(self, argv, **kwargs):
                    entered.set()
                    if not finish.wait(3):
                        raise AssertionError('reader barrier did not release')
                    return subprocess.CompletedProcess(argv, 0, 'WAZUH_VERSION="v4.14.9"\n', '')
            central = w.Central(root=root, runner=Native())
            with ThreadPoolExecutor(2) as pool:
                read = pool.submit(central.observe_manager)
                self.assertTrue(entered.wait(3))
                w.HostWriter(root).claim('2' * 32, 'central')   # a writer starts while the read runs
                finish.set()
                with self.assertRaisesRegex(w.Refused, 'claimed this host during the observation'):
                    read.result(timeout=3)

    def test_a_running_central_writer_still_makes_an_external_read_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private'
            central = w.Central(root=root, runner=ManagerVersion())
            # 1. The durable writer marker: the read is refused, and it created nothing of its own.
            w.HostWriter(root).claim('3' * 32, 'central')
            before = sorted(path.name for path in root.iterdir())
            with self.assertRaisesRegex(w.Refused, 'active Wazuh writer prevents a stable external read'):
                central.observe_manager()
            self.assertEqual(sorted(path.name for path in root.iterdir()), before)
            w.HostWriter(root).release('3' * 32)
            # 2. A writer holding the component lock without a marker (mid-transaction): refused at once.
            with central.component_lock():
                with self.assertRaisesRegex(w.Refused, 'another Wazuh transaction is running'):
                    central.observe_manager()
            self.assertEqual(central.observe_manager(), {'version': '4.14.1'})

    def test_policy_is_replanned_after_writer_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            native = Commands('Debian', '4.14.1-1')
            agent = w.Agent('Debian', root=Path(temporary) / 'private', runner=native)
            self.assertFalse(agent.check('4.14.1')['change'])
            native.installed = '4.14.9-1'
            w.HostWriter(agent.root).claim('a' * 32, 'agent')
            with self.assertRaisesRegex(w.Refused, 'newer than the observed manager'):
                agent.check('4.14.1', owner='a' * 32)
            self.assertFalse(agent.path.exists())
            w.HostWriter(agent.root).release('a' * 32)


class JournalTests(unittest.TestCase):
    def test_all_direct_file_deletions_use_the_durable_absence_primitive(self):
        import ast
        tree = ast.parse((REPO / 'playbooks/apply/files/wazuh-transaction.py').read_text())
        for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
            for call in ast.walk(function):
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr in ('unlink', 'remove'):
                    self.assertEqual(function.name, 'durable_unlink', 'native file absence must pass the durable publication barrier')

    def test_durable_absence_replay_syncs_parent_even_when_already_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'pin'
            path.write_text('target-only pin')
            observed = []
            original = w.sync_directory
            def sync(directory):
                self.assertFalse(path.exists())
                original(directory)
                observed.append(str(directory))
            w.sync_directory = sync
            try:
                w.durable_unlink(path)
                w.durable_unlink(path)
            finally:
                w.sync_directory = original
            self.assertEqual(observed, [temporary, temporary])

    def test_every_published_phase_has_a_declared_recovery_action(self):
        import ast
        module = ast.parse((REPO / 'playbooks/apply/files/wazuh-transaction.py').read_text())
        for class_name, matrix in (('Central', w.CENTRAL_RECOVERY), ('Agent', w.AGENT_RECOVERY)):
            node = next(item for item in module.body if isinstance(item, ast.ClassDef) and item.name == class_name)
            published = {'reserved'}
            for call in ast.walk(node):
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                        and isinstance(call.func.value, ast.Name) and call.func.value.id == 'self'
                        and call.func.attr in ('write', 'finish') and len(call.args) >= 2):
                    value = call.args[1]
                    candidates = [value] if not isinstance(value, ast.IfExp) else [value.body, value.orelse]
                    published.update(item.value for item in candidates if isinstance(item, ast.Constant) and isinstance(item.value, str))
            self.assertEqual(published - set(matrix), set(), (class_name, published))

    def test_unknown_recovery_phase_never_dispatches_a_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            central = FakeCentral(Path(temporary))
            with central.lock():
                item = central.begin('d' * 32, central.discover())
                central.write(item, 'unknown-future-phase')
            with self.assertRaisesRegex(w.Refused, 'no fully backed-up'):
                central.execute('4.14.9', recover=True)
            self.assertEqual(central.calls, [])

    def test_path_scope_rejects_ancestor_overlap_and_symlink_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'source').mkdir()
            (root / 'source' / 'backup').mkdir()
            with self.assertRaisesRegex(w.Refused, 'overlaps'):
                w.disjoint([root / 'source'], root / 'source' / 'backup')
            with self.assertRaisesRegex(w.Refused, 'sources overlap'):
                w.disjoint([root / 'source', root / 'source' / 'child'], root / 'other')
            (root / 'link').symlink_to(root / 'source', target_is_directory=True)
            with self.assertRaisesRegex(w.Refused, 'symlink'):
                w.canonical(root / 'link' / 'child')

    def test_owner_exclusion_and_incomplete_transaction(self):
        with tempfile.TemporaryDirectory() as temp:
            tx = w.Transaction('agent', root=Path(temp) / 'private')
            with tx.lock():
                item = tx.begin('a' * 32, {})
            with tx.lock():
                with self.assertRaisesRegex(w.Refused, 'incomplete'):
                    tx.idle()
                with self.assertRaisesRegex(w.Refused, 'owner'):
                    tx.owned('b' * 32)
                with self.assertRaisesRegex(w.Refused, 'phase'):
                    tx.owned('a' * 32, ('backed-up',))
                self.assertEqual(tx.owned('a' * 32)['owner'], 'a' * 32)
                tx.finish(item, 'recovered')
                tx.idle()
            self.assertTrue((Path(item['backup']) / 'manifest.json').exists())
            self.assertEqual(tx.root.stat().st_mode & 0o777, 0o700)

    def test_lock_and_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            tx = w.Transaction('central', root=Path(temp) / 'private')
            with tx.lock():
                with self.assertRaisesRegex(w.Refused, 'another'):
                    with w.Transaction('central', root=tx.root).lock():
                        pass
            link = Path(temp) / 'alias'
            link.symlink_to(tx.root, target_is_directory=True)
            with self.assertRaisesRegex(w.Refused, 'transaction path contains a symlink'):
                with w.Transaction('central', root=link).lock():
                    pass


class FakeCentral(w.Central):
    def __init__(self, workspace, fail=False):
        self.command = Commands()
        self.command.agent_release = '4.14.1'
        super().__init__(runner=self.command, root=workspace / 'backups')
        self.workspace = workspace
        self.project = workspace / 'project'
        self.volume = workspace / 'volume'
        self.project.mkdir()
        self.volume.mkdir()
        (self.volume / 'document').write_text('original indexed data')
        self.compose = self.project / 'docker-compose.yml'
        self.compose.write_text('\n'.join('image: wazuh/' + s.replace('.', '-') + ':4.14.1' for s in w.SERVICES))
        self.fail = fail
        self.calls = []

    def make_reader(self, checker_hash='', request=None, ack=False):
        reader = super().make_reader(checker_hash, request, ack)
        # All native Docker/proc inspection is an explicit command-model leaf.
        # Real files/tar/layout/version policy remain production code.
        reader.source = lambda state: str(self.volume)
        reader.observe = lambda loaded=True: {
            'schema':2,'mode_candidate':'never','files':{},'profile':None,'pid':0,
            'resources':[],'authorization':'UNVALIDATED_OBSERVATIONS'}

        reader.source_users = lambda *args, **kwargs: None
        return reader

    def execute(self, target, upgrade=False, preview=False, recover=False, owner=''):
        # Existing transaction tests enter through the real common owner API.
        # An explicit recovery call in this fixture represents the operator's
        # stopped-operation acknowledgement; production never infers it.
        writer = w.HostWriter(self.root)
        marker = writer.inspect()['writer']
        if marker:
            owner = marker['owner']
        elif recover and self.active():
            owner = self.active()['owner']
            writer.resume(owner, 'central', 'recover', confirmed=True)
        else:
            owner = '1' * 32
            writer.claim(owner, 'central')
        try:
            return super().execute(target, upgrade, preview, recover, owner)
        finally:
            if not self.active():
                writer.release(owner)

    def discover(self):
        return {'directory': str(self.project), 'compose': str(self.compose), 'version': '4.14.1',
                'images': {s: {'id': 'sha256:old', 'container': s, 'size': 1} for s in w.SERVICES},
                'paths': [str(self.project), str(self.volume)], 'compose_sha256': w.digest(self.compose)}

    def capacity(self, paths, extra_bytes=0):
        return 1

    def validate_compose_transition(self, state, old_text, new_text, target):
        # Native Compose has a separate parser/anchor behavioral test.
        state['target_config_hashes'] = {service: 'b' * 64 for service in w.SERVICES}

    def validate_persisted_graph(self, item, target=False):
        pass

    def data(self):
        return {'content': (self.volume / 'document').read_text()}

    def check_data(self, data):
        if (self.volume / 'document').read_text() != data['content']:
            raise w.Refused('data oracle failed')

    def canary(self):
        return {'synthetic-command-harness': True}

    def compose_run(self, item, *args, **kwargs):
        self.calls.append((item['phase'], args))
        if args[0] == 'up' and item['phase'] == 'switching':
            (self.volume / 'document').write_text('new schema migrated data')

    def validate_restore_scope(self, item):
        # The fixture intentionally lives under a temporary directory; native
        # production path validation has independent rejection controls below.
        w.disjoint(item['paths'], self.root)
        for entry in item['archives']:
            if w.digest(entry['archive']) != entry['sha256']:
                raise w.Refused('backup checksum mismatch')

    def validate_project_scope(self, item):
        w.disjoint(item['paths'], self.root)

    def retain_images(self, item):
        # Native docker-save/load is covered by the separate target evidence.
        # This explicit command harness still retains a real durable artifact.
        archive = Path(item['backup']) / 'old-images.tar'
        archive.write_bytes(b'synthetic image archive')
        w.sync_file(archive)
        item['image_archive'] = {'path': str(archive), 'sha256': w.digest(archive)}
        self.write(item, item['phase'])

    def quiesce_for_restore(self, item, remove=True, inspect_only=False):
        if inspect_only:
            return
        self.calls.append((item['phase'], ('down',)))

    def wait(self, release, images):
        if release == '4.14.9' and self.fail:
            raise w.Refused('injected failure after data changed')


class CentralTransactionTests(unittest.TestCase):
    def test_interrupted_restore_replays_with_live_compose_directory_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            central = FakeCentral(Path(temporary), fail=True)
            original = central.compose.read_bytes()
            interrupted = False
            restore = central.restore
            def fault(source, archive, checksum, **kwargs):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    import shutil
                    shutil.rmtree(source)
                    raise w.Refused('injected interruption after destination removal')
                return restore(source, archive, checksum, **kwargs)
            central.restore = fault
            with self.assertRaisesRegex(w.Refused, 'AND recovery failed'):
                central.execute('4.14.9', True)
            self.assertFalse(central.compose.exists())
            self.assertEqual(central.active()['phase'], 'recovering')
            central.execute('4.14.9', recover=True)
            self.assertEqual(central.compose.read_bytes(), original)
            self.assertEqual((central.volume / 'document').read_text(), 'original indexed data')
            self.assertFalse(central.path.exists())

    def test_all_durable_phases_have_exact_recovery_dispatch(self):
        for phase, expected in w.CENTRAL_RECOVERY.items():
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                central = FakeCentral(Path(temporary))
                with central.lock():
                    item = central.begin('e' * 32, central.discover())
                    central.write(item, phase)
                calls = []
                def action(label):
                    def run(state, **kwargs):
                        calls.append(label)
                        central.finish(state, 'recovered')
                    return run
                central.recover_pre_switch = action('resume-old')
                central.rollback = action('restore-old')
                central.complete_finalized = action(expected)
                central.execute('4.14.9', recover=True)
                self.assertEqual(calls, [expected])
                self.assertFalse(central.path.exists())

    def test_recovery_in_check_mode_never_executes_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            central = FakeCentral(Path(temp))
            with self.assertRaisesRegex(w.Refused, 'check mode'):
                central.execute('4.14.9', upgrade=True, preview=True, recover=True)
            self.assertEqual(central.calls, [])
            self.assertEqual(central.command.calls, [])

    def test_post_mutation_failure_restores_real_cold_data_and_compose(self):
        with tempfile.TemporaryDirectory() as temp:
            central = FakeCentral(Path(temp), fail=True)
            before = central.compose.read_bytes()
            with self.assertRaisesRegex(w.Refused, 'previous images, data and availability recovered'):
                central.execute('4.14.9', upgrade=True)
            self.assertEqual((central.volume / 'document').read_text(), 'original indexed data')
            self.assertEqual(central.compose.read_bytes(), before)
            self.assertFalse(central.path.exists())
            backup = list(central.root.glob('central-*/manifest.json'))
            self.assertEqual(len(backup), 1)
            self.assertEqual(json.loads(backup[0].read_text())['phase'], 'recovered')
            self.assertTrue(any(phase == 'recovering' and args[0] == 'up' for phase, args in central.calls))

    def test_no_opt_in_or_unsupported_transition_never_stops_stack(self):
        for target, upgrade in [('4.14.9', False), ('4.14.8', True), ('4.14.0', True)]:
            with tempfile.TemporaryDirectory() as temp:
                central = FakeCentral(Path(temp))
                with self.assertRaises(w.Refused):
                    central.execute(target, upgrade)
                self.assertEqual(central.calls, [])
                self.assertFalse(central.path.exists())

    def test_capacity_and_registry_failure_never_stops_stack(self):
        for cause in ('capacity', 'registry'):
            with tempfile.TemporaryDirectory() as temp:
                central = FakeCentral(Path(temp))
                if cause == 'capacity':
                    def capacity(paths, extra_bytes=0):
                        raise w.Refused('insufficient backup capacity')
                    central.capacity = capacity
                else:
                    central.command.unknown = True
                with self.assertRaises(w.Refused):
                    central.execute('4.14.9', True)
                self.assertEqual(central.calls, [])
                self.assertFalse(central.path.exists())

    def test_backup_tamper_preserves_journal_and_refuses_recovery_success(self):
        with tempfile.TemporaryDirectory() as temp:
            central = FakeCentral(Path(temp), fail=True)
            restore = central.restore
            def corrupt(source, archive, checksum, **kwargs):
                Path(archive).write_bytes(b'corrupt')
                return restore(source, archive, checksum, **kwargs)
            central.restore = corrupt
            with self.assertRaisesRegex(w.Refused, 'AND recovery failed'):
                central.execute('4.14.9', True)
            self.assertTrue(central.path.exists())


class ExactArtifactTests(unittest.TestCase):
    def test_loaded_images_require_exact_retained_official_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            central = w.Central(root=Path(temporary) / 'private')
            w.private_dir(central.root)
            image = {'Id': 'sha256:synthetic-exact-id', 'RepoDigests': []}
            repository = 'wazuh/wazuh-indexer'
            official = repository + '@sha256:' + 'a' * 64
            with self.assertRaisesRegex(w.Refused, 'lacks official'):
                central.image_provenance(image, repository, '4.14.1')
            w.atomic_json(central.root / 'image-provenance.json', {
                image['Id']: {'repository': repository, 'version': '4.14.1', 'digests': [official]}})
            self.assertEqual(central.image_provenance(image, repository, '4.14.1'), [official])
            with self.assertRaisesRegex(w.Refused, 'does not match'):
                central.image_provenance(image, repository, '4.14.9')
            with self.assertRaisesRegex(w.Refused, 'does not match'):
                central.image_provenance(dict(image, Id='sha256:other-image'), repository, '4.14.1')

    def test_metadata_sha256_and_package_identity_are_both_required(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / 'wazuh-agent_4.14.9-1_amd64.deb'
            artifact.write_bytes(b'authenticated package bytes')
            checksum = hashlib.sha256(artifact.read_bytes()).hexdigest()
            original = apt.run
            identity = ['wazuh-agent', '4.14.9-1', 'amd64']
            conflicting_payload = False
            def command(argv):
                if argv[0] == 'dpkg':
                    return 'amd64\n'
                if argv[0] == 'apt-cache':
                    record = '\n'.join(['Package: wazuh-agent', 'Version: 4.14.9-1', 'Architecture: amd64',
                                        'Filename: pool/' + artifact.name, 'SHA256: ' + checksum])
                    return record + ('\n\n' + record.replace(checksum, 'a' * 64) if conflicting_payload else '')
                return '\n'.join(identity)
            apt.run = command
            try:
                self.assertEqual(apt.verify({'wazuh-agent': '4.14.9-1'}, root)[0]['sha256'], checksum)
                conflicting_payload = True
                with self.assertRaisesRegex(ValueError, 'ambiguous authenticated'):
                    apt.verify({'wazuh-agent': '4.14.9-1'}, root)
                conflicting_payload = False
                identity[1] = '4.14.10-1'
                with self.assertRaises(ValueError):
                    apt.verify({'wazuh-agent': '4.14.9-1'}, root)
                identity[1] = '4.14.9-1'
                artifact.write_bytes(b'tampered package bytes')
                with self.assertRaises(ValueError):
                    apt.verify({'wazuh-agent': '4.14.9-1'}, root)
            finally:
                apt.run = original


class RestoreScopeTests(unittest.TestCase):
    def test_backup_bind_alias_is_rejected_before_private_metadata_changes(self):
        import stat
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / 'backup'; backup.mkdir(); backup.chmod(0o775)
            original = MOUNT_NAMESPACE['text']
            MOUNT_NAMESPACE['text'] += f'2 1 8:1 /var/ossec/data {backup} rw - ext4 /dev/synthetic rw\n'
            try:
                with self.assertRaisesRegex(w.Refused, 'subtree or bind-mount ancestry'):
                    w.HostWriter(backup).claim('d' * 32, 'agent')
                with self.assertRaisesRegex(w.Refused, 'subtree or bind-mount ancestry'):
                    with w.Transaction('agent', root=backup).lock(owner='d' * 32):
                        pass
                self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o775)
                self.assertEqual(list(backup.iterdir()), [])
            finally:
                MOUNT_NAMESPACE['text'] = original

    def test_mountinfo_decodes_paths_and_keeps_unrelated_kernel_object_mounts(self):
        table = RealMountTable('1 0 8:1 / / rw - ext4 /dev/synthetic rw\n'
                               '2 1 8:1 /source\\040with\\134slash /dest\\011tab rw - ext4 /dev/synthetic rw\n'
                               '3 1 0:5 net:[42] /run/netns/test rw - nsfs nsfs rw\n')
        self.assertEqual(table.rows[1]['root'], Path('/source with\\slash'))
        self.assertEqual(table.rows[1]['point'], Path('/dest\ttab'))
        self.assertEqual(table.physical(Path('/ordinary')), ('8:1', Path('/ordinary')))
        with self.assertRaisesRegex(w.Refused, 'non-filesystem'):
            table.physical(Path('/run/netns/test'))
        for invalid in ('', 'not mountinfo', '1 0 invalid / / rw - ext4 disk rw'):
            with self.assertRaises(w.Refused):
                RealMountTable(invalid)

    def test_physical_alias_and_distinct_backup_filesystem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, backup = root / 'source', root / 'backup'
            source.mkdir(); backup.mkdir()
            base = MOUNT_NAMESPACE['text']
            # An ordinary distinct backup filesystem is supported.
            table = RealMountTable(base + f'2 1 9:1 / {backup} rw - xfs /dev/backup rw\n')
            w.restore_sources({str(source): 'directory'}, backup, mounts=table)
            # Whole-filesystem bind aliases can have root=/; physical device
            # paths still detect overlap even when lexical paths are disjoint.
            table = RealMountTable(base + f'2 1 8:1 / {backup} rw - ext4 /dev/synthetic rw\n')
            with self.assertRaisesRegex(w.Refused, 'physical filesystem alias'):
                w.restore_sources({str(source): 'directory'}, backup, mounts=table)
            table = RealMountTable(base + f'2 1 8:1 {source} {backup} rw - ext4 /dev/synthetic rw\n')
            with self.assertRaisesRegex(w.Refused, 'subtree or bind-mount ancestry'):
                w.restore_sources({str(source): 'directory'}, backup, mounts=table)
            alias = root / 'alias'; (alias / 'child').mkdir(parents=True)
            table = RealMountTable(base + f'2 1 8:1 {source} {alias} rw - ext4 /dev/synthetic rw\n')
            with self.assertRaisesRegex(w.Refused, 'physical filesystem alias'):
                w.restore_sources({str(source): 'directory', str(alias / 'child'): 'directory'}, backup, mounts=table)

    def test_real_tar_top_level_symlink_omits_data_but_coordinator_refuses_before_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data, link = root / 'data', root / 'ossec'
            data.mkdir(); (data / 'retained-state').write_text('must survive')
            link.symlink_to(data, target_is_directory=True)
            native_archive = root / 'unsafe.tar'
            subprocess.run(['tar', '-cpf', str(native_archive), '-C', str(root), 'ossec'], check=True, capture_output=True)
            members = subprocess.check_output(['tar', '-tf', str(native_archive)], text=True).splitlines()
            self.assertEqual(members, ['ossec'])
            private = w.private_dir(root / 'private')
            with self.assertRaisesRegex(w.Refused, 'symlink'):
                w.Transaction('agent', root=private).archive(link, private / 'safe.tar')
            self.assertFalse((private / 'safe.tar').exists())
            self.assertEqual((data / 'retained-state').read_text(), 'must survive')

    @contextlib.contextmanager
    def agent(self, family='Debian'):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_path, old_mounts = w.Path, MOUNT_NAMESPACE['text']
            mapped = ('/var/ossec', '/etc/hosts', '/etc/apt/preferences.d', '/etc/yum.repos.d', '/var/cache/apt/archives', '/etc/audit/plugins.d', '/etc/dnf', '/usr/sbin/policy-rc.d')
            def path(value):
                value = str(value)
                return root / 'host' / value.lstrip('/') if any(value == p or value.startswith(p + '/') for p in mapped) else real_path(value)
            class Native(Commands):
                def __init__(self):
                    super().__init__(family, '4.14.1-1')
                    self.active = True
                def run(self, argv, **kwargs):
                    if argv[0] == 'du':
                        argv = [*argv[:-1], str(path(argv[-1]))]
                    if argv[0] == '/var/ossec/bin/wazuh-control':
                        return subprocess.CompletedProcess(argv, 0, 'WAZUH_VERSION="v' + self.installed.rsplit('-', 1)[0] + '"\n', '')
                    if argv[0] == 'systemctl':
                        self.calls.append(list(argv))
                        if argv[1] in ('stop', 'start'):
                            self.active = argv[1] == 'start'
                        return subprocess.CompletedProcess(argv, 0 if self.active or argv[1] != 'is-active' else 3,
                                                           'enabled' if argv[1] == 'is-enabled' else '', '')
                    return super().run(argv, **kwargs)
            class Agent(w.Agent):
                def guard(self): return PackagePolicyHarness(self.r)
                def package_archives(self, installed, target):
                    # Signed/native package identity has independent controls;
                    # this call-chain fixture supplies verified artifact bytes.
                    return {v: {'path': root / 'stage' / (v + '.pkg'), 'sha256': w.digest(root / 'stage' / (v + '.pkg'))}
                            for v in (installed, target)}
            w.Path = path
            try:
                for name, content in {'/var/ossec/etc/client.keys': '001 synthetic any TEST_KEY\n',
                                      '/var/ossec/etc/ossec.conf': 'original data', '/etc/hosts': 'original hosts',
                                      '/etc/apt/preferences.d/pilot-wazuh-agent': 'original pin',
                                      '/etc/yum.repos.d/wazuh.repo': 'original repo'}.items():
                    destination = path(name); destination.parent.mkdir(parents=True, exist_ok=True); destination.write_text(content)
                (root / 'stage').mkdir(mode=0o700)
                path('/var/cache/apt/archives').mkdir(parents=True)
                path('/etc/audit/plugins.d').mkdir(parents=True)
                path('/etc/dnf/plugins').mkdir(parents=True)
                path('/usr/sbin/policy-rc.d').parent.mkdir(parents=True)
                for release in ('4.14.1-1', '4.14.9-1'):
                    (root / 'stage' / (release + '.pkg')).write_text(release)
                native = Native()
                agent = Agent(family, root=root / 'private', runner=native)
                w.HostWriter(agent.root).claim('d' * 32, 'agent')
                yield agent, native, path, root
            finally:
                w.Path = real_path
                MOUNT_NAMESPACE['text'] = old_mounts

    def test_agent_reserve_rejects_every_selected_symlink_and_file_alias_before_authority(self):
        import os, shutil
        for family in ('Debian', 'RedHat'):
            for selected in ('/var/ossec', '/etc/hosts', 'pin', 'pin-parent', 'absent-pin-parent', 'hosts-hardlink',
                             '/var/ossec/etc/ossec.conf', 'config-hardlink', 'key-parent'):
                with self.subTest(family=family, selected=selected), self.agent(family) as (agent, native, path, root):
                    name = agent.pin_path() if selected in ('pin', 'pin-parent', 'absent-pin-parent') else selected
                    victim = path(name if selected != 'hosts-hardlink' else '/etc/hosts')
                    if selected == 'config-hardlink': victim = path('/var/ossec/etc/ossec.conf')
                    if selected == 'key-parent': victim = path('/var/ossec/etc')
                    if selected in ('pin-parent', 'absent-pin-parent'):
                        if selected == 'absent-pin-parent':
                            victim.unlink()
                        victim = victim.parent
                    alias = root / 'outside'
                    if selected in ('hosts-hardlink', 'config-hardlink'):
                        os.link(victim, alias)
                    else:
                        shutil.move(victim, alias)
                        victim.symlink_to(alias, target_is_directory=alias.is_dir())
                    with self.assertRaisesRegex(w.Refused, 'symlink|single-link|uncaptured external hardlink'):
                        agent.reserve('d' * 32, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                    self.assertFalse(agent.path.exists(), 'unsafe source must never acquire reserve authority')
                    self.assertFalse(any(call[:2] == ['systemctl', 'stop'] for call in native.calls))
                    self.assertTrue(native.active)

    def test_agent_reserve_rejects_root_and_descendant_mounts_before_authority(self):
        for family in ('Debian', 'RedHat'):
            for name in ('/var/ossec', '/var/ossec/nested', '/etc/hosts', 'pin', '/var/cache/apt/archives'):
                if family == 'RedHat' and name == '/var/cache/apt/archives':
                    continue
                with self.subTest(family=family, name=name), self.agent(family) as (agent, native, path, _):
                    point = path(agent.pin_path() if name == 'pin' else name)
                    MOUNT_NAMESPACE['text'] += f'2 1 8:1 {point} {point} rw - ext4 /dev/synthetic rw\n'
                    with self.assertRaisesRegex(w.Refused, 'unsupported mount or nested mount'):
                        agent.reserve('d' * 32, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                    self.assertFalse(agent.path.exists(), 'mounted source must never acquire reserve authority')
                    self.assertFalse(any(call[:2] == ['systemctl', 'stop'] for call in native.calls))

    def test_agent_revalidates_staged_sources_and_all_recovery_inputs_before_stop(self):
        for boundary in ('cold', 'recovery', 'retained-package', 'retained-parent'):
            with self.subTest(boundary=boundary), self.agent() as (agent, native, path, root):
                agent.reserve('d' * 32, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                if boundary != 'cold':
                    agent.cold_backup('d' * 32)
                before = sum(call[:2] == ['systemctl', 'stop'] for call in native.calls)
                if boundary == 'retained-parent':
                    item = agent.active()
                    item['packages']['4.14.1-1']['path'] = str(root / 'stage/4.14.1-1.pkg')
                    agent.write(item, item['phase'])
                elif boundary == 'retained-package':
                    package = Path(next(iter(agent.active()['packages'].values()))['path'])
                    package.unlink(); package.symlink_to(root / 'stage/4.14.1-1.pkg')
                else:
                    point = path('/var/ossec/nested')
                    MOUNT_NAMESPACE['text'] += f'2 1 8:1 {point} {point} rw - ext4 /dev/synthetic rw\n'
                phase = agent.active()['phase']
                with self.assertRaisesRegex(w.Refused, 'unsupported mount|symlink|exact private directory'):
                    (agent.cold_backup if boundary == 'cold' else agent.prepare_recovery)('d' * 32)
                self.assertEqual(agent.active()['phase'], phase)
                self.assertEqual(sum(call[:2] == ['systemctl', 'stop'] for call in native.calls), before)

    def test_rpm_staging_refuses_cache_and_artifact_aliases_before_native_tools(self):
        import os
        for target in ('stage-directory', 'artifact-symlink', 'artifact-hardlink'):
            with self.subTest(target=target), self.agent('RedHat') as (fixture, native, _, root):
                agent = w.Agent('RedHat', root=fixture.root, runner=native)
                agent.stage_preflight('d' * 32)
                stage = agent.root / 'rpm-stage'
                outside = root / 'outside.rpm'; outside.write_bytes(b'outside package bytes')
                if target == 'stage-directory':
                    stage.rmdir(); stage.symlink_to(root, target_is_directory=True)
                elif target == 'artifact-symlink':
                    (stage / 'old.rpm').symlink_to(outside)
                else:
                    os.link(outside, stage / 'old.rpm')
                with self.assertRaisesRegex(w.Refused, 'symlink|single-link'):
                    agent.stage_preflight('d' * 32)
                with self.assertRaisesRegex(w.Refused, 'symlink|single-link'):
                    agent.package_archives('4.14.1-1', '4.14.9-1')
                self.assertFalse(any(call[0] == 'rpmkeys' for call in native.calls))
                self.assertEqual(outside.read_bytes(), b'outside package bytes')

    def test_debian_cache_ancestor_and_artifact_aliases_refuse_before_metadata(self):
        import os
        for target in ('cache-ancestor', 'artifact-symlink', 'artifact-hardlink'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                cache = root / 'real/cache'; cache.mkdir(parents=True)
                cache.chmod(0o755)
                outside = root / 'outside.deb'; outside.write_bytes(b'outside package bytes')
                self.assertEqual(apt.validate_cache(cache), cache)
                if target == 'cache-ancestor':
                    (root / 'link').symlink_to(root / 'real', target_is_directory=True)
                    cache = root / 'link/cache'
                elif target == 'artifact-symlink':
                    (cache / 'old.deb').symlink_to(outside)
                else:
                    os.link(outside, cache / 'old.deb')
                with self.assertRaisesRegex(ValueError, 'symlink|untrusted'):
                    apt.validate_cache(cache)
                previous = apt.run
                calls = []
                apt.run = lambda argv: calls.append(argv)
                try:
                    with self.assertRaisesRegex(ValueError, 'symlink|untrusted'):
                        apt.verify({'wazuh-agent': '4.14.1-1'}, cache)
                    self.assertEqual(calls, [])
                finally:
                    apt.run = previous

    def test_private_debian_recovery_checks_every_ancestor_and_manifest_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = w.private_dir(Path(temporary) / 'private')
            parent = w.private_dir(root / ('agent-' + 'd' * 32))
            artifact = parent / 'old.deb'; artifact.write_bytes(b'verified old package bytes')
            item = {'owner': 'd' * 32, 'phase': 'recovering', 'family': 'Debian', 'kind': 'agent',
                    'installed': '4.14.1-1', 'backup': str(parent),
                    'packages': {'4.14.1-1': {'path': str(artifact), 'sha256': w.digest(artifact)}}}
            w.atomic_json(parent / 'manifest.json', item)
            w.atomic_json(root / 'agent-active.json', item)
            previous = apt.run
            apt.run = lambda argv: 'wazuh-agent\n4.14.1-1\namd64'
            try:
                self.assertEqual(apt.verify_recovery(artifact, {'wazuh-agent': '4.14.1-1'}, root)['version'], '4.14.1-1')
                with self.assertRaisesRegex(ValueError, 'native APT cache basename'):
                    apt.verify_recovery(artifact, {'wazuh-agent': '4.14.1-1'}, root, require_cache_name=True)
                parent.chmod(0o755)
                with self.assertRaisesRegex(ValueError, 'unsafe recovery directory'):
                    apt.verify_recovery(artifact, {'wazuh-agent': '4.14.1-1'}, root)
                parent.chmod(0o700)
                manifest = parent / 'manifest.json'
                manifest.rename(parent / 'real-manifest.json'); manifest.symlink_to(parent / 'real-manifest.json')
                with self.assertRaisesRegex(ValueError, 'symlink ancestor'):
                    apt.verify_recovery(artifact, {'wazuh-agent': '4.14.1-1'}, root)
            finally:
                apt.run = previous

    def test_retained_debian_target_and_recovery_have_distinct_phase_and_version_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = w.private_dir(Path(temporary) / 'private'); parent = w.private_dir(root / ('agent-' + 'd' * 32))
            old, new = parent / 'old.deb', parent / 'new.deb'; old.write_bytes(b'verified old bytes'); new.write_bytes(b'verified target bytes')
            item = {'owner': 'd' * 32, 'phase': 'installing', 'family': 'Debian', 'kind': 'agent',
                    'installed': '4.14.1-1', 'package': '4.14.9-1', 'backup': str(parent),
                    'packages': {'4.14.1-1': {'path': str(old), 'sha256': w.digest(old)},
                                 '4.14.9-1': {'path': str(new), 'sha256': w.digest(new)}}}
            previous = apt.run
            apt.run = lambda argv: 'wazuh-agent\n' + ('4.14.1-1' if argv[-1] == str(old) else '4.14.9-1') + '\namd64'
            try:
                for phase in ('installing', 'recovering'):
                    item['phase'] = phase; w.atomic_json(parent / 'manifest.json', item); w.atomic_json(root / 'agent-active.json', item)
                    artifact, version = (new, '4.14.9-1') if phase == 'installing' else (old, '4.14.1-1')
                    self.assertEqual(apt.verify_recovery(artifact, {'wazuh-agent': version}, root, installation=phase == 'installing')['version'], version)
                    with self.assertRaises(ValueError):
                        apt.verify_recovery(artifact, {'wazuh-agent': version}, root, installation=phase != 'installing')
                    with self.assertRaises(ValueError):
                        apt.verify_recovery(new if phase == 'recovering' else old, {'wazuh-agent': version}, root, installation=phase == 'installing')
                    active = dict(item, owner='e' * 32); w.atomic_json(root / 'agent-active.json', active)
                    with self.assertRaisesRegex(ValueError, 'owner is no longer active'):
                        apt.verify_recovery(artifact, {'wazuh-agent': version}, root, installation=phase == 'installing')
            finally: apt.run = previous

    def test_central_discovery_rejects_volume_mounts_and_backup_bind_alias(self):
        for target in ('volume-root', 'volume-descendant', 'project-root', 'backup-alias'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                central, compose, native = DiscoveryFilesystemTests().central(root)
                baseline = MOUNT_NAMESPACE['text']
                point = root / 'docker-data/volumes/single-node_volume_0/_data'
                if target == 'volume-descendant': point = point / 'nested'
                if target == 'project-root': point = compose.parent
                mount_root = point
                if target == 'backup-alias': point = central.root
                MOUNT_NAMESPACE['text'] += f'2 1 8:1 {mount_root} {point} rw - ext4 /dev/synthetic rw\n'
                try:
                    with self.assertRaisesRegex(w.Refused, 'unsupported mount|subtree or bind-mount ancestry'):
                        central.discover()
                    self.assertFalse(central.path.exists())
                    self.assertFalse(any(call[1] in ('stop', 'rm', 'compose') for call in native.calls))
                finally:
                    MOUNT_NAMESPACE['text'] = baseline


class AgentColdRecoveryTests(unittest.TestCase):
    def test_real_cold_state_and_identity_restored_for_both_backends(self):
        # Map only the coordinator's fixed host paths into disposable local
        # files. Real GNU tar still creates, verifies and restores the archives.
        # Native package/service state is an explicit command harness.
        for family, absent_pin in (('Debian', False), ('Debian', True), ('RedHat', False)):
            with self.subTest(family=family, absent_pin=absent_pin), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                real_path = w.Path
                real_sync_file, real_sync_tree, real_sync_directory = w.sync_file, w.sync_tree, w.sync_directory
                sealed, restored, synced_directories = set(), set(), set()
                def sync_directory(filename):
                    real_sync_directory(filename)
                    synced_directories.add(str(filename))
                def seal(filename):
                    real_sync_file(filename)
                    sealed.add(str(filename))
                def barrier(filename):
                    real_sync_tree(filename)
                    restored.add(str(filename))
                mapped = ('/var/ossec', '/etc/hosts', '/etc/apt/preferences.d', '/etc/yum.repos.d', '/var/cache/apt/archives', '/etc/audit/plugins.d', '/etc/dnf', '/usr/sbin/policy-rc.d')
                def path(value):
                    value = str(value)
                    if any(value == prefix or value.startswith(prefix + '/') for prefix in mapped):
                        return Path(root / 'host' / value.lstrip('/'))
                    return real_path(value)
                class Native(Commands):
                    def __init__(self):
                        super().__init__(family, '4.14.1-1')
                        self.active = True
                    def run(self, argv, **kwargs):
                        if argv[0] == 'du':
                            argv = list(argv[:-1]) + [str(path(argv[-1]))]
                        if argv[0] == 'systemctl':
                            self.calls.append(list(argv))
                            action = argv[1]
                            if action in ('start', 'stop'):
                                self.active = action == 'start'
                            code = 0 if action != 'is-active' or self.active else 3
                            return subprocess.CompletedProcess(argv, code, 'enabled' if action == 'is-enabled' else '', '')
                        if argv[0] == '/var/ossec/bin/wazuh-control':
                            return subprocess.CompletedProcess(argv, 0, 'WAZUH_VERSION="v' + self.installed.rsplit('-', 1)[0] + '"\n', '')
                        return super().run(argv, **kwargs)
                class LocalAgent(w.Agent):
                    def guard(self): return PackagePolicyHarness(self.r)
                    def write(self, item, phase):
                        if phase == 'staged':
                            self_test.assertTrue({entry['path'] for entry in item['packages'].values()}.issubset(sealed))
                        if phase == 'backed-up':
                            self_test.assertTrue({entry['archive'] for entry in item['archives']}.issubset(sealed))
                        if phase == 'restored':
                            self_test.assertTrue({str(path(value)) for value in item['paths']}.issubset(restored))
                            if not item['pin_state']['present']:
                                self_test.assertFalse(path(self.pin_path()).exists())
                                self_test.assertIn(str(path(self.pin_path()).parent), synced_directories,
                                                   'absent pin deletion must sync its parent before restored authority')
                        return super().write(item, phase)
                    def package_archives(self, installed, target):
                        return {release: {'path': root / (release + '.pkg'), 'sha256': w.digest(root / (release + '.pkg'))}
                                for release in (installed, target)}
                self_test = self
                w.Path, w.sync_file, w.sync_tree, w.sync_directory = path, seal, barrier, sync_directory
                try:
                    for filename, content in {
                        '/var/ossec/etc/client.keys': '001 synthetic any SYNTHETIC_KEY_ONLY\n',
                        '/var/ossec/etc/ossec.conf': 'old config and data', '/etc/hosts': 'old hosts',
                        '/etc/apt/preferences.d/pilot-wazuh-agent': 'old apt pin',
                        '/etc/yum.repos.d/wazuh.repo': 'old rpm pin',
                    }.items():
                        destination = path(filename)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_text(content)
                    if absent_pin:
                        path('/etc/apt/preferences.d/pilot-wazuh-agent').unlink()
                    path('/var/cache/apt/archives').mkdir(parents=True)
                    path('/etc/audit/plugins.d').mkdir(parents=True)
                    path('/etc/dnf/plugins').mkdir(parents=True)
                    path('/usr/sbin/policy-rc.d').parent.mkdir(parents=True)
                    for release in ('4.14.1-1', '4.14.9-1'):
                        (root / (release + '.pkg')).write_text(release)
                    native = Native()
                    agent = LocalAgent(family, runner=native, root=root / 'backups')
                    (agent.root / 'rpm-stage').mkdir(parents=True)
                    plan = w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True)
                    owner = 'c' * 32
                    w.HostWriter(agent.root).claim(owner, 'agent')
                    agent.reserve(owner, plan)
                    agent.cold_backup(owner)
                    agent.authorize_install(owner)
                    native.installed = '4.14.9-1'
                    path('/var/ossec/etc/ossec.conf').write_text('new migrated data')
                    path('/var/ossec/etc/client.keys').write_text('002 changed any SYNTHETIC_WRONG_KEY\n')
                    path('/etc/hosts').write_text('new hosts')
                    if absent_pin:
                        path('/etc/apt/preferences.d/pilot-wazuh-agent').write_text('target-only pin')
                    agent.activate(owner)
                    with self.assertRaisesRegex(w.Refused, 'identity changed'):
                        agent.commit(owner)
                    self.assertTrue(agent.path.exists())
                    recovery = agent.prepare_recovery(owner)
                    self.assertTrue(recovery['reinstall'])
                    native.installed = '4.14.1-1'  # shared framework's retained-package reinstall
                    agent.restore_state(owner)
                    self.assertEqual(path('/var/ossec/etc/ossec.conf').read_text(), 'old config and data')
                    self.assertEqual(path('/etc/hosts').read_text(), 'old hosts')
                    self.assertEqual(path('/var/ossec/etc/client.keys').read_text(), '001 synthetic any SYNTHETIC_KEY_ONLY\n')
                    self.assertTrue(native.active)
                    self.assertEqual(agent.active()['phase'], 'restored')
                    if absent_pin:
                        path(agent.pin_path()).write_text('simulate resurrected target pin')
                        with self.assertRaisesRegex(w.Refused, 'version pin does not match'):
                            agent.finish_recovery(owner)
                        self.assertTrue(agent.path.exists())
                        self.assertTrue(agent.prepare_recovery(owner)['need_commit'])
                        self.assertFalse(path(agent.pin_path()).exists())
                    agent.finish_recovery(owner)
                    self.assertFalse(agent.path.exists())
                    w.HostWriter(agent.root).release(owner)
                finally:
                    w.Path = real_path
                    w.sync_file, w.sync_tree, w.sync_directory = real_sync_file, real_sync_tree, real_sync_directory


class CaptureClosureTests(unittest.TestCase):
    def test_unreadable_or_changing_complete_metadata_never_grants_reserve_authority(self):
        from unittest.mock import patch
        for fault in ('unreadable', 'changed-earlier-root'):
            with self.subTest(fault=fault), RestoreScopeTests().agent() as (agent, native, path, root):
                original = w.ClosedCapture.attrs
                changed = False
                def attrs(filename):
                    nonlocal changed
                    if str(filename) == str(path('/etc/hosts')):
                        if fault == 'unreadable': raise OSError('synthetic denied metadata')
                        if not changed:
                            path('/var/ossec/etc/ossec.conf').write_text('changed during complete capture')
                            changed = True
                    return original(filename)
                with patch.object(w.ClosedCapture, 'attrs', side_effect=attrs):
                    with self.assertRaisesRegex(w.Refused, 'metadata is unreadable|metadata changed|layout namespace is unreadable|file changed'):
                        agent.reserve('d' * 32, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                self.assertIsNone(agent.active())
                self.assertFalse(any(call[:2] == ['systemctl', 'stop'] for call in native.calls))

    def test_external_descendant_data_alias_is_rejected_by_reserve_before_authority(self):
        import shutil
        for family in ('Debian', 'RedHat'):
            with self.subTest(family=family), RestoreScopeTests().agent(family) as (agent, native, path, root):
                outside = root / 'external-queue'; outside.mkdir()
                state = outside / 'data'; state.write_text('old persistent data')
                path('/var/ossec/queue').symlink_to(outside, target_is_directory=True)
                # Real tar demonstrates the original incomplete-capture bug:
                # restoring the alias cannot restore its external effective data.
                archive = root / 'incomplete.tar'
                subprocess.run(['tar', '-cpf', str(archive), '-C', str(path('/var/ossec').parent), 'ossec'], check=True, capture_output=True)
                state.write_text('new state survives incomplete restore')
                shutil.rmtree(path('/var/ossec'))
                subprocess.run(['tar', '-xpf', str(archive), '-C', str(path('/var/ossec').parent)], check=True, capture_output=True)
                self.assertEqual(state.read_text(), 'new state survives incomplete restore')
                with self.assertRaisesRegex(w.Refused, 'symlink escapes'):
                    agent.reserve('d' * 32, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                self.assertIsNone(agent.active())
                self.assertFalse(any(call[:2] == ['systemctl', 'stop'] for call in native.calls))

    def test_closed_internal_symlinks_and_complete_hardlinks_survive_real_recovery(self):
        import os
        for family in ('Debian', 'RedHat'):
            with self.subTest(family=family), RestoreScopeTests().agent(family) as (agent, native, path, root):
                conf = path('/var/ossec/etc/af_wazuh.conf'); conf.write_text('active component audit config')
                plugin = path('/etc/audit/plugins.d/af_wazuh.conf'); os.link(conf, plugin)
                os.setxattr(conf, 'user.issue244', b'preserved audit config attribute')
                data = path('/var/ossec/closed-data'); data.mkdir()
                (data / 'old').write_text('old persistent queue')
                os.link(data / 'old', data / 'other-name')
                path('/var/ossec/queue').symlink_to('closed-data', target_is_directory=True)
                owner = 'd' * 32
                agent.reserve(owner, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                agent.cold_backup(owner)
                capture = agent.active()['capture']
                self.assertIn(sorted([str(conf), str(plugin)]), capture['hardlinks'])
                agent.authorize_install(owner)
                native.installed = '4.14.9-1'
                (data / 'old').write_text('migrated new data')
                conf.write_text('new plugin config')
                agent.prepare_recovery(owner); native.installed = '4.14.1-1'
                agent.restore_state(owner)
                self.assertEqual((path('/var/ossec/queue') / 'old').read_text(), 'old persistent queue')
                self.assertEqual(conf.read_text(), 'active component audit config')
                self.assertEqual((conf.stat().st_dev, conf.stat().st_ino), (plugin.stat().st_dev, plugin.stat().st_ino))
                self.assertEqual(conf.stat().st_nlink, 2)
                self.assertEqual(os.getxattr(plugin, 'user.issue244'), b'preserved audit config attribute')
                agent.finish_recovery(owner)

    def test_unknown_third_audit_alias_refuses_admission_and_pre_stop_recheck(self):
        import os
        for boundary in ('admission', 'staged'):
            with self.subTest(boundary=boundary), RestoreScopeTests().agent() as (agent, native, path, root):
                conf = path('/var/ossec/etc/af_wazuh.conf'); conf.write_text('old plugin')
                os.link(conf, path('/etc/audit/plugins.d/af_wazuh.conf'))
                if boundary == 'staged':
                    agent.reserve('d' * 32, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                os.link(conf, root / 'uncaptured-third-link')
                with self.assertRaisesRegex(w.Refused, 'uncaptured external hardlink'):
                    if boundary == 'admission':
                        agent.reserve('d' * 32, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                    else: agent.cold_backup('d' * 32)
                self.assertFalse(any(call[:2] == ['systemctl', 'stop'] for call in native.calls))
                self.assertEqual(agent.active()['phase'] if agent.active() else None, 'staged' if boundary == 'staged' else None)

    def test_explicit_admission_checks_all_volume_descendants_and_complete_link_groups(self):
        import os
        for mutation in ('closed-pair', 'third-alias', 'external-symlink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); central, _, native = DiscoveryFilesystemTests().central(root)
                volume = next((root / 'docker-data/volumes').glob('*/_data'))
                data = volume / 'data'; data.write_text('persistent central data')
                os.link(data, volume / 'alias')
                if mutation == 'third-alias': os.link(data, root / 'outside-data')
                if mutation == 'external-symlink': (volume / 'queue').symlink_to(root, target_is_directory=True)
                if mutation == 'closed-pair':
                    state = central.discover()
                    self.assertEqual(state['version'], '4.14.1')
                    w.ScopeLayout.inspect({name: 'directory' for name in state['paths']}, central.root)
                else:
                    state = central.discover()
                    with self.assertRaisesRegex(w.Refused, 'uncaptured external hardlink|symlink escapes|dangling symlink'):
                        w.ScopeLayout.inspect({name: 'directory' for name in state['paths']}, central.root)
                self.assertFalse(any(call[1] in ('stop', 'rm', 'compose') for call in native.calls))

    def test_content_seal_and_symlink_component_resolution_are_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'source'; source.mkdir()
            (source / 'data').write_text('old'); (source / 'nested').mkdir()
            (source / 'valid').symlink_to('nested/../data')
            capture = w.ClosedCapture.take({str(source): 'directory'}, root / 'private', sealed=True)
            self.assertEqual(capture['nodes'][str(source / 'valid')]['resolved'], str(source / 'data'))
            (source / 'data').write_text('new')
            with self.assertRaisesRegex(w.Refused, 'differs from'):
                w.ClosedCapture.verify(capture, root / 'private')
            (source / 'nested/link').symlink_to(root, target_is_directory=True)
            (source / 'escape').symlink_to('nested/link/../outside')
            with self.assertRaisesRegex(w.Refused, 'symlink escapes'):
                w.ClosedCapture.take({str(source): 'directory'}, root / 'private')


class LiveLayoutTests(unittest.TestCase):
    @contextlib.contextmanager
    def append_on(self, trigger, log, enabled=lambda: True):
        # A real writer thread, deterministically admitted between the log's
        # lstat and the final complete-walk verification. No synthetic stat.
        original = w.ClosedCapture.attrs
        writes = []
        def attrs(filename):
            if str(filename) == str(trigger) and enabled():
                failures = []
                def append():
                    try:
                        with log.open('a') as stream:
                            stream.write('real active log append\n'); stream.flush()
                        writes.append(log.stat().st_size)
                    except BaseException as exc: failures.append(exc)
                thread = threading.Thread(target=append);thread.start();thread.join(3)
                self.assertFalse(thread.is_alive(), 'controlled writer did not finish')
                if failures: raise failures[0]
            return original(filename)
        with mock.patch.object(w.ClosedCapture, 'attrs', side_effect=attrs):
            yield writes

    def test_regular_append_is_live_layout_only_and_strict_cold_capture_still_refuses(self):
        for reader in ('layout', 'strict-unsealed', 'strict-sealed'):
            with self.subTest(reader=reader), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); source = root / 'source'; source.mkdir()
                log = source / '00-live.log'; log.write_text('old log\n')
                trigger = source / '99-trigger'; trigger.write_text('static')
                specs = {str(source): 'directory'}; backup = root / 'backups'
                with self.append_on(trigger, log) as writes:
                    if reader == 'layout':
                        layout = w.ScopeLayout.inspect(specs, backup)
                        self.assertFalse(layout['sealed']);self.assertEqual(layout['purpose'], 'live-layout-only')
                        with self.assertRaisesRegex(w.Refused, 'not content-sealed'):
                            w.ClosedCapture.verify(layout, backup)
                        with self.assertRaisesRegex(w.Refused, 'content-sealed cold capture'):
                            w.Transaction('agent', root=backup).archive(source, backup / 'forbidden.tar', capture=layout)
                    else:
                        with self.assertRaisesRegex(w.Refused, 'capture metadata changed'):
                            w.ClosedCapture.take(specs, backup, sealed=reader == 'strict-sealed')
                self.assertTrue(writes, 'the real file must change during the walk')

    def test_namespace_rotation_membership_and_missing_nodes_remain_inconclusive(self):
        for mutation in ('rotation', 'added-child', 'removed-node', 'new-link-alias', 'unreadable'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); source = root / 'source'; source.mkdir()
                log = source / '00-live.log'; log.write_text('old log')
                trigger = source / '99-trigger'; trigger.write_text('stable')
                original = w.ClosedCapture.attrs; changed = False
                def attrs(filename):
                    nonlocal changed
                    if str(filename) == str(trigger) and not changed:
                        changed = True
                        if mutation == 'rotation':
                            log.rename(source / 'old.log');log.write_text('new log inode')
                        elif mutation == 'added-child': (source / 'unseen').write_text('new')
                        elif mutation == 'removed-node': log.unlink()
                        elif mutation == 'new-link-alias': w.os.link(log, root / 'outside-alias')
                        else: raise OSError('bounded unreadable metadata')
                    return original(filename)
                with mock.patch.object(w.ClosedCapture, 'attrs', side_effect=attrs):
                    with self.assertRaisesRegex(w.Refused, 'layout.*changed|layout.*unreadable'):
                        w.ScopeLayout.inspect({str(source): 'directory'}, root / 'private')
                self.assertTrue(changed)

    def test_readonly_central_health_never_recursively_inspects_live_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            central, _, native = DiscoveryFilesystemTests().central(Path(temporary))
            checked = []; central.check_agents = lambda target: checked.append(target)
            with mock.patch.object(w.ClosedCapture, 'take', side_effect=w.Refused('strict capture invoked on live data')):
                with mock.patch.object(w.ScopeLayout, 'inspect', side_effect=AssertionError('C12 performed a data-tree walk')):
                    result = central.verify()
            self.assertEqual(result, {'pass': True, 'version': '4.14.1'})
            self.assertEqual(checked, ['4.14.1'])
            self.assertTrue(any(call[-1] == 'info' for call in native.calls))
            self.assertFalse(any(call[1] in ('stop', 'rm') for call in native.calls))

    def test_readonly_health_with_real_appends_has_no_live_content_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);central, _, native = DiscoveryFilesystemTests().central(root)
            volume = next((root / 'docker-data/volumes').glob('*/_data'))
            log = volume / '00-live.log';log.write_text('running')
            trigger = volume / '99-trigger';trigger.write_text('stable')
            central.check_agents = lambda target: None
            original = native.run; writes = []
            def run(argv, **kwargs):
                def append():
                    with log.open('a') as stream:stream.write('native observation active append\n')
                    writes.append(log.stat().st_size)
                writer=threading.Thread(target=append);writer.start();writer.join(3)
                self.assertFalse(writer.is_alive())
                return original(argv, **kwargs)
            native.run = run
            # If the old recursive snapshot is restored, this second real
            # writer deterministically mutates its earlier log node mid-walk.
            with self.append_on(trigger, log):
                self.assertTrue(central.verify()['pass'])
            self.assertTrue(writes)

    def test_native_recovery_scope_validation_is_nonfreezing_before_quiescence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);central,_,_=DiscoveryFilesystemTests().central(root)
            state=central.discover();state['backup']=str(w.private_dir(central.root/'retained'))
            volume=next((root/'docker-data/volumes').glob('*/_data'))
            log=volume/'00-live.log';log.write_text('running')
            trigger=volume/'99-trigger';trigger.write_text('stable')
            with self.append_on(trigger,log) as writes:
                central.validate_project_scope(state)
            self.assertTrue(writes)

    def test_pre_switch_and_finalized_completion_use_live_layout_after_restart(self):
        for method in ('recover_pre_switch', 'complete_finalized'):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as temporary:
                central = FakeCentral(Path(temporary))
                log = central.volume / '00-live.log';log.write_text('running')
                trigger = central.volume / '99-trigger';trigger.write_text('stable')
                owner = '1' * 32;w.HostWriter(central.root).claim(owner, 'central')
                with central.lock(owner=owner):
                    state=central.discover();state['data']=central.data()
                    item=central.begin(owner,state)
                    if method=='complete_finalized':central.write(item,'recovered')
                    with self.append_on(trigger, log) as writes:
                        getattr(central,method)(item)
                    self.assertTrue(writes)
                self.assertFalse(central.path.exists());w.HostWriter(central.root).release(owner)

    def test_mutating_data_after_agent_stop_cannot_grant_cold_backup_authority(self):
        with RestoreScopeTests().agent() as (agent,native,path,_):
            logs=path('/var/ossec/logs');logs.mkdir()
            log=logs/'ossec.log';log.write_text('old')
            owner='d'*32;agent.reserve(owner,w.agent_plan('4.14.1-1','4.14.9','4.14.9',True))
            with self.append_on(path('/etc/hosts'),log,lambda:not native.active) as writes:
                with self.assertRaisesRegex(w.Refused,'capture metadata changed'):
                    agent.cold_backup(owner)
            self.assertTrue(writes);self.assertEqual(agent.active()['phase'],'stopping')
            self.assertNotIn('archives',agent.active())
            self.assertFalse(list(Path(agent.active()['backup']).glob('*.tar')))

    def test_central_live_admission_and_poststart_commit_and_recovery_allow_data_append(self):
        for recovery in (False, True):
            with self.subTest(recovery=recovery), tempfile.TemporaryDirectory() as temporary:
                class ActiveCentral(FakeCentral):
                    running = True
                    def compose_run(self, item, *args, **kwargs):
                        self.calls.append((item['phase'], args))
                        if args[0] == 'stop': self.running = False
                        if args[0] == 'up': self.running = True
                    def quiesce_for_restore(self, item, remove=True, inspect_only=False):
                        if not inspect_only:self.running = False
                        super().quiesce_for_restore(item, remove, inspect_only=inspect_only)
                central = ActiveCentral(Path(temporary), fail=recovery)
                log = central.volume / '00-live.log';log.write_text('old log')
                trigger = central.volume / '99-trigger';trigger.write_text('stable')
                with self.append_on(trigger, log, lambda: central.running) as writes:
                    if recovery:
                        with self.assertRaisesRegex(w.Refused, 'previous images, data and availability recovered'):
                            central.execute('4.14.9', upgrade=True)
                    else:
                        self.assertTrue(central.execute('4.14.9', upgrade=True)['changed'])
                self.assertGreaterEqual(len(writes), 3)
                self.assertFalse(central.path.exists())
                manifest = json.loads(next(central.root.glob('central-*/manifest.json')).read_text())
                self.assertEqual(manifest['phase'], 'recovered' if recovery else 'committed')
                self.assertEqual((central.volume / 'document').read_text(), 'original indexed data')

    def test_agent_live_admission_activate_commit_and_recovery_use_layout_but_cold_stays_strict(self):
        for family in ('Debian', 'RedHat'):
            for recovery in (False, True):
                with self.subTest(family=family, recovery=recovery), RestoreScopeTests().agent(family) as (agent, native, path, _):
                    logs = path('/var/ossec/logs');logs.mkdir()
                    log = logs / 'ossec.log';log.write_text('old running log')
                    trigger = path('/etc/hosts')
                    owner = 'd' * 32;plan = w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True)
                    sync_file = w.sync_file
                    with self.append_on(trigger, log, lambda: native.active) as writes:
                        agent.reserve(owner, plan);agent.cold_backup(owner);agent.authorize_install(owner)
                        native.installed = '4.14.9-1'
                        agent.activate(owner)
                        if recovery:
                            agent.prepare_recovery(owner);native.installed = '4.14.1-1'
                            agent.restore_state(owner);agent.finish_recovery(owner)
                        else:
                            with mock.patch.object(w, 'sync_file', side_effect=lambda name: sync_file(path(name))):
                                agent.commit(owner)
                    self.assertGreaterEqual(len(writes), 3)
                    self.assertTrue(native.active);self.assertFalse(agent.path.exists())

    def test_live_layout_does_not_relax_exact_managed_key_or_config_hashes(self):
        for selected in ('/var/ossec/etc/client.keys', '/var/ossec/etc/ossec.conf'):
            with self.subTest(selected=selected), RestoreScopeTests().agent() as (agent, native, path, _):
                original = w.ClosedCapture.attrs; changed = False
                def attrs(filename):
                    nonlocal changed
                    if str(filename) == str(path('/etc/hosts')) and not changed:
                        path(selected).write_text('changed managed contents during layout');changed = True
                    return original(filename)
                with mock.patch.object(w.ClosedCapture, 'attrs', side_effect=attrs):
                    with self.assertRaisesRegex(w.Refused, 'capture file changed'):
                        agent.reserve('d' * 32, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                self.assertIsNone(agent.active());self.assertTrue(native.active)

    def test_layout_keeps_pre_stop_external_links_and_mount_refusals(self):
        for mutation in ('symlink', 'external-hardlink', 'nested-mount'):
            with self.subTest(mutation=mutation), RestoreScopeTests().agent() as (agent, native, path, root):
                data = path('/var/ossec/queue-data');data.write_text('persistent')
                if mutation == 'symlink': path('/var/ossec/queue').symlink_to(root, target_is_directory=True)
                elif mutation == 'external-hardlink': w.os.link(data, root / 'uncaptured-alias')
                else:
                    mount = path('/var/ossec/nested');mount.mkdir()
                    MOUNT_NAMESPACE['text'] += f'2 1 8:1 / {mount} rw - ext4 /dev/synthetic rw\n'
                with self.assertRaisesRegex(w.Refused, 'symlink escapes|dangling symlink|uncaptured external hardlink|unsupported mount'):
                    agent.reserve('d' * 32, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                self.assertIsNone(agent.active());self.assertTrue(native.active)
                self.assertFalse(any(call[:2] == ['systemctl','stop'] for call in native.calls))


class AuditNativeObservationTests(unittest.TestCase):
    def test_proc_identity_parser_preserves_real_usrmerge_executable_and_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); process = root / '100'; process.mkdir()
            fields = ['S', '1'] + ['0'] * 17 + ['4242']
            (process / 'stat').write_text('100 (auditd) ' + ' '.join(fields))
            (process / 'cmdline').write_bytes(b'/sbin/auditd\0')
            (process / 'exe').symlink_to('/usr/sbin/auditd')
            real_path = w.Path
            w.Path = lambda value: root / str(value).removeprefix('/proc').lstrip('/') if str(value) == '/proc' else real_path(value)
            try:
                self.assertEqual(w.AuditRuntime.process(100), {'pid': 100, 'ppid': 1, 'start': '4242',
                                 'exe': '/usr/sbin/auditd', 'argv': ['/sbin/auditd']})
            finally: w.Path = real_path

    def test_real_native_connection_watch_parser_and_executed_binary_countercontrol(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'proc/102').mkdir(parents=True); (root / 'ossec/bin').mkdir(parents=True)
            binary = root / 'ossec/bin/wazuh-syscheckd'; binary.write_bytes(b'installed target native executable')
            running = root / 'old-executed'; running.write_bytes(binary.read_bytes())
            (root / 'proc/102/exe').symlink_to(running)
            endpoint = str(root / 'ossec/queue/sockets/audit')
            class Native:
                def __init__(self): self.connected = True; self.watch = True
                def run(self, argv, **kwargs):
                    if argv[0] == 'ss':
                        text = ('u_str ESTAB 0 0 ' + endpoint + ' 100 * 200 users:(("audisp-af_unix",pid=101,fd=4))\n'
                                'u_str ESTAB 0 0 * 200 * ' + ('100' if self.connected else '999') + ' users:(("wazuh-syscheckd",pid=102,fd=7))')
                    else: text = '-a always,exit -F dir=/etc -F key=wazuh_fim' if self.watch else 'No rules'
                    return subprocess.CompletedProcess(argv, 0, text, '')
            native = Native(); runtime = w.AuditRuntime(native)
            runtime.process = lambda pid: {'pid': pid, 'exe': '/var/ossec/bin/wazuh-syscheckd'}
            real_path = w.Path
            def path(value):
                value = str(value)
                if value == '/proc': return root / 'proc'
                if value == '/var/ossec' or value.startswith('/var/ossec/'): return root / 'ossec' / value.removeprefix('/var/ossec').lstrip('/')
                return real_path(value)
            w.Path = path
            proof = {'listener': {'pid': 101}, 'watches': ['-a always,exit -F dir=/etc -F key=wazuh_fim']}
            try:
                self.assertEqual(runtime.ready(proof), proof['watches'])
                for fault in ('connection', 'kernel-watch'):
                    native.connected, native.watch = fault != 'connection', fault != 'kernel-watch'
                    with patch.object(w.time, 'monotonic', side_effect=[0, 61]):
                        with self.assertRaisesRegex(w.Refused, 'readiness timed out'): runtime.ready(proof)
                native.connected = native.watch = True
                binary.write_bytes(b'new package installed while old native process still executes')
                with self.assertRaisesRegex(w.Refused, 'executed audit client differs'): runtime.ready(proof)
            finally: w.Path = real_path


class PreservedAuditRuntimeTests(unittest.TestCase):
    """Real tar/prune/link recovery; kernel/socket/process probes are a harness.

    AF_UNIX bind is unavailable in this sandbox, so the single filesystem
    endpoint is a real regular sentinel whose reported native type is socket.
    The restoration algorithm, inode/security comparisons and archive guard
    remain production code. Root's native VM proof is separately required.
    """
    @contextlib.contextmanager
    def fixture(self):
        import os
        with RestoreScopeTests().agent() as (agent, native, path, root):
            endpoint = path('/var/ossec/queue/sockets/audit'); endpoint.parent.mkdir(parents=True)
            endpoint.write_text('external socket sentinel must not be unlinked')
            endpoint.chmod(0o640); os.setxattr(endpoint, 'user.issue244', b'live endpoint metadata')
            conf = path('/var/ossec/etc/af_wazuh.conf'); conf.write_text('active = yes\n')
            os.link(conf, path('/etc/audit/plugins.d/af_wazuh.conf'))
            class Runtime(w.AuditRuntime):
                def __init__(self, runner):
                    super().__init__(runner); self.boot_id = 'same-native-boot'; self.listener_start = '100'; self.kernel_setting = '1'; self.readiness = []
                def node(self, filename):
                    value = super().node(filename)
                    if filename == endpoint:
                        value['type'] = __import__('stat').S_IFSOCK
                        value['links'] = filename.stat().st_nlink
                    return value
                def boot(self): return self.boot_id
                def audit_processes(self):
                    return ({'pid': 100, 'ppid': 1, 'start': '99', 'exe': '/usr/sbin/auditd', 'argv': ['/sbin/auditd']},
                            {'pid': 101, 'ppid': 100, 'start': self.listener_start, 'exe': '/usr/sbin/audisp-af_unix',
                             'argv': ['/sbin/audisp-af_unix', '0640', str(endpoint)]})
                def kernel(self): return {'pid': '100', 'enabled': self.kernel_setting, 'lost': '0'}
                def ready(self, proof):
                    self.readiness.append(native.installed)
                    return ['-a always,exit -F dir=/etc -F key=wazuh_fim']
            runtime = Runtime(native)
            agent.audit_runtime = lambda: runtime
            yield agent, native, path, root, runtime

    def test_real_preserving_restore_replays_after_prune_interruption(self):
        for interrupted in (False, True):
            with self.subTest(interrupted=interrupted), self.fixture() as (agent, native, path, root, runtime):
                owner = 'd' * 32
                anchors = {str(name): runtime.node(name) for name in runtime.anchors()}
                agent.reserve(owner, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                agent.cold_backup(owner); agent.authorize_install(owner)
                native.installed = '4.14.9-1'; agent.activate(owner)
                sentinel = path('/var/ossec/new-migrated-state'); sentinel.write_text('new state must disappear')
                path('/var/ossec/etc/ossec.conf').write_text('new config')
                agent.prepare_recovery(owner); native.installed = '4.14.1-1'
                original_prune = runtime.prune
                fired = False
                def prune(source, proof):
                    nonlocal fired
                    original_prune(source, proof)
                    if source == path('/var/ossec') and not fired:
                        fired = True
                        raise w.Refused('controlled crash after preserving prune before extract')
                if interrupted:
                    runtime.prune = prune
                    with self.assertRaisesRegex(w.Refused, 'controlled crash after preserving prune'):
                        agent.restore_state(owner)
                    self.assertEqual(agent.active()['phase'], 'recovering')
                    self.assertTrue(path('/var/ossec/queue/sockets/audit').exists())
                    self.assertFalse(path('/var/ossec/etc/ossec.conf').exists())
                    self.assertEqual({str(name): runtime.node(name) for name in runtime.anchors()}, anchors)
                    agent.prepare_recovery(owner)
                    runtime.prune = original_prune
                try:
                    agent.restore_state(owner)
                except (OSError, w.Refused):
                    self.assertTrue(runtime.endpoint().exists(), 'restoration deleted the live external endpoint')
                    raise
                self.assertFalse(sentinel.exists())
                self.assertEqual(path('/var/ossec/etc/ossec.conf').read_text(), 'original data')
                self.assertEqual({str(name): runtime.node(name) for name in runtime.anchors()}, anchors)
                internal = path('/var/ossec/etc/af_wazuh.conf'); external = path('/etc/audit/plugins.d/af_wazuh.conf')
                self.assertEqual((internal.stat().st_dev, internal.stat().st_ino), (external.stat().st_dev, external.stat().st_ino))
                self.assertEqual(internal.stat().st_nlink, 2)
                agent.finish_recovery(owner)
                self.assertFalse(agent.path.exists())
                self.assertIn('4.14.9-1', runtime.readiness); self.assertIn('4.14.1-1', runtime.readiness)

    def test_changed_boot_listener_anchor_or_security_refuses_before_stop_or_restore(self):
        import os
        for phase in ('staged', 'installing'):
            for fault in ('boot', 'listener-start', 'endpoint-inode', 'anchor-security', 'kernel'):
                with self.subTest(phase=phase, fault=fault), self.fixture() as (agent, native, path, root, runtime):
                    owner = 'd' * 32
                    agent.reserve(owner, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                    if phase == 'installing': agent.cold_backup(owner); agent.authorize_install(owner)
                    if fault == 'boot': runtime.boot_id = 'different-boot'
                    if fault == 'listener-start': runtime.listener_start = 'reused-pid-new-process'
                    if fault == 'endpoint-inode':
                        endpoint = runtime.endpoint(); endpoint.rename(endpoint.with_name('old-socket')); endpoint.write_text('replacement endpoint')
                    if fault == 'anchor-security': os.chmod(runtime.endpoint().parent, 0o700)
                    if fault == 'kernel': runtime.kernel_setting = '2'
                    stops = sum(call[:2] == ['systemctl', 'stop'] for call in native.calls)
                    with self.assertRaisesRegex(w.Refused, 'endpoint/process/security/boot proof changed'):
                        (agent.cold_backup if phase == 'staged' else agent.prepare_recovery)(owner)
                    self.assertEqual(agent.active()['phase'], phase)
                    self.assertEqual(sum(call[:2] == ['systemctl', 'stop'] for call in native.calls), stops)
                    self.assertEqual(path('/var/ossec/etc/ossec.conf').read_text(), 'original data')

    def test_sealed_archive_cannot_replace_live_socket_or_redirect_ancestor(self):
        import io,tarfile
        for member_name,kind in (('ossec/queue/sockets/audit', 'file'), ('ossec/queue', 'symlink')):
            with self.subTest(member=member_name), self.fixture() as (agent, native, path, root, runtime):
                owner = 'd' * 32
                agent.reserve(owner, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                agent.cold_backup(owner); agent.authorize_install(owner)
                item = agent.active(); entry = next(entry for entry in item['archives'] if entry['path'] == '/var/ossec')
                # Model an invalid archive producer with matching recorded digest;
                # the semantic scope guard must still refuse before any restore.
                with tarfile.open(entry['archive'], 'r:') as archive:
                    saved = [(member, archive.extractfile(member).read() if member.isfile() else None) for member in archive]
                with tarfile.open(entry['archive'], 'w:') as archive:
                    for member, content in saved:
                        if kind == 'symlink' and member.name.rstrip('/') == member_name:
                            member.type = tarfile.SYMTYPE; member.linkname = '/outside'; member.size = 0; content = None
                        archive.addfile(member, io.BytesIO(content) if content is not None else None)
                    if kind == 'file':
                        member = tarfile.TarInfo(member_name); member.size = 3
                        archive.addfile(member, io.BytesIO(b'bad'))
                entry['sha256'] = w.digest(entry['archive']); agent.write(item, 'installing')
                before = runtime.node(runtime.endpoint())
                with self.assertRaisesRegex(w.Refused, 'sealed archive'):
                    agent.prepare_recovery(owner)
                self.assertEqual(agent.active()['phase'], 'installing')
                self.assertEqual(runtime.node(runtime.endpoint()), before)
                self.assertEqual(path('/var/ossec/etc/ossec.conf').read_text(), 'original data')


class PolicyHookRecoveryTests(unittest.TestCase):
    def test_original_policy_or_absence_is_durably_replayed_independent_of_broken_audit(self):
        import os
        from unittest.mock import patch
        for present in (False, True):
            with self.subTest(present=present), PreservedAuditRuntimeTests().fixture() as (agent, native, path, root, runtime):
                filename = path(agent.POLICY_HOOK)
                if present:
                    filename.write_text('#!/bin/sh\n# original operator policy\nexit 0\n'); filename.chmod(0o750)
                    os.setxattr(filename, 'user.issue244', b'original policy metadata')
                    original = w.ClosedCapture.take({str(filename): 'file'}, agent.root, sealed=True)
                owner = 'd' * 32
                agent.reserve(owner, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True)); agent.cold_backup(owner); agent.authorize_install(owner)
                agent.hook_prepare(owner)
                self.assertEqual(filename.read_text(), agent.POLICY_TEMP)
                with self.assertRaisesRegex(w.Refused, 'confirmation previous installer jobs stopped'):
                    agent.hook_cleanup(owner)
                with self.assertRaises(w.Refused): agent.hook_cleanup('e' * 32, True)
                runtime.boot_id = 'unsupported new boot'
                with self.assertRaisesRegex(w.Refused, 'endpoint/process/security/boot proof changed'):
                    agent.prepare_recovery(owner)
                synced, original_sync = [], w.sync_directory
                def sync(value): synced.append(str(value)); original_sync(value)
                with patch.object(w, 'sync_directory', side_effect=sync):
                    try:
                        agent.hook_cleanup(owner, True)
                    except w.Refused:
                        self.fail('known owned global hook cleanup was stranded behind a failed component proof')
                    agent.hook_cleanup(owner, True)  # exact replay, including durable absence
                self.assertIn(str(filename.parent), synced)
                if not present:
                    self.assertGreaterEqual(synced.count(str(filename.parent)), 2, 'absence replay must sync parent even when already absent')
                if present: w.ClosedCapture.verify(original, agent.root)
                else: self.assertFalse(filename.exists())
                self.assertEqual(agent.active()['phase'], 'installing')
                agent.hook_verify(agent.active())
                with self.assertRaisesRegex(w.Refused, 'endpoint/process/security/boot proof changed'):
                    agent.prepare_recovery(owner)
                with self.assertRaisesRegex(w.Refused, 'unfinished component journal'):
                    w.HostWriter(agent.root).release(owner)

    def test_partial_temporary_creation_and_unknown_foreign_hook_drift(self):
        for fault in ('prepared-600', 'moved-away', 'foreign'):
            with self.subTest(fault=fault), RestoreScopeTests().agent() as (agent, native, path, root):
                hook = path(agent.POLICY_HOOK); hook.write_text('original hook'); hook.chmod(0o755)
                owner = 'd' * 32
                agent.reserve(owner, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True)); agent.cold_backup(owner); agent.authorize_install(owner)
                agent.hook_prepare(owner)
                if fault == 'prepared-600': hook.chmod(0o600)
                if fault == 'moved-away': hook.unlink()
                if fault == 'foreign': hook.write_text('unknown foreign hook change')
                if fault == 'foreign':
                    with self.assertRaisesRegex(w.Refused, 'unknown foreign policy hook drift'):
                        agent.hook_cleanup(owner, True)
                    self.assertEqual(hook.read_text(), 'unknown foreign hook change')
                else:
                    agent.hook_cleanup(owner, True)
                    self.assertEqual(hook.read_text(), 'original hook')
                self.assertEqual(agent.active()['phase'], 'installing')

    def test_policy_hook_scope_and_aliases_refuse_before_reservation(self):
        import os,shutil
        for fault in ('symlink', 'hardlink', 'ancestor', 'bind-mount'):
            with self.subTest(fault=fault), RestoreScopeTests().agent() as (agent, native, path, root):
                hook = path(agent.POLICY_HOOK); hook.write_text('old hook'); hook.chmod(0o755)
                if fault == 'symlink': hook.rename(root / 'outside'); hook.symlink_to(root / 'outside')
                if fault == 'hardlink': os.link(hook, root / 'outside')
                if fault == 'ancestor':
                    parent = hook.parent; shutil.move(parent, root / 'outside'); parent.symlink_to(root / 'outside', target_is_directory=True)
                if fault == 'bind-mount': MOUNT_NAMESPACE['text'] += f'2 1 8:1 {hook} {hook} rw - ext4 /dev/synthetic rw\n'
                with self.assertRaisesRegex(w.Refused, 'symlink|single-link|unsupported mount'):
                    agent.reserve('d' * 32, w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True))
                self.assertIsNone(agent.active())
                self.assertFalse(any(call[:2] == ['systemctl', 'stop'] for call in native.calls))


class OrdinaryConfigAuthorityTests(unittest.TestCase):
    def test_restore_only_actual_changed_selected_files_with_complete_metadata(self):
        import os
        with RestoreScopeTests().agent() as (agent, native, path, root):
            config, hosts = path('/var/ossec/etc/ossec.conf'), path('/etc/hosts')
            config.chmod(0o640); os.setxattr(config, 'user.issue244', b'prior metadata')
            old = w.ClosedCapture.take({str(config): 'file'}, agent.root, sealed=True)
            snapshot = w.ConfigSnapshots('d' * 32, 'a' * 32, runner=native, root=agent.root)
            snapshot.save('config', '/var/ossec/etc/ossec.conf'); snapshot.save('hosts', '/etc/hosts')
            config.write_text('partial failure changed config'); config.chmod(0o600)
            hosts.write_text('unselected preexisting hosts sentinel')
            result = snapshot.restore(['config'])
            self.assertEqual(result, {'restored': ['config'], 'services': []})
            w.ClosedCapture.verify(old, agent.root)
            self.assertEqual(hosts.read_text(), 'unselected preexisting hosts sentinel')
            self.assertEqual(snapshot.restore(['config']), {'restored': [], 'services': []})
            other = w.ConfigSnapshots('d' * 32, 'b' * 32, runner=native, root=agent.root)
            with self.assertRaisesRegex(w.Refused, 'no snapshot for selected resource'): other.restore(['config'])
            self.assertEqual(other.restore([]), {'restored': [], 'services': []})
            self.assertFalse(any(call[:2] == ['systemctl', 'restart'] for call in native.calls))

    def test_selected_service_restores_active_enabled_without_unselected_audit_restart(self):
        with RestoreScopeTests().agent() as (agent, native, path, root):
            class Services:
                def __init__(self):
                    self.units = {'wazuh-agent': {'active': False, 'enabled': 'disabled'}, 'auditd': {'active': True, 'enabled': 'enabled'}}
                    self.calls = []
                    self.refuse_stop = False
                def run(self, argv, **kwargs):
                    if argv[0] != 'systemctl': return native.run(argv, **kwargs)
                    operation, unit = argv[1:3]; state = self.units[unit]; self.calls.append((operation, unit))
                    if operation == 'is-active': return subprocess.CompletedProcess(argv, 0 if state['active'] else 3, '', '')
                    if operation == 'is-enabled': return subprocess.CompletedProcess(argv, 0, state['enabled'], '')
                    if operation == 'show': return subprocess.CompletedProcess(argv, 0, 'yes' if self.refuse_stop else 'no', '')
                    if operation in ('start', 'stop'): state['active'] = operation == 'start'
                    if operation in ('enable', 'disable'): state['enabled'] = 'enabled' if operation == 'enable' else 'disabled'
                    return subprocess.CompletedProcess(argv, 0, '', '')
            services = Services()
            snapshot = w.ConfigSnapshots('d' * 32, 'a' * 32, runner=services, root=agent.root)
            snapshot.save('agent-service')
            services.units['wazuh-agent'] = {'active': True, 'enabled': 'enabled'}
            snapshot.restore(['agent-service'])
            self.assertEqual(services.units['wazuh-agent'], {'active': False, 'enabled': 'disabled'})
            self.assertFalse(any(unit == 'auditd' for operation, unit in services.calls))
            services.refuse_stop = True
            another = w.ConfigSnapshots('d' * 32, 'b' * 32, runner=services, root=agent.root)
            with self.assertRaisesRegex(w.Refused, 'cannot be safely restored after start'):
                another.save('agent-service')

    def test_snapshot_rejects_unbounded_file_alias_before_any_mutation_authority(self):
        import os
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind), RestoreScopeTests().agent() as (agent, native, path, root):
                config = path('/var/ossec/etc/ossec.conf'); outside = root / 'outside'
                if kind == 'hardlink': os.link(config, outside)
                else: config.rename(outside); config.symlink_to(outside)
                snapshot = w.ConfigSnapshots('d' * 32, 'a' * 32, runner=native, root=agent.root)
                with self.assertRaisesRegex(w.Refused, 'symlink|single-link'): snapshot.save('config', '/var/ossec/etc/ossec.conf')
                self.assertEqual(outside.read_text(), 'original data')
                with self.assertRaisesRegex(w.Refused, 'outside its bounded resource'):
                    snapshot.save('config', '/operator/other-file')


class AgentRecoveryDispatchTests(unittest.TestCase):
    def test_all_durable_phases_have_bounded_recovery_authority(self):
        for phase, action in w.AGENT_RECOVERY.items():
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                calls = []; self_test = self
                class Native(Commands):
                    def run(self, argv, **kwargs):
                        calls.append(str(argv[0]) + ':' + str(argv[1]))
                        if argv[0] == 'systemctl' and argv[1] == 'stop':
                            return subprocess.CompletedProcess(argv, 0, '', '')
                        return super().run(argv, **kwargs)
                class Agent(w.Agent):
                    def guard(self): return PackagePolicyHarness(self.r)
                    def authorize_rpm(self, owner, recovery=False): return {}
                    def audit_check(self, *args, **kwargs): return None
                    def validate_agent_layout(self, item, recovery=False):
                        calls.append('validate-layout')
                    def restore_service(self, item):
                        calls.append('restore-service')
                    def verify_old_state(self, item):
                        calls.append('verify-old-state')
                    def validate_agent_archives(self, item):
                        calls.append('validate-all-archives')
                    def capture_sources(self, sealed=False, recovery=False):
                        self_test.assertTrue(sealed and recovery)
                        calls.append('strict-cold-sources')
                        return {'sealed': True}
                    def restore_absence(self, item):
                        calls.append('restore-absence')
                    def verify_pin(self, item, target=False):
                        calls.append('verify-target-pin' if target else 'verify-old-pin')
                agent = Agent('RedHat', runner=Native(), root=root / 'backups')
                (agent.root / 'rpm-stage').mkdir(parents=True)
                package = root / 'old.rpm'
                package.write_bytes(b'synthetic package; native signature is a separate test')
                w.HostWriter(agent.root).claim('f' * 32, 'agent')
                with agent.lock():
                    item = agent.begin('f' * 32, {'installed': '4.14.1-1', 'manager_host': 'synthetic-manager',
                                                'packages': {'4.14.1-1': {'path': str(package), 'sha256': w.digest(package)}}})
                    agent.write(item, phase)
                result = agent.prepare_recovery('f' * 32)
                self.assertEqual(calls.pop(0), 'validate-layout')
                if action == 'resume-old':
                    self.assertEqual(calls, ['restore-service', 'verify-old-state'])
                    self.assertFalse(agent.path.exists())
                    self.assertFalse(result['need_commit'])
                elif action == 'restore-old':
                    self.assertEqual(calls[0], 'validate-all-archives')
                    self.assertIn('systemctl:stop', calls)
                    self.assertGreater(calls.index('strict-cold-sources'), calls.index('systemctl:stop'))
                    self.assertTrue(result['reinstall'])
                    self.assertEqual(agent.active()['phase'], 'recovering')
                else:
                    self.assertEqual(calls, ['verify-target-pin'] if action == 'verify-target'
                                     else ['restore-absence', 'verify-old-pin'])
                    self.assertTrue(result['need_commit'])
                    self.assertEqual(agent.active()['phase'], phase)


class OfficialRpmSignatureTests(RpmFixture, unittest.TestCase):
    """A's signature-line contract, kept on A's RpmFixture model (the shapes rpmkeys can print)."""

    def test_only_a_verified_signature_line_authorizes_the_rpm_whatever_the_return_code(self):
        # Accept case first: the signed shape passes and rpmkeys ran against the private key ring.
        with self.fixture() as (_, native, guard):
            ring = guard.official_rpm_keyring(self.OWNER)
            artifact = Path(ring['database']).parent / 'official.rpm'; artifact.write_bytes(b'official:4.14.1-1')
            provider = {'sha256': w.digest(artifact)}
            native.rpmkeys = 'signed'; native.calls.clear()
            guard.verify_official_rpm(artifact, provider, ring, self.OWNER)
            call = next(c for c in native.calls if c[0] == 'rpmkeys')
            self.assertEqual((call[1], call[3], call[-1]), ('--dbpath', '-Kv', str(artifact)))
            # Trigger cases for the coordinator's OWN line-level assertion: no verified signature line, rc 0.
            # 'digest-only' is the captured unsigned package; the other rc0 shapes force the return code.
            for shape in ('digest-only', 'nokey-rc0', 'empty'):
                with self.subTest(shape=shape):
                    native.rpmkeys = shape
                    with self.assertRaisesRegex(w.Refused, 'not signed by the authenticated official Wazuh key'):
                        guard.verify_official_rpm(artifact, provider, ring, self.OWNER)
            # rpm's own non-zero status is refused first, with the rc named (captured: NOKEY, tampered, truncated).
            for shape in ('nokey', 'tampered', 'truncated'):
                with self.subTest(shape=shape):
                    native.rpmkeys = shape
                    with self.assertRaisesRegex(w.Refused, 'RPM signature against only official Wazuh key rc=1'):
                        guard.verify_official_rpm(artifact, provider, ring, self.OWNER)

    def test_a_tampered_rpm_is_stopped_by_rpms_status_because_its_signature_line_still_says_ok(self):
        # Native capture: flipping one payload byte leaves `Header V3 RSA/SHA256 Signature ...: OK` as the
        # FIRST line (the payload digest and the *payload* signature lines are the BAD ones), so the
        # coordinator's line assertion is satisfied by a tampered package and only rc=1 refuses it.
        tampered = capture('rpmkeys-Kv.tampered.rc1.txt')
        self.assertTrue(re.search(r'Signature.*: OK', tampered), 'the capture must keep the property this test pins')
        self.assertIn('Payload SHA256 digest: BAD', tampered)
        with self.fixture() as (_, native, guard):
            ring = guard.official_rpm_keyring(self.OWNER)
            artifact = Path(ring['database']).parent / 'official.rpm'; artifact.write_bytes(b'official:4.14.1-1')
            provider = {'sha256': w.digest(artifact)}
            native.rpmkeys = 'tampered'
            with self.assertRaisesRegex(w.Refused, 'RPM signature against only official Wazuh key rc=1'):
                guard.verify_official_rpm(artifact, provider, ring, self.OWNER)
            # With the status forced to 0 the line assertion is satisfied: the status IS the control.
            native.rpmkeys = 'tampered-rc0'
            guard.verify_official_rpm(artifact, provider, ring, self.OWNER)

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
        # B's ownership contract: the stage runs under the exact host-wide writer owner.
        w.HostWriter(root).claim(self.OWNER, 'agent', 'apply')
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
            'a payload signed by another key': (lambda native: setattr(native, 'payload', b'foreign:' + self.PACKAGE.encode()), 'RPM signature against only official Wazuh key rc=1'),
            'an unsigned payload whose digests verify': (lambda native: setattr(native, 'rpmkeys', 'digest-only'),
                                                         'not signed by the authenticated official Wazuh key'),
            'an RPM that is another package version': (lambda native: setattr(native, 'identity', '4.14.9-1'), 'package identity mismatch'),
            'a competing-provider source': (None, 'not bound to the declared official Wazuh source'),
        }
        for name, (break_it, reason) in cases.items():
            with self.subTest(name), self.fixture() as (root, native, _):
                agent, guard = self.agent(root, native, official=break_it is not None)
                if break_it:
                    break_it(native)
                with self.assertRaisesRegex(w.Refused, reason):
                    agent.fresh_rpm(self.OWNER, self.plan())
                self.assertFalse(any(call[0] == 'dnf' and '--downloadonly' not in call for call in native.calls))
                self.assertEqual(self.leftovers(root), [], 'a refused stage must leave no private directory behind')

    @staticmethod
    def leftovers(root):
        return sorted(path.name for path in root.iterdir() if path.name.startswith(('agent-policy-', 'rpm-fresh-')))

    def test_a_failed_stage_removes_only_what_it_created_and_a_successful_one_keeps_it_for_the_install(self):
        with self.fixture() as (root, native, _):
            agent, guard = self.agent(root, native)
            staged = agent.fresh_rpm(self.OWNER, self.plan())
            self.assertEqual(self.leftovers(root), ['agent-policy-' + self.OWNER, 'rpm-fresh-' + self.OWNER],
                             'the playbook installs the staged RPM from these right after the stage')
            self.assertTrue(Path(staged['package_path']).is_file())
        # Failures at every depth: the key download, the provider check and an unexpected exception type.
        def fails(native, guard):
            native.failure = 'curl'
        def breaks_provider(native, guard):
            guard.official_rpm_provider = mock.Mock(side_effect=KeyError('provider'))
        for name, setup, error in (('key download', fails, w.Refused), ('unexpected exception', breaks_provider, KeyError)):
            with self.subTest(name), self.fixture() as (root, native, _):
                agent, guard = self.agent(root, native)
                setup(native, guard)
                with self.assertRaises(error):
                    agent.fresh_rpm(self.OWNER, self.plan())
                self.assertEqual(self.leftovers(root), [])
                self.assertTrue((root / 'agent.lock').exists(), 'only the lock file remains')
        # A directory that already existed (the same token reused) is never removed.
        with self.fixture() as (root, native, _):
            agent, guard = self.agent(root, native)
            folder = w.private_dir(root / ('rpm-fresh-' + self.OWNER))
            (folder / 'earlier-evidence.txt').write_text('kept')
            native.failure = 'curl'
            with self.assertRaises(w.Refused):
                agent.fresh_rpm(self.OWNER, self.plan())
            self.assertEqual(self.leftovers(root), ['rpm-fresh-' + self.OWNER])
            self.assertEqual((folder / 'earlier-evidence.txt').read_text(), 'kept')

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

    def test_the_fresh_stage_is_exclusive_per_component(self):
        with self.fixture() as (root, native, _):
            agent, _ = self.agent(root, native)
            locks = []
            real = w.bounded_flock

            @contextlib.contextmanager
            def recording(filename, **kwargs):
                locks.append(Path(filename).name)
                with real(filename, **kwargs):
                    yield
            components = []
            real_component = agent.component_lock

            @contextlib.contextmanager
            def component(shared=False):
                components.append(('agent.lock', shared))
                with real_component(shared=shared):
                    yield
            agent.component_lock = component
            with mock.patch.object(w, 'bounded_flock', recording):
                agent.fresh_rpm(self.OWNER, self.plan())
            # B's contract: the shared host-writer mutex checks the owner, and the stage then holds the
            # component lock EXCLUSIVELY (the lock A recorded as bounded_flock('agent.lock')).
            self.assertEqual(locks, ['coordinator.lock'])
            self.assertEqual(components, [('agent.lock', False)])

    def test_a_stale_or_aliased_artifact_in_the_stage_directory_is_refused(self):
        with self.fixture() as (root, native, _):
            agent, _ = self.agent(root, native)
            folder = w.private_dir(root / ('rpm-fresh-' + self.OWNER))
            outside = root / 'outside.rpm'; outside.write_bytes(b'x')
            (folder / 'alias.rpm').symlink_to(outside)
            with self.assertRaises(w.Refused):
                agent.fresh_rpm(self.OWNER, self.plan())
            self.assertFalse(any(call[0] == 'dnf' for call in native.calls))


class InstalledCoordinatorTests(unittest.TestCase):
    """The coordinator is installed 0700 as /usr/local/sbin/pilot-wazuh-transaction and run directly by the
    pin task, the fresh-RPM stage and the C10/C12 rows: the file itself must be executable, not just importable."""
    SOURCE = REPO / 'playbooks/apply/files/wazuh-transaction.py'

    def install(self, directory, text=None):
        path = Path(directory) / 'pilot-wazuh-transaction'
        path.write_text(self.SOURCE.read_text() if text is None else text)
        path.chmod(0o700)
        return path

    def test_the_first_line_is_a_portable_python3_shebang(self):
        self.assertEqual(self.SOURCE.read_text().split('\n', 1)[0], '#!/usr/bin/env python3')

    def test_the_installed_file_executes_directly_as_the_playbook_runs_it(self):
        with tempfile.TemporaryDirectory(prefix='pilot-wazuh-installed-') as directory:
            path = self.install(directory)
            try:
                help_run = subprocess.run([str(path), '--help'], capture_output=True, text=True, timeout=60)
                bogus = subprocess.run([str(path), 'agent-upgrade'], capture_output=True, text=True, timeout=60)
            except OSError as exc:
                self.fail('the installed coordinator cannot be executed directly (%s); is %s mounted noexec?' % (exc, directory))
            self.assertEqual(help_run.returncode, 0, help_run.stderr)
            self.assertIn('agent-verify', help_run.stdout)
            # Python's own argument parser rejected the action: the program ran (an exec failure never gets here).
            self.assertEqual(bogus.returncode, 2)
            self.assertIn('invalid choice', bogus.stderr)

    def test_negative_control_a_copy_without_the_shebang_cannot_be_executed(self):
        # This is the defect found on the native run: line 1 was a docstring, and executing the installed
        # file failed with `[Errno 8] Exec format error`. The same harness must see it.
        with tempfile.TemporaryDirectory(prefix='pilot-wazuh-installed-') as directory:
            path = self.install(directory, self.SOURCE.read_text().split('\n', 1)[1])
            with self.assertRaises(OSError) as failure:
                subprocess.run([str(path), '--help'], capture_output=True, text=True, timeout=60)
            self.assertEqual(failure.exception.errno, errno.ENOEXEC)


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
            owner = 'd' * 32
            w.HostWriter(agent.root).claim(owner, 'agent')
            with mock.patch.object(w, 'bounded_flock', recording):
                with self.assertRaisesRegex(w.Refused, 'absent'):
                    agent.protect_package(owner)
            # B's contract: the shared host-writer mutex, then the component lock file (never skipped).
            self.assertEqual(locks, ['coordinator.lock'])
            self.assertTrue((agent.root / 'agent.lock').is_file())
            self.assertEqual(oct((Path(temporary) / 'private').stat().st_mode & 0o777), '0o700')

    @wazuh_hermetic.absent('/var/ossec/etc/client.keys')
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
            self.assertEqual(agent.verify(), {'pass': True, 'version': '4.14.1', 'active': True, 'guard': 'apt-hold'})
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
            self.assertFalse((Path(temporary) / 'private').exists())

    def test_policy_ownership_runs_only_under_the_exact_writer_owner(self):
        # B's contract: the foreign-policy admission is an owned step (it is not a read).
        with tempfile.TemporaryDirectory() as temporary:
            agent = self.agent(Commands('RedHat', '4.14.1-1'), Path(temporary))
            agent.guard = lambda: mock.Mock(ownership=lambda: {'plugin': {'present': False}})
            with self.assertRaisesRegex(w.Refused, 'exact host-wide Wazuh writer owner'):
                agent.policy_ownership('f' * 32)
            w.HostWriter(agent.root).claim('f' * 32, 'agent')
            self.assertEqual(agent.policy_ownership('f' * 32), {'checked': True, 'prerequisite_plugin_present': False})

    def test_the_cli_privilege_check_follows_the_effective_uid(self):
        with mock.patch.object(w.os, 'geteuid', return_value=1000):
            self.assertFalse(w.is_root())
        with mock.patch.object(w.os, 'geteuid', return_value=0):
            self.assertTrue(w.is_root())

    def test_a_second_concurrent_mutator_is_refused_instead_of_interleaving(self):
        with tempfile.TemporaryDirectory() as temporary:
            agent = self.agent(Commands('Debian', '4.14.1-1'), Path(temporary))
            with agent.lock():
                with self.assertRaisesRegex(w.Refused, 'timed out'):
                    with w.bounded_flock(agent.root / 'agent.lock', timeout=0.1):
                        self.fail('the component lock must be exclusive')
            with agent.lock():
                pass


CENTRAL_OWNER = 'c' * 32


def central_execute(central, target, **kwargs):
    """An apply-time central action runs under the host-wide writer (B's ownership contract): claim it
    for the call, run the real Central.execute with that owner (no upgrade authorization unless the
    caller passes one) and release it, so later external reads see an idle host."""
    w.HostWriter(central.root).claim(CENTRAL_OWNER, 'central')
    try:
        return central.execute(target, owner=CENTRAL_OWNER, **kwargs)
    finally:
        w.HostWriter(central.root).release(CENTRAL_OWNER)


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
            with self.assertRaisesRegex(w.Refused, 'unknown committed manager version'):
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
            'digest of another repository': (lambda d: setattr(d, 'repo_digests', 'foreign'), 'official immutable release provenance'),
            'malformed digest or a mutable tag': (lambda d: setattr(d, 'repo_digests', 'malformed'), 'official immutable release provenance'),
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

    def test_each_of_the_three_components_must_report_the_requested_release_natively(self):
        # Legs 2 and 3 of the "three components run one release" claim: the dashboard's Wazuh plugin
        # (package.json) and the indexer (VERSION.json) are read separately from the manager.
        legs = (('dashboard_release', 'dashboard Wazuh plugin version probe failed'),
                ('indexer_release', 'indexer effective Wazuh version probe failed'))
        for knob, reason in legs:
            for reported in ('4.14.9', '4.14.0', ''):
                with self.subTest(component=knob, reported=reported):
                    central, docker = self.central('4.14.1')
                    setattr(docker, knob, reported)
                    # Every path that claims the release: discovery, the ordinary-apply gate and C12.
                    for action in (central.discover, lambda: central_execute(central, '4.14.1'), central.verify):
                        with self.assertRaisesRegex(w.Refused, reason):
                            action()
                    self.assertFalse(any(call[1] in ('compose', 'pull', 'stop', 'rm', 'up') for call in docker.calls if call[0] == 'docker'))
        # The dashboard's ROOT package.json carries the OpenSearch Dashboards release at the top level and the
        # Wazuh release one level down (native capture): reading it must not satisfy the plugin leg.
        central, docker = self.central('4.14.1')
        docker.dashboard_shape = 'opensearch-root'
        for action in (central.discover, lambda: central_execute(central, '4.14.1'), central.verify):
            with self.assertRaisesRegex(w.Refused, 'dashboard Wazuh plugin version probe failed'):
                action()
        # Accept case: both agree with the manager (also when stated explicitly, so the knob itself is inert).
        central, docker = self.central('4.14.1')
        docker.dashboard_release = docker.indexer_release = '4.14.1'
        self.assertEqual(central_execute(central, '4.14.1')['version'], '4.14.1')
        self.assertEqual(central.verify(), {'pass': True, 'version': '4.14.1'})
        # A disagreeing manager is still the first leg and is reported as such.
        central, docker = self.central('4.14.1')
        docker.release = '4.14.9'; docker.dashboard_release = docker.indexer_release = '4.14.1'
        with self.assertRaisesRegex(w.Refused, 'manager effective version probe failed'):
            central.verify()

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

    def test_execute_is_a_noop_on_an_absent_stack_so_a_fresh_install_pins_the_requested_release(self):
        central, docker = self.central()
        docker.drop = set(w.SERVICES)
        self.assertEqual(central_execute(central, '4.14.6'), {'changed': False, 'fresh': True, 'version': '4.14.6'})

    def test_execute_accepts_an_existing_stack_at_exactly_the_requested_release(self):
        central, docker = self.central('4.14.1')
        result = central_execute(central, '4.14.1')
        self.assertEqual(result, {'changed': False, 'fresh': False, 'version': '4.14.1', 'directory': str(docker.project)})

    def test_execute_refuses_an_unauthorized_release_change_before_looking_at_anything_that_could_mutate(self):
        # Without wazuh_upgrade authorization only an exact match passes. An unauthorized 4.14.1 -> 4.14.9
        # (and any other pair) is refused by the upgrade rule; a request below the running release is
        # refused earlier, because the registered agents (running at the manager release) would be newer.
        reasons = {('4.14.1', '4.14.9'): 'only explicit central 4.14.1 -> 4.14.9 upgrade is supported',
                   ('4.14.9', '4.14.1'): 'registered agent is newer than the central release',
                   ('4.14.6', '4.14.9'): 'only explicit central 4.14.1 -> 4.14.9 upgrade is supported',
                   ('4.14.9', '4.14.6'): 'registered agent is newer than the central release'}
        for (running, requested), reason in reasons.items():
            with self.subTest(running=running, requested=requested):
                central, docker = self.central(running)
                with self.assertRaisesRegex(w.Refused, reason):
                    central_execute(central, requested)
                self.assertFalse(any(call[1] in ('compose', 'pull', 'stop', 'rm', 'run', 'up', 'restart', 'image') and call[:3] != ['docker', 'image', 'inspect']
                                     for call in docker.calls if call[0] == 'docker'), docker.calls)

    def test_execute_refuses_an_invalid_or_unsupported_target(self):
        central, _ = self.central()
        for target in ('', '5.0.0', '4.14', 'latest', '4.14.1-1'):
            with self.assertRaises(w.Refused, msg=target):
                central_execute(central, target)

    def test_execute_refuses_a_registered_agent_newer_than_the_running_manager(self):
        central, docker = self.central('4.14.1', agents={'001': '4.14.1', '002': '4.14.9'})
        with self.assertRaisesRegex(w.Refused, 'registered agent is newer than the central release'):
            central_execute(central, '4.14.1')
        docker.agents['002'] = '4.14.1'
        central_execute(central, '4.14.1')

    def test_execute_refuses_when_the_active_compose_directory_is_not_the_requested_releases(self):
        central, docker = self.central('4.14.1')
        other = docker.managed / 'wazuh-docker-4.14.9' / 'single-node'
        other.mkdir(parents=True); (other / 'docker-compose.yml').write_text('services: {}\n')
        docker.project, docker.compose = other, other / 'docker-compose.yml'
        with self.assertRaisesRegex(w.Refused, 'does not match the requested release'):
            central_execute(central, '4.14.1')

    def test_registry_bounds_every_retained_agent_and_unknown_versions_are_refused(self):
        central, docker = self.central('4.14.1', agents={'001': '4.14.1', '002': '4.14.6'})
        self.assertEqual(central.check_agents('4.14.6'), {'001': '4.14.1', '002': '4.14.6'})
        with self.assertRaisesRegex(w.Refused, r'newer than the central release \(agent ID 002\)'):
            central.check_agents('4.14.1')
        docker.agents = {}
        self.assertEqual(central.check_agents('4.14.1'), {}, 'a registry with only the manager is valid')
        original = docker.run
        docker.run = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, 'garbage', '') if '-l' in argv else original(argv, **kwargs)
        with self.assertRaisesRegex(w.Refused, 'unknown or ambiguous manager agent registry'):
            central.check_agents('4.14.9')

    def test_captured_agent_states_connected_older_and_disconnected_are_accepted_never_connected_blocks(self):
        # Native captures (agent_control -l/-i): an Active agent on an older release and a Disconnected
        # one still report their release and are fine; a registered agent that never connected reports
        # `Client version: (null)` with rc 0 and blocks (fail closed, decision A4) until it is removed.
        central, docker = self.central('4.14.9', agents={'001': '4.14.1', '002': {'status': 'Disconnected', 'release': '4.14.9'}})
        listing = docker.agent_list()
        self.assertIn('Active', listing); self.assertIn('Disconnected', listing)
        self.assertEqual(central.check_agents('4.14.9'), {'001': '4.14.1', '002': '4.14.9'})
        self.assertEqual(central.verify(), {'pass': True, 'version': '4.14.9'})
        docker.agents['003'] = {'status': 'Never connected'}
        self.assertIn('Never connected', docker.agent_list())
        self.assertIn('Client version:      (null)', docker.agent_info('003'))
        for action in (lambda: central.check_agents('4.14.9'), central.verify, lambda: central_execute(central, '4.14.9')):
            with self.assertRaises(w.Refused) as refusal:
                action()
            self.assertEqual(str(refusal.exception), 'unknown retained agent version in manager registry (agent ID 003)')
        # The refusal names the offending agent by its numeric id only: never its name, address or any text.
        value = w.typed_error('refused', str(refusal.exception))
        for leaked in ('ghost-never', '10.9.9.9', 'agent-003'):
            self.assertNotIn(leaked, json.dumps(value))
        # Removing the agent (manage_agents -r) restores the ordinary path.
        del docker.agents['003']
        self.assertEqual(central.verify(), {'pass': True, 'version': '4.14.9'})

    def test_a_pre_4_14_agent_or_an_unparsable_registry_entry_blocks_and_is_named(self):
        for release in ('4.8.0', '3.13.6'):
            central, docker = self.central('4.14.1', agents={'001': '4.14.1', '017': release})
            with self.assertRaisesRegex(w.Refused, r'unknown retained agent version in manager registry \(agent ID 017\)'):
                central.verify()
        # An id with many digits is bounded in the message.
        central, docker = self.central('4.14.1', agents={'1234567890123': {'status': 'Never connected'}})
        with self.assertRaises(w.Refused) as refusal:
            central.verify()
        self.assertEqual(str(refusal.exception), 'unknown retained agent version in manager registry (agent ID 123456789)')

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
            central.observe_manager(); central.verify()
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
        status, value = self.invoke('agent-check', '--family', 'Debian', '--manager', '4.14.9', '--version', '',
                                    commands=Commands('Debian', '4.14.1-1'))
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
        self.assertEqual((status, value['error']), (1, 'agent upgrade requires wazuh_upgrade=true and target 4.14.9'))
        status, value = self.invoke('central', '--version', '4.14.9', '--legacy', '4.14.1')
        self.assertEqual((status, value['error']), (1, 'wazuh_version conflicts with wazuh_docker_version'))

    def test_a_native_failure_is_typed_without_leaking_what_failed(self):
        class Broken(Commands):
            def run(self, argv, **kwargs):
                raise KeyError('SECRET_SENTINEL')
        status, value = self.invoke('agent-check', commands=Broken())
        self.assertEqual((status, value['error_kind']), (1, 'native'))
        self.assertNotIn('SECRET_SENTINEL', json.dumps(value))

    def test_central_actions_run_execute_under_the_writer_and_the_c12_oracle(self):
        with tempfile.TemporaryDirectory() as temporary:
            docker = Docker(w, Path(temporary), '4.14.1')
            root = Path(temporary) / 'p'
            with mock.patch.object(w.Central, '__init__', lambda self, **kwargs: w.Transaction.__init__(self, 'central', runner=docker, root=root) or setattr(self, 'managed_root', docker.managed)):
                def run(*action):
                    # `central` is a mutating action: it needs the exact host-wide writer owner (B's contract).
                    if action[0] != 'central':
                        return self.invoke(*action, commands=docker)
                    w.HostWriter(root).claim(CENTRAL_OWNER, 'central')
                    try:
                        return self.invoke(*action, '--owner', CENTRAL_OWNER, commands=docker)
                    finally:
                        w.HostWriter(root).release(CENTRAL_OWNER)
                self.assertEqual(run('manager-version'), (0, {'version': '4.14.1'}))
                self.assertEqual(run('central', '--version', '4.14.1')[1]['fresh'], False)
                self.assertEqual(run('central-verify'), (0, {'pass': True, 'version': '4.14.1'}))
                status, value = run('central', '--version', '4.14.9')
                self.assertEqual((status, value['error']), (1, 'only explicit central 4.14.1 -> 4.14.9 upgrade is supported'))
                # Without the writer owner the same action is refused before it looks at anything.
                status, value = self.invoke('central', '--version', '4.14.1', '--owner', CENTRAL_OWNER, commands=docker)
                self.assertEqual((status, value['error']), (1, 'operation requires the exact host-wide Wazuh writer owner'))
                # The C12 command and the apply action both refuse a dashboard or indexer on another release.
                for knob, reason in (('dashboard_release', 'dashboard Wazuh plugin version probe failed'),
                                     ('indexer_release', 'indexer effective Wazuh version probe failed')):
                    setattr(docker, knob, '4.14.9')
                    for action in (('central-verify',), ('central', '--version', '4.14.1')):
                        status, value = run(*action)
                        self.assertEqual((status, value['error'], value['error_kind']), (1, reason, 'refused'), (knob, action))
                    setattr(docker, knob, None)
                self.assertEqual(run('central-verify'), (0, {'pass': True, 'version': '4.14.1'}))
                self.assertEqual(run('central')[0], 0, 'the default release is the shipped 4.14.1')

    def test_the_cli_refuses_to_run_unprivileged_and_unknown_actions(self):
        with mock.patch.object(sys, 'argv', ['x', 'agent-check']), mock.patch.object(w, 'is_root', return_value=False):
            with self.assertRaises(SystemExit) as stop, contextlib.redirect_stderr(io.StringIO()):
                w.main()
            self.assertEqual(stop.exception.code, 2)
        # writer-claim is a real action since the host-writer ownership contract (it is exercised by CommonWriterTests).
        for action in ('agent-upgrade', 'central-recover'):
            with mock.patch.object(sys, 'argv', ['x', action]), mock.patch.object(w, 'is_root', return_value=True):
                with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                    w.main()

    def test_fresh_rpm_reads_its_plan_from_stdin_and_validates_the_owner(self):
        status, value = self.invoke('agent-rpm-fresh', '--family', 'RedHat', '--owner', '../x',
                                    stdin=json.dumps(w.agent_plan('', '4.14.1')), commands=Commands('RedHat', ''))
        self.assertEqual((status, value['error']), (1, 'invalid private RPM stage owner'))
        # Without the exact host-wide writer owner the stage is refused (B's ownership contract) ...
        status, value = self.invoke('agent-rpm-fresh', '--family', 'RedHat', '--owner', 'a' * 32,
                                    stdin='{}', commands=Commands('RedHat', ''))
        self.assertEqual((status, value['error']), (1, 'operation requires the exact host-wide Wazuh writer owner'))
        # ... and with it a malformed plan is a typed native failure, not a traceback.
        w.HostWriter().claim('a' * 32, 'agent')
        try:
            status, value = self.invoke('agent-rpm-fresh', '--family', 'RedHat', '--owner', 'a' * 32,
                                        stdin='{}', commands=Commands('RedHat', ''))
        finally:
            w.HostWriter().release('a' * 32)
        self.assertEqual((status, value['error_kind']), (1, 'native'), 'a malformed plan is a typed native failure, not a traceback')


if __name__ == '__main__':
    unittest.main(verbosity=2)
