"""Unit controls for playbooks/apply/files/wazuh-agent-hotfix.py (agent version-skew hotfix).

The native tool outputs below are real captures, not guesses (AGENTS.md section 5.6):
  * dpkg-query installed / never-known / known-but-not-installed: Ubuntu 26.04 on the
    developer host, 2026-11-13 (`dpkg-query -W -f='${Status}\\t${Version}\\t${Architecture}'`).
  * the rpm "package wazuh-agent is not installed" answer: the native capture recorded in
    wazuh-transaction.py's Agent.installed() (2026-11-03).
Every refusal case has a passing twin: a control that only ever sees the refusing input
proves nothing about the matcher.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import unittest.mock

REPO = Path(__file__).resolve().parents[3]
FILES = REPO / 'playbooks/apply/files'
spec = importlib.util.spec_from_file_location('wazuh_agent_hotfix', FILES / 'wazuh-agent-hotfix.py')
hotfix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hotfix)

PREF_OWNED = ('Package: wazuh-agent\nPin: version 4.14.9-1\nPin-Priority: 1000\n\n'
              'Package: wazuh-agent\nPin: version *\nPin-Priority: -1\n')
OWNER = 'a1' * 16
OTHER = 'b2' * 16
KEY_SECRET = 'c0ffee' * 10
CLIENT_KEYS = '003 agent-new.example.org any ' + KEY_SECRET + '\n'


class Result:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class FakeRunner:
    """Answers the native probes from a table and records every other argv in order."""
    def __init__(self, dpkg=None, rpm=None, held=(), unit=('inactive', 'disabled'), listener=False, stuck_listener=False):
        self.dpkg, self.rpm, self.held, self.unit = dpkg, rpm, list(held), list(unit)
        self.listener, self.stuck_listener = listener, stuck_listener
        self.calls = []

    def run(self, argv, allowed=(0,), timeout=120, operation=None):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        tool = argv[0]
        if tool == 'dpkg-query':
            return self.dpkg
        if tool == 'rpm':
            return self.rpm
        if tool == 'apt-mark' and argv[1] == 'showhold':
            return Result(stdout=''.join(name + '\n' for name in self.held))
        if tool == 'systemctl' and argv[1] == 'is-active':
            return Result(returncode=0 if self.unit[0] == 'active' else 3, stdout=self.unit[0] + '\n')
        if tool == 'systemctl' and argv[1] == 'is-enabled':
            return Result(returncode=0 if self.unit[1].startswith('enabled') else 1, stdout=self.unit[1] + '\n')
        if tool == 'ss' and argv[1:] == ['-xl']:
            # real `ss -xl` shape, AlmaLinux 9.8, with the endpoint a stale audisp-af_unix still listens on
            line = 'u_str LISTEN 0      1                  /var/ossec/queue/sockets/audit 41824             * 0\n'
            return Result(stdout='Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n'
                          'u_str LISTEN 0      4096               /run/systemd/private 12 * 0\n' + (line if self.listener else ''))
        if argv == [str(hotfix.AUDIT_LEGACY_RESTART)] or argv == ['systemctl', 'restart', 'auditd']:
            if not self.stuck_listener:
                self.listener = False
            return Result()
        if tool == 'systemctl' and argv[1] == 'stop':
            self.unit[0] = 'inactive'
        if tool == 'systemctl' and argv[1] == 'disable':
            self.unit[1] = 'disabled'
        if tool == 'apt-mark' and argv[1] == 'unhold':
            self.held = []
        return Result()

    def mutations(self):
        return [call for call in self.calls
                if call[0] in ('apt-get', 'dnf') or call[0].endswith('/restart') or call[:2] in (['apt-mark', 'unhold'], ['systemctl', 'stop'], ['systemctl', 'disable'], ['systemctl', 'restart'])]


def installed_deb(version='4.14.9-1', status='install ok installed'):
    return Result(stdout=status + '\t' + version + '\tamd64')


ABSENT_DEB = Result(returncode=1, stderr='dpkg-query: no packages found matching wazuh-agent\n')
KNOWN_NOT_INSTALLED_DEB = Result(stdout='unknown ok not-installed\t\t')
ABSENT_RPM = Result(returncode=1, stdout='package wazuh-agent is not installed\n')


class HotfixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pilot-agent-hotfix-')
        base = Path(self.tmp.name)
        self.saved = {name: getattr(hotfix, name) for name in ('ROOT', 'PREF', 'LOCKS', 'CLIENT_KEYS', 'AUDIT_PLUGIN', 'AUDIT_RETIRE_WAIT', 'AUDIT_LEGACY_RESTART')}
        hotfix.AUDIT_PLUGIN = base / 'af_wazuh.conf'
        hotfix.AUDIT_RETIRE_WAIT = 3
        hotfix.AUDIT_LEGACY_RESTART = base / 'legacy-restart'
        hotfix.AUDIT_LEGACY_RESTART.write_text('#!/bin/sh\n')
        self.saved_sleep = hotfix.Host.sleep
        hotfix.Host.sleep = staticmethod(lambda seconds: None)
        hotfix.ROOT = base / 'backups'
        hotfix.PREF = base / 'pilot-wazuh-agent'
        hotfix.LOCKS = base / 'versionlock.list'
        hotfix.CLIENT_KEYS = base / 'client.keys'
        # The files are owned by the test user, not root: the production uid check is root-only.
        self.uid = os.geteuid()
        self.read_policy = hotfix.Host.read_policy_file
        hotfix.Host.read_policy_file = staticmethod(self.read_policy_as_current_user)

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(hotfix, name, value)
        hotfix.Host.read_policy_file = self.read_policy
        hotfix.Host.sleep = self.saved_sleep
        self.tmp.cleanup()

    @staticmethod
    def read_policy_as_current_user(path):
        if path.is_symlink():
            raise hotfix.Refused('package policy path is a symlink')
        return path.read_text() if path.exists() else None

    def claim(self, owner=OWNER, component='agent'):
        """The writer claim wazuh-transaction.py writer-claim leaves (same file, same keys)."""
        hotfix.ROOT.mkdir(parents=True, exist_ok=True)
        (hotfix.ROOT / 'writer-active.json').write_text(json.dumps({'owner': owner, 'component': component, 'mode': 'apply'}))

    def deb(self, **kwargs):
        return hotfix.Host('Debian', FakeRunner(**kwargs))

    def rpm_host(self, **kwargs):
        return hotfix.Host('RedHat', FakeRunner(**kwargs))

    # -- the one comparison -----------------------------------------------------

    def test_only_a_strictly_newer_agent_is_skewed(self):
        for installed, manager, skewed in (
                ('4.14.9-1', '4.14.1', True), ('4.14.10-1', '4.14.9', True), ('4.15.0-1', '4.14.9', True),
                ('5.0.0-1', '4.14.9', True), ('4.14.1-1', '4.14.1', False), ('4.14.1-2', '4.14.1', False),
                ('4.14.0-1', '4.14.1', False), ('4.13.9-1', '4.14.1', False), ('4.9.2-1', '4.14.1', False)):
            with self.subTest(installed=installed, manager=manager):
                state = self.deb(dpkg=installed_deb(installed)).inspect(manager)
                self.assertIs(state['skewed'], skewed)

    def test_numeric_not_lexical_comparison(self):
        # '4.14.10' < '4.14.9' lexically; the hotfix must not remove a 4.14.9 agent from a 4.14.10 manager
        self.assertFalse(self.deb(dpkg=installed_deb('4.14.9-1')).inspect('4.14.10')['skewed'])
        self.assertTrue(self.deb(dpkg=installed_deb('4.14.10-1')).inspect('4.14.9')['skewed'])

    def test_not_installed_is_never_skewed_whatever_the_manager(self):
        for dpkg in (ABSENT_DEB, KNOWN_NOT_INSTALLED_DEB):
            with self.subTest(dpkg=dpkg.stdout or dpkg.stderr):
                state = self.deb(dpkg=dpkg).inspect('')
                self.assertEqual((state['installed'], state['skewed']), ('', False))
        self.assertEqual(self.rpm_host(rpm=ABSENT_RPM).inspect('4.14.1')['installed'], '')

    def test_an_installed_agent_without_a_manager_version_is_refused(self):
        with self.assertRaises(hotfix.Refused):
            self.deb(dpkg=installed_deb()).inspect('')

    def test_unparseable_or_unsupported_versions_are_refused(self):
        for version in ('4.14', '4.14.9~rc1-1', 'banana-1', '04.14.9-1'):
            with self.subTest(agent=version), self.assertRaises(hotfix.Refused):
                self.deb(dpkg=installed_deb(version)).inspect('4.14.1')
        for manager in ('4.13.1', '5.0.0', 'v4.14.1', '4.14'):
            with self.subTest(manager=manager), self.assertRaises(hotfix.Refused):
                self.deb(dpkg=installed_deb('4.14.9-1')).inspect(manager)

    def test_unknown_package_state_is_refused_not_guessed(self):
        for dpkg in (installed_deb(status='deinstall ok config-files'),
                     Result(stdout='install ok installed\t4.14.9-1\tarm64'),
                     Result(stdout='garbage'),
                     Result(returncode=1, stderr='dpkg-query: error: some other failure\n'),
                     Result(returncode=1, stdout='x', stderr='dpkg-query: no packages found matching wazuh-agent\n')):
            with self.subTest(dpkg=dpkg.stdout or dpkg.stderr), self.assertRaises(hotfix.Refused):
                self.deb(dpkg=dpkg).inspect('4.14.1')

    def test_a_hold_status_is_still_an_installed_agent(self):
        state = self.deb(dpkg=installed_deb(status='hold ok installed'), held=['wazuh-agent']).inspect('4.14.1')
        self.assertTrue(state['skewed'])
        self.assertTrue(state['policy']['held'])

    # -- fail closed before any change -----------------------------------------------

    def test_an_active_wazuh_writer_or_journal_refuses_the_host(self):
        for marker in hotfix.WRITER_MARKERS:
            with self.subTest(marker=marker):
                hotfix.ROOT.mkdir(parents=True, exist_ok=True)
                (hotfix.ROOT / marker).write_text('{}')
                with self.assertRaises(hotfix.Refused):
                    self.deb(dpkg=installed_deb()).inspect('4.14.1')
                (hotfix.ROOT / marker).unlink()
        # twin: with no marker the same host is judged
        self.assertTrue(self.deb(dpkg=installed_deb()).inspect('4.14.1')['skewed'])

    def test_a_mutation_runs_only_under_its_own_writer_claim(self):
        for action in ('quiesce', 'remove'):
            hotfix.CLIENT_KEYS.write_text(CLIENT_KEYS)
            with self.subTest(action=action, case='no owner named'):
                self.claim()
                host = self.deb(dpkg=installed_deb())
                with self.assertRaisesRegex(hotfix.Refused, 'requires the owner'):
                    getattr(host, action)('4.14.1', '')
                self.assertEqual(host.r.mutations(), [])
            with self.subTest(action=action, case='no writer marker at all'):
                (hotfix.ROOT / 'writer-active.json').unlink()
                host = self.deb(dpkg=installed_deb())
                with self.assertRaisesRegex(hotfix.Refused, 'does not hold the Wazuh writer claim'):
                    getattr(host, action)('4.14.1', OWNER)
                self.assertEqual(host.r.mutations(), [])
            with self.subTest(action=action, case="another writer's marker"):
                self.claim(owner=OTHER)
                host = self.deb(dpkg=installed_deb())
                with self.assertRaisesRegex(hotfix.Refused, 'writer or unfinished transaction is active'):
                    getattr(host, action)('4.14.1', OWNER)
                self.assertEqual(host.r.mutations(), [])
            with self.subTest(action=action, case='a central claim with our owner id'):
                self.claim(component='central')
                with self.assertRaisesRegex(hotfix.Refused, 'writer or unfinished transaction is active'):
                    getattr(self.deb(dpkg=installed_deb()), action)('4.14.1', OWNER)
            with self.subTest(action=action, case='an unfinished journal next to our claim'):
                self.claim()
                (hotfix.ROOT / 'agent-active.json').write_text('{}')
                with self.assertRaisesRegex(hotfix.Refused, 'agent-active.json'):
                    getattr(self.deb(dpkg=installed_deb()), action)('4.14.1', OWNER)
                (hotfix.ROOT / 'agent-active.json').unlink()
            with self.subTest(action=action, case='twin: our own claim is accepted'):
                self.claim()
                self.assertTrue(getattr(self.deb(dpkg=installed_deb()), action)('4.14.1', OWNER)['changed'] in (True, False))
        # a read-only inspection accepts no writer at all, not even a claim of ours
        with self.assertRaises(hotfix.Refused):
            self.deb(dpkg=installed_deb()).inspect('4.14.1')

    def test_foreign_preference_content_refuses(self):
        hotfix.PREF.write_text('Package: wazuh-agent\nPin: version 4.14.9-1\nPin-Priority: 990\n')
        with self.assertRaises(hotfix.Refused):
            self.deb(dpkg=installed_deb()).inspect('4.14.1')
        hotfix.PREF.write_text(PREF_OWNED)
        self.assertTrue(self.deb(dpkg=installed_deb()).inspect('4.14.1')['policy']['owned'])

    def test_versionlock_block_ownership(self):
        owned = 'wazuh-agent-0:4.14.9-1.x86_64\n'
        rpm = Result(stdout='4.14.9-1\tx86_64')
        hotfix.LOCKS.write_text('foo-0:1.0-1.x86_64\n' + hotfix.BEGIN + owned + hotfix.END)
        state = self.rpm_host(rpm=rpm).inspect('4.14.1')
        self.assertTrue(state['policy']['owned'])
        self.assertFalse(state['policy']['foreign_overlap'])
        for text in (hotfix.BEGIN + 'wazuh-agent-0:4.14.9-1.noarch\n' + hotfix.END,
                     hotfix.BEGIN + owned,                                         # END missing
                     hotfix.BEGIN + owned + hotfix.END + hotfix.BEGIN + owned + hotfix.END):
            with self.subTest(text=text), self.assertRaises(hotfix.Refused):
                hotfix.LOCKS.write_text(text)
                self.rpm_host(rpm=rpm).inspect('4.14.1')

    def test_a_foreign_rule_naming_the_agent_refuses_only_a_skewed_host(self):
        hotfix.LOCKS.write_text('wazuh-agent-0:4.14.9-1.x86_64\n')
        with self.assertRaises(hotfix.Refused):
            self.rpm_host(rpm=Result(stdout='4.14.9-1\tx86_64')).inspect('4.14.1')
        # a compatible host with the same foreign rule is none of this hotfix's business
        self.assertFalse(self.rpm_host(rpm=Result(stdout='4.14.1-1\tx86_64')).inspect('4.14.1')['skewed'])

    # -- enrollment ------------------------------------------------------------------

    def test_registration_reports_id_and_name_and_never_the_key(self):
        hotfix.CLIENT_KEYS.write_text(CLIENT_KEYS)
        state = self.deb(dpkg=installed_deb()).inspect('4.14.1')
        self.assertEqual(state['registration'], {'id': '003', 'name': 'agent-new.example.org'})
        self.assertNotIn(KEY_SECRET, json.dumps(state))

    def test_a_malformed_client_keys_refuses_a_skewed_host_only(self):
        for text in ('003 only-two-fields\n', 'xx1 name any key\n', '003 a any k\n004 b any k\n'):
            hotfix.CLIENT_KEYS.write_text(text)
            with self.subTest(text=text), self.assertRaises(hotfix.Refused):
                self.deb(dpkg=installed_deb()).inspect('4.14.1')
            # twin: the same file on a compatible host is ignored, so one odd host cannot stop the run
            state = self.deb(dpkg=installed_deb('4.14.1-1')).inspect('4.14.1')
            self.assertFalse(state['skewed'])
            self.assertIsNone(state['registration'])

    def test_no_enrollment_is_none(self):
        self.assertIsNone(self.deb(dpkg=installed_deb()).inspect('4.14.1')['registration'])
        hotfix.CLIENT_KEYS.write_text('')
        self.assertIsNone(self.deb(dpkg=installed_deb()).inspect('4.14.1')['registration'])

    # -- mutation --------------------------------------------------------------------

    def test_a_compatible_host_is_never_changed(self):
        for action in ('quiesce', 'remove'):
            with self.subTest(action=action):
                self.claim()
                host = self.deb(dpkg=installed_deb('4.14.1-1'))
                hotfix.CLIENT_KEYS.write_text(CLIENT_KEYS)
                with self.assertRaisesRegex(hotfix.Refused, 'not newer than the manager'):
                    getattr(host, action)('4.14.1', OWNER)
                self.assertEqual(host.r.mutations(), [])
                self.assertTrue(hotfix.CLIENT_KEYS.exists())

    def test_debian_removal_order_and_scope(self):
        self.claim()
        hotfix.PREF.write_text(PREF_OWNED)
        hotfix.CLIENT_KEYS.write_text(CLIENT_KEYS)
        host = self.deb(dpkg=installed_deb(status='hold ok installed'), held=['wazuh-agent'], unit=['active', 'enabled'])
        self.assertTrue(host.quiesce('4.14.1', OWNER)['changed'])
        self.assertEqual(host.r.unit, ['inactive', 'disabled'])
        self.assertTrue(hotfix.CLIENT_KEYS.exists(), 'quiesce must delete nothing')
        self.assertTrue(host.remove('4.14.1', OWNER)['changed'])
        mutations = host.r.mutations()
        # unhold first (apt refuses to remove a held package), then purge, never plain remove
        unhold = mutations.index(['apt-mark', 'unhold', 'wazuh-agent'])
        purge = next(i for i, call in enumerate(mutations) if call[:2] == ['apt-get', 'purge'])
        self.assertLess(unhold, purge)
        self.assertEqual(mutations[purge][-1], 'wazuh-agent')
        self.assertIn('DPkg::Lock::Timeout=300', mutations[purge])
        self.assertFalse(any(call[:2] == ['apt-get', 'remove'] for call in mutations))
        self.assertFalse(hotfix.PREF.exists())
        self.assertFalse(hotfix.CLIENT_KEYS.exists())

    def test_redhat_removal_keeps_foreign_versionlock_rules(self):
        self.claim()
        hotfix.LOCKS.write_text('foo-0:1.0-1.x86_64\n' + hotfix.BEGIN + 'wazuh-agent-0:4.14.9-1.x86_64\n' + hotfix.END + 'bar-0:2-1.x86_64\n')
        host = self.rpm_host(rpm=Result(stdout='4.14.9-1\tx86_64'))
        self.assertTrue(host.remove('4.14.1', OWNER)['changed'])
        self.assertEqual(hotfix.LOCKS.read_text(), 'foo-0:1.0-1.x86_64\nbar-0:2-1.x86_64\n')
        self.assertEqual(host.r.mutations(), [['dnf', 'remove', '-y', 'wazuh-agent']])

    def test_a_rerun_after_a_partial_removal_finishes_it(self):
        # package already purged, but the preference and client.keys are still there
        self.claim()
        hotfix.PREF.write_text(PREF_OWNED)
        hotfix.CLIENT_KEYS.write_text(CLIENT_KEYS)
        host = self.deb(dpkg=KNOWN_NOT_INSTALLED_DEB)
        self.assertTrue(host.remove('4.14.1', OWNER)['changed'])
        self.assertFalse(hotfix.PREF.exists())
        self.assertFalse(hotfix.CLIENT_KEYS.exists())
        self.assertFalse(any(call[0] == 'apt-get' for call in host.r.calls), 'nothing left to purge')
        # and once nothing is left, a further rerun is refused (not a silent no-op that hides a wrong target)
        with self.assertRaises(hotfix.Refused):
            self.deb(dpkg=KNOWN_NOT_INSTALLED_DEB).remove('4.14.1', OWNER)

    # -- the audit plugin the RPM removal leaves running (EL) ---------------------------

    def restarts(self, host):
        return [call for call in host.r.calls if call == [str(hotfix.AUDIT_LEGACY_RESTART)] or call == ['systemctl', 'restart', 'auditd']]

    def test_redhat_removal_restarts_auditd_through_its_legacy_action(self):
        self.claim()
        host = self.rpm_host(rpm=Result(stdout='4.14.9-1\tx86_64'), listener=True)
        self.assertTrue(host.remove('4.14.1', OWNER)['changed'])
        # EL refuses `systemctl restart auditd` (RefuseManualStop): the package's own legacy action is used
        self.assertEqual(self.restarts(host), [[str(hotfix.AUDIT_LEGACY_RESTART)]])
        self.assertFalse(host.r.listener)
        # never the lighter ways that real hosts showed leave the plugin dispatcher unrecoverable
        self.assertFalse([c for c in host.r.calls if c[:2] == ['systemctl', 'kill']])
        order = [c[0] + ' ' + c[1] if len(c) > 1 else c[0] for c in host.r.calls if c[0] == 'dnf' or c[0] == str(hotfix.AUDIT_LEGACY_RESTART)]
        self.assertEqual(order, ['dnf remove', str(hotfix.AUDIT_LEGACY_RESTART)], 'the restart comes after the package is gone')

    def test_debian_removal_restarts_auditd_with_systemctl(self):
        self.claim()
        host = self.deb(dpkg=installed_deb(), listener=True)
        host.remove('4.14.1', OWNER)
        self.assertEqual(self.restarts(host), [['systemctl', 'restart', 'auditd']])
        self.assertFalse(host.r.listener)

    def test_auditd_is_left_alone_when_nothing_is_orphaned(self):
        self.claim()
        cases = {
            'config still present (someone owns it)': (dict(listener=True), lambda: hotfix.AUDIT_PLUGIN.write_text('active = yes\n')),
            'no listener': (dict(listener=False), lambda: None),
        }
        for name, (kwargs, prepare) in cases.items():
            with self.subTest(name):
                if hotfix.AUDIT_PLUGIN.exists():
                    hotfix.AUDIT_PLUGIN.unlink()
                prepare()
                host = self.rpm_host(rpm=Result(stdout='4.14.9-1\tx86_64'), **kwargs)
                host.remove('4.14.1', OWNER)
                self.assertEqual(self.restarts(host), [])

    def test_a_missing_legacy_action_refuses_instead_of_guessing(self):
        self.claim()
        hotfix.AUDIT_LEGACY_RESTART.unlink()
        with self.assertRaisesRegex(hotfix.Refused, 'no supported way to restart auditd'):
            self.rpm_host(rpm=Result(stdout='4.14.9-1\tx86_64'), listener=True).remove('4.14.1', OWNER)

    def test_a_listener_that_survives_the_restart_refuses(self):
        self.claim()
        host = self.rpm_host(rpm=Result(stdout='4.14.9-1\tx86_64'), listener=True, stuck_listener=True)
        with self.assertRaisesRegex(hotfix.Refused, 'still present after restarting auditd'):
            host.remove('4.14.1', OWNER)

    def test_a_rerun_finishes_a_retirement_the_first_run_did_not(self):
        # package and keys already gone, only the orphaned plugin is left: still actionable
        self.claim()
        host = self.rpm_host(rpm=ABSENT_RPM, listener=True)
        self.assertTrue(host.remove('4.14.1', OWNER)['changed'])
        self.assertFalse(host.r.listener)
        # and with nothing at all left the rerun is refused, not a silent no-op
        with self.assertRaisesRegex(hotfix.Refused, 'not newer than the manager'):
            self.rpm_host(rpm=ABSENT_RPM).remove('4.14.1', OWNER)

    def test_verify_fails_while_the_endpoint_listener_remains(self):
        with self.assertRaisesRegex(hotfix.Refused, 'who-data endpoint'):
            self.rpm_host(rpm=ABSENT_RPM, listener=True).verify()
        self.assertEqual(self.rpm_host(rpm=ABSENT_RPM).verify(), {'removed': True})

    def test_verify_demands_the_whole_end_state(self):
        clean = self.deb(dpkg=ABSENT_DEB)
        self.assertEqual(clean.verify(), {'removed': True})
        for name, host, prepare in (
                ('still installed', self.deb(dpkg=installed_deb()), lambda: None),
                ('preference left', self.deb(dpkg=ABSENT_DEB), lambda: hotfix.PREF.write_text(PREF_OWNED)),
                ('hold left', self.deb(dpkg=ABSENT_DEB, held=['wazuh-agent']), lambda: None),
                ('client.keys left', self.deb(dpkg=ABSENT_DEB), lambda: hotfix.CLIENT_KEYS.write_text(CLIENT_KEYS)),
                ('unit enabled', self.deb(dpkg=ABSENT_DEB, unit=['inactive', 'enabled']), lambda: None),
                ('unit active', self.deb(dpkg=ABSENT_DEB, unit=['active', 'disabled']), lambda: None)):
            with self.subTest(name):
                for path in (hotfix.PREF, hotfix.CLIENT_KEYS):
                    if path.exists():
                        path.unlink()
                prepare()
                with self.assertRaises(hotfix.Refused):
                    host.verify()

    def test_refusals_are_typed_json_without_tool_output(self):
        error = hotfix.typed_error('refused', 'bad\nvalue\x00 with control characters')
        self.assertEqual(set(error), {'error', 'error_kind'})
        self.assertNotIn('\n', error['error'])


class EntryPointTests(unittest.TestCase):
    def test_requires_root(self):
        with unittest.mock.patch.object(hotfix.os, 'geteuid', return_value=1000):
            with self.assertRaises(SystemExit) as raised, contextlib.redirect_stderr(io.StringIO()) as stderr:
                hotfix.main(['inspect', '--family', 'Debian'])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn('requires root', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
