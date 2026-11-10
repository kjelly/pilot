"""agent-whodata-ensure: the ordinary apply leaves the who-data endpoint live, or refuses (Issue #244, D1).

The real Agent.whodata_ensure and AuditRuntime (endpoint/plugin/process/ready) run over a temporary /proc and
host tree. Declared native leaves, each shaped from a capture of an Ubuntu 24.04 / AlmaLinux 9 VM
(native-captures/ss-xHap.audit-endpoint.*, auditctl-l.*, af_wazuh.conf.*):
  * `ss -xHap` and `auditctl -l` answer from those captures with only the endpoint path and the pids
    substituted;
  * auditd's reaction to SIGHUP (loading the af_unix plugin, which creates the endpoint and its listener) and
    wazuh-agent's reaction to a restart (syscheckd connects and the kernel watches appear) are modeled; the
    native fact each models is named at the model.
This does not certify auditd, systemd or Wazuh; the native VM run is separately required evidence.
"""
import contextlib
import io
import itertools
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import wazuh_models
import wazuh_transaction_test as existing

w = existing.w
ENDPOINT = '/var/ossec/queue/sockets/audit'
OWNER = 'd' * 32


class Host:
    """auditd, an optional af_unix listener and wazuh-syscheckd, as /proc, sockets and command answers."""
    AUDITD, LISTENER, SYSCHECKD = 500, 501, 700

    def __init__(self, root, path, native, family):
        self.root, self.path, self.native, self.family = root, path, native, family
        self.proc = root / 'proc'
        self.proc.mkdir()
        self.events, self.sockets = [], []
        self.plugin_binary = True      # audispd-plugins (EL) / auditd (Debian) provides /sbin/audisp-af_unix
        self.connected = self.watches = False
        self.health_check_fails = False  # who-data engine "could not start": syscheckd falls back to real-time
        self.auditd_exe = '/usr/sbin/auditd'
        self.watch_text = wazuh_models.capture('auditctl-l.wazuh_fim.' + ('ubuntu2404' if family == 'Debian' else 'almalinux9') + '.txt')
        syscheckd = path('/var/ossec/bin/wazuh-syscheckd')
        syscheckd.parent.mkdir(parents=True, exist_ok=True)
        syscheckd.write_bytes(b'installed wazuh-syscheckd executable')
        self.process(self.AUDITD, 1, self.auditd_exe, ['/sbin/auditd'])
        self.process(self.SYSCHECKD, 1, str(syscheckd), ['/var/ossec/bin/wazuh-syscheckd'])

    # --- /proc ---
    def process(self, pid, ppid, exe, argv):
        folder = self.proc / str(pid)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / 'stat').write_text('%d (modeled) S %d %s 4242' % (pid, ppid, ' '.join(['0'] * 17)))
        (folder / 'cmdline').write_bytes(b'\0'.join(value.encode() for value in argv) + b'\0')
        link = folder / 'exe'
        if link.is_symlink():
            link.unlink()
        link.symlink_to(exe)

    def endpoint(self):
        return self.path(ENDPOINT)

    def plugin_conf(self, active=True):
        text = wazuh_models.capture('af_wazuh.conf.' + ('ubuntu2404' if self.family == 'Debian' else 'almalinux9') + '.txt')
        conf = self.path('/etc/audit/plugins.d/af_wazuh.conf')
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text(text if active else text.replace('active = yes', 'active = no'))

    def endpoint_socket(self):
        """The audisp-af_unix plugin's listening socket, a real AF_UNIX socket at the (mapped) endpoint path."""
        target = self.endpoint()
        target.parent.mkdir(parents=True, exist_ok=True)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(target))
        sock.listen(1)
        self.sockets.append(sock)

    def start_listener(self):
        self.process(self.LISTENER, self.AUDITD, '/usr/sbin/audisp-af_unix',
                     ['/sbin/audisp-af_unix', '0640', str(self.endpoint())])

    def healthy(self):
        """The state an ordinary apply on a correctly provisioned host converges to."""
        self.plugin_conf()
        self.endpoint_socket()
        self.start_listener()
        self.connected = self.watches = True

    # --- native reactions (MODELED) ---
    def sighup(self, descriptor, number):
        # Native (AlmaLinux 9, auditd 3.1.5): SIGHUP makes auditd re-read plugins.d; an installed, active plugin is
        # started as a child of auditd and creates the endpoint socket immediately. Without the plugin binary
        # (audispd-plugins absent, the pre-fix EL state) nothing changes.
        self.events.append(('sighup', number))
        conf = self.path('/etc/audit/plugins.d/af_wazuh.conf')
        if self.plugin_binary and conf.exists() and 'active = yes' in conf.read_text() and not self.endpoint().exists():
            self.endpoint_socket()
            self.start_listener()
            self.events.append(('endpoint-created', None))

    def run(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        if argv[:5] == ['systemctl', 'show', 'auditd', '-p', 'MainPID']:
            return subprocess.CompletedProcess(argv, 0, str(self.AUDITD) + '\n', '')
        if argv[:3] == ['systemctl', 'restart', 'wazuh-agent']:
            # Native: a syscheckd started while the endpoint exists connects to it and arms the kernel watches after
            # its audit health check; one started without it logs "Who-data engine could not start. Switching
            # who-data to real-time." and arms nothing.
            self.events.append(('restart', self.endpoint().exists()))
            up = self.endpoint().exists() and not self.health_check_fails
            self.connected = self.watches = up
            return subprocess.CompletedProcess(argv, 0, '', '')
        if argv[:2] == ['ss', '-xHap']:
            return subprocess.CompletedProcess(argv, 0, self.ss(), '')
        if argv[:2] == ['auditctl', '-l']:
            text = self.watch_text if self.watches else wazuh_models.capture('auditctl-l.no-rules.ubuntu2404.txt')
            return subprocess.CompletedProcess(argv, 0, text, '')
        self.native.calls.append(argv)
        return self.native.__class__.run(self.native, argv, **kwargs)

    def ss(self):
        family = 'ubuntu2404' if self.family == 'Debian' else 'almalinux9'
        listener, syscheckd = ('pid=8609', 'pid=9509') if family == 'ubuntu2404' else ('pid=7823', 'pid=7946')
        lines = wazuh_models.capture('ss-xHap.audit-endpoint.healthy.' + family + '.txt').splitlines()
        out = []
        for line in lines:
            if not self.connected and 'ESTAB' in line and line.startswith('u_str'):
                continue  # the connected stream is both ends of one ESTAB pair
            out.append(line.replace(ENDPOINT, str(self.endpoint())).replace(listener, 'pid=%d' % self.LISTENER)
                       .replace(syscheckd, 'pid=%d' % self.SYSCHECKD))
        return '\n'.join(out) + '\n'


class Runtime(w.AuditRuntime):
    """The real AuditRuntime; only the syscheckd executable identity is a declared leaf (its /proc/<pid>/exe is a
    private file standing for the installed binary, which the real code digests)."""
    host = None

    @staticmethod
    def process(pid):
        if pid == Runtime.host.SYSCHECKD:
            return {'pid': pid, 'ppid': 1, 'start': '4242', 'exe': '/var/ossec/bin/wazuh-syscheckd',
                    'argv': ['/var/ossec/bin/wazuh-syscheckd']}
        return w.AuditRuntime.process(pid)


class WhodataEnsureTests(unittest.TestCase):
    @contextlib.contextmanager
    def host(self, family='RedHat'):
        with existing.RestoreScopeTests().agent(family) as (agent, native, path, root):
            inner = w.Path

            def mapped(value):
                text = str(value)
                if text == '/proc':
                    return root / 'proc'
                if text.startswith('/proc/'):
                    return root / 'proc' / text[len('/proc/'):]
                return inner(value)
            w.Path = mapped
            model = Host(root, path, native, family)
            # ready() digests /proc/<pid>/exe; the symlink target is the installed binary (mapped by the fixture).
            (root / 'proc' / str(model.SYSCHECKD) / 'exe').unlink()
            (root / 'proc' / str(model.SYSCHECKD) / 'exe').symlink_to(path('/var/ossec/bin/wazuh-syscheckd'))
            Runtime.host = model
            runtime = Runtime(model)
            agent.audit_runtime = lambda: runtime
            agent.r = model
            ticks = itertools.count(0, 5)
            # Bounded waits run on a fast fake clock; the real sleeps are not needed to prove the ordering.
            with mock.patch.object(w.os, 'pidfd_open', lambda pid: os.open(os.devnull, os.O_RDONLY)), \
                    mock.patch.object(w.signal, 'pidfd_send_signal', model.sighup), \
                    mock.patch.object(w.time, 'sleep', lambda seconds: None), \
                    mock.patch.object(w.time, 'monotonic', lambda: next(ticks)):
                try:
                    yield agent, model
                finally:
                    for sock in model.sockets:
                        sock.close()

    def kinds(self, model):
        return [event[0] for event in model.events]

    def test_existing_live_endpoint_is_only_verified(self):
        for family in ('Debian', 'RedHat'):
            with self.subTest(family=family), self.host(family) as (agent, model):
                model.healthy()
                result = agent.whodata_ensure(OWNER)
                self.assertEqual(result, {'changed': False, 'watches': 2})
                self.assertEqual(model.events, [], 'a healthy host gets no signal and no restart')

    def test_missing_endpoint_under_an_active_plugin_is_repaired_by_one_hup_then_one_agent_restart(self):
        # The pre-fix EL state after the plugin package is installed: af_wazuh.conf is active, auditd was already
        # running (it never loaded the plugin), the agent runs in real-time fallback with no watches.
        for family in ('RedHat', 'Debian'):
            with self.subTest(family=family), self.host(family) as (agent, model):
                model.plugin_conf()
                result = agent.whodata_ensure(OWNER)
                self.assertEqual(result, {'changed': True, 'watches': 2})
                # Exactly one SIGHUP, then the endpoint, and only then the agent restart (a restart before the
                # endpoint exists would leave syscheckd in real-time again).
                self.assertEqual(model.events, [('sighup', int(w.signal.SIGHUP)), ('endpoint-created', None), ('restart', True)])
                # A second ordinary apply is a no-op: no signal, no restart.
                model.events.clear()
                self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False, 'watches': 2})
                self.assertEqual(model.events, [])

    def test_endpoint_that_never_appears_fails_typed_without_restarting_the_agent(self):
        # audispd-plugins is not installed: the plugin is active but its binary is absent, so a HUP changes nothing.
        with self.host() as (agent, model):
            model.plugin_conf()
            model.plugin_binary = False
            with self.assertRaisesRegex(w.Refused, 'external audit endpoint did not appear after reloading the audit daemon'):
                agent.whodata_ensure(OWNER)
            self.assertEqual(self.kinds(model), ['sighup'], 'one signal, no retry, and no agent restart')

    def test_inactive_or_absent_plugin_without_an_endpoint_is_refused_before_any_signal(self):
        for case in ('inactive', 'absent'):
            with self.subTest(plugin=case), self.host() as (agent, model):
                if case == 'inactive':
                    model.plugin_conf(active=False)
                with self.assertRaisesRegex(w.Refused, 'the Wazuh audit plugin is not active'):
                    agent.whodata_ensure(OWNER)
                self.assertEqual(model.events, [])

    def test_stale_or_non_socket_endpoint_is_refused_and_never_repaired(self):
        # Ubuntu 24.04 capture: after the plugin is deactivated the socket FILE stays with no listener.
        with self.host() as (agent, model):
            model.plugin_conf()
            model.endpoint_socket()  # no listener process: the plugin is gone
            with self.assertRaisesRegex(w.Refused, 'exact external audit listener is missing or ambiguous'):
                agent.whodata_ensure(OWNER)
            self.assertEqual(model.events, [])
        with self.host() as (agent, model):
            model.plugin_conf()
            model.endpoint().parent.mkdir(parents=True)
            model.endpoint().write_text('a regular file is not an audit endpoint')
            with self.assertRaisesRegex(w.Refused, 'not a socket'):
                agent.whodata_ensure(OWNER)
            self.assertEqual(model.events, [])

    def test_who_data_that_never_arms_is_not_reported_as_live(self):
        # The "verify passes but the effect is not real" shape: endpoint and listener exist, but syscheckd fell back to
        # real-time (no connected stream, no kernel watch). Both the no-op and the repair path must refuse it.
        with self.host() as (agent, model):
            model.healthy()
            model.connected = model.watches = False
            with self.assertRaisesRegex(w.Refused, 'readiness timed out'):
                agent.whodata_ensure(OWNER)
            self.assertEqual(model.events, [])
        with self.host() as (agent, model):
            model.plugin_conf()
            model.health_check_fails = True
            with self.assertRaisesRegex(w.Refused, 'readiness timed out'):
                agent.whodata_ensure(OWNER)
            self.assertEqual(self.kinds(model), ['sighup', 'endpoint-created', 'restart'])

    def test_signal_target_must_be_the_exact_auditd(self):
        with self.host() as (agent, model):
            model.plugin_conf()
            model.process(model.AUDITD, 1, '/usr/sbin/not-auditd', ['/sbin/auditd'])
            with self.assertRaisesRegex(w.Refused, 'unsupported audit daemon executable'):
                agent.whodata_ensure(OWNER)
            self.assertEqual(model.events, [], 'nothing is signalled when the main process is not auditd')
        with self.host() as (agent, model):
            model.plugin_conf()
            real = model.run
            model.run = lambda argv, **kw: (subprocess.CompletedProcess(argv, 0, '0\n', '')
                                            if list(argv)[:3] == ['systemctl', 'show', 'auditd'] else real(argv, **kw))
            with self.assertRaisesRegex(w.Refused, 'audit daemon identity is unavailable'):
                agent.whodata_ensure(OWNER)
            self.assertEqual(model.events, [])

    def test_the_action_is_reachable_from_the_coordinator_command_line(self):
        # Every earlier test calls the method; the playbook calls the CLI. A missing dispatch would pass all of them.
        with tempfile.TemporaryDirectory() as temporary:
            calls = []

            def ensure(agent, owner):
                calls.append((agent.family, owner))
                return {'changed': False, 'watches': 2}
            out = io.StringIO()
            argv = ['pilot-wazuh-transaction', 'agent-whodata-ensure', '--family', 'RedHat', '--owner', OWNER]
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(w, 'is_root', lambda: True), \
                    mock.patch.object(w.Agent, 'whodata_ensure', ensure), contextlib.redirect_stdout(out):
                self.assertEqual(w.main(), 0)
            self.assertEqual(calls, [('RedHat', OWNER)])
            self.assertEqual(json.loads(out.getvalue()), {'changed': False, 'watches': 2})
            # A refusal is a typed JSON error with a non-zero exit, never a traceback or a silent success.
            out = io.StringIO()

            def refuse(agent, owner):
                raise w.Refused('external audit endpoint did not appear after reloading the audit daemon')
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(w, 'is_root', lambda: True), \
                    mock.patch.object(w.Agent, 'whodata_ensure', refuse), contextlib.redirect_stdout(out):
                self.assertEqual(w.main(), 1)
            self.assertEqual(json.loads(out.getvalue())['error_kind'], 'refused')


if __name__ == '__main__':
    unittest.main()
