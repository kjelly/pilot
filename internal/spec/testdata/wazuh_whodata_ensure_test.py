"""agent-whodata-ensure: the ordinary apply on EL leaves the who-data endpoint live and connected, or refuses (Issue #323).

The real Agent.whodata_ensure and AuditRuntime (endpoint_kind, plugin_active, parse_streams, reload_plugins, poll,
armed) run over a temporary /proc and host tree under the production host-wide writer owner and component lock.
Declared leaves, each shaped from the captures of an AlmaLinux 9 VM in native-captures/
(ss-xHap.audit-endpoint.healthy.almalinux9, auditctl-l.wazuh_fim.almalinux9, af_wazuh.conf.almalinux9):
  * `ss -xHap` and `auditctl -l` answer from those captures; which of their lines are present is the modeled state
    (listening, connected) and only the endpoint path is substituted. The state "listening, no connected syscheckd"
    (the host after a SIGHUP alone, before any agent restart) answers from a NATIVE capture of it
    (ss-xHap.audit-endpoint.hup-only.almalinux9: the endpoint-path lines of `ss -xHap` on AlmaLinux 9.8, one LISTEN
    line); the other partial states (stale socket, crossed stream) are derived by editing the healthy capture;
  * auditd's reaction to SIGHUP (loading the plugin, which opens the listening endpoint) and wazuh-agent's reaction
    to a restart (syscheckd connects and arms the kernel watches only if the endpoint already exists) are MODELED;
    the native fact each models is named where it is produced (they are the fresh AlmaLinux 9 sequence probes recorded
    in docs/verification/wazuh-fim.md, not new observations of this change);
  * the builtin-listener state (auditd itself listening, as Ubuntu 22.04's builtin_af_unix does) is DERIVED from the
    AlmaLinux capture by renaming the listening program; no native capture of it is committed;
  * time is simulated: sleeping advances a clock and lets the modeled host react, nothing really waits.
This does not certify auditd, systemd or Wazuh: the native VM run is separately required evidence.
"""
import contextlib
import io
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


class Clock:
    """Simulated time: sleeping advances it and lets the modeled host react."""

    def __init__(self):
        self.now, self.hooks = 0.0, []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        for hook in self.hooks:
            hook(self.now)


class Host:
    """auditd, an optional listening endpoint and wazuh-syscheckd, as /proc, a socket file and command answers."""
    AUDITD = 500

    def __init__(self, root, path, native, clock):
        self.root, self.path, self.native, self.clock = root, path, native, clock
        self.proc = root / 'proc'
        self.proc.mkdir()
        self.events, self.commands, self.schedule = [], [], []
        self.plugin_binary = True        # /sbin/audisp-af_unix is installed (audispd-plugins)
        self.listening = False           # a socket in LISTEN is bound to the endpoint path
        self.connected = False           # syscheckd's ESTAB stream is the peer of the accepted server side
        self.watches = False             # the kernel has the wazuh_fim rules
        self.health_check_fails = False  # syscheckd's who-data engine "could not start": real-time fallback
        self.arms_watches = True         # a connected syscheckd arms the kernel rules after its health check
        self.crossed = False             # the syscheckd ESTAB stream is connected to something else
        self.listener = 'audisp-af_unix'  # which program holds the listening side
        self.ss_fails = False
        self.endpoint_delay = 2          # seconds between a SIGHUP and the plugin opening the endpoint (MODELED)
        self.sighup_time = None
        clock.hooks.append(self.tick)
        self.process(self.AUDITD, 1, '/usr/sbin/auditd', ['/sbin/auditd'])

    # --- /proc, the plugin file and the endpoint socket ---
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
        text = wazuh_models.capture('af_wazuh.conf.almalinux9.txt')
        conf = self.path('/etc/audit/plugins.d/af_wazuh.conf')
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text(text if active else text.replace('active = yes', 'active = no'))

    def socket_file(self):
        """A real AF_UNIX socket inode at the (mapped) endpoint path. Closing the socket leaves the file, which is
        exactly what a stale endpoint is (native Ubuntu 24.04 capture: plugin deactivated, file stays)."""
        target = self.endpoint()
        target.parent.mkdir(parents=True, exist_ok=True)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(target))
        sock.close()

    def healthy(self, watches=True):
        """The state an ordinary apply converges to."""
        self.plugin_conf()
        self.socket_file()
        self.listening = self.connected = True
        self.watches = watches

    def at(self, seconds, action):
        self.schedule.append((seconds, action))

    def tick(self, now):
        for item in [item for item in self.schedule if item[0] <= now]:
            self.schedule.remove(item)
            item[1]()

    # --- native reactions (MODELED) ---
    def sighup(self, descriptor, number):
        # Native (AlmaLinux 9, fresh x3, recorded in the spec): a SIGHUP makes auditd re-read plugins.d; an installed,
        # active plugin is started and opens the endpoint socket immediately, with no kernel watch yet. Without the
        # plugin binary (audispd-plugins absent) nothing changes.
        self.events.append(('sighup', number))
        self.sighup_time = self.clock.now
        conf = self.path('/etc/audit/plugins.d/af_wazuh.conf')
        if self.plugin_binary and conf.exists() and 'active = yes' in conf.read_text() and not self.endpoint().exists():
            def open_endpoint():
                self.socket_file()
                self.listening = True
                self.events.append(('endpoint-created', None))
            self.at(self.clock.now + self.endpoint_delay, open_endpoint)

    def restart_agent(self):
        # Native (AlmaLinux 9, fresh x3): a syscheckd that starts while the endpoint exists connects to it and arms the
        # kernel watches after its audit health check; one that starts without it logs "Who-data engine could not
        # start. Switching who-data to real-time." and arms nothing.
        self.events.append(('restart', self.listening))
        up = self.listening and not self.health_check_fails
        self.connected = up
        self.watches = up and self.arms_watches
        self.crossed = False  # a new syscheckd process opens a new stream to the endpoint

    def run(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        self.commands.append(argv)
        if argv[:5] == ['systemctl', 'show', 'auditd', '-p', 'MainPID']:
            return subprocess.CompletedProcess(argv, 0, str(self.AUDITD) + '\n', '')
        if argv[:3] == ['systemctl', 'restart', 'wazuh-agent']:
            self.restart_agent()
            return subprocess.CompletedProcess(argv, 0, '', '')
        if argv[:2] == ['ss', '-xHap']:
            if self.ss_fails:
                raise w.Refused('operation failed: ss rc=1')
            return subprocess.CompletedProcess(argv, 0, self.ss(), '')
        if argv[:2] == ['auditctl', '-l']:
            text = wazuh_models.capture('auditctl-l.wazuh_fim.almalinux9.txt' if self.watches else 'auditctl-l.no-rules.almalinux9.txt')
            return subprocess.CompletedProcess(argv, 0, text, '')
        self.native.calls.append(argv)
        return self.native.__class__.run(self.native, argv, **kwargs)

    def ss(self):
        if self.listening and not self.connected:
            # NATIVE state: the listener exists, no syscheckd stream (what a SIGHUP alone leaves behind).
            text = wazuh_models.capture('ss-xHap.audit-endpoint.hup-only.almalinux9.txt')
            if self.listener == 'auditd':
                text = text.replace('"audisp-af_unix"', '"auditd"')
            return text.replace(ENDPOINT, str(self.endpoint()))
        out = []
        for line in wazuh_models.capture('ss-xHap.audit-endpoint.healthy.almalinux9.txt').splitlines():
            fields = line.split()
            listen = fields[1] == 'LISTEN' and fields[4] == ENDPOINT
            pair = fields[0] == 'u_str' and fields[1] == 'ESTAB' and (fields[4] == ENDPOINT or 'wazuh-syscheckd' in line)
            if (listen and not self.listening) or (pair and not self.connected):
                continue
            if self.crossed and pair and 'wazuh-syscheckd' in line:
                line = line.replace('42613', '99999').replace('43081', '88888')
            if self.listener == 'auditd':
                line = line.replace('"audisp-af_unix"', '"auditd"')
            out.append(line.replace(ENDPOINT, str(self.endpoint())))
        return '\n'.join(out) + '\n'


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
            clock = Clock()
            model = Host(root, path, native, clock)
            agent.r = model
            with mock.patch.object(w.os, 'pidfd_open', lambda pid: os.open(os.devnull, os.O_RDONLY)), \
                    mock.patch.object(w.signal, 'pidfd_send_signal', model.sighup), \
                    mock.patch.object(w.time, 'sleep', clock.sleep), \
                    mock.patch.object(w.time, 'monotonic', clock.monotonic):
                yield agent, model

    def untouched(self, model):
        self.assertEqual(model.events, [], 'no signal and no restart')

    # ---- no-op paths: nothing changes, nothing is signalled, nothing restarts ----
    def test_a_listening_connected_endpoint_is_only_verified_whoever_listens(self):
        for listener in ('audisp-af_unix', 'auditd'):
            with self.subTest(listener=listener), self.host() as (agent, model):
                model.healthy()
                model.listener = listener  # the builtin af_unix of auditd (Ubuntu 22.04's shape) is as good as the plugin
                self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False})
                self.untouched(model)
                self.assertNotIn(['auditctl', '-l'], model.commands, 'the steady-state path does not read watches')

    def test_a_host_whose_watches_were_flushed_by_another_role_is_a_no_op(self):
        # audit-log-forwarding's `augenrules --load` clears the kernel rules while the endpoint and the connection
        # survive (#324, spec section 2). Requiring watches here would make every second apply change something.
        with self.host() as (agent, model):
            model.healthy(watches=False)
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False})
            self.untouched(model)

    def test_a_syscheckd_that_connects_within_the_grace_costs_no_restart(self):
        with self.host() as (agent, model):
            model.plugin_conf()
            model.socket_file()
            model.listening = True
            model.at(10, lambda: setattr(model, 'connected', True))  # the agent was just restarted by Step 11
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False})
            self.untouched(model)
            self.assertGreaterEqual(model.clock.now, 10, 'it waited for the connection instead of restarting')

    # ---- repair paths: at most one signal and one restart, in that order ----
    def test_a_listener_without_a_connected_syscheckd_costs_one_restart_and_no_signal(self):
        # The state after HUP alone (spec section 2): the endpoint listens, but syscheckd runs in real-time with no
        # stream. The ss answer is the native capture of exactly that state (hup-only.almalinux9).
        with self.host() as (agent, model):
            model.plugin_conf()
            model.socket_file()
            model.listening = True
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
            self.assertEqual(model.events, [('restart', True)])
            self.assertGreaterEqual(model.clock.now, w.AuditRuntime.CLIENT_GRACE, 'the grace is bounded, then it acts')
            model.events.clear()
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False})
            self.untouched(model)

    def test_a_syscheckd_connected_to_something_else_does_not_count_as_connected(self):
        # The pairing is by inode: an ESTAB stream owned by wazuh-syscheckd that is not the peer of the endpoint's
        # accepted side is not who-data (a mutation that accepts any syscheckd stream no-ops here and fails this).
        with self.host() as (agent, model):
            model.healthy()
            model.crossed = True
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
            self.assertEqual(model.events, [('restart', True)])

    def test_a_missing_endpoint_under_an_active_plugin_is_repaired_by_one_hup_then_one_agent_restart(self):
        # The state after an ordinary apply that installed audispd-plugins: af_wazuh.conf is `active = yes`, auditd
        # never loaded it, the agent runs in real-time with no watches.
        with self.host() as (agent, model):
            model.plugin_conf()
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
            # Exactly one SIGHUP, then the endpoint, and only then the agent restart (a restart before the endpoint
            # exists would leave syscheckd in real-time again).
            self.assertEqual(model.events, [('sighup', int(w.signal.SIGHUP)), ('endpoint-created', None), ('restart', True)])
            model.events.clear()
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False})
            self.untouched(model)

    def test_the_plugin_file_the_agent_writes_late_is_awaited_before_anything_is_signalled(self):
        # On a fresh host Step 11 restarts the agent right after Step 10 and the first start writes af_wazuh.conf.
        with self.host() as (agent, model):
            model.at(20, model.plugin_conf)
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
            self.assertGreaterEqual(model.sighup_time, 20, 'no signal before the plugin was configured')
            self.assertEqual([kind for kind, _ in model.events], ['sighup', 'endpoint-created', 'restart'])

    def test_an_endpoint_that_appears_while_waiting_for_the_plugin_is_not_signalled(self):
        with self.host() as (agent, model):
            def appear():
                model.plugin_conf()
                model.socket_file()
                model.listening = model.connected = model.watches = True
            model.at(15, appear)
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False})
            self.untouched(model)

    # ---- typed refusals: the apply fails, nothing is repaired around them ----
    def test_a_plugin_that_never_becomes_active_is_refused_without_a_signal(self):
        for case in ('absent', 'inactive'):
            with self.subTest(plugin=case), self.host() as (agent, model):
                if case == 'inactive':
                    model.plugin_conf(active=False)
                with self.assertRaisesRegex(w.Refused, 'the Wazuh audit plugin is not active'):
                    agent.whodata_ensure(OWNER)
                self.untouched(model)
                self.assertGreaterEqual(model.clock.now, w.AuditRuntime.PLUGIN_WAIT, 'the wait is bounded, then it refuses')

    def test_an_endpoint_that_never_appears_after_the_one_hup_is_refused_without_restarting_the_agent(self):
        # audispd-plugins is not installed: the plugin file is active but its binary is absent, so a HUP changes nothing.
        with self.host() as (agent, model):
            model.plugin_conf()
            model.plugin_binary = False
            with self.assertRaisesRegex(w.Refused, 'external audit endpoint did not appear after reloading the audit daemon'):
                agent.whodata_ensure(OWNER)
            self.assertEqual(model.events, [('sighup', int(w.signal.SIGHUP))], 'one signal, no retry and no agent restart')

    def test_who_data_that_never_arms_after_the_restart_is_refused(self):
        for case, setup in (('real-time fallback', lambda m: setattr(m, 'health_check_fails', True)),
                            ('connected without watches', lambda m: setattr(m, 'arms_watches', False))):
            with self.subTest(case=case), self.host() as (agent, model):
                model.plugin_conf()
                setup(model)
                with self.assertRaisesRegex(w.Refused, 'stream or watches did not appear after restarting the agent'):
                    agent.whodata_ensure(OWNER)
                self.assertEqual([kind for kind, _ in model.events], ['sighup', 'endpoint-created', 'restart'])
                self.assertGreaterEqual(model.clock.now, w.AuditRuntime.READY_WAIT)

    def test_an_endpoint_that_is_not_a_socket_is_refused_and_never_repaired(self):
        for case in ('regular file', 'symlink to a socket', 'directory'):
            with self.subTest(case=case), self.host() as (agent, model):
                model.plugin_conf()
                target = model.endpoint()
                target.parent.mkdir(parents=True)
                if case == 'regular file':
                    target.write_text('a regular file is not an audit endpoint')
                elif case == 'directory':
                    target.mkdir()
                else:
                    model.socket_file()
                    real = target.with_name('real-audit')
                    target.rename(real)
                    target.symlink_to(real)
                with self.assertRaisesRegex(w.Refused, 'not a socket'):
                    agent.whodata_ensure(OWNER)
                self.untouched(model)

    def test_a_socket_nobody_listens_on_is_refused_and_never_repaired(self):
        # Native Ubuntu 24.04 capture: after the plugin is deactivated the socket FILE stays with no listener.
        with self.host() as (agent, model):
            model.plugin_conf()
            model.socket_file()
            with self.assertRaisesRegex(w.Refused, 'socket has no listener'):
                agent.whodata_ensure(OWNER)
            self.untouched(model)
            self.assertGreaterEqual(model.clock.now, w.AuditRuntime.LISTENER_WAIT)

    def test_an_endpoint_probe_that_fails_is_a_refusal_not_a_guess(self):
        with self.host() as (agent, model):
            model.healthy()
            model.ss_fails = True
            with self.assertRaisesRegex(w.Refused, 'operation failed: ss'):
                agent.whodata_ensure(OWNER)
            self.untouched(model)

    def test_only_the_redhat_family_is_ensured(self):
        with self.host('Debian') as (agent, model):
            with self.assertRaisesRegex(w.Refused, 'supports only the RedHat family'):
                agent.whodata_ensure(OWNER)
            self.untouched(model)
            self.assertEqual(model.commands, [], 'Debian is not even observed')

    def test_the_signal_target_must_be_the_exact_auditd(self):
        with self.host() as (agent, model):
            model.plugin_conf()
            model.process(model.AUDITD, 1, '/usr/sbin/not-auditd', ['/sbin/auditd'])
            with self.assertRaisesRegex(w.Refused, 'unsupported audit daemon executable'):
                agent.whodata_ensure(OWNER)
            self.untouched(model)
        with self.host() as (agent, model):
            model.plugin_conf()
            real = model.run
            model.run = lambda argv, **kw: (subprocess.CompletedProcess(argv, 0, '0\n', '')
                                            if list(argv)[:3] == ['systemctl', 'show', 'auditd'] else real(argv, **kw))
            with self.assertRaisesRegex(w.Refused, 'audit daemon identity is unavailable'):
                agent.whodata_ensure(OWNER)
            self.untouched(model)

    # ---- ownership and the unchanged admission gate ----
    def test_the_ensure_runs_only_under_the_exact_host_writer_and_an_idle_component(self):
        with self.host() as (agent, model):
            model.plugin_conf()
            with self.assertRaises(w.Refused):
                agent.whodata_ensure('e' * 32)  # not the writer that was claimed
            self.untouched(model)
            w.atomic_json(agent.path, {'kind': 'agent', 'owner': OWNER, 'phase': 'installing'})
            with self.assertRaisesRegex(w.Refused, 'incomplete Wazuh transaction'):
                agent.whodata_ensure(OWNER)
            self.untouched(model)

    def test_the_upgrade_admission_gate_still_refuses_an_active_plugin_without_an_endpoint(self):
        # The ensure never loosens the gate: a version transaction on a legacy host (plugin active, no endpoint) still
        # refuses, signals nothing and restarts nothing; the host is repaired by an ordinary apply first.
        with self.host() as (agent, model):
            model.plugin_conf()
            with self.assertRaisesRegex(w.Refused, 'configured external audit endpoint is unavailable before upgrade'):
                w.AuditRuntime(model).snapshot(None)
            self.untouched(model)

    # ---- the CLI the playbook calls ----
    def test_the_action_is_reachable_from_the_coordinator_command_line(self):
        # Every earlier test calls the method; the playbook calls the CLI. A missing dispatch would pass all of them.
        calls = []

        def ensure(agent, owner):
            calls.append((agent.family, owner))
            return {'changed': False}
        out = io.StringIO()
        argv = ['pilot-wazuh-transaction', 'agent-whodata-ensure', '--family', 'RedHat', '--owner', OWNER]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(w, 'is_root', lambda: True), \
                mock.patch.object(w.Agent, 'whodata_ensure', ensure), contextlib.redirect_stdout(out):
            self.assertEqual(w.main(), 0)
        self.assertEqual(calls, [('RedHat', OWNER)])
        self.assertEqual(json.loads(out.getvalue()), {'changed': False})
        # Without --family the action sees Debian (the CLI default) and refuses; the refusal is typed JSON with a
        # non-zero exit, never a traceback or a silent success.
        out = io.StringIO()
        argv = ['pilot-wazuh-transaction', 'agent-whodata-ensure', '--owner', OWNER]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(w, 'is_root', lambda: True), contextlib.redirect_stdout(out):
            self.assertEqual(w.main(), 1)
        value = json.loads(out.getvalue())
        self.assertEqual(value['error_kind'], 'refused')
        self.assertIn('supports only the RedHat family', value['error'])


if __name__ == '__main__':
    unittest.main()
