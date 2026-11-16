"""agent-whodata-ensure: the ordinary apply on EL leaves the who-data endpoint live and connected, or refuses (Issues #323, #330).

The real Agent.whodata_ensure and AuditRuntime (endpoint_kind, plugin_active, parse_streams, reload_plugins, poll,
boot_ticks, agent_unit, agent_processes, settled, await_fresh_stream) run over a temporary /proc and host tree under
the production host-wide writer owner and component lock.
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
Issue #330 adds the race the atomic restart model above used to hide. Declared leaves of that model:
  * `systemctl show wazuh-agent -p LoadState -p ActiveState -p Job` answers from the AlmaLinux 9 capture
    (systemctl-show-wazuh-agent.active.almalinux9, .not-found.almalinux9) with only ActiveState substituted; the `Job=`
    line is MODELED (empty when idle was confirmed on a systemd 259 workstation, a queued job's id is not captured),
    and so are the `reloading`, `activating`, `deactivating` answers;
  * the processes of the Wazuh agent service (/proc/<pid>/cgroup, comm, cmdline, exe, stat starttime) are MODELED:
    the unified-hierarchy cgroup line, restart.sh run as `sh active-response/bin/restart.sh agent reload` (upstream
    Wazuh sources as read for the Issue: execd/wcom start it with that relative path, the unit is Type=forking with
    KillMode=process and TimeoutSec=45), and a wazuh-syscheckd whose starttime is the boot clock in ticks (the
    kernel's documented /proc/<pid>/stat field 22; /proc/uptime is the same clock);
  * a `systemctl restart` issued while a reload job runs is merged into it and leaves the old wazuh-syscheckd
    running (the journal of the failed apply of Issue #330: `remains running after unit stopped`, then `wazuh-syscheckd
    already running`; that journal is quoted by Issue #330 and the hotfix runbook, it is not in a committed evidence
    record), a syscheckd that started before the endpoint existed stays unconnected for good, and a reload's own
    `wazuh-control reload` replaces syscheckd. The committed native observations are narrower and all taken after a
    HUP alone with no agent restart: the sequence probes in docs/verification/wazuh-fim.md section 2 (the wazuh_fim
    watch count stayed 0 for 60 s) and arm A' of docs/evidence/wazuh-fim/issue-323.md (`ss`/`auditctl` sampled 8 s
    after the HUP: one LISTEN, no ESTAB, no watch). A survivor that stays unconnected after an agent restart, and the
    merge itself, are MODELED here and pending the native run of Issue #330.
A native vm-target run of Issue #330 (candidate d094e0f2, AlmaLinux 9.8, systemd 252, Wazuh 4.14.1; its record is
written separately under docs/evidence/wazuh-fim/) showed the settle wait working but a restart right after it killing
a syscheckd that Wazuh's own reload had started after the endpoint existed, and the next syscheckd then failing its
audit health check. The model of that is declared too, as MODELED observations and not as a proven mechanism:
  * a syscheckd started after the endpoint is connected at once, logs its who-data engine start `engine_delay` seconds
    later and has its kernel watches `arm_delay` seconds after the start (the native one needed several seconds; the
    value is a stand-in);
  * `kill_mid_init_poisons_next`: a syscheckd killed after its engine started and before it armed makes the NEXT
    syscheckd connect but never arm (the observed correlation: 2 failures in which the first syscheckd had passed its
    engine start, 3 passes in which it had not; the mechanism was not established);
  * `fallback_starts`: the next N syscheckd starts fall back to real-time: connected, never armed.
This does not certify auditd, systemd or Wazuh: the native VM run is separately required evidence.
"""
import ast
import contextlib
import io
import json
import os
import shutil
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
BOOT = 5000.0  # MODELED: seconds of uptime when the simulated clock reads 0; starttimes are compared in this base
HZ = os.sysconf('SC_CLK_TCK')
SYSCHECKD = '/var/ossec/bin/wazuh-syscheckd'
AGENT_CGROUP = '0::/system.slice/wazuh-agent.service\n'  # MODELED: the unified-hierarchy line of a service process
OTHER_CGROUP = '0::/user.slice/user-1000.slice/session-3.scope\n'


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
    """auditd, an optional listening endpoint, the Wazuh agent service and wazuh-syscheckd, as /proc, a socket file and command answers."""
    AUDITD, AGENTD, RESTART_SH = 500, 800, 7100

    def __init__(self, root, path, native, clock):
        self.root, self.path, self.native, self.clock = root, path, native, clock
        self.proc = root / 'proc'
        self.proc.mkdir()
        self.events, self.log, self.commands, self.schedule = [], [], [], []
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
        # --- the Wazuh agent service (Issue #330; all MODELED, see the module docstring) ---
        self.unit_state, self.job = 'active', ''   # what `systemctl show wazuh-agent` reports
        self.show_fails, self.show_output = False, None
        self.reload_active = False       # Wazuh's own `restart.sh agent reload` job is running
        self.restart_replaces_syscheckd = True   # False: the restart is swallowed by something the unit shows nothing of
        self.restart_starts_syscheckd = True     # False: no syscheckd is running after the restart
        self.extra_syscheckd_on_restart = False  # True: a second syscheckd of the service runs after the restart
        self.endpoint_lost_on_restart = False    # True: the listener is gone after the restart
        self.endpoint_removed_on_restart = False
        self.bad_stat_on_restart = False
        self.uptime_unreadable = False
        self.before_restart = None       # runs at the instant the restart command is issued (after the last probe)
        self.syscheckd_pids, self.syscheckd_started, self.next_pid = [], None, 810
        # --- how a syscheckd arms (Issue #330 native follow-up; MODELED, see the module docstring) ---
        self.arm_delay = 0.0             # seconds from a syscheckd start to its kernel watches (0: immediately)
        self.engine_delay = 2.0          # seconds from a start to its who-data engine having started
        self.fallback_starts = 0         # the next N starts fall back to real-time: connected, never armed
        self.kill_mid_init_poisons_next = False  # MODELED correlation, not a proven mechanism
        self.poisoned = False            # the next start's audit health check will fail
        self.syscheckd_gen, self.arm_at = 0, None
        clock.hooks.append(self.tick)
        self.process(self.AUDITD, 1, '/usr/sbin/auditd', ['/sbin/auditd'])
        self.process(self.AGENTD, 1, '/var/ossec/bin/wazuh-agentd', ['/var/ossec/bin/wazuh-agentd'], cgroup=AGENT_CGROUP,
                     comm='wazuh-agentd', start=-100.0)
        # The syscheckd every host starts with was started long before the run and before any endpoint listened.
        self.place_syscheckd(-100.0)
        self.write_uptime()

    # --- /proc, the plugin file and the endpoint socket ---
    @staticmethod
    def ticks(seconds):
        """A starttime in the boot clock: seconds into the run to ticks since boot (MODELED base BOOT)."""
        return int(round((BOOT + seconds) * HZ))

    def write_uptime(self):
        if self.uptime_unreadable:
            (self.proc / 'uptime').unlink(missing_ok=True)
            return
        (self.proc / 'uptime').write_text('%.2f %.2f\n' % (BOOT + self.clock.now, 0.0))

    def process(self, pid, ppid, exe, argv, cgroup='0::/system.slice/auditd.service\n', comm='modeled', start=None):
        folder = self.proc / str(pid)
        folder.mkdir(parents=True, exist_ok=True)
        starttime = '4242' if start is None else str(self.ticks(start))
        (folder / 'stat').write_text('%d (%s) S %d %s %s' % (pid, comm, ppid, ' '.join(['0'] * 17), starttime))
        (folder / 'comm').write_text(comm + '\n')
        (folder / 'cgroup').write_text(cgroup)
        (folder / 'cmdline').write_bytes(b'\0'.join(value.encode() for value in argv) + b'\0')
        link = folder / 'exe'
        if link.is_symlink():
            link.unlink()
        link.symlink_to(exe)

    def drop_process(self, pid):
        shutil.rmtree(self.proc / str(pid), ignore_errors=True)

    def kill_syscheckd(self):
        """Every syscheckd of the agent service stops. MODELED correlation (Issue #330 native run, no proven mechanism):
        one stopped after its who-data engine started and before it armed makes the NEXT syscheckd's audit health check
        fail, so that one connects and never arms."""
        if (self.kill_mid_init_poisons_next and self.syscheckd_pids and self.arm_at is not None
                and self.syscheckd_started + self.engine_delay <= self.clock.now < self.arm_at):
            self.poisoned = True
        for old in self.syscheckd_pids:
            self.drop_process(old)
        self.syscheckd_pids, self.arm_at = [], None
        self.syscheckd_gen += 1  # the arming of the one that died never happens

    def place_syscheckd(self, start, pid=None):
        """The one wazuh-syscheckd of the agent service, started `start` seconds into the run (the old one is gone)."""
        self.kill_syscheckd()
        pid = pid or self.next_pid
        self.next_pid = max(self.next_pid, pid) + 1
        self.syscheckd_pids, self.syscheckd_started = [pid], start
        self.process(pid, 1, SYSCHECKD, [SYSCHECKD], cgroup=AGENT_CGROUP, comm='wazuh-syscheckd', start=start)
        return pid

    def add_syscheckd(self, start):
        """A second wazuh-syscheckd in the agent service's cgroup (a restart stops it with the first)."""
        pid = self.add_process(SYSCHECKD, [SYSCHECKD], AGENT_CGROUP, 'wazuh-syscheckd', start)
        self.syscheckd_pids.append(pid)
        return pid

    def arm(self, generation):
        if generation == self.syscheckd_gen:
            self.watches = True
            self.log.append((self.clock.now, 'armed'))

    def add_process(self, exe, argv, cgroup, comm, start):
        pid = self.next_pid
        self.next_pid += 1
        self.process(pid, 1, exe, argv, cgroup=cgroup, comm=comm, start=start)
        return pid

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
        self.place_syscheckd(-50.0)

    def at(self, seconds, action):
        self.schedule.append((seconds, action))

    def note(self, kind, value=None):
        self.events.append((kind, value))
        self.log.append((self.clock.now, kind))

    def times(self, kind):
        return [when for when, name in self.log if name == kind]

    def tick(self, now):
        self.write_uptime()
        for item in [item for item in self.schedule if item[0] <= now]:
            self.schedule.remove(item)
            item[1]()

    # --- native reactions (MODELED) ---
    def sighup(self, descriptor, number):
        # Native (AlmaLinux 9, fresh x3, recorded in the spec): a SIGHUP makes auditd re-read plugins.d; an installed,
        # active plugin is started and opens the endpoint socket immediately, with no kernel watch yet. Without the
        # plugin binary (audispd-plugins absent) nothing changes.
        self.note('sighup', number)
        self.sighup_time = self.clock.now
        conf = self.path('/etc/audit/plugins.d/af_wazuh.conf')
        if self.plugin_binary and conf.exists() and 'active = yes' in conf.read_text() and not self.endpoint().exists():
            def open_endpoint():
                self.socket_file()
                self.listening = True
                self.note('endpoint-created')
            self.at(self.clock.now + self.endpoint_delay, open_endpoint)

    def start_syscheckd(self, start=None, arm_after=None):
        # Native (AlmaLinux 9, fresh x3): a syscheckd that starts while the endpoint exists connects to it and arms the
        # kernel watches after its audit health check; one that starts without it logs "Who-data engine could not
        # start. Switching who-data to real-time." and arms nothing, and (MODELED, native arm A' saw it for at least
        # 60 s) never connects later. Natively observed so far: after a HUP alone the watch count stayed 0 for 60 s
        # (spec section 2 sequence probes) and arm A' of #323 sampled no ESTAB 8 s after the HUP; nothing observed a
        # stale syscheckd after an agent restart. The delay before arming and the poison/fallback fates are MODELED.
        start = self.clock.now if start is None else start
        self.place_syscheckd(start)
        self.log.append((self.clock.now, 'syscheckd-start'))
        poisoned, self.poisoned = self.poisoned, False
        fallback = self.fallback_starts > 0
        self.fallback_starts = max(0, self.fallback_starts - 1)
        up = self.listening and not self.health_check_fails
        self.connected = up
        self.crossed = False  # a new syscheckd process opens a new stream to the endpoint
        delay = self.arm_delay if arm_after is None else arm_after
        arms = up and self.arms_watches and not poisoned and not fallback
        self.arm_at = start + delay if arms else None
        self.watches = arms and delay <= 0
        if arms and delay > 0:
            generation = self.syscheckd_gen
            self.at(self.arm_at, lambda: self.arm(generation))

    def begin_reload(self, state='reloading', job='4711', script=True):
        """MODELED: Wazuh's own `restart.sh agent reload` (run by the agent after a shared configuration push) starts:
        its `systemctl reload` puts the unit in `reloading` with a queued job while restart.sh is alive; `state`
        `active` with no job is the moment before restart.sh has issued the reload."""
        self.reload_active = True
        self.unit_state, self.job = state, job
        if script:
            self.process(self.RESTART_SH, self.AGENTD, '/usr/bin/bash', ['/bin/sh', 'active-response/bin/restart.sh', 'agent', 'reload'],
                         cgroup=AGENT_CGROUP, comm='restart.sh', start=self.clock.now)
        self.note('reload-begin')

    def settle_unit(self):
        self.reload_active = False
        self.unit_state, self.job = 'active', ''
        self.drop_process(self.RESTART_SH)

    def end_reload(self, restarts_syscheckd=True):
        """The reload job completes; its `wazuh-control reload` replaces syscheckd unless it never got that far."""
        self.settle_unit()
        self.note('reload-finished')
        if restarts_syscheckd:
            self.start_syscheckd()

    def restart_agent(self):
        if self.before_restart:
            hook, self.before_restart = self.before_restart, None
            hook()
        if self.reload_active:
            # MODELED systemd: the restart is merged into the running reload job. The reload's control process is
            # stopped, KillMode=process leaves the processes of the service (syscheckd, restart.sh) running, and the
            # start that follows finds wazuh-syscheckd already running: no new syscheckd, whatever its age.
            self.note('restart-merged', self.listening)
            self.settle_unit()
            return
        if not self.restart_replaces_syscheckd:
            self.note('restart-ineffective', self.listening)
            return
        self.note('restart', self.listening)
        if self.endpoint_lost_on_restart:
            self.listening = False
        if self.endpoint_removed_on_restart:
            self.listening = False
            self.endpoint().unlink()
        if self.restart_starts_syscheckd:
            self.start_syscheckd()
            if self.extra_syscheckd_on_restart:
                self.add_process(SYSCHECKD, [SYSCHECKD], AGENT_CGROUP, 'wazuh-syscheckd', self.clock.now)
            if self.bad_stat_on_restart:
                (self.proc / str(self.syscheckd_pids[0]) / 'stat').write_text('garbage')
        else:
            self.kill_syscheckd()
            self.connected = self.watches = False

    def show(self):
        text = wazuh_models.capture('systemctl-show-wazuh-agent.active.almalinux9.rc0.txt')
        return text.replace('ActiveState=active', 'ActiveState=' + self.unit_state) + 'Job=' + self.job + '\n'

    def run(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        self.commands.append(argv)
        if argv[:5] == ['systemctl', 'show', 'auditd', '-p', 'MainPID']:
            return subprocess.CompletedProcess(argv, 0, str(self.AUDITD) + '\n', '')
        if argv[:3] == ['systemctl', 'show', 'wazuh-agent']:
            if self.show_fails:
                raise w.Refused('operation failed: native Wazuh agent service state rc=1')
            return subprocess.CompletedProcess(argv, 0, self.show() if self.show_output is None else self.show_output, '')
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

    RESTART = ['systemctl', 'restart', 'wazuh-agent']

    def restarts(self, model):
        return model.commands.count(self.RESTART)

    def probes_of_the_agent_unit(self, model):
        return [argv for argv in model.commands if argv[:3] == ['systemctl', 'show', 'wazuh-agent']]

    def steps(self, model):
        """The mutations and their order, without the model's own bookkeeping events."""
        return [kind for kind, _ in model.events if kind in ('sighup', 'endpoint-created', 'restart', 'restart-merged', 'restart-ineffective')]

    def invariants(self, model):
        """What every run keeps, however it ends: at most one SIGHUP and one agent restart, auditd is never
        restarted, stopped or reloaded through systemd, and no process is killed."""
        self.assertLessEqual(sum(1 for kind, _ in model.events if kind == 'sighup'), 1)
        self.assertLessEqual(self.restarts(model), 1)
        self.assertEqual([argv for argv in model.commands if argv[:2] in (['systemctl', 'restart'], ['systemctl', 'stop'],
                                                                         ['systemctl', 'reload'], ['systemctl', 'kill'])
                          and argv[2] != 'wazuh-agent'], [])
        self.assertFalse([argv for argv in model.commands if argv[0] in ('kill', 'pkill', 'killall')])
        self.assertEqual(os.readlink(model.proc / str(model.AUDITD) / 'exe'), '/usr/sbin/auditd', 'auditd is the same process')

    def raised(self, setup):
        """Run the ensure on a RedHat host with an active plugin and no endpoint, prepared by setup(model); returns
        the text of the typed refusal and the model."""
        with self.host() as (agent, model):
            model.plugin_conf()
            setup(model)
            with self.assertRaises(w.Refused) as caught:
                agent.whodata_ensure(OWNER)
            self.invariants(model)
            return str(caught.exception), model

    # ---- no-op paths: nothing changes, nothing is signalled, nothing restarts ----
    def test_a_listening_connected_endpoint_is_only_verified_whoever_listens(self):
        for listener in ('audisp-af_unix', 'auditd'):
            with self.subTest(listener=listener), self.host() as (agent, model):
                model.healthy()
                model.listener = listener  # the builtin af_unix of auditd (Ubuntu 22.04's shape) is as good as the plugin
                self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False})
                self.untouched(model)
                self.assertNotIn(['auditctl', '-l'], model.commands, 'the steady-state path does not read watches')
                self.assertEqual(self.probes_of_the_agent_unit(model), [], 'the steady-state path does not look at the agent unit')

    def test_a_host_whose_watches_were_flushed_by_another_role_is_a_no_op(self):
        # audit-log-forwarding's `augenrules --load` clears the kernel rules while the endpoint and the connection
        # survive (#324, spec section 2). Requiring watches here would make every second apply change something.
        with self.host() as (agent, model):
            model.healthy(watches=False)
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False})
            self.untouched(model)
            self.assertEqual(self.probes_of_the_agent_unit(model), [])

    def test_a_syscheckd_that_connects_within_the_grace_costs_no_restart(self):
        with self.host() as (agent, model):
            model.plugin_conf()
            model.socket_file()
            model.listening = True
            model.at(10, lambda: setattr(model, 'connected', True))  # the agent was just restarted by Step 11
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False})
            self.untouched(model)
            self.assertGreaterEqual(model.clock.now, 10, 'it waited for the connection instead of restarting')
            self.assertEqual(self.probes_of_the_agent_unit(model), [])

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

    # ---- Issue #330: the agent's own reload racing the ensure's restart ----
    def test_an_in_flight_self_reload_is_waited_out_before_any_restart(self):
        # The failure of Issue #330: on a fresh host the agent runs `restart.sh agent reload` for the first shared
        # configuration while the ensure waits for the endpoint, and a restart issued inside that job is merged into it
        # and leaves the pre-endpoint syscheckd running. The ensure must act only once the reload is over. What it does
        # then depends on the syscheckd it finds: the old one (it never saw the endpoint) is restarted, once; one that
        # the reload itself started after the endpoint existed is left alone (see the arm-window tests).
        for case, reload_replaces_syscheckd in (('the reload leaves syscheckd alone', False), ('the reload replaces syscheckd itself', True)):
            with self.subTest(case=case), self.host() as (agent, model):
                model.plugin_conf()
                model.at(1.0, lambda: model.begin_reload())
                model.at(15.0, lambda: model.end_reload(restarts_syscheckd=reload_replaces_syscheckd))
                self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
                if reload_replaces_syscheckd:
                    # Legitimately changed with Issue #330's refinement: the reload's own syscheckd started after the
                    # endpoint (15.0 >= 2.0) and is armed, so there is nothing to restart (it used to be restarted a
                    # second time for nothing).
                    self.assertEqual(self.steps(model), ['sighup', 'endpoint-created'], 'one signal, no restart of a healthy post-endpoint syscheckd')
                    self.assertEqual(self.restarts(model), 0)
                    self.assertEqual(model.syscheckd_started, 15.0, 'the reload\'s syscheckd is the one that serves')
                else:
                    self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart'], 'one signal, one restart, never merged')
                    self.assertGreaterEqual(model.times('restart')[0], model.times('reload-finished')[0], 'restarted only after the reload ended')
                    self.assertEqual(self.restarts(model), 1)
                    # The effective state: one syscheckd, started after the endpoint was listening, connected, with watches.
                    self.assertGreaterEqual(model.syscheckd_started, model.times('endpoint-created')[0])
                self.assertEqual(len(model.syscheckd_pids), 1)
                self.assertTrue(model.connected and model.watches)
                self.invariants(model)
                model.events.clear()
                model.commands.clear()
                self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False}, 'a second apply changes nothing')
                self.untouched(model)

    def test_every_sign_of_a_transition_in_flight_holds_the_restart_until_it_clears(self):
        # Each signal alone blocks the restart: the unit state, a queued job, and Wazuh's restart.sh (matched by name or
        # by the script in its arguments, only inside the agent service's cgroup). Without the signal the restart goes.
        def state(value):
            return lambda m: setattr(m, 'unit_state', value), lambda m: setattr(m, 'unit_state', 'active')

        def script(argv, comm):
            pid = []

            def up(m):
                pid.append(m.add_process('/usr/bin/bash', argv, AGENT_CGROUP, comm, 0.0))
            return up, lambda m: m.drop_process(pid[0])
        cases = {
            'reload job: unit reloading, restart.sh alive': (lambda m: m.begin_reload(), lambda m: m.settle_unit()),
            'restart.sh alive before it issued the reload (unit still active, no job)': (lambda m: m.begin_reload('active', ''), lambda m: m.settle_unit()),
            'unit reloading, no restart.sh, no job': state('reloading'),
            'unit activating': state('activating'),
            'unit deactivating': state('deactivating'),
            'unit refreshing': state('refreshing'),
            'a job is queued on an active unit': (lambda m: setattr(m, 'job', '4712'), lambda m: setattr(m, 'job', '')),
            'restart.sh by its comm alone': script(['sh', '-c', 'true'], 'restart.sh'),
            'restart.sh by a relative script argument': script(['/bin/sh', 'active-response/bin/restart.sh', 'agent', 'reload'], 'sh'),
            'restart.sh by an absolute script argument': script(['/bin/bash', '/var/ossec/active-response/bin/restart.sh', 'agent', 'restart'], 'bash'),
        }
        for name, (up, clear) in cases.items():
            with self.subTest(blocks=name):
                with self.host() as (agent, model):
                    model.plugin_conf()
                    up(model)
                    model.at(20, lambda: clear(model))
                    self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
                    self.assertGreaterEqual(model.times('restart')[0], 20, 'the restart waited for the signal to clear')
                    self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart'])
                    self.invariants(model)
            with self.subTest(never_clears=name):
                text, model = self.raised(lambda m: up(m))
                self.assertIn('did not finish an in-flight reload or restart within the bound, so it was not restarted', text)
                self.assertEqual(self.restarts(model), 0, 'nothing is restarted when the unit never settles')
                self.assertEqual(self.steps(model), ['sighup', 'endpoint-created'], 'the SIGHUP already sent stays; no restart')
                self.assertGreaterEqual(model.clock.now, w.AuditRuntime.SETTLE_WAIT, 'the wait is bounded, then it refuses')
                self.assertLessEqual(model.clock.now, w.AuditRuntime.LISTENER_WAIT + w.AuditRuntime.SETTLE_WAIT, 'and not longer than that')

    def test_a_stable_unit_whose_processes_are_not_a_reload_does_not_hold_the_restart(self):
        # restart.sh and a stale-looking syscheckd outside the agent service's cgroup are somebody else's (an operator's
        # shell, a container): they neither delay the restart nor count as a survivor or a second syscheckd. An
        # inactive or failed unit with nothing queued is not a transition (the restart starts it, as before).
        for state in ('active', 'inactive', 'failed', 'maintenance'):
            with self.subTest(state=state), self.host() as (agent, model):
                model.plugin_conf()
                model.unit_state = state
                model.add_process('/usr/bin/bash', ['/bin/sh', 'active-response/bin/restart.sh', 'agent', 'reload'], OTHER_CGROUP, 'restart.sh', 0.0)
                model.add_process(SYSCHECKD, [SYSCHECKD], OTHER_CGROUP, 'wazuh-syscheckd', -500.0)
                self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
                self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart'])
                self.assertLess(model.clock.now, w.AuditRuntime.LISTENER_WAIT, 'no waiting for a process that is not the agent service')
                self.invariants(model)

    def test_a_reload_that_starts_between_the_last_probe_and_the_restart_does_not_cause_a_false_refusal(self):
        # The mark is the instant the endpoint was first seen listening, not the instant of the restart: a reload that
        # began after the last settle probe has already replaced syscheckd (after the endpoint existed) when the merged
        # restart returns, and that syscheckd is fine. A floor taken at the restart would refuse it.
        def late(model):
            def reload_that_already_replaced_syscheckd():
                model.begin_reload('reloading', '4713')
                model.start_syscheckd(model.clock.now - 0.25)
            model.before_restart = reload_that_already_replaced_syscheckd
        with self.subTest(path='a listener without a connected syscheckd'), self.host() as (agent, model):
            model.plugin_conf()
            model.socket_file()
            model.listening = True
            late(model)
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
            self.assertEqual(self.steps(model), ['restart-merged'])
            self.assertLess(model.syscheckd_started, model.times('restart-merged')[0], 'it started before the restart was issued')
            self.invariants(model)
        with self.subTest(path='after the one SIGHUP'), self.host() as (agent, model):
            model.plugin_conf()
            model.at(1.0, lambda: model.begin_reload())
            model.at(9.0, lambda: model.end_reload(restarts_syscheckd=False))
            late(model)
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
            self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart-merged'])
            self.assertGreaterEqual(model.syscheckd_started, model.times('endpoint-created')[0])
            self.assertLess(model.syscheckd_started, model.times('restart-merged')[0])
            self.invariants(model)

    # ---- Issue #330, native follow-up: a syscheckd that came up after the endpoint is not killed while it arms ----
    def reload_spawns_syscheckd(self, model, spawn_at=4.0, end_at=7.0):
        """MODELED after the native observation of Issue #330: Wazuh's own reload begins while pilot waits for the
        endpoint, its `wazuh-control reload` starts a syscheckd after the endpoint exists (spawn_at), and the reload
        job ends later (end_at), which is when the ensure's settle wait is over."""
        model.at(1.0, lambda: model.begin_reload())
        model.at(spawn_at, lambda: model.start_syscheckd())
        model.at(end_at, lambda: model.end_reload(restarts_syscheckd=False))

    def assert_served_by_the_reloads_syscheckd(self, agent, model):
        self.assertEqual(self.restarts(model), 0, 'a syscheckd that came up after the endpoint is never restarted by pilot')
        self.assertEqual(self.steps(model), ['sighup', 'endpoint-created'])
        self.assertEqual(model.times('syscheckd-start'), [4.0], 'the reload\'s syscheckd is the only one that ever started')
        self.assertGreaterEqual(model.clock.now, 4.0 + model.arm_delay, 'it waited for that syscheckd to arm')
        self.assertTrue(model.connected and model.watches)
        self.invariants(model)
        model.events.clear()
        model.commands.clear()
        self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False}, 'a second apply is a no-op')
        self.untouched(model)

    def test_a_syscheckd_that_came_up_after_the_endpoint_is_given_time_to_arm_and_is_not_restarted(self):
        # T-A: the reload-spawned syscheckd needs ~10 s to arm (the native one needed several seconds). The ensure
        # sent the SIGHUP, so it reports a change; it restarts nothing.
        with self.host() as (agent, model):
            model.plugin_conf()
            model.arm_delay = 10.0
            self.reload_spawns_syscheckd(model)
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
            self.assert_served_by_the_reloads_syscheckd(agent, model)

    def test_pilot_never_kills_a_post_endpoint_syscheckd_inside_its_arm_window(self):
        # T-B: the observed correlation as a model: a syscheckd stopped after its engine started and before it armed
        # makes the next one fail its audit health check. Restarting right after the settle (the previous behaviour)
        # kills the reload's syscheckd at 7.0, 3 s into its initialisation, and the next one never arms.
        with self.host() as (agent, model):
            model.plugin_conf()
            model.arm_delay = 10.0
            model.kill_mid_init_poisons_next = True
            self.reload_spawns_syscheckd(model)
            try:
                result = agent.whodata_ensure(OWNER)
            except w.Refused as exc:
                self.fail('pilot restarted a syscheckd that was initialising and the next one never armed: %s' % exc)
            self.assertEqual(result, {'changed': True, 'watches': 2})
            self.assert_served_by_the_reloads_syscheckd(agent, model)

    def test_the_poison_model_only_bites_when_a_syscheckd_is_killed_between_its_engine_start_and_arming(self):
        # Negative control of the model behind the test above, so that test cannot pass because the model never bites.
        for age, bites in ((1.0, False), (3.0, True), (9.9, True), (10.0, False), (30.0, False)):
            with self.subTest(killed_at_age=age), self.host() as (agent, model):
                model.listening = True
                model.arm_delay = 10.0
                model.kill_mid_init_poisons_next = True
                model.start_syscheckd(0.0)
                model.clock.now = age
                model.start_syscheckd()
                self.assertEqual(model.watches, False)
                model.clock.sleep(model.arm_delay + 1)
                self.assertEqual(model.watches, not bites, 'the next syscheckd %s' % ('never arms' if bites else 'arms normally'))
                self.assertEqual(model.connected, True)

    def test_a_post_endpoint_syscheckd_that_never_arms_costs_exactly_one_restart_after_the_window(self):
        # T-C: the reload's syscheckd fell back to real-time (connected, never armed; the next start is healthy). It
        # gets READY_WAIT, then the one restart replaces it and the proof passes.
        with self.host() as (agent, model):
            model.plugin_conf()
            model.fallback_starts = 1
            self.reload_spawns_syscheckd(model)
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
            self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart'])
            self.assertEqual(self.restarts(model), 1)
            self.assertGreaterEqual(model.times('restart')[0], 7.0 + w.AuditRuntime.READY_WAIT, 'the window was given before restarting')
            self.assertEqual(model.times('syscheckd-start')[0], 4.0)
            self.assertGreater(model.syscheckd_started, 4.0, 'the restart replaced it')
            self.assertTrue(model.connected and model.watches)
            self.invariants(model)

    def test_a_post_endpoint_syscheckd_that_never_arms_even_after_the_one_restart_is_the_typed_refusal(self):
        # T-E: the restart does not help either: the existing refusal for a connection without a watch, after exactly
        # one restart, with both waits spent.
        text, model = self.raised(lambda m: (setattr(m, 'fallback_starts', 2), self.reload_spawns_syscheckd(m)))
        self.assertEqual(text, self.NEW_REFUSALS['watch'])
        self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart'])
        self.assertEqual(self.restarts(model), 1)
        self.assertGreaterEqual(model.clock.now, 7.0 + 2 * w.AuditRuntime.READY_WAIT)

    def test_a_stale_syscheckd_is_restarted_at_once_without_an_arm_window(self):
        # T-D: a syscheckd that started before the endpoint is past its initialisation and cannot connect; waiting for it
        # to arm would only add READY_WAIT. Treating it as healthy would wait and then restart late, or never.
        with self.host() as (agent, model):
            model.plugin_conf()
            model.arm_delay = 10.0
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
            self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart'])
            self.assertEqual(model.times('restart')[0], model.times('endpoint-created')[0], 'restarted in the same instant, no waiting')
            self.invariants(model)

    def test_no_syscheckd_or_more_than_one_is_restarted_at_once(self):
        # T-F: only exactly one post-endpoint syscheckd earns the arm window (listener path: the endpoint was already
        # there, nothing connected within the grace).
        def listener_not_connected(model):
            model.plugin_conf()
            model.socket_file()
            model.listening = True
            model.health_check_fails = True
            model.at(29.0, lambda: setattr(model, 'health_check_fails', False))
        for case, setup in (('no syscheckd', lambda m: m.kill_syscheckd()),
                            ('two post-endpoint syscheckd', lambda m: m.at(5.0, lambda: (m.start_syscheckd(), m.add_syscheckd(5.0))))):
            with self.subTest(case=case), self.host() as (agent, model):
                listener_not_connected(model)
                setup(model)
                self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})
                self.assertEqual(self.steps(model), ['restart'])
                self.assertEqual(model.times('restart')[0], w.AuditRuntime.CLIENT_GRACE, 'restarted right after the grace, no arm window')
                self.assertEqual(len(model.syscheckd_pids), 1)
                self.invariants(model)

    def test_a_post_endpoint_syscheckd_that_arms_in_the_window_of_the_listener_path_changes_nothing(self):
        # `changed` is true only if this call signalled or restarted: no SIGHUP and no restart means false.
        with self.host() as (agent, model):
            model.plugin_conf()
            model.socket_file()
            model.listening = True
            model.health_check_fails = True
            model.at(10.0, lambda: model.start_syscheckd())  # a syscheckd after the endpoint that is not connected yet
            model.at(45.0, lambda: (setattr(model, 'connected', True), setattr(model, 'watches', True)))
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': False, 'watches': 2})
            self.untouched(model)
            self.assertEqual(self.restarts(model), 0)
            self.assertGreaterEqual(model.clock.now, 45.0)
            self.invariants(model)

    def test_a_syscheckd_that_started_before_the_endpoint_and_survived_the_restart_is_a_distinct_refusal(self):
        survived = 'a wazuh-syscheckd that started before the audit endpoint was listening survived the agent restart, so who-data cannot connect'
        # (a) Something the unit shows nothing of swallowed the restart: the syscheckd of long before survives.
        text, model = self.raised(lambda m: setattr(m, 'restart_replaces_syscheckd', False))
        self.assertEqual(text, survived)
        self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart-ineffective'], 'one restart, no corrective second one')
        self.assertLess(model.clock.now, w.AuditRuntime.READY_WAIT, 'a process that cannot recover is not waited for')
        # (b) A syscheckd that started after the SIGHUP but before the endpoint appeared is just as stale: the mark is
        # taken when the endpoint is seen listening, not when the ensure began.
        def started_in_between(model):
            model.at(1.0, lambda: model.start_syscheckd())
            model.restart_replaces_syscheckd = False
        text, model = self.raised(started_in_between)
        self.assertEqual(text, survived)
        self.assertEqual(model.syscheckd_started, 1.0)
        # (c) The same through the listener path (the endpoint was there, the syscheckd never connected).
        with self.host() as (agent, model):
            model.plugin_conf()
            model.socket_file()
            model.listening = True
            model.restart_replaces_syscheckd = False
            with self.assertRaises(w.Refused) as caught:
                agent.whodata_ensure(OWNER)
            self.assertEqual(str(caught.exception), survived)
            self.assertEqual(self.steps(model), ['restart-ineffective'])

    def test_the_restart_that_merged_into_an_unseen_reload_is_refused_not_retried(self):
        # The incident itself, without the settle wait having seen anything: the restart is merged into a reload the
        # unit never showed. The ensure refuses with the survivor text and does not restart a second time.
        def unseen(model):
            model.before_restart = lambda: model.begin_reload('reloading', '4714')
        text, model = self.raised(unseen)
        self.assertIn('survived the agent restart', text)
        self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart-merged'])
        self.assertEqual(self.restarts(model), 1)

    def test_each_way_the_stream_can_fail_after_the_restart_has_its_own_refusal(self):
        cases = {
            'endpoint listener gone': (lambda m: setattr(m, 'endpoint_lost_on_restart', True),
                                       'the audit endpoint was no longer listening after the agent restart'),
            'endpoint socket removed': (lambda m: setattr(m, 'endpoint_removed_on_restart', True),
                                        'the audit endpoint was no longer listening after the agent restart'),
            'fresh syscheckd never connects': (lambda m: setattr(m, 'health_check_fails', True),
                                               'the restarted wazuh-syscheckd did not connect to the audit endpoint after the agent restart'),
            'connected without a watch': (lambda m: setattr(m, 'arms_watches', False),
                                          'wazuh-syscheckd connected to the audit endpoint but no wazuh_fim kernel audit watch appeared after the agent restart'),
            'no syscheckd runs': (lambda m: setattr(m, 'restart_starts_syscheckd', False),
                                  'the Wazuh agent service did not have exactly one wazuh-syscheckd after the agent restart'),
            'two syscheckd run': (lambda m: setattr(m, 'extra_syscheckd_on_restart', True),
                                  'the Wazuh agent service did not have exactly one wazuh-syscheckd after the agent restart'),
        }
        texts = {}
        for name, (setup, literal) in cases.items():
            with self.subTest(case=name):
                text, model = self.raised(setup)
                texts[name] = text
                self.assertEqual(text, literal)
                self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart'], 'one restart and nothing after it')
                self.assertGreaterEqual(model.clock.now, w.AuditRuntime.READY_WAIT, 'what may still be settling is polled for the bound')
        self.assertEqual(len(set(texts.values())), 4, 'four distinct conditions, four distinct refusals')

    def test_a_syscheckd_that_connects_late_within_the_bound_is_not_refused(self):
        # The post-restart conditions are polled, not judged once: a stream that comes up after a few seconds passes.
        with self.host() as (agent, model):
            model.plugin_conf()
            model.health_check_fails = True
            model.at(20, lambda: setattr(model, 'health_check_fails', False))
            model.at(20, lambda: model.start_syscheckd())  # a syscheckd of the agent service that comes up after the restart
            self.assertEqual(agent.whodata_ensure(OWNER), {'changed': True, 'watches': 2})

    def test_a_probe_that_cannot_be_read_is_a_typed_refusal_and_restarts_nothing_further(self):
        shown = {
            'no lines at all': '',
            'LoadState is missing': 'ActiveState=active\nJob=\n',
            'the unit is not loaded (native not-found capture)': wazuh_models.capture('systemctl-show-wazuh-agent.not-found.almalinux9.rc0.txt') + 'Job=\n',
            'an ActiveState nobody knows': 'LoadState=loaded\nActiveState=bogus\nJob=\n',
            'a Job that is not an id': 'LoadState=loaded\nActiveState=active\nJob=abc\n',
            'a repeated key': 'LoadState=loaded\nActiveState=active\nActiveState=inactive\nJob=\n',
        }
        for name, output in shown.items():
            with self.subTest(show=name):
                text, model = self.raised(lambda m: setattr(m, 'show_output', output))
                self.assertEqual(text, 'the Wazuh agent service state could not be read or its unit is not loaded')
                self.assertEqual(self.restarts(model), 0)
                self.assertEqual(self.steps(model), ['sighup', 'endpoint-created'])
        with self.subTest(show='systemctl show itself fails'):
            text, model = self.raised(lambda m: setattr(m, 'show_fails', True))
            self.assertEqual(text, 'operation failed: native Wazuh agent service state rc=1')
            self.assertEqual(self.restarts(model), 0)
        with self.subTest(proc='the cgroup of a process cannot be read'):
            def unreadable_cgroup(model):
                # a directory where the file should be: reading it fails whoever runs the test (chmod would not stop root)
                (model.proc / str(model.AUDITD) / 'cgroup').unlink()
                (model.proc / str(model.AUDITD) / 'cgroup').mkdir()
            text, model = self.raised(unreadable_cgroup)
            self.assertEqual(text, 'the Wazuh agent service processes could not be read from /proc')
            self.assertEqual(self.restarts(model), 0)
        with self.subTest(proc='the new syscheckd has an unreadable stat'):
            text, model = self.raised(lambda m: setattr(m, 'bad_stat_on_restart', True))
            self.assertEqual(text, 'the Wazuh agent service processes could not be read from /proc')
            self.assertEqual(self.steps(model), ['sighup', 'endpoint-created', 'restart'])
        with self.subTest(proc='/proc/uptime cannot be read'):
            def no_uptime(model):
                model.uptime_unreadable = True
                model.write_uptime()
            text, model = self.raised(no_uptime)
            self.assertEqual(text, 'the boot-relative clock could not be read from /proc/uptime')
            self.assertEqual(self.restarts(model), 0)

    NEW_REFUSALS = {
        'settle': 'the Wazuh agent service did not finish an in-flight reload or restart within the bound, so it was not restarted',
        'state': 'the Wazuh agent service state could not be read or its unit is not loaded',
        'proc': 'the Wazuh agent service processes could not be read from /proc',
        'clock': 'the boot-relative clock could not be read from /proc/uptime',
        'survived': 'a wazuh-syscheckd that started before the audit endpoint was listening survived the agent restart, so who-data cannot connect',
        'process': 'the Wazuh agent service did not have exactly one wazuh-syscheckd after the agent restart',
        'endpoint': 'the audit endpoint was no longer listening after the agent restart',
        'stream': 'the restarted wazuh-syscheckd did not connect to the audit endpoint after the agent restart',
        'watch': 'wazuh-syscheckd connected to the audit endpoint but no wazuh_fim kernel audit watch appeared after the agent restart',
    }

    def test_every_new_refusal_is_a_typed_clean_fixed_literal_with_its_own_scenario(self):
        # Same contract as TypedErrorContractTests: a fixed literal that typed_error passes through unchanged, so the
        # operator reads it as written. Then the converse: every Refused literal this change added to the ensure path is
        # in the table below and a scenario of its own raises exactly it (a literal nobody can reach is dead text).
        tree = ast.parse((existing.REPO / 'playbooks/apply/files/wazuh-transaction.py').read_text())
        scanned = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in ('AuditRuntime', 'Agent'):
                for function in (n for n in node.body if isinstance(n, ast.FunctionDef)):
                    if (node.name, function.name) in (('Agent', 'whodata_ensure'), ('AuditRuntime', 'boot_ticks'), ('AuditRuntime', 'agent_unit'),
                                                      ('AuditRuntime', 'agent_processes'), ('AuditRuntime', 'await_fresh_stream'),
                                                      ('AuditRuntime', 'settled'), ('AuditRuntime', 'syscheckd_starts'), ('AuditRuntime', 'restart_scripts'),
                                                      ('AuditRuntime', 'fresh_armed')):
                        for call in (n for n in ast.walk(function) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'Refused'):
                            self.assertEqual(len(call.args), 1)
                            self.assertIsInstance(call.args[0], ast.Constant, 'line %d: a refusal here must be a fixed literal' % call.lineno)
                            scanned[call.args[0].value] = function.name
        earlier = {'the who-data endpoint ensure supports only the RedHat family',
                   'the Wazuh audit plugin is not active, so no who-data endpoint can exist',
                   'external audit endpoint did not appear after reloading the audit daemon',
                   'the external audit endpoint socket has no listener'}
        self.assertEqual(set(scanned) - earlier, set(self.NEW_REFUSALS.values()), 'a new literal without a scenario, or a scenario without its literal')
        for literal in self.NEW_REFUSALS.values():
            self.assertEqual(w.typed_error('refused', literal), {'error': literal, 'error_kind': 'refused'})
        scenarios = {
            'settle': lambda m: m.begin_reload(),
            'state': lambda m: setattr(m, 'show_output', ''),
            'proc': lambda m: setattr(m, 'bad_stat_on_restart', True),
            'clock': lambda m: (setattr(m, 'uptime_unreadable', True), m.write_uptime()),
            'survived': lambda m: setattr(m, 'restart_replaces_syscheckd', False),
            'process': lambda m: setattr(m, 'restart_starts_syscheckd', False),
            'endpoint': lambda m: setattr(m, 'endpoint_lost_on_restart', True),
            'stream': lambda m: setattr(m, 'health_check_fails', True),
            'watch': lambda m: setattr(m, 'arms_watches', False),
        }
        self.assertEqual(set(scenarios), set(self.NEW_REFUSALS))
        for key, setup in scenarios.items():
            with self.subTest(refusal=key):
                text, _ = self.raised(setup)
                self.assertEqual(text, self.NEW_REFUSALS[key])

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
