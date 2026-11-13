#!/usr/bin/env python3
"""Wazuh agent version-skew hotfix helper (pilot hotfix wazuh-agent-skew).

Runs as root on an agent host through ansible.builtin.script, driven by
playbooks/apply/wazuh-fim-agent-skew-hotfix.yml. Spec:
docs/verification/wazuh-fim-agent-skew-hotfix.md.

An agent whose installed release V is strictly newer than the manager release
M is refused by wazuh-fim-apply.yml with no downgrade path, so the host cannot
be redeployed. This helper takes such a host back to "no agent installed and no
pilot-owned package policy left" so a later `pilot deploy` installs M.

Actions
  inspect   read-only: installed release, whether it is newer than M (the ONLY
            place that comparison is made), pilot-owned package policy, and the
            enrollment ID/name from client.keys (never the key itself)
  quiesce   stop and disable wazuh-agent (reversible; nothing is deleted)
  remove    release pilot's hold/versionlock/apt preference, purge the package,
            drop client.keys, and retire the audit plugin the package left running
  verify    the end state checks of the spec (C1-C5), fail-closed

Every action re-inspects first and refuses on anything it does not recognise.
Refusals are typed JSON ({"error", "error_kind"}) with exit 1; tool stderr is
never echoed (it may carry private values). The constants below are duplicated
from wazuh-transaction.py on purpose (that file is a durable transaction and is
not touched); internal/spec/wazuh_agent_hotfix_regression_test.go locks them
equal.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path('/var/backups/pilot/wazuh')
PACKAGE = 'wazuh-agent'
SERVICE = 'wazuh-agent'
PREF = Path('/etc/apt/preferences.d/pilot-wazuh-agent')
LOCKS = Path('/etc/dnf/plugins/versionlock.list')
BEGIN = '# BEGIN PILOT WAZUH VERSIONLOCK\n'
END = '# END PILOT WAZUH VERSIONLOCK\n'
CLIENT_KEYS = Path('/var/ossec/etc/client.keys')
AUDIT_PLUGIN = Path('/etc/audit/plugins.d/af_wazuh.conf')
AUDIT_ENDPOINT = '/var/ossec/queue/sockets/audit'
AUDIT_RETIRE_WAIT = 20
# EL's auditd.service sets RefuseManualStop, so `systemctl restart auditd` is refused there; the auditd
# package's own legacy action (stop, then systemctl start) is the supported restart.
AUDIT_LEGACY_RESTART = Path('/usr/libexec/initscripts/legacy-actions/auditd/restart')
WRITER_MARKERS = ('writer-active.json', 'agent-active.json', 'central-active.json')

MANAGER_RELEASE = re.compile(r'^4\.14\.(0|[1-9][0-9]*)$')
AGENT_RELEASE = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')
PREF_TEXT = re.compile(
    r'Package: wazuh-agent\nPin: version 4\.14\.(?:0|[1-9][0-9]*)-[1-9][0-9]*\nPin-Priority: 1000\n\n'
    r'Package: wazuh-agent\nPin: version \*\nPin-Priority: -1\n')
OWNED_LOCK = re.compile(r'wazuh-agent-0:4\.14\.(?:0|[1-9][0-9]*)-[1-9][0-9]*\.x86_64\n')
CLIENT_KEY_ID = re.compile(r'^[0-9]{3,}$')
OWNER = re.compile(r'^[a-f0-9]{32}$')
DPKG_ABSENT = 'dpkg-query: no packages found matching wazuh-agent'
RPM_ABSENT = 'package wazuh-agent is not installed'


class Refused(RuntimeError):
    """A typed, fixed-text refusal. Never built from tool output."""


def typed_error(kind, text):
    assert kind in ('refused', 'native')
    return {'error': re.sub(r'[^ !#-\[\]-z|~]', '?', str(text))[:300], 'error_kind': kind}


class Runner:
    def run(self, argv, allowed=(0,), timeout=120, operation=None):
        label = operation or str(argv[0])
        try:
            result = subprocess.run([str(a) for a in argv], text=True, capture_output=True,
                                    timeout=timeout, env=dict(os.environ, LC_ALL='C', DEBIAN_FRONTEND='noninteractive'))
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refused('operation unavailable or timed out: ' + label) from exc
        if result.returncode not in allowed:
            raise Refused('operation failed: ' + label + ' rc=' + str(result.returncode))
        return result


def release_tuple(value, pattern, what):
    match = pattern.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise Refused('unsupported ' + what + ' release')
    return tuple(int(part) for part in value.split('.'))


class Host:
    def __init__(self, family, runner=None):
        if family not in ('Debian', 'RedHat'):
            raise Refused('unknown OS family')
        self.family = family
        self.r = runner or Runner()

    # -- observation (read-only) ---------------------------------------------------

    def writer_idle(self, owner=''):
        """Refuse while any Wazuh writer or unfinished transaction owns the host.

        A mutating action runs under the writer claim this hotfix took itself, so it names
        its owner and exactly that one writer marker is accepted; a read-only inspection names
        none and accepts nothing. Journals (agent-active.json, central-active.json) are never
        accepted: they mean an interrupted transaction that needs its own recovery.
        """
        for name in WRITER_MARKERS:
            path = ROOT / name
            if not (path.exists() or path.is_symlink()):
                continue
            if name == 'writer-active.json' and owner and self.owns_writer(path, owner):
                continue
            raise Refused('a Wazuh writer or unfinished transaction is active on this host (' + name
                          + '); recover or finish it before the hotfix')
        if owner and not (ROOT / 'writer-active.json').exists():
            raise Refused('this hotfix does not hold the Wazuh writer claim it must run under')

    @staticmethod
    def owns_writer(path, owner):
        if path.is_symlink() or not OWNER.fullmatch(owner):
            return False
        try:
            item = json.loads(path.read_text())
        except (OSError, ValueError):
            return False
        return isinstance(item, dict) and item.get('owner') == owner and item.get('component') == 'agent'

    def installed(self):
        """The installed agent package version, or '' when it is not installed.

        The native probes and their absent-package answers are the ones
        wazuh-transaction.py's Agent.installed() recorded from real hosts.
        """
        if self.family == 'Debian':
            result = self.r.run(['dpkg-query', '-W', '-f=${Status}\t${Version}\t${Architecture}', PACKAGE], allowed=(0, 1))
            if result.returncode == 1:
                if result.stdout or result.stderr.strip() != DPKG_ABSENT:
                    raise Refused('Debian installed-package probe failed')
                return ''
            fields = result.stdout.split('\t')
            if len(fields) != 3:
                raise Refused('unknown agent package state')
            if fields[0].endswith(' not-installed'):
                return ''
            if fields[0] not in ('install ok installed', 'hold ok installed') or fields[2] != 'amd64':
                raise Refused('unknown agent package state or architecture; purge or repair it by hand first')
            return fields[1]
        result = self.r.run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}\t%{ARCH}', PACKAGE], allowed=(0, 1))
        if result.returncode == 1:
            if result.stdout.strip() != RPM_ABSENT:
                raise Refused('RPM installed-package probe failed')
            return ''
        fields = result.stdout.split('\t')
        if len(fields) != 2 or fields[1] != 'x86_64':
            raise Refused('unknown agent RPM architecture')
        return fields[0]

    @staticmethod
    def read_policy_file(path):
        if path.is_symlink():
            raise Refused('package policy path is a symlink')
        if not path.exists():
            return None
        info = path.stat()
        if not path.is_file() or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused('package policy file has unsafe ownership or permissions')
        return path.read_text()

    def policy(self):
        """pilot's own package policy on this host. Foreign content is reported, not touched."""
        if self.family == 'Debian':
            text = self.read_policy_file(PREF)
            if text is not None and not PREF_TEXT.fullmatch(text):
                raise Refused('foreign ownership at the managed APT preference path')
            held = self.r.run(['apt-mark', 'showhold'], operation='native APT holds').stdout.split()
            return {'owned': text is not None, 'foreign_overlap': False,
                    'held': any(value in (PACKAGE, PACKAGE + ':amd64') for value in held)}
        text = self.read_policy_file(LOCKS)
        if text is None:
            return {'owned': False, 'foreign_overlap': False, 'held': False}
        owned, foreign = self.split_locks(text)
        overlap = any(PACKAGE in line for line in foreign.splitlines()
                      if line.strip() and not line.lstrip().startswith('#'))
        return {'owned': owned is not None, 'foreign_overlap': overlap, 'held': owned is not None}

    @staticmethod
    def split_locks(text):
        """Returns (owned rule or None, text without the owned block)."""
        if not text.count(BEGIN) and not text.count(END):
            return None, text
        if text.count(BEGIN) != 1 or text.count(END) != 1:
            raise Refused('ambiguous owned versionlock block')
        before, rest = text.split(BEGIN)
        owned, after = rest.split(END)
        if not OWNED_LOCK.fullmatch(owned):
            raise Refused('unknown owned Wazuh versionlock rule')
        return owned, before + after

    @staticmethod
    def enrolled():
        """Whether client.keys holds anything; says nothing about whether it is well formed."""
        path = CLIENT_KEYS
        if path.is_symlink():
            raise Refused('client.keys is a symlink')
        return path.exists() and path.stat().st_size > 0

    def registration(self):
        """The agent's enrollment ID and name; the key (third field onward) is never read out."""
        path = CLIENT_KEYS
        if not self.enrolled():
            return None
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        if len(lines) != 1:
            raise Refused('client.keys does not hold exactly one enrollment')
        fields = lines[0].split()
        if len(fields) != 4 or not CLIENT_KEY_ID.fullmatch(fields[0]) or not fields[1]:
            raise Refused('client.keys enrollment line is not parseable')
        return {'id': fields[0], 'name': fields[1]}

    def inspect(self, manager, owner=''):
        self.writer_idle(owner)
        installed = self.installed()
        policy = self.policy()
        enrolled = self.enrolled()
        release = installed.split('-')[0] if installed else ''
        skewed = False
        if installed:
            current = release_tuple(release, AGENT_RELEASE, 'agent')
            if not manager:
                raise Refused('the manager release is required to judge an installed agent')
            skewed = current > release_tuple(manager, MANAGER_RELEASE, 'manager')
        if skewed and policy['foreign_overlap']:
            raise Refused('a foreign versionlock rule names wazuh-agent and would block the reinstall')
        # Only a host that is going to be changed needs a well-formed enrollment; a compatible
        # host's client.keys is none of this hotfix's business and must not make the run refuse.
        registration = self.registration() if skewed else None
        return {'family': self.family, 'installed': installed, 'release': release, 'manager': manager,
                'skewed': skewed, 'enrolled': enrolled, 'registration': registration, 'policy': policy,
                'audit_orphaned': self.audit_plugin_orphaned()}

    def stale_audit_listener(self):
        """Whether a unix socket is still listening on the Wazuh who-data endpoint.

        Real `ss -xl` line (AlmaLinux 9.8): `u_str LISTEN 0 1 /var/ossec/queue/sockets/audit 41824 * 0`.
        """
        return AUDIT_ENDPOINT in self.r.run(['ss', '-xl'], operation='unix listeners').stdout

    def audit_plugin_orphaned(self):
        """The package (and its audit plugin config) is gone but auditd still runs the plugin.

        Removing the package deletes /etc/audit/plugins.d/af_wazuh.conf and /var/ossec, yet auditd keeps
        the audisp-af_unix process it started, with a listener on the now-deleted endpoint, on both OS
        families (a real purge on Ubuntu 24.04 and a real RPM removal on AlmaLinux 9.8, 2026-11-13). A later
        reinstall then finds no endpoint, and a SIGHUP does not respawn a plugin whose config is unchanged:
        on EL, pilot deploy failed at its who-data step with `external audit endpoint did not appear after
        reloading the audit daemon`; on Debian the same orphan stays unnoticed because that apply has no
        such step, and a syscheckd that starts without an endpoint silently falls back to real-time.
        """
        if AUDIT_PLUGIN.exists() or AUDIT_PLUGIN.is_symlink():
            return False
        return self.stale_audit_listener()

    def restart_auditd(self):
        if self.family == 'RedHat':
            if not AUDIT_LEGACY_RESTART.exists():
                raise Refused('this host has no supported way to restart auditd')
            self.r.run([AUDIT_LEGACY_RESTART], timeout=60, operation='restart auditd')
        else:
            self.r.run(['systemctl', 'restart', 'auditd'], timeout=60, operation='restart auditd')

    def retire_audit_plugin(self):
        """Restart auditd so it forgets the orphaned plugin; only when an orphaned listener exists.

        Both lighter ways were tried on real hosts (2026-11-13) and both leave auditd's plugin dispatcher
        in a state the later ordinary apply cannot recover from with its single SIGHUP: reloading with the
        config gone makes the dispatcher exit (`After reconfigure, there are no active plugins, exiting`)
        and a later SIGHUP then reports `initialized with 1 active plugins` without ever starting the
        plugin; killing the plugin process makes auditd respawn it until `exceeded max_restarts`. A
        restart gives the state of a host that never ran the plugin, which is what the apply expects. The
        audit daemon is down for about a second while kernel audit events queue.
        """
        if not self.audit_plugin_orphaned():
            return False
        self.restart_auditd()
        waited = 0
        while self.stale_audit_listener():
            if waited >= AUDIT_RETIRE_WAIT:
                raise Refused('the audit plugin listener on the removed Wazuh endpoint is still present after restarting auditd')
            self.sleep(1)
            waited += 1
        return True

    @staticmethod
    def sleep(seconds):
        time.sleep(seconds)

    def unit_state(self):
        active = self.r.run(['systemctl', 'is-active', SERVICE], allowed=(0, 3, 4), operation='service state').stdout.strip()
        enabled = self.r.run(['systemctl', 'is-enabled', SERVICE], allowed=(0, 1, 4), operation='service enablement').stdout.strip()
        return active, enabled

    # -- mutation ---------------------------------------------------------------------

    def require_actionable(self, manager, owner):
        """Re-read the state; only a skewed host, or one a previous hotfix half cleaned, may be changed."""
        if not owner:
            raise Refused('a mutating action requires the owner of this hotfix\'s Wazuh writer claim')
        state = self.inspect(manager, owner)
        residue = (not state['installed']) and (state['policy']['owned'] or state['enrolled'] or state['audit_orphaned'])
        if not state['skewed'] and not residue:
            raise Refused('this host is not newer than the manager; refusing to change it')
        return state

    def quiesce(self, manager, owner=''):
        state = self.require_actionable(manager, owner)
        changed = False
        if state['installed']:
            active, enabled = self.unit_state()
            if active == 'active':
                self.r.run(['systemctl', 'stop', SERVICE], timeout=180, operation='stop agent')
                changed = True
            if enabled in ('enabled', 'enabled-runtime'):
                self.r.run(['systemctl', 'disable', SERVICE], operation='disable agent')
                changed = True
            if self.unit_state()[0] == 'active':
                raise Refused('the agent is still active after stop')
        return {'changed': changed, 'registration': state['registration']}

    def remove(self, manager, owner=''):
        state = self.require_actionable(manager, owner)
        changed = False
        if self.family == 'Debian':
            if state['policy']['held']:
                self.r.run(['apt-mark', 'unhold', PACKAGE], operation='release the agent hold')
                changed = True
            if state['policy']['owned']:
                os.unlink(PREF)
                changed = True
            if state['installed']:
                # purge, not remove: a package left in "deinstall ok config-files" is refused as an
                # unknown state by wazuh-transaction.py's Agent.installed() and blocks the redeploy.
                self.r.run(['apt-get', 'purge', '-y', '-o', 'DPkg::Lock::Timeout=300', PACKAGE],
                           timeout=900, operation='purge the agent package')
                changed = True
        else:
            if state['policy']['owned']:
                text = self.read_policy_file(LOCKS)
                _, foreign = self.split_locks(text)
                self.atomic_write(LOCKS, foreign)
                changed = True
            if state['installed']:
                self.r.run(['dnf', 'remove', '-y', PACKAGE], timeout=900, operation='remove the agent package')
                changed = True
        if CLIENT_KEYS.exists() or CLIENT_KEYS.is_symlink():
            os.unlink(CLIENT_KEYS)
            changed = True
        if self.retire_audit_plugin():
            changed = True
        return {'changed': changed}

    @staticmethod
    def atomic_write(path, text):
        info = path.stat()
        fd, temporary = tempfile.mkstemp(dir=str(path.parent), prefix='.' + path.name + '.pilot-')
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, info.st_mode & 0o7777)
            os.chown(temporary, info.st_uid, info.st_gid)
            os.replace(temporary, path)
        except BaseException:
            if os.path.exists(temporary):
                os.unlink(temporary)
            raise

    def verify(self):
        """The spec's end state for a removed host (C1-C5); fail-closed, no partial credit."""
        problems = []
        if self.installed():
            problems.append('wazuh-agent is still installed')
        policy = self.policy()
        if policy['held'] or policy['owned']:
            problems.append('a pilot package hold or policy artifact is still present')
        if CLIENT_KEYS.exists() and CLIENT_KEYS.stat().st_size > 0:
            problems.append('client.keys still holds an enrollment')
        active, enabled = self.unit_state()
        if active == 'active' or enabled in ('enabled', 'enabled-runtime'):
            problems.append('the wazuh-agent service is still active or enabled')
        if self.stale_audit_listener():
            problems.append('a listener is still bound to the Wazuh who-data endpoint')
        if problems:
            raise Refused('; '.join(problems))
        return {'removed': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'quiesce', 'remove', 'verify'])
    parser.add_argument('--family', required=True, choices=['Debian', 'RedHat'])
    parser.add_argument('--manager', default='')
    parser.add_argument('--owner', default='')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error('the Wazuh agent hotfix requires root')
    try:
        host = Host(args.family)
        if args.action == 'inspect':
            value = host.inspect(args.manager)
        elif args.action == 'quiesce':
            value = host.quiesce(args.manager, args.owner)
        elif args.action == 'remove':
            value = host.remove(args.manager, args.owner)
        else:
            value = host.verify()
        print(json.dumps(value, sort_keys=True))
        return 0
    except Refused as exc:
        print(json.dumps(typed_error('refused', exc)))
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps(typed_error('native', 'native probe or state operation failed')))
        return 1


if __name__ == '__main__':
    sys.exit(main())
