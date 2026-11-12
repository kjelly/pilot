#!/usr/bin/env python3
"""Read-only probes of the kernel audit list, and the bounded who-data re-arm.

audit-log-forwarding-apply.yml shares the kernel audit rule list with the Wazuh
agent (who-data keeps `wazuh_fim` watches in it). `augenrules --load` and an
auditd restart replace that whole list, so this helper lets the playbook

  probe  - read, without changing anything, what the list holds (managed keys,
           the `wazuh_fim` watch set), whether `augenrules --check` sees a
           difference, and whether wazuh-agent exists and is active;
  rearm  - after the playbook disturbed the list: wait (bounded) for auditd and
           the audisp af_unix listener, restart wazuh-agent once, wait (bounded)
           until the kernel holds every `wazuh_fim` watch it held before.

Every state it cannot read is reported as such ("unreadable", "unknown"), never
as "no watches": the caller decides what an unreadable state means. Output is
one JSON object on stdout. Exit status: probe 0, rearm 0 on success and 1 on a
typed failure, 2 for a malformed invocation.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import time

# The same pattern text as AuditRuntime.ready in wazuh-transaction.py, which is
# the coordinator's own definition of "a Wazuh who-data watch".
# TestRegression_WhodataWatchPatternHasOneSource keeps the two (and the
# `auditctl -l | grep` of spec row C23) from drifting apart.
WAZUH_FIM_WATCH = r'(?:key=|\-k\s+)wazuh_fim(?:\s|$)'
ENDPOINT = '/var/ossec/queue/sockets/audit'
LISTENER = 'audisp-af_unix'

# `auditctl -l` prints a watch rule's key as `-k <key>` and a syscall rule's as
# `-F key=<key>`; the rules files this role renders use `-k <key>` for both.
KEY_FLAG = re.compile(r'(?:^|\s)-k\s+(\S+)')
KEY_FIELD = re.compile(r'(?:^|\s)-F\s+key=(\S+)')

CHECK_UNCHANGED = ': No change'
CHECK_CHANGED = ': Rules have changed and should be updated'


def run(argv, timeout):
    """(rc, stdout) of argv, or None when the program is missing or timed out."""
    try:
        done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                              encoding='utf-8', errors='replace')
    except (OSError, subprocess.SubprocessError):
        return None
    return done.returncode, done.stdout


def unit_properties(unit, names):
    """The requested systemd properties of a unit, or None when they cannot be read."""
    result = run(['systemctl', 'show', unit] + ['--property=' + name for name in names], 30)
    if result is None or result[0] != 0:
        return None
    values = {}
    for line in result[1].splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value
    return values if all(name in values for name in names) else None


def agent_state():
    """absent | inactive | active | unknown for the wazuh-agent unit."""
    values = unit_properties('wazuh-agent', ['LoadState', 'ActiveState'])
    if values is None:
        return 'unknown'
    if values['LoadState'] == 'not-found':
        return 'absent'
    if values['ActiveState'] in ('active', 'reloading'):
        return 'active'
    if values['ActiveState'] in ('inactive', 'failed', 'deactivating'):
        return 'inactive'
    return 'unknown'


def kernel_list():
    """('absent'|'unreadable'|'ok', lines) for `auditctl -l`."""
    if shutil.which('auditctl') is None:
        return 'absent', []
    result = run(['auditctl', '-l'], 30)
    if result is None or result[0] != 0:
        return 'unreadable', []
    return 'ok', result[1].splitlines()


def watches(lines):
    return sorted({line for line in lines if re.search(WAZUH_FIM_WATCH, line)})


def keys(line):
    return KEY_FLAG.findall(line) + KEY_FIELD.findall(line)


def key_counts(lines):
    counts = {}
    for line in lines:
        for key in keys(line):
            counts[key] = counts.get(key, 0) + 1
    return counts


def managed_state(rules_path, kernel_state, kernel_lines):
    """present | missing | unknown | n/a: does the kernel hold every rule key the rules file declares?

    Counted per key: the file declares a key once per rule, and the kernel lists
    one line per rule. A key the kernel lists fewer times than the file declares
    it is missing. "n/a" when there is no rules file to compare (a preview on a
    host this role has not rendered yet), "unknown" when the kernel list cannot
    be read; neither counts as "present".
    """
    try:
        with open(rules_path, encoding='utf-8') as handle:
            declared = [line for line in handle.read().splitlines() if not line.lstrip().startswith('#')]
    except OSError:
        return 'n/a', {}
    want = key_counts(declared)
    if kernel_state != 'ok':
        return 'unknown', want
    have = key_counts(kernel_lines)
    missing = sorted(key for key, count in want.items() if have.get(key, 0) < count)
    return ('missing' if missing else 'present'), want


def augenrules_state():
    """absent | unreadable | no_change | changed | unrecognized for `augenrules --check`.

    The script exits 0 whether or not the generated /etc/audit/audit.rules
    differs from /etc/audit/rules.d and says which on stdout, prefixed with its
    own path.
    """
    if shutil.which('augenrules') is None:
        return 'absent'
    result = run(['augenrules', '--check'], 60)
    if result is None or result[0] != 0:
        return 'unreadable'
    lines = [line.strip() for line in result[1].splitlines()]
    unchanged = any(line.endswith(CHECK_UNCHANGED) for line in lines)
    changed = any(line.endswith(CHECK_CHANGED) for line in lines)
    if unchanged == changed:
        return 'unrecognized'
    return 'no_change' if unchanged else 'changed'


def probe(args):
    kernel_state, lines = kernel_list()
    document = {'schema': 1, 'agent': agent_state(), 'kernel': kernel_state, 'watches': watches(lines)}
    if args.rules:
        document['managed'], expected = managed_state(args.rules, kernel_state, lines)
        document['managed_keys'] = sorted(expected)
        document['augenrules'] = augenrules_state()
    print(json.dumps(document, sort_keys=True))
    return 0


def listener_up():
    """True when the audisp af_unix plugin listens on the Wazuh endpoint; None when ss cannot say."""
    if shutil.which('ss') is None:
        return None
    result = run(['ss', '-xHap'], 30)
    if result is None or result[0] != 0:
        return None
    for line in result[1].splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[0] == 'u_str' and fields[1] == 'LISTEN' and fields[4] == ENDPOINT \
                and LISTENER in line:
            return True
    return False


def auditd_active():
    values = unit_properties('auditd', ['ActiveState'])
    return None if values is None else values['ActiveState'] == 'active'


def failure(reason, restarted, **detail):
    """A typed failure. `restarted` says whether wazuh-agent was restarted before it."""
    detail.update({'state': 'failed', 'reason': reason, 'restarted': restarted})
    print(json.dumps(detail, sort_keys=True))
    return 1


def rearm(args):
    try:
        expected = json.loads(args.expect_json)
        if not isinstance(expected, list) or not expected or not all(isinstance(item, str) for item in expected):
            raise ValueError('not a non-empty list of strings')
    except ValueError as exc:
        print(json.dumps({'state': 'failed', 'reason': 'bad_invocation', 'detail': str(exc)}))
        return 2
    interval = max(args.interval, 0.01)

    deadline = time.monotonic() + args.endpoint_timeout
    while True:
        active, listening = auditd_active(), listener_up()
        if active and listening:
            break
        if time.monotonic() >= deadline:
            return failure('endpoint_not_ready', False, auditd_active=active, listener=listening,
                           wait_seconds=args.endpoint_timeout)
        time.sleep(interval)

    restarted = run(['systemctl', 'restart', 'wazuh-agent'], 120)
    if restarted is None or restarted[0] != 0:
        return failure('agent_restart_failed', True)

    deadline = time.monotonic() + args.watch_timeout
    while True:
        state, lines = kernel_list()
        have = watches(lines)
        if state == 'ok' and set(expected).issubset(have):
            print(json.dumps({'state': 'restored', 'restarted': True, 'watches': have}, sort_keys=True))
            return 0
        if time.monotonic() >= deadline:
            if state != 'ok':
                return failure('kernel_unreadable', True, wait_seconds=args.watch_timeout)
            return failure('watches_not_restored', True, missing=sorted(set(expected) - set(have)),
                           wait_seconds=args.watch_timeout)
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='action', required=True)
    probe_parser = sub.add_parser('probe')
    probe_parser.add_argument('--rules', default='')
    rearm_parser = sub.add_parser('rearm')
    rearm_parser.add_argument('--expect-json', required=True)
    rearm_parser.add_argument('--endpoint-timeout', type=float, default=30.0)
    rearm_parser.add_argument('--watch-timeout', type=float, default=60.0)
    rearm_parser.add_argument('--interval', type=float, default=1.0)
    args = parser.parse_args()
    return {'probe': probe, 'rearm': rearm}[args.action](args)


if __name__ == '__main__':
    sys.exit(main())
