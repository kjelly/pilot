#!/usr/bin/env python3
"""Verify forwarding rescue against only the disposable aq-* VM topology."""

import argparse
import json
import os
import pathlib
import runpy
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pilot', required=True)
    parser.add_argument('--evidence-dir', required=True, type=pathlib.Path)
    parser.add_argument('--vars', type=pathlib.Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    helper = runpy.run_path(str(pathlib.Path(__file__).with_name('audit-forward-queue-test.py')))

    def remote(host, code):
        assert host in ('aq-ubuntu', 'aq-el')
        return helper['remote'](args.pilot, host, code)

    def apply(host, name):
        inventory = args.evidence_dir / (name + '-inventory.yml')
        with inventory.open('w') as output:
            subprocess.run([args.pilot, 'vm-target', 'topology', 'inventory', '--topology',
                            'docs/topologies/audit-forward-queue-topology.yaml'], stdout=output, check=True)
        command = [args.pilot, 'vm-target', 'run', '--group', 'log-server=aq-log', '--group',
                   'audit-log-forwarding=aq-log,aq-ubuntu,aq-el', '--sandbox',
                   '--sandbox-image', 'pilot-cli:latest', 'playbooks/apply/audit-log-forwarding-apply.yml',
                   '--limit', host, '--tags', 'C19']
        if args.vars:
            command += ['-e', '@' + str(args.vars.resolve())]
        with (args.evidence_dir / (name + '.log')).open('w') as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=300)
        assert result.returncode != 0, name + ' unexpectedly succeeded'

    for host in ('aq-ubuntu', 'aq-el'):
        before = remote(host, """
import hashlib,json,pathlib,subprocess
p=pathlib.Path('/etc/rsyslog.conf');backup=p.with_name('rsyslog.conf.pilot-review-hold')
assert p.is_file() and not backup.exists()
assert subprocess.run(['systemctl','is-active','--quiet','rsyslog']).returncode==0
identity=subprocess.check_output(['systemctl','show','rsyslog','-p','InvocationID','--value'],text=True).strip()
assert identity
config=hashlib.sha256(pathlib.Path('/etc/rsyslog.d/99-siem-forward.conf').read_bytes()).hexdigest()
p.rename(backup)
print(json.dumps([identity,config]))
""").strip()
        try:
            apply(host, 'fatal-config-' + host)
            after = remote(host, """
import hashlib,json,pathlib,subprocess
assert not pathlib.Path('/etc/rsyslog.conf').exists()
assert subprocess.run(['systemctl','is-active','--quiet','rsyslog']).returncode==0
identity=subprocess.check_output(['systemctl','show','rsyslog','-p','InvocationID','--value'],text=True).strip()
config=hashlib.sha256(pathlib.Path('/etc/rsyslog.d/99-siem-forward.conf').read_bytes()).hexdigest()
print(json.dumps([identity,config]))
""").strip()
            assert json.loads(before) == json.loads(after), host + ' changed the loaded daemon/config'
            print(host + ' fatal_config_refused runtime_invocation_unchanged=PASS', flush=True)
        finally:
            remote(host, """
import pathlib,subprocess
p=pathlib.Path('/etc/rsyslog.conf');backup=p.with_name('rsyslog.conf.pilot-review-hold')
if backup.exists():backup.rename(p)
subprocess.run(['rsyslogd','-N1'],check=True,capture_output=True)
assert subprocess.run(['systemctl','is-active','--quiet','rsyslog']).returncode==0
""")


if __name__ == '__main__':
    main()
