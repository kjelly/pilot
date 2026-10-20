#!/usr/bin/env python3
"""Exercise rotation, rollback, peer withdrawal and TCP retirement on aq VMs."""

import argparse
import json
import os
import pathlib
import runpy
import subprocess
import time
import uuid


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pilot', required=True)
    p.add_argument('--vars', required=True, type=pathlib.Path)
    p.add_argument('--rotated-vars', required=True, type=pathlib.Path)
    p.add_argument('--evidence-dir', required=True, type=pathlib.Path)
    args = p.parse_args()
    os.umask(0o077)
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    h = runpy.run_path(str(pathlib.Path(__file__).with_name('audit-forward-queue-test.py')))
    remote = lambda host, code: h['remote'](args.pilot, host, code)
    base = json.loads(args.vars.read_text())
    rotated = json.loads(args.rotated_vars.read_text())
    groups = ['--group', 'log-server=aq-log', '--group', 'audit-log-forwarding=aq-log,aq-ubuntu,aq-el']

    def apply(name, values, play='playbooks/test/audit-forward-queue-chain.yml', extra=(), failure=False):
        variables = args.evidence_dir / (name + '-vars.json')
        variables.write_text(json.dumps(values))
        with (args.evidence_dir / (name + '-inventory.yml')).open('w') as f:
            subprocess.run([args.pilot, 'vm-target', 'topology', 'inventory', '--topology',
                            'docs/topologies/audit-forward-queue-topology.yaml'], stdout=f, check=True)
        with (args.evidence_dir / (name + '.log')).open('w') as f:
            r = subprocess.run([args.pilot, 'vm-target', 'run', *groups, '--sandbox',
                                '--sandbox-image', 'pilot-cli:latest', play, '-e', '@' + str(variables), *extra],
                               stdout=f, stderr=subprocess.STDOUT, timeout=900)
        assert (r.returncode != 0) == failure, (name, r.returncode)
        print(name + ('=REFUSED' if failure else '=PASS'), flush=True)

    def snapshot(host, role):
        return remote(host, """
import hashlib,json,pathlib
d=pathlib.Path('/etc/rsyslog.d/pilot-relp-ROLE')
paths=list(d.iterdir())+[pathlib.Path('/etc/rsyslog.d/CONFIG')]
print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()},sort_keys=True))
""".replace('ROLE', role).replace('CONFIG', '99-siem-forward.conf' if role == 'sender' else '10-siem-receiver.conf')).strip()

    # A new valid PEM with the wrong private key must fail before restart;
    # compare every role file and the real fragment after rescue.
    for host, role, play, tag in [
            ('aq-log', 'receiver', 'log-server', 'C4'),
            ('aq-ubuntu', 'sender', 'audit-log-forwarding', 'C17'),
            ('aq-el', 'sender', 'audit-log-forwarding', 'C17')]:
        before = snapshot(host, role)
        bad = dict(base, siem_relp_key_pem=base['relp_test_identities']['unauthorized']['key'])
        apply('mismatched-key-' + host, bad, 'playbooks/apply/' + play + '-apply.yml',
              ['--limit', host, '--tags', tag], failure=True)
        assert snapshot(host, role) == before, 'rollback changed material/config: ' + host
        remote(host, "import subprocess; subprocess.run(['/usr/local/libexec/pilot-siem-relp-check','" + role + "'],check=True,timeout=35)")
        print(host + ' material_and_config_restored=PASS', flush=True)

    before = {host: snapshot(host, 'sender') for host in ['aq-log', 'aq-ubuntu', 'aq-el']}
    apply('rotate', rotated)
    for host in before:
        assert snapshot(host, 'sender') != before[host], 'rotation did not change material'
        print(host, remote(host, "import subprocess; subprocess.run(['/usr/local/libexec/pilot-siem-relp-check','sender'],check=True,timeout=35); print('rotated_peer_and_ACK=PASS')").strip(), flush=True)

    # Removing only this peer must deny the actual daemon, then recover all
    # numbered IDs without restarting that sender when the name is restored.
    denied = dict(rotated, siem_relp_client_names=['aq-log.test', 'aq-el.test'])
    sender_pid = remote('aq-ubuntu', "import subprocess; print(subprocess.check_output(['systemctl','show','rsyslog','-p','MainPID','--value'],text=True).strip())").strip()
    token = 'PILOT-RELP-DENY-' + uuid.uuid4().hex
    try:
        apply('deny-client', denied, 'playbooks/apply/log-server-apply.yml')
        print(remote('aq-ubuntu', """
import subprocess
r=subprocess.run(['/usr/local/libexec/pilot-siem-relp-check','sender'],capture_output=True,timeout=35)
assert r.returncode!=0
print('removed_peer=REFUSED')
""").strip(), flush=True)
        h['send'](args.pilot, 'aq-ubuntu', token, 80, .01)
        time.sleep(5)
        assert not h['received'](args.pilot, token), 'removed peer still delivered'
    finally:
        apply('restore-client', rotated, 'playbooks/apply/log-server-apply.yml')
    expected = {('aq-ubuntu', f, i) for f in ['local6', 'auth', 'authpriv'] for i in range(80)}
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        found = {tuple(k) for k, _ in h['received'](args.pilot, token)}
        if expected <= found:break
        time.sleep(2)
    assert expected <= found, 'withdrawn-peer backlog did not recover'
    assert sender_pid == remote('aq-ubuntu', "import subprocess; print(subprocess.check_output(['systemctl','show','rsyslog','-p','MainPID','--value'],text=True).strip())").strip()
    print('restored_peer_backlog=240/240 sender_restarts=0', flush=True)

    try:
        apply('tcp-retirement', dict(rotated, siem_forward_transport='tcp', siem_receiver_relp_enabled=False))
        for host in before:
            print(host, remote(host, """
import pathlib,subprocess
for role in ['sender','receiver']:
 d=pathlib.Path('/etc/rsyslog.d/pilot-relp-'+role)
 assert not list(d.glob('*.pem')), 'retired private material remains'
subprocess.run(['/usr/local/libexec/pilot-siem-relp-check','sender'],check=True,timeout=35)
print('TCP_delivery_and_private_material_retirement=PASS')
""").strip(), flush=True)
    finally:
        apply('relp-restore', rotated)
    print('rotation_rollback_withdrawal_retirement=PASS', flush=True)


if __name__ == '__main__':
    main()
