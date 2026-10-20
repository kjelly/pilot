#!/usr/bin/env python3
"""Exercise first/partial TLS failure rollback only on disposable aq-* VMs."""

import argparse
import json
import os
import pathlib
import runpy
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pilot', required=True)
    parser.add_argument('--vars', required=True, type=pathlib.Path)
    parser.add_argument('--evidence-dir', required=True, type=pathlib.Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    base = json.loads(args.vars.read_text())
    helper = runpy.run_path(str(pathlib.Path(__file__).with_name('audit-forward-queue-test.py')))

    def remote(host, code):
        assert host in ('aq-log', 'aq-ubuntu', 'aq-el')
        return helper['remote'](args.pilot, host, code)

    def apply(host, role, name, values, failure=False):
        variables = args.evidence_dir / (name + '-vars.json')
        variables.write_text(json.dumps(values))
        with (args.evidence_dir / (name + '-inventory.yml')).open('w') as output:
            subprocess.run([args.pilot, 'vm-target', 'topology', 'inventory', '--topology',
                            'docs/topologies/audit-forward-queue-topology.yaml'], stdout=output, check=True)
        play, tag = ('log-server', 'C4') if role == 'receiver' else ('audit-log-forwarding', 'C17')
        command = [args.pilot, 'vm-target', 'run', '--group', 'log-server=aq-log', '--group',
                   'audit-log-forwarding=aq-log,aq-ubuntu,aq-el', '--sandbox', '--sandbox-image',
                   'pilot-cli:latest', 'playbooks/apply/' + play + '-apply.yml', '--limit', host,
                   '--tags', tag, '-e', '@' + str(variables.resolve())]
        with (args.evidence_dir / (name + '.log')).open('w') as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=300)
        assert (result.returncode != 0) == failure, (name, result.returncode)

    def snapshot(host, role):
        return json.loads(remote(host, """
import hashlib,json,pathlib,subprocess
directory=pathlib.Path('/etc/rsyslog.d/pilot-relp-ROLE')
assert subprocess.run(['systemctl','is-active','--quiet','rsyslog']).returncode==0
files={}
for name in ['ca.pem','cert.pem','key.pem','profile.json']:
 p=directory/name
 if p.exists():
  s=p.stat();files[name]=[hashlib.sha256(p.read_bytes()).hexdigest(),s.st_mode,s.st_uid,s.st_gid]
fragment=pathlib.Path('/etc/rsyslog.d/FRAGMENT')
files['fragment']=hashlib.sha256(fragment.read_bytes()).hexdigest()
for name in ['ca.pem','cert.pem','key.pem','profile.json']:
 assert (pathlib.Path.home()/name).read_text()=='unrelated pilot rollback test '+name
print(json.dumps(files,sort_keys=True))
""".replace('ROLE', role).replace('FRAGMENT', '10-siem-receiver.conf' if role == 'receiver' else '99-siem-forward.conf')))

    for host, role in [('aq-log', 'receiver'), ('aq-ubuntu', 'sender'), ('aq-el', 'sender')]:
        saved = remote(host, """
import pathlib,shutil,tempfile
directory=pathlib.Path('/etc/rsyslog.d/pilot-relp-ROLE')
saved=pathlib.Path(tempfile.mkdtemp(prefix='pilot-relp-review-',dir='/run'))
for name in ['ca.pem','cert.pem','key.pem','profile.json']:
 p=pathlib.Path.home()/name
 assert not p.exists(), 'refuse to replace an unrelated pre-existing basename'
for name in ['ca.pem','cert.pem','key.pem','profile.json']:
 shutil.copy2(directory/name,saved/name)
 p=pathlib.Path.home()/name;p.write_text('unrelated pilot rollback test '+name);p.chmod(0o600)
print(saved)
""".replace('ROLE', role)).strip()
        try:
            for scenario in ('existing-relp', 'fresh', 'tcp-profile', 'partial'):
                name = host + '-' + scenario
                tcp = dict(base, siem_forward_transport='tcp', siem_receiver_relp_enabled=False)
                if scenario != 'existing-relp':
                    apply(host, role, name + '-tcp', tcp)
                    remote(host, """
import pathlib,shutil
directory=pathlib.Path('/etc/rsyslog.d/pilot-relp-ROLE')
assert not any((directory/n).exists() for n in ['ca.pem','cert.pem','key.pem'])
if SCENARIO=='fresh':(directory/'profile.json').unlink()
if SCENARIO=='partial':
 for name in ['ca.pem','key.pem']:
  p=directory/name;shutil.copy2(pathlib.Path(SAVED)/name,p);p.chmod(0o600)
""".replace('ROLE', role).replace('SCENARIO', repr(scenario)).replace('SAVED', repr(saved)))
                before = snapshot(host, role)
                bad = dict(base, siem_relp_key_pem=base['relp_test_identities']['unauthorized']['key'])
                apply(host, role, name + '-bad-key', bad, failure=True)
                assert snapshot(host, role) == before, name + ' did not restore the exact original files/modes'
                if scenario == 'existing-relp':
                    remote(host, "import subprocess;subprocess.run(['/usr/local/libexec/pilot-siem-relp-check','" + role + "'],check=True,timeout=35)")
                print(name + ' material_and_profile_restored unrelated_basenames_preserved=PASS', flush=True)
                apply(host, role, name + '-recover', base)
                remote(host, "import subprocess;subprocess.run(['/usr/local/libexec/pilot-siem-relp-check','" + role + "'],check=True,timeout=35)")
        finally:
            remote(host, """
import pathlib,shutil
saved=pathlib.Path(SAVED)
assert saved.parent==pathlib.Path('/run') and saved.name.startswith('pilot-relp-review-')
for name in ['ca.pem','cert.pem','key.pem','profile.json']:
 p=pathlib.Path.home()/name
 if p.is_file() and p.read_text()=='unrelated pilot rollback test '+name:p.unlink()
shutil.rmtree(saved)
""".replace('SAVED', repr(saved)))


if __name__ == '__main__':
    main()
