#!/usr/bin/env python3
"""Measure numbered-message delivery through a disposable pilot VM topology.

Use only the aq-log/aq-ubuntu/aq-el topology after applying its chain and
test/fixtures/audit-forward-queue-input.yml. No production host is accepted.
"""

import argparse
import concurrent.futures
import json
import subprocess
import time
import uuid


def remote(pilot, host, code):
    wrapper = "import json,subprocess,sys\n"
    wrapper += "r=subprocess.run([sys.executable,'-c'," + repr(code) + "],text=True,capture_output=True)\n"
    wrapper += "print(json.dumps(dict(rc=r.returncode,stdout=r.stdout,stderr=r.stderr)))\n"
    r = subprocess.run([pilot, 'vm-target', 'exec', '--name', host, '--', 'python3', '-'],
                       input=wrapper, text=True, capture_output=True, timeout=180)
    r.check_returncode()
    result = json.loads(r.stdout)
    if result['rc']:
        raise RuntimeError(host + ': ' + str(result))
    return result['stdout']


def service(pilot, state, host='aq-log'):
    # SSH/audit traffic otherwise reactivates rsyslog via syslog.socket while
    # the test believes the receiver is stopped. A runtime mask is removed
    # by every start, including the finally block. Only disposable VMs are used.
    commands = []
    if state in ('stop', 'start'):
        commands.append(['systemctl', 'mask' if state == 'stop' else 'unmask',
                         '--runtime', 'rsyslog.service'])
    commands.append(['systemctl', state, 'rsyslog'])
    remote(pilot, host, 'import subprocess\nfor argv in ' + repr(commands)
           + ':\n    subprocess.run(argv,check=True,timeout=45)')


def send(pilot, host, token, count, delay):
    return remote(pilot, host, f"""
import socket,time
with socket.create_connection(('127.0.0.1',514),timeout=60) as s:
    for i in range({count}):
        for facility,pri in [('local6',182),('auth',38),('authpriv',86)]:
            s.sendall(('<%d>Oct 20 00:00:00 {host} pilot-queue: {token} %s %d\\n' % (pri,facility,i)).encode())
        time.sleep({delay})
print('sent', {count} * 3)
""")


def received(pilot, token):
    return json.loads(remote(pilot, 'aq-log', f"""
import collections,json,pathlib,re
counts=collections.Counter()
for path in pathlib.Path('/var/log/siem').glob('*/*.log'):
    for m in re.finditer(r'{token} (local6|auth|authpriv) (\\d+)', path.read_text(errors='replace')):
        counts[(path.parent.name,m[1],int(m[2]))]+=1
print(json.dumps([[list(k),v] for k,v in counts.items()]))
"""))


def probe_failures(pilot):
    for host in ['aq-ubuntu', 'aq-el']:
        print(host, remote(pilot, host, """
import pathlib,subprocess,time
config=pathlib.Path('/etc/rsyslog.d/99-siem-forward.conf')
saved=config.read_bytes()
stat=config.stat()
probe=['/usr/local/libexec/pilot-siem-queue-check']
for args in [['local6'],['auth','authpriv']]:
    subprocess.run(probe+args,check=True)
try:
    config.write_bytes(saved.replace(b'queue.type="LinkedList"', b'queue.type="Direct"'))
    r=subprocess.run(probe+['local6'],capture_output=True,text=True)
    assert r.returncode and 'invalid queue/retry contract' in r.stderr, r
finally:
    config.write_bytes(saved)
r=subprocess.run(probe+['auth','authpriv'],capture_output=True,text=True)
assert r.returncode and 'not loaded' in r.stderr, r
# Start without the fragment, then put it back with its OLD timestamp. The
# parameter and mtime checks now pass; only actual worker absence can reject it.
hidden=config.with_suffix('.disabled')
try:
    config.rename(hidden)
    subprocess.run(['systemctl','restart','rsyslog'],check=True,timeout=45)
finally:
    if hidden.exists():
        hidden.rename(config)
import os
os.utime(config,ns=(stat.st_atime_ns,stat.st_mtime_ns))
try:
    r=subprocess.run(probe+['local6'],capture_output=True,text=True)
    assert r.returncode and 'workers absent' in r.stderr, r
finally:
    # Leave an explicit pending restart for the subsequent --tags C17 repair.
    config.write_bytes(saved)
print('valid=PASS direct_queue=REFUSED pending_config=REFUSED unloaded_fragment=REFUSED')
""").strip(), flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pilot', required=True)
    p.add_argument('--scenario', choices=['outage', 'restart', 'spill', 'probe'], required=True)
    p.add_argument('--expect-loss', action='store_true', help='baseline: assert loss is reproduced')
    args = p.parse_args()
    if args.scenario == 'probe':
        probe_failures(args.pilot)
        return
    token = 'PILOT-QUEUE-' + uuid.uuid4().hex
    clients = ['aq-ubuntu', 'aq-el']
    count, delay = (12000, 0.001) if args.scenario == 'spill' else (240, 0.05)
    # Inventory is a prerequisite, collected by the caller. Verify the receiver
    # is alive before disrupting it, then restore it even when sending fails.
    service(args.pilot, 'start')
    try:
        if args.scenario != 'restart':
            service(args.pilot, 'stop')
            # All numbered messages in outage/spill start AFTER confirmed stop.
            remote(args.pilot, 'aq-log', "import subprocess; assert subprocess.run(['systemctl','is-active','--quiet','rsyslog']).returncode != 0")
            if args.scenario == 'spill':
                # Isolate queue persistence from the documented plain-TCP
                # in-flight window: force both old sender connections to notice
                # the close before numbering the disk-spill workload. The
                # restart scenario separately measures the live disconnect.
                for host in clients:
                    remote(args.pilot, host, """
import socket,subprocess,time
with socket.create_connection(('127.0.0.1',514),timeout=5) as s:
    for pri in [182,38,86]:
        s.sendall(('<%d>Oct 20 00:00:00 queue-primer pilot-queue: disconnect-primer\\n' % pri).encode())
address=socket.gethostbyname('siem-log-server')
for i in range(50):
    out=subprocess.check_output(['ss','-Htnp','state','established','( dst '+address+' and dport = :514 )'],text=True)
    if not out.strip():
        break
    time.sleep(0.1)
else:
    raise RuntimeError('forwarding connection still established')
time.sleep(1)
""")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(send, args.pilot, host, token, count, delay) for host in clients]
            if args.scenario == 'restart':
                time.sleep(3)
                service(args.pilot, 'restart')
            for future in futures:
                print(future.result().strip(), flush=True)
        if args.scenario == 'spill':
            for host in clients:
                # Require both queues to have spilled before any client restart.
                print(host, remote(args.pilot, host, """
import pathlib
spool=next(p for p in [pathlib.Path('/var/spool/rsyslog/pilot-siem'),pathlib.Path('/var/lib/rsyslog/pilot-siem')] if p.is_dir())
for name in ['siem_audit','siem_auth']:
    files=list(spool.glob(name+'.[0-9]*'))
    assert files, 'no disk spill: '+name
    print(name, sum(p.stat().st_size for p in files), 'bytes')
""").strip(), flush=True)
                service(args.pilot, 'restart', host)
    finally:
        service(args.pilot, 'start')
    expected = {(host, facility, i) for host in clients
                for facility in ['local6', 'auth', 'authpriv'] for i in range(count)}
    deadline = time.monotonic() + 75
    found = {}
    while time.monotonic() < deadline:
        found = {tuple(k): v for k, v in received(args.pilot, token)}
        if expected <= found.keys():
            break
        time.sleep(2)
    missing = expected - found.keys()
    print(json.dumps(dict(scenario=args.scenario, token=token, sent=len(expected),
                          received_unique=len(expected & found.keys()), missing=len(missing),
                          duplicates=sum(v - 1 for v in found.values()),
                          missing_by_host={host: sum(k[0] == host for k in missing) for host in clients}),
                     sort_keys=True), flush=True)
    if bool(missing) != args.expect_loss:
        raise SystemExit('unexpected delivery result')


if __name__ == '__main__':
    main()
