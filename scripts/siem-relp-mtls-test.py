#!/usr/bin/env python3
"""Exercise mTLS rejection and missing RELP ACK on the disposable aq topology."""

import argparse
import concurrent.futures
import json
import pathlib
import runpy
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pilot', required=True)
    parser.add_argument('--scenario', choices=['negative', 'auth-retry'], default='negative')
    args = parser.parse_args()
    harness = runpy.run_path(str(pathlib.Path(__file__).with_name('audit-forward-queue-test.py')))
    remote, service = harness['remote'], harness['service']
    if args.scenario == 'auth-retry':
        auth_retry(args.pilot, harness)
        return
    for host in ['aq-ubuntu', 'aq-el']:
        print(host, remote(args.pilot, host, r'''
import pathlib,runpy,shutil,ssl,tempfile
h=runpy.run_path('/usr/local/libexec/pilot-siem-relp-check')
base=h['read_profile']('sender')
h['relp_probe'](base)
import socket
try:
    with socket.create_connection(('siem-log-server',514),timeout=3):pass
except OSError:print('remote_plain_TCP=REFUSED')
else:raise AssertionError('remote plain TCP bypasses mTLS')
for case in ['no-cert','unauthorized','expired','untrusted-client','wrong-server-name','untrusted-server']:
    with tempfile.TemporaryDirectory(dir='/run/pilot-relp-test') as name:
        directory=pathlib.Path(name)
        for f in ['ca.pem','cert.pem','key.pem']:
            shutil.copyfile(base['directory']/f,directory/f)
        peer=base['peers'][0]
        if case in ['unauthorized','expired','untrusted-client']:
            shutil.copyfile('/run/pilot-relp-test/'+case+'.pem',directory/'cert.pem')
            shutil.copyfile('/run/pilot-relp-test/'+case+'.key',directory/'key.pem')
        if case=='wrong-server-name': peer='wrong-server.test'
        if case=='untrusted-server':
            # Trust a normal public CA store, which cannot validate our private test CA.
            default=ssl.get_default_verify_paths().cafile
            assert default
            shutil.copyfile(default,directory/'ca.pem')
        # Reject malformed local fixtures before interpreting any handshake
        # failure as evidence of remote certificate enforcement.
        local=ssl.create_default_context(cafile=str(directory/'ca.pem'))
        local.load_cert_chain(str(directory/'cert.pem'),str(directory/'key.pem'))
        profile=dict(base,directory=directory,peers=[peer])
        original=ssl.SSLContext.load_cert_chain
        if case=='no-cert': ssl.SSLContext.load_cert_chain=lambda *a,**kw:None
        try:
            h['relp_probe'](profile)
        except (OSError,ValueError):
            print(case+'=REFUSED')
        else:
            raise AssertionError('accepted '+case)
        finally:
            ssl.SSLContext.load_cert_chain=original
        h['relp_probe'](base)
print('valid=PASS')
''').strip(), flush=True)

    # Use the real destination port and certificate, but withhold RELP ACKs.
    # This proves C22 cannot pass merely because TCP and TLS both work.
    fake = r'''
import pathlib,socket,ssl,threading
PILOT_RELP_NOACK=True
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
c.load_cert_chain('/etc/rsyslog.d/pilot-relp-receiver/cert.pem','/etc/rsyslog.d/pilot-relp-receiver/key.pem')
c.load_verify_locations('/etc/rsyslog.d/pilot-relp-receiver/ca.pem');c.verify_mode=ssl.CERT_REQUIRED
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',20514));s.listen()
pathlib.Path('/run/pilot-relp-noack.ready').write_text('ready')
def connection(raw):
    try:
        with raw:
            raw.settimeout(5)
            with c.wrap_socket(raw,server_side=True) as tls:
                data=tls.recv(4096)
                if b' open ' in data and b'relp_software=pilot' in data:
                    with open('/run/pilot-relp-noack.accepted','a') as f:f.write('mTLS RELP open accepted; no ACK\n')
    except OSError:pass
while True:
    raw,_=s.accept();threading.Thread(target=connection,args=(raw,),daemon=True).start()
'''
    service(args.pilot, 'stop')
    try:
        remote(args.pilot, 'aq-log', 'import pathlib,subprocess,time\n'
               "for suffix in ['ready','accepted']: pathlib.Path('/run/pilot-relp-noack.'+suffix).unlink(missing_ok=True)\n"
               + 'p=subprocess.Popen(["python3","-c",' + repr(fake) + '],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\n'
               + "pathlib.Path('/run/pilot-relp-noack.pid').write_text(str(p.pid))\n"
               + "for _ in range(50):\n if pathlib.Path('/run/pilot-relp-noack.ready').exists():break\n time.sleep(.1)\n"
               + "assert pathlib.Path('/run/pilot-relp-noack.ready').exists()")
        for host in ['aq-ubuntu', 'aq-el']:
            print(host, remote(args.pilot, host, '''
import subprocess
r=subprocess.run(['/usr/local/libexec/pilot-siem-relp-check','sender'],capture_output=True,text=True,timeout=20)
assert r.returncode!=0,(r.stdout,r.stderr)
print('C22_without_RELP_ACK=REFUSED')
''').strip(), flush=True)
        print(remote(args.pilot, 'aq-log', "import pathlib; p=pathlib.Path('/run/pilot-relp-noack.accepted'); assert p.exists(); n=len(p.read_text().splitlines()); assert n>=2,n; print('verified_probe_mTLS_connections_without_ACK='+str(n))").strip(), flush=True)
    finally:
        remote(args.pilot, 'aq-log', '''
import os,pathlib,signal,time
p=pathlib.Path('/run/pilot-relp-noack.pid')
if p.exists():
    pid=int(p.read_text())
    try:
        assert b'PILOT_RELP_NOACK' in pathlib.Path('/proc/'+str(pid)+'/cmdline').read_bytes()
        os.kill(pid,signal.SIGTERM)
    except FileNotFoundError:pass
    for _ in range(50):
        if not pathlib.Path('/proc/'+str(pid)).exists():break
        time.sleep(.1)
''')
        service(args.pilot, 'start')


def auth_retry(pilot, harness):
    """Real omrelp must resume without restarting after a TLS identity error."""
    remote, service = harness['remote'], harness['service']
    clients = ['aq-ubuntu', 'aq-el']
    pids = {h: remote(pilot, h, "import subprocess; print(subprocess.check_output(['systemctl','show','rsyslog','-p','MainPID','--value'],text=True).strip())").strip() for h in clients}
    token = 'PILOT-RELP-AUTH-' + uuid.uuid4().hex
    fake = r'''
import pathlib,socket,ssl,threading
PILOT_RELP_BADPEER=True
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
c.load_cert_chain('/run/pilot-relp-test/wrong-server.pem','/run/pilot-relp-test/wrong-server.key')
c.load_verify_locations('/etc/rsyslog.d/pilot-relp-receiver/ca.pem');c.verify_mode=ssl.CERT_REQUIRED
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',20514));s.listen()
pathlib.Path('/run/pilot-relp-badpeer.ready').write_text('ready')
def connection(raw):
    with open('/run/pilot-relp-badpeer.attempts','a') as f:f.write('attempt\n')
    try:
        with raw:
            raw.settimeout(3)
            with c.wrap_socket(raw,server_side=True) as tls:tls.recv(4096)
    except OSError:pass
while True:
    raw,_=s.accept();threading.Thread(target=connection,args=(raw,),daemon=True).start()
'''
    service(pilot, 'stop')
    try:
        remote(pilot, 'aq-log', 'import pathlib,subprocess,time\n'
               + "for suffix in ['ready','attempts']: pathlib.Path('/run/pilot-relp-badpeer.'+suffix).unlink(missing_ok=True)\n"
               + 'p=subprocess.Popen(["python3","-c",' + repr(fake) + '],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\n'
               + "pathlib.Path('/run/pilot-relp-badpeer.pid').write_text(str(p.pid))\n"
               + "for _ in range(50):\n if pathlib.Path('/run/pilot-relp-badpeer.ready').exists():break\n time.sleep(.1)\n"
               + "assert pathlib.Path('/run/pilot-relp-badpeer.ready').exists()")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            for result in pool.map(lambda h: harness['send'](pilot, h, token, 240, .01), clients):
                print(result.strip(), flush=True)
        time.sleep(12)
        assert not harness['received'](pilot, token), 'delivered through an unauthenticated peer'
        print(remote(pilot, 'aq-log', "import pathlib; n=len(pathlib.Path('/run/pilot-relp-badpeer.attempts').read_text().splitlines()); assert n>=2,n; print('bad_server_attempts='+str(n))").strip(), flush=True)
        for host in clients:
            print(host, remote(pilot, host, '''
import subprocess
r=subprocess.check_output(['journalctl','-u','rsyslog','--since','-2min','--no-pager'],text=True)
assert 'not permitted' in r or 'not authorized' in r or 'authentication error' in r or 'certificate' in r.lower(),r[-2000:]
assert 'permanently disabled' not in r.lower(),r[-2000:]
print('real_daemon_TLS_rejection=PASS')
''').strip(), flush=True)
    finally:
        remote(pilot, 'aq-log', '''
import os,pathlib,signal,time
p=pathlib.Path('/run/pilot-relp-badpeer.pid')
if p.exists():
    pid=int(p.read_text())
    try:
        assert b'PILOT_RELP_BADPEER' in pathlib.Path('/proc/'+str(pid)+'/cmdline').read_bytes()
        os.kill(pid,signal.SIGTERM)
    except FileNotFoundError:pass
    for _ in range(50):
        if not pathlib.Path('/proc/'+str(pid)).exists():break
        time.sleep(.1)
''')
        service(pilot, 'start')
    expected = {(h, f, i) for h in clients for f in ['local6', 'auth', 'authpriv'] for i in range(240)}
    deadline = time.monotonic() + 75
    found = {}
    while time.monotonic() < deadline:
        found = {tuple(k): v for k, v in harness['received'](pilot, token)}
        if expected <= found.keys():break
        time.sleep(2)
    for host in clients:
        current = remote(pilot, host, "import subprocess; print(subprocess.check_output(['systemctl','show','rsyslog','-p','MainPID','--value'],text=True).strip())").strip()
        assert current == pids[host], 'sender restarted during recovery: ' + host
    print(json.dumps(dict(scenario='auth-retry', sent=len(expected), received_unique=len(expected & found.keys()),
                          missing=len(expected - found.keys()), duplicates=sum(v - 1 for v in found.values()),
                          sender_restarts=0)), flush=True)
    assert expected <= found.keys(), 'lost messages following TLS authentication failure'


if __name__ == '__main__':
    main()
