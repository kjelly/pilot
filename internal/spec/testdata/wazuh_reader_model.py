"""Explicit native account/process observations for local reader caller models.

Real source files, native-shaped cursor bytes and private journals remain real.
These observations do not certify rsyslog/systemd/VM behavior.
"""
import json
import os
from pathlib import Path
import wazuh_transaction_test as existing
w = existing.w


def resources(source, spool, owner):
    expected = {'type':'imfile','file':str(Path(source)/'alerts/alerts.json'),
        'tag':'pilot-wazuh-alert:','facility':'local5','severity':'info','persiststateinterval':'1',
        'freshstarttail':'off','reopenontruncate':'on','addmetadata':'off','ruleset':'pilotWazuhForward'}
    return [{'kind':'module','attrs':{'load':'imfile','statefile.directory':str(Path(spool)/'state')},
             'file':str(owner),'workdirectory':None},
            {'kind':'input','attrs':expected,'file':str(owner),'workdirectory':None}]


def cursor(spool, source, **changes):
    state = Path(spool)/'state'; state.mkdir(mode=0o700,exist_ok=True)
    path=Path(source)/'alerts/alerts.json'; info=path.stat()
    suffix=w.imfile_id(path.read_bytes()[:512])
    name='imfile-state:'+str(info.st_ino)+(':'+suffix if suffix else '')
    value={'filename':str(path),'prev_was_nl':0,'curr_offs':info.st_size,'strt_offs':info.st_size}
    value.update(changes)
    target=state/name;target.write_text(json.dumps(value));target.chmod(0o600)
    return target


def proc_root(proc, source):
    proc=Path(proc); (proc/'self').mkdir(parents=True,exist_ok=True)
    boot=proc/'sys/kernel/random';boot.mkdir(parents=True,exist_ok=True)
    (boot/'boot_id').write_text('explicit-modeled-boot\n')
    dev=Path(source).stat().st_dev
    text=f'1 0 {os.major(dev)}:{os.minor(dev)} / / rw - ext4 fixture rw\n'
    (proc/'self/mountinfo').write_text(text)
    return text


def process(proc, source, pid, exe='/usr/sbin/rsyslogd', opened=True, cgroup=''):
    proc=Path(proc);text=proc_root(proc,source);folder=proc/str(pid)
    (folder/'fd').mkdir(parents=True,exist_ok=True);(folder/'fdinfo').mkdir(exist_ok=True)
    (folder/'ns').mkdir(exist_ok=True);(folder/'ns/mnt').touch()
    (folder/'stat').write_text(str(pid)+' (native-model) S '+'0 '*18+'123\n')
    (folder/'mountinfo').write_text(text);(folder/'cgroup').write_text(cgroup)
    for name,target in [('exe',exe),('root','/')]:
        path=folder/name
        if path.is_symlink():path.unlink()
        path.symlink_to(target)
    for path in (folder/'fd').iterdir():path.unlink()
    for path in (folder/'fdinfo').iterdir():path.unlink()
    if opened:
        path=Path(source)/'alerts/alerts.json';info=path.stat()
        (folder/'fd/5').symlink_to(path)
        (folder/'fdinfo/5').write_text(f'pos:\t{info.st_size}\nflags:\t0100000\nmnt_id:\t1\nino:\t{info.st_ino}\n')
    return folder
