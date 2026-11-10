"""Explicit native account/process observations for local reader caller models.

Real source files, native-shaped cursor bytes and private journals remain real.
These observations do not certify rsyslog/systemd/VM behavior.
"""
import json
import os
from pathlib import Path
import subprocess
from unittest import mock
import wazuh_models
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


def process(proc, source, pid, exe='/usr/sbin/rsyslogd', opened=True, cgroup='', maps=None):
    """One modeled rsyslogd process. maps is its /proc/<pid>/maps text; the default is the
    native capture of a rsyslogd that loaded no imfile (what a disabled or never-configured
    host runs), so an enabled reader must pass Rsyslog.maps(imfile=True) explicitly."""
    proc=Path(proc);text=proc_root(proc,source);folder=proc/str(pid)
    (folder/'fd').mkdir(parents=True,exist_ok=True);(folder/'fdinfo').mkdir(exist_ok=True)
    (folder/'ns').mkdir(exist_ok=True);(folder/'ns/mnt').touch()
    (folder/'stat').write_text(str(pid)+' (native-model) S '+'0 '*18+'123\n')
    (folder/'mountinfo').write_text(text);(folder/'cgroup').write_text(cgroup)
    (folder/'maps').write_text(wazuh_models.capture('rsyslog-maps.no-imfile.ubuntu2404.txt') if maps is None else maps)
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


class Rsyslog:
    """The native observations Reader.qualify reads, so the real qualify runs in a harness.

    Modeled leaves, each shaped from a native capture (Ubuntu 24.04, rsyslog 8.2312.0-3ubuntu9.2):
    the on-disk rsyslogd and imfile.so (private files registered in READER_ENGINES by their own
    digest, with the real qualification's version/package/engine/transport), `rsyslogd -v`,
    `dpkg-query -W -f=${Version} rsyslog`, and /proc/<pid>/maps (rsyslog-maps.*.txt, with only the
    device, inode and path of imfile.so substituted by the private file's). The comparison itself
    (identity, version, package, mapping) is the production code: qualify is never stubbed.
    """
    ENGINE = '/usr/sbin/rsyslogd'
    MODULE = '/usr/lib/x86_64-linux-gnu/rsyslog/imfile.so'

    def __init__(self, root):
        folder = Path(root) / 'rsyslog-engine'
        folder.mkdir()
        self.engine, self.module = (folder / 'rsyslogd').resolve(), (folder / 'imfile.so').resolve()
        self.engine.write_bytes(b'modeled native rsyslogd executable identity')
        self.module.write_bytes(b'modeled native rsyslog imfile module identity')

    def enter(self, case):
        """Point the production qualify at this engine for the duration of one test case."""
        real = w.canonical
        mapping = {self.ENGINE: self.engine, self.MODULE: self.module}
        case.enterContext(mock.patch.object(w, 'canonical', lambda value: real(mapping.get(str(value), value))))
        qualified = dict(next(iter(w.READER_ENGINES.values())), imfile_sha256=w.digest(self.module))
        case.enterContext(mock.patch.dict(w.READER_ENGINES, {w.digest(self.engine): qualified}))
        return self

    def run(self, argv):
        """The two native version commands qualify issues, else None (not this model's command)."""
        argv = [str(value) for value in argv]
        if argv == [str(self.engine), '-v']:
            return subprocess.CompletedProcess(argv, 0, wazuh_models.capture('rsyslogd-v.ubuntu2404.rc0.txt'), '')
        if argv[:2] == ['dpkg-query', '-W'] and argv[-1] == 'rsyslog':
            return subprocess.CompletedProcess(argv, 0, wazuh_models.capture('dpkg-query-Version.rsyslog.ubuntu2404.rc0.txt'), '')
        return None

    def maps(self, imfile=False, inode=None):
        """/proc/<pid>/maps of a running rsyslogd: with the real imfile mapping when it loaded the module
        (inode overrides the mapped file's inode to model a different file than the qualified one)."""
        text = wazuh_models.capture('rsyslog-maps.no-imfile.ubuntu2404.txt')
        if not imfile:
            return text
        info = self.module.stat()
        device = format(os.major(info.st_dev), '02x') + ':' + format(os.minor(info.st_dev), '02x')
        lines = []
        for line in wazuh_models.capture('rsyslog-maps.imfile.ubuntu2404.txt').splitlines():
            fields = line.split()
            fields[3:6] = [device, str(info.st_ino if inode is None else inode), str(self.module)]
            lines.append(' '.join(fields))
        return text + '\n'.join(lines) + '\n'
