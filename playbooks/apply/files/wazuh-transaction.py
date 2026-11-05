#!/usr/bin/env python3
"""Wazuh's bounded release policy and durable, private upgrade transactions.

Central transactions hold flock for their complete lifetime. Agent transactions
span Ansible package tasks: a durable owner/phase journal reserves the resource,
and each transition checks that owner under flock. Debian installation remains
in apt-package-install.yml, including recovery; this module only probes APT
plans and never performs an APT/dpkg installation.
"""
import argparse
import contextlib
import configparser
import copy
import fcntl
import hashlib
import ipaddress
import importlib.util
import io
import fnmatch
import glob
import json
import os
import pwd
import grp
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import uuid
from urllib.parse import urlsplit


ROOT = Path('/var/backups/pilot/wazuh')
SERVICES = ('wazuh.manager', 'wazuh.indexer', 'wazuh.dashboard')
VERSION = re.compile(r'^4\.14\.(0|[1-9][0-9]*)$')
CENTRAL_RECOVERY = {
    'reserved': 'resume-old', 'stopping': 'resume-old',
    'backed-up': 'restore-old', 'switching': 'restore-old',
    'validating': 'restore-old', 'recovering': 'restore-old',
    'committed': 'complete-target', 'recovered': 'complete-old',
    'recovered-before-switch': 'complete-old',
}
AGENT_RECOVERY = {
    'reserved': 'resume-old', 'staged': 'resume-old', 'stopping': 'resume-old',
    'backed-up': 'restore-old', 'installing': 'restore-old', 'recovering': 'restore-old',
    'restored': 'verify-old', 'committed': 'verify-target', 'recovered': 'verify-old',
    'recovered-before-install': 'resume-old',
}


class Refused(RuntimeError):
    pass


def version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise Refused('unsupported Wazuh release; expected stable 4.14.x')
    return tuple(map(int, value.split('.')))


def desired(common='', legacy=''):
    if common and legacy and common != legacy:
        raise Refused('wazuh_version conflicts with wazuh_docker_version')
    result = common or legacy or '4.14.1'
    version(result)
    return result


def agent_plan(installed, manager, requested='', upgrade=False):
    """Separate observed compatibility from an operator's desired release."""
    if manager:
        version(manager)
    if installed:
        # Only known Wazuh packaging is accepted; epoch/build surprises fail.
        match = re.fullmatch(r'(4\.14\.(?:0|[1-9][0-9]*))-([1-9][0-9]*)', installed)
        if not match:
            raise Refused('unknown installed Wazuh agent package version')
        current = match[1]
        if manager and version(current) > version(manager):
            raise Refused('installed Wazuh agent is newer than the observed manager')
    else:
        current = ''
    target = requested or (current if current else manager) or '4.14.1'
    version(target)
    if manager and version(target) > version(manager):
        raise Refused('requested Wazuh agent is newer than the observed manager')
    if current and version(target) < version(current):
        raise Refused('Wazuh agent downgrade refused')
    change = bool(current and target != current)
    if change and not manager:
        raise Refused('controlled agent upgrade requires an observed manager version')
    if change and (not upgrade or target != '4.14.9'):
        raise Refused('agent upgrade requires wazuh_upgrade=true and target 4.14.9')
    return {'installed': installed, 'version': target, 'package': target + '-1' if change or not installed else installed,
            'change': change, 'install': not installed, 'manager': manager}


class Runner:
    def run(self, argv, cwd=None, allowed=(0,), timeout=900, input=None, operation=None):
        label = operation or str(argv[0])
        try:
            result = subprocess.run([str(a) for a in argv], cwd=cwd, input=input,
                                    text=True, capture_output=True, timeout=timeout,
                                    env=dict(os.environ, LC_ALL='C'))
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refused('operation unavailable or timed out: ' + label) from exc
        if result.returncode not in allowed:
            # Tool stderr can include credentials. Never put it in Ansible output.
            raise Refused('operation failed: ' + label + ' rc=' + str(result.returncode))
        return result

    def json(self, argv, **kwargs):
        try:
            return json.loads(self.run(argv, **kwargs).stdout)
        except (ValueError, TypeError) as exc:
            raise Refused('invalid native JSON probe') from exc


def digest(path):
    result = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused('durable artifact is not a regular file')
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_directory(Path(path).parent)


def sync_tree(path):
    path = Path(path)
    if not path.is_dir():
        sync_file(path)
        return
    for directory, _, files in os.walk(path, topdown=False, followlinks=False):
        for name in files:
            filename = Path(directory) / name
            if stat.S_ISREG(filename.lstat().st_mode):
                sync_file(filename)
        sync_directory(directory)
    sync_directory(path.parent)


def durable_unlink(path):
    """Restore absence durably, including an already absent replay target."""
    path = Path(path)
    canonical(path.parent)
    if path.exists() or path.is_symlink():
        if path.is_dir() and not path.is_symlink():
            raise Refused('absence restoration expected a file')
        path.unlink()
    sync_directory(path.parent)


def private_dir(path):
    path = Path(path)
    # Reject symlink parents, including a symlink introduced at a prior step.
    for parent in reversed((path, *path.parents)):
        if parent.exists() or parent.is_symlink():
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise Refused('unsafe backup directory')
        else:
            parent.mkdir(mode=0o700)
            sync_directory(parent.parent)
            sync_directory(parent)
    if path.stat().st_uid != os.geteuid():
        raise Refused('backup directory has a different owner')
    path.chmod(0o700)
    sync_directory(path)
    return path


def canonical(path):
    """Return an absolute path only if every existing ancestor is non-symlink."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise Refused('non-canonical transaction path')
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise Refused('transaction path contains a symlink')
    return path.resolve()


def disjoint(paths, backup):
    paths = [canonical(path) for path in paths]
    backup = canonical(backup)
    for index, path in enumerate(paths):
        if path == backup or path in backup.parents or backup in path.parents:
            raise Refused('backup overlaps transaction source data')
        for other in paths[index + 1:]:
            if path == other or path in other.parents or other in path.parents:
                raise Refused('transaction backup sources overlap')


class MountTable:
    """The current host mount namespace, including same-device bind mounts."""
    def __init__(self, text=None):
        if text is None:
            text = Path('/proc/self/mountinfo').read_text()
        self.rows = []
        for line in text.splitlines():
            fields, separator, filesystem = line.partition(' - ')
            fields, filesystem = fields.split(), filesystem.split()
            if not separator or len(fields) < 6 or len(filesystem) < 3 or not re.fullmatch(r'[0-9]+:[0-9]+', fields[2]):
                raise Refused('unknown host mount namespace')
            decode = lambda value: re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), value)
            root, point = Path(decode(fields[3])), Path(decode(fields[4]))
            if not point.is_absolute() or '..' in root.parts or '..' in point.parts:
                raise Refused('non-canonical host mount namespace')
            # Kernel object mounts (e.g. nsfs net:[inode]) have no filesystem
            # root. Keep their mountpoint for descendant rejection, and refuse
            # physical mapping only if a selected path actually uses one.
            root = root if root.is_absolute() else None
            self.rows.append({'id': fields[0], 'device': fields[2], 'root': root, 'point': point,
                              'writable': 'rw' in fields[5].split(',')})
        if not self.rows:
            raise Refused('empty host mount namespace')

    def containing(self, path):
        candidates = [row for row in self.rows if path == row['point'] or row['point'] in path.parents]
        if not candidates:
            raise Refused('path has no known enclosing host mount')
        depth = max(len(row['point'].parts) for row in candidates)
        selected = [row for row in candidates if len(row['point'].parts) == depth]
        if len({(row['device'], row['root'], row['writable']) for row in selected}) != 1:
            raise Refused('selected path has ambiguous stacked mounts')
        return selected[0]

    def project(self, path):
        """Read-only physical identity; this grants no recovery/write authority."""
        row = self.containing(path)
        if row['root'] is None:
            raise Refused('selected path has a non-filesystem mount root')
        return row['device'], row['root'] / path.relative_to(row['point'])

    def physical(self, path):
        row = self.containing(path)
        if not row['writable']:
            raise Refused('selected recovery filesystem is read-only')
        return self.project(path)

    def backup(self, root):
        root = canonical(root)
        row = self.containing(root)
        if not row['writable']:
            raise Refused('backup filesystem is read-only')
        if row['root'] != Path('/'):
            raise Refused('backup store has unsupported subtree or bind-mount ancestry')
        if any(root in mount['point'].parents for mount in self.rows):
            raise Refused('backup store contains an unsupported nested mount')
        return root


def path_shape(filename, kind, missing=False):
    """Validate every ancestor before following a selected source or artifact."""
    path = canonical(filename)
    for parent in path.parents:
        if parent.exists() and not parent.is_dir():
            raise Refused('transaction path has a non-directory ancestor')
    if not path.exists():
        if missing:
            return path
        raise Refused('required transaction source is absent')
    info = path.lstat()
    if kind == 'directory' and not stat.S_ISDIR(info.st_mode):
        raise Refused('transaction source must be a real directory')
    if kind in ('file', 'linked-file') and (not stat.S_ISREG(info.st_mode) or (kind == 'file' and info.st_nlink != 1)):
        raise Refused('transaction source must be a regular single-link file')
    return path


def restore_sources(specs, backup, missing=(), mounts=None):
    """Reject layouts the bounded tar/delete/recreate recovery cannot restore.

    Sources may live below ordinary filesystem mounts, but a selected root or
    descendant mount cannot be deleted/recreated. Compare mount-backed physical
    paths too, so a backup bind alias cannot evade lexical overlap checks.
    """
    mounts = mounts or MountTable()
    backup = mounts.backup(path_shape(backup, 'directory', missing=True))
    paths = [path_shape(name, kind, missing=name in missing) for name, kind in specs.items()]
    disjoint(paths, backup)
    for path in paths:
        if any(row['point'] == path or path in row['point'].parents for row in mounts.rows):
            raise Refused('transaction source contains an unsupported mount or nested mount')
    physical = [mounts.physical(path) for path in [*paths, backup]]
    for index, (device, path) in enumerate(physical):
        for other_device, other in physical[index + 1:]:
            if device == other_device and (path == other or path in other.parents or other in path.parents):
                raise Refused('transaction source or backup has a physical filesystem alias')


def private_file(filename, parent):
    path = path_shape(filename, 'file')
    parent = path_shape(parent, 'directory')
    info = parent.stat()
    if path.parent != parent or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused('retained artifact escaped its exact private directory')
    if path.stat().st_uid != os.geteuid():
        raise Refused('retained artifact has a different owner')
    return path


class ClosedCapture:
    """A no-dereference, complete inode/link inventory of bounded roots.

    Runtime sockets are inventoried but are not persistent archive contents.
    Their owning runtime must separately prove quiescence or exact endpoint
    preservation; this class never follows an external target to expand scope.
    """
    @staticmethod
    def identity(info):
        return [info.st_dev, info.st_ino, info.st_nlink, info.st_mode,
                info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns]

    @staticmethod
    def attrs(path):
        return {name: hashlib.sha256(os.getxattr(path, name, follow_symlinks=False)).hexdigest()
                for name in sorted(os.listxattr(path, follow_symlinks=False))}

    @staticmethod
    def file_hash(path, expected):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if ClosedCapture.identity(os.fstat(fd)) != expected:
                raise Refused('capture file changed while being read')
            value = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                value.update(chunk)
            if ClosedCapture.identity(os.fstat(fd)) != expected:
                raise Refused('capture file changed while being read')
            return value.hexdigest()
        finally:
            os.close(fd)

    @staticmethod
    def resolve_link(path, nodes, roots):
        # Resolve components in kernel order. Normalizing '..' before resolving
        # a preceding symlink would incorrectly accept paths with external
        # effective targets.
        current, pending, links = Path('/'), list(path.parts[1:]), 0
        while pending:
            part = pending.pop(0)
            if part in ('', '.'):
                continue
            if part == '..':
                current = current.parent
                continue
            candidate = current / part
            node = nodes.get(str(candidate))
            if node is None:
                if not any(candidate in root.parents for root in roots):
                    raise Refused('capture symlink escapes or has an unrecorded target')
                current = candidate
                continue
            if node['type'] == 'symlink':
                links += 1
                if links > 40:
                    raise Refused('capture symlink resolution exceeded its bound')
                target = node['target']
                if target.startswith('/'):
                    current = Path('/')
                pending = target.split('/') + pending
            else:
                if pending and node['type'] != 'directory':
                    raise Refused('capture symlink traverses a non-directory')
                current = candidate
        if str(current) not in nodes:
            raise Refused('capture contains a dangling symlink')
        return str(current)

    @classmethod
    def close_links(cls, nodes, groups, roots):
        # Shared closure policy for live namespace inspection and strict cold
        # capture. Neither walk may omit an outside alias or follow its data.
        for aliases in groups.values():
            if any(nodes[name]['identity'][2] != len(aliases) for name in aliases):
                raise Refused('capture has an uncaptured external hardlink alias')
        for name, node in nodes.items():
            if node['type'] == 'symlink':
                node['resolved'] = cls.resolve_link(Path(name), nodes, [Path(root) for root in roots])
        return sorted(sorted(aliases) for aliases in groups.values() if len(aliases) > 1)

    @classmethod
    def take(cls, specs, backup, missing=(), sealed=False):
        restore_sources(specs, backup, missing=missing)
        roots = {str(path_shape(name, kind, missing=name in missing)): kind for name, kind in specs.items()}
        nodes, groups, absent = {}, {}, []
        def walk(path):
            info = path.lstat()
            before = cls.identity(info)
            if stat.S_ISDIR(info.st_mode): kind = 'directory'
            elif stat.S_ISREG(info.st_mode): kind = 'file'
            elif stat.S_ISLNK(info.st_mode): kind = 'symlink'
            elif stat.S_ISSOCK(info.st_mode): kind = 'socket'
            else: raise Refused('capture contains an unsupported special file')
            node = {'type': kind, 'identity': before, 'mode': stat.S_IMODE(info.st_mode),
                    'uid': info.st_uid, 'gid': info.st_gid, 'mtime_ns': info.st_mtime_ns,
                    'xattrs': cls.attrs(path)}
            if kind == 'file':
                node['size'] = info.st_size
                group = groups.setdefault((info.st_dev, info.st_ino), [])
                group.append(str(path))
                if sealed:
                    node['sha256'] = cls.file_hash(path, before) if len(group) == 1 else nodes[group[0]]['sha256']
            elif kind == 'symlink':
                node['target'] = os.readlink(path)
            nodes[str(path)] = node
            if kind == 'directory':
                with os.scandir(path) as entries:
                    children = sorted(entry.name for entry in entries)
                for name in children:
                    walk(path / name)
            if cls.identity(path.lstat()) != before or cls.attrs(path) != node['xattrs']:
                raise Refused('capture metadata changed during the complete walk')
        try:
            for name in roots:
                path = Path(name)
                if path.exists(): walk(path)
                else: absent.append(name)
            # Recheck all entries, including earlier roots, before accepting the
            # complete graph. Nothing unreadable or newly changed is omitted.
            for name, node in nodes.items():
                if cls.identity(Path(name).lstat()) != node['identity'] or cls.attrs(name) != node['xattrs']:
                    raise Refused('capture metadata changed before closure was sealed')
            hardlinks = cls.close_links(nodes, groups, roots)
        except OSError as exc:
            raise Refused('complete capture metadata is unreadable or changed') from exc
        return {'roots': roots, 'nodes': nodes, 'absent': sorted(absent), 'sealed': sealed,
                'hardlinks': hardlinks}

    @staticmethod
    def persistent(capture, deferred=()):
        deferred = set(deferred)
        return {'roots': {name: kind for name, kind in capture['roots'].items() if name not in deferred},
                'absent': [name for name in capture['absent'] if name not in deferred],
                'hardlinks': capture['hardlinks'],
                'nodes': {name: {key: value for key, value in node.items() if key != 'identity'}
                          for name, node in capture['nodes'].items() if node['type'] != 'socket' and name not in deferred}}

    @classmethod
    def verify(cls, expected, backup, deferred=()):
        if not expected.get('sealed'):
            raise Refused('cold capture was not content-sealed')
        actual = cls.take(expected['roots'], backup, missing=expected['absent'], sealed=True)
        if cls.persistent(actual, deferred) != cls.persistent(expected, deferred):
            raise Refused('persistent capture differs from its verified cold state')
        return actual

    @classmethod
    def relink(cls, expected, backup, deferred=()):
        # Extracted per-root archives may contain independent copies of a
        # cross-root inode. Validate every copy before changing any link.
        actual = cls.take(expected['roots'], backup, missing=expected['absent'], sealed=True)
        for aliases in expected['hardlinks']:
            for name in aliases:
                old, new = expected['nodes'][name], actual['nodes'].get(name)
                if not new or any(new.get(key) != old.get(key) for key in ('type', 'sha256', 'mode', 'uid', 'gid', 'xattrs', 'size')):
                    raise Refused('restored hardlink member differs from the sealed old file')
        for aliases in expected['hardlinks']:
            first = Path(aliases[0])
            for name in aliases[1:]:
                path = Path(name)
                if (path.stat().st_dev, path.stat().st_ino) != (first.stat().st_dev, first.stat().st_ino):
                    durable_unlink(path)
                    os.link(first, path, follow_symlinks=False)
                    sync_file(path)
        for name, node in sorted(expected['nodes'].items(), key=lambda pair: len(Path(pair[0]).parts), reverse=True):
            if node['type'] == 'directory':
                info = Path(name).lstat()
                os.utime(name, ns=(info.st_atime_ns, node['mtime_ns']), follow_symlinks=False)
                sync_directory(name)
        cls.verify(expected, backup, deferred)


class ScopeLayout:
    """Non-freezing admission only; never a recoverable content snapshot.

    Ordinary file appends may change size/timestamps. Every observed namespace
    entry, directory membership, alias and mount must still be accounted for.
    The strict identity retained on each node is used only to hash selected
    managed key/config files separately, not to freeze a running data tree.
    """
    @staticmethod
    def identity(info):
        return [info.st_dev, info.st_ino, info.st_nlink, stat.S_IFMT(info.st_mode)]

    @classmethod
    def inspect(cls, specs, backup, missing=()):
        restore_sources(specs, backup, missing=missing)
        roots = {str(path_shape(name, kind, missing=name in missing)): kind for name, kind in specs.items()}
        nodes, groups, absent = {}, {}, []
        def children(path):
            with os.scandir(path) as entries:
                return sorted(entry.name for entry in entries)
        def walk(path):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode): kind = 'directory'
            elif stat.S_ISREG(info.st_mode): kind = 'file'
            elif stat.S_ISLNK(info.st_mode): kind = 'symlink'
            elif stat.S_ISSOCK(info.st_mode): kind = 'socket'
            else: raise Refused('layout contains an unsupported special file')
            node = {'type': kind, 'scope_identity': cls.identity(info),
                    'identity': ClosedCapture.identity(info), 'xattrs': ClosedCapture.attrs(path)}
            if kind == 'file':
                groups.setdefault((info.st_dev, info.st_ino), []).append(str(path))
            elif kind == 'symlink':
                node['target'] = os.readlink(path)
            elif kind == 'directory':
                node['children'] = children(path)
            nodes[str(path)] = node
            if kind == 'directory':
                for name in node['children']:
                    walk(path / name)
            check(path, node)
        def check(path, node):
            if cls.identity(path.lstat()) != node['scope_identity']:
                raise Refused('live layout namespace changed during inspection')
            if node['type'] == 'symlink' and os.readlink(path) != node['target']:
                raise Refused('live layout symlink target changed during inspection')
            if node['type'] == 'directory' and children(path) != node['children']:
                raise Refused('live layout directory membership changed during inspection')
        try:
            for name in roots:
                path = Path(name)
                if os.path.lexists(path): walk(path)
                else: absent.append(name)
            for name, node in nodes.items():
                check(Path(name), node)
            if any(os.path.lexists(name) for name in absent):
                raise Refused('live layout absent source appeared during inspection')
            # Refresh root/ancestor/mount/physical-disjoint checks after the
            # complete namespace walk too. No mutable file data is frozen.
            restore_sources(specs, backup, missing=missing)
            hardlinks = ClosedCapture.close_links(nodes, groups, roots)
        except OSError as exc:
            raise Refused('complete live layout namespace is unreadable or changed') from exc
        return {'roots': roots, 'nodes': nodes, 'absent': sorted(absent),
                'hardlinks': hardlinks, 'sealed': False, 'purpose': 'live-layout-only'}


def agent_socket_gate(capture, stopped=False, preserved=None):
    """Fail closed on external runtime writers; never archive a live endpoint.

    The only supported external writer is the separately proven exact audit
    listener. Other endpoints must belong to Wazuh, then disappear at stop.
    """
    paths = {name for name, node in capture['nodes'].items() if node['type'] == 'socket'}
    active = {}
    try:
        for line in Path('/proc/net/unix').read_text().splitlines()[1:]:
            fields = line.split(maxsplit=7)
            if len(fields) == 8 and fields[7] in paths:
                active.setdefault(fields[7], set()).add(fields[6])
        endpoint = str(Path('/var/ossec/queue/sockets/audit'))
        if stopped and set(active) - ({endpoint} if preserved else set()):
            raise Refused('agent runtime endpoints remain active after quiescence')
        for name, inodes in active.items():
            owners = set()
            for process in Path('/proc').iterdir():
                if not process.name.isdecimal(): continue
                try:
                    for descriptor in (process / 'fd').iterdir():
                        if os.readlink(descriptor) in {'socket:[' + inode + ']' for inode in inodes}:
                            owners.add((int(process.name), os.readlink(process / 'exe')))
                except (FileNotFoundError, ProcessLookupError):
                    continue
            allowed = {(preserved['listener']['pid'], preserved['listener']['exe'])} if preserved and name == endpoint else None
            if not owners or (owners != allowed if allowed else any(not value.startswith('/var/ossec/bin/') for _, value in owners)):
                raise Refused('controlled upgrade cannot restore an unknown live external agent endpoint')
    except OSError as exc:
        raise Refused('agent runtime endpoint ownership is unreadable') from exc


class AuditRuntime:
    """Preserve one demonstrated same-boot external endpoint, never recreate it.

    Native feasibility: exact old/target packages, audit processes, directory
    anchors and a genuine who-data event were independently probed before this
    implementation. Final candidate/platform evidence remains separate.
    """
    def __init__(self, runner): self.r = runner

    @staticmethod
    def endpoint(): return Path('/var/ossec/queue/sockets/audit')

    @classmethod
    def anchors(cls):
        endpoint = cls.endpoint()
        return [Path('/var/ossec'), endpoint.parent.parent, endpoint.parent, endpoint]

    @staticmethod
    def node(path):
        info = path.lstat()
        value = {'device': info.st_dev, 'inode': info.st_ino, 'type': stat.S_IFMT(info.st_mode),
                'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
                'xattrs': ClosedCapture.attrs(path)}
        if stat.S_ISSOCK(info.st_mode): value['links'] = info.st_nlink
        return value

    @staticmethod
    def boot(): return Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    @staticmethod
    def process(pid):
        path = Path('/proc') / str(pid)
        fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': int(pid), 'ppid': int(fields[1]), 'start': fields[19],
                'exe': os.readlink(path / 'exe'),
                'argv': (path / 'cmdline').read_bytes().decode().rstrip('\0').split('\0')}

    def audit_processes(self):
        value = self.r.run(['systemctl', 'show', 'auditd', '-p', 'MainPID', '--value'], timeout=30,
                           operation='native audit daemon identity').stdout.strip()
        if not value.isdecimal() or int(value) <= 1:
            raise Refused('audit daemon identity is unavailable')
        audit, listeners = self.process(int(value)), []
        if audit['exe'] != '/usr/sbin/auditd':
            raise Refused('unsupported audit daemon executable')
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal(): continue
            try: process = self.process(int(path.name))
            except (FileNotFoundError, ProcessLookupError): continue
            if process['ppid'] == audit['pid'] and process['exe'] == '/usr/sbin/audisp-af_unix' and str(self.endpoint()) in process['argv']:
                listeners.append(process)
        if len(listeners) != 1:
            raise Refused('exact external audit listener is missing or ambiguous')
        return audit, listeners[0]

    def kernel(self):
        text = self.r.run(['auditctl', '-s'], timeout=30, operation='native kernel audit settings').stdout
        values = {}
        for line in text.splitlines():
            fields = line.split(maxsplit=1)
            if len(fields) == 2:
                if fields[0] in values: raise Refused('ambiguous kernel audit status')
                values[fields[0]] = fields[1]
        keys = ('enabled', 'failure', 'pid', 'rate_limit', 'backlog_limit', 'backlog_wait_time', 'loginuid_immutable', 'lost')
        if not set(keys).issubset(values) or values['enabled'] not in ('1', '2'):
            raise Refused('unknown kernel audit settings')
        return {key: values[key] for key in keys}

    def ready(self, proof):
        deadline = time.monotonic() + 60
        while True:
            lines = self.r.run(['ss', '-xHap'], timeout=15, operation='native audit client connection').stdout.splitlines()
            servers = [line.split() for line in lines if str(self.endpoint()) in line and 'u_str' in line and 'ESTAB' in line
                       and ('pid=' + str(proof['listener']['pid']) + ',') in line]
            clients = [line.split() for line in lines if 'wazuh-syscheckd' in line and 'u_str' in line and 'ESTAB' in line]
            paired = [client for server in servers for client in clients if len(server) > 7 and len(client) > 7
                      and server[5] == client[7] and server[7] == client[5]]
            pids = {int(value) for client in paired for value in re.findall(r'pid=([0-9]+)', ' '.join(client))}
            text = self.r.run(['auditctl', '-l'], timeout=15, operation='native Wazuh audit watches').stdout
            watches = sorted(line for line in text.splitlines() if re.search(r'(?:key=|\-k\s+)wazuh_fim(?:\s|$)', line))
            if len(pids) == 1 and watches and set(proof.get('watches', [])).issubset(watches):
                process = self.process(pids.pop())
                if process['exe'] != '/var/ossec/bin/wazuh-syscheckd' or digest(Path('/proc') / str(process['pid']) / 'exe') != digest(Path('/var/ossec/bin/wazuh-syscheckd')):
                    raise Refused('executed audit client differs from the installed native binary')
                return watches
            if time.monotonic() >= deadline:
                raise Refused('native Wazuh audit client/watch readiness timed out')
            time.sleep(0.5)

    def snapshot(self, capture):
        endpoint = self.endpoint()
        if not endpoint.exists():
            plugin = Path('/etc/audit/plugins.d/af_wazuh.conf')
            if plugin.exists() and re.search(r'^\s*active\s*=\s*yes\s*$', plugin.read_text(), re.M):
                raise Refused('configured external audit endpoint is unavailable before upgrade')
            agent_socket_gate(capture)
            return None
        nodes = {str(path): self.node(path_shape(path, 'directory' if path != endpoint else 'socket')) for path in self.anchors()}
        if any(value['type'] != (stat.S_IFSOCK if name == str(endpoint) else stat.S_IFDIR) for name, value in nodes.items()):
            raise Refused('unsupported audit runtime anchor type')
        if nodes[str(endpoint)]['links'] != 1:
            raise Refused('external audit socket has an unowned hardlink alias')
        audit, listener = self.audit_processes()
        proof = {'boot': self.boot(), 'anchors': nodes, 'audit': audit, 'listener': listener, 'kernel': self.kernel()}
        if proof['kernel']['pid'] != str(audit['pid']):
            raise Refused('kernel audit daemon differs from native service identity')
        agent_socket_gate(capture, preserved=proof)
        proof['watches'] = self.ready(proof)
        return proof

    def check(self, proof, capture, stopped=False, ready=False):
        if proof:
            if (set(proof['anchors']) != {str(path) for path in self.anchors()} or self.boot() != proof['boot']
                    or any(self.node(path) != proof['anchors'][str(path)] for path in self.anchors())
                    or self.audit_processes() != (proof['audit'], proof['listener']) or self.kernel() != proof['kernel']):
                raise Refused('preserved audit endpoint/process/security/boot proof changed; explicit recovery required')
            if ready: self.ready(proof)
        agent_socket_gate(capture, stopped=stopped, preserved=proof)

    def validate_archive(self, source, archive, capture, proof):
        if not proof: return
        source = Path(source)
        expected = {name for name, node in capture['nodes'].items() if (Path(name) == source or source in Path(name).parents)
                    and node['type'] != 'socket' and Path(name) != self.endpoint()}
        seen = set()
        try:
            with tarfile.open(archive, 'r:') as stream:
                for member in stream:
                    relative = Path(member.name)
                    target = source.parent / relative
                    name = str(target)
                    if relative.is_absolute() or '..' in relative.parts or name in seen or name not in expected:
                        raise Refused('sealed archive escaped its exact persistent capture set')
                    seen.add(name)
                    node = capture['nodes'][name]
                    if (target == self.endpoint() or (target in self.endpoint().parents and not member.isdir())
                            or (node['type'] == 'directory' and not member.isdir())
                            or (node['type'] == 'symlink' and (not member.issym() or member.linkname != node['target']))
                            or (node['type'] == 'file' and not (member.isfile() or member.islnk()))):
                        raise Refused('sealed archive would replace a live anchor or persistent type')
                    if member.islnk():
                        linked = Path(member.linkname)
                        other = str(source.parent / linked)
                        if linked.is_absolute() or '..' in linked.parts or not any(name in group and other in group for group in capture['hardlinks']):
                            raise Refused('sealed archive hardlink escaped its captured inode group')
                    if node['type'] == 'file':
                        content = stream.extractfile(member)
                        if content is None:
                            raise Refused('sealed archive file payload is unavailable')
                        checksum = hashlib.sha256()
                        for chunk in iter(lambda: content.read(1024 * 1024), b''): checksum.update(chunk)
                        if checksum.hexdigest() != node['sha256']:
                            raise Refused('sealed archive payload differs from its cold content proof')
                if seen != expected:
                    raise Refused('sealed archive omitted persistent captured entries')
        except (tarfile.TarError, OSError) as exc:
            raise Refused('sealed persistent archive is unreadable') from exc

    def prune(self, source, proof):
        # Called only after complete source/archive validation and stopped
        # Wazuh. Keep each exact real ancestor and the socket inode in place.
        endpoint = self.endpoint()
        for entry in os.scandir(source):
            child = Path(entry.path)
            if child == endpoint: continue
            if child in endpoint.parents:
                if self.node(child) != proof['anchors'][str(child)]:
                    raise Refused('live audit ancestor changed before preserving prune')
                self.prune(child, proof)
            elif entry.is_dir(follow_symlinks=False):
                shutil.rmtree(child)
                sync_directory(child.parent)
            else:
                durable_unlink(child)


def atomic_text(path, text, private=False, mtime_ns=None):
    """Durable policy replacement; retain existing owner/mode/ACL/xattrs."""
    path = path_shape(path, 'file', missing=True)
    original = path.stat() if path.exists() else None
    if original and original.st_uid != os.geteuid():
        raise Refused('policy file has a foreign owner')
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        written = tmp.stat()
        if original and not private:
            shutil.copystat(path, tmp, follow_symlinks=False)
            os.chown(tmp, original.st_uid, original.st_gid)
        else:
            tmp.chmod(0o600 if private else 0o644)
        if mtime_ns is not None:
            info = tmp.stat()
            os.utime(tmp, ns=(info.st_atime_ns, mtime_ns), follow_symlinks=False)
        elif original and not private:
            os.utime(tmp, ns=(written.st_atime_ns, written.st_mtime_ns), follow_symlinks=False)
        sync_file(tmp)
        os.replace(tmp, path)
        sync_directory(path.parent)
    finally:
        if tmp.exists():
            durable_unlink(tmp)


DNF_POLICY_PLAN = r'''
import json,sys,dnf,dnf.subject,hawkey
p=json.load(sys.stdin)
if p['action']=='names':
 result=[]
 for pattern in p['patterns']:
  values=list(dnf.subject.Subject(pattern.lstrip('!')).get_nevra_possibilities(forms=[hawkey.FORM_NEVRA,hawkey.FORM_NEVR,hawkey.FORM_NEV,hawkey.FORM_NA,hawkey.FORM_NAME]))
  if not values: raise ValueError('invalid foreign lock')
  result.append(sorted(set(v.name for v in values if v.name)))
 print(json.dumps(result)); sys.exit(0)
with dnf.Base() as base:
 base.conf.read(p['config'])
 if not base.conf.plugins or base.conf.installroot!='/': raise ValueError('unsupported plugin/install context')
 base.conf.cacheonly=p.get('cacheonly',True)
 base.conf.disable_excludes=['wazuh']
 base.init_plugins(); base.pre_configure_plugins(); base.read_all_repos(); base.configure_plugins()
 loaded=sorted(plugin.name for plugin in base._plugins.plugins)
 if 'versionlock' not in loaded: raise ValueError('versionlock not loaded')
 base.fill_sack(load_system_repo=True,load_available_repos=not bool(p.get('artifact')))
 if p['action']=='providers':
  version,release=p['package'].rsplit('-',1)
  values=base.sack.query(flags=hawkey.IGNORE_EXCLUDES).available().filter(name='wazuh-agent',epoch=0,version=version,release=release,arch='x86_64')
  result=[]
  for value in values:
   algorithm,checksum=value.returnIdSum(); repo=base.repos[value.reponame]
   result.append({'repo':value.reponame,'url':value.remote_location(),'checksum_type':algorithm,'sha256':checksum,
                  'gpgcheck':bool(repo.gpgcheck),'gpgkey':list(repo.gpgkey),'baseurl':list(repo.baseurl)})
  print(json.dumps(result)); sys.exit(0)
 if p['action']=='upgrade': base.upgrade('wazuh-agent')
 elif p.get('artifact'):
  values=base.add_remote_rpms([p['artifact']],strict=True)
  if len(values)!=1: raise ValueError('invalid local package set')
  if p.get('reinstall'): base.package_reinstall(values[0])
  elif p.get('downgrade'): base.package_downgrade(values[0],strict=True)
  else: base.package_upgrade(values[0])
 elif p.get('reinstall'): base.reinstall(p['spec'])
 else: base.install(p['spec'],strict=True)
 base.resolve(allow_erasing=False)
 def package(value): return {'name':value.name,'version':value.version+'-'+value.release,'epoch':str(value.epoch or '0'),'arch':value.arch}
 print(json.dumps({'plugins':loaded,'install':[package(v) for v in base.transaction.install_set],
                   'remove':[package(v) for v in base.transaction.remove_set]}))
'''


class PackageGuard:
    """Native hold/versionlock enforcement, with Wazuh-only scoped overrides.

    DNF plugin lifecycle and transaction sets follow the supported DNF 4 API:
    https://dnf.readthedocs.io/en/latest/api_base.html
    https://github.com/rpm-software-management/dnf-plugins-core/blob/4.3.0/plugins/versionlock.py
    No resolving plan performs a package transaction.
    """
    BEGIN = '# BEGIN PILOT WAZUH VERSIONLOCK\n'
    END = '# END PILOT WAZUH VERSIONLOCK\n'
    MAIN = '/etc/dnf/dnf.conf'
    PLUGIN = '/etc/dnf/plugins/versionlock.conf'
    LOCKS = '/etc/dnf/plugins/versionlock.list'
    PREF = '/etc/apt/preferences.d/pilot-wazuh-agent'

    def __init__(self, family, runner, root=ROOT):
        self.family, self.r, self.root = family, runner, Path(root)

    @staticmethod
    def parser(text):
        value = configparser.ConfigParser(interpolation=None, strict=True)
        try:
            value.read_string(text)
        except configparser.Error as exc:
            raise Refused('ambiguous native package policy configuration') from exc
        return value

    @staticmethod
    def file_state(filename):
        path = path_shape(filename, 'file', missing=True)
        if not path.exists(): return {'present': False}
        info = path.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise Refused('native package policy permissions are unsafe')
        return {'present': True, 'text': path.read_text(), 'sha256': digest(path),
                'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
                'mtime_ns': info.st_mtime_ns, 'xattrs': ClosedCapture.attrs(path)}

    def split_locks(self, text):
        if not text.count(self.BEGIN) and not text.count(self.END):
            return text, None
        if text.count(self.BEGIN) != 1 or text.count(self.END) != 1:
            raise Refused('ambiguous owned versionlock block')
        before, rest = text.split(self.BEGIN)
        owned, after = rest.split(self.END)
        if not re.fullmatch(r'wazuh-agent-0:4\.14\.(?:0|[1-9][0-9]*)-[1-9][0-9]*\.x86_64\n', owned):
            raise Refused('unknown owned Wazuh versionlock rule')
        return before + after, owned.strip()

    def lock_text(self, original, package):
        foreign, _ = self.split_locks(original)
        return foreign + ('' if not foreign or foreign.endswith('\n') else '\n') + self.BEGIN + self.nevra(package) + '\n' + self.END

    @staticmethod
    def nevra(package):
        if not re.fullmatch(r'4\.14\.(?:0|[1-9][0-9]*)-[1-9][0-9]*', package):
            raise Refused('unknown exact Wazuh package for native guard')
        return 'wazuh-agent-0:' + package + '.x86_64'

    def dnf_native(self, payload):
        return self.r.json([sys.executable, '-c', DNF_POLICY_PLAN], input=json.dumps(payload), timeout=300,
                           operation='native DNF versionlock resolving plan')

    def dnf_context(self, dependency_optional=False):
        main = self.file_state(self.MAIN)
        if not main['present']:
            raise Refused('native DNF main configuration is absent')
        parsed = self.parser(main['text'])
        if not parsed.has_section('main') or not parsed.getboolean('main', 'plugins', fallback=True):
            raise Refused('global DNF plugins are disabled')
        section = parsed['main']
        if (section.get('installroot', '/') != '/' or section.get('pluginconfpath', '/etc/dnf/plugins').strip() != '/etc/dnf/plugins'
                or 'pluginpath' in section or 'include' in section):
            raise Refused('redirected or unknown native DNF plugin context')
        plugin = self.file_state(self.PLUGIN)
        if not plugin['present']:
            if dependency_optional:
                latent = self.file_state(self.LOCKS)
                if any(line.strip() and not line.lstrip().startswith('#') for line in latent.get('text', '').splitlines()):
                    raise Refused('installing versionlock would activate latent global rules')
                return {'main': main, 'plugin': plugin, 'locks': latent}
            raise Refused('native versionlock dependency/configuration is absent')
        settings = self.parser(plugin['text'])
        if (not settings.has_section('main') or not settings.getboolean('main', 'enabled', fallback=True)
                or settings.get('main', 'locklist', fallback='') != self.LOCKS):
            raise Refused('disabled or redirected native versionlock configuration')
        locks = self.file_state(self.LOCKS)
        foreign, owned = self.split_locks(locks.get('text', ''))
        patterns = [line.strip() for line in foreign.splitlines() if line.strip() and not line.lstrip().startswith('#')]
        if patterns:
            names = self.dnf_native({'action': 'names', 'patterns': patterns})
            if len(names) != len(patterns) or any(not values for values in names):
                raise Refused('unknown foreign versionlock rule')
            if any(fnmatch.fnmatchcase('wazuh-agent', value) for values in names for value in values):
                raise Refused('foreign versionlock ownership overlaps Wazuh')
        return {'main': main, 'plugin': plugin, 'locks': locks, 'foreign': foreign, 'owned': owned}

    def apt_state(self):
        selection = self.r.run(['dpkg', '--get-selections', 'wazuh-agent'], timeout=30,
                               operation='native Wazuh dpkg selection').stdout
        match = re.fullmatch(r'wazuh-agent(?::amd64)?\s+(hold|install)\s*', selection)
        holds = self.r.run(['apt-mark', 'showhold'], timeout=30, operation='native APT holds').stdout.splitlines()
        held = any(value in ('wazuh-agent', 'wazuh-agent:amd64') for value in holds)
        if not match or (match[1] == 'hold') != held:
            raise Refused('native APT/dpkg hold observations disagree')
        text = self.r.run(['apt-cache', 'policy', 'wazuh-agent'], timeout=30,
                          operation='effective APT agent candidate/priorities').stdout
        installed = re.findall(r'^\s*Installed:\s*(\S+)\s*$', text, re.M)
        candidate = re.findall(r'^\s*Candidate:\s*(\S+)\s*$', text, re.M)
        if len(installed) != 1 or len(candidate) != 1:
            raise Refused('unknown effective APT agent policy')
        return {'selection': match[1], 'held': held, 'holds': sorted(holds),
                'installed': installed[0], 'candidate': candidate[0]}

    def ownership(self):
        if self.family == 'Debian':
            pref = self.file_state(self.PREF)
            if pref['present'] and not re.fullmatch(
                    r'Package: wazuh-agent\nPin: version 4\.14\.(?:0|[1-9][0-9]*)-[1-9][0-9]*\nPin-Priority: 1000\n\n'
                    r'Package: wazuh-agent\nPin: version \*\nPin-Priority: -1\n', pref['text']):
                raise Refused('foreign ownership at the managed APT preference path')
            return {'preference': pref}
        return self.dnf_context(dependency_optional=True)

    def snapshot(self):
        self.ownership()
        if self.family == 'Debian':
            return dict(self.apt_state(), preference=self.file_state(self.PREF))
        return self.dnf_context()

    def same_context(self, before, after):
        if self.family == 'Debian':
            return {k: v for k, v in before.items() if k != 'candidate'} == {k: v for k, v in after.items() if k != 'candidate'}
        return before == after

    def protect(self, package, require_installed=True):
        self.nevra(package)
        self.ownership()
        if self.family == 'Debian':
            if not self.apt_state()['held']:
                self.r.run(['apt-mark', 'hold', 'wazuh-agent'], timeout=60, operation='hold only Wazuh agent')
            if not require_installed:
                if not self.apt_state()['held']:
                    raise Refused('recovery did not establish the native Wazuh hold')
                return {'guard': 'apt-hold'}
        else:
            context = self.dnf_context()
            content = self.lock_text(context['locks'].get('text', ''), package)
            if content != context['locks'].get('text', ''):
                atomic_text(self.LOCKS, content)
        return self.verify(package)

    def verify(self, package):
        self.nevra(package)
        if self.family == 'Debian':
            state = self.apt_state()
            if not state['held'] or state['installed'] != package:
                raise Refused('effective agent is not protected by its native APT hold')
            return {'guard': 'apt-hold', 'candidate': state['candidate']}
        context = self.dnf_context()
        if context['owned'] != self.nevra(package):
            raise Refused('native global Wazuh versionlock differs from installed package')
        plan = self.dnf_native({'action': 'upgrade', 'config': self.MAIN, 'cacheonly': True})
        self.validate_dnf_plan(plan, package, unchanged=True)
        return {'guard': 'dnf-global-versionlock'}

    @staticmethod
    def validate_dnf_plan(plan, package, unchanged=False):
        if 'versionlock' not in plan.get('plugins', []):
            raise Refused('resolving DNF transaction did not load versionlock')
        install, remove = plan['install'], plan['remove']
        if unchanged and (install or remove):
            raise Refused('native versionlock permits a replacement transaction')
        for value in [*install, *remove]:
            if value['name'] != 'wazuh-agent' or value['epoch'] != '0' or value['arch'] != 'x86_64':
                raise Refused('native Wazuh transaction changes an unsupported dependency/package')
        if not unchanged and (len(install) != 1 or install[0]['version'] != package):
            raise Refused('native DNF plan did not select the exact authorized agent')

    def apt_plan(self, package, artifact=''):
        self.nevra(package)
        argv = ['apt-get', '-s', '-o', 'APT::Get::AllowUnauthenticated=false', '--no-install-recommends',
                '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold',
                '--no-remove', '--allow-change-held-packages', '--reinstall']
        if artifact:
            if Path(artifact).name != 'wazuh-agent_' + package + '_amd64.deb':
                raise Refused('retained artifact has an unsupported native APT cache basename')
            argv += ['--allow-downgrades', '--no-download', '-o', 'Dir::Cache::archives=' + str(Path(artifact).parent) + '/',
                     '-o', 'APT::Keep-Downloaded-Packages=true']
        argv += ['install', artifact or 'wazuh-agent=' + package]
        text = self.r.run(argv, timeout=180, operation='native Wazuh-only APT held-change plan').stdout
        selected = []
        for line in text.splitlines():
            if line.startswith(('Remv ', 'Purg ')):
                raise Refused('authorized APT plan removes packages')
            if line.startswith('Inst '):
                match = re.match(r'^Inst (\S+)(?: \[[^\]]*\])? \((\S+)', line)
                if not match or match[1] not in ('wazuh-agent', 'wazuh-agent:amd64') or match[2] != package:
                    raise Refused('authorized APT plan changes another held package or dependency')
                selected.append(match[2])
            elif line.startswith('Conf ') and line.split()[1] not in ('wazuh-agent', 'wazuh-agent:amd64'):
                raise Refused('authorized APT plan configures an unrelated package')
        if selected != [package]:
            raise Refused('native APT plan did not select exactly the authorized Wazuh package')
        return {'authorized': True}

    def overlay(self, owner, package, installed=''):
        context = self.dnf_context()
        folder = private_dir(self.root / ('agent-policy-' + owner))
        plugins = private_dir(folder / ('plugins-' + package))
        locks = plugins / 'versionlock.list'
        plugin = plugins / 'versionlock.conf'
        config = folder / ('dnf-' + package + '.conf')
        atomic_text(locks, self.lock_text(context['locks'].get('text', ''), package), private=True)
        settings = self.parser(context['plugin']['text']); settings.set('main', 'locklist', str(locks))
        stream = io.StringIO(); settings.write(stream); atomic_text(plugin, stream.getvalue(), private=True)
        settings = self.parser(context['main']['text'])
        before = {section: dict(settings[section]) for section in settings.sections()}
        settings.set('main', 'pluginconfpath', '/etc/dnf/plugins, ' + str(plugins))
        after = {section: dict(settings[section]) for section in settings.sections()}
        after['main'].pop('pluginconfpath', None); before['main'].pop('pluginconfpath', None)
        if before != after:
            raise Refused('private DNF override changed unrelated native configuration')
        stream = io.StringIO(); settings.write(stream); atomic_text(config, stream.getvalue(), private=True)
        result = {'owner': owner, 'package': package, 'config': str(config),
                  'files': {str(path): digest(path) for path in (config, plugin, locks)},
                  'foreign': context['foreign'], 'main_sha256': context['main']['sha256'],
                  'plugin_sha256': context['plugin']['sha256']}
        for path in (config, plugin, locks): private_file(path, path.parent)
        plan = self.dnf_native({'action': 'install', 'config': str(config), 'spec': self.nevra(package),
                                'reinstall': package == installed, 'cacheonly': False})
        self.validate_dnf_plan(plan, package)
        return result

    def verify_overlay(self, overlay, owner):
        if overlay['owner'] != owner:
            raise Refused('private DNF policy belongs to another writer')
        folder = canonical(self.root / ('agent-policy-' + owner))
        self.nevra(overlay['package'])
        expected = {str(folder / ('dnf-' + overlay['package'] + '.conf')),
                    str(folder / ('plugins-' + overlay['package']) / 'versionlock.conf'),
                    str(folder / ('plugins-' + overlay['package']) / 'versionlock.list')}
        if set(overlay['files']) != expected or overlay['config'] != str(folder / ('dnf-' + overlay['package'] + '.conf')):
            raise Refused('private DNF overlay escaped its exact owned artifact set')
        for name, checksum in overlay['files'].items():
            path = private_file(name, Path(name).parent)
            if folder not in path.parents or digest(path) != checksum:
                raise Refused('private DNF policy fingerprint/scope changed')
        context = self.dnf_context()
        if (context['foreign'] != overlay['foreign'] or context['main']['sha256'] != overlay['main_sha256']
                or context['plugin']['sha256'] != overlay['plugin_sha256']):
            raise Refused('foreign/global DNF policy changed during the owned override')
        return overlay['config']

    def artifact_plan(self, overlay, owner, artifact, package, recovery=False, reinstall=False):
        config = self.verify_overlay(overlay, owner)
        plan = self.dnf_native({'action': 'install', 'config': config, 'artifact': str(artifact),
                                'downgrade': recovery, 'reinstall': reinstall, 'cacheonly': True})
        self.validate_dnf_plan(plan, package)
        return config

    def official_rpm_provider(self, overlay, package):
        records = self.dnf_native({'action': 'providers', 'config': overlay['config'], 'package': package, 'cacheonly': False})
        hashes = {item['sha256'] for item in records if item.get('checksum_type') == 'sha256' and re.fullmatch('[a-f0-9]{64}', item.get('sha256', ''))}
        if not records or len(hashes) != 1 or any(item.get('checksum_type') != 'sha256' or item.get('sha256') not in hashes for item in records):
            raise Refused('missing or ambiguous same-NEVRA RPM payload providers')
        def official(value, base=False):
            parsed = urlsplit(value or '')
            if parsed.scheme != 'https' or parsed.netloc != 'packages.wazuh.com' or parsed.query or parsed.fragment:
                return False
            return parsed.path.rstrip('/') == '/4.x/yum' if base else parsed.path.startswith('/4.x/yum/')
        allowed = [item for item in records if item['repo'] == 'wazuh' and official(item['url'])
                   and item['gpgcheck'] and item['gpgkey'] == ['https://packages.wazuh.com/key/GPG-KEY-WAZUH']
                   and item['baseurl'] and all(official(value, base=True) for value in item['baseurl'])]
        if not allowed or any(item['sha256'] not in hashes for item in allowed):
            raise Refused('RPM payload is not bound to the declared official Wazuh source')
        return allowed[0]

    def rpm_keyring_scope(self, database, owner):
        if not re.fullmatch('[a-f0-9]{32}', owner):
            raise Refused('invalid private RPM keyring owner')
        root = path_shape(self.root, 'directory')
        folder = path_shape(root / ('agent-policy-' + owner), 'directory')
        database = path_shape(database, 'directory')
        if (database.parent != folder or not re.fullmatch('official-keyring-[a-f0-9]{32}', database.name)
                or any(path.stat().st_uid != os.geteuid() or stat.S_IMODE(path.stat().st_mode) != 0o700
                       for path in (root, folder, database))):
            raise Refused('private RPM keyring escaped its exact root-owned private scope')
        MountTable().backup(root)
        return database

    def rpm_keyring_type(self):
        state = self.r.run(['getenforce'], timeout=30, operation='observe native SELinux state for private RPM DB').stdout.strip()
        if state == 'Disabled':
            return None
        if state not in ('Enforcing', 'Permissive'):
            raise Refused('unknown native SELinux state for private RPM DB')
        native = self.r.run(['rpm', '--eval', '%{_dbpath}'], timeout=30, operation='observe native RPM database path').stdout.strip()
        if native not in ('/var/lib/rpm', '/usr/lib/sysimage/rpm'):
            raise Refused('unsupported native RPM database policy path')
        policy = self.r.run(['matchpathcon', '-n', '--', native], timeout=30,
                            operation='observe installed native RPM database SELinux policy').stdout.strip()
        if self.rpm_context_parts(policy)[2] != 'rpm_var_lib_t':
            raise Refused('unsupported native RPM database SELinux policy type')
        return 'rpm_var_lib_t'

    @staticmethod
    def rpm_context_parts(value):
        parts = value.split(':', 3)
        if (len(parts) != 4 or any(not re.fullmatch('[A-Za-z0-9_]+', field) for field in parts[:3])
                or not re.fullmatch(r's[0-9]+(?:-s[0-9]+)?(?::c[0-9]+(?:[.,]c?[0-9]+)*)?', parts[3])):
            raise Refused('invalid native private RPM DB SELinux context')
        return parts

    @classmethod
    def rpm_context(cls, path):
        try:
            value = os.getxattr(path, 'security.selinux', follow_symlinks=False).decode().rstrip('\0')
        except (OSError, UnicodeError) as exc:
            raise Refused('native private RPM DB SELinux context is unavailable') from exc
        cls.rpm_context_parts(value)
        return value

    def prepare_rpm_keyring(self, database, owner):
        # Only the newly created, still empty exact directory may be labeled.
        # Retained DBs are verified below and never silently repaired.
        database = self.rpm_keyring_scope(database, owner)
        if any(database.iterdir()):
            raise Refused('private RPM DB context preparation requires a new empty directory')
        native_type = self.rpm_keyring_type()
        if native_type is None:
            return None
        before = self.rpm_context_parts(self.rpm_context(database))
        self.r.run(['chcon', '--type=' + native_type, '--', database], timeout=30,
                   operation='prepare exact private RPM database SELinux type')
        after = self.rpm_context(database)
        parts = self.rpm_context_parts(after)
        if parts[2] != native_type or before[:2] + before[3:] != parts[:2] + parts[3:]:
            raise Refused('private RPM DB type preparation changed native user/range or failed')
        sync_directory(database)
        return after

    def verify_rpm_keyring(self, keyring, owner):
        database = self.rpm_keyring_scope(keyring['database'], owner)
        folder = database.parent
        key = private_file(keyring['key'], folder)
        if digest(key) != keyring['sha256']:
            raise Refused('authenticated private RPM key changed')
        native_type = self.rpm_keyring_type()
        if native_type is not None:
            context = self.rpm_context(database)
            if self.rpm_context_parts(context)[2] != native_type or context != keyring.get('context'):
                raise Refused('retained private RPM DB SELinux context drift; journal retained')
        children = list(database.iterdir())
        allowed = {'.rpm.lock', 'rpmdb.sqlite', 'rpmdb.sqlite-shm', 'rpmdb.sqlite-wal'}
        if not {'.rpm.lock', 'rpmdb.sqlite'}.issubset({path.name for path in children}):
            raise Refused('private RPM DB is missing native SQLite/lock artifacts')
        for path in children:
            private_file(path, database)
            if path.name not in allowed or path.stat().st_mode & 0o022:
                raise Refused('unsupported private RPM database artifact shape or permissions')
            if native_type is not None and self.rpm_context(path) != context:
                raise Refused('retained private RPM DB child SELinux context drift; journal retained')
        keys = self.r.run(['rpm', '--dbpath', database, '-qa', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}\n'], timeout=60,
                          operation='verify private vendor-only public-key inventory').stdout.splitlines()
        if (len(keys) != 1 or not re.fullmatch('gpg-pubkey-[a-f0-9]+-[a-f0-9]+', keys[0])
                or keys != keyring.get('keys')):
            raise Refused('private RPM DB vendor-only key inventory changed')
        return database

    def official_rpm_keyring(self, owner):
        if not re.fullmatch('[a-f0-9]{32}', owner):
            raise Refused('invalid private RPM keyring owner')
        folder = private_dir(self.root / ('agent-policy-' + owner))
        key = folder / ('official-wazuh-' + uuid.uuid4().hex + '.key')
        self.r.run(['curl', '--fail', '--silent', '--show-error', '--max-time', '30', '--proto', '=https',
                    '--output', key, 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'], timeout=40,
                   operation='authenticated official Wazuh public key')
        private_file(key, folder); key.chmod(0o600); sync_file(key)
        database = folder / ('official-keyring-' + uuid.uuid4().hex)
        try:
            database.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise Refused('private RPM DB creation requires an exclusive new directory') from exc
        sync_directory(folder)
        context = self.prepare_rpm_keyring(database, owner)
        self.r.run(['rpm', '--dbpath', database, '--initdb'], operation='initialize private vendor keyring')
        self.r.run(['rpm', '--dbpath', database, '--import', key], operation='import only official Wazuh key')
        keys = self.r.run(['rpm', '--dbpath', database, '-qa', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}\n'], timeout=60,
                          operation='record private vendor-only public-key inventory').stdout.splitlines()
        result = {'key': str(key), 'sha256': digest(key), 'database': str(database), 'context': context, 'keys': keys}
        self.verify_rpm_keyring(result, owner)
        sync_tree(database)
        return result

    def verify_official_rpm(self, path, provider, keyring, owner):
        database = self.verify_rpm_keyring(keyring, owner)
        if digest(path) != provider['sha256']:
            raise Refused('official RPM provider/key/payload identity changed')
        text = self.r.run(['rpmkeys', '--dbpath', database, '-Kv', path], timeout=60,
                          operation='RPM signature against only official Wazuh key').stdout
        if not re.search(r'Signature.*: OK', text):
            raise Refused('RPM is not signed by the authenticated official Wazuh key')

    def restore_prior(self, before):
        if self.family == 'Debian':
            self.r.run(['apt-mark', 'hold' if before['held'] else 'unhold', 'wazuh-agent'], timeout=60,
                       operation='restore only previous Wazuh hold selection')
            if self.apt_state()['selection'] != before['selection']:
                raise Refused('previous native Wazuh selection was not restored')
            if self.file_state(self.PREF) != before['preference']:
                raise Refused('previous managed APT preference state was not restored')
            return
        current = self.dnf_context()
        if current['foreign'] != before['foreign'] or current['main']['sha256'] != before['main']['sha256'] or current['plugin']['sha256'] != before['plugin']['sha256']:
            raise Refused('refusing to overwrite changed foreign DNF policy')
        saved = before['locks']
        if saved['present']:
            atomic_text(self.LOCKS, saved['text'], mtime_ns=saved['mtime_ns'])
        else:
            durable_unlink(self.LOCKS)
        after = self.dnf_context()
        if after['locks'] != saved:
            raise Refused('previous global versionlock state was not restored')


def atomic_json(path, value):
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if tmp.exists():
            durable_unlink(tmp)


@contextlib.contextmanager
def bounded_flock(filename, shared=False, timeout=30):
    fd = os.open(filename, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise Refused('unsafe Wazuh coordinator lock')
        until = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= until:
                    raise Refused('Wazuh coordinator lock acquisition timed out') from exc
                time.sleep(0.02)
        yield
    finally:
        os.close(fd)


class HostWriter:
    """One durable owner for all Wazuh writers on this host, including hosts.

    The short coordinator mutex precedes component mutexes. A marker survives
    controller death; only explicit same-owner resume with stopped-operation
    confirmation may continue it. No expiry, PID inference or token takeover.
    """
    def __init__(self, root=ROOT):
        self.root = Path(root)
        self.path = self.root / 'writer-active.json'

    @contextlib.contextmanager
    def mutex(self, shared=False):
        MountTable().backup(path_shape(self.root, 'directory', missing=True))
        private_dir(self.root)
        with bounded_flock(self.root / 'coordinator.lock', shared=shared):
            yield

    def active(self):
        if self.path.is_symlink():
            raise Refused('unsafe Wazuh writer marker')
        if not self.path.exists():
            return None
        info = self.path.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise Refused('unsafe Wazuh writer marker permissions')
        try:
            item = json.loads(self.path.read_text())
            if (not re.fullmatch('[a-f0-9]{32}', item['owner'])
                    or item['component'] not in ('central', 'agent')
                    or item['mode'] not in ('apply', 'recover', 'canary')):
                raise ValueError('invalid writer identity')
            return item
        except (ValueError, KeyError, TypeError) as exc:
            raise Refused('invalid Wazuh writer marker; explicit inspection required') from exc

    def journals(self):
        return [item for kind in ('central', 'agent')
                if (item := Transaction(kind, root=self.root).active()) is not None]

    @staticmethod
    def identity(owner, component, mode):
        if (not re.fullmatch('[a-f0-9]{32}', owner) or component not in ('central', 'agent')
                or mode not in ('apply', 'recover', 'canary')):
            raise Refused('invalid Wazuh writer identity')

    def claim(self, owner, component, mode='apply'):
        self.identity(owner, component, mode)
        with self.mutex(shared=True):
            if self.active():
                raise Refused('another Wazuh writer owns this host; inspect and explicitly resume if interrupted')
        with self.mutex():
            if self.active():
                raise Refused('another Wazuh writer owns this host; inspect and explicitly resume if interrupted')
            if self.journals():
                raise Refused('unfinished component journal prevents a new Wazuh writer')
            if any((self.root / (kind + '-' + owner)).exists() for kind in ('central', 'agent')):
                raise Refused('writer owner would reuse a retained transaction backup')
            item = {'owner': owner, 'component': component, 'mode': mode}
            atomic_json(self.path, item)
            return item

    def resume(self, owner, component, mode='apply', confirmed=False):
        self.identity(owner, component, mode)
        if not confirmed:
            raise Refused('resume requires confirmation that the previous operation has stopped')
        with self.mutex():
            marker = self.active()
            journals = self.journals()
            if marker and (marker['owner'] != owner or marker['component'] != component):
                raise Refused('interrupted writer owner or component does not match')
            if any(item['owner'] != owner or item['kind'] != component for item in journals):
                raise Refused('component journal does not belong to the interrupted writer')
            if not marker and not journals:
                raise Refused('no interrupted writer or matching component journal to resume')
            item = {'owner': owner, 'component': component, 'mode': mode}
            atomic_json(self.path, item)
            return item

    def release(self, owner):
        with self.mutex():
            marker = self.active()
            if not marker or marker['owner'] != owner:
                raise Refused('writer release requires its exact active owner')
            if self.journals():
                raise Refused('unfinished component journal prevents writer release')
            durable_unlink(self.path)
            return {'released': True}

    def inspect(self):
        with self.mutex(shared=True):
            return {'writer': self.active(), 'journals': [
                {'component': item['kind'], 'owner': item['owner'], 'phase': item['phase']}
                for item in self.journals()]}

    @contextlib.contextmanager
    def guard(self, owner, component):
        with self.mutex(shared=True):
            marker = self.active()
            if not marker or marker['owner'] != owner or marker['component'] != component:
                raise Refused('operation requires the exact host-wide Wazuh writer owner')
            yield

    @contextlib.contextmanager
    def reader(self, component, owner=None):
        with self.mutex(shared=True):
            marker = self.active()
            if marker:
                own = owner and marker['owner'] == owner and marker['component'] == component
                stable_manager = component == 'central' and marker['component'] == 'agent'
                if not own and not stable_manager:
                    raise Refused('active Wazuh writer prevents a stable external read')
            elif owner:
                raise Refused('reader owner has no active Wazuh writer claim')
            yield


class Transaction:
    def __init__(self, kind, runner=None, root=ROOT):
        self.r = runner or Runner()
        self.kind = kind
        self.root = Path(root)
        self.path = self.root / (kind + '-active.json')

    @contextlib.contextmanager
    def lock(self, owner=None, reader=False):
        MountTable().backup(path_shape(self.root, 'directory', missing=True))
        private_dir(self.root)
        host = HostWriter(self.root)
        scope = host.reader(self.kind, owner) if reader else host.guard(owner, self.kind) if owner is not None else contextlib.nullcontext()
        with scope:
            with self.component_lock(shared=reader):
                yield

    @contextlib.contextmanager
    def component_lock(self, shared=False):
        fd = os.open(self.root / (self.kind + '.lock'),
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise Refused('unsafe transaction lock')
            try:
                fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Refused('another Wazuh transaction is running') from exc
            yield
        finally:
            os.close(fd)

    def active(self):
        if self.path.is_symlink():
            raise Refused('unsafe transaction journal')
        if not self.path.exists():
            return None
        info = self.path.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise Refused('unsafe transaction journal permissions')
        try:
            result = json.loads(self.path.read_text())
            if result['kind'] != self.kind or not re.fullmatch('[a-f0-9]{32}', result['owner']):
                raise ValueError('invalid journal identity')
            return result
        except (KeyError, TypeError, ValueError) as exc:
            raise Refused('invalid transaction journal; manual recovery required') from exc

    def idle(self):
        if self.active():
            raise Refused('incomplete Wazuh transaction; explicit recovery with its owner is required')

    def owned(self, owner, phases=None):
        item = self.active()
        if not item or item['owner'] != owner or (phases and item['phase'] not in phases):
            raise Refused('transaction owner or phase mismatch')
        return item

    def write(self, item, phase):
        item['phase'] = phase
        atomic_json(self.path, item)
        atomic_json(Path(item['backup']) / 'manifest.json', item)

    def begin(self, owner, state):
        self.idle()
        if not re.fullmatch('[a-f0-9]{32}', owner):
            raise Refused('invalid transaction owner')
        destination = self.root / (self.kind + '-' + owner)
        if destination.exists() or destination.is_symlink():
            raise Refused('transaction would reuse retained recovery material')
        backup = private_dir(destination)
        item = dict(state, kind=self.kind, owner=owner, backup=str(backup))
        self.write(item, 'reserved')
        return item

    def finish(self, item, phase):
        self.write(item, phase)
        durable_unlink(self.path)

    def capacity(self, paths, extra_bytes=0):
        size = 0
        for path in paths:
            # du accounts for sparse files and real allocated blocks.
            result = self.r.run(['du', '-sx', '--block-size=1', path], timeout=300)
            try:
                size += int(result.stdout.split()[0])
            except (ValueError, IndexError) as exc:
                raise Refused('invalid backup size probe') from exc
        # Cold archives are uncompressed: require size plus 20% and 1 GiB.
        if shutil.disk_usage(self.root).free < (size + extra_bytes) * 1.2 + 1024 ** 3:
            raise Refused('insufficient backup capacity before downtime')
        return size

    def archive(self, source, dest, capture=None, excluded=()):
        source = Path(source)
        kind = 'directory' if source.is_dir() else 'linked-file'
        if capture is None:
            capture = ClosedCapture.take({str(source): kind}, self.root, sealed=True)
        if not capture.get('sealed'):
            raise Refused('archive requires a content-sealed cold capture')
        if str(canonical(source)) not in capture['roots']:
            raise Refused('archive source escaped its complete cold capture')
        restore_sources({str(source): kind}, self.root)
        path_shape(Path(dest).parent, 'directory')
        if Path(dest).exists() or Path(dest).is_symlink():
            raise Refused('archive destination already exists')
        self.r.run(['tar', '--acls', '--xattrs', '--xattrs-include=*', '--selinux', '--numeric-owner', '--sparse',
                    *['--exclude=' + str(Path(path).relative_to(source.parent)) for path in excluded],
                    '-cpf', dest, '-C', source.parent, source.name], timeout=1800)
        self.r.run(['tar', '-tf', dest], timeout=300)
        checksum = digest(dest)
        sync_file(dest)
        return checksum

    def restore(self, source, archive, checksum, capture=None, runtime=None, proof=None):
        kind = 'directory' if Path(source).is_dir() else 'linked-file'
        if capture is None:
            ClosedCapture.take({str(source): kind}, self.root, missing=(str(source),))
        else:
            if str(canonical(source)) not in capture['roots']:
                raise Refused('restore source escaped its complete cold capture')
            ClosedCapture.take(capture['roots'], self.root, missing=tuple(capture['roots']))
        restore_sources({str(source): kind}, self.root, missing=(str(source),))
        private_file(archive, Path(archive).parent)
        if digest(archive) != checksum:
            raise Refused('backup checksum mismatch; refusing restore')
        source = canonical(source)
        archive = canonical(archive)
        disjoint([source], self.root)
        if source.exists():
            if runtime and proof and source == Path('/var/ossec'):
                runtime.prune(source, proof)
            elif source.is_dir():
                shutil.rmtree(source)
            else:
                durable_unlink(source)
        self.r.run(['tar', '--acls', '--xattrs', '--xattrs-include=*', '--selinux', '--numeric-owner', '--same-owner',
                    '--same-permissions', '-xpf', archive, '-C', source.parent], timeout=1800)
        sync_tree(source)



# These descriptors are software qualifications, not operator-supplied passes.
# V4 demonstrated only this native classic LinkedList mechanism. Systemd and
# integrated producer/recovery evidence is separately required for a candidate.
READER_ENGINES = {
    'd6ae52a9a0b5451ba10f3e936e81a10ddae8c0acc0f9618c54544dad2af9e3c8':
        {
            'version': '8.2312.0', 'package': '8.2312.0-3ubuntu9.2',
            'imfile_sha256': '8117d858deb8bbaef7c967e3af128fab5cd08ad930ffa943824c737a723f3c1b',
            'engine': 'classic-linked-list', 'transport': 'tcp'},
}
READER_PHASES = {
    'admitted', 'producer-stop-intent', 'producers-stopped', 'drained',
    'reader-stop-intent', 'reader-stopped', 'queue-sealed', 'cursor-prepare-intent',
    'cursor-prepared', 'cursor-retire-intent', 'cursor-retired',
    'cursor-publish-intent', 'cursor-published', 'exposure-intent',
    'reader-active', 'producers-start-intent', 'active', 'final',
}


def imfile_id(data):
    """Exact Ubuntu8.2312 imfile SipHash2-4, key00..0f, output LE bytes.

    Authenticated orig77403200... member plugins/imfile/siphash.c SHA5a26dbc0...
    and imfile.c SHA7cf15f39... get_file_id_hash/getFileID1315-1348. A short
    read has NO suffix; this identifier disambiguates, it does not authenticate.
    """
    if len(data) < 512:
        return ''
    data = data[:512]
    mask = (1 << 64) - 1
    key = bytes(range(16))
    k0, k1 = int.from_bytes(key[:8], 'little'), int.from_bytes(key[8:], 'little')
    v = [0x736f6d6570736575 ^ k0, 0x646f72616e646f6d ^ k1,
         0x6c7967656e657261 ^ k0, 0x7465646279746573 ^ k1]
    def rotate(value, count): return ((value << count) | (value >> (64 - count))) & mask
    def rounds(count):
        for _ in range(count):
            v[0] = (v[0] + v[1]) & mask; v[1] = rotate(v[1], 13) ^ v[0]; v[0] = rotate(v[0], 32)
            v[2] = (v[2] + v[3]) & mask; v[3] = rotate(v[3], 16) ^ v[2]
            v[0] = (v[0] + v[3]) & mask; v[3] = rotate(v[3], 21) ^ v[0]
            v[2] = (v[2] + v[1]) & mask; v[1] = rotate(v[1], 17) ^ v[2]; v[2] = rotate(v[2], 32)
    for offset in range(0, len(data) // 8 * 8, 8):
        block = int.from_bytes(data[offset:offset + 8], 'little')
        v[3] ^= block; rounds(2); v[0] ^= block
    block = (len(data) & 255) << 56
    for offset, byte in enumerate(data[len(data) // 8 * 8:]): block |= byte << (8 * offset)
    v[3] ^= block; rounds(2); v[0] ^= block; v[2] ^= 255; rounds(4)
    return (v[0] ^ v[1] ^ v[2] ^ v[3]).to_bytes(8, 'little').hex()


class ReaderSource:
    """Fresh Docker-bound source closure; proc names never grant FD authority."""
    def __init__(self, source, backup, proc=Path('/proc'), missing=()):
        self.source, self.backup, self.proc = canonical(source), backup, Path(proc)
        self.layout = ScopeLayout.inspect({str(self.source): 'directory'}, backup, missing=missing)
        # Explicit host/process mount namespaces: pure projection, not restore
        # policy or an assumption that container paths use host spelling.
        self.mounts = MountTable((self.proc / 'self/mountinfo').read_text())
        self.groups = {}
        for name, node in self.layout['nodes'].items():
            if node['type'] == 'file':
                key = tuple(node['scope_identity'][:2])
                self.groups.setdefault(key, []).append(name)
        self.current = None
        name = str(self.source / 'alerts/alerts.json')
        node = self.layout['nodes'].get(name)
        if node and node['type'] == 'symlink': node = self.layout['nodes'].get(node['resolved'])
        if node and node['type'] == 'file': self.current = tuple(node['scope_identity'][:2])

    @staticmethod
    def stamp(info):
        return [info.st_dev, info.st_ino, info.st_nlink, info.st_mode, info.st_uid,
                info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns]

    def process(self, pid):
        text = (self.proc / str(pid) / 'stat').read_text()
        fields = text.rsplit(') ', 1)[1].split()
        if fields[0] in ('Z', 'X', 'x'):
            raise Refused('source FD process is not live')
        return [pid, fields[19], os.stat(self.proc / str(pid) / 'ns/mnt').st_ino,
                (self.proc / 'sys/kernel/random/boot_id').read_text().strip()]

    def group(self, key):
        aliases = self.groups.get(key)
        if not aliases:
            raise Refused('source descriptor has no closed inode group')
        if any(not (Path(name) == self.source / 'alerts/alerts.json'
                        or self.source / 'alerts' in Path(name).parents) for name in aliases):
            raise Refused('unknown non-alert native reader source group')
        return aliases

    def descriptor(self, pid, number, protected_reader=False):
        folder = self.proc / str(pid)
        link = folder / 'fd' / number
        info = link.stat()
        if not stat.S_ISREG(info.st_mode): return None
        name = os.readlink(link)
        key = (info.st_dev, info.st_ino)
        if (key not in self.groups and str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev)) != self.mounts.project(self.source)[0]
                and not name.startswith(str(self.source) + '/')):
            return None  # Different backing filesystem cannot alias this source.
        raw = (folder / 'fdinfo' / number).read_text()
        fields = dict(line.split(':', 1) for line in raw.splitlines() if ':' in line)
        if not all(re.fullmatch(r'\s*[0-9]+\s*', fields.get(key, '')) for key in ('pos', 'mnt_id', 'ino')):
            raise Refused('unknown source FD metadata')
        if not re.fullmatch(r'\s*[0-7]+\s*', fields.get('flags', '')):
            raise Refused('unknown source FD flags')
        position, flags = int(fields['pos']), int(fields['flags'], 8)
        if position > (1 << 63) - 1 or int(fields['ino']) != info.st_ino:
            raise Refused('source FD inode/offset metadata differs')
        table = MountTable((folder / 'mountinfo').read_text())
        rows = [row for row in table.rows if row['id'] == fields['mnt_id'].strip()]
        if len(rows) != 1 or rows[0]['root'] is None:
            raise Refused('source FD mount identity is unknown')
        row = rows[0]
        device = str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev))
        if row['device'] != device:
            raise Refused('source FD mount device differs from fstat')
        # The diagnostic suffix is used ONLY to reject an unknown protected
        # orphan. Acceptance always requires the closed live inode group.
        label = Path(name.removesuffix(' (deleted)'))
        physical = None
        if label.is_absolute() and (label == row['point'] or row['point'] in label.parents):
            physical = row['root'] / label.relative_to(row['point'])
        source_device, source_location = self.mounts.project(self.source)
        related = (key in self.groups or (row['device'] == source_device and physical is not None
                   and (physical == source_location or source_location in physical.parents)))
        if not related: return None
        if key not in self.groups or info.st_nlink == 0:
            raise Refused('orphan or unknown protected source FD')
        aliases = self.group(key) if protected_reader else self.groups[key]
        if info.st_nlink != len(aliases):
            raise Refused('source FD has an outside hardlink alias')
        if protected_reader and ((flags & os.O_ACCMODE) != os.O_RDONLY
                                 or flags & getattr(os, 'O_PATH', 0)):
            raise Refused('native reader has a writable or opaque source FD')
        # At least one captured alias must be visible through THIS descriptor's
        # mount; an inode match alone does not bless an unknown bind namespace.
        visible = False
        for alias in aliases:
            alias_device, alias_location = self.mounts.project(Path(alias))
            if alias_device == row['device'] and (alias_location == row['root'] or row['root'] in alias_location.parents):
                logical = row['point'] / alias_location.relative_to(row['root'])
                try:
                    observed = (folder / 'root' / str(logical).lstrip('/')).stat()
                    visible |= (observed.st_dev, observed.st_ino, observed.st_nlink) == (info.st_dev, info.st_ino, len(aliases))
                except FileNotFoundError:
                    pass
        if not visible:
            raise Refused('source FD mount does not expose a closed source alias')
        after = link.stat()
        again = dict(line.split(':', 1) for line in (folder / 'fdinfo' / number).read_text().splitlines() if ':' in line)
        # Appends and normal reads may change size/time/position during live
        # observation. None is descriptor identity or logical drain authority.
        if (self.stamp(after)[:6] != self.stamp(info)[:6]
                or any(again.get(key) != fields.get(key) for key in ('ino', 'flags', 'mnt_id'))):
            raise Refused('source FD changed during classification')
        return {'fd': number, 'device': info.st_dev, 'inode': info.st_ino,
                'links': info.st_nlink, 'size': info.st_size, 'position': position,
                'flags': flags, 'mount': int(fields['mnt_id']), 'aliases': sorted(aliases)}

    def fds(self, pid, reader=True):
        if not pid: return []
        before = self.process(pid)
        folder = self.proc / str(pid) / 'fd'
        for attempt in range(3):
            names = sorted(path.name for path in folder.iterdir())
            if len(names) > 4096: raise Refused('source FD count exceeds bound')
            result = []
            try:
                for number in names:
                    if not number.isdecimal(): raise Refused('unknown source FD entry')
                    value = self.descriptor(pid, number, reader)
                    if value: result.append(value)
            except FileNotFoundError:
                # A closed slot may vanish in a live FD table. A reused or
                # foreign descriptor is a Refused, never retried into absence.
                if self.process(pid) != before:
                    raise Refused('source FD process changed during classification')
                if attempt == 2: raise
                continue
            if self.process(pid) != before:
                raise Refused('source FD process changed during classification')
            if sorted(path.name for path in folder.iterdir()) == names:
                return result
        raise Refused('source FD set changed during bounded classification')

    def frozen(self, keys):
        result = {}
        for key in sorted(keys):
            aliases = self.group(key)
            name = aliases[0]
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                if (before.st_dev, before.st_ino) != key or before.st_nlink != len(aliases):
                    raise Refused('source group changed before fingerprint')
                if before.st_size == 0:
                    raise Refused('empty native input is not qualified for handoff')
                prefix = os.pread(fd, min(512, before.st_size), 0)
                last = os.pread(fd, 1, before.st_size - 1)
                if self.stamp(os.fstat(fd)) != self.stamp(before):
                    raise Refused('source changed during endpoint inspection')
                result[str(key[0]) + ':' + str(key[1])] = {
                    'identity': self.stamp(before), 'aliases': sorted(aliases),
                    'fingerprint': imfile_id(prefix), 'complete': last == b'\n'}
            finally:
                os.close(fd)
        return result


class NativeCursor:
    """Qualified native O_TRUNC state reader; live coherence is not durability."""
    LIMIT = 1024 * 1024
    @staticmethod
    def json(data):
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result: raise Refused('duplicate native cursor key')
                result[key] = value
            return result
        try:
            value = json.loads(data, object_pairs_hook=unique)
        except (ValueError, UnicodeError) as exc:
            raise Refused('incoherent native cursor JSON') from exc
        required = {'filename', 'prev_was_nl', 'curr_offs', 'strt_offs'}
        if (not isinstance(value, dict) or not required.issubset(value)
                or set(value) - required - {'prev_line_segment', 'prev_msg_segment'}
                or not isinstance(value['filename'], str)
                or type(value['prev_was_nl']) is not int or value['prev_was_nl'] not in (0, 1)
                or any(type(value[key]) is not int or not 0 <= value[key] <= (1 << 63) - 1
                       for key in ('curr_offs', 'strt_offs'))
                or any(not isinstance(value[key], str) for key in ('prev_line_segment', 'prev_msg_segment') if key in value)):
            raise Refused('unsupported native cursor schema/types')
        return value

    @classmethod
    def read(cls, data, source, required, eof=False, frozen=None):
        with data.directory() as directory:
            namespace = data.identity(os.fstat(directory))
            if data.identity(os.stat('state', dir_fd=data.fd, follow_symlinks=False)) != namespace:
                raise Refused('native cursor directory changed')
            names = sorted(os.listdir(directory))
            if not names or len(names) > 2048:
                raise Refused('missing or excessive native cursor state')
            records, bound = {}, set()
            for name in names:
                match = re.fullmatch(r'imfile-state:([1-9][0-9]*)(?::([a-f0-9]{16}))?', name)
                if not match: raise Refused('unknown native cursor basename')
                inode = int(match[1]); candidates = [key for key in source.groups if key[1] == inode]
                if len(candidates) != 1: raise Refused('native cursor inode is stale or ambiguous')
                key = candidates[0]
                endpoint = source.frozen({key})
                identifier = str(key[0]) + ':' + str(key[1]); group = endpoint[identifier]
                if (match[2] or '') != group['fingerprint']:
                    raise Refused('native cursor fingerprint differs from closed source')
                if key in bound: raise Refused('competing native cursors for one source group')
                bound.add(key)
                with data.file(name, directory) as (opened, info):
                    if info.st_uid != data.stamp[3] or info.st_gid != data.stamp[4] or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > cls.LIMIT:
                        raise Refused('unsafe native cursor ownership/size')
                    payload = os.read(opened, cls.LIMIT + 1)
                    if len(payload) != info.st_size:
                        raise Refused('native cursor short coherent read')
                    value = cls.json(payload)
                    if (ReaderSource.stamp(os.fstat(opened)) != ReaderSource.stamp(info)
                            or ReaderSource.stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)) != ReaderSource.stamp(info)
                            or os.pread(opened, cls.LIMIT + 1, 0) != payload):
                        raise Refused('native cursor changed during coherent read')
                if value['filename'] not in (str(source.source / 'alerts/alerts.json'), *group['aliases']):
                    raise Refused('native cursor label has no watched/retained provenance')
                size = group['identity'][6]
                if not 0 <= value['strt_offs'] <= value['curr_offs'] <= size:
                    raise Refused('native cursor logical range differs from source')
                if (eof or key not in required) and (not group['complete'] or value['curr_offs'] != size or value['strt_offs'] != size
                            or value['prev_was_nl'] != 0 or value.get('prev_line_segment') or value.get('prev_msg_segment')):
                    raise Refused('native logical input has not reached a complete EOF')
                if frozen is not None and frozen.get(identifier) != group:
                    raise Refused('frozen source changed before native cursor witness')
                records[name] = {'source': identifier, 'logical': {key: value[key] for key in ('curr_offs','strt_offs','prev_was_nl')},
                                 'segments': {key: len(value.get(key, '')) for key in ('prev_line_segment','prev_msg_segment')},
                                 'identity': ReaderSource.stamp(info), 'sha256': hashlib.sha256(payload).hexdigest()}
            if not set(required).issubset(bound):
                raise Refused('native cursor is missing a current or retained input group')
            if (data.identity(os.fstat(directory)) != namespace
                    or data.identity(os.stat('state', dir_fd=data.fd, follow_symlinks=False)) != namespace):
                raise Refused('native cursor directory changed')
            if sorted(os.listdir(directory)) != names:
                raise Refused('native cursor membership changed during coherent read')
            data.namespace()
            return {'schema': 1, 'namespace': namespace, 'records': records, 'groups': source.frozen(bound)}


class ReaderData:
    """Pinned service-data capability. Syslog parents are not root controlled."""
    def __init__(self, path):
        self.path = canonical(path)
        restore_sources({str(self.path): 'directory'}, ROOT)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.stamp = self.identity(os.fstat(self.fd))

    @staticmethod
    def identity(info):
        return [info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode),
                info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]

    def close(self):
        os.close(self.fd)

    def namespace(self):
        if (self.identity(self.path.lstat()) != self.stamp
                or self.identity(os.fstat(self.fd)) != self.stamp
                or os.readlink('/proc/self/fd/' + str(self.fd)) != str(self.path)):
            raise Refused('reader service-data namespace changed')
        restore_sources({str(self.path): 'directory'}, ROOT)

    @contextlib.contextmanager
    def file(self, name, directory=None):
        if not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\0' in name:
            raise Refused('invalid reader data child')
        parent = self.fd if directory is None else directory
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            value = os.fstat(fd)
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
                raise Refused('reader data has unsupported type or external alias')
            yield fd, value
        finally:
            os.close(fd)

    def files(self, fd, prefix=None, copy_to=None):
        names, result, size = sorted(os.listdir(fd)), {}, 0
        if len(names) > 2048:
            raise Refused('reader file count exceeds qualified bound')
        for name in names:
            if prefix and not name.startswith(prefix):
                continue
            if prefix and not re.fullmatch(r'wazuh_alerts(?:\.[0-9]+|\.qi|\.da-engine)?', name):
                raise Refused('unknown native Wazuh queue file family')
            with self.file(name, fd) as (opened, info):
                if info.st_uid not in (0, self.stamp[3]):
                    raise Refused('foreign reader data owner')
                size += info.st_size
                if size > 512 * 1024 ** 2:
                    raise Refused('reader data exceeds qualified capacity bound')
                attrs = {key: os.getxattr(opened, key).hex() for key in sorted(os.listxattr(opened))}
                value = hashlib.sha256()
                destination = open(Path(copy_to) / name, 'xb') if copy_to is not None else None
                try:
                    while True:
                        block = os.read(opened, 1024 * 1024)
                        if not block:
                            break
                        value.update(block)
                        if destination:
                            destination.write(block)
                    if destination:
                        destination.flush()
                        os.fchmod(destination.fileno(), 0o600)
                        os.fsync(destination.fileno())
                    os.fsync(opened)
                    if os.fstat(opened) != info:
                        # atime may change from the read; content identities
                        # below deliberately compare every persistent field.
                        after = os.fstat(opened)
                        if any(getattr(after, field) != getattr(info, field) for field in
                               ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                                'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                            raise Refused('reader data changed during cold seal')
                finally:
                    if destination:
                        destination.close()
                result[name] = {'identity': self.identity(info), 'links': info.st_nlink,
                                'size': info.st_size, 'mtime': info.st_mtime_ns,
                                'sha256': value.hexdigest(), 'xattrs': attrs}
        os.fsync(fd)
        if copy_to is not None:
            sync_directory(copy_to)
        self.namespace()
        return result

    def layout(self, fd, queue=False):
        names = os.listdir(fd)
        if len(names) > 2048:
            raise Refused('reader namespace exceeds qualified file count')
        total = 0
        for name in names:
            if queue and not name.startswith('wazuh_alerts'):
                continue
            if queue and not re.fullmatch(r'wazuh_alerts(?:\.[0-9]+|\.qi|\.da-engine)?', name):
                raise Refused('unknown reader queue file family')
            with self.file(name, fd) as (_, info):
                if info.st_uid not in (0, self.stamp[3]):
                    raise Refused('reader namespace has foreign ownership')
                total += info.st_size
        if total > 512 * 1024 ** 2:
            raise Refused('reader namespace exceeds qualified size')
        self.namespace()

    def queue(self, copy_to=None):
        return self.files(self.fd, 'wazuh_alerts', copy_to)

    @classmethod
    def custody(cls, spool, identity, generation=None, checkpoint=None, cold=False):
        """CURRENT cold bytes before first exposure; live layout afterwards."""
        data = cls(spool)
        try:
            if data.stamp != identity:
                raise Refused('CURRENT reader queue changed before resume')
            if generation:
                actual = data.identity(os.stat('state', dir_fd=data.fd, follow_symlinks=False))
                if actual != generation['new']:
                    raise Refused('pending cursor generation changed')
                with data.directory() as state:
                    data.layout(state)
            if cold:
                if checkpoint is None or data.queue() != checkpoint['queue']:
                    raise Refused('CURRENT reader queue changed before resume')
            else:
                data.layout(data.fd, queue=True)
        finally:
            data.close()

    @contextlib.contextmanager
    def directory(self, name='state'):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            value = os.fstat(fd)
            if value.st_uid != self.stamp[3] or stat.S_IMODE(value.st_mode) != 0o700:
                raise Refused('unsupported cursor directory ownership')
            yield fd
        finally:
            os.close(fd)


class ReaderInputProfile:
    @staticmethod
    def qualify(observed, source, spool, owner):
        inputs, modules = [], []
        for entry in observed['resources']:
            attrs = entry['attrs']
            if entry['file'] == owner and entry['kind'] == 'input' and attrs.get('type', '').lower() == 'imfile': inputs.append(entry)
            if entry['file'] == owner and entry['kind'] == 'module' and Path(attrs.get('load', '')).name in ('imfile', 'imfile.so'): modules.append(entry)
        expected = {'type':'imfile', 'file':str(Path(source) / 'alerts/alerts.json'),
                    'tag':'pilot-wazuh-alert:', 'facility':'local5', 'severity':'info',
                    'persiststateinterval':'1', 'freshstarttail':'off', 'reopenontruncate':'on',
                    'addmetadata':'off', 'ruleset':'pilotWazuhForward'}
        module = {'load':'imfile', 'statefile.directory':str(Path(spool) / 'state')}
        if (len(inputs) != 1 or len(modules) != 1 or inputs[0]['file'] != owner
                or modules[0]['file'] != owner or inputs[0]['attrs'] != expected or modules[0]['attrs'] != module):
            raise Refused('unqualified complete native imfile input/module semantics')
        return {'schema':1, 'input':expected, 'module':module}


class ReaderNamespace:
    """One coordinator authority for live source closure and physical extent."""
    def __init__(self, source, spool, layout, mounts=None, owner_config=Path('/etc/rsyslog.d/31-pilot-wazuh.conf')):
        self.owner_config = str(owner_config)
        self.source, self.spool = Path(source), Path(spool)
        self.layout, self.mounts = layout, mounts or MountTable()
        self.roots = (self.source, self.spool)
        self.projected = [self.mounts.project(path) for path in self.roots]
        self.inodes = {tuple(node['scope_identity'][:2]) for node in layout['nodes'].values()
                       if node['type'] == 'file'}

    def path(self, value):
        if (not isinstance(value, str) or not value.startswith('/') or value.startswith('//')
                or os.path.normpath(value) != value or any(c in value for c in '$%\\\x00')):
            raise Refused('unknown noncanonical reader resource namespace')
        path = Path(value)
        if self.source == path or self.source in path.parents:
            # Only the already closed producer tree may contain supported
            # internal symlinks. External selectors cannot follow aliases.
            resolved = path.resolve()
            if resolved != self.source and self.source not in resolved.parents:
                raise Refused('reader selector escaped the closed producer source')
            return resolved
        return canonical(path)

    def literal(self, value):
        path = self.path(value)
        device, physical = self.mounts.project(path)
        if any(device == target_device and (physical == target or target in physical.parents)
               for target_device, target in self.projected):
            return True
        if path.exists() and path.is_file():
            info = path.stat()
            if (info.st_dev, info.st_ino) in self.inodes:
                return True
        return False

    def pattern(self, value):
        self.path(value)
        if not isinstance(value, str) or '**' in value:
            raise Refused('unknown recursive reader source pattern')
        parts = Path(value).parts
        first = next((i for i, part in enumerate(parts) if glob.has_magic(part)), None)
        if first is None:
            return self.literal(value)
        if any(part.count('[') != part.count(']') for part in parts):
            raise Refused('unknown reader source pattern syntax')
        prefix = self.path(str(Path(*parts[:first])))
        device, physical = self.mounts.project(prefix)
        candidate = (*physical.parts, *parts[first:])
        for target_device, target in self.projected:
            # Component matching preserves native path separators. Even an
            # empty future glob below a protected root cannot prove absence.
            if device == target_device and len(candidate) >= len(target.parts):
                if all(fnmatch.fnmatchcase(actual, pattern)
                       for actual, pattern in zip(target.parts, candidate)):
                    return True
        for count, match in enumerate(glob.iglob(value)):
            if count >= 2048:
                raise Refused('reader source pattern exceeds qualified bound')
            if self.literal(match):
                return True
        return False

    def resources(self, observed):
        if (observed.get('schema') != 2
                or observed.get('authorization') != 'UNVALIDATED_OBSERVATIONS'
                or not isinstance(observed.get('resources'), list)
                or len(observed['resources']) > 2048):
            raise Refused('reader observations lack the pinned typed resource protocol')
        mode = observed.get('mode_candidate')
        if mode not in ('never', 'disabled', 'enabled'):
            raise Refused('unknown reader baseline candidate')
        if mode == 'never' and (self.spool.exists() or self.spool.is_symlink()):
            raise Refused('retained Wazuh data cannot be classified as never configured')
        for resource in observed['resources']:
            if (not isinstance(resource, dict) or set(resource) != {'kind','attrs','workdirectory','file'}
                    or not isinstance(resource['attrs'], dict)
                    or resource['file'] not in observed.get('files', {})):
                raise Refused('unknown typed reader declaration')
            kind, attrs, anchor = resource['kind'], resource['attrs'], resource['workdirectory']
            related = False
            if kind == 'input' and attrs.get('type', '').lower() == 'imfile':
                if not attrs.get('file'):
                    raise Refused('unknown imfile source selector')
                related |= self.pattern(attrs['file'])
                if 'statefile' in attrs:
                    state = attrs['statefile']
                    if not state.startswith('/'):
                        raise Refused('unsupported explicit relative imfile state file')
                    related |= self.literal(state)
            if kind == 'module' and Path(attrs.get('load', '')).name in ('imfile', 'imfile.so'):
                directory = attrs.get('statefile.directory') or anchor
                if not directory:
                    raise Refused('unknown inherited imfile state directory')
                related |= self.literal(directory)
            if 'queue.spooldirectory' in attrs:
                # Directory alone is an anchor, not recursive queue access.
                anchor = attrs['queue.spooldirectory']
                self.path(anchor)
            filename = attrs.get('queue.filename')
            if filename is not None:
                if filename.startswith('/'):
                    location = filename
                else:
                    if (not anchor or filename in ('.', '..')
                            or not re.fullmatch(r'[A-Za-z0-9_.:-]+', filename)):
                        raise Refused('unknown inherited reader queue filename')
                    location = str(self.path(anchor) / filename)
                related |= self.literal(location)
            elif (attrs.get('queue.type', '').lower() == 'disk'
                  or attrs.get('queue.saveonshutdown', '').lower() in ('on', 'true', '1')):
                raise Refused('unknown native persistent queue filename')
            reserved = ((kind == 'input' and attrs.get('ruleset') == 'pilotWazuhForward')
                        or (kind == 'module' and Path(attrs.get('load', '')).name in ('imfile', 'imfile.so'))
                        or (kind == 'action' and attrs.get('name') == 'wazuh_alerts')
                        or (kind == 'ruleset' and attrs.get('name') == 'pilotWazuhForward'))
            owned = mode == 'enabled' and resource['file'] == self.owner_config and reserved
            if related and not owned:
                raise Refused('unowned reader declarations access a protected physical namespace')
            if kind == 'ruleset' and attrs.get('name') == 'pilotWazuhForward' and not owned:
                raise Refused('unowned reader still declares its reserved ruleset')
        result = dict(observed, mode=mode)
        if mode == 'enabled':
            result['input_profile'] = ReaderInputProfile.qualify(observed, self.source, self.spool, self.owner_config)
        return result


class ReaderPrestart:
    """Qualified Ubuntu vendor hook; OS loader/runtime remains the trusted baseline.

    Pins originate in official Ubuntu snapshot 20260610T120000Z signed indexes
    (noble/noble-updates), not a hash learned from the running host. The full
    policy tree is sealed conservatively; unrelated static edits also refuse.
    Compiled cache bytes are outputs of -W/-T, never immutable input authority.
    """
    HOOK = '/usr/lib/rsyslog/reload-apparmor-profile'
    PINS = {
        '/usr/lib/systemd/system/rsyslog.service': '2728f43f3e86d6eb2480d6cbc38a977e185b369c3733351459f40a9fc7581b2c',
        HOOK: 'eec0bf16836e34f166fb5da22836bd65676e5b670152a00c257f24d4176b2cac',
        '/usr/bin/dash': '86d31f6fb799e91fa21bad341484564510ca287703a16e9e46c53338776f4f42',
        '/usr/sbin/aa-status': 'af9f579ad039f0e669bfb15735c55efd17896f838d684e7f9be15b09fa1e2dd4',
        '/usr/sbin/apparmor_parser': '6bc852b37807961c14976be9a227ae96bd817f73b5189cb0e0ff5eca4448c01c',
        '/etc/apparmor/parser.conf': 'f8586f1c3bfd7abac6a182c1b45d22a8397c0db5a737b54bc8f9fc48da53d5bd',
    }
    CONTEXT = ('Environment', 'EnvironmentFiles', 'PassEnvironment', 'UnsetEnvironment',
               'ExecSearchPath', 'RootDirectory', 'RootImage', 'WorkingDirectory',
               'PAMName', 'User', 'Group', 'BindPaths', 'BindReadOnlyPaths',
               'ReadWritePaths', 'InaccessiblePaths', 'TemporaryFileSystem')
    POLICY = Path('/etc/apparmor.d')
    CONFIG = Path('/etc/apparmor')
    FEATURES = Path('/sys/kernel/security/apparmor/features')
    CACHE = Path('/var/cache/apparmor')

    def __init__(self, runner):
        self.r = runner

    @staticmethod
    def node(path, contents=True):
        path = canonical(path)
        before = path.lstat()
        if (before.st_uid != 0 or before.st_mode & 0o022
                or not (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode))
                or (stat.S_ISREG(before.st_mode) and before.st_nlink != 1)):
            raise Refused('unsafe prestart input/output namespace')
        result = [before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode),
                  before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)]
        if stat.S_ISREG(before.st_mode) and contents:
            result += [before.st_size, before.st_mtime_ns, before.st_ctime_ns, digest(path)]
        after = path.lstat()
        if (before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
                before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise Refused('prestart input changed during inspection')
        return result

    @classmethod
    def tree(cls, root, contents=True):
        result, pending = {}, [Path(root)]
        while pending:
            path = pending.pop()
            if len(result) >= 4096:
                raise Refused('prestart namespace exceeds qualified bounds')
            result[str(path)] = cls.node(path, contents)
            if path.is_dir():
                names = sorted(os.listdir(path))
                pending.extend(path / name for name in names)
                result[str(path)].append(names)
        # Recheck membership and object identities after the walk. This is a
        # static closure, deliberately not the live producer ScopeLayout.
        for name, expected in result.items():
            current = cls.node(name, contents)
            if Path(name).is_dir():
                current.append(sorted(os.listdir(name)))
            if current != expected:
                raise Refused('prestart closure changed during inspection')
        return result

    @classmethod
    def includes(cls):
        pending, seen = [cls.POLICY / 'usr.sbin.rsyslogd'], set()
        while pending:
            path = pending.pop()
            if path in seen:
                continue
            seen.add(path)
            if not path.exists():
                raise Refused('required prestart policy input absent')
            if path.is_dir():
                pending.extend(path / name for name in sorted(os.listdir(path))
                               if not name.startswith('.'))
                continue
            for line in path.read_text().splitlines():
                if re.match(r'^\s*#\s+include\b', line):
                    raise Refused('unknown prestart policy include syntax')
                if not re.match(r'^\s*(?:#?include|abi)\b', line):
                    if (not line.lstrip().startswith('#')
                            and re.search(r'\b(?:include|abi)\s', line.split('#', 1)[0])):
                        raise Refused('unknown inline prestart policy include syntax')
                    continue
                match = re.fullmatch(r'\s*(#?include|abi)\s+(?:(if exists)\s+)?'
                                     r'(?:<([^<>]+)>|"([^"\n]+)")\s*,?\s*(?:#.*)?', line)
                if not match:
                    raise Refused('unknown prestart policy include syntax')
                name = match[3] or match[4]
                if (not re.fullmatch(r'[A-Za-z0-9_./+-]+', name)
                        or '..' in Path(name).parts):
                    raise Refused('unknown prestart policy include target')
                target = Path(name) if name.startswith('/') else cls.POLICY / name
                if target != cls.POLICY and cls.POLICY not in target.parents:
                    raise Refused('prestart policy include escapes sealed inputs')
                if target.exists():
                    pending.append(target)
                elif not match[2]:
                    raise Refused('required prestart policy include absent')

    @staticmethod
    def ancestry(path):
        result = {}
        for parent in reversed((Path(path), *Path(path).parents)):
            if parent.exists() or parent.is_symlink():
                result[str(parent)] = ReaderPrestart.node(parent, contents=False)
            else:
                result[str(parent)] = None
        return result

    def environment(self, pid):
        text = self.r.run(['systemctl', 'show-environment'], timeout=20,
                          operation='reader service execution environment').stdout
        values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
        if set(values) != {'LANG', 'PATH'} or values['LANG'] not in ('C.UTF-8', 'C', 'en_US.UTF-8'):
            raise Refused('unqualified reader manager execution environment')
        allowed = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin'
        if values['PATH'] not in (allowed, allowed + ':/snap/bin'):
            raise Refused('unqualified reader service PATH')
        if pid:
            raw = (Path('/proc') / str(pid) / 'environ').read_bytes().split(b'\0')
            live = dict(value.decode().split('=', 1) for value in raw if b'=' in value)
            runtime = {'NOTIFY_SOCKET', 'LISTEN_PID', 'LISTEN_FDS', 'LISTEN_FDNAMES', 'USER',
                       'INVOCATION_ID', 'JOURNAL_STREAM', 'SYSTEMD_EXEC_PID',
                       'MEMORY_PRESSURE_WATCH', 'MEMORY_PRESSURE_WRITE'}
            if (set(live) - runtime != {'LANG', 'PATH'}
                    or any(live.get(name) != value for name, value in values.items())):
                raise Refused('reader live execution environment differs from qualified manager')
        return values

    def tools(self, env):
        result = {}
        for tool in ('aa-status', 'apparmor_parser'):
            result.update(self.resolve_tool(tool, '/usr/sbin/' + tool, env['PATH'].split(':')))
        return result

    def resolve_tool(self, tool, expected, directories):
        result = {}
        for directory in directories:
            name = Path(directory) / tool
            result.update(self.ancestry(name.parent))
            if name.exists() or name.is_symlink():
                if str(name) != expected:
                    raise Refused('reader prestart PATH shadowed before authenticated tool')
                result[str(name)] = self.node(name)
                return result
            result[str(name)] = None
        raise Refused('authenticated reader prestart tool absent from service PATH')

    @staticmethod
    def aliases():
        result = {}
        for name, target in (('/bin', 'usr/bin'), ('/sbin', 'usr/sbin'), ('/usr/bin/sh', 'dash')):
            info = Path(name).lstat()
            if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or os.readlink(name) != target:
                raise Refused('unqualified prestart interpreter alias')
            result[name] = [info.st_dev, info.st_ino, target]
        return result

    def inspect(self, service, protected):
        if (any(service.get(name, '') for name in self.CONTEXT)
                or service.get('DynamicUser') != 'no' or service.get('ProtectSystem') != 'no'
                or service.get('FragmentPath') != '/usr/lib/systemd/system/rsyslog.service'):
            raise Refused('unqualified prestart service execution context')
        if not protected:
            raise Refused('prestart namespace lacks actual protected transaction roots')
        files = {}
        for name, expected in self.PINS.items():
            files[name] = self.node(name)
            member_mode = 0o644 if name.endswith(('rsyslog.service', 'parser.conf')) else 0o755
            if (files[name][-1] != expected or files[name][4:6] != [0, member_mode]):
                raise Refused('reader prestart differs from authenticated Ubuntu member')
        # Deliberately finite stock usrmerge/interpreter aliases, not arbitrary
        # resolution followed by trusting whatever target happens to exist.
        aliases = self.aliases()
        env = self.environment(int(service.get('MainPID', '0')))
        search = self.tools(env)
        policy = {**self.tree(self.CONFIG), **self.tree(self.POLICY), **self.tree(self.FEATURES)}
        self.includes()
        cache = self.CACHE
        output = self.r.run(['/usr/sbin/apparmor_parser', '--print-cache-dir'], timeout=20,
                            operation='qualified AppArmor cache destination').stdout.strip()
        if (not re.fullmatch(re.escape(str(cache)) + r'/[A-Za-z0-9_.-]+', output)
                or Path(output).name in ('.', '..')):
            raise Refused('unqualified prestart cache destination')
        if not cache.is_dir() or not Path(output).is_dir():
            raise Refused('prestart cache namespace is not a directory')
        self.tree(cache, contents=False)
        roots = [self.CONFIG, self.POLICY, self.FEATURES, cache]
        table = MountTable()
        for root in roots:
            canonical(root)
            if table.containing(root)['root'] != Path('/'):
                raise Refused('prestart namespace uses a foreign bind/subtree mount')
            if any(row['point'] != root and root in row['point'].parents for row in table.rows):
                raise Refused('prestart namespace contains a foreign mount')
        ancestry = {}
        for root in [*roots, *(Path(name).parent for name in self.PINS)]:
            ancestry.update(self.ancestry(root))
        if not table.containing(cache)['writable']:
            raise Refused('prestart cache output filesystem is read-only')
        projections = [(str(root), table.project(root)) for root in roots]
        for name, (device, location) in projections:
            for other in [Path(value) for value in protected]:
                other_device, other_location = table.project(canonical(other))
                if device == other_device and (location == other_location or location in other_location.parents
                                               or other_location in location.parents):
                    raise Refused('prestart inputs/cache overlap protected transaction data')
            for other_name, (other_device, other_location) in projections:
                if name != other_name and device == other_device and (location == other_location
                        or location in other_location.parents or other_location in location.parents):
                    raise Refused('prestart policy input/output namespaces overlap')
        return {'schema': 1, 'files': files, 'aliases': aliases, 'environment': env,
                'search': search, 'ancestry': ancestry, 'policy': policy, 'cache': self.node(cache, False),
                'cache_destination': output, 'cache_directory': self.node(output, False),
                'mounts': {name: [device, str(location)] for name, (device, location) in projections},
                'protected': sorted(set(str(value) for value in protected))}


class ReaderUnits:
    """Narrow native unit protocol. A stop request is never a save proof."""
    SERVICE, SOCKET = 'rsyslog.service', 'syslog.socket'
    STATIC = ('Id', 'Names', 'FragmentPath', 'DropInPaths', 'Requires', 'After', 'Triggers',
              'TriggeredBy', 'UnitFileState', 'ExecStart', 'Listen', 'Accept',
              'RemoveOnStop', 'KillMode', 'SendSIGKILL', 'Restart', 'TimeoutStopUSec',
              'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecStopPre',
              'RefuseManualStart', 'RefuseManualStop', 'ExecCondition', 'ExecReload',
              *ReaderPrestart.CONTEXT, 'DynamicUser', 'ProtectSystem')
    RUNTIME = ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID',
               'ControlGroup', 'Result', 'ExecMainCode', 'ExecMainStatus', 'ExecMainStartTimestampMonotonic', 'ExecMainExitTimestampMonotonic', 'ControlPID', 'Job')
    def __init__(self, runner):
        self.r = runner

    def show(self, unit):
        text = self.r.run(['systemctl', 'show', unit, '--no-pager'] +
                          [value for field in self.STATIC + self.RUNTIME for value in ('-p', field)],
                          timeout=20, operation='reader native unit state').stdout
        result = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
        required = {'LoadState', 'ActiveState', 'SubState', 'InvocationID', 'ControlGroup',
                    'Result', 'ControlPID', 'Job'}
        if unit == self.SERVICE:
            required.update({'MainPID', 'ExecMainCode', 'ExecMainStatus',
                             'ExecMainStartTimestampMonotonic', 'ExecMainExitTimestampMonotonic'})
        if not required.issubset(result) or result.get('LoadState') != 'loaded':
            raise Refused('unknown reader native unit properties')
        return result

    @staticmethod
    def control(value):
        result = {key: value.get(key, '') for key in ReaderUnits.STATIC}
        for key in ReaderUnits.STATIC:
            if key.startswith('Exec') and key not in ('ExecSearchPath',):
                result[key] = ReaderUnits.commands(result[key])
        for key in ('Names', 'Requires', 'After', 'Triggers', 'TriggeredBy'):
            result[key] = sorted(result[key].split())
        return result

    @staticmethod
    def commands(text):
        """Consume every native declared-command record; discard only runtime fields.

        Qualified systemctl serialization uses unquoted plain argv tokens here.
        Unknown escapes/quoting are refused rather than interpreted differently
        from systemd. A second command can never hide after a first regex match.
        """
        records = []
        pattern = re.compile(r'\s*\{ path=([^ ;{}]+) ; argv\[\]=([^;{}]+) ; '
                             r'ignore_errors=(yes|no) ; start_time=(\[[^]{}]*\]) ; '
                             r'stop_time=(\[[^]{}]*\]) ; pid=([0-9]+) ; '
                             r'code=([^ ;{}]+) ; status=([0-9]+(?:/[0-9]+)?) \}')
        offset = 0
        while offset < len(text):
            if offset and text.startswith(' ; ', offset):
                offset += 3
            match = pattern.match(text, offset)
            if not match:
                raise Refused('unknown reader declared Exec command serialization')
            argv = match[2].split()
            if (not argv or any(not re.fullmatch(r'[A-Za-z0-9_./:=+-]+', value) for value in argv)
                    or argv[0] != match[1]):
                raise Refused('unknown reader declared Exec argv')
            records.append({'path': match[1], 'argv': argv, 'ignore_errors': match[3] == 'yes'})
            offset = match.end()
        return records

    @staticmethod
    def static(proof):
        if proof.get('schema') != 2 or 'prestart' not in proof:
            raise Refused('reader native proof lacks qualified static authority')
        return {name: proof[name] for name in ('schema', 'units', 'fragments', 'prestart', 'boot')}

    @staticmethod
    def process(pid):
        result = AuditRuntime.process(pid)
        path = Path('/proc') / str(pid)
        fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
        if fields[0] in ('Z', 'X', 'x'):
            raise Refused('reader process is not live')
        status = (path / 'status').read_text()
        result.update(boot=AuditRuntime.boot(), mac=(path / 'attr/current').read_text().strip(),
                      executable_sha256=digest(path / 'exe'),
                      uid=re.search(r'^Uid:\s+(.+)$', status, re.M)[1].split(),
                      gid=re.search(r'^Gid:\s+(.+)$', status, re.M)[1].split())
        return result

    def admit(self, protected=()):
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                       if '=' in line)
        if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04':
            raise Refused('reader pause supports the qualified Ubuntu24 unit lifecycle only')
        service, socket = self.show(self.SERVICE), self.show(self.SOCKET)
        for value, unit, enabled in ((service, self.SERVICE, 'enabled'), (socket, self.SOCKET, 'static')):
            if (value['Id'] != unit or value['ActiveState'] != 'active'
                    or value['UnitFileState'] != enabled or value['DropInPaths']
                    or value['Job'] not in ('', '0')):
                raise Refused('unsupported reader unit state or extra activation')
        if (set(service['Names'].split()) != {'rsyslog.service', 'syslog.service'}
                or socket['Names'].split() != ['syslog.socket']
                or set(service['After'].split()) != {'sysinit.target', 'system.slice', 'syslog.socket',
                                                    'systemd-journald.socket', 'basic.target'}
                or set(socket['After'].split()) != {'-.mount', 'system.slice'}
                or set(service['Requires'].split()) != {'sysinit.target', 'syslog.socket', 'system.slice'}
                or service['TriggeredBy'].split() != [self.SOCKET] or service['Triggers']
                or socket['TriggeredBy'] or socket['Triggers'].split() != [self.SERVICE]
                or set(socket['Requires'].split()) != {'-.mount', 'system.slice'}
                or socket['Listen'] != '/run/systemd/journal/syslog (Datagram)'
                or socket['Accept'] != 'no' or socket['RemoveOnStop'] != 'no'
                or service['KillMode'] != 'control-group' or service['SendSIGKILL'] != 'yes'
                or service['Restart'] != 'on-failure' or service['TimeoutStopUSec'] not in ('1min 30s', '90s')
                or any(value.get(hook) for value in (service, socket)
                       for hook in ('ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecStopPre', 'ExecCondition', 'ExecReload'))
                or bool(socket.get('ExecStartPre'))
                or any(value.get(key) == 'yes' for value in (service, socket)
                       for key in ('RefuseManualStart', 'RefuseManualStop'))):
            raise Refused('unsupported reader unit/socket dependency graph')
        controls = {self.SERVICE: self.control(service), self.SOCKET: self.control(socket)}
        command = lambda path, argv: {'path': path, 'argv': argv, 'ignore_errors': False}
        if (controls[self.SERVICE]['ExecStart'] != [command('/usr/sbin/rsyslogd', ['/usr/sbin/rsyslogd', '-n', '-iNONE'])]
                or controls[self.SOCKET]['ExecStart']):
            raise Refused('unsupported reader declared start commands')
        prestart = None
        if controls[self.SERVICE]['ExecStartPre']:
            if controls[self.SERVICE]['ExecStartPre'] != [command(ReaderPrestart.HOOK, [ReaderPrestart.HOOK])]:
                raise Refused('unsupported reader declared prestart commands')
            prestart = ReaderPrestart(self.r).inspect(service, protected)
        if service['ControlGroup'] != '/system.slice/rsyslog.service':
            raise Refused('reader cgroup escaped qualified service scope')
        process = self.process(int(service['MainPID']))
        if (process['argv'] != ['/usr/sbin/rsyslogd', '-n', '-iNONE']
                or process['exe'] != '/usr/sbin/rsyslogd'
                or process['mac'] != 'rsyslogd (enforce)'):
            raise Refused('unsupported loaded reader executable/config/MAC')
        files = {}
        for value in (service, socket):
            filename = canonical(value['FragmentPath'])
            info = filename.stat()
            if info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
                raise Refused('unsafe reader unit fragment')
            files[str(filename)] = digest(filename)
        for policy in (Path('/etc/apparmor.d/usr.sbin.rsyslogd'), Path('/etc/apparmor.d/local/usr.sbin.rsyslogd')):
            if policy.exists() or policy.is_symlink():
                path_shape(policy, 'file')
                if policy.stat().st_uid != 0 or policy.stat().st_mode & 0o022:
                    raise Refused('reader MAC policy has unknown ownership')
                files[str(policy)] = digest(policy)
        return {'schema': 2, 'units': controls, 'prestart': prestart,
                'process': process, 'invocation': service['InvocationID'],
                'cgroup': service['ControlGroup'], 'start_monotonic': service['ExecMainStartTimestampMonotonic'], 'fragments': files,
                'boot': AuditRuntime.boot()}

    def boundary(self, proof):
        self.static(proof)
        if AuditRuntime.boot() != proof['boot']:
            raise Refused('reader lifecycle reboot is not qualified')
        for unit, expected in proof['units'].items():
            if self.control(self.show(unit)) != expected:
                raise Refused('reader unit policy changed during transaction')
        if proof['prestart'] is not None:
            observed = ReaderPrestart(self.r).inspect(self.show(self.SERVICE), proof['prestart']['protected'])
            if observed != proof['prestart']:
                raise Refused('reader prestart execution/input authority changed')
        if any(digest(path) != value for path, value in proof['fragments'].items()):
            raise Refused('reader unit fragment changed during transaction')

    def stop(self, proof, requested=False):
        self.boundary(proof)
        if not requested:
            if self.process(proof['process']['pid']) != proof['process']:
                raise Refused('reader invocation changed before stop')
            self.r.run(['systemctl', 'stop', '--no-block', self.SOCKET, self.SERVICE],
                       timeout=20, operation='request graceful reader unit stop')
        if requested:
            current = self.show(self.SERVICE)
            if current['ActiveState'] == 'active' and current['Job'] in ('', '0'):
                if self.process(int(current['MainPID'])) != proof['process']:
                    raise Refused('reader reactivated with an unknown invocation')
                self.r.run(['systemctl', 'stop', '--no-block', self.SOCKET, self.SERVICE],
                           timeout=20, operation='reconcile recorded reader stop intent')
        deadline = time.monotonic() + 110
        while True:
            service, socket = self.show(self.SERVICE), self.show(self.SOCKET)
            self.boundary(proof)
            old = Path('/proc') / str(proof['process']['pid'])
            if service['ActiveState'] == socket['ActiveState'] == 'inactive':
                if (service['ExecMainStartTimestampMonotonic'] != proof['start_monotonic']
                        or not service['ExecMainExitTimestampMonotonic'].isdigit()
                        or int(service['ExecMainExitTimestampMonotonic']) < int(proof['start_monotonic'])
                        or service['ControlPID'] != '0'
                        or service['InvocationID'] not in ('', proof['invocation'])
                        or service['Job'] not in ('', '0') or socket['Job'] not in ('', '0')
                        or service['Result'] != 'success' or socket['Result'] != 'success'
                        or service['ExecMainCode'] != '1' or service['ExecMainStatus'] != '0'
                        or old.exists() or service['MainPID'] != '0'):
                    raise Refused('reader did not prove a qualified graceful exit')
                cgroup = Path('/sys/fs/cgroup') / proof['cgroup'].lstrip('/')
                if cgroup.exists() and any((node / 'cgroup.procs').read_text().strip()
                                           for node in [cgroup] + list(cgroup.rglob('*'))
                                           if node.is_dir() and (node / 'cgroup.procs').exists()):
                    raise Refused('reader cgroup still has processes')
                # A stale filesystem pathname is permitted, a live kernel
                # activation socket/held socket FD is not.
                if any(line.split()[-1:] == ['/run/systemd/journal/syslog']
                       for line in Path('/proc/net/unix').read_text().splitlines()[1:]):
                    raise Refused('reader activation socket remains held in the kernel')
                return {'graceful': True, 'invocation': proof['invocation'],
                        'exit': [service['ExecMainCode'], service['ExecMainStatus']]}
            if time.monotonic() >= deadline:
                raise Refused('reader stop timed out; no queue save authority')
            time.sleep(0.25)

    def start(self, proof):
        self.boundary(proof)
        # These are exactly the prior-active admitted units; never enable,
        # disable, mask, relabel, kill or rewrite policy.
        self.r.run(['systemctl', 'start', self.SOCKET, self.SERVICE], timeout=110,
                   operation='resume prior active reader units')
        service, socket = self.show(self.SERVICE), self.show(self.SOCKET)
        self.boundary(proof)
        if service['ActiveState'] != 'active' or socket['ActiveState'] != 'active':
            raise Refused('reader prior active units did not resume')
        return self.process(int(service['MainPID']))


READER_TRANSITIONS = {
    'admitted': {'producer-stop-intent', 'producers-stopped', 'final'},
    'producer-stop-intent': {'producers-stopped', 'final'},
    'producers-stopped': {'drained', 'queue-sealed', 'exposure-intent', 'producers-start-intent', 'final'},
    'drained': {'reader-stop-intent'},
    'reader-stop-intent': {'reader-stopped'},
    'reader-stopped': {'queue-sealed', 'exposure-intent', 'final'},
    'queue-sealed': {'reader-stopped', 'cursor-prepare-intent', 'cursor-retire-intent', 'cursor-publish-intent', 'cursor-published', 'exposure-intent', 'producers-start-intent', 'final'},
    'cursor-prepare-intent': {'cursor-prepared', 'reader-stopped', 'queue-sealed'},
    'cursor-prepared': {'cursor-retire-intent', 'cursor-publish-intent', 'reader-stopped', 'queue-sealed'},
    'cursor-retire-intent': {'cursor-retired', 'cursor-publish-intent', 'reader-stopped', 'queue-sealed'},
    'cursor-retired': {'cursor-publish-intent', 'reader-stopped', 'queue-sealed'},
    'cursor-publish-intent': {'cursor-published', 'reader-stopped', 'queue-sealed'},
    'cursor-published': {'exposure-intent', 'producers-start-intent', 'reader-stopped', 'queue-sealed', 'final'},
    'exposure-intent': {'reader-active', 'drained'},
    'reader-active': {'producers-start-intent', 'drained', 'final'},
    'producers-start-intent': {'active', 'drained', 'final'},
    'active': {'drained', 'reader-stopped', 'queue-sealed', 'producers-start-intent', 'final'},
    'final': {'drained', 'reader-stopped', 'queue-sealed', 'producers-start-intent', 'final'},
}


class Reader:
    """Current queue custody. Cursor archives/evidence are never restore input."""
    PROC = Path('/proc')
    SPOOL = Path('/var/spool/rsyslog/pilot-wazuh')
    PROFILE = Path('/etc/rsyslog.d/pilot-wazuh/profile.json')
    CONFIG = Path('/etc/rsyslog.d/31-pilot-wazuh.conf')
    CHECKER = Path('/usr/local/libexec/pilot-wazuh-heartbeat')
    def __init__(self, central, checker_hash='', request=None, ack=False):
        self.t, self.r = central, central.r
        self.checker_hash, self.request, self.ack = checker_hash, request or {}, ack
        self.units = ReaderUnits(self.r)

    @classmethod
    def check_tool_destinations(cls):
        folder = Path('/usr/local/libexec')
        path_shape(folder, 'directory', missing=True)
        for parent in (folder, *folder.parents):
            if parent.exists() and (parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022):
                raise Refused('reader control-code directory is writable or foreign')
        for name in ('pilot-wazuh-heartbeat', 'pilot-wazuh-delivery', 'pilot-siem-relp-check'):
            path = folder / name
            if path.exists() or path.is_symlink():
                path_shape(path, 'file')
                if path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
                    raise Refused('reader control-code target has foreign ownership or permissions')
        return {'control_code_scope': True, 'create_directory': not folder.exists()}

    def observe(self, loaded=True):
        # Old journals and fresh unmanaged hosts need no adjacent helper.
        resources = any(path.exists() or path.is_symlink() for path in
                        (self.PROFILE, self.CONFIG, self.SPOOL, Path('/etc/rsyslog.conf')))
        if not self.checker_hash:
            if resources:
                raise Refused('configured reader requires the pinned inspection helper')
            return {'schema': 2, 'mode_candidate': 'never', 'files': {}, 'profile': None,
                    'pid': 0, 'resources': [], 'authorization': 'UNVALIDATED_OBSERVATIONS'}
        path_shape(self.CHECKER, 'file')
        info = self.CHECKER.stat()
        if any(parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022 for parent in self.CHECKER.parents):
            raise Refused('reader inspection helper has untrusted ancestors')
        if info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or digest(self.CHECKER) != self.checker_hash:
            raise Refused('reader inspection helper differs from tracked source')
        return self.r.json([self.CHECKER, 'inspect-reader'] + ([] if loaded else ['--cold']), timeout=40,
                           operation='inspect effective owned reader baseline')

    def inspect(self, state=None, loaded=True):
        # Discovery has no registry-bound C12 gate: original version skew may
        # legitimately be the baseline being repaired/restored.
        state = state if state is not None else self.t.discover()
        source = self.source(state)
        missing = (source,) if not Path(source).exists() and state.get('phase') == 'recovering' else ()
        layout = ScopeLayout.inspect({source: 'directory'}, self.t.root, missing=missing)
        mounts = MountTable()
        observed = self.observe(loaded=loaded)
        result = ReaderNamespace(source, self.SPOOL, layout, mounts, self.CONFIG).resources(observed)
        if result['mode'] != 'never' and result.get('profile', {}).get('source') not in (source, ''):
            raise Refused('owned reader profile source differs from actual Docker source')
        result['source_proof'] = {'source': source, 'helper': self.checker_hash,
                                  'root_identity': layout['nodes'].get(source, {}).get('scope_identity'),
                                  'physical': [str(value) for value in mounts.project(Path(source))]}
        return result

    def source(self, state):
        """Fresh Docker source authority, independent of profile/request text."""
        ids = self.r.run(['docker', 'ps', '-aq', '--no-trunc', '--filter',
                          'label=com.docker.compose.project=single-node', '--filter',
                          'label=com.docker.compose.service=wazuh.manager'], timeout=30,
                         operation='current reader producer identity').stdout.split()
        if len(ids) == 1:
            container = self.r.json(['docker', 'inspect', ids[0]], timeout=30,
                                    operation='reader actual producer mount')[0]
            labels = container['Config']['Labels']
            if (labels.get('com.docker.compose.project') != 'single-node'
                    or labels.get('com.docker.compose.service') != 'wazuh.manager'):
                raise Refused('reader producer is outside the owned project')
            values = [entry for entry in container['Mounts']
                      if entry['Destination'] == '/var/ossec/logs']
            if len(values) != 1 or values[0]['Type'] != 'volume':
                raise Refused('reader producer lacks one owned logs volume')
            binding = {'name': values[0]['Name'], 'path': values[0]['Source']}
        elif not ids:
            # Containers may be absent only during genuine cold rollback.
            # The private active journal, writer, all backup artifacts and fresh
            # volume/root ownership jointly authorize this narrow fallback.
            owner = state.get('owner')
            active = self.t.owned(owner, ('recovering',))
            writer = HostWriter(self.t.root).active()
            if (active.get('kind') != 'central' or not writer
                    or writer['owner'] != owner or writer['component'] != 'central'
                    or state.get('backup') != active.get('backup')):
                raise Refused('absent reader producer lacks owned recovery authority')
            self.t.validate_restore_scope(active)
            binding = active.get('reader_source_volume')
            if not binding:
                raise Refused('cold journal lacks native logs volume binding')
        else:
            raise Refused('reader producer inventory is ambiguous')
        if (not isinstance(binding, dict) or set(binding) != {'name','path'}
                or not re.fullmatch(r'single-node_[A-Za-z0-9_.-]+', binding['name'])):
            raise Refused('unknown reader source volume binding')
        volume = self.r.json(['docker', 'volume', 'inspect', binding['name']], timeout=30,
                             operation='current reader source volume ownership')[0]
        docker_root = canonical(self.r.run(['docker', 'info', '--format', '{{.DockerRootDir}}'],
                                           timeout=30, operation='current reader Docker data root').stdout.strip())
        expected = docker_root / 'volumes' / binding['name'] / '_data'
        if (volume.get('Driver') != 'local' or volume.get('Options')
                or volume.get('Labels', {}).get('com.docker.compose.project') != 'single-node'
                or canonical(volume['Mountpoint']) != expected
                or canonical(binding['path']) != expected or str(expected) not in state['paths']
                or (state.get('docker_root') and canonical(state['docker_root']) != docker_root)):
            raise Refused('reader source is not the current owned selected volume')
        recorded = state.get('reader_source_volume')
        if recorded and recorded != binding:
            raise Refused('reader source volume changed during the owned operation')
        state['reader_source_volume'] = binding
        return str(expected)


    def source_capability(self, state, source=None):
        source = source or self.source(state)
        missing = ()
        if not Path(source).exists():
            if state.get('phase') != 'recovering' or self.source(state) != str(source):
                raise Refused('absent producer source lacks validated cold recovery authority')
            missing = (str(source),)
        return ReaderSource(source, self.t.root, self.PROC, missing)

    def source_users(self, state, source, reader_pid=None, producers=True, reader_fds=True):
        capability = self.source_capability(state, source)
        containers = {entry['container'] for entry in state['images'].values()} if producers else set()
        for process in self.PROC.iterdir():
            if not process.name.isdecimal() or int(process.name) == os.getpid(): continue
            try:
                executable = os.readlink(process / 'exe'); pid = int(process.name)
                if Path(executable.removesuffix(' (deleted)')).name == 'rsyslogd' and pid != reader_pid:
                    raise Refused('unknown additional native reader invocation')
                cgroups = (process / 'cgroup').read_text()
                container = any(re.search(r'(?:/docker/' + re.escape(identity) + r'(?:/|$)|/docker-' + re.escape(identity) + r'\.scope(?:/|$))', cgroups)
                                for identity in containers if re.fullmatch('[a-f0-9]{64}', identity))
                records = capability.fds(pid, reader=pid == reader_pid)
                if records and not (reader_fds and pid == reader_pid) and not container:
                    raise Refused('unowned process retains a Wazuh producer source FD')
            except (FileNotFoundError, ProcessLookupError):
                if reader_pid and int(process.name) == reader_pid:
                    raise Refused('native reader disappeared during source exclusion')
                continue

    def fds(self, pid, source, drained=False):
        if drained:
            raise Refused('kernel FD positions cannot grant logical drain authority')
        # Caller boundary has freshly bound this path to the actual Docker
        # volume; this shared capability never accepts a profile path instead.
        return ReaderSource(source, self.t.root, self.PROC).fds(pid)

    def cursor(self, item, pid=0, eof=False, frozen=None, retry=False):
        value = self.use(item)
        deadline = time.monotonic() + (30 if retry else 0)
        while True:
            try:
                capability = self.source_capability(item, value['source'])
                if capability.current is None:
                    raise Refused('current native input has no closed source group')
                records = capability.fds(pid) if pid else []
                required = {(entry['device'], entry['inode']) for entry in records}
                if pid and capability.current not in required:
                    raise Refused('native reader has no classified current input FD')
                required.add(capability.current)
                if frozen is not None:
                    required.update(tuple(map(int, key.split(':'))) for key in frozen)
                data = ReaderData(self.SPOOL)
                try:
                    if data.stamp != value['spool_identity']:
                        raise Refused('native cursor spool identity changed')
                    result = NativeCursor.read(data, capability, required, eof=eof, frozen=frozen)
                    expected = value['generation']['new'] if value.get('generation') else value.get('cursor_identity')
                    if result['namespace'] != expected:
                        raise Refused('native cursor current generation differs')
                finally:
                    data.close()
                # Refresh namespace after coherent file reads too. Appends are
                # allowed only in admission; frozen proof is exact thereafter.
                after = self.source_capability(item, value['source'])
                if frozen is not None:
                    keys = {tuple(map(int, key.split(':'))) for key in frozen}
                    if after.frozen(keys) != frozen:
                        raise Refused('frozen producer source changed during cursor proof')
                result['watch'] = [{'device': entry['device'], 'inode': entry['inode']} for entry in records]
                return result
            except (Refused, FileNotFoundError, ProcessLookupError):
                if time.monotonic() >= deadline: raise
                time.sleep(0.05)

    def qualify(self, baseline):
        engine = canonical('/usr/sbin/rsyslogd')
        qualification = READER_ENGINES.get(digest(engine))
        action = baseline.get('action', {})
        if (not qualification or baseline['profile']['transport'] != qualification['transport']
                or action.get('queue.diskqueuetype') is not None
                or qualification['engine'] != 'classic-linked-list'):
            raise Refused('actual native reader queue engine has not been qualified')
        # New software/file engines are not inferred from a familiar selector.
        native = self.r.run([engine, '-v'], timeout=15, operation='reader software build').stdout
        if qualification['version'] not in native:
            raise Refused('reader native software identity differs from qualification')
        package = self.r.run(['dpkg-query', '-W', '-f=$' + '{Version}', 'rsyslog'], timeout=15,
                             operation='reader native package build').stdout.strip()
        module = canonical('/usr/lib/x86_64-linux-gnu/rsyslog/imfile.so')
        if package != qualification['package'] or digest(module) != qualification['imfile_sha256']:
            raise Refused('reader package/module differs from qualified software build')
        if baseline['pid']:
            info = module.stat()
            maps = (Path('/proc') / str(baseline['pid']) / 'maps').read_text().splitlines()
            entries = [line.split() for line in maps if str(module) in line]
            device = format(os.major(info.st_dev), '02x') + ':' + format(os.minor(info.st_dev), '02x')
            if not entries or any(len(entry) != 6 or entry[3] != device
                                  or entry[4] != str(info.st_ino) or entry[5] != str(module)
                                  for entry in entries):
                raise Refused('loaded imfile module differs from qualified on-disk identity')
        return dict(qualification, sha256=digest(engine))

    def admit(self, state, preview=False):
        observed = self.inspect(state)
        mode = observed['mode']
        if mode not in ('never', 'disabled', 'enabled'):
            raise Refused('unknown reader baseline mode')
        if self.request.get('selected'):
            requested_enabled = self.request.get('enabled')
            if type(requested_enabled) is not bool:
                raise Refused('unknown desired forwarding request')
            actual_enabled = mode == 'enabled'
            if requested_enabled != actual_enabled:
                raise Refused('mixed forwarding/profile and version transition refused')
            if mode != 'never':
                profile = observed['profile']
                if self.request.get('transport') != profile['transport']:
                    raise Refused('mixed forwarding transport and version transition refused')
                if actual_enabled:
                    action = observed['action']
                    if str(self.request.get('port')) != action.get('port'):
                        raise Refused('mixed receiver port and version transition refused')
                    hostlines = Path('/etc/hosts').read_text().splitlines()
                    addresses = [line.split('#', 1)[0].split()[0] for line in hostlines
                                 if 'siem-log-server' in line.split('#', 1)[0].split()[1:]]
                    try:
                        pinned = [str(ipaddress.ip_address(value)) for value in addresses]
                        desired = str(ipaddress.ip_address(self.request['address']))
                    except (ValueError, KeyError, TypeError) as exc:
                        raise Refused('unknown numeric receiver address binding') from exc
                    if pinned != [desired]:
                        raise Refused('mixed receiver address and version transition refused')
                    if profile['transport'] == 'relp':
                        tls = Path('/etc/rsyslog.d/pilot-relp-wazuh-sender')
                        expected = self.request.get('tls', {})
                        for name in ('ca.pem', 'cert.pem', 'key.pem'):
                            if digest(canonical(tls / name)) != expected.get(name):
                                raise Refused('mixed TLS material and version transition refused')
                        if observed['action'].get('tls.permittedpeer') != self.request.get('peer'):
                            raise Refused('mixed TLS peer and version transition refused')
        result = {'schema': 1, 'protocol': 2, 'source_epoch': uuid.uuid4().hex,
                  'mode': mode, 'phase': 'admitted', 'cycle': 0,
                  'generation': None, 'checkpoints': [], 'checker_sha256': self.checker_hash,
                  'baseline': observed, 'ack': self.ack, 'request': self.request,
                  'source': observed['source_proof']['source']}
        if mode == 'enabled':
            result['data_epoch'] = result['source_epoch']
        if mode == 'never':
            source = result['source']
            self.source_users(state, source, observed['pid'] or None, reader_fds=False)
            if observed['pid'] and (self.fds(observed['pid'], source)
                    or any(fnmatch.fnmatchcase(str(Path(source) / 'alerts/alerts.json'), entry.get('file', ''))
                           for entry in observed.get('imfile_inputs', []))):
                raise Refused('unowned Wazuh runtime reader cannot be treated as absent')
            if self.SPOOL.exists():
                raise Refused('retained Wazuh data cannot be classified as never configured')
            return result
        source = result['source']
        self.source_users(state, source, observed['pid'] or None, reader_fds=mode == 'enabled')
        if observed['profile']['source'] not in (source, ''):
            raise Refused('owned reader profile source differs from the actual volume')
        if self.SPOOL.exists():
            restore_sources(dict({path: 'directory' for path in state['paths']}, **{str(self.SPOOL): 'directory'}), self.t.root)
            ScopeLayout.inspect({str(self.SPOOL): 'directory'}, self.t.root)
            data = ReaderData(self.SPOOL)
            try:
                # Live admission is namespace-only. File data may still change.
                native_user, native_group = pwd.getpwnam('syslog'), grp.getgrnam('syslog')
                if data.stamp[3:] != [native_user.pw_uid, native_group.gr_gid, 0o700]:
                    raise Refused('managed reader spool is not private native syslog data')
                result['spool_identity'] = data.stamp
                result['cursor_present'] = 'state' in os.listdir(data.fd)
                result['cursor_identity'] = data.identity(os.stat('state', dir_fd=data.fd, follow_symlinks=False)) if result['cursor_present'] else None
                if result['cursor_present']:
                    with data.directory() as cursor:
                        data.layout(cursor)
                data.layout(data.fd, queue=True)
                names = os.listdir(data.fd)
                if mode == 'enabled' and any(name.endswith(('.da-engine', '.segq')) for name in names):
                    raise Refused('actual reader queue uses an unqualified file engine')
                if any(name.startswith('wazuh_alerts') and not re.fullmatch(
                        r'wazuh_alerts(?:\.[0-9]+|\.qi|\.da-engine)?', name) for name in names):
                    raise Refused('unknown actual native queue file engine')
                result['queue_present'] = any(name.startswith('wazuh_alerts') for name in names)
            finally:
                data.close()
        else:
            result.update(spool_identity=None, cursor_present=False, queue_present=False, cursor_identity=None)
        if mode == 'disabled':
            if result['cursor_present'] or result['queue_present']:
                result['engine'] = self.qualify(dict(observed, pid=0))
                if any(name.endswith(('.da-engine', '.segq')) for name in names):
                    raise Refused('retained disabled queue uses an unqualified engine')
            if self.fds(observed['pid'], source):
                raise Refused('disabled Wazuh reader still holds source FDs')
            if (result['cursor_present'] or result['queue_present']) and not self.ack and not preview:
                raise Refused('disabled retained reader recovery requires replay acknowledgement')
            return result
        if not self.ack and not preview:
            raise Refused('configured version upgrade requires rsyslog downtime and replay acknowledgement')
        result['engine'] = self.qualify(observed)
        if not result.get('spool_identity') or not result.get('cursor_present'):
            raise Refused('enabled native input lacks a qualified nonempty cursor baseline')
        native = self.cursor(dict(state, reader=result), pid=observed['pid'], retry=True)
        if any(not group['complete'] for group in native['groups'].values()):
            raise Refused('incomplete native input baseline is not qualified before downtime')
        result['units'] = self.units.admit(protected=[*state['paths'], str(ROOT), str(self.SPOOL)])
        self.verify_tools()
        self.r.run(['/usr/local/libexec/pilot-wazuh-delivery', 'local'], timeout=50,
                   operation='current effective local C11 baseline')
        return result

    def verify_tools(self):
        tools = self.request.get('tools', {})
        for name in ('pilot-wazuh-delivery', 'pilot-siem-relp-check'):
            path = Path('/usr/local/libexec') / name
            path_shape(path, 'file')
            if path.stat().st_uid != 0 or path.stat().st_mode & 0o022 or digest(path) != tools.get(name):
                raise Refused('reader proof tool differs from tracked source')

    def use(self, item):
        value = item['reader']
        if value.get('schema') != 1 or value.get('phase') not in READER_PHASES:
            raise Refused('unknown durable reader phase')
        self.checker_hash = value['checker_sha256']
        self.request = value['request']
        return value

    def write(self, item, phase):
        if phase not in READER_PHASES:
            raise Refused('invalid reader phase transition')
        value = self.use(item)
        if phase != value['phase'] and phase not in READER_TRANSITIONS[value['phase']]:
            reentry = (value.get('mode'), value['phase'], phase) in (
                ('disabled', 'producers-start-intent', 'queue-sealed'),
                ('enabled', 'exposure-intent', 'reader-stopped'))
            if not reentry:
                raise Refused('reader phase cannot grant this next effect')
            active = self.t.owned(item.get('owner'), ('recovering',))
            marker = HostWriter(self.t.root).active()
            if (not marker or marker['owner'] != active['owner'] or marker['component'] != 'central'
                    or active.get('reader', {}).get('mode') != value['mode']
                    or active.get('reader', {}).get('phase') != value['phase']):
                raise Refused('reader reentry lacks the matching durable recovery context')
            # Only pause writes these edges: after qualified StopProof for the
            # enabled branch, or after producer/FD exclusion and a fresh,
            # durable CURRENT seal for the disabled branch. No new effect
            # authority is inferred from an in-memory phase/proof flag.
        value['phase'] = phase
        if phase.startswith('cursor-') and value.get('generation'):
            value['generation']['phase'] = phase
        if value.get('generation'):
            value.setdefault('generations', {})[value['generation']['id']] = copy.deepcopy(value['generation'])
        self.t.write(item, item['phase'])

    def boundary(self, item, running=False):
        value = self.use(item)
        if value['mode'] == 'never':
            current = self.inspect(item, loaded=running)
            if current['mode'] != 'never':
                raise Refused('reader appeared during version-only transaction')
            return
        current = self.inspect(item, loaded=running)
        baseline = value['baseline']
        # inspect-reader runtime checks require an active reader. Cold boundary
        # checks immutable physical config/profile hashes without invoking it.
        for path, checksum in baseline['files'].items():
            if digest(canonical(path)) != checksum:
                raise Refused('reader include/config boundary changed')
        if digest(canonical(self.PROFILE)) != baseline['profile_sha256']:
            raise Refused('reader profile boundary changed')
        if current and (current['mode'] != value['mode'] or current['files'] != baseline['files']):
            raise Refused('reader runtime boundary differs from admitted baseline')
        if value['mode'] == 'enabled':
            self.units.boundary(value['units'])
        if value.get('engine'):
            software = current if current else dict(baseline, pid=0)
            if self.qualify(software) != value['engine']:
                raise Refused('native reader software/engine changed before an effect')


    @staticmethod
    def proof_hash(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def context(self, item):
        active = self.t.owned(item.get('owner'))
        marker = HostWriter(self.t.root).active()
        if (not marker or marker['owner'] != active['owner'] or marker['component'] != 'central'
                or marker['mode'] not in ('apply', 'recover') or item.get('backup') != active.get('backup')):
            raise Refused('reader proof lacks genuine journal/writer ownership')
        value = self.use(item)
        if value['mode'] == 'enabled' and (value.get('protocol') != 2
                or not re.fullmatch('[a-f0-9]{32}', value.get('source_epoch', ''))):
            raise Refused('old reader journal lacks logical handoff protocol')
        return active, value

    def input_binding(self, value):
        return self.proof_hash({'profile':value['baseline']['profile_sha256'],
                               'files':value['baseline']['files'],
                               'input':value['baseline']['input_profile'], 'engine':value['engine'],
                               'checker':value['checker_sha256'],
                               'static_units':ReaderUnits.static(value['units'])})

    def stopped(self, value):
        service, socket = self.units.show(ReaderUnits.SERVICE), self.units.show(ReaderUnits.SOCKET)
        if service['ActiveState'] != 'inactive' or socket['ActiveState'] != 'inactive':
            raise Refused('reader cold authority requires the original stopped invocation')
        return self.units.stop(value['units'], requested=True)

    def seal_current(self, item):
        value = self.use(item)
        if not value.get('spool_identity'):
            return {'cursor_identity':None, 'cursor':{}, 'checkpoint':None}
        ScopeLayout.inspect({str(self.SPOOL): 'directory'}, self.t.root)
        data = ReaderData(self.SPOOL)
        try:
            if data.stamp != value['spool_identity']:
                raise Refused('reader spool identity changed')
            cursor_identity, cursor_files = None, {}
            if 'state' in os.listdir(data.fd):
                with data.directory() as cursor:
                    cursor_identity = data.identity(os.fstat(cursor))
                    cursor_files = data.files(cursor)
            cycle = value['cycle'] + 1
            destination = Path(item['backup']) / ('reader-queue-evidence-' + uuid.uuid4().hex)
            value.setdefault('checkpoint_intents', []).append({'cycle':cycle, 'evidence':str(destination)})
            self.t.write(item, item['phase'])
            if destination.exists(): raise Refused('reader evidence name already exists')
            private_dir(destination)
            queue = data.queue(destination)
            checkpoint = {'cycle':cycle, 'kind':'CURRENT_EVIDENCE_ONLY', 'queue':queue, 'evidence':str(destination)}
            value['cycle'] = cycle; value['checkpoints'].append(checkpoint)
            return {'cursor_identity':cursor_identity, 'cursor':cursor_files, 'checkpoint':checkpoint}
        finally:
            data.close()

    def cursor_custody(self, value, authority, generation=False):
        ReaderData.custody(self.SPOOL, value['spool_identity'], checkpoint=authority['checkpoint'], cold=True)
        data = ReaderData(self.SPOOL)
        try:
            gen = value.get('generation')
            if generation and gen and gen.get('data_epoch') == value.get('data_epoch'):
                # Cursor preparation/reconciliation already has durable intents.
                # It cannot be replaced or reset here. An exposed but never
                # actually activated generation still must be exactly empty.
                names = set(os.listdir(data.fd))
                def identity(name):
                    return data.identity(os.stat(name, dir_fd=data.fd, follow_symlinks=False)) if name in names else None
                current, prepared, retired = (identity(name) for name in ('state', gen['prepared'], gen['retired']))
                if 'new' not in gen:
                    # A durable prepare intent grants only the same existing
                    # cursor plus a private EMPTY creation at its unique name.
                    # It does not grant adoption of an unknown data generation.
                    if (gen.get('phase') != 'cursor-prepare-intent' or current != gen.get('old')
                            or retired is not None):
                        raise Refused('unfinished cursor creation lost its original arrangement')
                    if prepared is not None:
                        fd = os.open(gen['prepared'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=data.fd)
                        try:
                            info = os.fstat(fd)
                            if (os.listdir(fd) or info.st_uid not in (os.geteuid(),data.stamp[3])
                                    or stat.S_IMODE(info.st_mode) != 0o700 or info.st_nlink != 2):
                                raise Refused('unknown unfinished prepared cursor')
                        finally: os.close(fd)
                    with data.directory() as directory:
                        if data.files(directory) != authority['cursor']:
                            raise Refused('retained original cursor changed')
                else:
                    arrangements = ((gen.get('old'), gen['new'], None),
                                    (None, gen['new'], gen.get('old')),
                                    (gen['new'], None, gen.get('old')))
                    if (current,prepared,retired) not in arrangements:
                        raise Refused('restore intent cursor arrangement is foreign')
                    for name, observed in (('state',current), (gen['prepared'],prepared), (gen['retired'],retired)):
                        if observed is None: continue
                        with data.directory(name) as directory:
                            files = data.files(directory)
                            if observed == gen.get('old'):
                                if files != authority['cursor']: raise Refused('retained original cursor changed')
                            elif files:
                                raise Refused('new cursor generation changed before qualified activation')
            else:
                with data.directory() as cursor:
                    if data.identity(os.fstat(cursor)) != authority['cursor_identity'] or data.files(cursor) != authority['cursor']:
                        raise Refused('CURRENT native cursor changed before cold authority')
        finally:
            data.close()

    def certificate(self, item):
        active, value = self.context(item)
        proof = value.get('handoff')
        durable = active.get('reader', {}).get('handoff')
        if (not isinstance(proof, dict) or proof != durable or proof.get('schema') != 1
                or proof.get('kind') != 'NATIVE_INPUT_HANDOFF' or proof.get('owner') != item['owner']
                or proof.get('binding') != self.input_binding(value) or proof.get('cycle') != value['cycle']
                or proof.get('epoch') != value.get('preliminary', {}).get('epoch')
                or proof.get('cycle') != proof['checkpoint']['cycle']
                or proof.get('stop') != value.get('exit') or not proof['stop'].get('graceful')):
            raise Refused('cold effect lacks a durable native handoff certificate')
        return value, proof

    def cold_ready(self, item):
        value = self.use(item)
        if value['mode'] != 'enabled':
            self.unchanged_queue(item)
            return
        value, proof = self.certificate(item)
        self.stopped(value)
        self.source_users(item, value['source'], producers=False, reader_fds=False)
        self.cursor_custody(value, proof, generation=bool(value.get('restore_intent')))
        intent = value.get('restore_intent')
        if intent:
            active = self.t.owned(item['owner'])
            if (active.get('reader', {}).get('restore_intent') != intent
                    or intent.get('schema') != 1 or intent.get('kind') != 'SOURCE_RESTORE_INTENT'
                    or intent.get('owner') != item['owner'] or intent.get('certificate') != self.proof_hash(proof)
                    or intent.get('source_data_epoch') != proof['epoch']
                    or intent.get('restore_epoch') != value.get('restore_plan', {}).get('epoch')
                    or value.get('data_epoch') != (intent['restore_epoch'] if intent.get('state') == 'restored' else proof['epoch'])):
                raise Refused('source restore intent differs from its durable handoff')
            # Source may already be absent/replaced by our recorded restoration.
            # Never bind its old cursor to a new inode on this replay path.
            return
        if proof['source_epoch'] != value['source_epoch'] or proof['epoch'] != value.get('data_epoch'):
            raise Refused('handoff no longer describes this source epoch')
        self.cursor(item, eof=True, frozen=proof['source'])

    def restore_intent(self, item):
        value = self.use(item)
        self.cold_ready(item)
        if value['mode'] != 'enabled': return
        if value.get('restore_intent'): return
        proof = value['handoff']
        value['restore_intent'] = {'schema':1, 'kind':'SOURCE_RESTORE_INTENT', 'owner':item['owner'],
            'certificate':self.proof_hash(proof), 'source_epoch':proof['source_epoch'],
            'source_data_epoch':proof['epoch'], 'restore_epoch':value['restore_plan']['epoch'],
            'state':'prepared', 'exposed':False}
        self.t.write(item, item['phase'])

    def restore_plan(self, item):
        value = self.use(item)
        previous = value.get('restore_intent')
        if previous:
            try:
                self.cold_ready(item)
                return True  # Prior stopped/custody proof permits partial replay.
            except Refused:
                if self.units.show(ReaderUnits.SERVICE)['ActiveState'] != 'active':
                    raise  # Do not adopt a different, unexpectedly exited reader.
                value.setdefault('restore_history', []).append(previous)
                value.pop('restore_intent')
        generation = (value.get('generation') or {}).get('id')
        plan = value.get('restore_plan')
        if not plan or plan.get('generation') != generation or plan.get('source_epoch') != value.get('source_epoch'):
            plan = {'epoch':uuid.uuid4().hex, 'generation':generation, 'source_epoch':value.get('source_epoch')}
            value['restore_plan'] = plan
        # Intent for the post-restore epoch is durable BEFORE the certificate.
        # The current source/data epoch does not change until physical replay;
        # restore_intent explicitly binds both epochs to that certificate.
        self.t.write(item, item['phase'])
        return False

    def restored(self, item):
        value = self.use(item)
        if value['mode'] == 'enabled':
            self.cold_ready(item)
            value['restore_intent']['state'] = 'restored'
            value['source_epoch'] = value['restore_intent']['restore_epoch']
        value['data_epoch'] = value['restore_plan']['epoch']
        self.t.write(item, item['phase'])

    def pause(self, item, restoring=False):
        value = self.use(item)
        if value['mode'] == 'never':
            self.boundary(item)
            self.source_users(item, value['source'], value['baseline']['pid'] or None, producers=False, reader_fds=False)
            return
        self.boundary(item)
        current_pid = int(self.units.show(ReaderUnits.SERVICE)['MainPID']) if value['mode'] == 'enabled' else value['baseline']['pid']
        self.source_users(item, value['source'], current_pid or None, producers=False, reader_fds=value['mode'] == 'enabled')
        if value['mode'] == 'enabled':
            state = self.units.show(ReaderUnits.SERVICE)
            if state['ActiveState'] == 'active':
                process = self.units.process(int(state['MainPID']))
                expected = value.get('resumed_process', value['units']['process'])
                if process != expected and value['phase'] != 'exposure-intent':
                    raise Refused('reader invocation changed outside a recorded exposure')
                proof = self.units.admit(protected=[*item['paths'], str(ROOT), str(self.SPOOL)])
                if ReaderUnits.static(proof) != ReaderUnits.static(value['units']):
                    raise Refused('recovery reader differs from the admitted native policy')
                value['units'] = proof
                self.context(item)
                first = self.cursor(item, pid=process['pid'], retry=True)
                frozen = first['groups']
                logical = self.cursor(item, pid=process['pid'], eof=True, frozen=frozen, retry=True)
                recorded_stop = value['phase'] == 'reader-stop-intent'
                previous = value.get('preliminary') if recorded_stop else None
                if recorded_stop and (not previous or previous.get('source') != frozen or previous.get('source_epoch') != value['source_epoch'] or previous.get('epoch') != value['data_epoch']):
                    raise Refused('recorded stop intent lacks its unchanged logical source barrier')
                value['preliminary'] = {'schema':1, 'kind':'LOGICAL_PRELIMINARY_ONLY', 'owner':item['owner'],
                    'epoch':previous['epoch'] if previous else value['data_epoch'], 'source_epoch':value['source_epoch'],
                    'source':frozen, 'logical':logical, 'binding':self.input_binding(value)}
                self.t.write(item, item['phase'])
                if not recorded_stop:
                    self.write(item, 'drained'); self.write(item, 'reader-stop-intent')
                value['exit'] = self.units.stop(proof, requested=recorded_stop)
            elif state['ActiveState'] == 'inactive' and value['phase'] in ('reader-stop-intent','reader-stopped','queue-sealed','exposure-intent'):
                self.context(item)
                value['exit'] = self.stopped(value)
            else:
                raise Refused('reader stop has unknown or unfinished native state')
            preliminary = value.get('preliminary')
            if (not preliminary or preliminary.get('schema') != 1 or preliminary.get('kind') != 'LOGICAL_PRELIMINARY_ONLY'
                    or preliminary.get('owner') != item['owner'] or preliminary.get('source_epoch') != value['source_epoch']
                    or preliminary.get('epoch') != value.get('data_epoch')
                    or preliminary.get('binding') != self.input_binding(value)):
                raise Refused('stopped reader lacks its native preliminary source proof')
            self.write(item, 'reader-stopped')
            self.source_users(item, value['source'], producers=False, reader_fds=False)
            # Mandatory final native logical proof AFTER genuine StopProof.
            logical = self.cursor(item, eof=True, frozen=preliminary['source'])
            sealed = self.seal_current(item)
            again = self.cursor(item, eof=True, frozen=preliminary['source'])
            if logical != again:
                raise Refused('native cursor changed across the complete cold seal')
            value['handoff'] = dict(sealed, schema=1, kind='NATIVE_INPUT_HANDOFF', owner=item['owner'],
                cycle=value['cycle'], epoch=preliminary['epoch'], source_epoch=value['source_epoch'],
                source=preliminary['source'], logical=logical, stop=value['exit'], binding=self.input_binding(value))
            self.t.write(item, item['phase'])
            self.write(item, 'queue-sealed')
            self.cold_ready(item)
            return
        self.source_users(item, value['source'], current_pid or None, producers=False, reader_fds=False)
        if not value.get('spool_identity'): return
        self.seal_current(item)
        self.write(item, 'queue-sealed')

    def resume_same_epoch(self, item):
        active, value = self.context(item)
        if value.get('restore_intent'):
            raise Refused('resume-only cannot cross an existing source restore intent')
        preliminary = value.get('preliminary')
        if (not preliminary or preliminary.get('owner') != item['owner']
                or preliminary.get('source_epoch') != value.get('source_epoch')
                or preliminary.get('epoch') != value.get('data_epoch')
                    or preliminary.get('binding') != self.input_binding(value)):
            raise Refused('same-epoch resume lacks its original frozen source proof')
        self.boundary(item)
        value['exit'] = self.stopped(value)
        self.write(item, 'reader-stopped')
        self.source_users(item, value['source'], producers=False, reader_fds=False)
        logical = self.cursor(item, frozen=preliminary['source'])
        sealed = self.seal_current(item)
        if logical != self.cursor(item, frozen=preliminary['source']):
            raise Refused('resume-only native cursor changed across cold custody')
        authority = dict(sealed, schema=1, kind='SAME_EPOCH_RESUME_ONLY', owner=item['owner'],
                         source_epoch=value['source_epoch'], source=preliminary['source'],
                         logical=logical, stop=value['exit'], binding=self.input_binding(value), exposed=False)
        value['resume_custody'] = authority
        self.t.write(item, item['phase'])
        durable = self.t.owned(item['owner'])['reader'].get('resume_custody')
        if durable != authority:
            raise Refused('resume-only custody was not durably published')
        self.cursor_custody(value, authority)
        self.cursor(item, frozen=authority['source'])
        authority['exposed'] = True
        self.write(item, 'exposure-intent')
        self.start_reader(item)

    def resume_unmodified(self, item):
        """Cancel without restore/reset; malformed stopped state retains owner."""
        value = self.use(item)
        if value['mode'] != 'enabled': return
        state, socket = self.units.show(ReaderUnits.SERVICE), self.units.show(ReaderUnits.SOCKET)
        expected = value.get('resumed_process', value['units']['process'])
        if (state['ActiveState'] == socket['ActiveState'] == 'active'
                and state['Job'] in ('', '0') and socket['Job'] in ('', '0')
                and self.units.process(int(state['MainPID'])) == expected):
            self.boundary(item, running=True)
            if value['phase'] != 'reader-stop-intent':
                return
            # A still-active SAME stop intent must be reconciled once; it is
            # not the stopped/failed-witness cancellation case below. Never
            # rewind to drained or infer a cold certificate from active=true.
            try:
                self.pause(item)
            except Refused:
                self.resume_same_epoch(item)
            else:
                self.resume(item)
            return
        try:
            self.cold_ready(item)
        except Refused:
            self.resume_same_epoch(item)
        else:
            self.resume(item)

    def unchanged_queue(self, item):
        value = self.use(item)
        if value['mode'] == 'never' or not value.get('spool_identity'):
            return
        if not value['checkpoints']:
            raise Refused('cold restore lacks CURRENT queue authority')
        ReaderData.custody(self.SPOOL, value['spool_identity'],
                           checkpoint=value['checkpoints'][-1], cold=True)

    def retire_cursor(self, item):
        value = self.use(item)
        self.cold_ready(item)
        if value['mode'] == 'never' or not value.get('spool_identity'):
            return
        self.boundary(item)
        self.unchanged_queue(item)
        if not value.get('cursor_present') and not value.get('queue_present'):
            return
        data = ReaderData(self.SPOOL)
        try:
            generation = value.get('generation')
            if not generation or generation.get('data_epoch') != value.get('data_epoch'):
                old = os.stat('state', dir_fd=data.fd, follow_symlinks=False) if 'state' in os.listdir(data.fd) else None
                epoch = uuid.uuid4().hex
                generation = {'id': epoch, 'data_epoch': value['data_epoch'],
                              'old': data.identity(old) if old else None,
                              'prepared': '.state-prepared-' + epoch,
                              'retired': '.state-retired-' + epoch, 'exposed': False}
                if value.get('generation'):
                    previous = value['generation']
                    value.setdefault('generations', {})[previous['id']] = copy.deepcopy(previous)
                value['generation'] = generation
                self.write(item, 'cursor-prepare-intent')
            if 'new' not in generation:
                # The creation intent grants only an empty, private directory
                # at one unique name. It never grants replacement of unknown
                # content, another owner, a linked object or a mount.
                old = os.stat('state', dir_fd=data.fd, follow_symlinks=False) if 'state' in os.listdir(data.fd) else None
                if (data.identity(old) if old else None) != generation['old']:
                    raise Refused('cursor changed before generation preparation')
                if old:
                    with data.directory() as cursor:
                        captured = data.files(cursor)
                        if generation.get('sealed_cursor') not in (None, captured):
                            raise Refused('cursor changed while its archive was prepared')
                        generation['sealed_cursor'] = captured
                        if not generation.get('archive'):
                            archive = Path(item['backup']) / ('reader-cursor-' + uuid.uuid4().hex + '.tar')
                            generation.setdefault('archive_intents', []).append(str(archive))
                            self.t.write(item, item['phase'])
                            with tarfile.open(archive, 'x') as output:
                                for name, node in captured.items():
                                    with data.file(name, cursor) as (fd, info):
                                        entry = tarfile.TarInfo(name)
                                        entry.size, entry.uid, entry.gid = info.st_size, info.st_uid, info.st_gid
                                        entry.mode, entry.mtime = stat.S_IMODE(info.st_mode), info.st_mtime
                                        with os.fdopen(os.dup(fd), 'rb') as stream:
                                            output.addfile(entry, stream)
                            os.chmod(archive, 0o600)
                            sync_file(archive)
                            generation['archive'] = {'path': str(archive), 'sha256': digest(archive)}
                            self.t.write(item, item['phase'])
                        private_file(generation['archive']['path'], item['backup'])
                        if digest(generation['archive']['path']) != generation['archive']['sha256']:
                            raise Refused('retained cursor archive changed')
                name = generation['prepared']
                if name not in os.listdir(data.fd):
                    os.mkdir(name, mode=0o700, dir_fd=data.fd)
                    os.fsync(data.fd)
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=data.fd)
                try:
                    info = os.fstat(fd)
                    if (os.listdir(fd) or info.st_uid not in (os.geteuid(), data.stamp[3])
                            or stat.S_IMODE(info.st_mode) != 0o700 or info.st_nlink != 2):
                        raise Refused('unknown prepared cursor object; refusing adoption')
                    os.fchown(fd, data.stamp[3], data.stamp[4])
                    os.fchmod(fd, 0o700)
                    os.fsync(fd)
                    generation['new'] = data.identity(os.fstat(fd))
                finally:
                    os.close(fd)
                os.fsync(data.fd)
                self.write(item, 'cursor-prepared')
            if generation.get('archive'):
                private_file(generation['archive']['path'], item['backup'])
                if digest(generation['archive']['path']) != generation['archive']['sha256']:
                    raise Refused('retained cursor archive changed before retirement')
            self.reconcile_cursor(item, data, generation)
        finally:
            data.close()

    def reconcile_cursor(self, item, data, generation):
        if generation.get('exposed'):
            if 'state' not in os.listdir(data.fd) or data.identity(
                    os.stat('state', dir_fd=data.fd, follow_symlinks=False)) != generation['new']:
                raise Refused('exposed reader generation changed; refusing reset')
            return
        names = os.listdir(data.fd)
        identify = lambda name: data.identity(os.stat(name, dir_fd=data.fd, follow_symlinks=False)) if name in names else None
        old, prepared, retired = identify('state'), identify(generation['prepared']), identify(generation['retired'])
        if old == generation.get('old') and prepared == generation.get('new') and retired is None:
            self.write(item, 'cursor-retire-intent')
            if old is not None:
                os.rename('state', generation['retired'], src_dir_fd=data.fd, dst_dir_fd=data.fd)
                os.fsync(data.fd)
            self.write(item, 'cursor-retired')
            old, retired = None, generation.get('old')
        if old is None and prepared == generation.get('new') and retired == generation.get('old'):
            self.write(item, 'cursor-publish-intent')
            os.rename(generation['prepared'], 'state', src_dir_fd=data.fd, dst_dir_fd=data.fd)
            os.fsync(data.fd)
            self.write(item, 'cursor-published')
        elif old != generation.get('new') or prepared is not None or retired != generation.get('old'):
            raise Refused('cursor generation arrangement is unknown; preserving all objects')
        else:
            if generation.get('phase') not in ('cursor-publish-intent', 'cursor-published'):
                raise Refused('published cursor lacks its prior durable publication intent')
            self.write(item, 'cursor-published')
        data.namespace()

    def resume(self, item):
        value = self.use(item)
        if value['mode'] != 'enabled':
            self.boundary(item)
            return
        self.boundary(item)
        self.cold_ready(item)
        self.unchanged_queue(item)
        if value.get('restore_intent'):
            value['restore_intent']['exposed'] = True
        if value.get('generation'):
            data = ReaderData(self.SPOOL)
            try:
                self.reconcile_cursor(item, data, value['generation'])
            finally:
                data.close()
            value['generation']['exposed'] = True
        self.write(item, 'exposure-intent')
        self.start_reader(item)

    def start_reader(self, item):
        value = self.use(item)
        value['resumed_process'] = self.units.start(value['units'])
        expected, current = value['units']['process'], value['resumed_process']
        for field in ('exe', 'argv', 'executable_sha256', 'uid', 'gid', 'mac', 'boot'):
            if current.get(field) != expected.get(field):
                raise Refused('resumed reader differs from admitted executable/privileges/MAC')
        self.write(item, 'reader-active')
        self.boundary(item, running=True)
        self.r.run(['runuser', '-u', 'syslog', '--', 'test', '-r',
                    str(Path(value['source']) / 'alerts/alerts.json')], timeout=15,
                   operation='restored reader source access')
        deadline = time.monotonic() + 20
        while True:
            capability = self.source_capability(item, value['source'])
            records = capability.fds(value['resumed_process']['pid'])
            if capability.current is not None and capability.current in {(entry['device'],entry['inode']) for entry in records}:
                break
            if time.monotonic() >= deadline:
                raise Refused('resumed native reader does not watch the current restored input')
            time.sleep(0.25)

    def final(self, item):
        value = self.use(item)
        if value.get('spool_identity'):
            data = ReaderData(self.SPOOL)
            try:
                expected = value['generation']['new'] if value.get('generation') else value.get('cursor_identity')
                actual = data.identity(os.stat('state', dir_fd=data.fd, follow_symlinks=False)) if 'state' in os.listdir(data.fd) else None
                if data.stamp != value['spool_identity'] or actual != expected:
                    raise Refused('reader final generation or spool identity differs')
            finally:
                data.close()
        self.boundary(item, running=value['mode'] == 'enabled')
        if value['mode'] == 'enabled':
            self.verify_tools()
            self.r.run(['/usr/local/libexec/pilot-wazuh-delivery', 'local'], timeout=50,
                       operation='final effective local C11')
        if (value['mode'] == 'disabled' and value.get('data_epoch') and value.get('spool_identity')
                and (value.get('cursor_present') or value.get('queue_present'))):
            ReplayReceipt(self.t).publish(item)
        self.write(item, 'final')


class ReplayReceipt:
    """Local replay ACK/custody record, never a remote delivery certificate."""
    def __init__(self, central):
        self.t, self.r = central, central.r
        self.path = central.root / 'reader-replay-pending.json'

    def inspect(self):
        if not self.path.exists() and not self.path.is_symlink():
            return None
        private_file(self.path, self.t.root)
        value = json.loads(self.path.read_text())
        if value.get('schema') != 1 or value.get('kind') != 'LOCAL_REPLAY_ACK':
            raise Refused('unknown local replay receipt')
        return value

    def publish(self, item):
        reader = item['reader']
        self.t.reader.inspect(item, loaded=False)
        ReaderData.custody(Reader.SPOOL, reader['spool_identity'], reader['generation'],
                           reader['checkpoints'][-1] if reader['checkpoints'] else None, cold=True)
        value = {'schema': 1, 'kind': 'LOCAL_REPLAY_ACK', 'central_owner': item['owner'],
                 'source': reader['source'], 'profile_sha256': reader['baseline']['profile_sha256'],
                 'spool_identity': reader['spool_identity'], 'generation': reader['generation'],
                 'checkpoint': reader['checkpoints'][-1] if reader['checkpoints'] else None,
                 'status': 'pending', 'attempt': None, 'ever_exposed': False, 'attempts': [],
                 'checker_sha256': reader['checker_sha256'],
                 'tools': reader['request'].get('tools', {})}
        existing = self.inspect()
        if existing and existing.get('generation') == value['generation']:
            # Publication cannot erase prior exposure within this generation.
            if 'ever_exposed' not in existing:
                raise Refused('unknown replay exposure provenance')
            value['ever_exposed'] = existing['ever_exposed']
            value['attempts'] = existing.get('attempts', [])
            value['attempt'] = existing.get('attempt')
        if existing and existing['central_owner'] != item['owner']:
            # A new disabled restore must explicitly carry forward the prior
            # receipt, never discard unacknowledged custody.
            if item.get('previous_reader_receipt') != existing:
                raise Refused('unknown earlier replay receipt prevents finalization')
            value['previous'] = digest(self.path)
        atomic_json(self.path, value)

    def custody(self, value, native=True):
        if type(value.get('ever_exposed')) is not bool:
            raise Refused('unknown replay exposure provenance')
        proof = Reader(self.t, value.get('checker_sha256', ''),
                       {'tools': value.get('tools', {})})
        observed = proof.inspect(loaded=native)
        if observed['source_proof']['source'] != value['source']:
            raise Refused('pending replay actual Docker source changed')
        ReaderData.custody(Reader.SPOOL, value['spool_identity'], value['generation'],
                           value['checkpoint'], cold=not value['ever_exposed'])
        if value['ever_exposed']:
            if (observed.get('mode') not in ('enabled', 'disabled')
                    or observed.get('profile', {}).get('source') != value['source']):
                raise Refused('exposed replay lost its native profile provenance')
            proof.verify_tools()

    def operation(self, owner, operation, action, ack=False, preview=False):
        if not re.fullmatch('[a-f0-9]{32}', operation):
            raise Refused('invalid local replay invocation identity')
        with self.t.lock(owner=owner):
            self.t.idle()
            value = self.inspect()
            if not value:
                if action == 'verify':
                    self.r.run(['/usr/local/libexec/pilot-wazuh-delivery', 'local'], timeout=50,
                               operation='selected precommit local C11')
                return {'pending': False}
            if action == 'admit':
                if not ack:
                    raise Refused('pending replay requires a new explicit acknowledgement before enable')
                current_hash = digest(canonical(Reader.PROFILE))
                if current_hash != value['profile_sha256']:
                    prior = value.get('attempt') or {}
                    current = json.loads(Reader.PROFILE.read_text())
                    permitted = (prior.get('verified_profile_sha256') == current_hash
                                 or value.get('ever_exposed') is True)
                    if (not permitted or current.get('enabled') is not True
                            or current.get('source') != value['source']):
                        raise Refused('pending replay profile changed outside its recorded enable attempt')
                    Reader(self.t, request={'tools': value.get('tools', {})}).verify_tools()
                    self.r.run(['/usr/local/libexec/pilot-wazuh-delivery', 'local'], timeout=50,
                               operation='reconcile previous local replay enable attempt')
                self.custody(value)
                if preview:
                    return {'pending': True, 'planned': True}
                if value.get('attempt'):
                    attempts = value.get('attempts', [])
                    if len(attempts) >= 256:
                        raise Refused('replay attempt history exceeds supported bound')
                    value['attempts'] = attempts + [value['attempt']]
                value['attempt'] = {'owner': owner, 'operation': operation, 'exposed': False}
            else:
                if (value.get('attempt') or {}).get('owner') != owner or (value.get('attempt') or {}).get('operation') != operation:
                    raise Refused('replay receipt operation owner mismatch')
                if value['attempt'].get('failed') and action in ('expose', 'verify', 'complete'):
                    raise Refused('failed local enable requires a fresh acknowledged invocation')
                if action == 'expose':
                    # Native loaded-profile admission occurred before selected
                    # configuration writes. Here the new config may correctly
                    # await activation; queue/generation/source custody must
                    # still hold before any reader can consume it.
                    self.custody(value, native=False)
                    value['ever_exposed'] = True
                    value['attempt']['exposed'] = True
                elif action == 'failed':
                    value['attempt']['failed'] = True
                elif action == 'verify':
                    self.custody(value)
                    proof = Reader(self.t, request={'tools': value.get('tools', {})})
                    proof.verify_tools()
                    self.r.run(['/usr/local/libexec/pilot-wazuh-delivery', 'local'], timeout=50,
                               operation='committed local replay enable convergence')
                    value['attempt']['verified_profile_sha256'] = digest(canonical(Reader.PROFILE))
                elif action == 'complete':
                    if (not value['attempt'].get('verified_profile_sha256')
                            or digest(canonical(Reader.PROFILE)) != value['attempt']['verified_profile_sha256']):
                        raise Refused('local replay enable has not passed its precommit native proof')
                    self.custody(value)
                    value['status'] = 'locally_acknowledged'
                    history = self.t.root / ('reader-replay-ack-' + operation + '.json')
                    if history.exists():
                        private_file(history, self.t.root)
                        if json.loads(history.read_text()) != value:
                            raise Refused('replay acknowledgement history would be overwritten')
                    else:
                        atomic_json(history, value)
                    durable_unlink(self.path)
                    return {'pending': False, 'local_acknowledged': True, 'remote_delivery_certified': False}
                else:
                    raise Refused('unknown local replay operation')
            atomic_json(self.path, value)
            return {'pending': True, 'operation': operation}

class Central(Transaction):
    def __init__(self, managed_root=Path('/opt/pilot/wazuh-docker'), **kwargs):
        super().__init__('central', **kwargs)
        # Internal filesystem seam for discovery tests; the CLI never exposes
        # this setting and always enforces the production pilot-owned root.
        self.managed_root = Path(managed_root)
        self.reader = self.make_reader()

    def make_reader(self, checker_hash='', request=None, ack=False):
        return Reader(self, checker_hash, request, ack)

    def project_directory(self, directory):
        directory = canonical(directory)
        try:
            relative = directory.relative_to(canonical(self.managed_root))
        except ValueError as exc:
            raise Refused('active Compose directory is outside the pilot-owned single-node layout') from exc
        if not re.fullmatch(r'wazuh-docker-4\.14\.[0-9]+/single-node', str(relative)):
            raise Refused('active Compose directory is outside the pilot-owned single-node layout')
        return directory

    def image_provenance(self, image, repository, release):
        identities = image.get('RepoDigests') or []
        valid = re.compile(re.escape(repository) + r'@sha256:[a-f0-9]{64}$')
        if any(valid.fullmatch(value) for value in identities):
            return identities
        # docker load may restore an authenticated saved image's ID without
        # its RepoDigests. Trust only exact IDs durably recorded from official
        # digests before our own upgrade, never a mutable local tag alone.
        filename = self.root / 'image-provenance.json'
        if filename.is_symlink() or not filename.is_file():
            raise Refused('central image lacks official immutable release provenance')
        info = filename.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise Refused('unsafe retained image provenance')
        record = json.loads(filename.read_text()).get(image['Id'], {})
        if (record.get('repository') != repository or record.get('version') != release
                or not any(valid.fullmatch(value) for value in record.get('digests', []))):
            raise Refused('loaded central image does not match retained immutable provenance')
        return record['digests']

    def retain_images(self, item):
        filename = self.root / 'image-provenance.json'
        if filename.is_symlink():
            raise Refused('unsafe retained image provenance')
        records = json.loads(filename.read_text()) if filename.exists() else {}
        for service, image in item['images'].items():
            records[image['id']] = {'repository': 'wazuh/' + service.replace('.', '-'),
                                    'version': item['version'], 'digests': image['digests']}
        atomic_json(filename, records)
        archive = Path(item['backup']) / 'old-images.tar'
        self.r.run(['docker', 'image', 'save', '--output', archive,
                    *sorted({image['id'] for image in item['images'].values()})], timeout=1800,
                   operation='retain exact old image artifacts')
        self.r.run(['tar', '-tf', archive], timeout=300)
        checksum = digest(archive)
        sync_file(archive)
        item['image_archive'] = {'path': str(archive), 'sha256': checksum}
        self.write(item, item['phase'])

    def observe_manager(self):
        # This atomic read cannot observe a temporary upgraded manager that a
        # central transaction may still roll back. Supported transitions only
        # move forward, so a bound to this committed version remains safe.
        with self.lock(reader=True):
            self.idle()
            text = self.r.run(['docker', 'exec', 'single-node-wazuh.manager-1',
                               '/var/ossec/bin/wazuh-control', 'info'], timeout=30, operation='committed manager version').stdout
            values = re.findall(r'^WAZUH_VERSION="v?(4\.14\.[0-9]+)"$', text, re.M)
            if len(values) != 1:
                raise Refused('unknown committed manager version')
            version(values[0])
            return {'version': values[0]}

    def verify_agent(self, identifier, name, expected):
        if not re.fullmatch('[0-9]+', identifier) or not name or '\n' in name:
            raise Refused('invalid exact agent identity')
        version(expected)
        with self.lock(reader=True):
            self.idle()
            text = self.r.run(['docker', 'exec', 'single-node-wazuh.manager-1',
                               '/var/ossec/bin/agent_control', '-i', identifier], timeout=30).stdout
            if (re.findall(r'^\s*Agent ID:\s*([0-9]+)\s*$', text, re.M) != [identifier]
                    or re.findall(r'^\s*Agent Name:\s*(\S+)\s*$', text, re.M) != [name]
                    or re.findall(r'^\s*Status:\s*(\S+)\s*$', text, re.M) != ['Active']
                    or re.findall(r'^\s*Client version:\s*Wazuh v(4\.14\.[0-9]+)\s*$', text, re.M) != [expected]):
                raise Refused('manager has not observed the exact active agent identity and version')
            return {'pass': True}

    def verify(self, canary=False, owner=None):
        if canary and not owner:
            raise Refused('canary requires host-wide central writer ownership')
        with self.lock(owner=owner, reader=not canary):
            self.idle()
            state = self.discover()
            if not state:
                raise Refused('central stack is absent')
            self.check_agents(state['version'])
            result = {'pass': True, 'version': state['version']}
            if canary:
                result['canary'] = self.canary()
            return result

    def discover(self):
        self.r.run(['docker', 'info'], timeout=30)
        docker_root = canonical(self.r.run(['docker', 'info', '--format', '{{.DockerRootDir}}'], timeout=30).stdout.strip())
        ids = self.r.run(['docker', 'ps', '-aq', '--no-trunc', '--filter',
                         'label=com.docker.compose.project=single-node'], timeout=30).stdout.split()
        if not ids:
            return None
        raw = self.r.json(['docker', 'inspect', *ids], timeout=30)
        found = {}
        for container in raw:
            labels = container['Config'].get('Labels', {})
            service = labels.get('com.docker.compose.service')
            if service not in SERVICES or service in found:
                raise Refused('unexpected or duplicate Compose service')
            if not container['State']['Running']:
                raise Refused('existing central component is not running')
            found[service] = container
        if set(found) != set(SERVICES):
            raise Refused('partial Wazuh central stack')
        directories = {c['Config']['Labels'].get('com.docker.compose.project.working_dir') for c in raw}
        files = {c['Config']['Labels'].get('com.docker.compose.project.config_files') for c in raw}
        if len(directories) != 1 or len(files) != 1:
            raise Refused('inconsistent Compose provenance')
        directory = Path(directories.pop() or '')
        compose = files.pop() or ''
        if not directory.is_absolute() or ',' in compose or Path(compose).resolve().parent != directory.resolve():
            raise Refused('unsupported Compose location or multiple configuration files')
        if directory.is_symlink() or not Path(compose).is_file():
            raise Refused('missing or unsafe active Compose file')
        directory = canonical(directory)
        canonical(compose)
        if Path(compose).stat().st_nlink != 1:
            raise Refused('active Compose file has an outside hardlink alias')
        self.project_directory(directory)
        images = {}
        paths = {str(directory.resolve())}
        volume_names = set()
        for service, container in found.items():
            image = self.r.json(['docker', 'image', 'inspect', container['Image']], timeout=30)[0]
            repo = 'wazuh/' + service.replace('.', '-')
            expected = re.fullmatch(re.escape(repo) + r':(4\.14\.[0-9]+)', container['Config']['Image'])
            if not expected:
                raise Refused('central image lacks official immutable release provenance')
            identities = self.image_provenance(image, repo, expected[1])
            if not isinstance(image.get('Size'), int) or image['Size'] <= 0:
                raise Refused('unknown old image size for backup capacity')
            images[service] = {'id': image['Id'], 'version': expected[1],
                               'digests': identities, 'container': container['Id'], 'size': image['Size'],
                               'config_hash': container['Config']['Labels'].get('com.docker.compose.config-hash')}
            for mount in container['Mounts']:
                source = Path(mount['Source'])
                if mount['Type'] == 'volume':
                    volume = self.r.json(['docker', 'volume', 'inspect', mount['Name']], timeout=30)[0]
                    if volume.get('Driver') != 'local' or volume.get('Options') or volume.get('Labels', {}).get('com.docker.compose.project') != 'single-node':
                        raise Refused('unowned or non-local persistent volume')
                    expected = docker_root / 'volumes' / mount['Name'] / '_data'
                    if (not re.fullmatch(r'single-node_[A-Za-z0-9_.-]+', mount['Name'])
                            or canonical(source) != canonical(volume['Mountpoint'])
                            or canonical(source) != expected):
                        raise Refused('persistent volume source or Docker ownership mismatch')
                    volume_names.add(mount['Name'])
                    paths.add(str(source))
                elif mount['Type'] == 'bind':
                    if not source.resolve().is_relative_to(directory.resolve()):
                        raise Refused('bind mount outside managed Compose directory')
                else:
                    raise Refused('unsupported persistent mount type')
        releases = {value['version'] for value in images.values()}
        if len(releases) != 1:
            raise Refused('central components have mixed Wazuh releases')
        release = releases.pop()
        restore_sources({path: 'directory' for path in paths}, self.root)
        for name in volume_names:
            consumers = self.r.run(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'volume=' + name], timeout=30).stdout.split()
            if not consumers or not set(consumers).issubset(set(ids)):
                raise Refused('persistent volume has consumers outside the selected stack')
        self.health(release, images)
        return {'directory': str(directory), 'compose': compose, 'images': images,
                'version': release, 'paths': sorted(paths), 'volumes': sorted(volume_names),
                'docker_root': str(docker_root), 'compose_sha256': digest(compose)}

    def check_agents(self, target):
        registry = {}
        listing = self.r.run(['docker', 'exec', 'single-node-wazuh.manager-1',
                              '/var/ossec/bin/agent_control', '-l'], timeout=30).stdout
        identifiers = re.findall(r'^\s+ID: ([0-9]+),', listing, re.M)
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise Refused('unknown or ambiguous manager agent registry')
        for identifier in identifiers:
            if int(identifier) == 0:
                continue
            text = self.r.run(['docker', 'exec', 'single-node-wazuh.manager-1',
                               '/var/ossec/bin/agent_control', '-i', identifier], timeout=30).stdout
            ids = re.findall(r'^\s*Agent ID:\s*([0-9]+)\s*$', text, re.M)
            releases = re.findall(r'^\s*Client version:\s*Wazuh v(4\.14\.[0-9]+)\s*$', text, re.M)
            if ids != [identifier] or len(releases) != 1:
                raise Refused('unknown retained agent version in manager registry')
            registry[identifier] = releases[0]
            if version(releases[0]) > version(target):
                raise Refused('selected central target is older than a retained registered agent')
        return registry

    def compose_graph(self, directory, text):
        return self.r.json(['docker', 'compose', '--project-name', 'single-node',
                            '--project-directory', directory, '-f', '-', 'config', '--format', 'json'],
                           cwd=directory, input=text, timeout=60, operation='resolved Compose configuration')

    @staticmethod
    def graph_hash(graph):
        return hashlib.sha256(json.dumps(graph, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def service_hash(self, directory, text, service):
        value = self.r.run(['docker', 'compose', '--project-name', 'single-node',
                            '--project-directory', directory, '-f', '-', 'config', '--hash', service],
                           cwd=directory, input=text, timeout=60, operation='native Compose service hash').stdout
        matches = re.fullmatch(re.escape(service) + r' ([a-f0-9]{64})\n?', value)
        if not matches:
            raise Refused('unknown native Compose service hash output')
        return matches[1]

    def validate_compose_transition(self, state, old_text, new_text, target):
        for service in SERVICES:
            expected = state['images'][service].get('config_hash')
            if not expected or self.service_hash(state['directory'], old_text, service) != expected:
                raise Refused('rendered Compose control differs from the running container; apply configuration separately first')
        before = self.compose_graph(state['directory'], old_text)
        after = self.compose_graph(state['directory'], new_text)
        masked_before, masked_after = copy.deepcopy(before), copy.deepcopy(after)
        for service in SERVICES:
            repository = 'wazuh/' + service.replace('.', '-')
            if (before.get('services', {}).get(service, {}).get('image') != repository + ':' + state['version']
                    or after.get('services', {}).get(service, {}).get('image') != repository + ':' + target):
                raise Refused('resolved Compose images do not match the exact bounded transition')
            masked_before['services'][service]['image'] = '<managed-Wazuh-image>'
            masked_after['services'][service]['image'] = '<managed-Wazuh-image>'
        if masked_before != masked_after:
            raise Refused('version-only upgrade would alter resolved operator configuration outside image fields')
        state['compose_graph_sha256'] = self.graph_hash(before)
        state['target_graph_sha256'] = self.graph_hash(after)
        state['target_config_hashes'] = {service: self.service_hash(state['directory'], new_text, service) for service in SERVICES}

    def validate_persisted_graph(self, item, target=False):
        text = Path(item['compose']).read_bytes().decode('utf-8')
        graph = self.compose_graph(item['directory'], text)
        expected = item['target_graph_sha256'] if target else item['compose_graph_sha256']
        if self.graph_hash(graph) != expected:
            raise Refused('persisted Compose graph differs from the validated version-only configuration')

    def assert_volume_consumers(self, item, allow_empty=False):
        expected = {image['container'] for image in item['images'].values()}
        for name in item.get('volumes', []):
            actual = set(self.r.run(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'volume=' + name], timeout=30).stdout.split())
            if (not actual and not allow_empty) or not actual.issubset(expected):
                raise Refused('persistent volume acquired a foreign consumer')

    def quiesce_for_restore(self, item, remove=True, inspect_only=False):
        """Replayable even when a previous restore removed live Compose files."""
        ids = self.r.run(['docker', 'ps', '-aq', '--no-trunc', '--filter',
                         'label=com.docker.compose.project=single-node'], timeout=30).stdout.split()
        if not ids:
            self.assert_volume_consumers(item, allow_empty=True)
            return
        containers = self.r.json(['docker', 'inspect', *ids], timeout=30)
        seen = set()
        for container in containers:
            labels = container['Config'].get('Labels', {})
            service = labels.get('com.docker.compose.service')
            if service not in SERVICES or service in seen:
                raise Refused('unexpected project service during recovery')
            seen.add(service)
            allowed = {item['images'][service]['id'], item['target_images'][service]['id']}
            if (container['Image'] not in allowed
                    or labels.get('com.docker.compose.project.working_dir') != item['directory']
                    or labels.get('com.docker.compose.project.config_files') != item['compose']):
                raise Refused('current project container escaped recovery ownership')
            for mount in container['Mounts']:
                if mount['Type'] == 'volume':
                    expected = Path(item['docker_root']) / 'volumes' / mount['Name'] / '_data'
                    if mount['Name'] not in item['volumes'] or canonical(mount['Source']) != expected:
                        raise Refused('current recovery container has an unowned volume')
                elif mount['Type'] == 'bind':
                    if not canonical(mount['Source']).is_relative_to(canonical(item['directory'])):
                        raise Refused('current recovery container has an unowned bind mount')
                else:
                    raise Refused('unsupported recovery container mount')
        for name in item['volumes']:
            consumers = self.r.run(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'volume=' + name], timeout=30).stdout.split()
            if not set(consumers).issubset(set(ids)):
                raise Refused('recovery volume has a foreign consumer')
        if inspect_only:
            return
        self.r.run(['docker', 'stop', '--time', '60', *ids], timeout=120, operation='quiesce owned recovery containers')
        states = self.r.json(['docker', 'inspect', *ids], timeout=30)
        if any(container['State']['Running'] for container in states):
            raise Refused('owned recovery container did not stop')
        if not remove:
            return
        self.r.run(['docker', 'rm', *ids], timeout=60, operation='remove quiesced owned recovery containers')
        # No recorded project volume may have any remaining consumer now.
        for name in item['volumes']:
            if self.r.run(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'volume=' + name], timeout=30).stdout.strip():
                raise Refused('persistent volume still has a consumer before restore')

    def health(self, release, images):
        manager = self.r.run(['docker', 'exec', images['wazuh.manager']['container'],
                              '/var/ossec/bin/wazuh-control', 'info'], timeout=30, operation='manager native version').stdout
        match = re.search(r'^WAZUH_VERSION="v?(4\.14\.[0-9]+)"$', manager, re.M)
        if not match or match[1] != release:
            raise Refused('manager effective version probe failed')
        dashboard = self.r.json(['docker', 'exec', images['wazuh.dashboard']['container'],
                                 'cat', '/usr/share/wazuh-dashboard/plugins/wazuh/package.json'], timeout=30, operation='dashboard Wazuh plugin version')
        if dashboard.get('version') != release:
            raise Refused('dashboard Wazuh plugin version probe failed')
        indexer = self.r.json(['docker', 'exec', images['wazuh.indexer']['container'],
                               'cat', '/usr/share/wazuh-indexer/VERSION.json'], timeout=30, operation='indexer native Wazuh version')
        if indexer.get('version') != release:
            raise Refused('indexer effective Wazuh version probe failed')
        self.indexer(['/_cluster/health?wait_for_status=yellow&timeout=20s'])
        status = self.r.run(['docker', 'exec', images['wazuh.manager']['container'],
                             '/var/ossec/bin/wazuh-control', 'status'], timeout=30,
                            allowed=(0, 1), operation='manager native daemon status')
        # Native 4.14.1 on the disposable i244-manager returns rc1 whenever
        # intentionally disabled optional daemons are stopped (capture
        # /tmp/issue-to-pr-244/dev-native-status-coder.log, 2026-11-03).
        # Do not turn that rc into either universal failure or universal PASS.
        observed = re.findall(r'^(wazuh-[a-z0-9-]+) (is running|not running)\.\.\.$', status.stdout, re.M)
        required = {'wazuh-modulesd', 'wazuh-logcollector', 'wazuh-remoted', 'wazuh-analysisd',
                    'wazuh-execd', 'wazuh-db', 'wazuh-authd', 'wazuh-apid'}
        if (not observed or len(observed) != len(status.stdout.splitlines()) or status.stderr
                or len(dict(observed)) != len(observed)
                or any(dict(observed).get(name) != 'is running' for name in required)):
            raise Refused('required manager native daemons are not healthy')

    def indexer(self, suffix):
        # Read credentials from the container environment inside the container;
        # neither argv nor returned JSON contains them. Use its admin TLS cert.
        cmd = ['docker', 'exec', 'single-node-wazuh.indexer-1', 'curl', '--fail',
               '--silent', '--show-error', '--max-time', '30', '--cacert',
               '/usr/share/wazuh-indexer/config/certs/root-ca.pem', '--cert',
               '/usr/share/wazuh-indexer/config/certs/admin.pem', '--key',
               '/usr/share/wazuh-indexer/config/certs/admin-key.pem',
               'https://wazuh.indexer:9200' + suffix[0]]
        value = self.r.json(cmd, timeout=40, operation='authenticated indexer API probe')
        if 'status' in value and value['status'] not in ('yellow', 'green'):
            raise Refused('indexer health failed')
        return value

    def data(self):
        # Bounded representative oracle: retain one real indexed document,
        # including its content hash, rather than assuming volume files suffice.
        value = self.indexer(['/wazuh-alerts-*/_search?size=1&sort=timestamp:desc'])
        hits = value.get('hits', {}).get('hits', [])
        if not hits:
            raise Refused('upgrade requires an existing representative indexed alert')
        hit = hits[0]
        return {'index': hit['_index'], 'id': hit['_id'],
                'sha256': hashlib.sha256(json.dumps(hit['_source'], sort_keys=True).encode()).hexdigest()}

    def check_data(self, expected):
        from urllib.parse import quote
        result = self.indexer(['/' + quote(expected['index'], safe='') + '/_doc/' + quote(expected['id'], safe='')])
        actual = hashlib.sha256(json.dumps(result.get('_source'), sort_keys=True).encode()).hexdigest()
        if actual != expected['sha256']:
            raise Refused('representative indexed data changed or is missing')

    def canary(self):
        """Real analysis -> Filebeat -> indexer oracle, without an auth attempt.

        Native framing and SOCK_DGRAM transport are documented at
        https://documentation.wazuh.com/current/development/message-format.html
        and implemented in wazuh/v4.14.9/src/shared/mq_op.c SendMSGAction.
        The upstream 0095-sshd_rules.xml defines child rule 5760 (of 5716)
        for Failed password; native 4.14.1 canary capture confirmed 5760.
        Agent transport is verified separately by the topology tests.
        """
        from urllib.parse import urlencode
        nonce = uuid.uuid4().hex
        user = 'pilot_canary_' + nonce
        # A nonce-derived benchmark address avoids accumulating multiple
        # independent canaries into the same-source brute-force correlation.
        address = '198.18.' + str(int(nonce[:2], 16)) + '.' + str(int(nonce[2:4], 16))
        message = time.strftime('%b %d %H:%M:%S', time.gmtime()) + ' pilot-canary sshd[244]: Failed password for ' + user + ' from ' + address + ' port 12345 ssh2'
        payload = '1:pilot-wazuh-upgrade-canary:' + message
        program = ('import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); '
                   's.settimeout(10); s.connect("/var/ossec/queue/sockets/queue"); '
                   's.send(sys.stdin.buffer.read()); s.close()')
        self.r.run(['docker', 'exec', '-i', 'single-node-wazuh.manager-1',
                    '/var/ossec/framework/python/bin/python3', '-c', program], input=payload, timeout=30, operation='synthetic analysis queue event')
        until = time.monotonic() + 120
        query = '/wazuh-alerts-*/_search?' + urlencode({'q': 'full_log:"' + user + '"', 'size': 10})
        while True:
            result = self.indexer([query])
            for hit in result.get('hits', {}).get('hits', []):
                source = hit.get('_source', {})
                if (user in source.get('full_log', '') and str(source.get('rule', {}).get('id')) == '5760'
                        and str(source.get('agent', {}).get('id')) == '000'):
                    return {'index': hit['_index'], 'id': hit['_id'], 'nonce': nonce}
            if time.monotonic() >= until:
                raise Refused('new synthetic analysis event was not indexed within 120 seconds')
            time.sleep(3)

    def compose_run(self, item, *args, override=None):
        cmd = ['docker', 'compose', '--project-name', 'single-node', '-f', item['compose']]
        if override:
            cmd += ['-f', override]
        return self.r.run(cmd + list(args), cwd=item['directory'], timeout=900)

    def wait(self, release, images):
        until = time.monotonic() + 420
        while True:
            try:
                # Container IDs change on recreation; inspect known names.
                current = dict(images)
                for service in SERVICES:
                    value = self.r.json(['docker', 'inspect', 'single-node-' + service + '-1'], timeout=30)[0]
                    if not value['State']['Running'] or value['Image'] != images[service]['id']:
                        raise Refused('central image identity or availability mismatch')
                    if (images[service].get('config_hash')
                            and value['Config']['Labels'].get('com.docker.compose.config-hash') != images[service]['config_hash']):
                        raise Refused('recreated central service configuration hash differs from its validated control')
                    current[service] = dict(images[service], container=value['Id'])
                self.health(release, current)
                return
            except Refused:
                if time.monotonic() >= until:
                    raise
                time.sleep(5)

    def validate_project_scope(self, item):
        directory = self.project_directory(item['directory'])
        compose = canonical(item['compose'])
        if compose.parent != directory or (compose.exists() and (not compose.is_file() or compose.stat().st_nlink != 1)):
            raise Refused('recovery Compose file scope is invalid')
        if canonical(item['backup']).parent != canonical(self.root):
            raise Refused('recovery backup escaped its private store')
        disjoint(item['paths'], self.root)
        docker_root = canonical(self.r.run(['docker', 'info', '--format', '{{.DockerRootDir}}'], timeout=30).stdout.strip())
        if str(docker_root) != item['docker_root']:
            raise Refused('Docker data root changed during the transaction')
        expected_paths = {str(directory)}
        for name in item['volumes']:
            if not re.fullmatch(r'single-node_[A-Za-z0-9_.-]+', name):
                raise Refused('recovery volume identity is invalid')
            expected = docker_root / 'volumes' / name / '_data'
            info = self.r.json(['docker', 'volume', 'inspect', name], timeout=30)[0]
            if (info.get('Driver') != 'local' or info.get('Options')
                    or info.get('Labels', {}).get('com.docker.compose.project') != 'single-node'
                    or canonical(info['Mountpoint']) != expected):
                raise Refused('recovery volume ownership or source changed')
            expected_paths.add(str(expected))
        if set(item['paths']) != expected_paths:
            raise Refused('recovery source paths escaped the recorded owned project')
        restore_sources({path: 'directory' for path in item['paths']}, self.root, missing=item['paths'])
        ScopeLayout.inspect({path: 'directory' for path in item['paths']}, self.root, missing=item['paths'])

    def validate_restore_scope(self, item):
        self.validate_project_scope(item)
        expected_roots = {str(canonical(path)): 'directory' for path in item['paths']}
        if item['capture']['roots'] != expected_roots or not item['capture']['sealed']:
            raise Refused('central cold capture escaped its exact source set')
        if {entry['path'] for entry in item['archives']} != set(item['paths']):
            raise Refused('recovery archive scope does not match recorded sources')
        for entry in item['archives']:
            if canonical(entry['archive']).parent != canonical(item['backup']):
                raise Refused('recovery archive escaped the retained backup')
            private_file(entry['archive'], item['backup'])
        # Validate every archive before stopping any currently running stack.
        for entry in item['archives']:
            if digest(entry['archive']) != entry['sha256']:
                raise Refused('recovery archive checksum mismatch')
        image_archive = item['image_archive']
        private_file(image_archive['path'], item['backup'])
        if (canonical(image_archive['path']).parent != canonical(item['backup'])
                or digest(image_archive['path']) != image_archive['sha256']):
            raise Refused('old image archive checksum or scope mismatch')

    def recover_pre_switch(self, item):
        self.validate_project_scope(item)
        if 'reader' in item:
            self.reader.boundary(item)
        if digest(item['compose']) != item['compose_sha256']:
            raise Refused('pre-switch Compose configuration changed; refusing to guess recovery')
        self.validate_persisted_graph(item)
        for service, image in item['images'].items():
            self.r.run(['docker', 'image', 'tag', image['id'],
                        'wazuh/' + service.replace('.', '-') + ':' + item['version']], timeout=30)
        if 'reader' in item:
            value = self.reader.use(item)
            self.reader.resume_unmodified(item)
        self.compose_run(item, 'up', '-d', '--pull', 'never')
        self.wait(item['version'], item['images'])
        self.check_data(item['data'])
        self.canary()
        ScopeLayout.inspect({path: 'directory' for path in item['paths']}, self.root)
        self.final_reader(item, restored=True)
        self.finish(item, 'recovered-before-switch')

    def complete_finalized(self, item):
        expected = item['target_version'] if item['phase'] == 'committed' else item['version']
        images = item['target_images'] if item['phase'] == 'committed' else item['images']
        current = self.discover()
        if (not current or current['version'] != expected
                or any(current['images'][service]['id'] != images[service]['id'] for service in SERVICES)):
            raise Refused('finalized transaction no longer matches its effective state')
        expected_hash = item['target_compose_sha256'] if item['phase'] == 'committed' else item['compose_sha256']
        if digest(item['compose']) != expected_hash:
            raise Refused('finalized Compose configuration no longer matches its durable version selectors')
        self.validate_persisted_graph(item, target=item['phase'] == 'committed')
        ScopeLayout.inspect({path: 'directory' for path in item['paths']}, self.root)
        self.check_data(item['data'])
        if 'reader' in item:
            self.reader.final(item)
        if item['phase'] != 'committed':
            self.recovery_outcome(item)
        else:
            self.check_agents(item['target_version'])
        self.finish(item, item['phase'])

    def rollback(self, item, retry_reader=False):
        # Only the durable journal supplies cold restore authority. A caller's
        # in-memory phase/paths cannot promote an incomplete or foreign state.
        phases = tuple(phase for phase, action in CENTRAL_RECOVERY.items() if action == 'restore-old')
        active = self.owned(item.get('owner'), phases)
        writer = HostWriter(self.root).active()
        if (not writer or writer['owner'] != active['owner']
                or writer['component'] != 'central' or writer['mode'] not in ('apply', 'recover')
                or item.get('backup') != active.get('backup')):
            raise Refused('cold recovery journal and host writer authority differ')
        self.validate_restore_scope(active)
        self.quiesce_for_restore(active, inspect_only=True)
        # The fully validated intent must precede every consumer of absent-
        # manager source authority. A failed boundary leaves this retryable.
        self.write(active, 'recovering')
        item.clear()
        item.update(active)
        if 'reader' in item:
            self.reader.boundary(item)
        self.r.run(['docker', 'image', 'load', '--input', item['image_archive']['path']], timeout=1800,
                   operation='load retained old image artifacts')
        if 'reader' in item:
            value = self.reader.use(item)
            self.capacity([], extra_bytes=768 * 1024 ** 2)
            self.quiesce_for_restore(item, remove=False)
            replay = self.reader.restore_plan(item)
            if not replay:
                try:
                    self.reader.pause(item, restoring=True)
                except Refused:
                    if not retry_reader or value.get('restore_intent'):
                        raise
                    value.setdefault('redrain_attempts', []).append({'source_epoch':value.get('source_epoch'), 'cycle':value['cycle']})
                    self.write(item, 'recovering')
                    self.reader.resume_same_epoch(item)
                    self.reader.pause(item, restoring=True)
            self.write(item, 'recovering')
            self.reader.unchanged_queue(item)
            self.reader.restore_intent(item)
        self.quiesce_for_restore(item)
        ClosedCapture.take({path: 'directory' for path in item['paths']}, self.root, missing=item['paths'], sealed=True)
        for entry in item['archives']:
            self.restore(entry['path'], entry['archive'], entry['sha256'], capture=item['capture'])
        ClosedCapture.relink(item['capture'], self.root)
        if 'reader' in item:
            self.reader.restored(item)
        if digest(item['compose']) != item['compose_sha256']:
            raise Refused('restored Compose selectors differ from the old durable configuration')
        self.validate_persisted_graph(item)
        # Restore the tags from exact retained image identities, then check
        # the actual recreated container IDs. Do not leave an override file in
        # Compose labels: subsequent discovery must inspect the original config.
        for service, image in item['images'].items():
            self.r.run(['docker', 'image', 'tag', image['id'],
                        'wazuh/' + service.replace('.', '-') + ':' + item['version']], timeout=30)
        self.reader_before_producers(item, restored=True)
        self.compose_run(item, 'up', '-d', '--pull', 'never')
        self.wait(item['version'], item['images'])
        self.check_data(item['data'])
        self.canary()
        ScopeLayout.inspect(item['capture']['roots'], self.root)
        self.final_reader(item, restored=True)
        self.finish(item, 'recovered')

    def recovery_outcome(self, item):
        if 'registry' not in item:  # Pre-reader journals keep their original proof boundary.
            return {}
        current = self.check_agents(item['target_version'])
        if current != item['registry']:
            raise Refused('restored registry differs from the captured native version baseline')
        compatible = all(version(value) <= version(item['version']) for value in current.values())
        item['outcome'] = {
            'outcome': 'restored_baseline' if compatible else 'restored_preexisting_incompatible_baseline',
            'restored_native_available': True, 'fleet_compatible': compatible,
            'overall_success': compatible, 'c12_pass': compatible}
        self.write(item, item['phase'])
        return item['outcome']

    def reader_before_producers(self, item, restored=False):
        if 'reader' in item:
            if restored:
                self.reader.retire_cursor(item)
            self.reader.resume(item)
            self.reader.write(item, 'producers-start-intent')

    def final_reader(self, item, restored=False):
        if 'reader' in item:
            self.reader.final(item)
        if restored:
            return self.recovery_outcome(item)
        self.check_agents(item['target_version'])
        return {}

    def execute(self, target, upgrade=False, preview=False, recover=False, owner='',
                reader_request=None, reader_checker='', reader_ack=False):
        version(target)
        if preview and recover:
            raise Refused('check mode cannot execute central recovery')
        with self.lock(owner=owner):
            self.reader = self.make_reader(reader_checker, reader_request, reader_ack)
            if recover:
                item = self.active()
                if not item:
                    raise Refused('no active central transaction to recover')
                if item['owner'] != owner:
                    raise Refused('central journal does not belong to the host writer owner')
                action = CENTRAL_RECOVERY.get(item['phase'])
                if action == 'resume-old':
                    self.recover_pre_switch(item)
                    return dict({'changed': True, 'recovered': True}, **item.get('outcome', {}))
                if action in ('complete-target', 'complete-old'):
                    self.complete_finalized(item)
                    return dict({'changed': False, 'completed': True}, **item.get('outcome', {}))
                if action != 'restore-old':
                    raise Refused('no fully backed-up central transaction to recover')
                self.rollback(item, retry_reader=True)
                return dict({'changed': True, 'recovered': True}, **item.get('outcome', {}))
            self.idle()
            state = self.discover()
            if not state:
                return {'changed': False, 'fresh': True, 'version': target}
            state['registry'] = self.check_agents(target)
            if state['version'] == target:
                return {'changed': False, 'fresh': False, 'version': target,
                        'directory': state['directory']}
            if not upgrade or (state['version'], target) != ('4.14.1', '4.14.9'):
                raise Refused('only explicit central 4.14.1 -> 4.14.9 upgrade is supported')
            state['reader'] = self.reader.admit(state, preview)
            state['previous_reader_receipt'] = ReplayReceipt(self).inspect()
            state['admission_capture'] = ScopeLayout.inspect({path: 'directory' for path in state['paths']}, self.root)
            image_bytes = sum(image['size'] for image in state['images'].values())
            if state['reader']['mode'] != 'never':
                image_bytes += 768 * 1024 ** 2  # bounded queue evidence + memory-save/cursor allowance
            self.capacity(state['paths'], extra_bytes=image_bytes)
            state['data'] = self.data()
            old_text = Path(state['compose']).read_bytes().decode('utf-8')
            text = old_text
            for service in SERVICES:
                repo = 'wazuh/' + service.replace('.', '-')
                text, count = re.subn(re.escape(repo) + r':4\.14\.1(?=[\s\"\']|$)', repo + ':' + target, text)
                if count != 1:
                    raise Refused('expected exactly one pinned image selector per central component')
            state['target_compose_sha256'] = hashlib.sha256(text.encode('utf-8')).hexdigest()
            self.validate_compose_transition(state, old_text, text, target)
            if preview:
                return {'changed': False, 'planned_upgrade': True, 'directory': state['directory'], 'version': target}
            # Prove the old pipeline works before accepting downtime. A failed
            # preflight never grants restore or stop authority.
            self.canary()
            target_images = {}
            for service in SERVICES:
                image = 'wazuh/' + service.replace('.', '-') + ':' + target
                self.r.run(['docker', 'pull', image], timeout=900)
                info = self.r.json(['docker', 'image', 'inspect', image], timeout=30)[0]
                if not any(d.startswith(image.split(':')[0] + '@sha256:') for d in info.get('RepoDigests', [])):
                    raise Refused('target image lacks immutable official provenance')
                target_images[service] = {'id': info['Id'], 'digests': info['RepoDigests'],
                                          'config_hash': state['target_config_hashes'][service]}
            # Re-evaluate capacity after pulls, before granting any downtime.
            self.capacity(state['paths'], extra_bytes=image_bytes)
            state['target_version'] = target
            state['target_images'] = target_images
            state['admission_capture'] = ScopeLayout.inspect({path: 'directory' for path in state['paths']}, self.root)
            item = self.begin(owner, state)
            try:
                self.retain_images(item)
                ScopeLayout.inspect({path: 'directory' for path in item['paths']}, self.root)
                self.write(item, 'stopping')
                self.reader.write(item, 'producer-stop-intent')
                self.compose_run(item, 'stop', '--timeout', '60')
                for image in item['images'].values():
                    stopped = self.r.json(['docker', 'inspect', image['container']], timeout=30)[0]
                    if stopped['State']['Running']:
                        raise Refused('central component did not quiesce')
                self.assert_volume_consumers(item)
                self.reader.write(item, 'producers-stopped')
                self.reader.pause(item)
                self.reader.cold_ready(item)
                item['capture'] = ClosedCapture.take({path: 'directory' for path in item['paths']}, self.root, sealed=True)
                self.write(item, 'stopping')
                item['archives'] = []
                for index, path in enumerate(item['paths']):
                    archive = str(Path(item['backup']) / ('state-' + str(index) + '.tar'))
                    item['archives'].append({'path': path, 'archive': archive,
                                             'sha256': self.archive(path, archive, capture=item['capture'])})
                ClosedCapture.verify(item['capture'], self.root)
                self.validate_restore_scope(item)
                self.write(item, 'backed-up')
                # Preserve the active config, credentials and certificates;
                # the supported patch transition changes only image selectors.
                compose = Path(item['compose'])
                self.write(item, 'switching')
                compose.write_bytes(text.encode('utf-8'))
                sync_file(compose)
                if digest(compose) != item['target_compose_sha256']:
                    raise Refused('target Compose configuration was not durably written')
                self.validate_persisted_graph(item, target=True)
                self.reader_before_producers(item)
                self.compose_run(item, 'up', '-d', '--pull', 'never')
                self.reader.write(item, 'active')
                self.write(item, 'validating')
                self.wait(target, target_images)
                self.check_data(item['data'])
                item['canary'] = self.canary()
                ScopeLayout.inspect({path: 'directory' for path in item['paths']}, self.root)
                self.final_reader(item)
                self.finish(item, 'committed')
                return {'changed': True, 'version': target, 'directory': item['directory'], 'backup': item['backup']}
            except Exception as failure:
                try:
                    if item['phase'] in ('backed-up', 'switching', 'validating', 'recovering'):
                        self.rollback(item)
                    else:
                        # Backup failure changed no package/data. Restart old
                        # stack without restoring an incomplete archive.
                        self.recover_pre_switch(item)
                except Exception as recovery:
                    raise Refused('central upgrade failed AND recovery failed; persistent journal retained') from recovery
                raise Refused('central upgrade failed; previous images, data and availability recovered') from failure


class ConfigSnapshots:
    """Bounded ordinary config/service rollback within one selected invocation.

    These are private snapshots, not upgrade journals or package authority.
    The caller supplies only resources it selected/attempted this invocation;
    a new operation UUID prevents a resumed verifier using an older snapshot.
    """
    FILES = {'config': '/var/ossec/etc/ossec.conf', 'hosts': '/etc/hosts'}
    SERVICES = {'agent-service': 'wazuh-agent', 'audit-service': 'auditd'}

    def __init__(self, owner, operation, runner=None, root=ROOT, paths=None):
        if not all(re.fullmatch('[a-f0-9]{32}', value or '') for value in (owner, operation)):
            raise Refused('invalid ordinary configuration snapshot identity')
        self.owner, self.operation, self.r, self.root = owner, operation, runner or Runner(), Path(root)
        # Internal filesystem seam; the CLI exposes only the fixed resources.
        self.paths = paths or self.FILES
        self.folder = self.root / ('normal-' + owner + '-' + operation)
        self.manifest = self.folder / 'manifest.json'

    def state(self):
        if not self.manifest.exists():
            return {'owner': self.owner, 'operation': self.operation, 'resources': {}}
        private_file(self.manifest, self.folder)
        item = json.loads(self.manifest.read_text())
        if item['owner'] != self.owner or item['operation'] != self.operation or not set(item['resources']).issubset(self.FILES.keys() | self.SERVICES.keys()):
            raise Refused('ordinary snapshot identity or resource scope changed')
        return item

    @contextlib.contextmanager
    def lock(self):
        with HostWriter(self.root).guard(self.owner, 'agent'):
            transaction = Transaction('agent', runner=self.r, root=self.root)
            with transaction.component_lock():
                transaction.idle()
                yield transaction

    def service(self, unit):
        active = self.r.run(['systemctl', 'is-active', unit], allowed=(0, 3, 4), timeout=30).returncode == 0
        enabled = self.r.run(['systemctl', 'is-enabled', unit], allowed=(0, 1, 3, 4), timeout=30).stdout.strip()
        if enabled not in ('enabled', 'disabled'):
            raise Refused('unsupported prior ordinary service enablement state')
        return {'active': active, 'enabled': enabled}

    def save(self, resource, selected_path=''):
        if resource not in self.FILES and resource not in self.SERVICES:
            raise Refused('unknown ordinary Wazuh resource')
        if selected_path and selected_path != self.FILES.get(resource):
            raise Refused('ordinary configuration path is outside its bounded resource')
        with self.lock() as transaction:
            private_dir(self.folder)
            item = self.state()
            if resource not in item['resources']:
                if resource in self.FILES:
                    path = str(Path(self.paths[resource]))
                    capture = ClosedCapture.take({path: 'file'}, self.root, missing=(path,), sealed=True)
                    entry = {'path': path, 'capture': capture, 'archive': None, 'sha256': None}
                    if not capture['absent']:
                        archive = self.folder / (resource + '.tar')
                        entry.update(archive=str(archive), sha256=transaction.archive(path, archive, capture=capture))
                    item['resources'][resource] = entry
                else:
                    unit = self.SERVICES[resource]
                    previous = self.service(unit)
                    if not previous['active']:
                        stoppable = self.r.run(['systemctl', 'show', unit, '-p', 'RefuseManualStop', '--value'], timeout=30).stdout.strip()
                        if stoppable != 'no':
                            raise Refused('inactive ordinary service cannot be safely restored after start')
                    item['resources'][resource] = previous
                atomic_json(self.manifest, item)
            return {'saved': resource}

    def restore(self, resources):
        if (not isinstance(resources, list) or len(resources) != len(set(resources))
                or not set(resources).issubset(self.FILES.keys() | self.SERVICES.keys())):
            raise Refused('invalid ordinary rollback resource authority')
        if not resources: return {'restored': [], 'services': []}
        with self.lock() as transaction:
            item = self.state()
            if not set(resources).issubset(item['resources']):
                raise Refused('ordinary rollback has no snapshot for selected resource')
            current = {}
            # Check every selected source and archive before changing any file.
            for resource in resources:
                if resource not in self.FILES: continue
                entry = item['resources'][resource]
                path = str(Path(self.paths[resource]))
                if entry['path'] != path or entry['capture']['roots'] != {path: 'file'} or not entry['capture']['sealed']:
                    raise Refused('ordinary snapshot escaped its fixed file scope')
                absent = entry['capture']['absent']
                if (absent not in ([], [path]) or bool(entry['archive']) == bool(absent)
                        or set(entry['capture']['nodes']) != (set() if absent else {path})):
                    raise Refused('ordinary snapshot presence is inconsistent')
                current[resource] = ClosedCapture.take({path: 'file'}, self.root, missing=(path,), sealed=True)
                if entry['archive']:
                    if entry['archive'] != str(self.folder / (resource + '.tar')):
                        raise Refused('ordinary archive escaped its snapshot directory')
                    private_file(entry['archive'], self.folder)
                    if digest(entry['archive']) != entry['sha256']:
                        raise Refused('ordinary snapshot checksum changed')
            restored, services = [], []
            for resource in resources:
                if resource not in self.FILES: continue
                entry = item['resources'][resource]
                if ClosedCapture.persistent(current[resource]) == ClosedCapture.persistent(entry['capture']): continue
                if entry['archive']:
                    transaction.restore(entry['path'], entry['archive'], entry['sha256'])
                else:
                    durable_unlink(entry['path'])
                ClosedCapture.verify(entry['capture'], self.root)
                restored.append(resource)
            for resource in resources:
                if resource not in self.SERVICES: continue
                unit, before = self.SERVICES[resource], item['resources'][resource]
                if not isinstance(before.get('active'), bool) or before.get('enabled') not in ('enabled', 'disabled'):
                    raise Refused('ordinary snapshot service state is invalid')
                actual = self.service(unit)
                if actual['enabled'] != before['enabled']:
                    self.r.run(['systemctl', 'enable' if before['enabled'] == 'enabled' else 'disable', unit], timeout=60)
                    services.append(resource)
                if actual['active'] != before['active']:
                    self.r.run(['systemctl', 'start' if before['active'] else 'stop', unit], timeout=90)
                    services.append(resource)
                elif resource == 'agent-service' and before['active'] and restored:
                    # Only a service selected/attempted by this invocation can
                    # have loaded its changed config. Never restart auditd.
                    self.r.run(['systemctl', 'restart', unit], timeout=90)
                    services.append(resource)
                if self.service(unit) != before:
                    raise Refused('selected ordinary service state was not restored')
            return {'restored': sorted(restored), 'services': sorted(set(services))}


class Agent(Transaction):
    POLICY_HOOK = '/usr/sbin/policy-rc.d'
    POLICY_TEMP = '#!/bin/sh\nexit 101\n'
    def __init__(self, family, **kwargs):
        super().__init__('agent', **kwargs)
        if family not in ('Debian', 'RedHat'):
            raise Refused('unsupported agent package backend')
        self.family = family

    def pin_path(self):
        return '/etc/apt/preferences.d/pilot-wazuh-agent' if self.family == 'Debian' else '/etc/yum.repos.d/wazuh.repo'

    def guard(self):
        return PackageGuard(self.family, self.r, self.root)

    def audit_runtime(self): return AuditRuntime(self.r)

    def audit_check(self, item, stopped=False, ready=False, capture=None):
        self.audit_runtime().check(item.get('audit_runtime'), capture or self.capture_sources(recovery=True), stopped, ready)

    def hook_original(self, item):
        """Validate only sealed hook material; independent of live audit/data."""
        if self.family != 'Debian' or 'policy_hook' not in item: return None
        hook = item['policy_hook']
        path = path_shape(self.POLICY_HOOK, 'file', missing=True)
        if hook['path'] != self.POLICY_HOOK or hook['temporary_sha256'] != hashlib.sha256(self.POLICY_TEMP.encode()).hexdigest():
            raise Refused('policy hook authority escaped its exact resource')
        expected = item['capture']['nodes'].get(str(path))
        if bool(expected) != hook['present'] or expected != hook['node']:
            raise Refused('original policy hook differs from sealed cold capture')
        if hook['present']:
            entry = hook['archive']
            if entry not in item['archives'] or entry['path'] != self.POLICY_HOOK:
                raise Refused('policy hook archive escaped its original transaction')
            private_file(entry['archive'], item['backup'])
            if digest(entry['archive']) != entry['sha256']:
                raise Refused('original policy hook archive checksum mismatch')
            try:
                with tarfile.open(entry['archive'], 'r:') as archive:
                    members = archive.getmembers()
                    if len(members) != 1 or members[0].name != path.name or not members[0].isfile():
                        raise Refused('original policy hook archive is not a single regular file')
                    content = archive.extractfile(members[0])
                    if content is None or hashlib.sha256(content.read()).hexdigest() != expected['sha256']:
                        raise Refused('original policy hook payload is not its sealed bytes')
            except tarfile.TarError as exc:
                raise Refused('original policy hook archive is unreadable') from exc
        elif str(path) not in item['capture']['absent'] or hook['archive'] is not None:
            raise Refused('policy hook absence is not its sealed original state')
        return hook

    def hook_matches(self, hook):
        path = path_shape(self.POLICY_HOOK, 'file', missing=True)
        if not path.exists(): return not hook['present']
        if not hook['present']: return False
        actual = ClosedCapture.take({str(path): 'file'}, self.root, sealed=True)['nodes'][str(path)]
        return {key: value for key, value in actual.items() if key != 'identity'} == {key: value for key, value in hook['node'].items() if key != 'identity'}

    def hook_current_owned(self, hook):
        if self.hook_matches(hook): return
        path = path_shape(self.POLICY_HOOK, 'file', missing=True)
        # A stopped native module may have moved the original aside or be
        # between atomic creation and chmod. These are recorded owned gaps.
        if not path.exists(): return
        info = path.stat()
        if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in (0o600, 0o755)
                or digest(path) != hook['temporary_sha256']):
            raise Refused('unknown foreign policy hook drift; refusing overwrite')

    def hook_prepare(self, owner):
        with self.lock(owner=owner):
            item = self.owned(owner, ('installing', 'recovering'))
            self.audit_check(item, stopped=True)
            hook = self.hook_original(item)
            if hook is None: raise Refused('installer has no sealed policy hook authority')
            self.hook_current_owned(hook)
            item['hook_state'] = 'preparing'
            self.write(item, item['phase'])
            atomic_text(self.POLICY_HOOK, self.POLICY_TEMP, private=True)
            path = path_shape(self.POLICY_HOOK, 'file'); path.chmod(0o755); sync_file(path)
            item['hook_state'] = 'prepared'
            self.write(item, item['phase'])
            return {'prepared': True}

    def hook_cleanup(self, owner, confirmed=False):
        if not confirmed:
            raise Refused('policy hook cleanup requires confirmation previous installer jobs stopped')
        with self.lock(owner=owner):
            item = self.owned(owner)
            hook = self.hook_original(item)
            if hook is None: return {'changed': False}
            self.hook_current_owned(hook)
            if hook['present']:
                if not self.hook_matches(hook):
                    entry = hook['archive']
                    self.restore(self.POLICY_HOOK, entry['archive'], entry['sha256'])
                else:
                    sync_file(Path(self.POLICY_HOOK))
            else:
                durable_unlink(self.POLICY_HOOK)
            if not self.hook_matches(hook):
                raise Refused('original global policy hook was not restored')
            item['hook_state'] = 'restored'
            self.write(item, item['phase'])
            return {'changed': False, 'restored': True}

    def hook_verify(self, item):
        hook = self.hook_original(item)
        if hook is not None and not self.hook_matches(hook):
            raise Refused('original global policy hook must be restored before native proof')

    def policy_stage_file(self, owner):
        if not re.fullmatch('[a-f0-9]{32}', owner):
            raise Refused('invalid policy-stage owner')
        return self.root / ('agent-policy-' + owner) / 'stage.json'

    def prepare_policy_stage(self, owner, plan):
        actual = agent_plan(self.installed(), plan['manager'], plan['version'], True)
        if not actual['change'] or any(plan[key] != actual[key] for key in ('installed', 'version', 'package', 'manager', 'change')):
            raise Refused('policy stage does not match the native compatible upgrade plan')
        guard = self.guard()
        before = guard.snapshot()
        if self.family == 'Debian' and before['installed'] != plan['installed']:
            raise Refused('native APT installed policy differs from the package probe')
        folder = private_dir(self.policy_stage_file(owner).parent)
        overlays = {}
        providers, keyring = {}, None
        if self.family == 'RedHat':
            for package in (plan['installed'], plan['package']):
                overlays[package] = guard.overlay(owner, package, plan['installed'])
                providers[package] = guard.official_rpm_provider(overlays[package], package)
            keyring = guard.official_rpm_keyring(owner)
        item = {'owner': owner, 'family': self.family, 'installed': plan['installed'], 'package': plan['package'],
                'policy_before': before, 'overlays': overlays, 'providers': providers, 'keyring': keyring}
        atomic_json(folder / 'stage.json', item)
        return item

    def load_policy_stage(self, owner):
        filename = self.policy_stage_file(owner)
        private_file(filename, filename.parent)
        item = json.loads(filename.read_text())
        if item['owner'] != owner or item['family'] != self.family:
            raise Refused('policy stage belongs to another writer/backend')
        self.guard().nevra(item['installed']); self.guard().nevra(item['package'])
        if self.family == 'RedHat':
            if set(item['overlays']) != {item['installed'], item['package']}:
                raise Refused('policy stage has an unsupported package set')
            for overlay in item['overlays'].values():
                self.guard().verify_overlay(overlay, owner)
        return item

    def authorize_apt(self, owner, package, stage=False, artifact=''):
        with self.lock(owner=owner):
            if self.family != 'Debian':
                raise Refused('APT authorization requires the Debian backend')
            item = self.active()
            if stage:
                if item:
                    raise Refused('package downloads cannot reuse installation/recovery authority')
                prepared = self.load_policy_stage(owner)
                if artifact or package not in (prepared['installed'], prepared['package']):
                    raise Refused('APT stage escaped its exact prepared versions')
                if self.installed() != prepared['installed'] or not self.guard().same_context(prepared['policy_before'], self.guard().snapshot()):
                    raise Refused('native package/policy changed since stage admission')
            else:
                item = self.owned(owner, ('installing', 'recovering'))
                self.audit_check(item, stopped=True)
                expected = item['package'] if item['phase'] == 'installing' else item['installed']
                info = item['packages'].get(expected)
                if package != expected or not info or artifact != info['path']:
                    raise Refused('APT installation escaped its exact owned retained artifact')
                private_file(artifact, item['backup'])
                if digest(artifact) != info['sha256']:
                    raise Refused('authorized APT artifact changed')
            return self.guard().apt_plan(package, artifact)

    def authorize_rpm(self, owner, recovery=False):
        item = self.owned(owner, ('recovering',) if recovery else ('installing',))
        package = item['installed'] if recovery else item['package']
        self.validate_packages(item)
        artifact = item['packages'][package]['path']
        guard = self.guard()
        guard.verify_official_rpm(artifact, item['packages'][package]['provider'], item['policy_stage']['keyring'], owner)
        config = guard.artifact_plan(item['policy_stage']['overlays'][package], owner, artifact, package,
                                     recovery=recovery and self.installed() != package, reinstall=self.installed() == package)
        return {'package_path': artifact, 'dnf_conf_file': config,
                'dnf_action': 'reinstall' if self.installed() == package else 'downgrade' if recovery else 'install'}

    def protect_package(self, owner):
        with self.lock(owner=owner):
            item = self.active()
            package = self.installed()
            if item:
                self.owned(owner, ('installing',))
                self.audit_check(item)
                if package != item['package']:
                    raise Refused('cannot advance native protection before the exact target is installed')
            return self.guard().protect(package)

    def policy_ownership(self, owner):
        with self.lock(owner=owner):
            if self.active():
                self.owned(owner, ('installing',))
                self.audit_check(self.active())
            state = self.guard().ownership()
            return {'checked': True, 'prerequisite_plugin_present': state.get('plugin', {}).get('present')}

    def fresh_rpm(self, owner, plan):
        with self.lock(owner=owner):
            self.idle()
            if self.family != 'RedHat' or self.installed() or plan != agent_plan('', plan['manager'], plan['version']):
                raise Refused('fresh RPM stage requires the current compatible fresh plan')
            guard = self.guard()
            overlay = guard.overlay(owner, plan['package'])
            provider = guard.official_rpm_provider(overlay, plan['package'])
            keyring = guard.official_rpm_keyring(owner)
            folder = private_dir(self.root / ('rpm-fresh-' + owner))
            for path in folder.iterdir(): private_file(path, folder)
            self.r.run(['dnf', '-c', overlay['config'], '-y', '--disableexcludes=wazuh',
                        '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1', 'install', '--downloadonly',
                        '--downloaddir=' + str(folder), guard.nevra(plan['package'])], timeout=900,
                       operation='stage exact official fresh Wazuh RPM')
            matches = []
            for path in folder.glob('*.rpm'):
                private_file(path, folder)
                if digest(path) == provider['sha256']: matches.append(path)
            if len(matches) != 1:
                raise Refused('fresh RPM stage does not contain one exact official payload')
            path = matches[0]
            guard.verify_official_rpm(path, provider, keyring, owner)
            fields = self.r.run(['rpm', '-qp', '--qf', '%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}', path]).stdout.splitlines()
            if fields != ['wazuh-agent', plan['package'], 'x86_64']:
                raise Refused('fresh official RPM package identity mismatch')
            config = guard.verify_overlay(overlay, owner)
            return {'package_path': str(path), 'dnf_conf_file': config}

    def source_specs(self):
        specs = {'/var/ossec': 'directory', '/etc/hosts': 'file', self.pin_path(): 'file',
                 '/etc/audit/plugins.d/af_wazuh.conf': 'linked-file'}
        if self.family == 'RedHat':
            specs.update({PackageGuard.MAIN: 'file', PackageGuard.PLUGIN: 'file', PackageGuard.LOCKS: 'file'})
        else:
            specs[self.POLICY_HOOK] = 'file'
        return specs

    def capture_sources(self, sealed=False, recovery=False):
        specs = self.source_specs()
        path_shape(Path('/etc/audit/plugins.d/af_wazuh.conf').parent, 'directory')
        missing = tuple(specs) if recovery else tuple(name for name in specs if name != '/var/ossec')
        capture = (ClosedCapture.take(specs, self.root, missing=missing, sealed=True) if sealed
                   else ScopeLayout.inspect(specs, self.root, missing=missing))
        capture['managed_files'] = self.managed_files(capture, missing=recovery)
        plugin = str(Path('/etc/audit/plugins.d/af_wazuh.conf'))
        if plugin in capture['nodes'] and not recovery:
            internal = ClosedCapture.resolve_link(Path('/var/ossec/etc/af_wazuh.conf'), capture['nodes'],
                                                 [Path(root) for root in capture['roots']])
            if sorted([plugin, internal]) not in capture['hardlinks']:
                raise Refused('component audit plugin must be the exact captured two-link pair')
        return capture

    def source_paths(self):
        specs = self.source_specs()
        self.capture_sources()
        return [name for name in specs if Path(name).exists()]

    def managed_files(self, capture=None, missing=False):
        # These files are directly read/written by enrollment/configuration;
        # preserving only an alias would omit their effective old contents.
        if capture is None:
            capture = ScopeLayout.inspect(self.source_specs(), self.root, missing=tuple(self.source_specs()) if missing else
                                         tuple(name for name in self.source_specs() if name != '/var/ossec'))
        managed = {}
        for filename in ('/var/ossec/etc/client.keys', '/var/ossec/etc/ossec.conf'):
            try:
                effective = ClosedCapture.resolve_link(Path(filename), capture['nodes'], [Path(root) for root in capture['roots']])
            except Refused:
                if missing:
                    continue
                raise
            if capture['nodes'][effective]['type'] != 'file':
                raise Refused('managed agent identity/configuration must resolve to a captured regular file')
            managed[str(Path(filename))] = {'effective': effective,
                                          'sha256': ClosedCapture.file_hash(effective, capture['nodes'][effective]['identity'])}
        return managed

    def validate_agent_layout(self, item, recovery=False):
        pin = self.pin_path()
        expected = set(self.source_specs()) - set(item['absent_sources'])
        if (set(item['paths']) != expected or '/var/ossec' not in expected
                or len(item['absent_sources']) != len(set(item['absent_sources']))
                or not set(item['absent_sources']).issubset(set(self.source_specs()) - {'/var/ossec'})
                or item['pin_state']['path'] != pin or item['pin_state']['present'] != (pin in expected)):
            raise Refused('agent selected recovery sources escaped their exact allowed scope')
        self.capture_sources(recovery=recovery)
        if not recovery and set(self.source_paths()) != expected:
            raise Refused('agent source presence changed before cold backup')

    def validate_packages(self, item):
        if self.family == 'RedHat':
            self.guard().verify_rpm_keyring(item['policy_stage']['keyring'], item['owner'])
        if set(item['packages']) != {item['installed'], item['package']}:
            raise Refused('retained exact package set changed')
        for info in item['packages'].values():
            path = private_file(info['path'], item['backup'])
            if digest(path) != info['sha256']:
                raise Refused('retained package checksum mismatch')

    def validate_stage_scope(self):
        if self.family == 'Debian':
            # A cache bind alias into agent data is also an output-scope escape,
            # even though it has no symlink components. Debian package writes
            # remain entirely in the sanctioned framework.
            cache = '/var/cache/apt/archives'
            restore_sources({'/var/ossec': 'directory', '/etc/hosts': 'file',
                             self.pin_path(): 'file', cache: 'directory'}, self.root,
                            missing=('/etc/hosts', self.pin_path()))

    def stage_preflight(self, owner, plan=None):
        with self.lock(owner=owner):
            self.idle()
            self.source_paths()
            self.validate_stage_scope()
            if self.family == 'RedHat':
                cache = self.root / 'rpm-stage'
                path_shape(cache, 'directory', missing=True)
                private_dir(cache)
                # Do not let stale aliases become DNF output destinations.
                for path in cache.glob('*'):
                    private_file(path, cache)
            result = {'ready': True}
            if plan is not None:
                prepared = self.prepare_policy_stage(owner, plan)
                result['dnf_configs'] = {package: value['config'] for package, value in prepared['overlays'].items()}
            return result

    def capture_pin(self):
        path = path_shape(self.pin_path(), 'file', missing=True)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise Refused('unsafe agent pin state')
        return {'path': self.pin_path(), 'present': path.exists(),
                'sha256': digest(path) if path.exists() else None}

    def verify_pin(self, item, target=False):
        expected = item['target_pin_state'] if target else item['pin_state']
        if expected['path'] != self.pin_path() or self.capture_pin() != expected:
            raise Refused('agent version pin does not match the verified transaction state')

    def restore_absence(self, item):
        self.validate_agent_layout(item, recovery=True)
        expected = item['absent_sources']
        if item['absent_pins'] != expected or set(expected) & set(item['paths']):
            raise Refused('agent absence restoration escaped its recorded scope')
        for filename in expected:
            if self.family != 'RedHat' or filename != PackageGuard.LOCKS:
                durable_unlink(filename)

    def verify_managed_pin(self, installed):
        return self.guard().verify(installed)

    def installed(self):
        if self.family == 'Debian':
            result = self.r.run(['dpkg-query', '-W', '-f=${Status}\t${Version}\t${Architecture}', 'wazuh-agent'], allowed=(0, 1))
            if result.returncode == 1:
                # Native local capture 2026-11-03: absence is rc1, empty stdout,
                # and this exact C-locale diagnostic; query errors are distinct.
                if result.stdout or result.stderr.strip() != 'dpkg-query: no packages found matching wazuh-agent':
                    raise Refused('Debian installed-package probe failed')
                return ''
            fields = result.stdout.split('\t')
            if len(fields) != 3 or fields[0] not in ('install ok installed', 'hold ok installed') or fields[2] != 'amd64':
                raise Refused('unknown agent package state or architecture')
            return fields[1]
        result = self.r.run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}\t%{ARCH}', 'wazuh-agent'], allowed=(0, 1))
        if result.returncode == 1:
            # rpm rc=1 is only treated as absent for its native not-installed
            # response. Database/query errors must never become fresh installs.
            if result.stdout.strip() != 'package wazuh-agent is not installed':
                raise Refused('RPM installed-package probe failed')
            return ''
        fields = result.stdout.split('\t')
        if len(fields) != 2 or fields[1] != 'x86_64':
            raise Refused('unknown agent RPM architecture')
        return fields[0]

    def check(self, manager='', requested='', upgrade=False, owner=None):
        with self.lock(owner=owner, reader=True):
            self.idle()
            return agent_plan(self.installed(), manager, requested, upgrade)

    def package_archives(self, installed, target):
        # The sanctioned package framework populates this authenticated cache
        # before reserve/quiesce. Copy exact old and new artifacts privately.
        result = {}
        self.validate_stage_scope()
        if self.family == 'Debian':
            filename = Path(__file__).with_name('apt-exact-stage.py')
            spec = importlib.util.spec_from_file_location('pilot_apt_exact_stage', filename)
            if spec is None or spec.loader is None:
                raise Refused('shared APT stage verifier is unavailable')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            try:
                for release in (installed, target):
                    if release:
                        verified = module.verify({'wazuh-agent': release})[0]
                        provider = module.verify_wazuh_source({'wazuh-agent': release})[release]
                        if (provider['sha256'] != verified['sha256']
                                or Path(verified['path']).name != 'wazuh-agent_' + release + '_amd64.deb'):
                            raise ValueError('official provider differs from staged bytes')
                        result[release] = {'path': Path(verified['path']), 'sha256': verified['sha256'], 'provider': provider}
            except (ValueError, KeyError, OSError, ImportError, SystemError, subprocess.SubprocessError) as exc:
                raise Refused('exact staged Debian artifact failed authenticated metadata validation') from exc
            return result
        cache = self.root / 'rpm-stage'
        path_shape(cache, 'directory')
        if cache.stat().st_uid != os.geteuid() or stat.S_IMODE(cache.stat().st_mode) != 0o700:
            raise Refused('unsafe private RPM staging directory')
        for path in cache.glob('*.rpm'):
            private_file(path, cache)
        marker = HostWriter(self.root).active()
        if not marker or marker['component'] != 'agent':
            raise Refused('RPM verification requires its exact agent writer')
        prepared = self.load_policy_stage(marker['owner'])
        for path in cache.glob('*.rpm'):
            path = private_file(path, cache)
            signature = self.r.run(['rpmkeys', '-Kv', path]).stdout
            if not re.search(r'Signature.*: OK', signature):
                raise Refused('staged RPM lacks a verified trusted signature')
            value = self.r.run(['rpm', '-qp', '--qf', '%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}', path]).stdout.splitlines()
            if len(value) == 3 and value[0] == 'wazuh-agent' and value[2] == 'x86_64':
                if value[1] not in (installed, target):
                    continue
                provider = prepared['providers'][value[1]]
                self.guard().verify_official_rpm(path, provider, prepared['keyring'], marker['owner'])
                if value[1] in result and result[value[1]]['sha256'] != digest(path):
                    raise Refused('ambiguous staged same-NEVRA RPM bytes')
                result[value[1]] = {'path': path, 'sha256': digest(path), 'provider': provider}
        for expected in (installed, target):
            if expected and expected not in result:
                raise Refused('exact signed package artifact missing before downtime')
        return result

    def reserve(self, owner, plan):
        with self.lock(owner=owner):
            self.idle()
            if not plan.get('installed') or not plan.get('change'):
                raise Refused('durable agent transactions are only for existing enrolled-agent upgrades')
            if self.installed() != plan['installed']:
                raise Refused('installed package changed since compatibility probe')
            admission = self.capture_sources()
            runtime = self.audit_runtime().snapshot(admission)
            paths = [name for name in self.source_specs() if Path(name).exists()]
            self.validate_stage_scope()
            keys = Path('/var/ossec/etc/client.keys')
            if keys.stat().st_size == 0:
                raise Refused('controlled upgrade requires an existing enrolled agent identity')
            effective_keys = ClosedCapture.resolve_link(keys, admission['nodes'], [Path(root) for root in admission['roots']])
            keys_hash = ClosedCapture.file_hash(effective_keys, admission['nodes'][effective_keys]['identity'])
            if not self.policy_stage_file(owner).exists():
                self.prepare_policy_stage(owner, plan)
            prepared = self.load_policy_stage(owner)
            packages = self.package_archives(plan['installed'], plan['package'])
            for release, artifact in packages.items():
                if release in (plan['installed'], plan['package']):
                    retained_source = path_shape(artifact['path'], 'file')
                    if retained_source.stat().st_uid != os.geteuid():
                        raise Refused('staged package has a different owner')
            pin = self.pin_path()
            policy_before = self.guard().snapshot()
            if not self.guard().same_context(prepared['policy_before'], policy_before):
                raise Refused('native package policy changed between staging and reservation')
            self.capacity(paths)
            active = self.r.run(['systemctl', 'is-active', 'wazuh-agent'], allowed=(0, 3, 4)).returncode == 0
            enabled = self.r.run(['systemctl', 'is-enabled', 'wazuh-agent'], allowed=(0, 1, 3, 4)).stdout.strip()
            if enabled not in ('enabled', 'disabled'):
                raise Refused('unsupported previous agent service enablement state')
            if self.source_paths() != paths:
                raise Refused('agent source presence changed before reservation')
            admission = self.capture_sources()
            self.audit_runtime().check(runtime, admission)
            if digest(keys) != keys_hash:
                raise Refused('agent identity changed before reservation')
            plugin_present = Path('/etc/audit/plugins.d/af_wazuh.conf').exists()
            absent = [name for name in self.source_specs() if name not in paths]
            item = self.begin(owner, dict(plan, active=active, enabled=enabled, family=self.family,
                                          paths=paths, absent_pins=absent, absent_sources=absent,
                                          audit_plugin_present=plugin_present, admission_capture=admission,
                                          pin_state=self.capture_pin(), keys=keys_hash,
                                          policy_before=policy_before, policy_stage=prepared, audit_runtime=runtime))
            item['packages'] = {}
            for release, artifact in packages.items():
                if release not in (plan['installed'], plan['package']):
                    continue
                path_shape(artifact['path'], 'file')
                destination = Path(item['backup']) / artifact['path'].name
                if destination.exists() or destination.is_symlink():
                    raise Refused('retained package destination already exists')
                shutil.copy2(artifact['path'], destination)
                private_file(destination, item['backup'])
                if digest(destination) != artifact['sha256']:
                    raise Refused('signed package changed between staging and private retention')
                sync_file(destination)
                item['packages'][release] = {'path': str(destination), 'sha256': artifact['sha256'],
                                             'provider': artifact.get('provider')}
            self.write(item, 'staged')
            return {'backup': item['backup'], 'changed': False}

    def cold_backup(self, owner):
        with self.lock(owner=owner):
            item = self.owned(owner, ('staged',))
            self.validate_agent_layout(item)
            self.audit_check(item)
            self.verify_pin(item)
            self.validate_packages(item)
            self.write(item, 'stopping')
            if item['installed']:
                self.r.run(['systemctl', 'stop', 'wazuh-agent'], timeout=90)
                if self.r.run(['systemctl', 'is-active', 'wazuh-agent'], allowed=(0, 3, 4)).returncode == 0:
                    raise Refused('agent failed to quiesce')
            item['capture'] = self.capture_sources(sealed=True)
            self.audit_check(item, stopped=True, capture=item['capture'])
            self.write(item, 'stopping')
            item['archives'] = []
            for index, path in enumerate(item['paths']):
                archive = str(Path(item['backup']) / ('agent-state-' + str(index) + '.tar'))
                excluded = [AuditRuntime.endpoint()] if item['audit_runtime'] and Path(path) == Path('/var/ossec') else []
                item['archives'].append({'path': path, 'archive': archive,
                                         'sha256': self.archive(path, archive, capture=item['capture'], excluded=excluded)})
            ClosedCapture.verify(item['capture'], self.root)
            self.validate_agent_archives(item)
            keys = Path('/var/ossec/etc/client.keys')
            if (digest(keys) if keys.is_file() else None) != item['keys']:
                raise Refused('agent identity changed before cold backup completed')
            self.write(item, 'backed-up')
            return {'changed': False}

    def authorize_install(self, owner):
        with self.lock(owner=owner):
            item = self.owned(owner, ('backed-up',))
            self.validate_agent_archives(item)
            ClosedCapture.verify(item['capture'], self.root)
            self.audit_check(item, stopped=True)
            if self.family == 'Debian':
                path = str(Path(self.POLICY_HOOK))
                node = item['capture']['nodes'].get(path)
                item['policy_hook'] = {'path': self.POLICY_HOOK, 'present': node is not None, 'node': node,
                                       'archive': next((entry for entry in item['archives'] if entry['path'] == self.POLICY_HOOK), None),
                                       'temporary_sha256': hashlib.sha256(self.POLICY_TEMP.encode()).hexdigest()}
            self.write(item, 'installing')
            self.guard().protect(item['installed'])
            result = {'changed': False, 'package_path': item['packages'][item['package']]['path']}
            if self.family == 'RedHat':
                result.update(self.authorize_rpm(owner))
            return result

    def prepare_recovery(self, owner):
        with self.lock(owner=owner):
            item = self.owned(owner)
            self.validate_agent_layout(item, recovery=True)
            self.audit_check(item)
            action = AGENT_RECOVERY.get(item['phase'])
            if action == 'resume-old':
                # No package/data restore authority exists before a cold backup.
                self.restore_service(item)
                self.verify_old_state(item)
                self.finish(item, 'recovered-before-install')
                return {'reinstall': False, 'restored': True, 'need_commit': False}
            if action in ('verify-old', 'verify-target'):
                if action == 'verify-old':
                    self.restore_absence(item)
                self.verify_pin(item, target=action == 'verify-target')
                return {'reinstall': False, 'restored': True, 'need_commit': True,
                        'manager_host': item.get('manager_host', '')}
            if action != 'restore-old':
                raise Refused('agent transaction is not recoverable')
            if not item['installed']:
                raise Refused('fresh install failed; explicit cleanup required, journal retained')
            # Validate ALL old state before even a recovery package mutation.
            self.validate_agent_archives(item)
            self.hook_verify(item)
            old = item['packages'].get(item['installed'])
            if item['installed'] and (not old or digest(old['path']) != old['sha256']):
                raise Refused('old agent package is unavailable; journal retained')
            self.r.run(['systemctl', 'stop', 'wazuh-agent'], timeout=90)
            if self.r.run(['systemctl', 'is-active', 'wazuh-agent'], allowed=(0, 3, 4)).returncode == 0:
                raise Refused('agent failed to quiesce before recovery')
            cold = self.capture_sources(sealed=True, recovery=True)
            self.audit_check(item, stopped=True, capture=cold)
            self.write(item, 'recovering')
            self.guard().protect(item['installed'], require_installed=False)
            result = {'reinstall': bool(item['installed']), 'version': item['installed'],
                    'package_path': old['path'] if old else '', 'restored': False,
                    'need_commit': True, 'manager_host': item.get('manager_host', '')}
            if self.family == 'RedHat':
                result.update(self.authorize_rpm(owner, recovery=True))
            return result

    def validate_agent_archives(self, item):
        self.validate_agent_layout(item, recovery=True)
        self.validate_packages(item)
        allowed = set(self.source_specs())
        if not set(item['paths']).issubset(allowed) or {entry['path'] for entry in item['archives']} != set(item['paths']):
            raise Refused('agent recovery path scope is invalid')
        disjoint(item['paths'], self.root)
        if item['capture']['roots'] != {str(Path(name)): kind for name, kind in self.source_specs().items()} or not item['capture']['sealed']:
            raise Refused('agent cold capture escaped its exact bounded source set')
        if item['capture']['absent'] != sorted(str(Path(name)) for name in item['absent_sources']):
            raise Refused('agent cold capture absence differs from the admitted sources')
        for entry in item['archives']:
            private_file(entry['archive'], item['backup'])
            if canonical(entry['archive']).parent != canonical(item['backup']) or digest(entry['archive']) != entry['sha256']:
                raise Refused('agent recovery archive validation failed before restoration')
            self.audit_runtime().validate_archive(entry['path'], entry['archive'], item['capture'], item.get('audit_runtime'))

    def restore_state(self, owner):
        with self.lock(owner=owner):
            item = self.owned(owner, ('recovering',))
            self.validate_agent_archives(item)
            self.hook_verify(item)
            if item['installed'] and self.installed() != item['installed']:
                raise Refused('old exact package has not been reinstalled')
            self.audit_check(item, stopped=True)
            for entry in item['archives']:
                self.restore(entry['path'], entry['archive'], entry['sha256'], capture=item['capture'],
                             runtime=self.audit_runtime(), proof=item.get('audit_runtime'))
            self.restore_absence(item)
            # Native protection stays on old while availability/identity are
            # proved; its exact original state is restored at final recovery.
            self.guard().protect(item['installed'])
            deferred = [str(Path(PackageGuard.LOCKS))] if self.family == 'RedHat' else []
            ClosedCapture.relink(item['capture'], self.root, deferred=deferred)
            self.verify_pin(item)
            self.hook_verify(item)
            self.audit_check(item, stopped=True)
            self.restore_service(item)
            self.audit_check(item, ready=item['active'])
            self.check_identity(item)
            self.write(item, 'restored')
            return {'changed': True, 'restored': True, 'need_commit': True}

    def finish_recovery(self, owner):
        with self.lock(owner=owner):
            item = self.owned(owner, ('restored', 'committed', 'recovered'))
            self.validate_agent_layout(item, recovery=True)
            self.managed_files()
            already_committed = item['phase'] == 'committed'
            expected = item['package'] if already_committed else item['installed']
            if self.installed() != expected:
                raise Refused('restored package version changed before recovery commit')
            self.check_identity(item)
            self.verify_pin(item, target=already_committed)
            runtime = self._runtime()
            if (already_committed and not runtime['active']) or (not already_committed and runtime['active'] != item['active']):
                raise Refused('previous agent availability changed before recovery commit')
            self.audit_check(item, ready=runtime['active'])
            self.hook_verify(item)
            if already_committed:
                self.guard().verify(item['package'])
            else:
                self.guard().restore_prior(item['policy_before'])
            self.finish(item, 'committed' if already_committed else 'recovered')
            return {'changed': False, 'restored': not already_committed}

    def restore_service(self, item):
        if item['enabled'] in ('enabled', 'disabled'):
            self.r.run(['systemctl', 'enable' if item['enabled'] == 'enabled' else 'disable', 'wazuh-agent'], timeout=60)
        self.r.run(['systemctl', 'start' if item['active'] else 'stop', 'wazuh-agent'], timeout=90)
        active = self.r.run(['systemctl', 'is-active', 'wazuh-agent'], allowed=(0, 3, 4)).returncode == 0
        if active != item['active']:
            raise Refused('previous agent availability was not restored')
        enabled = self.r.run(['systemctl', 'is-enabled', 'wazuh-agent'], allowed=(0, 1, 3, 4)).stdout.strip()
        if enabled != item['enabled']:
            raise Refused('previous agent enablement was not restored')

    def verify_old_state(self, item):
        if self.installed() != item['installed']:
            raise Refused('previous exact agent package was not restored')
        runtime = self._runtime()
        if runtime['active'] != item['active']:
            raise Refused('previous native agent availability was not restored')
        self.check_identity(item)
        self.verify_pin(item)
        self.hook_verify(item)
        self.audit_check(item, ready=item['active'])

    def check_identity(self, item):
        layout = self.capture_sources()
        keys = layout['managed_files'].get(str(Path('/var/ossec/etc/client.keys')))
        if (keys['sha256'] if keys else None) != item.get('keys'):
            raise Refused('agent enrollment identity changed')

    def commit(self, owner):
        with self.lock(owner=owner):
            item = self.owned(owner, ('installing',))
            self.validate_agent_layout(item, recovery=True)
            self.managed_files()
            if self.installed() != item['package']:
                raise Refused('agent effective package version does not match frozen target')
            native = self.r.run(['/var/ossec/bin/wazuh-control', 'info'], timeout=30).stdout
            if re.findall(r'^WAZUH_VERSION="v?(4\.14\.[0-9]+)"$', native, re.M) != [item['version']]:
                raise Refused('agent runtime Wazuh version probe failed')
            self.check_identity(item)
            if item['active'] and self.r.run(['systemctl', 'is-active', 'wazuh-agent'], allowed=(0, 3, 4)).returncode != 0:
                raise Refused('previously active agent is not active after upgrade')
            self.verify_managed_pin(item['package'])
            self.audit_check(item, ready=item['active'])
            self.hook_verify(item)
            for filename in ('/var/ossec/etc/ossec.conf', '/var/ossec/etc/client.keys', '/etc/hosts', self.pin_path()):
                sync_file(filename)
            item['target_pin_state'] = self.capture_pin()
            self.finish(item, 'committed')
            return {'changed': True, 'backup': item['backup']}

    def activate(self, owner):
        with self.lock(owner=owner):
            item = self.owned(owner, ('installing',))
            self.audit_check(item)
            self.restore_service(item)
            self.audit_check(item, ready=item['active'])
            return {'changed': False}

    def _runtime(self):
        package = self.installed()
        if not package:
            raise Refused('agent package is not installed')
        text = self.r.run(['/var/ossec/bin/wazuh-control', 'info'], timeout=30).stdout
        release = package.rsplit('-', 1)[0]
        if re.findall(r'^WAZUH_VERSION="v?(4\.14\.[0-9]+)"$', text, re.M) != [release]:
            raise Refused('installed agent and native binary release differ')
        result = {'version': release, 'active': self.r.run(['systemctl', 'is-active', 'wazuh-agent'], allowed=(0, 3, 4)).returncode == 0}
        keys = Path('/var/ossec/etc/client.keys')
        if keys.is_file() and keys.stat().st_size:
            lines = keys.read_text().splitlines()
            if len(lines) != 1 or len(lines[0].split()) != 4:
                raise Refused('unknown agent enrollment identity')
            fields = lines[0].split()
            result.update(id=fields[0], name=fields[1])
        return result

    def runtime(self, owner=None):
        with self.lock(owner=owner, reader=True):
            item = self.active()
            if item and (not owner or item['owner'] != owner):
                raise Refused('external agent reader cannot inspect an incomplete transaction')
            if item:
                self.owned(owner, ('installing', 'restored', 'committed', 'recovered'))
            return self._runtime()

    def verify(self, owner=None):
        with self.lock(owner=owner, reader=True):
            self.idle()
            result = self._runtime()
            if not result['active']:
                raise Refused('agent native service is inactive')
            installed = self.installed()
            self.verify_managed_pin(installed)
            return dict(result, **{'pass': True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['writer-inspect', 'writer-claim', 'writer-resume', 'writer-release',
                                         'central', 'central-verify', 'manager-version', 'verify-agent', 'agent-verify', 'agent-runtime', 'agent-check', 'agent-stage', 'agent-reserve', 'agent-backup',
                                         'agent-install', 'agent-recovery', 'agent-restore', 'agent-recovery-commit', 'agent-commit', 'agent-activate',
                                         'agent-policy-check', 'agent-protect', 'agent-apt-plan', 'agent-rpm-fresh',
                                         'agent-hook-prepare', 'agent-hook-cleanup', 'agent-config-save', 'agent-config-restore',
                                         'reader-tools-check', 'reader-enable-admit', 'reader-enable-expose', 'reader-enable-verify', 'reader-enable-complete', 'reader-enable-failed'])
    parser.add_argument('--version', default='')
    parser.add_argument('--legacy', default='')
    parser.add_argument('--manager', default='')
    parser.add_argument('--family', choices=['Debian', 'RedHat'], default='Debian')
    parser.add_argument('--owner', default='')
    parser.add_argument('--component', choices=['central', 'agent'], default='central')
    parser.add_argument('--mode', choices=['apply', 'recover', 'canary'], default='apply')
    parser.add_argument('--confirm-previous-stopped', action='store_true')
    parser.add_argument('--agent-id', default='')
    parser.add_argument('--agent-name', default='')
    parser.add_argument('--upgrade', action='store_true')
    parser.add_argument('--preview', action='store_true')
    parser.add_argument('--recover', action='store_true')
    parser.add_argument('--canary', action='store_true')
    parser.add_argument('--stage', action='store_true')
    parser.add_argument('--artifact', default='')
    parser.add_argument('--operation', default='')
    parser.add_argument('--resource', default='')
    parser.add_argument('--path', default='')
    parser.add_argument('--resources', default='[]')
    parser.add_argument('--reader-desired-json', default='{}')
    parser.add_argument('--reader-checker-sha256', default='')
    parser.add_argument('--ack-rsyslog-downtime-and-replay', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Wazuh transactions require root')
    try:
        if args.action == 'writer-inspect':
            value = HostWriter().inspect()
        elif args.action == 'writer-claim':
            value = HostWriter().claim(args.owner, args.component, args.mode)
        elif args.action == 'writer-resume':
            value = HostWriter().resume(args.owner, args.component, args.mode, args.confirm_previous_stopped)
        elif args.action == 'writer-release':
            value = HostWriter().release(args.owner)
        elif args.action == 'manager-version':
            value = Central().observe_manager()
        elif args.action == 'verify-agent':
            value = Central().verify_agent(args.agent_id, args.agent_name, args.version)
        elif args.action == 'central-verify':
            if args.canary and not args.owner:
                foreground = uuid.uuid4().hex
                HostWriter().claim(foreground, 'central', 'canary')
                try:
                    value = Central().verify(True, foreground)
                finally:
                    HostWriter().release(foreground)
            else:
                value = Central().verify(args.canary, args.owner or None)
        elif args.action == 'central':
            value = Central().execute(desired(args.version, args.legacy), args.upgrade, args.preview, args.recover, args.owner,
                                      json.loads(args.reader_desired_json), args.reader_checker_sha256,
                                      args.ack_rsyslog_downtime_and_replay)
        elif args.action == 'reader-tools-check':
            with HostWriter().guard(args.owner, 'central'):
                value = Reader.check_tool_destinations()
        elif args.action.startswith('reader-enable-'):
            value = ReplayReceipt(Central()).operation(args.owner, args.operation,
                        args.action.removeprefix('reader-enable-'),
                        args.ack_rsyslog_downtime_and_replay, args.preview)
        elif args.action in ('agent-config-save', 'agent-config-restore'):
            snapshot = ConfigSnapshots(args.owner, args.operation)
            value = snapshot.save(args.resource, args.path) if args.action == 'agent-config-save' else snapshot.restore(json.loads(args.resources))
        else:
            agent = Agent(args.family)
            if args.action == 'agent-check':
                value = agent.check(args.manager, args.version, args.upgrade, args.owner or None)
            elif args.action == 'agent-stage':
                value = agent.stage_preflight(args.owner, json.load(sys.stdin))
            elif args.action == 'agent-policy-check':
                value = agent.policy_ownership(args.owner)
            elif args.action == 'agent-protect':
                value = agent.protect_package(args.owner)
            elif args.action == 'agent-apt-plan':
                value = agent.authorize_apt(args.owner, args.version, args.stage, args.artifact)
            elif args.action == 'agent-rpm-fresh':
                value = agent.fresh_rpm(args.owner, json.load(sys.stdin))
            elif args.action == 'agent-hook-prepare':
                value = agent.hook_prepare(args.owner)
            elif args.action == 'agent-hook-cleanup':
                value = agent.hook_cleanup(args.owner, args.confirm_previous_stopped)
            elif args.action == 'agent-runtime':
                value = agent.runtime(args.owner or None)
            elif args.action == 'agent-verify':
                value = agent.verify(args.owner or None)
            elif args.action == 'agent-reserve':
                value = agent.reserve(args.owner, json.load(sys.stdin))
            else:
                method = {'agent-backup': agent.cold_backup, 'agent-install': agent.authorize_install,
                          'agent-recovery': agent.prepare_recovery, 'agent-restore': agent.restore_state,
                          'agent-commit': agent.commit, 'agent-activate': agent.activate,
                          'agent-recovery-commit': agent.finish_recovery}[args.action]
                value = method(args.owner)
        print(json.dumps(value, sort_keys=True))
        return 0 if value.get('overall_success', True) else 2
    except Refused as exc:
        print(json.dumps({'error': str(exc)}))
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Native JSON/config/tool failures may carry private values. Do not
        # expose tool stderr, argv, parsed documents or exception repr here.
        print(json.dumps({'error': 'native transaction probe or state operation failed; private journal retained if present'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
