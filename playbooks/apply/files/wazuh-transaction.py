#!/usr/bin/env python3
"""Wazuh's bounded release policy and durable, private upgrade transactions.

Central transactions hold flock for their complete lifetime. Agent transactions
span Ansible package tasks: a durable owner/phase journal reserves the resource,
and each transition checks that owner under flock. Debian installation remains
in apt-package-install.yml, including recovery; this module never invokes APT.
"""
import argparse
import contextlib
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid


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
            tmp.unlink()


class Transaction:
    def __init__(self, kind, runner=None, root=ROOT):
        self.r = runner or Runner()
        self.kind = kind
        self.root = Path(root)
        self.path = self.root / (kind + '-active.json')

    @contextlib.contextmanager
    def lock(self):
        private_dir(self.root)
        fd = os.open(self.root / (self.kind + '.lock'),
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise Refused('unsafe transaction lock')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
        backup = private_dir(self.root / (self.kind + '-' + owner))
        item = dict(state, kind=self.kind, owner=owner, backup=str(backup))
        self.write(item, 'reserved')
        return item

    def finish(self, item, phase):
        self.write(item, phase)
        self.path.unlink()
        sync_directory(self.root)

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

    def archive(self, source, dest):
        source = Path(source)
        self.r.run(['tar', '--acls', '--xattrs', '--xattrs-include=*', '--selinux', '--numeric-owner', '--sparse',
                    '-cpf', dest, '-C', source.parent, source.name], timeout=1800)
        self.r.run(['tar', '-tf', dest], timeout=300)
        checksum = digest(dest)
        sync_file(dest)
        return checksum

    def restore(self, source, archive, checksum):
        if digest(archive) != checksum:
            raise Refused('backup checksum mismatch; refusing restore')
        source = canonical(source)
        archive = canonical(archive)
        disjoint([source], self.root)
        if source.exists():
            if source.is_dir():
                shutil.rmtree(source)
            else:
                source.unlink()
        self.r.run(['tar', '--acls', '--xattrs', '--xattrs-include=*', '--selinux', '--numeric-owner', '--same-owner',
                    '--same-permissions', '-xpf', archive, '-C', source.parent], timeout=1800)
        sync_tree(source)


class Central(Transaction):
    def __init__(self, **kwargs):
        super().__init__('central', **kwargs)

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
        with self.lock():
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
        with self.lock():
            self.idle()
            text = self.r.run(['docker', 'exec', 'single-node-wazuh.manager-1',
                               '/var/ossec/bin/agent_control', '-i', identifier], timeout=30).stdout
            if (re.findall(r'^\s*Agent ID:\s*([0-9]+)\s*$', text, re.M) != [identifier]
                    or re.findall(r'^\s*Agent Name:\s*(\S+)\s*$', text, re.M) != [name]
                    or re.findall(r'^\s*Status:\s*(\S+)\s*$', text, re.M) != ['Active']
                    or re.findall(r'^\s*Client version:\s*Wazuh v(4\.14\.[0-9]+)\s*$', text, re.M) != [expected]):
                raise Refused('manager has not observed the exact active agent identity and version')
            return {'pass': True}

    def verify(self, canary=False):
        with self.lock():
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
        if not re.fullmatch(r'/opt/pilot/wazuh-docker/wazuh-docker-4\.14\.[0-9]+/single-node', str(directory)):
            raise Refused('active Compose directory is outside the pilot-owned single-node layout')
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
        disjoint(sorted(paths), self.root)
        for name in volume_names:
            consumers = self.r.run(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'volume=' + name], timeout=30).stdout.split()
            if not consumers or not set(consumers).issubset(set(ids)):
                raise Refused('persistent volume has consumers outside the selected stack')
        self.health(release, images)
        return {'directory': str(directory), 'compose': compose, 'images': images,
                'version': release, 'paths': sorted(paths), 'volumes': sorted(volume_names),
                'docker_root': str(docker_root), 'compose_sha256': digest(compose)}

    def check_agents(self, target):
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
            if version(releases[0]) > version(target):
                raise Refused('selected central target is older than a retained registered agent')

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

    def quiesce_for_restore(self, item):
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
        self.r.run(['docker', 'stop', '--time', '60', *ids], timeout=120, operation='quiesce owned recovery containers')
        states = self.r.json(['docker', 'inspect', *ids], timeout=30)
        if any(container['State']['Running'] for container in states):
            raise Refused('owned recovery container did not stop')
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
        if not re.fullmatch(r'/opt/pilot/wazuh-docker/wazuh-docker-4\.14\.[0-9]+/single-node', item['directory']):
            raise Refused('recovery project scope is invalid')
        directory = canonical(item['directory'])
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

    def validate_restore_scope(self, item):
        self.validate_project_scope(item)
        if {entry['path'] for entry in item['archives']} != set(item['paths']):
            raise Refused('recovery archive scope does not match recorded sources')
        for entry in item['archives']:
            if canonical(entry['archive']).parent != canonical(item['backup']):
                raise Refused('recovery archive escaped the retained backup')
        # Validate every archive before stopping any currently running stack.
        for entry in item['archives']:
            if digest(entry['archive']) != entry['sha256']:
                raise Refused('recovery archive checksum mismatch')
        image_archive = item['image_archive']
        if (canonical(image_archive['path']).parent != canonical(item['backup'])
                or digest(image_archive['path']) != image_archive['sha256']):
            raise Refused('old image archive checksum or scope mismatch')

    def recover_pre_switch(self, item):
        self.validate_project_scope(item)
        if digest(item['compose']) != item['compose_sha256']:
            raise Refused('pre-switch Compose configuration changed; refusing to guess recovery')
        self.validate_persisted_graph(item)
        for service, image in item['images'].items():
            self.r.run(['docker', 'image', 'tag', image['id'],
                        'wazuh/' + service.replace('.', '-') + ':' + item['version']], timeout=30)
        self.compose_run(item, 'up', '-d', '--pull', 'never')
        self.wait(item['version'], item['images'])
        self.check_data(item['data'])
        self.canary()
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
        self.check_data(item['data'])
        self.finish(item, item['phase'])

    def rollback(self, item):
        self.validate_restore_scope(item)
        self.write(item, 'recovering')
        self.r.run(['docker', 'image', 'load', '--input', item['image_archive']['path']], timeout=1800,
                   operation='load retained old image artifacts')
        self.quiesce_for_restore(item)
        for entry in item['archives']:
            self.restore(entry['path'], entry['archive'], entry['sha256'])
        if digest(item['compose']) != item['compose_sha256']:
            raise Refused('restored Compose selectors differ from the old durable configuration')
        self.validate_persisted_graph(item)
        # Restore the tags from exact retained image identities, then check
        # the actual recreated container IDs. Do not leave an override file in
        # Compose labels: subsequent discovery must inspect the original config.
        for service, image in item['images'].items():
            self.r.run(['docker', 'image', 'tag', image['id'],
                        'wazuh/' + service.replace('.', '-') + ':' + item['version']], timeout=30)
        self.compose_run(item, 'up', '-d', '--pull', 'never')
        self.wait(item['version'], item['images'])
        self.check_data(item['data'])
        self.canary()
        self.finish(item, 'recovered')

    def execute(self, target, upgrade=False, preview=False, recover=False):
        version(target)
        if preview and recover:
            raise Refused('check mode cannot execute central recovery')
        with self.lock():
            if recover:
                item = self.active()
                if not item:
                    raise Refused('no active central transaction to recover')
                action = CENTRAL_RECOVERY.get(item['phase'])
                if action == 'resume-old':
                    self.recover_pre_switch(item)
                    return {'changed': True, 'recovered': True}
                if action in ('complete-target', 'complete-old'):
                    self.complete_finalized(item)
                    return {'changed': False, 'completed': True}
                if action != 'restore-old':
                    raise Refused('no fully backed-up central transaction to recover')
                self.rollback(item)
                return {'changed': True, 'recovered': True}
            self.idle()
            state = self.discover()
            if not state:
                return {'changed': False, 'fresh': True, 'version': target}
            self.check_agents(target)
            if state['version'] == target:
                return {'changed': False, 'fresh': False, 'version': target,
                        'directory': state['directory']}
            if not upgrade or (state['version'], target) != ('4.14.1', '4.14.9'):
                raise Refused('only explicit central 4.14.1 -> 4.14.9 upgrade is supported')
            image_bytes = sum(image['size'] for image in state['images'].values())
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
            item = self.begin(uuid.uuid4().hex, state)
            try:
                self.retain_images(item)
                self.write(item, 'stopping')
                self.compose_run(item, 'stop', '--timeout', '60')
                for image in item['images'].values():
                    stopped = self.r.json(['docker', 'inspect', image['container']], timeout=30)[0]
                    if stopped['State']['Running']:
                        raise Refused('central component did not quiesce')
                self.assert_volume_consumers(item)
                item['archives'] = []
                for index, path in enumerate(item['paths']):
                    archive = str(Path(item['backup']) / ('state-' + str(index) + '.tar'))
                    item['archives'].append({'path': path, 'archive': archive, 'sha256': self.archive(path, archive)})
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
                self.compose_run(item, 'up', '-d', '--pull', 'never')
                self.write(item, 'validating')
                self.wait(target, target_images)
                self.check_data(item['data'])
                item['canary'] = self.canary()
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


class Agent(Transaction):
    def __init__(self, family, **kwargs):
        super().__init__('agent', **kwargs)
        if family not in ('Debian', 'RedHat'):
            raise Refused('unsupported agent package backend')
        self.family = family

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
            if len(fields) != 3 or fields[0] != 'install ok installed' or fields[2] != 'amd64':
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

    def check(self, manager='', requested='', upgrade=False):
        with self.lock():
            self.idle()
            return agent_plan(self.installed(), manager, requested, upgrade)

    def package_archives(self, installed, target):
        # The sanctioned package framework populates this authenticated cache
        # before reserve/quiesce. Copy exact old and new artifacts privately.
        result = {}
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
                        result[release] = {'path': Path(verified['path']), 'sha256': verified['sha256']}
            except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
                raise Refused('exact staged Debian artifact failed authenticated metadata validation') from exc
            return result
        cache = self.root / 'rpm-stage'
        for path in cache.glob('**/*.rpm'):
            signature = self.r.run(['rpmkeys', '-Kv', path]).stdout
            if not re.search(r'Signature.*: OK', signature):
                raise Refused('staged RPM lacks a verified trusted signature')
            value = self.r.run(['rpm', '-qp', '--qf', '%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}', path]).stdout.splitlines()
            if len(value) == 3 and value[0] == 'wazuh-agent' and value[2] == 'x86_64':
                result[value[1]] = {'path': path, 'sha256': digest(path)}
        for expected in (installed, target):
            if expected and expected not in result:
                raise Refused('exact signed package artifact missing before downtime')
        return result

    def reserve(self, owner, plan):
        with self.lock():
            self.idle()
            if not plan.get('installed') or not plan.get('change'):
                raise Refused('durable agent transactions are only for existing enrolled-agent upgrades')
            if self.installed() != plan['installed']:
                raise Refused('installed package changed since compatibility probe')
            keys = Path('/var/ossec/etc/client.keys')
            if not keys.is_file() or keys.stat().st_size == 0:
                raise Refused('controlled upgrade requires an existing enrolled agent identity')
            packages = self.package_archives(plan['installed'], plan['package'])
            paths = ['/var/ossec'] if plan['installed'] else []
            if Path('/etc/hosts').exists():
                paths.append('/etc/hosts')
            pin = '/etc/apt/preferences.d/pilot-wazuh-agent' if self.family == 'Debian' else '/etc/yum.repos.d/wazuh.repo'
            if Path(pin).is_symlink():
                raise Refused('agent version pin became a symlink')
            if Path(pin).exists():
                paths.append(pin)
            self.capacity(paths)
            active = self.r.run(['systemctl', 'is-active', 'wazuh-agent'], allowed=(0, 3, 4)).returncode == 0
            enabled = self.r.run(['systemctl', 'is-enabled', 'wazuh-agent'], allowed=(0, 1, 3, 4)).stdout.strip()
            if enabled not in ('enabled', 'disabled'):
                raise Refused('unsupported previous agent service enablement state')
            item = self.begin(owner, dict(plan, active=active, enabled=enabled, family=self.family,
                                          paths=paths, absent_pins=[] if Path(pin).exists() else [pin], keys=digest(keys)))
            item['packages'] = {}
            for release, artifact in packages.items():
                if release not in (plan['installed'], plan['package']):
                    continue
                destination = Path(item['backup']) / artifact['path'].name
                shutil.copy2(artifact['path'], destination)
                if digest(destination) != artifact['sha256']:
                    raise Refused('signed package changed between staging and private retention')
                sync_file(destination)
                item['packages'][release] = {'path': str(destination), 'sha256': artifact['sha256']}
            self.write(item, 'staged')
            return {'backup': item['backup'], 'changed': False}

    def cold_backup(self, owner):
        with self.lock():
            item = self.owned(owner, ('staged',))
            self.write(item, 'stopping')
            if item['installed']:
                self.r.run(['systemctl', 'stop', 'wazuh-agent'], timeout=90)
                if self.r.run(['systemctl', 'is-active', 'wazuh-agent'], allowed=(0, 3, 4)).returncode == 0:
                    raise Refused('agent failed to quiesce')
            item['archives'] = []
            for index, path in enumerate(item['paths']):
                archive = str(Path(item['backup']) / ('agent-state-' + str(index) + '.tar'))
                item['archives'].append({'path': path, 'archive': archive, 'sha256': self.archive(path, archive)})
            keys = Path('/var/ossec/etc/client.keys')
            if (digest(keys) if keys.is_file() else None) != item['keys']:
                raise Refused('agent identity changed before cold backup completed')
            self.write(item, 'backed-up')
            return {'changed': False}

    def authorize_install(self, owner):
        with self.lock():
            item = self.owned(owner, ('backed-up',))
            for info in item['packages'].values():
                if digest(info['path']) != info['sha256']:
                    raise Refused('staged package checksum mismatch')
            self.write(item, 'installing')
            return {'changed': False}

    def prepare_recovery(self, owner):
        with self.lock():
            item = self.owned(owner)
            action = AGENT_RECOVERY.get(item['phase'])
            if action == 'resume-old':
                # No package/data restore authority exists before a cold backup.
                self.restore_service(item)
                self.verify_old_state(item)
                self.finish(item, 'recovered-before-install')
                return {'reinstall': False, 'restored': True, 'need_commit': False}
            if action in ('verify-old', 'verify-target'):
                return {'reinstall': False, 'restored': True, 'need_commit': True,
                        'manager_host': item.get('manager_host', '')}
            if action != 'restore-old':
                raise Refused('agent transaction is not recoverable')
            if not item['installed']:
                raise Refused('fresh install failed; explicit cleanup required, journal retained')
            # Validate ALL old state before even a recovery package mutation.
            self.validate_agent_archives(item)
            old = item['packages'].get(item['installed'])
            if item['installed'] and (not old or digest(old['path']) != old['sha256']):
                raise Refused('old agent package is unavailable; journal retained')
            self.r.run(['systemctl', 'stop', 'wazuh-agent'], timeout=90)
            self.write(item, 'recovering')
            if old:
                cache = Path('/var/cache/apt/archives') if self.family == 'Debian' else self.root / 'rpm-stage'
                shutil.copy2(old['path'], cache / Path(old['path']).name)
            return {'reinstall': bool(item['installed']), 'version': item['installed'],
                    'package_path': old['path'] if old else '', 'restored': False,
                    'need_commit': True, 'manager_host': item.get('manager_host', '')}

    def validate_agent_archives(self, item):
        allowed = {'/var/ossec', '/etc/hosts', '/etc/apt/preferences.d/pilot-wazuh-agent', '/etc/yum.repos.d/wazuh.repo'}
        if not set(item['paths']).issubset(allowed) or {entry['path'] for entry in item['archives']} != set(item['paths']):
            raise Refused('agent recovery path scope is invalid')
        disjoint(item['paths'], self.root)
        for entry in item['archives']:
            if canonical(entry['archive']).parent != canonical(item['backup']) or digest(entry['archive']) != entry['sha256']:
                raise Refused('agent recovery archive validation failed before restoration')

    def restore_state(self, owner):
        with self.lock():
            item = self.owned(owner, ('recovering',))
            self.validate_agent_archives(item)
            if item['installed'] and self.installed() != item['installed']:
                raise Refused('old exact package has not been reinstalled')
            for entry in item['archives']:
                self.restore(entry['path'], entry['archive'], entry['sha256'])
            for path in item['absent_pins']:
                Path(path).unlink(missing_ok=True)
            self.restore_service(item)
            self.check_identity(item)
            self.write(item, 'restored')
            return {'changed': True, 'restored': True, 'need_commit': True}

    def finish_recovery(self, owner):
        with self.lock():
            item = self.owned(owner, ('restored', 'committed', 'recovered'))
            already_committed = item['phase'] == 'committed'
            expected = item['package'] if already_committed else item['installed']
            if self.installed() != expected:
                raise Refused('restored package version changed before recovery commit')
            self.check_identity(item)
            runtime = self.runtime()
            if (already_committed and not runtime['active']) or (not already_committed and runtime['active'] != item['active']):
                raise Refused('previous agent availability changed before recovery commit')
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
        runtime = self.runtime()
        if runtime['active'] != item['active']:
            raise Refused('previous native agent availability was not restored')
        self.check_identity(item)

    def check_identity(self, item):
        keys = Path('/var/ossec/etc/client.keys')
        if (digest(keys) if keys.is_file() else None) != item.get('keys'):
            raise Refused('agent enrollment identity changed')

    def commit(self, owner):
        with self.lock():
            item = self.owned(owner, ('installing',))
            if self.installed() != item['package']:
                raise Refused('agent effective package version does not match frozen target')
            native = self.r.run(['/var/ossec/bin/wazuh-control', 'info'], timeout=30).stdout
            if re.findall(r'^WAZUH_VERSION="v?(4\.14\.[0-9]+)"$', native, re.M) != [item['version']]:
                raise Refused('agent runtime Wazuh version probe failed')
            self.check_identity(item)
            if item['active'] and self.r.run(['systemctl', 'is-active', 'wazuh-agent'], allowed=(0, 3, 4)).returncode != 0:
                raise Refused('previously active agent is not active after upgrade')
            self.finish(item, 'committed')
            return {'changed': True, 'backup': item['backup']}

    def activate(self, owner):
        with self.lock():
            item = self.owned(owner, ('installing',))
            self.restore_service(item)
            return {'changed': False}

    def runtime(self):
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

    def verify(self):
        with self.lock():
            self.idle()
            result = self.runtime()
            if not result['active']:
                raise Refused('agent native service is inactive')
            installed = self.installed()
            if self.family == 'Debian':
                pin = Path('/etc/apt/preferences.d/pilot-wazuh-agent').read_text()
                if ('Pin: version ' + installed + '\nPin-Priority: 1000' not in pin
                        or 'Pin: version *\nPin-Priority: -1' not in pin):
                    raise Refused('agent effective version is not protected by the managed APT pin')
            else:
                repo = Path('/etc/yum.repos.d/wazuh.repo').read_text()
                if not re.search(r'^exclude\s*=\s*wazuh-agent\*\s*$', repo, re.M):
                    raise Refused('agent effective version is not protected against unattended DNF changes')
            return dict(result, **{'pass': True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['central', 'central-verify', 'manager-version', 'verify-agent', 'agent-verify', 'agent-runtime', 'agent-check', 'agent-reserve', 'agent-backup',
                                         'agent-install', 'agent-recovery', 'agent-restore', 'agent-recovery-commit', 'agent-commit', 'agent-activate'])
    parser.add_argument('--version', default='')
    parser.add_argument('--legacy', default='')
    parser.add_argument('--manager', default='')
    parser.add_argument('--family', choices=['Debian', 'RedHat'], default='Debian')
    parser.add_argument('--owner', default='')
    parser.add_argument('--agent-id', default='')
    parser.add_argument('--agent-name', default='')
    parser.add_argument('--upgrade', action='store_true')
    parser.add_argument('--preview', action='store_true')
    parser.add_argument('--recover', action='store_true')
    parser.add_argument('--canary', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Wazuh transactions require root')
    try:
        if args.action == 'manager-version':
            value = Central().observe_manager()
        elif args.action == 'verify-agent':
            value = Central().verify_agent(args.agent_id, args.agent_name, args.version)
        elif args.action == 'central-verify':
            value = Central().verify(args.canary)
        elif args.action == 'central':
            value = Central().execute(desired(args.version, args.legacy), args.upgrade, args.preview, args.recover)
        else:
            agent = Agent(args.family)
            if args.action == 'agent-check':
                value = agent.check(args.manager, args.version, args.upgrade)
            elif args.action == 'agent-runtime':
                value = agent.runtime()
            elif args.action == 'agent-verify':
                value = agent.verify()
            elif args.action == 'agent-reserve':
                value = agent.reserve(args.owner, json.load(sys.stdin))
            else:
                method = {'agent-backup': agent.cold_backup, 'agent-install': agent.authorize_install,
                          'agent-recovery': agent.prepare_recovery, 'agent-restore': agent.restore_state,
                          'agent-commit': agent.commit, 'agent-activate': agent.activate,
                          'agent-recovery-commit': agent.finish_recovery}[args.action]
                value = method(args.owner)
        print(json.dumps(value, sort_keys=True))
        return 0
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
