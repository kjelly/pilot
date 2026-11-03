#!/usr/bin/env python3
"""Verify exact Debian artifacts against the metadata APT authenticated.

Only called after the shared APT framework's successful authenticated download;
never resolves, downloads, installs, or changes package state itself.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import stat
import os


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=True)
    return result.stdout


def records(text):
    for paragraph in text.strip().split('\n\n'):
        record = {}
        for line in paragraph.splitlines():
            if line and not line[0].isspace() and ': ' in line:
                key, value = line.split(': ', 1)
                record[key] = value
        yield record


def verify(versions, cache=Path('/var/cache/apt/archives')):
    artifacts = []
    architecture = run(['dpkg', '--print-architecture']).strip()
    for package, version in versions.items():
        name, _, requested_arch = package.partition(':')
        arch = requested_arch or architecture
        metadata = [item for item in records(run(['apt-cache', 'show', package + '=' + version]))
                    if item.get('Package') == name and item.get('Version') == version
                    and item.get('Architecture') in (arch, 'all') and item.get('SHA256') and item.get('Filename')]
        matched = None
        for item in metadata:
            path = cache / Path(item['Filename']).name
            if path.is_symlink() or not path.is_file():
                continue
            check = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    check.update(chunk)
            if check.hexdigest() != item['SHA256']:
                continue
            fields = run(['dpkg-deb', '--show', '--showformat=${Package}\n${Version}\n${Architecture}', str(path)]).splitlines()
            if fields != [name, version, item['Architecture']]:
                continue
            matched = {'package': package, 'version': version, 'architecture': item['Architecture'],
                       'path': str(path), 'sha256': check.hexdigest()}
            break
        if not matched:
            raise ValueError('exact staged package failed metadata checksum or identity validation')
        artifacts.append(matched)
    return artifacts


def verify_recovery(filename, versions):
    """Trust an archive only through the coordinator's private recovery manifest.

    The original stage verified APT metadata and the manifest froze its digest.
    Recovery must work after repository metadata changes or disappears.
    """
    path = Path(filename)
    if path.is_symlink() or not path.is_file():
        raise ValueError('unsafe recovery artifact')
    parent = path.parent
    if parent.parent != Path('/var/backups/pilot/wazuh') or not parent.name.startswith('agent-'):
        raise ValueError('artifact outside private agent transaction')
    for directory in (parent, parent.parent):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('unsafe recovery directory')
    manifest = parent / 'manifest.json'
    info = manifest.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('unsafe recovery manifest')
    item = json.loads(manifest.read_text())
    active = json.loads((parent.parent / 'agent-active.json').read_text())
    if active.get('owner') != item.get('owner') or active.get('phase') != 'recovering':
        raise ValueError('recovery owner is no longer active')
    if item['phase'] != 'recovering' or item['family'] != 'Debian' or item['kind'] != 'agent':
        raise ValueError('recovery is not authorized')
    if versions != {'wazuh-agent': item['installed']}:
        raise ValueError('recovery target does not match the saved package')
    expected = item['packages'][item['installed']]
    if expected['path'] != str(path) or str(parent) != item['backup']:
        raise ValueError('recovery archive identity mismatch')
    checksum = hashlib.sha256(path.read_bytes()).hexdigest()
    if checksum != expected['sha256']:
        raise ValueError('recovery artifact checksum mismatch')
    fields = run(['dpkg-deb', '--show', '--showformat=${Package}\n${Version}\n${Architecture}', str(path)]).splitlines()
    if fields != ['wazuh-agent', item['installed'], 'amd64']:
        raise ValueError('recovery artifact package identity mismatch')
    return {'path': str(path), 'version': item['installed'], 'sha256': checksum}


if __name__ == '__main__':
    try:
        if len(sys.argv) == 4 and sys.argv[1] == '--recovery':
            result = verify_recovery(sys.argv[2], json.loads(sys.argv[3]))
        else:
            result = verify(json.loads(sys.argv[1]))
        print(json.dumps(result, sort_keys=True))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        print('exact staged Debian package verification failed', file=sys.stderr)
        sys.exit(1)
