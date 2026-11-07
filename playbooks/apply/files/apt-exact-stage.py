#!/usr/bin/env python3
"""Verify exact Debian artifacts against the metadata APT authenticated.

Only called by the shared APT framework: --cache-preflight before any download
or install (output paths must be plain, owner-private, alias-free), and the
verification of a staged exact package after the framework's successful
authenticated download. Never resolves, downloads, installs, or changes package
state itself.
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


def safe_path(filename, directory=False):
    path = Path(filename)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('non-canonical artifact path')
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('artifact path contains a symlink ancestor')
        if parent != path and parent.exists() and not parent.is_dir():
            raise ValueError('artifact path has a non-directory ancestor')
    info = path.lstat()
    if directory:
        valid = stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022
    else:
        valid = stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    if not valid or info.st_uid != os.geteuid():
        raise ValueError('untrusted artifact type, permissions or ownership')
    return path


def validate_cache(cache=Path('/var/cache/apt/archives')):
    cache = safe_path(cache, directory=True)
    for path in cache.glob('*.deb'):
        safe_path(path)
    return cache


def verify(versions, cache=Path('/var/cache/apt/archives')):
    cache = validate_cache(cache)
    artifacts = []
    architecture = run(['dpkg', '--print-architecture']).strip()
    for package, version in versions.items():
        name, _, requested_arch = package.partition(':')
        arch = requested_arch or architecture
        metadata = [item for item in records(run(['apt-cache', 'show', package + '=' + version]))
                    if item.get('Package') == name and item.get('Version') == version
                    and item.get('Architecture') in (arch, 'all') and item.get('SHA256') and item.get('Filename')]
        if len({item['SHA256'] for item in metadata}) > 1:
            raise ValueError('ambiguous authenticated same-version package payloads')
        matched = None
        for item in metadata:
            path = cache / Path(item['Filename']).name
            if not path.exists():
                continue
            safe_path(path)
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


def verify_wazuh_source(versions, source_file='/etc/apt/sources.list.d/wazuh.list'):
    """Bind the payload to the declared authenticated official index.

    python3-apt is the native APT index/record parser. No preference interpreter
    or origin label supplied by a competing repository is trusted here.
    """
    import apt_pkg
    source = safe_path(source_file)
    if not __import__('re').fullmatch(r'deb \[signed-by=/usr/share/keyrings/wazuh[.]gpg\] https://packages[.]wazuh[.]com/4[.]x/apt/ stable main\n', source.read_text()):
        raise ValueError('unknown declared Wazuh APT source')
    apt_pkg.init_config(); apt_pkg.init_system()
    cache, sources = apt_pkg.Cache(None), apt_pkg.SourceList()
    sources.read_main_list()
    result = {}
    for package, version in versions.items():
        if package != 'wazuh-agent':
            raise ValueError('official Wazuh source check cannot authorize other packages')
        matches = [item for item in cache[package].version_list if item.ver_str == version and item.arch in ('amd64', 'all')]
        payloads, official = set(), []
        for item in matches:
            for location in item.file_list:
                index = sources.find_index(location[0])
                if index is None:
                    continue  # The installed dpkg status record is not a provider.
                record = apt_pkg.PackageRecords(cache)
                if not record.lookup(location):
                    raise ValueError('native APT provider record is unreadable')
                fields = next(records(record.record))
                checksum = fields.get('SHA256')
                if not checksum:
                    raise ValueError('APT provider has no SHA256 payload binding')
                payloads.add(checksum)
                uri = index.archive_uri(record.filename)
                if index.is_trusted and uri.startswith('https://packages.wazuh.com/4.x/apt/'):
                    official.append({'sha256': checksum, 'uri': uri, 'source': source_file})
        if len(payloads) != 1 or not official or {item['sha256'] for item in official} != payloads:
            raise ValueError('missing or ambiguous authenticated official Wazuh payload provider')
        result[version] = official[0]
    return result


if __name__ == '__main__':
    try:
        if len(sys.argv) == 2 and sys.argv[1] == '--cache-preflight':
            result = {'cache': str(validate_cache())}
        else:
            result = verify(json.loads(sys.argv[1]))
            if len(sys.argv) == 4 and sys.argv[2] == '--wazuh-source':
                providers = verify_wazuh_source(json.loads(sys.argv[1]), sys.argv[3])
                if any(item['sha256'] != providers[item['version']]['sha256'] for item in result):
                    raise ValueError('staged artifact differs from official authenticated source')
        print(json.dumps(result, sort_keys=True))
    except (ValueError, KeyError, OSError, ImportError, SystemError, subprocess.SubprocessError):
        print('exact staged Debian package verification failed', file=sys.stderr)
        sys.exit(1)
