"""Wazuh release compatibility and native package protection (Issue #244, part A).

Read-only observations of a central stack's and an agent's effective Wazuh
release, one deterministic compatibility plan, and the native package guard of
an agent (APT hold plus preference, or an owned DNF versionlock rule), including
the signed exact fresh RPM install path. The invariant this version enforces:

  for every agent with an observed manager M, installed agent V <= M before and
  after apply. A fresh install is exactly the requested release, or M. A
  compatible installed agent is kept as-is. Any release change of an agent or of
  an existing central stack is a typed refusal that comes before the first
  mutation.

There is no upgrade, downgrade, backup, journal or host-wide writer here:
the only mutating actions (agent-protect, agent-rpm-fresh) are idempotent and
re-derivable from native state, and take one per-component flock. Debian package
installation stays in apt-package-install.yml; this module never runs apt/dpkg
install, dnf install (except the stage-only --downloadonly of the exact RPM), or
touches a service.
"""
import argparse
import configparser
import contextlib
import fcntl
import fnmatch
import hashlib
import io
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
from urllib.parse import urlsplit
ROOT = Path('/var/backups/pilot/wazuh')


SERVICES = ('wazuh.manager', 'wazuh.indexer', 'wazuh.dashboard')


VERSION = re.compile(r'^4\.14\.(0|[1-9][0-9]*)$')


class Refused(RuntimeError):
    pass


def typed_error(kind, text):
    """Bounded, secret-free failure field for Ansible output.

    A typed failure is what the operator sees when a coordinator task fails, so
    it must stay readable without no_log. kind is a closed set. text is only
    ever a fixed Refused literal or the generic native message (a regression
    test scans every Refused() call site for non-literal arguments); it is still
    reduced to printable ASCII without quote, backslash or brace, so it needs no
    JSON escaping, cannot carry Jinja markers into Ansible's templating, and can
    be extracted by a strict pattern. Tool stdout/stderr/argv never reach it.
    """
    assert kind in ('refused', 'native')
    return {'error': re.sub(r'[^ !#-\[\]-z|~]', '?', str(text))[:300], 'error_kind': kind}


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


def agent_plan(installed, manager, requested=''):
    """One agent's compatibility plan against the observed manager release.

    installed is the native package version ('' when absent), manager the
    observed manager release ('' when no manager is observable) and requested the
    operator's wazuh_version. A compatible installed agent is kept; every
    release change is refused here, before any caller can mutate.
    """
    if manager:
        version(manager)
    if requested:
        version(requested)
    if installed:
        # Only known Wazuh packaging is accepted; epoch/build surprises fail.
        match = re.fullmatch(r'(4\.14\.(?:0|[1-9][0-9]*))-([1-9][0-9]*)', installed)
        if not match:
            raise Refused('unknown installed Wazuh agent package version')
        current = match[1]
        if manager and version(current) > version(manager):
            raise Refused('installed Wazuh agent is newer than the observed manager')
        if requested and version(requested) > version(current):
            raise Refused('Wazuh agent upgrade is not supported by this version')
        if requested and version(requested) < version(current):
            raise Refused('Wazuh agent downgrade refused')
        return {'installed': installed, 'version': current, 'package': installed,
                'install': False, 'manager': manager}
    target = requested or manager or '4.14.1'
    version(target)
    if manager and version(target) > version(manager):
        raise Refused('requested Wazuh agent is newer than the observed manager')
    return {'installed': '', 'version': target, 'package': target + '-1',
            'install': True, 'manager': manager}


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
    """Remove a file and make the removal durable, including when already absent."""
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
            # root; they are kept only so a descendant mount is still seen.
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

    def backup(self, root):
        """The private store must be a plain, writable, subtree-free filesystem."""
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
    if kind == 'file' and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise Refused('transaction source must be a regular single-link file')
    return path


def private_file(filename, parent):
    path = path_shape(filename, 'file')
    parent = path_shape(parent, 'directory')
    info = parent.stat()
    if path.parent != parent or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused('retained artifact escaped its exact private directory')
    if path.stat().st_uid != os.geteuid():
        raise Refused('retained artifact has a different owner')
    return path


def atomic_text(path, text, private=False):
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
        if original and not private:
            os.utime(tmp, ns=(written.st_atime_ns, written.st_mtime_ns), follow_symlinks=False)
        sync_file(tmp)
        os.replace(tmp, path)
        sync_directory(path.parent)
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
 base.fill_sack(load_system_repo=True,load_available_repos=True)
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

    def __init__(self, family, runner, root=None):
        self.family, self.r, self.root = family, runner, Path(ROOT if root is None else root)

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
                'mode': stat.S_IMODE(info.st_mode)}

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

    def protect(self, package):
        """Establish the native guard for the installed package; idempotent."""
        self.nevra(package)
        self.ownership()
        if self.family == 'Debian':
            changed = not self.apt_state()['held']
            if changed:
                self.r.run(['apt-mark', 'hold', 'wazuh-agent'], timeout=60, operation='hold only Wazuh agent')
        else:
            context = self.dnf_context()
            content = self.lock_text(context['locks'].get('text', ''), package)
            changed = content != context['locks'].get('text', '')
            if changed:
                atomic_text(self.LOCKS, content)
        return dict(self.verify(package), changed=changed)

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

    def overlay(self, owner, package):
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
                                'cacheonly': False})
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
                raise Refused('retained private RPM DB SELinux context drift')
        children = list(database.iterdir())
        allowed = {'.rpm.lock', 'rpmdb.sqlite', 'rpmdb.sqlite-shm', 'rpmdb.sqlite-wal'}
        if not {'.rpm.lock', 'rpmdb.sqlite'}.issubset({path.name for path in children}):
            raise Refused('private RPM DB is missing native SQLite/lock artifacts')
        for path in children:
            private_file(path, database)
            if path.name not in allowed or path.stat().st_mode & 0o022:
                raise Refused('unsupported private RPM database artifact shape or permissions')
            if native_type is not None and self.rpm_context(path) != context:
                raise Refused('retained private RPM DB child SELinux context drift')
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


class Transaction:
    """Per-component mutual exclusion for the few mutating coordinator actions.

    Reads take no lock and create nothing, so a check-mode preview never writes.
    """
    def __init__(self, kind, runner=None, root=None):
        self.r = runner or Runner()
        self.kind = kind
        # Resolved per call, not at definition time, so ROOT is one overridable seam.
        self.root = Path(ROOT if root is None else root)

    @contextlib.contextmanager
    def lock(self):
        MountTable().backup(path_shape(self.root, 'directory', missing=True))
        private_dir(self.root)
        with bounded_flock(self.root / (self.kind + '.lock')):
            yield


class Central(Transaction):
    def __init__(self, managed_root=Path('/opt/pilot/wazuh-docker'), **kwargs):
        super().__init__('central', **kwargs)
        # Internal filesystem seam for discovery tests; the CLI never exposes
        # this setting and always enforces the production pilot-owned root.
        self.managed_root = Path(managed_root)

    def project_directory(self, directory):
        directory = canonical(directory)
        try:
            relative = directory.relative_to(canonical(self.managed_root))
        except ValueError as exc:
            raise Refused('active Compose directory is outside the pilot-owned single-node layout') from exc
        if not re.fullmatch(r'wazuh-docker-4\.14\.[0-9]+/single-node', str(relative)):
            raise Refused('active Compose directory is outside the pilot-owned single-node layout')
        return directory

    @staticmethod
    def image_provenance(image, repository):
        """Only an official immutable repository digest proves a release."""
        valid = re.compile(re.escape(repository) + r'@sha256:[a-f0-9]{64}$')
        identities = [value for value in image.get('RepoDigests') or [] if valid.fullmatch(value)]
        if not identities:
            raise Refused('central image lacks official immutable release provenance')
        return identities

    def observe_manager(self):
        text = self.r.run(['docker', 'exec', 'single-node-wazuh.manager-1',
                           '/var/ossec/bin/wazuh-control', 'info'], timeout=30, operation='effective manager version').stdout
        values = re.findall(r'^WAZUH_VERSION="v?(4\.14\.[0-9]+)"$', text, re.M)
        if len(values) != 1:
            raise Refused('unknown effective manager version')
        version(values[0])
        return {'version': values[0]}

    def verify(self):
        state = self.discover()
        if not state:
            raise Refused('central stack is absent')
        self.check_agents(state['version'])
        return {'pass': True, 'version': state['version']}

    def gate(self, target):
        """An existing stack must already run the requested release; none is changed."""
        version(target)
        state = self.discover()
        if not state:
            return {'changed': False, 'fresh': True, 'version': target}
        if state['version'] != target:
            raise Refused('central release change is not supported by this version')
        expected = canonical(self.managed_root / ('wazuh-docker-' + target) / 'single-node')
        if Path(state['directory']) != expected:
            raise Refused('active Compose directory does not match the requested release')
        self.check_agents(state['version'])
        return {'changed': False, 'fresh': False, 'version': target, 'directory': state['directory']}

    def discover(self):
        self.r.run(['docker', 'info'], timeout=30)
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
        self.project_directory(directory)
        images = {}
        for service, container in found.items():
            image = self.r.json(['docker', 'image', 'inspect', container['Image']], timeout=30)[0]
            repo = 'wazuh/' + service.replace('.', '-')
            expected = re.fullmatch(re.escape(repo) + r':(4\.14\.[0-9]+)', container['Config']['Image'])
            if not expected:
                raise Refused('central image lacks official immutable release provenance')
            images[service] = {'id': image['Id'], 'version': expected[1],
                               'digests': self.image_provenance(image, repo), 'container': container['Id']}
        releases = {value['version'] for value in images.values()}
        if len(releases) != 1:
            raise Refused('central components have mixed Wazuh releases')
        release = releases.pop()
        self.health(release, images)
        return {'directory': str(directory), 'compose': compose, 'images': images, 'version': release}

    def check_agents(self, target):
        """Every registered agent must be at or below the manager release."""
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
                raise Refused('a registered agent is newer than the central release')
        return registry

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
        # Native 4.14.1 on a disposable manager returns rc1 whenever
        # intentionally disabled optional daemons are stopped. Do not turn that
        # rc into either universal failure or universal PASS.
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


class Agent(Transaction):
    def __init__(self, family, **kwargs):
        super().__init__('agent', **kwargs)
        if family not in ('Debian', 'RedHat'):
            raise Refused('unsupported agent package backend')
        self.family = family

    def guard(self):
        return PackageGuard(self.family, self.r, self.root)

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

    def check(self, manager='', requested=''):
        return agent_plan(self.installed(), manager, requested)

    def policy_ownership(self):
        # Read-only: refuses foreign ownership before any managed write.
        state = self.guard().ownership()
        return {'checked': True, 'prerequisite_plugin_present': state.get('plugin', {}).get('present')}

    def protect_package(self):
        with self.lock():
            package = self.installed()
            if not package:
                raise Refused('cannot protect an absent Wazuh agent package')
            return self.guard().protect(package)

    def fresh_rpm(self, owner, plan):
        # The owner names private directories; it is this run's random token.
        if not isinstance(owner, str) or not re.fullmatch('[a-f0-9]{32}', owner):
            raise Refused('invalid private RPM stage owner')
        with self.lock():
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

    def _runtime(self):
        package = self.installed()
        if not package:
            raise Refused('agent package is not installed')
        text = self.r.run(['/var/ossec/bin/wazuh-control', 'info'], timeout=30).stdout
        release = package.rsplit('-', 1)[0]
        if re.findall(r'^WAZUH_VERSION="v?(4\.14\.[0-9]+)"$', text, re.M) != [release]:
            raise Refused('installed agent and native binary release differ')
        return {'version': release, 'package': package,
                'active': self.r.run(['systemctl', 'is-active', 'wazuh-agent'], allowed=(0, 3, 4)).returncode == 0}

    def verify(self):
        result = self._runtime()
        if not result['active']:
            raise Refused('agent native service is inactive')
        guard = self.guard().verify(result['package'])
        return {'pass': True, 'version': result['version'], 'guard': guard['guard']}


def is_root():
    return os.geteuid() == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['manager-version', 'central', 'central-verify', 'agent-check',
                                           'agent-policy-check', 'agent-protect', 'agent-rpm-fresh', 'agent-verify'])
    parser.add_argument('--version', default='')
    parser.add_argument('--legacy', default='')
    parser.add_argument('--manager', default='')
    parser.add_argument('--family', choices=['Debian', 'RedHat'], default='Debian')
    parser.add_argument('--owner', default='')
    args = parser.parse_args()
    if not is_root():
        parser.error('Wazuh version checks require root')
    try:
        if args.action == 'manager-version':
            value = Central().observe_manager()
        elif args.action == 'central':
            value = Central().gate(desired(args.version, args.legacy))
        elif args.action == 'central-verify':
            value = Central().verify()
        else:
            agent = Agent(args.family)
            if args.action == 'agent-check':
                value = agent.check(args.manager, args.version)
            elif args.action == 'agent-policy-check':
                value = agent.policy_ownership()
            elif args.action == 'agent-protect':
                value = agent.protect_package()
            elif args.action == 'agent-rpm-fresh':
                value = agent.fresh_rpm(args.owner, json.load(sys.stdin))
            else:
                value = agent.verify()
        print(json.dumps(value, sort_keys=True))
        return 0
    except Refused as exc:
        print(json.dumps(typed_error('refused', exc)))
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Native JSON/config/tool failures may carry private values. Do not
        # expose tool stderr, argv, parsed documents or exception repr here.
        print(json.dumps(typed_error('native', 'native version probe or state operation failed')))
        return 1


if __name__ == '__main__':
    sys.exit(main())
