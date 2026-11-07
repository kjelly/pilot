"""Hermetic guard for the Wazuh Python harnesses.

The harnesses import and drive the real coordinator in-process. Its host paths
(reader spool, rsyslog configuration, writer ledger, installed helpers, /etc/hosts,
the Docker/Wazuh trees, ...) are class attributes or literals pointing at the
machine running the tests. A harness that leaves one of them unpatched silently
reads, or as root writes, real host state, so the result depends on whoever ran
it: a PermissionError for an unprivileged developer, a pass on a CI runner where
the path happens to be absent, a mutation of live state as root.

Importing this module installs a tripwire over the filesystem entry points.
Any access to one of HOST_STATE (read, stat, list, create, rename, remove)
raises HostStateTouched, with the offending call site, instead of reaching the
host. Tests must patch the path into a temporary directory first.

Set PILOT_WAZUH_HERMETIC=record to log offenders to the file named by
PILOT_WAZUH_HERMETIC_LOG instead of raising (used only to survey a harness).
Read-only identity probes of system software that the harnesses model on
purpose (/usr/bin/python3, /proc, /dev, interpreters) are not host state.
"""
import builtins
import contextlib
import io
import os
import sys
import traceback

# Absolute prefixes that hold state the coordinator inspects or mutates.
HOST_STATE = (
    '/var/spool/rsyslog', '/var/ossec', '/var/backups/pilot', '/var/lib/docker',
    '/var/lib/rpm', '/usr/lib/sysimage/rpm', '/var/cache/apparmor',
    '/etc/rsyslog.d', '/etc/rsyslog.conf', '/etc/audit', '/etc/hosts',
    '/etc/dnf', '/etc/apparmor', '/etc/apparmor.d', '/etc/apt', '/etc/yum.repos.d',
    '/usr/local/libexec', '/usr/local/sbin/pilot-wazuh-transaction', '/opt/pilot', '/run/pilot',
    '/usr/share/wazuh-indexer', '/usr/share/wazuh-dashboard',
    '/sys/kernel/security',
)
MODE = os.environ.get('PILOT_WAZUH_HERMETIC', 'enforce')
LOG = os.environ.get('PILOT_WAZUH_HERMETIC_LOG', '')


class HostStateTouched(AssertionError):
    """A harness reached real host state instead of a patched temporary path."""


def _text(path):
    try:
        value = os.fspath(path)
    except TypeError:
        return None
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    return value if isinstance(value, str) and value.startswith('/') else None


def offending(path):
    """Return the HOST_STATE root that path falls under, else None."""
    value = _text(path)
    if value is None:
        return None
    value = os.path.normpath(value)
    for root in HOST_STATE:
        if value == root or value.startswith(root + '/'):
            return root
    return None


def _trip(operation, path):
    root = offending(path)
    if root is None:
        return
    site = ''.join(traceback.format_stack(limit=8)[:-2])
    message = 'harness touched real host state %s via %s(%r); patch it into a temporary directory\n%s' % (
        root, operation, os.fspath(path), site)
    if MODE == 'record':
        if LOG:
            with _real_open(LOG, 'a') as stream:
                stream.write(message.splitlines()[0] + '\n' + site)
        return
    raise HostStateTouched(message)


_real_open = builtins.open
_installed = False


def install():
    """Wrap the filesystem entry points once per process."""
    global _installed
    if _installed:
        return
    _installed = True

    def guard(module, name, operation=None, position=0):
        original = getattr(module, name, None)
        if original is None:
            return

        def wrapper(*args, **kwargs):
            path = args[position] if len(args) > position else kwargs.get('path', kwargs.get('src', kwargs.get('file')))
            if path is not None and not isinstance(path, int):
                _trip(operation or name, path)
            return original(*args, **kwargs)
        wrapper.__name__ = name
        wrapper.__wrapped__ = original
        setattr(module, name, wrapper)

    for name in ('open',):
        guard(builtins, name, 'open')
        guard(io, name, 'open')
    for name in ('open', 'stat', 'lstat', 'listdir', 'scandir', 'access', 'readlink', 'mkdir', 'rmdir',
                 'unlink', 'remove', 'chmod', 'chown', 'utime', 'truncate', 'mkfifo', 'statvfs', 'chdir',
                 'getxattr', 'listxattr', 'setxattr', 'removexattr', 'lchown'):
        guard(os, name)
    # rename/replace/link touch both paths. symlink only creates its second: the
    # first is link text (a fake /proc exe names /var/ossec/... without opening it).
    for name, checked in (('rename', (0, 1)), ('replace', (0, 1)), ('link', (0, 1)), ('symlink', (1,))):
        original = getattr(os, name)

        def two_paths(*args, __original=original, __name=name, __checked=checked, **kwargs):
            named = {0: kwargs.get('src'), 1: kwargs.get('dst')}
            for position in __checked:
                value = args[position] if len(args) > position else named[position]
                if value is not None and not isinstance(value, int):
                    _trip(__name, value)
            return __original(*args, **kwargs)
        two_paths.__name__ = name
        two_paths.__wrapped__ = original
        setattr(os, name, two_paths)


@contextlib.contextmanager
def absent(*paths):
    """Declare host paths absent: stat/open/list of them raise FileNotFoundError.

    An explicit native-leaf model for a path the code under test names (for
    example a default location rendered into configuration text) when the test
    has no temporary equivalent. The request never reaches the host.
    """
    prefixes = tuple(os.path.normpath(str(path)) for path in paths)

    def modeled(name):
        previous = getattr(os, name)

        def wrapper(*args, **kwargs):
            target = args[0] if args else kwargs.get('path', kwargs.get('file'))
            value = _text(target) if target is not None and not isinstance(target, int) else None
            if value is not None:
                value = os.path.normpath(value)
                if any(value == prefix or value.startswith(prefix + '/') for prefix in prefixes):
                    raise FileNotFoundError(2, 'modeled absent host path', value)
            return previous(*args, **kwargs)
        wrapper.__wrapped__ = previous
        return previous, wrapper

    names = ('stat', 'lstat', 'open', 'listdir', 'scandir', 'access', 'readlink')
    saved = {}
    try:
        for name in names:
            saved[name], wrapper = modeled(name)
            setattr(os, name, wrapper)
        yield
    finally:
        for name, previous in saved.items():
            setattr(os, name, previous)


def sandbox(module):
    """Redirect the coordinator's host-path constants into a private temp tree.

    Nothing is created: every redirected path starts absent, exactly like a bare
    host, and a test that needs one creates it (or patches its own). Returns the
    tree root. Every host path is read from the module at call time (the
    coordinator resolves its default root from ROOT when it is constructed), so
    patching the constants here is enough; the tripwire fails a test that still
    names real host state.
    """
    import atexit
    import shutil
    import tempfile
    from pathlib import Path
    root = Path(tempfile.mkdtemp(prefix='pilot-wazuh-hermetic-'))
    atexit.register(shutil.rmtree, str(root), True)
    module.ROOT = root / 'var-backups-pilot-wazuh'
    # The version coordinator has no host reader; these constants only exist
    # in a coordinator that gains one, and are redirected here when they do.
    reader = getattr(module, 'Reader', None)
    if reader is not None:
        reader.SPOOL = root / 'var-spool-rsyslog-pilot-wazuh'
        reader.PROFILE = root / 'etc-rsyslog.d/pilot-wazuh/profile.json'
        reader.CONFIG = root / 'etc-rsyslog.d/31-pilot-wazuh.conf'
        reader.CHECKER = root / 'usr-local-libexec/pilot-wazuh-heartbeat'
        reader.RSYSLOG = root / 'etc-rsyslog.conf'
    prestart = getattr(module, 'ReaderPrestart', None)
    if prestart is not None:
        prestart.POLICY = root / 'etc-apparmor.d'
        prestart.CONFIG = root / 'etc-apparmor'
        prestart.FEATURES = root / 'sys-kernel-security-apparmor-features'
        prestart.CACHE = root / 'var-cache-apparmor'
    return root


install()
