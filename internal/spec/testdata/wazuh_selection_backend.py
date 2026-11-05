"""Explicit native backend substitute for the real Ansible selection graph.

The production coordinator runs for real here: the compatibility planning, the
typed refusals, the Debian dpkg/APT-hold guard (including its foreign-ownership
refusals on a real preference file) and the C10 verification all execute their
actual code against a modeled dpkg/rpm/apt-mark/systemctl. The EL package guard
and the signed RPM stage are modeled (they have their own behavioral tests), as
are repository, package-manager, service and manager observations. This is not
native VM evidence.
"""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import contextlib

settings_file, action, *rest = sys.argv[1:]
settings = json.loads(Path(settings_file).read_text())
spec = importlib.util.spec_from_file_location('production', settings['library'])
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
state_file = Path(settings['state'])
state = json.loads(state_file.read_text())


def save():
    state_file.write_text(json.dumps(state))


def event(name, **fields):
    with open(settings['events'], 'a') as out:
        out.write(json.dumps(dict(action=name, **fields)) + '\n')


class Native:
    """dpkg / rpm / apt-mark / apt-cache / wazuh-control / systemctl model."""
    def run(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        version = state['installed']
        if argv[0] == 'dpkg-query':
            if not version:
                return subprocess.CompletedProcess(argv, 1, '', 'dpkg-query: no packages found matching wazuh-agent\n')
            return subprocess.CompletedProcess(argv, 0, ('hold' if state['protected'] else 'install') + ' ok installed\t' + version + '\tamd64', '')
        if argv[:2] == ['rpm', '-q']:
            if not version:
                return subprocess.CompletedProcess(argv, 1, 'package wazuh-agent is not installed\n', '')
            return subprocess.CompletedProcess(argv, 0, version + '\tx86_64', '')
        if argv[0] == 'dpkg':
            return subprocess.CompletedProcess(argv, 0, 'wazuh-agent\t' + ('hold' if state['protected'] else 'install') + '\n', '')
        if argv[:2] == ['apt-mark', 'showhold']:
            return subprocess.CompletedProcess(argv, 0, 'wazuh-agent\n' if state['protected'] else '', '')
        if argv[:2] == ['apt-mark', 'hold']:
            state['protected'] = True; state['protected_version'] = version; save()
            event('protected', version=version)
            return subprocess.CompletedProcess(argv, 0, '', '')
        if argv[:2] == ['apt-cache', 'policy']:
            return subprocess.CompletedProcess(argv, 0, '  Installed: ' + (version or '(none)') + '\n  Candidate: 4.14.9-1\n', '')
        if argv[0] == '/var/ossec/bin/wazuh-control':
            return subprocess.CompletedProcess(argv, 0, 'WAZUH_VERSION="v' + version.rsplit('-', 1)[0] + '"\n', '')
        if argv[:2] == ['systemctl', 'is-active']:
            active = state['services'][argv[2]]['active']
            return subprocess.CompletedProcess(argv, 0 if active else 3, '', '')
        raise AssertionError(argv)

    def json(self, argv, **kwargs):
        raise AssertionError(argv)


class ModelGuard:
    """EL guard model: the real PackageGuard is covered by its own behavioral tests."""
    def ownership(self):
        if state.get('foreign_policy'):
            raise w.Refused('foreign ownership at the managed native package policy')
        return {'plugin': {'present': True}}

    def protect(self, package):
        self.ownership()
        changed = not (state['protected'] and state['protected_version'] == package)
        state['protected'], state['protected_version'] = True, package; save()
        event('protected', version=package)
        return {'guard': 'dnf-global-versionlock', 'changed': changed}

    def verify(self, package):
        if not state['protected'] or state['protected_version'] != package:
            raise w.Refused('native global Wazuh versionlock differs from installed package')
        return {'guard': 'dnf-global-versionlock'}


def coordinate(arguments):
    """Run the real w.main() over the model; return (rc, stdout)."""
    native = Native()
    sys.argv = ['wazuh-transaction.py', *arguments]
    w.ROOT = Path(settings['root'])
    mounts = w.MountTable
    w.MountTable = lambda text=None: mounts('1 0 8:1 / / rw - ext4 /dev/synthetic rw\n' if text is None else text)
    w.PackageGuard.PREF = settings['preference']
    w.is_root = lambda: True
    w.Runner = lambda: native
    if '--family' in arguments and arguments[arguments.index('--family') + 1] == 'RedHat':
        w.Agent.guard = lambda self: ModelGuard()
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        rc = w.main()
    return rc, captured.getvalue()


def refuse(text):
    print(json.dumps(w.typed_error('refused', text)))
    event('refused', reason=text)
    sys.exit(1)


def main():
    global action
    parser = argparse.ArgumentParser()
    for field in ('family', 'manager', 'version', 'legacy', 'owner', 'packages', 'payload', 'version-map'):
        parser.add_argument('--' + field, default='')
    args, passthrough = parser.parse_known_args(rest)
    event(action)
    if action in ('agent-check', 'agent-policy-check', 'agent-protect', 'agent-verify'):
        if action == 'agent-protect' and state.get('fail_protect'):
            refuse('controlled protection failure')
        if action == 'agent-verify' and settings.get('fail_verify'):
            refuse('controlled stable C10 failure')
        arguments = [action, '--family', args.family]
        if action == 'agent-check':
            arguments += ['--manager', args.manager, '--version', args.version]
        rc, text = coordinate(arguments)
        value = json.loads(text)
        if rc:
            event('refused', reason=value['error'])
        elif action == 'agent-check':
            state['plan'] = value; save()
        print(text, end='')
        sys.exit(rc)
    if action == 'manager-version':
        if settings.get('manager_error'):
            refuse('operation failed: docker rc=1')
        print(json.dumps({'version': settings['manager']}))
    elif action == 'agent-rpm-fresh':
        if state['repo'] != 'official' or not state['key']:
            refuse('official RPM source/provenance missing')
        plan = json.loads(sys.stdin.read())
        event('artifact-provenance', version=plan['package'])
        print(json.dumps({'package_path': '/private/wazuh-agent-' + plan['package'] + '.x86_64.rpm', 'dnf_conf_file': '/private/identical.conf'}))
    elif action == 'install-coordinator':
        print('{}')
    elif action == 'artifact-proof':
        versions = json.loads(args.version_map or '{}')
        if versions:
            if state['repo'] != 'official' or not state['key']:
                refuse('official APT source/provenance missing')
            for version in versions.values():
                event('artifact-provenance', version=version)
        print('[]')
    elif action == 'package-install':
        names = json.loads(args.packages)
        if isinstance(names, str):
            names = [names]
        for name in names:
            if name.startswith('wazuh-agent') or 'wazuh-agent' in name:
                version = name.split('=', 1)[1] if '=' in name else name.rsplit('wazuh-agent-', 1)[1].removesuffix('.x86_64.rpm')
                if state['repo'] != 'official' or not state['key']:
                    refuse('official source/provenance missing before package replacement')
                if state['installed']:
                    refuse('the exact install must never replace an installed agent')
                if w.version(version.rsplit('-', 1)[0]) > w.version(settings['manager'] or '4.14.9'):
                    refuse('exact install escaped manager compatibility')
                state['installed'], state['protected'] = version, False
                if settings.get('drift_preference'):
                    # A foreign party claims the managed preference path after the first ownership check.
                    Path(settings['preference']).write_text('Package: *\nPin: release a=foreign\nPin-Priority: 900\n')
                    Path(settings['preference']).chmod(0o644)
                state['services']['wazuh-agent']['active'] = settings.get('policy_rc_d_active', False) or state['services']['wazuh-agent']['active']
                event('install-agent', version=version)
            else:
                event('install-prerequisite', package=name)
        save()
        print('{}')
    elif action == 'source':
        payload = json.loads(args.payload); kind = payload['kind']
        if kind == 'key':
            state['key'] = True
        if kind == 'repo':
            state['repo'] = 'official'; state['key'] = True if args.family == 'RedHat' else state['key']
        save(); event('source-ready', kind=kind)
        print('{}')
    elif action == 'service-module':
        payload = json.loads(args.payload); unit = payload['name']
        service = state['services'][unit]
        if payload.get('state') == 'restarted' or not service['active']:
            service['generation'] += 1
        service['active'] = True; service['enabled'] = 'enabled'
        save(); event('service', unit=unit, state=payload.get('state'))
        print('{}')
    elif action in ('fault-before', 'fault-partial'):
        if action == 'fault-partial':
            target = Path(settings['paths'][settings['fault_resource']]); target.write_text(target.read_text() + '\nPARTIAL MUTATION\n')
        refuse('controlled selected mutator failure')
    elif action == 'metadata':
        print('{}')
    elif action == 'native-probe':
        payload = json.loads(args.payload)
        argv = payload.get('argv', []); text = ''
        if 'apt-cache' in argv:
            text = 'Package: wazuh-agent\nVersion: 4.14.1-1\nArchitecture: amd64\nFilename: synthetic.deb' if 'show' in argv else '  Candidate: 1'
        elif 'dnf' in argv and '--downloadonly' in argv:
            event('artifact-provenance', version='downloaded')
        print(text)
    else:
        refuse('unknown selection backend action: ' + action)


main()
