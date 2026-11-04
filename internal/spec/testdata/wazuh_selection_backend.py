"""Explicit native backend substitutes for the real Ansible selection graph.

Real production owner locks, policy planning, ordinary snapshot/tar restoration
and real Ansible include/apply/config modules are retained. Package/signature,
service, kernel and manager observations here are modeled, not VM evidence.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument('settings'); p.add_argument('action')
for field in ('owner', 'component', 'mode', 'family', 'manager', 'version', 'legacy', 'agent-id', 'agent-name',
              'operation', 'resource', 'path', 'resources', 'artifact', 'payload', 'version-map', 'packages'):
    p.add_argument('--' + field, default='')
for field in ('confirm-previous-stopped', 'upgrade', 'preview', 'recover', 'canary', 'stage'):
    p.add_argument('--' + field, action='store_true')
a = p.parse_args()
settings = json.loads(Path(a.settings).read_text())
s = importlib.util.spec_from_file_location('production', settings['library']); w = importlib.util.module_from_spec(s); s.loader.exec_module(w)
mounts = w.MountTable; w.MountTable = lambda: mounts('1 0 8:1 / / rw - ext4 /dev/synthetic rw\n')
filename = Path(settings['state']); state = json.loads(filename.read_text())
host = w.HostWriter(settings['root'])
def save(): filename.write_text(json.dumps(state))
def event(action, **fields):
    with open(settings['events'], 'a') as out: out.write(json.dumps(dict(action=action, **fields)) + '\n')
def pkg_version(): return state['installed']
class Native:
    def run(self, argv, **kwargs):
        argv = [str(v) for v in argv]
        if argv[0] in ('tar', 'du'): return w.Runner().run(argv, **kwargs)
        if argv[0] == 'systemctl':
            operation, unit = argv[1:3]; service = state['services'][unit]
            if operation == 'is-active': return subprocess.CompletedProcess(argv, 0 if service['active'] else 3, 'active' if service['active'] else 'inactive', '')
            if operation == 'is-enabled': return subprocess.CompletedProcess(argv, 0 if service['enabled'] == 'enabled' else 1, service['enabled'], '')
            if operation == 'show': return subprocess.CompletedProcess(argv, 0, 'no', '')
            if operation in ('start', 'restart'):
                if operation == 'restart' or not service['active']: service['generation'] += 1
                service['active'] = True
            elif operation == 'stop': service['active'] = False
            elif operation in ('enable', 'disable'): service['enabled'] = 'enabled' if operation == 'enable' else 'disabled'
            else: raise AssertionError(argv)
            event('service', operation=operation, unit=unit); save()
            return subprocess.CompletedProcess(argv, 0, '', '')
        if argv[0] == 'dpkg-query':
            value = ('hold' if state['protected'] else 'install') + ' ok installed\t' + pkg_version() + '\tamd64'
            return subprocess.CompletedProcess(argv, 0, value, '') if pkg_version() else subprocess.CompletedProcess(argv, 1, '', 'dpkg-query: no packages found matching wazuh-agent\n')
        if argv[:2] == ['rpm', '-q']:
            return subprocess.CompletedProcess(argv, 0, pkg_version() + '\tx86_64', '') if pkg_version() else subprocess.CompletedProcess(argv, 1, 'package wazuh-agent is not installed\n', '')
        raise AssertionError(argv)
native = Native()
def own():
    marker = host.active()
    if not marker: raise w.Refused('native substitute has no writer')
    return marker['owner']
def transaction(): return w.Transaction('agent', root=settings['root'], runner=native)
def install(packages, version=''):
    for package in packages:
        if package == 'wazuh-agent':
            if state['repo'] != 'official' or not state['key']: raise w.Refused('official source/provenance missing before package replacement')
            if not version or w.version(version.rsplit('-', 1)[0]) > w.version(settings['manager']): raise w.Refused('exact install escaped manager compatibility')
            state['installed'] = version; state['protected'] = False
            event('install-agent', version=version)
        else:
            event('install-prerequisite', package=package)
    save()
def runtime(): return {'version': pkg_version().rsplit('-', 1)[0], 'active': state['services']['wazuh-agent']['active'], 'id': '001', 'name': 'localhost'}
try:
    action = a.action; event(action)
    if action == 'writer-claim': result = host.claim(a.owner, a.component, a.mode)
    elif action == 'writer-resume': result = host.resume(a.owner, a.component, a.mode, a.confirm_previous_stopped)
    elif action == 'writer-release': result = host.release(a.owner)
    elif action == 'manager-version':
        with host.reader('central'): result = {'version': settings['manager']}
    elif action == 'agent-check':
        result = w.Agent(a.family, root=settings['root'], runner=native).check(a.manager, a.version, a.upgrade, a.owner)
        state['plan'] = result; save()
    elif action in ('agent-config-save', 'agent-config-restore'):
        snapshot = w.ConfigSnapshots(a.owner, a.operation, runner=native, root=settings['root'], paths=settings['paths'])
        if action == 'agent-config-save':
            selected = w.ConfigSnapshots.FILES.get(a.resource) if a.path == settings['paths'].get(a.resource) else a.path
            result = snapshot.save(a.resource, selected)
        else:
            result = snapshot.restore(json.loads(a.resources)); event('ordinary-restored', **result)
    elif action == 'agent-policy-check':
        with host.guard(a.owner, 'agent'):
            if state.get('foreign_policy'): raise w.Refused('foreign ownership at managed native package policy')
            result = {'checked': True, 'prerequisite_plugin_present': True}
    elif action == 'agent-protect':
        with host.guard(a.owner, 'agent'):
            if not pkg_version(): raise w.Refused('cannot protect absent package')
            state['protected'] = True; state['protected_version'] = pkg_version(); save(); event('protected', version=pkg_version())
            result = {'guard_verified': True}
    elif action == 'agent-rpm-fresh':
        with host.guard(a.owner, 'agent'):
            if state['repo'] != 'official' or not state['key']: raise w.Refused('official RPM source/provenance missing')
            event('artifact-provenance', version=state['plan']['package'])
            result = {'package_path': '/private/wazuh-agent_' + state['plan']['package'] + '_amd64.deb', 'dnf_conf_file': '/private/identical.conf'}
    elif action == 'agent-stage':
        with host.guard(a.owner, 'agent'):
            plan = json.load(sys.stdin)
            result = {'ready': True, 'dnf_configs': {v: '/private/identical.conf' for v in (plan['installed'], plan['package'])}}
    elif action == 'agent-reserve':
        plan = json.load(sys.stdin)
        with host.guard(a.owner, 'agent'):
            if set((plan['installed'], plan['package'])) - set(state['staged']): raise w.Refused('exact old/new artifacts were not staged')
            with transaction().component_lock():
                item = transaction().begin(a.owner, dict(plan, previous_protected=state['protected'], original={key: Path(value).read_text() for key, value in settings['paths'].items()}))
                transaction().write(item, 'staged')
            result = {'backup': item['backup']}
    elif action == 'agent-backup':
        with host.guard(a.owner, 'agent'):
            item = transaction().owned(a.owner, ('staged',)); transaction().write(item, 'backed-up'); state['services']['wazuh-agent']['active'] = False; save(); result = {}
    elif action == 'agent-install':
        with host.guard(a.owner, 'agent'):
            item = transaction().owned(a.owner, ('backed-up',)); transaction().write(item, 'installing')
            result = {'package_path': '/private/wazuh-agent_' + item['package'] + '_amd64.deb', 'dnf_conf_file': '/private/identical.conf'}
    elif action in ('agent-apt-plan', 'agent-hook-prepare', 'agent-hook-cleanup'):
        with host.guard(a.owner, 'agent'):
            if not a.stage: transaction().owned(a.owner, ('installing', 'recovering'))
            result = {'authorized': True}
    elif action == 'agent-activate':
        with host.guard(a.owner, 'agent'):
            transaction().owned(a.owner, ('installing',)); state['services']['wazuh-agent']['active'] = True; save(); result = {}
    elif action == 'agent-runtime': result = runtime()
    elif action == 'verify-agent':
        with host.reader('central'):
            if not runtime()['active'] or a.version != runtime()['version']: raise w.Refused('native manager identity/version mismatch')
            result = {'checked': True}
    elif action == 'agent-commit':
        with host.guard(a.owner, 'agent'):
            item = transaction().owned(a.owner, ('installing',))
            if settings.get('fail_commit'): raise w.Refused('controlled commit failure')
            if not state['protected'] or pkg_version() != item['package'] or not runtime()['active']: raise w.Refused('commit lacks installed/protected/active target')
            transaction().finish(item, 'committed'); result = {'committed': True}
    elif action == 'agent-verify':
        with host.reader('agent', a.owner):
            transaction().idle()
            if settings.get('fail_verify') or not state['protected'] or not runtime()['active']: raise w.Refused('controlled stable C10 failure')
            result = {'pass': True}
    elif action == 'agent-recovery':
        with host.guard(a.owner, 'agent'):
            item = transaction().owned(a.owner); transaction().write(item, 'recovering')
            result = {'version': item['installed'], 'reinstall': True, 'restored': False, 'need_commit': True, 'manager_host': 'localhost',
                      'package_path': '/private/wazuh-agent_' + item['installed'] + '_amd64.deb', 'dnf_conf_file': '/private/identical.conf', 'dnf_action': 'downgrade'}
    elif action == 'agent-restore':
        with host.guard(a.owner, 'agent'):
            item = transaction().owned(a.owner, ('recovering',))
            for key, text in item['original'].items(): Path(settings['paths'][key]).write_text(text)
            state['installed'] = item['installed']; state['protected'] = item['previous_protected']; state['services']['wazuh-agent']['active'] = True; save()
            transaction().write(item, 'restored'); result = {'restored': True}
    elif action == 'agent-recovery-commit':
        with host.guard(a.owner, 'agent'):
            item = transaction().owned(a.owner, ('restored',)); transaction().finish(item, 'recovered'); result = {'restored': True}
    elif action == 'artifact-proof':
        versions = json.loads(a.version_map or '{}')
        if versions:
            if state['repo'] != 'official' or not state['key']: raise w.Refused('official APT source/provenance missing')
            for version in versions.values():
                if version not in state['staged']: state['staged'].append(version)
                event('artifact-provenance', version=version)
            save()
        result = []
    elif action == 'native-probe':
        payload = json.loads(a.payload)
        argv = payload.get('argv', []); text = ''
        if 'apt-cache' in argv:
            text = 'Package: wazuh-agent\nVersion: 4.14.1-1\nArchitecture: amd64\nFilename: synthetic.deb' if 'show' in argv else '  Candidate: 1'
        elif 'apt-get' in argv and '--no-download' in argv:
            item = transaction().owned(own(), ('recovering',)); install(['wazuh-agent'], item['installed'])
        elif 'dnf' in argv and '--downloadonly' in argv:
            version = next(v for v in (state['plan']['installed'], state['plan']['package']) if 'wazuh-agent-' + v + '.x86_64' in argv)
            state['staged'].append(version); save(); event('artifact-provenance', version=version)
        elif 'dnf' in argv and ('reinstall' in argv or 'downgrade' in argv):
            item = transaction().owned(own(), ('recovering',)); install(['wazuh-agent'], item['installed'])
        print(text); sys.exit(0)
    elif action == 'package-install':
        packages = json.loads(a.packages)
        if isinstance(packages, str): packages = ['wazuh-agent'] if 'wazuh-agent' in packages else [packages]
        version = state['plan']['package'] if 'wazuh-agent' in packages else ''
        item = transaction().active()
        if item and item['phase'] == 'recovering': version = item['installed']
        install(packages, version); result = {}
    elif action == 'source':
        payload = json.loads(a.payload); kind = payload['kind']
        if kind == 'key': state['key'] = True
        if kind == 'repo': state['repo'] = 'official'; state['key'] = True if a.family == 'RedHat' else state['key']
        save(); event('source-ready', kind=kind); result = {}
    elif action == 'service-module':
        payload = json.loads(a.payload); unit = payload['name']
        if 'enabled' in payload: native.run(['systemctl', 'enable' if payload['enabled'] else 'disable', unit])
        native.run(['systemctl', 'restart' if payload['state'] == 'restarted' else 'start', unit]); result = {}
    elif action in ('fault-before', 'fault-partial'):
        if action == 'fault-partial':
            target = Path(settings['paths'][settings['fault_resource']]); target.write_text(target.read_text() + '\nPARTIAL MUTATION\n')
        raise w.Refused('controlled selected mutator failure')
    elif action == 'metadata': result = {}
    else: raise w.Refused('unknown selection backend action: ' + action)
    print(json.dumps(result))
except w.Refused as error:
    event('refused', reason=str(error)); print(str(error)); sys.exit(1)
