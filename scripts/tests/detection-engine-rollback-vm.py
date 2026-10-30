#!/usr/bin/env python3
"""Fault-inject production Ansible tasks through one disposable pilot vm-target.

Never accepts an arbitrary inventory or localhost transport. CI creates and tears
 down the target. Uses the real compiled detection engine's SQLite commands and
real systemd; the unit's sleep process isolates service-state checks from HTTP
providers. This lane tests the upgrade/rollback slice, not the detection daemon.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import yaml

ROOT = Path(__file__).resolve().parents[2]
BASE = '/var/lib/pilot-rollback-test'
UNIT = '/etc/systemd/system/pilot-detection-engine.service'
UNIT_TEXT = '[Unit]\nDescription=Disposable rollback test\n[Service]\nExecStart=/usr/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n'


def task(name, module, args, **kw):
    return {'name': name, module: args, 'tags': ['always'], **kw}


def command(name, argv, **kw):
    return task(name, 'ansible.builtin.command', {'argv': argv}, **kw)


def put(path, content, **kw):
    return task('Fixture write ' + path, 'ansible.builtin.copy', {'dest': path, 'content': content, **kw})


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pilot', required=True, type=Path)
    ap.add_argument('--name', required=True)
    ap.add_argument('--old-binary', required=True, type=Path)
    ap.add_argument('--new-binary', required=True, type=Path)
    ap.add_argument('--evidence', required=True, type=Path)
    args = ap.parse_args()
    if not re.fullmatch(r'de-rollback-[0-9]+', args.name):
        ap.error('only the dedicated de-rollback-<run-id> disposable target is accepted')
    args.pilot = args.pilot.resolve()
    args.evidence.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'playbooks/apply/detection-engine-apply.yml'
    plays = yaml.safe_load(source.read_text())
    prod = plays[0]
    probes = [t for t in prod['tasks'] if t.get('name', '').startswith('Step 0')]
    install = next(t for t in prod['tasks'] if t.get('name') == 'Detection Engine install + systemd service')
    steps = [t for t in install['block'] if t.get('name', '').startswith(('Step 3', 'Step 4', 'Step 5', 'Step 6:', 'Step 7:'))]
    evidence = {'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                'tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
                'playbook_sha256': sha(source), 'old_binary_sha256': sha(args.old_binary),
                'new_binary_sha256': sha(args.new_binary), 'cases': []}
    assert evidence['old_binary_sha256'] != evidence['new_binary_sha256']

    def run(label, tasks, variables, check=False):
        # Read the authoritative inventory before EVERY invocation, never hand-edit it.
        inv = subprocess.check_output([str(args.pilot), 'vm-target', 'show-inventory', '--name', args.name], text=True)
        inventory = yaml.safe_load(inv)
        hosts = inventory['all']['hosts']
        assert list(hosts) == [args.name] and hosts[args.name]['ansible_connection'] == 'ssh'
        (args.evidence / 'inventory.yml').write_text(inv)
        play = [{'name': label, 'hosts': args.name, 'gather_facts': False, 'become': True,
                 'vars': variables, 'tasks': tasks}]
        pb = args.evidence / (label + '.yml')
        pb.write_text(yaml.safe_dump(play, sort_keys=False))
        cmd = [str(args.pilot), 'vm-target', 'run', '--name', args.name, '--skip-lint', str(pb.resolve())]
        if check:
            cmd += ['--check', '--diff']
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=360)
        (args.evidence / (label + '.log')).write_text(proc.stdout)
        print(label, 'rc=', proc.returncode, flush=True)
        if proc.returncode:
            print(proc.stdout[-18000:], flush=True)
            raise RuntimeError(label)
        return proc.stdout

    variables = {'detection_engine_bin_dest': BASE + '/engine', 'detection_engine_db_path': BASE + '/state.db',
                 'detection_engine_backup_dir': BASE + '/backups', 'detection_engine_config_dir': BASE + '/etc',
                 'detection_engine_unit_path': UNIT, 'detection_engine_feature_profile_dest': BASE + '/etc/profile.yaml',
                 'detection_engine_user': 'root', 'detection_engine_artifact_abs_path': str(args.new_binary.resolve()),
                 'detection_engine_artifact_sha256': evidence['new_binary_sha256'],
                 'detection_engine_rollback_files': prod['vars']['detection_engine_rollback_files']}
    # This harness's private data directory belongs to root. Production uses pilot-detect;
    # no task owner/group or become setting is removed from production task YAML.
    sqlite = 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute("CREATE TABLE marker(value TEXT)"); c.execute("INSERT INTO marker VALUES (?)", (sys.argv[2],)); c.commit(); c.close()'
    mutate = 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute("CREATE TABLE IF NOT EXISTS marker(value TEXT)"); c.execute("DELETE FROM marker"); c.execute("INSERT INTO marker VALUES (?)", ("MIGRATED",)); c.commit(); c.close()'
    cases = ['normal-upgrade', 'first-install', 'after-step6', 'no-db-stale', 'db-backup-fails',
             'binary-backup-fails', 'db-backup-corrupt', 'binary-backup-corrupt',
             'missing-binary-snapshot', 'changed-db-snapshot', 'stop-fails', 'tag-skips-binary']
    for case in cases:
        fresh = case == 'first-install'
        nodb = fresh or case == 'no-db-stale'
        v = dict(variables)
        setup = [task('Fixture stop any prior unit', 'ansible.builtin.systemd', {'name': 'pilot-detection-engine.service', 'state': 'stopped', 'enabled': False}, failed_when=False),
                 task('Fixture remove private scenario tree', 'ansible.builtin.file', {'path': BASE, 'state': 'absent'}),
                 task('Fixture remove prior unit', 'ansible.builtin.file', {'path': UNIT, 'state': 'absent'}),
                 task('Fixture reload systemd', 'ansible.builtin.systemd', {'daemon_reload': True}),
                 task('Fixture private directories', 'ansible.builtin.file', {'path': '{{ item }}', 'state': 'directory', 'mode': '0700'}, loop=[BASE, BASE + '/etc', BASE + '/backups']),
                 task('Fixture copy real old executable', 'ansible.builtin.copy', {'src': str(args.old_binary.resolve()), 'dest': BASE + '/engine', 'mode': '0755'}, when=not fresh),
                 put(BASE + '/etc/config.yaml', 'ORIGINAL-CONFIG\n', mode='0640'),
                 put(BASE + '/etc/profile.yaml', 'ORIGINAL-PROFILE\n'),
                 put(BASE + '/etc/provider.env', 'TEST_ONLY_SECRET=rollback-fixture\n', mode='0600'),
                 put(BASE + '/backups/pilot-detection-engine.prev', 'STALE-BIN'),
                 put(BASE + '/backups/pre-upgrade.db', 'STALE-DB')]
        if not fresh:
            setup += [put(UNIT, UNIT_TEXT, mode='0644'), task('Fixture original running enabled service', 'ansible.builtin.systemd', {'name': 'pilot-detection-engine.service', 'state': 'started', 'enabled': True, 'daemon_reload': True})]
        if not nodb:
            setup += [command('Fixture real SQLite database', ['python3', '-c', sqlite, BASE + '/state.db', 'ORIGINAL'])]
        run(case + '-setup', setup, v)
        if fresh:
            run('fresh-check-mode', probes + [{'name': 'Upgrade slice', 'block': steps, 'rescue': install['rescue']}], v, check=True)
        selected = copy.deepcopy(steps)
        def insert_after(prefix, injection):
            idx = next(i for i, t in enumerate(selected) if t['name'].startswith(prefix))
            selected[idx + 1:idx + 1] = injection
        if case in ('db-backup-fails', 'binary-backup-fails'):
            name = '/pre-upgrade.db' if case == 'db-backup-fails' else '/pilot-detection-engine.prev'
            # A nonempty directory at the real module destination forces a real IO failure.
            insert_after('Step 3e:', [task('Inject unwritable snapshot destination', 'ansible.builtin.file', {'path': '{{ detection_engine_backup_run.path }}' + name, 'state': 'directory'}),
                                     task('Inject nested destination conflict', 'ansible.builtin.file', {'path': '{{ detection_engine_backup_run.path }}' + name + '/engine', 'state': 'directory'}), put('{{ detection_engine_backup_run.path }}' + name + '/engine/blocker', 'occupied')])
        if case in ('db-backup-corrupt', 'binary-backup-corrupt'):
            prefix = 'Step 4:' if case.startswith('db-') else 'Step 5:'
            path = '/pre-upgrade.db' if case.startswith('db-') else '/pilot-detection-engine.prev'
            insert_after(prefix, [put('{{ detection_engine_backup_run.path }}' + path, 'CORRUPT-SNAPSHOT')])
        if case == 'missing-binary-snapshot':
            insert_after('Step 6:', [task('Inject missing binary snapshot', 'ansible.builtin.file', {'path': '{{ detection_engine_backup_run.path }}/pilot-detection-engine.prev', 'state': 'absent'})])
        if case == 'changed-db-snapshot':
            insert_after('Step 6:', [put('{{ detection_engine_backup_run.path }}/pre-upgrade.db', 'CORRUPT-AFTER-COPY')])
        failure = case not in ('normal-upgrade', 'first-install')
        post = [command('Simulate migration against actual SQLite', ['python3', '-c', mutate, BASE + '/state.db']),
                put(BASE + '/etc/config.yaml', 'NEW-CONFIG\n'), put(BASE + '/etc/provider.env', 'TEST_ONLY_SECRET=new\n', mode='0600')]
        if case == 'tag-skips-binary':
            # Two plays in one process share facts: prove the reset removes stale authority.
            selected = []
        if failure:
            post += [task('Inject post-Step6 failure', 'ansible.builtin.fail', {'msg': 'EXPECTED_FAULT'})]
        else:
            post += [put(UNIT, UNIT_TEXT, mode='0644'), task('Fixture successful installation service', 'ansible.builtin.systemd', {'name': 'pilot-detection-engine.service', 'state': 'started', 'enabled': True, 'daemon_reload': True})]
        rescue = copy.deepcopy(install['rescue'])
        if case == 'stop-fails':
            # Ansible failure injection at the actual stop boundary; leave the unit active.
            rescue[0] = task('Injected stop failure', 'ansible.builtin.fail', {'msg': 'EXPECTED_STOP_FAILURE'}, register='detection_engine_rescue_stop', ignore_errors=True)
        if failure:
            transaction = [{'name': 'Execute production upgrade and rescue', 'block': selected + post, 'rescue': rescue}]
            # Catch only the deliberate final fail; assertions below independently check state.
            transaction = probes + [{'block': transaction, 'rescue': [task('Require original failure to remain observable', 'ansible.builtin.assert', {'that': ["ansible_failed_task.name == 'ROLLBACK — surface the original failure (evidence preserved, spec §26)'"]})]}]
        else:
            transaction = probes + [{'block': selected + post, 'rescue': rescue}]
        if case == 'tag-skips-binary':
            transaction.insert(0, task('Seed facts from a previous play', 'ansible.builtin.set_fact', {'detection_engine_rollback': {'install_started': True, 'binary_ready': True, 'db_ready': True, 'path': BASE + '/backups'}}))
        run(case + '-apply', transaction, v)
        safe_failure = case in ('missing-binary-snapshot', 'changed-db-snapshot', 'stop-fails')
        pre_failed = case in ('db-backup-fails', 'binary-backup-fails', 'db-backup-corrupt', 'binary-backup-corrupt')
        expected_hash = evidence['old_binary_sha256'] if pre_failed or (failure and not safe_failure) else evidence['new_binary_sha256']
        expected_marker = 'ORIGINAL' if pre_failed or (failure and not safe_failure and not nodb and case != 'tag-skips-binary') else 'MIGRATED'
        verify_script = '''import hashlib,json,pathlib,sqlite3,subprocess,sys
b=pathlib.Path(sys.argv[1]); c=sqlite3.connect(b/'state.db'); integrity=c.execute('PRAGMA integrity_check').fetchall(); marker=c.execute('SELECT value FROM marker').fetchone()[0]; c.close()
status=subprocess.run(['systemctl','is-active','pilot-detection-engine.service'],capture_output=True,text=True).stdout.strip()
enabled=subprocess.run(['systemctl','is-enabled','pilot-detection-engine.service'],capture_output=True,text=True).stdout.strip()
result={'binary_sha256':hashlib.sha256((b/'engine').read_bytes()).hexdigest(),'integrity':integrity,'marker':marker,'active':status,'enabled':enabled,'config':(b/'etc/config.yaml').read_text(),'provider':(b/'etc/provider.env').read_text(),'config_mode':oct((b/'etc/config.yaml').stat().st_mode & 0o777)}
assert result['binary_sha256']==sys.argv[2],result
assert integrity==[('ok',)] and marker==sys.argv[3],result
assert status==sys.argv[4] and enabled==sys.argv[5],result
assert result['config']==sys.argv[6] and result['provider']==sys.argv[7],result
assert (b/'backups/pre-upgrade.db').read_text()=='STALE-DB' and (b/'backups/pilot-detection-engine.prev').read_text()=='STALE-BIN'
print(json.dumps({k:v for k,v in result.items() if k!='provider'}))
'''
        stopped = safe_failure and case != 'stop-fails'
        config = 'ORIGINAL-CONFIG\n' if failure else 'NEW-CONFIG\n'
        provider = 'TEST_ONLY_SECRET=rollback-fixture\n' if failure else 'TEST_ONLY_SECRET=new\n'
        run(case + '-verify', [command('Assert checksum SQLite service and original configuration', ['python3', '-c', verify_script, BASE, expected_hash, expected_marker, 'inactive' if stopped else 'active', 'disabled' if stopped else 'enabled', config, provider])], v)
        if not failure:
            # Genuine production backup/copy slice, no fixture migrations in the replay.
            log = run(case + '-second-apply', probes + [{'block': steps, 'rescue': install['rescue']}], v)
            assert re.search(r'changed=0\b', log), log[-8000:]
        evidence['cases'].append({'name': case, 'verdict': 'PASS'})
        (args.evidence / 'results.json').write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    main()
