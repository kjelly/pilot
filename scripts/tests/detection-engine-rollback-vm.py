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
import shutil
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
    ap.add_argument('--base-image', required=True, type=Path)
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
    evidence = {'revision': subprocess.check_output(['git', '-c', 'safe.directory=' + str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
                'tree': subprocess.check_output(['git', '-c', 'safe.directory=' + str(ROOT), 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
                'playbook_sha256': sha(source), 'spec_sha256': sha(ROOT / 'docs/verification/detection-engine.md'),
                'base_image_sha256': sha(args.base_image), 'stage': 'sandbox',
                'old_binary_sha256': sha(args.old_binary),
                'new_binary_sha256': sha(args.new_binary), 'cases': []}
    assert evidence['old_binary_sha256'] != evidence['new_binary_sha256']

    def run(label, tasks, variables, check=False, full=False, extra_args=(), expected_failure=False):
        # Read the authoritative inventory before EVERY invocation, never hand-edit it.
        inv = subprocess.check_output([str(args.pilot), 'vm-target', 'show-inventory', '--name', args.name], text=True)
        inventory = yaml.safe_load(inv)
        hosts = inventory['all']['hosts']
        assert list(hosts) == [args.name] and hosts[args.name]['ansible_connection'] == 'ssh'
        (args.evidence / 'inventory.yml').write_text(inv)
        play = [{'name': label, 'hosts': args.name, 'gather_facts': False, 'become': True,
                 'vars': variables, 'tasks': tasks}]
        if full:
            play = [{'ansible.builtin.import_playbook': str(source), 'tags': ['observability', 'detection-engine']}]
        pb = args.evidence / (label + '.yml')
        pb.write_text(yaml.safe_dump(play, sort_keys=False))
        cmd = [str(args.pilot), 'vm-target', 'run', '--name', args.name, '--skip-lint', str(pb.resolve())]
        if full:
            extra = args.evidence / (label + '-vars.json')
            extra.write_text(json.dumps(variables))
            cmd += ['-e', '@' + str(extra.resolve())]
        if check:
            cmd += ['--check', '--diff']
        cmd += list(extra_args)
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=360)
        (args.evidence / (label + '.log')).write_text(proc.stdout)
        print(label, 'rc=', proc.returncode, flush=True)
        if (proc.returncode != 0) != expected_failure:
            print(proc.stdout[-18000:], flush=True)
            raise RuntimeError(label)
        return proc.stdout

    def target_test(label, variables):
        inv = subprocess.check_output([str(args.pilot), 'vm-target', 'show-inventory', '--name', args.name], text=True)
        inventory = yaml.safe_load(inv)
        assert list(inventory['all']['hosts']) == [args.name]
        assert 'detection-engine' in inventory['all']['children']
        (args.evidence / (label + '-inventory.yml')).write_text(inv)
        extra = args.evidence / (label + '-vars.json')
        extra.write_text(json.dumps(variables))
        cmd = [str(args.pilot), 'vm-target', 'test', '--name', args.name,
               '--playbook', str(source), '--spec', str(ROOT / 'docs/verification/detection-engine.md'),
               '--verify-timeout', '60', '--', '-e', '@' + str(extra.resolve())]
        before_reports = set((ROOT / '.verification').glob('detection-engine-*'))
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
        (args.evidence / (label + '.log')).write_text(proc.stdout)
        reports = set((ROOT / '.verification').glob('detection-engine-*')) - before_reports
        verified_rows = []
        for report in reports:
            if report.suffix not in ('.md', '.ndjson'):
                continue
            shutil.copyfile(report, args.evidence / report.name)
            if report.suffix == '.ndjson':
                verified_rows = [json.loads(line) for line in report.read_text().splitlines() if line.strip()]
                if proc.returncode:
                    print(report.read_text()[-14000:], flush=True)
        print(label, 'rc=', proc.returncode, flush=True)
        if proc.returncode or 'ALL TESTS PASSED SUCCESSFULLY' not in proc.stdout:
            print(proc.stdout[-20000:], flush=True)
            raise RuntimeError(label)
        assert {r['id'] for r in verified_rows} == {'C' + str(i) for i in range(1,13)}, verified_rows
        assert all(r['status'] == 'pass' and r['host'] == args.name for r in verified_rows), verified_rows
        evidence['cases'].append({'name': label, 'verdict': 'PASS', 'spec_pass': 12, 'spec_fail': 0, 'spec_skip': 0})
        (args.evidence / 'results.json').write_text(json.dumps(evidence, indent=2))

    variables = {'detection_engine_bin_dest': BASE + '/engine', 'detection_engine_db_path': BASE + '/state.db',
                 'detection_engine_backup_dir': BASE + '/backups', 'detection_engine_config_dir': BASE + '/etc',
                 'detection_engine_config_path': BASE + '/etc/config.yaml', 'detection_engine_unit_path': UNIT, 'detection_engine_feature_profile_dest': BASE + '/etc/profile.yaml',
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
assert (b/'etc/config.yaml').stat().st_mode & 0o777 == 0o640
assert (b/'etc/provider.env').stat().st_mode & 0o777 == 0o600
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
    # Exercise the complete apply as well as the fault-isolated upgrade slice.
    # Existing protocol fixtures supply external dependencies; the daemon is real.
    fixtures = yaml.safe_load((ROOT / 'playbooks/test/detection-engine-fixtures.yml').read_text())
    for i, fixture in enumerate(fixtures[:2]):
        run('full-protocol-fixture-' + str(i), fixture['tasks'], {})
    cleanup = [task('Stop slice fixture unit', 'ansible.builtin.systemd', {'name': 'pilot-detection-engine.service', 'state': 'stopped', 'enabled': False}),
               task('Remove slice fixture unit and prior full installation', 'ansible.builtin.file', {'path': '{{ item }}', 'state': 'absent'}, loop=[UNIT, '/etc/pilot/detection-engine', '/var/lib/pilot/detection-engine', '/var/backups/pilot-detection-engine', '/usr/local/bin/pilot-detection-engine']),
               task('Reload for genuine first install', 'ansible.builtin.systemd', {'daemon_reload': True}),
               task('Prepare host-monitoring prerequisite user', 'ansible.builtin.user', {'name': 'pilot-detect', 'system': True, 'create_home': False, 'shell': '/usr/sbin/nologin'}),
               task('Prepare host-monitoring textfile prerequisite', 'ansible.builtin.file', {'path': '/var/lib/node_exporter/textfile', 'state': 'directory', 'owner': 'pilot-detect', 'group': 'pilot-detect', 'mode': '0755'})]
    run('full-apply-prerequisites', cleanup, {})
    fullvars = {'target_group': args.name, 'stage': 'sandbox', 'detection_metrics_source_host': '127.0.0.1',
                'detection_alertmanager_target_host': '127.0.0.1',
                'detection_engine_feature_profile_src': str(ROOT / 'monitoring/detection/feature-profiles/linux-host-v1.yaml'),
                'detection_engine_artifact_path': str(args.old_binary.resolve()),
                'detection_engine_artifact_sha256': evidence['old_binary_sha256']}
    target_test('committed-spec-first-install-C1-C12', fullvars)
    fullvars.update(detection_engine_artifact_path=str(args.new_binary.resolve()),
                    detection_engine_artifact_sha256=evidence['new_binary_sha256'])
    target_test('committed-spec-upgrade-C1-C12', fullvars)
    run('full-apply-final-verify', [command('Full deployment binary and SQLite checks', ['/usr/local/bin/pilot-detection-engine', 'db', 'check', '--db', '/var/lib/pilot/detection-engine/state.db'], register='full_db_check', changed_when=False),
        task('Full deployment checksum', 'ansible.builtin.stat', {'path': '/usr/local/bin/pilot-detection-engine', 'checksum_algorithm': 'sha256'}, register='full_binary_stat'),
        command('Full deployment service state', ['systemctl', 'is-active', 'pilot-detection-engine.service'], register='full_service', changed_when=False),
        task('Full deployment expected state', 'ansible.builtin.assert', {'that': ["full_db_check.stdout | trim == 'ok'", "full_service.stdout | trim == 'active'", "full_binary_stat.stat.checksum == '" + evidence['new_binary_sha256'] + "'"]})], {})
    snapshot_script = r"""import hashlib,json,pathlib,subprocess,sys,time
base=pathlib.Path('/etc/pilot/detection-engine')
paths=[pathlib.Path('/etc/systemd/system/pilot-detection-engine.service'), base/'config.yaml',base/'feature-profile.yaml',base/'provider.env']
def capture():
 files={}
 for p in paths:
  if p.exists():
   st=p.stat(); files[str(p)]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':st.st_mode&0o777,'uid':st.st_uid,'gid':st.st_gid}
  else: files[str(p)]=None
 raw=subprocess.check_output(['systemctl','show','pilot-detection-engine.service','--property=ActiveState,SubState,UnitFileState,MainPID,NRestarts'],text=True)
 state=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
 return {'files':files,'service':state,'binary_sha256':hashlib.sha256(pathlib.Path('/usr/local/bin/pilot-detection-engine').read_bytes()).hexdigest()}
record=pathlib.Path('/opt/pilot-fixtures/native-before.json')
if sys.argv[1]=='before':
 data=capture(); assert data['service']['ActiveState']=='active' and data['service']['SubState']=='running',data
 assert data['service']['UnitFileState']=='enabled' and data['service']['NRestarts']=='0',data
 record.write_text(json.dumps(data));print(json.dumps(data))
else:
 time.sleep(3)
 before=json.loads(record.read_text());after=capture()
 assert before['files']==after['files'] and before['binary_sha256']==after['binary_sha256'],after
 assert after['service']['ActiveState']=='active' and after['service']['SubState']=='running',after
 assert after['service']['UnitFileState']=='enabled' and after['service']['NRestarts']=='0',after
 if sys.argv[1]=='same-pid': assert before['service']['MainPID']==after['service']['MainPID'],after
 else: assert before['service']['MainPID']!=after['service']['MainPID'],after
 check=subprocess.check_output(['/usr/local/bin/pilot-detection-engine','db','check','--db','/var/lib/pilot/detection-engine/state.db'],text=True)
 assert check.strip()=='ok',check
 print(json.dumps(after))
"""
    nativevars = dict(prod['vars'])
    nativevars.update(fullvars)
    nativevars['detection_engine_artifact_abs_path'] = str(args.new_binary.resolve())
    defaults = [t for t in prod['pre_tasks'] if t['name'] in (
        'Resolve model provider defaults without overriding inventory or extra vars',
        'Resolve inventory-overridable defaults without shadowing group_vars/host_vars')]
    for case in ['native-C1-skipped-Step8-failure', 'native-one-shot-query-failure',
                 'native-rejected-config', 'native-unit-rewrite-failure']:
        # Test-only secret; restoring provider.env is verified without printing contents.
        run(case + '-before', [put('/etc/pilot/detection-engine/provider.env', 'TEST_ONLY_TOKEN=original-native-fixture\n', mode='0600'),
            command('Capture native original service and file state', ['python3', '-c', snapshot_script, 'before'])], {})
        if case == 'native-C1-skipped-Step8-failure':
            faultvars = dict(fullvars)
            faultvars['detection_engine_feature_profile_dest'] = '/proc/pilot-rollback-forced-copy-failure.yaml'
            log = run(case, None, faultvars, full=True,
                      extra_args=['--tags','detection-engine','--skip-tags','detection-engine-C1'], expected_failure=True)
            assert 'detection-engine apply FAILED' in log and 'Step 8:' in log
        elif case == 'native-one-shot-query-failure':
            wrapper = '#!/bin/sh\nif [ "$1" = show ] && [ ! -e /opt/pilot-fixtures/query-failed-once ]; then touch /opt/pilot-fixtures/query-failed-once; exit 1; fi\nexec /usr/bin/systemctl "$@"\n'
            run(case + '-inject', [put('/opt/pilot-fixtures/query-fail-systemctl', wrapper, mode='0755')], {})
            faultprobes = copy.deepcopy(probes)
            for t in faultprobes:
                if t['name'].startswith('Step 0: query'):
                    t['ansible.builtin.command']['argv'][0] = '/opt/pilot-fixtures/query-fail-systemctl'
            log = run(case, faultprobes + [task('Must not reach mutation block', 'ansible.builtin.fail', {'msg':'UNREACHABLE_MUTATION'})], nativevars, expected_failure=True)
            assert 'Refusing to change anything' in log and 'TASK [Must not reach mutation block]' not in log
            run(case + '-confirm-injection', [task('Observe actual one-shot query injection', 'ansible.builtin.stat', {'path':'/opt/pilot-fixtures/query-failed-once'}, register='query_injection_marker'), task('Require the wrapper to have actually run', 'ansible.builtin.assert', {'that':['query_injection_marker.stat.exists']})], {})
        else:
            faultsteps = []
            for t in install['block']:
                name = t.get('name','')
                if not re.match(r'Step (?:[3-9][a-z]?|1[0-2]):', name):
                    continue
                faultsteps.append(copy.deepcopy(t))
                if case == 'native-rejected-config' and name.startswith('Step 9:'):
                    faultsteps += [put('/etc/pilot/detection-engine/config.yaml', 'invalid: [unterminated\n')]
                if case == 'native-unit-rewrite-failure' and name.startswith('Step 11:'):
                    faultsteps += [put(UNIT, '[Service]\nExecStart=/usr/bin/false\n'),
                                   task('Inject failure after unit rewrite', 'ansible.builtin.fail', {'msg':'EXPECTED_AFTER_UNIT_REWRITE'})]
            log = run(case, defaults + probes + [{'name':'Native production rollback', 'block':faultsteps,'rescue':install['rescue']}], nativevars, expected_failure=True)
            assert 'detection-engine apply FAILED' in log
            if case == 'native-rejected-config':
                assert 'Step 10: validate the rendered config' in log
            else:
                assert 'EXPECTED_AFTER_UNIT_REWRITE' in log
        run(case + '-after', [command('Assert native availability restored with original files',
            ['python3','-c',snapshot_script,'same-pid' if case == 'native-one-shot-query-failure' else 'restarted'])], {})
        run(case + '-cleanup', [task('Remove test-only provider secret', 'ansible.builtin.file', {'path':'/etc/pilot/detection-engine/provider.env','state':'absent'})], {})
        evidence['cases'].append({'name':case,'verdict':'PASS'})
        (args.evidence/'results.json').write_text(json.dumps(evidence,indent=2))
    evidence['cases'].append({'name': 'complete-apply-first-install-upgrade-idempotency', 'verdict': 'PASS'})
    (args.evidence / 'results.json').write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    main()
