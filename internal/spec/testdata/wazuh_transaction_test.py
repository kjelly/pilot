"""Behavioral controls for the real Wazuh coordinator (no host mutation).

Native command harnesses are explicitly separate from VM/systemd evidence.
Cold-backup recovery tests use real GNU tar and actual changed filesystem data.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[3]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, REPO / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w = load('wazuh_transaction', 'playbooks/apply/files/wazuh-transaction.py')
apt = load('apt_exact_stage', 'playbooks/apply/files/apt-exact-stage.py')


class PolicyTests(unittest.TestCase):
    def test_native_failure_does_not_echo_argv_or_tool_output(self):
        sentinel = 'PILOT_SYNTHETIC_SECRET_244'
        with self.assertRaises(w.Refused) as failure:
            w.Runner().run(['python3', '-c', 'import sys; print(sys.argv[1]); print(sys.argv[1],file=sys.stderr); sys.exit(1)', sentinel])
        self.assertNotIn(sentinel, str(failure.exception))

    def test_common_legacy_conflict_and_default(self):
        self.assertEqual(w.desired(), '4.14.1')
        self.assertEqual(w.desired('4.14.9'), '4.14.9')
        self.assertEqual(w.desired('', '4.14.6'), '4.14.6')
        with self.assertRaisesRegex(w.Refused, 'conflicts'):
            w.desired('4.14.9', '4.14.1')

    def test_installed_older_equal_newer_and_explicit_upgrade(self):
        for installed in ('4.14.1-1', '4.14.6-1', '4.14.9-1', '4.14.9-2'):
            plan = w.agent_plan(installed, '4.14.9')
            self.assertFalse(plan['change'])
            self.assertEqual(plan['package'], installed)
        with self.assertRaisesRegex(w.Refused, 'newer than the observed manager'):
            w.agent_plan('4.14.9-1', '4.14.1')
        with self.assertRaisesRegex(w.Refused, 'requires'):
            w.agent_plan('4.14.6-1', '4.14.9', '4.14.9')
        self.assertTrue(w.agent_plan('4.14.6-1', '4.14.9', '4.14.9', True)['change'])
        with self.assertRaisesRegex(w.Refused, 'downgrade'):
            w.agent_plan('4.14.9-1', '4.14.9', '4.14.6', True)

    def test_unknown_versions_and_candidate_bound(self):
        for invalid in ('', '4.14', '5.0.0', '4.14.9-rc1', 'v4.14.9', '4.14.09'):
            if invalid:
                with self.assertRaises(w.Refused):
                    w.agent_plan('', invalid)
        with self.assertRaises(w.Refused):
            w.agent_plan('4.14.9-rc1', '4.14.9')
        with self.assertRaisesRegex(w.Refused, 'newer'):
            w.agent_plan('', '4.14.1', '4.14.9')
        self.assertEqual(w.agent_plan('', '4.14.9')['package'], '4.14.9-1')


class NativeComposeControlTests(unittest.TestCase):
    """Real Compose parser/config hashing; no daemon, containers or network."""
    def test_version_only_graph_and_anchor_side_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            central = w.Central(root=directory / 'private')
            for anchored in (False, True):
                old = ('x-manager-image: &manager_image wazuh/wazuh-manager:4.14.1\n' if anchored else '')
                old += 'services:\n'
                for service in w.SERVICES:
                    old += '  ' + service + ':\n'
                    old += '    image: ' + ('*manager_image' if anchored and service == 'wazuh.manager'
                                             else 'wazuh/' + service.replace('.', '-') + ':4.14.1') + '\n'
                    if service == 'wazuh.manager':
                        old += '    environment:\n      NON_IMAGE_SETTING: ' + ('*manager_image' if anchored else 'preserved') + '\n'
                state = {'directory': str(directory), 'version': '4.14.1',
                         'images': {s: {'config_hash': central.service_hash(str(directory), old, s)} for s in w.SERVICES}}
                new = old.replace(':4.14.1', ':4.14.9')
                if anchored:
                    with self.assertRaisesRegex(w.Refused, 'outside image fields'):
                        central.validate_compose_transition(state, old, new, '4.14.9')
                else:
                    central.validate_compose_transition(state, old, new, '4.14.9')
                    self.assertEqual(set(state['target_config_hashes']), set(w.SERVICES))

    def test_pending_environment_edit_refuses_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            central = w.Central(root=Path(temporary) / 'private')
            original = 'services:\n' + ''.join('  ' + s + ':\n    image: wazuh/' + s.replace('.', '-') + ':4.14.1\n    environment:\n      SETTING: applied\n' for s in w.SERVICES)
            state = {'directory': temporary, 'version': '4.14.1',
                     'images': {s: {'config_hash': central.service_hash(temporary, original, s)} for s in w.SERVICES}}
            pending = original.replace('SETTING: applied', 'SETTING: unapplied')
            with self.assertRaisesRegex(w.Refused, 'differs from the running container'):
                central.validate_compose_transition(state, pending, pending.replace(':4.14.1', ':4.14.9'), '4.14.9')
            self.assertFalse(central.root.exists())


class Commands:
    def __init__(self, family='Debian', installed='4.14.6-1'):
        self.family, self.installed = family, installed
        self.calls = []
        self.agent_release = '4.14.9'
        self.unknown = False

    def run(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        self.calls.append(argv)
        if argv[0] == 'tar' or argv[0] == 'du':
            return w.Runner().run(argv, **kwargs)
        if argv[0] == 'dpkg-query':
            text, rc = ('install ok installed\t' + self.installed + '\tamd64', 0) if self.installed else ('', 1)
        elif argv[:2] == ['rpm', '-q']:
            text, rc = (self.installed + '\tx86_64', 0) if self.installed else ('package wazuh-agent is not installed\n', 1)
        elif '-l' in argv:
            text, rc = ('   ID: 000, Name: local (server)\n   ID: 001, Name: synthetic, Active\n', 0)
        elif '-i' in argv:
            text, rc = ('Agent ID: 001\nClient version: ' + ('unknown' if self.unknown else 'Wazuh v' + self.agent_release), 0)
        elif argv[0] == 'systemctl':
            text, rc = ('enabled', 0) if argv[1] == 'is-enabled' else ('', 3)
        else:
            text, rc = '', 0
        if rc not in kwargs.get('allowed', (0,)):
            raise w.Refused('injected native probe failure')
        diagnostic = 'dpkg-query: no packages found matching wazuh-agent\n' if argv[0] == 'dpkg-query' and not self.installed else ''
        return subprocess.CompletedProcess(argv, rc, text, diagnostic)

    def json(self, argv, **kwargs):
        self.calls.append([str(value) for value in argv])
        if argv[:3] == ['docker', 'image', 'inspect']:
            return [{'Id': 'sha256:new', 'RepoDigests': [str(argv[-1]).split(':')[0] + '@sha256:new']}]
        if argv[:2] == ['docker', 'inspect']:
            return [{'State': {'Running': False}}]
        raise AssertionError(argv)


class BackendTests(unittest.TestCase):
    def test_known_absent_and_unknown_query_failure_are_distinct(self):
        for family in ('Debian', 'RedHat'):
            native = Commands(family, '')
            self.assertEqual(w.Agent(family, runner=native).installed(), '')
        class BadQuery(Commands):
            def run(self, argv, **kwargs):
                return subprocess.CompletedProcess(argv, 1, '', 'database query failed')
        with self.assertRaisesRegex(w.Refused, 'probe failed'):
            w.Agent('Debian', runner=BadQuery()).installed()

    def test_both_package_backends_enforce_same_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            for family in ('Debian', 'RedHat'):
                for release in ('4.14.1-1', '4.14.9-1'):
                    command = Commands(family, release)
                    agent = w.Agent(family, runner=command, root=Path(temp) / family)
                    self.assertEqual(agent.check('4.14.9')['package'], release)
                    with self.assertRaisesRegex(w.Refused, 'newer'):
                        agent.check('4.14.0')
                    self.assertTrue(any(call[0] == ('dpkg-query' if family == 'Debian' else 'rpm') for call in command.calls))

    def test_probe_errors_never_become_fresh_installs(self):
        class Broken(Commands):
            def run(self, argv, **kwargs):
                if argv[0] == 'rpm':
                    return subprocess.CompletedProcess(argv, 1, 'rpmdb: query failed', '')
                raise w.Refused('query failed')
        for family in ('Debian', 'RedHat'):
            with self.assertRaises(w.Refused):
                w.Agent(family, runner=Broken()).installed()

    def test_registry_all_retained_agents_bound_target(self):
        command = Commands()
        central = w.Central(runner=command)
        with self.assertRaisesRegex(w.Refused, 'older than a retained'):
            central.check_agents('4.14.1')
        central.check_agents('4.14.9')
        command.unknown = True
        with self.assertRaisesRegex(w.Refused, 'unknown retained'):
            central.check_agents('4.14.9')


class JournalTests(unittest.TestCase):
    def test_every_published_phase_has_a_declared_recovery_action(self):
        import ast
        module = ast.parse((REPO / 'playbooks/apply/files/wazuh-transaction.py').read_text())
        for class_name, matrix in (('Central', w.CENTRAL_RECOVERY), ('Agent', w.AGENT_RECOVERY)):
            node = next(item for item in module.body if isinstance(item, ast.ClassDef) and item.name == class_name)
            published = {'reserved'}
            for call in ast.walk(node):
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                        and call.func.attr in ('write', 'finish') and len(call.args) >= 2):
                    value = call.args[1]
                    candidates = [value] if not isinstance(value, ast.IfExp) else [value.body, value.orelse]
                    published.update(item.value for item in candidates if isinstance(item, ast.Constant) and isinstance(item.value, str))
            self.assertEqual(published - set(matrix), set(), (class_name, published))

    def test_unknown_recovery_phase_never_dispatches_a_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            central = FakeCentral(Path(temporary))
            with central.lock():
                item = central.begin('d' * 32, central.discover())
                central.write(item, 'unknown-future-phase')
            with self.assertRaisesRegex(w.Refused, 'no fully backed-up'):
                central.execute('4.14.9', recover=True)
            self.assertEqual(central.calls, [])

    def test_path_scope_rejects_ancestor_overlap_and_symlink_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'source').mkdir()
            (root / 'source' / 'backup').mkdir()
            with self.assertRaisesRegex(w.Refused, 'overlaps'):
                w.disjoint([root / 'source'], root / 'source' / 'backup')
            with self.assertRaisesRegex(w.Refused, 'sources overlap'):
                w.disjoint([root / 'source', root / 'source' / 'child'], root / 'other')
            (root / 'link').symlink_to(root / 'source', target_is_directory=True)
            with self.assertRaisesRegex(w.Refused, 'symlink'):
                w.canonical(root / 'link' / 'child')

    def test_owner_exclusion_and_incomplete_transaction(self):
        with tempfile.TemporaryDirectory() as temp:
            tx = w.Transaction('agent', root=Path(temp) / 'private')
            with tx.lock():
                item = tx.begin('a' * 32, {})
            with tx.lock():
                with self.assertRaisesRegex(w.Refused, 'incomplete'):
                    tx.idle()
                with self.assertRaisesRegex(w.Refused, 'owner'):
                    tx.owned('b' * 32)
                with self.assertRaisesRegex(w.Refused, 'phase'):
                    tx.owned('a' * 32, ('backed-up',))
                self.assertEqual(tx.owned('a' * 32)['owner'], 'a' * 32)
                tx.finish(item, 'recovered')
                tx.idle()
            self.assertTrue((Path(item['backup']) / 'manifest.json').exists())
            self.assertEqual(tx.root.stat().st_mode & 0o777, 0o700)

    def test_lock_and_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            tx = w.Transaction('central', root=Path(temp) / 'private')
            with tx.lock():
                with self.assertRaisesRegex(w.Refused, 'another'):
                    with w.Transaction('central', root=tx.root).lock():
                        pass
            link = Path(temp) / 'alias'
            link.symlink_to(tx.root, target_is_directory=True)
            with self.assertRaisesRegex(w.Refused, 'unsafe'):
                with w.Transaction('central', root=link).lock():
                    pass


class FakeCentral(w.Central):
    def __init__(self, workspace, fail=False):
        self.command = Commands()
        self.command.agent_release = '4.14.1'
        super().__init__(runner=self.command, root=workspace / 'backups')
        self.workspace = workspace
        self.project = workspace / 'project'
        self.volume = workspace / 'volume'
        self.project.mkdir()
        self.volume.mkdir()
        (self.volume / 'document').write_text('original indexed data')
        self.compose = self.project / 'docker-compose.yml'
        self.compose.write_text('\n'.join('image: wazuh/' + s.replace('.', '-') + ':4.14.1' for s in w.SERVICES))
        self.fail = fail
        self.calls = []

    def discover(self):
        return {'directory': str(self.project), 'compose': str(self.compose), 'version': '4.14.1',
                'images': {s: {'id': 'sha256:old', 'container': s, 'size': 1} for s in w.SERVICES},
                'paths': [str(self.project), str(self.volume)], 'compose_sha256': w.digest(self.compose)}

    def capacity(self, paths, extra_bytes=0):
        return 1

    def validate_compose_transition(self, state, old_text, new_text, target):
        # Native Compose has a separate parser/anchor behavioral test.
        state['target_config_hashes'] = {service: 'b' * 64 for service in w.SERVICES}

    def validate_persisted_graph(self, item, target=False):
        pass

    def data(self):
        return {'content': (self.volume / 'document').read_text()}

    def check_data(self, data):
        if (self.volume / 'document').read_text() != data['content']:
            raise w.Refused('data oracle failed')

    def canary(self):
        return {'synthetic-command-harness': True}

    def compose_run(self, item, *args, **kwargs):
        self.calls.append((item['phase'], args))
        if args[0] == 'up' and item['phase'] == 'switching':
            (self.volume / 'document').write_text('new schema migrated data')

    def validate_restore_scope(self, item):
        # The fixture intentionally lives under a temporary directory; native
        # production path validation has independent rejection controls below.
        w.disjoint(item['paths'], self.root)
        for entry in item['archives']:
            if w.digest(entry['archive']) != entry['sha256']:
                raise w.Refused('backup checksum mismatch')

    def validate_project_scope(self, item):
        w.disjoint(item['paths'], self.root)

    def retain_images(self, item):
        # Native docker-save/load is covered by the separate target evidence.
        # This explicit command harness still retains a real durable artifact.
        archive = Path(item['backup']) / 'old-images.tar'
        archive.write_bytes(b'synthetic image archive')
        w.sync_file(archive)
        item['image_archive'] = {'path': str(archive), 'sha256': w.digest(archive)}
        self.write(item, item['phase'])

    def quiesce_for_restore(self, item):
        self.calls.append((item['phase'], ('down',)))

    def wait(self, release, images):
        if release == '4.14.9' and self.fail:
            raise w.Refused('injected failure after data changed')


class CentralTransactionTests(unittest.TestCase):
    def test_interrupted_restore_replays_with_live_compose_directory_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            central = FakeCentral(Path(temporary), fail=True)
            original = central.compose.read_bytes()
            interrupted = False
            restore = central.restore
            def fault(source, archive, checksum):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    import shutil
                    shutil.rmtree(source)
                    raise w.Refused('injected interruption after destination removal')
                return restore(source, archive, checksum)
            central.restore = fault
            with self.assertRaisesRegex(w.Refused, 'AND recovery failed'):
                central.execute('4.14.9', True)
            self.assertFalse(central.compose.exists())
            self.assertEqual(central.active()['phase'], 'recovering')
            central.execute('4.14.9', recover=True)
            self.assertEqual(central.compose.read_bytes(), original)
            self.assertEqual((central.volume / 'document').read_text(), 'original indexed data')
            self.assertFalse(central.path.exists())

    def test_all_durable_phases_have_exact_recovery_dispatch(self):
        for phase, expected in w.CENTRAL_RECOVERY.items():
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                central = FakeCentral(Path(temporary))
                with central.lock():
                    item = central.begin('e' * 32, central.discover())
                    central.write(item, phase)
                calls = []
                def action(label):
                    def run(state):
                        calls.append(label)
                        central.finish(state, 'recovered')
                    return run
                central.recover_pre_switch = action('resume-old')
                central.rollback = action('restore-old')
                central.complete_finalized = action(expected)
                central.execute('4.14.9', recover=True)
                self.assertEqual(calls, [expected])
                self.assertFalse(central.path.exists())

    def test_recovery_in_check_mode_never_executes_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            central = FakeCentral(Path(temp))
            with self.assertRaisesRegex(w.Refused, 'check mode'):
                central.execute('4.14.9', upgrade=True, preview=True, recover=True)
            self.assertEqual(central.calls, [])
            self.assertEqual(central.command.calls, [])

    def test_post_mutation_failure_restores_real_cold_data_and_compose(self):
        with tempfile.TemporaryDirectory() as temp:
            central = FakeCentral(Path(temp), fail=True)
            before = central.compose.read_bytes()
            with self.assertRaisesRegex(w.Refused, 'previous images, data and availability recovered'):
                central.execute('4.14.9', upgrade=True)
            self.assertEqual((central.volume / 'document').read_text(), 'original indexed data')
            self.assertEqual(central.compose.read_bytes(), before)
            self.assertFalse(central.path.exists())
            backup = list(central.root.glob('central-*/manifest.json'))
            self.assertEqual(len(backup), 1)
            self.assertEqual(json.loads(backup[0].read_text())['phase'], 'recovered')
            self.assertTrue(any(phase == 'recovering' and args[0] == 'up' for phase, args in central.calls))

    def test_no_opt_in_or_unsupported_transition_never_stops_stack(self):
        for target, upgrade in [('4.14.9', False), ('4.14.8', True), ('4.14.0', True)]:
            with tempfile.TemporaryDirectory() as temp:
                central = FakeCentral(Path(temp))
                with self.assertRaises(w.Refused):
                    central.execute(target, upgrade)
                self.assertEqual(central.calls, [])
                self.assertFalse(central.path.exists())

    def test_capacity_and_registry_failure_never_stops_stack(self):
        for cause in ('capacity', 'registry'):
            with tempfile.TemporaryDirectory() as temp:
                central = FakeCentral(Path(temp))
                if cause == 'capacity':
                    def capacity(paths, extra_bytes=0):
                        raise w.Refused('insufficient backup capacity')
                    central.capacity = capacity
                else:
                    central.command.unknown = True
                with self.assertRaises(w.Refused):
                    central.execute('4.14.9', True)
                self.assertEqual(central.calls, [])
                self.assertFalse(central.path.exists())

    def test_backup_tamper_preserves_journal_and_refuses_recovery_success(self):
        with tempfile.TemporaryDirectory() as temp:
            central = FakeCentral(Path(temp), fail=True)
            restore = central.restore
            def corrupt(source, archive, checksum):
                Path(archive).write_bytes(b'corrupt')
                return restore(source, archive, checksum)
            central.restore = corrupt
            with self.assertRaisesRegex(w.Refused, 'AND recovery failed'):
                central.execute('4.14.9', True)
            self.assertTrue(central.path.exists())


class ExactArtifactTests(unittest.TestCase):
    def test_loaded_images_require_exact_retained_official_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            central = w.Central(root=Path(temporary) / 'private')
            w.private_dir(central.root)
            image = {'Id': 'sha256:synthetic-exact-id', 'RepoDigests': []}
            repository = 'wazuh/wazuh-indexer'
            official = repository + '@sha256:' + 'a' * 64
            with self.assertRaisesRegex(w.Refused, 'lacks official'):
                central.image_provenance(image, repository, '4.14.1')
            w.atomic_json(central.root / 'image-provenance.json', {
                image['Id']: {'repository': repository, 'version': '4.14.1', 'digests': [official]}})
            self.assertEqual(central.image_provenance(image, repository, '4.14.1'), [official])
            with self.assertRaisesRegex(w.Refused, 'does not match'):
                central.image_provenance(image, repository, '4.14.9')
            with self.assertRaisesRegex(w.Refused, 'does not match'):
                central.image_provenance(dict(image, Id='sha256:other-image'), repository, '4.14.1')

    def test_metadata_sha256_and_package_identity_are_both_required(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / 'wazuh-agent_4.14.9-1_amd64.deb'
            artifact.write_bytes(b'authenticated package bytes')
            checksum = hashlib.sha256(artifact.read_bytes()).hexdigest()
            original = apt.run
            identity = ['wazuh-agent', '4.14.9-1', 'amd64']
            def command(argv):
                if argv[0] == 'dpkg':
                    return 'amd64\n'
                if argv[0] == 'apt-cache':
                    return '\n'.join(['Package: wazuh-agent', 'Version: 4.14.9-1', 'Architecture: amd64',
                                      'Filename: pool/' + artifact.name, 'SHA256: ' + checksum])
                return '\n'.join(identity)
            apt.run = command
            try:
                self.assertEqual(apt.verify({'wazuh-agent': '4.14.9-1'}, root)[0]['sha256'], checksum)
                identity[1] = '4.14.10-1'
                with self.assertRaises(ValueError):
                    apt.verify({'wazuh-agent': '4.14.9-1'}, root)
                identity[1] = '4.14.9-1'
                artifact.write_bytes(b'tampered package bytes')
                with self.assertRaises(ValueError):
                    apt.verify({'wazuh-agent': '4.14.9-1'}, root)
            finally:
                apt.run = original


class AgentColdRecoveryTests(unittest.TestCase):
    def test_real_cold_state_and_identity_restored_for_both_backends(self):
        # Map only the coordinator's fixed host paths into disposable local
        # files. Real GNU tar still creates, verifies and restores the archives.
        # Native package/service state is an explicit command harness.
        for family in ('Debian', 'RedHat'):
            with self.subTest(family=family), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                real_path = w.Path
                real_sync_file, real_sync_tree = w.sync_file, w.sync_tree
                sealed, restored = set(), set()
                def seal(filename):
                    real_sync_file(filename)
                    sealed.add(str(filename))
                def barrier(filename):
                    real_sync_tree(filename)
                    restored.add(str(filename))
                mapped = ('/var/ossec', '/etc/hosts', '/etc/apt/preferences.d', '/etc/yum.repos.d', '/var/cache/apt/archives')
                def path(value):
                    value = str(value)
                    if any(value == prefix or value.startswith(prefix + '/') for prefix in mapped):
                        return Path(root / 'host' / value.lstrip('/'))
                    return real_path(value)
                class Native(Commands):
                    def __init__(self):
                        super().__init__(family, '4.14.1-1')
                        self.active = True
                    def run(self, argv, **kwargs):
                        if argv[0] == 'du':
                            argv = list(argv[:-1]) + [str(path(argv[-1]))]
                        if argv[0] == 'systemctl':
                            self.calls.append(list(argv))
                            action = argv[1]
                            if action in ('start', 'stop'):
                                self.active = action == 'start'
                            code = 0 if action != 'is-active' or self.active else 3
                            return subprocess.CompletedProcess(argv, code, 'enabled' if action == 'is-enabled' else '', '')
                        if argv[0] == '/var/ossec/bin/wazuh-control':
                            return subprocess.CompletedProcess(argv, 0, 'WAZUH_VERSION="v' + self.installed.rsplit('-', 1)[0] + '"\n', '')
                        return super().run(argv, **kwargs)
                class LocalAgent(w.Agent):
                    def write(self, item, phase):
                        if phase == 'staged':
                            self_test.assertTrue({entry['path'] for entry in item['packages'].values()}.issubset(sealed))
                        if phase == 'backed-up':
                            self_test.assertTrue({entry['archive'] for entry in item['archives']}.issubset(sealed))
                        if phase == 'restored':
                            self_test.assertTrue({str(path(value)) for value in item['paths']}.issubset(restored))
                        return super().write(item, phase)
                    def package_archives(self, installed, target):
                        return {release: {'path': root / (release + '.pkg'), 'sha256': w.digest(root / (release + '.pkg'))}
                                for release in (installed, target)}
                self_test = self
                w.Path, w.sync_file, w.sync_tree = path, seal, barrier
                try:
                    for filename, content in {
                        '/var/ossec/etc/client.keys': '001 synthetic any SYNTHETIC_KEY_ONLY\n',
                        '/var/ossec/etc/ossec.conf': 'old config and data', '/etc/hosts': 'old hosts',
                        '/etc/apt/preferences.d/pilot-wazuh-agent': 'old apt pin',
                        '/etc/yum.repos.d/wazuh.repo': 'old rpm pin',
                    }.items():
                        destination = path(filename)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_text(content)
                    path('/var/cache/apt/archives').mkdir(parents=True)
                    for release in ('4.14.1-1', '4.14.9-1'):
                        (root / (release + '.pkg')).write_text(release)
                    native = Native()
                    agent = LocalAgent(family, runner=native, root=root / 'backups')
                    (agent.root / 'rpm-stage').mkdir(parents=True)
                    plan = w.agent_plan('4.14.1-1', '4.14.9', '4.14.9', True)
                    owner = 'c' * 32
                    agent.reserve(owner, plan)
                    agent.cold_backup(owner)
                    agent.authorize_install(owner)
                    native.installed = '4.14.9-1'
                    path('/var/ossec/etc/ossec.conf').write_text('new migrated data')
                    path('/var/ossec/etc/client.keys').write_text('002 changed any SYNTHETIC_WRONG_KEY\n')
                    path('/etc/hosts').write_text('new hosts')
                    agent.activate(owner)
                    with self.assertRaisesRegex(w.Refused, 'identity changed'):
                        agent.commit(owner)
                    self.assertTrue(agent.path.exists())
                    recovery = agent.prepare_recovery(owner)
                    self.assertTrue(recovery['reinstall'])
                    native.installed = '4.14.1-1'  # shared framework's retained-package reinstall
                    agent.restore_state(owner)
                    self.assertEqual(path('/var/ossec/etc/ossec.conf').read_text(), 'old config and data')
                    self.assertEqual(path('/etc/hosts').read_text(), 'old hosts')
                    self.assertEqual(path('/var/ossec/etc/client.keys').read_text(), '001 synthetic any SYNTHETIC_KEY_ONLY\n')
                    self.assertTrue(native.active)
                    self.assertEqual(agent.active()['phase'], 'restored')
                    agent.finish_recovery(owner)
                    self.assertFalse(agent.path.exists())
                finally:
                    w.Path = real_path
                    w.sync_file, w.sync_tree = real_sync_file, real_sync_tree


class AgentRecoveryDispatchTests(unittest.TestCase):
    def test_all_durable_phases_have_bounded_recovery_authority(self):
        for phase, action in w.AGENT_RECOVERY.items():
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                calls = []
                class Native(Commands):
                    def run(self, argv, **kwargs):
                        calls.append(str(argv[0]) + ':' + str(argv[1]))
                        if argv[0] == 'systemctl' and argv[1] == 'stop':
                            return subprocess.CompletedProcess(argv, 0, '', '')
                        return super().run(argv, **kwargs)
                class Agent(w.Agent):
                    def restore_service(self, item):
                        calls.append('restore-service')
                    def verify_old_state(self, item):
                        calls.append('verify-old-state')
                    def validate_agent_archives(self, item):
                        calls.append('validate-all-archives')
                agent = Agent('RedHat', runner=Native(), root=root / 'backups')
                (agent.root / 'rpm-stage').mkdir(parents=True)
                package = root / 'old.rpm'
                package.write_bytes(b'synthetic package; native signature is a separate test')
                with agent.lock():
                    item = agent.begin('f' * 32, {'installed': '4.14.1-1', 'manager_host': 'synthetic-manager',
                                                'packages': {'4.14.1-1': {'path': str(package), 'sha256': w.digest(package)}}})
                    agent.write(item, phase)
                result = agent.prepare_recovery('f' * 32)
                if action == 'resume-old':
                    self.assertEqual(calls, ['restore-service', 'verify-old-state'])
                    self.assertFalse(agent.path.exists())
                    self.assertFalse(result['need_commit'])
                elif action == 'restore-old':
                    self.assertEqual(calls[0], 'validate-all-archives')
                    self.assertIn('systemctl:stop', calls)
                    self.assertTrue(result['reinstall'])
                    self.assertEqual(agent.active()['phase'], 'recovering')
                else:
                    self.assertEqual(calls, [])
                    self.assertTrue(result['need_commit'])
                    self.assertEqual(agent.active()['phase'], phase)


if __name__ == '__main__':
    unittest.main(verbosity=2)
