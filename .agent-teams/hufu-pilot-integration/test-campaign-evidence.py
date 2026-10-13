#!/usr/bin/env python3
"""Source drift, partial evidence, timeout and signal fixtures; no VM actions."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import campaign_evidence as e
import workflow_contract as c


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project, self.root = self.base / 'project', self.base / 'checkpoint'
        for name in e.SOURCE_FILES:
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture source\n')
        self.playbook = self.project / 'playbooks/apply/tasks/nested.yml'
        self.playbook.parent.mkdir(parents=True)
        self.playbook.write_text('nested task\n')
        e.pin_sources(self.root, self.project)

    def test_transitive_source_binary_addition_removal_and_mode_drift(self):
        binary = self.project / 'pilot'
        original = binary.read_bytes()
        for path in (binary, self.playbook):
            before = path.read_bytes()
            path.write_bytes(before + b'changed')
            with self.assertRaises(RuntimeError):
                e.verify_sources(self.root, self.project)
            path.write_bytes(before)
        added = self.playbook.parent / 'added.yml'
        added.write_text('new task')
        with self.assertRaises(RuntimeError):
            e.verify_sources(self.root, self.project)
        added.unlink()
        binary.unlink()
        with self.assertRaises(RuntimeError):
            e.verify_sources(self.root, self.project)
        binary.write_bytes(original)
        binary.chmod(0o700)
        with self.assertRaises(RuntimeError):
            e.verify_sources(self.root, self.project)

    def test_symlink_sources_fail_before_mutation(self):
        self.playbook.unlink()
        self.playbook.symlink_to('/etc/passwd')
        with self.assertRaises(RuntimeError):
            e.pin_sources(self.root, self.project)

    def test_nonzero_stage_preserves_real_exit_and_private_raw_log(self):
        with patch.object(c, 'PROJECT', self.project), patch.dict(os.environ, HUFU_CHECKPOINT_WORKSPACE=str(self.root)):
            with self.assertRaises(RuntimeError):
                c.run('deploy', ['/bin/sh', '-c', 'echo real-diagnostic; exit 23'])
        rows = [json.loads(line) for line in (self.root / 'logs/stages.jsonl').read_text().splitlines()]
        self.assertEqual(rows[-1]['exit_code'], 23)
        log = self.root / rows[-1]['log']
        self.assertIn('real-diagnostic', log.read_text())
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        self.assertEqual(rows[-1]['log_sha256'], e.digest(log))
        self.assertFalse((self.root / 'receipts/execution.json').exists())

    def test_failure_seals_survive_resume_and_detect_snapshot_tampering(self):
        log = self.root / 'logs/deploy.log'
        log.parent.mkdir(parents=True)
        log.write_text('real failure\n')
        e.record_stage(self.root, 'deploy', 'failed', log, 23)
        first = e.seal_failure(self.root, 'failed', 23, 'workflow_exit')
        reference = json.loads((self.root / 'receipts/failed-evidence.json').read_text())
        self.assertEqual(reference['sha256'], e.digest(self.root / reference['manifest']))
        log.write_text('resumed command\n')
        second = e.seal_failure(self.root, 'failed', 24, 'workflow_exit')
        self.assertNotEqual(first['proofs'], second['proofs'])
        for name, expected in first['proofs'].items():
            self.assertEqual(e.digest(self.root / name), expected)
        archived_log = next(name for name, original in first['original_paths'].items() if original == 'logs/deploy.log')
        (self.root / archived_log).write_text('tampered')
        self.assertNotEqual(e.digest(self.root / archived_log), first['proofs'][archived_log])
        self.assertEqual(first['last_failed_command']['stage'], 'deploy')

    def test_timeout_reaps_descendants_and_records_partial_evidence(self):
        marker = self.root / 'late-write'
        with patch.object(c, 'PROJECT', self.project), patch.dict(os.environ, HUFU_CHECKPOINT_WORKSPACE=str(self.root)):
            with self.assertRaises(subprocess.TimeoutExpired):
                c.run('timeout', ['/bin/sh', '-c', '(sleep 0.5; touch "$1") & wait', 'fixture', str(marker)], timeout=0.03)
        time.sleep(0.55)
        self.assertFalse(marker.exists())
        rows = [json.loads(line) for line in (self.root / 'logs/stages.jsonl').read_text().splitlines()]
        self.assertEqual(rows[-1]['status'], 'timeout')
        self.assertIn('[local timeout=0.03]', (self.root / 'logs/timeout.log').read_text())

    def test_cancellation_preserves_stage_and_stops_child_group(self):
        script = self.base / 'fixture.py'
        marker = self.base / 'late-write'
        ready = self.base / 'ready'
        command = 'printf ready > "$2"; (sleep 0.6; touch "$1") & wait'
        script.write_text("import sys, os\nsys.path.insert(0, " + repr(str(e.TEAM)) + ")\n"
            "import campaign_evidence as e, workflow_contract as c\ne.install_signal_handlers()\n"
            "try: c.run('cancel', ['/bin/sh', '-c', " + repr(command) + ", 'fixture', " + repr(str(marker)) + ", " + repr(str(ready)) + "])\n"
            "except e.CampaignCancelled as error: sys.exit(128 + error.number)\n")
        process = subprocess.Popen([sys.executable, str(script)], env=dict(os.environ, HUFU_CHECKPOINT_WORKSPACE=str(self.root)),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        deadline = time.monotonic() + 3
        while not ready.exists():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        time.sleep(0.05)
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=3), 143)
        time.sleep(0.65)
        self.assertFalse(marker.exists())
        rows = [json.loads(line) for line in (self.root / 'logs/stages.jsonl').read_text().splitlines()]
        self.assertEqual((rows[-1]['status'], rows[-1]['exit_code']), ('cancelled', 143))

    def test_timeout_stops_pty_descendants_before_sealing_logs(self):
        marker, ready = self.base / 'pty-late', self.base / 'pty-ready'
        command = 'touch "$1"; sleep 3; touch "$2"'
        with patch.object(c, 'PROJECT', self.project), patch.dict(os.environ, HUFU_CHECKPOINT_WORKSPACE=str(self.root)):
            with self.assertRaises(subprocess.TimeoutExpired):
                c.run('pty-timeout', ['bash', str(e.TEAM / 'run-in-pty.sh'), '/bin/sh', '-c',
                                     command, 'fixture', str(ready), str(marker)], timeout=2)
        self.assertTrue(ready.exists(), 'PTY fixture never began execution')
        time.sleep(3.1)
        self.assertFalse(marker.exists())

    def test_guard_signal_seals_failure_after_stopping_its_workflow(self):
        team = self.project / '.agent-teams/hufu-pilot-integration'
        team.mkdir(parents=True)
        for name in ('campaign_evidence.py', 'resource_guard.py', 'resource-policy.json'):
            (team / name).write_bytes((e.TEAM / name).read_bytes())
        # Newly added fixture sources require a new campaign snapshot.
        (self.root / 'facts/source-snapshot.json').unlink()
        ready, marker = self.base / 'guard-ready', self.base / 'guard-late'
        command = 'touch "$1"; (sleep 0.6; touch "$2") & wait'
        process = subprocess.Popen([sys.executable, str(team / 'resource_guard.py'), '--', '/bin/sh', '-c',
            command, 'fixture', str(ready), str(marker)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=dict(os.environ, HUFU_CHECKPOINT_WORKSPACE=str(self.root), HUFU_RESOURCE_POLICY=json.dumps({
                'stop_vms_on_resource_failure': False, 'host_min_available_mib': 128, 'pressure_full_avg60_percent': 90})))
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        deadline = time.monotonic() + 3
        while not ready.exists() and process.poll() is None:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.assertTrue(ready.exists())
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=3)
        self.assertEqual(process.returncode, 143)
        time.sleep(0.65)
        self.assertFalse(marker.exists())
        reference = json.loads((self.root / 'receipts/failed-evidence.json').read_text())
        manifest = json.loads((self.root / reference['manifest']).read_text())
        self.assertEqual((manifest['status'], manifest['exit_code']), ('cancelled', 143))
        self.assertFalse((self.root / 'receipts/execution.json').exists())

    def test_success_seal_requires_current_complete_pipeline(self):
        e.write_json(self.root / 'receipts/execution.json', {'status': 'passed'})
        e.write_json(self.root / 'receipts/evidence-manifest.json', {'version': 1, 'sources': e.sources(self.project), 'proofs': {}, 'pipeline_complete': False})
        e.record_stage(self.root, 'campaign', 'started')
        for stage in e.PIPELINE_STAGES[:-1]:
            e.record_stage(self.root, stage, 'completed')
        with self.assertRaises(RuntimeError):
            e.seal_success(self.root, self.project)
        self.assertFalse(json.loads((self.root / 'receipts/evidence-manifest.json').read_text())['pipeline_complete'])
        e.record_stage(self.root, e.PIPELINE_STAGES[-1], 'completed')
        e.seal_success(self.root, self.project)
        manifest = json.loads((self.root / 'receipts/evidence-manifest.json').read_text())
        self.assertTrue(manifest['pipeline_complete'])
        for name, expected in manifest['proofs'].items():
            self.assertEqual(e.digest(self.root / name), expected)
        e.record_stage(self.root, 'campaign', 'started')
        with self.assertRaises(RuntimeError):
            e.seal_success(self.root, self.project)


if __name__ == '__main__':
    unittest.main()
