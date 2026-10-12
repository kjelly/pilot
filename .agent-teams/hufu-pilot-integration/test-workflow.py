#!/usr/bin/env python3
"""Behavioral regression gates; fixtures never provision or contact a VM."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import workflow_contract as c
import section4
import campaign_evidence as evidence


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), c.TEAM / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WorkflowTests(unittest.TestCase):
    def test_remote_exit_is_not_pilot_exit(self):
        for output in ('no sentinel', '__HUFU_REMOTE_RC=42\n', '__HUFU_REMOTE_RC=0\ntrailing data',
                       '__HUFU_REMOTE_RC=0\n__HUFU_REMOTE_RC=0\n'):
            with self.subTest(output=output), patch.object(c, 'run', return_value=output):
                with self.assertRaises(RuntimeError):
                    c.remote('probe', 'nexus', 'false')
        with patch.object(c, 'run', return_value='actual output\n__HUFU_REMOTE_RC=0\n'):
            self.assertEqual(c.remote('probe', 'nexus', 'true'), 'actual output')

    def test_recap_requires_real_success_and_zero_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'recap.log'
            for text in ('', 'PLAY RECAP\n', 'PLAY RECAP\nnexus : ok=0 changed=0 unreachable=0 failed=0',
                         'PLAY RECAP\nnexus : ok=4 changed=0 unreachable=1 failed=0',
                         'PLAY RECAP\nnexus : ok=4 changed=1 unreachable=0 failed=0'):
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(RuntimeError):
                    c.recap(path, idempotent=True)
            path.write_text('PLAY RECAP\nnexus : ok=4 changed=0 unreachable=0 failed=0\n')
            self.assertEqual(c.recap(path, idempotent=True), {'nexus'})
            path.write_text('PLAY RECAP\nlocalhost : ok=1 changed=0 unreachable=0 failed=0\nnexus : ok=4 changed=0 unreachable=0 failed=0\n')
            self.assertEqual(c.recap(path, idempotent=True), {'nexus'})
            path.write_text('PLAY RECAP\nlocalhost : ok=1 changed=0 unreachable=0 failed=1\nnexus : ok=4 changed=0 unreachable=0 failed=0\n')
            with self.assertRaises(RuntimeError):
                c.recap(path, idempotent=True)

    def test_campaign_credentials_and_checkpoint_are_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / 'control'
            control.mkdir()
            evidence = root / 'evidence'
            command = [sys.executable, str(c.TEAM / 'launch-state.py'), str(control), str(evidence)]
            first = subprocess.run(command + ['new'], capture_output=True, text=True, check=True)
            secrets = (control / 'pilot-launch.json').read_bytes()
            resumed = subprocess.run(command + ['resume'], capture_output=True, text=True, check=True,
                                     env=dict(os.environ, PILOT_ALICE_PASSWORD='must-not-replace-secret'))
            self.assertEqual(first.stdout, resumed.stdout)
            self.assertEqual(secrets, (control / 'pilot-launch.json').read_bytes())
            values = json.loads(secrets)['secrets']
            self.assertEqual(values['PILOT_THANOS_AWS_ACCESS_KEY_ID'], values['PILOT_RESTIC_AWS_ACCESS_KEY_ID'])
            self.assertEqual(values['PILOT_THANOS_AWS_SECRET_ACCESS_KEY'], values['PILOT_RESTIC_AWS_SECRET_ACCESS_KEY'])
            self.assertEqual((control / 'pilot-launch.json').stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(subprocess.run(command + ['new'], capture_output=True).returncode, 0)
            wrong = command[:-1] + [str(root / 'other')]
            self.assertNotEqual(subprocess.run(wrong + ['resume'], capture_output=True).returncode, 0)

    def test_pty_capture_has_one_recap_and_preserves_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrapper = c.TEAM / 'run-in-pty.sh'
            command = 'printf "PLAY RECAP\\nnexus : ok=4 changed=0 unreachable=0 failed=0\\n"'
            with patch.dict(os.environ, HUFU_CHECKPOINT_WORKSPACE=str(root)):
                output = c.run('pty-recap', ['bash', str(wrapper), 'bash', '-c', command])
                self.assertEqual(output.count('PLAY RECAP'), 1)
                self.assertEqual(c.recap(root / 'logs/pty-recap.log'), {'nexus'})
                with self.assertRaises(RuntimeError):
                    c.run('pty-failed', ['bash', str(wrapper), 'bash', '-c', 'echo actual-failure; exit 23'])
            self.assertIn('actual-failure', (root / 'logs/pty-failed.log').read_text())
            self.assertIn('[local exit=23]', (root / 'logs/pty-failed.log').read_text())

    def test_adapter_keeps_protocol_stdout_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            team = root / '.agent-teams/hufu-pilot-integration'
            team.mkdir(parents=True)
            for name in ('resource_guard.py', 'resource-policy.json', 'campaign_evidence.py'):
                (team / name).write_bytes((c.TEAM / name).read_bytes())
            workflow = team / 'execute-structured-workflow.sh'
            workflow.write_text("python3 - <<'PY'\nimport sys\nsys.path.insert(0, '.agent-teams/hufu-pilot-integration')\nimport campaign_evidence as e\nimport os\nfrom pathlib import Path\nfor stage in e.PIPELINE_STAGES: e.record_stage(Path(os.environ['HUFU_CHECKPOINT_WORKSPACE']), stage, 'completed')\nPY\n")
            for name in evidence.SOURCE_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
            evidence.pin_sources(checkpoint := root / 'checkpoint', root)
            c.write_json(checkpoint / 'receipts/evidence-manifest.json', {'version': 1, 'sources': evidence.sources(root), 'proofs': {}})
            checkpoint = root / 'checkpoint'
            (checkpoint / 'receipts').mkdir(parents=True, exist_ok=True)
            c.write_json(checkpoint / 'receipts/execution.json', {'version': 1, 'status': 'passed'})
            action = {'capability': 'pilot-structured-actions', 'type': 'execute_bundle',
                      'payload': '{"operation":"minimal-poc-structured-run","version":1}'}
            adapter = c.TEAM / 'pilot-structured-action-adapter.sh'
            result = subprocess.run(['bash', str(adapter)], cwd=root, input=json.dumps(action),
                text=True, capture_output=True, check=True,
                env=dict(os.environ, HUFU_CHECKPOINT_WORKSPACE=str(checkpoint)))
            response = json.loads(result.stdout)
            self.assertEqual(set(response), {'outputs'})
            self.assertEqual(response['outputs']['status'], 'passed')
            self.assertIn('HUFU_ACTION_PROGRESS', result.stderr)
            (checkpoint / 'facts/source-snapshot.json').unlink()
            workflow.write_text('exit 19\n')
            result = subprocess.run(['bash', str(adapter)], cwd=root, input=json.dumps(action),
                text=True, capture_output=True, env=dict(os.environ, HUFU_CHECKPOINT_WORKSPACE=str(checkpoint)))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['error']['failure_class'], 'execution')
            self.assertTrue((checkpoint / 'receipts/failed-evidence.json').is_file())

    def test_authoritative_dns_must_cover_both_reconciler_records(self):
        checks = section4.Checks.__new__(section4.Checks)
        checks.facts = {'freeipa-server': {'ansible_host': '10.0.0.1'}}
        checks.nexus = '10.0.0.2'
        checks.record = lambda name, probe: probe()
        def response(name, host, command):
            if name == 'endpoint-health':
                return '{"database":"ok"}'
            if name == 'endpoint-certificate':
                return 'grafana.it.pilot.internal Certificate Authority'
            return '10.0.0.2'
        with patch.object(section4, 'remote', side_effect=response) as remote:
            checks.endpoint()
            for host in c.HOSTS:
                for record in ('grafana', 'wazuh', 'thanos'):
                    self.assertTrue(any(call.args[0] == 'dns-authority-' + host + '-' + record
                                        for call in remote.call_args_list))
        def missing_wazuh(name, host, command):
            if name.endswith('-wazuh'):
                return ''
            return response(name, host, command)
        with patch.object(section4, 'remote', side_effect=missing_wazuh), self.assertRaisesRegex(RuntimeError, 'wazuh'):
            checks.endpoint()

    def test_evidence_gate_rejects_missing_failed_and_tampered_proof(self):
        verifier = load('verify-evidence')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in c.SCENARIOS:
                c.write_json(root / 'actions' / name, {'version': 1, 'steps': []})
            proof = root / 'logs/section4.jsonl'
            proof.parent.mkdir()
            values = [{'id': name, 'status': 'pass'} for name in sorted(section4.REQUIRED)]
            proof.write_text('\n'.join(json.dumps(value) for value in values) + '\n')
            c.write_json(root / 'receipts/execution.json', {'status': 'passed', 'sections': list(c.SECTIONS),
                'component_specs': {}, 'bundle_sha256': c.bundle_hash(root)})
            c.write_json(root / 'receipts/evidence-manifest.json', {'version': 1, 'bundle_sha256': c.bundle_hash(root),
                'proofs': {'logs/section4.jsonl': hashlib.sha256(proof.read_bytes()).hexdigest()},
                'sources': {name: hashlib.sha256((c.PROJECT / name).read_bytes()).hexdigest() for name in ['docs/runbooks/minimal-poc-architecture.md', 'docs/topologies/minimal-poc-topology.yaml']}})
            project = root / 'project'
            for name in evidence.SOURCE_FILES:
                target = project / name
                target.parent.mkdir(parents=True, exist_ok=True)
                original = c.PROJECT / name
                target.write_bytes(original.read_bytes() if name.endswith(('.md', '.yaml')) else b'fixture')
            evidence.pin_sources(root, project)
            evidence.record_stage(root, 'campaign', 'started')
            for stage in evidence.PIPELINE_STAGES:
                evidence.record_stage(root, stage, 'completed')
            evidence.record_stage(root, 'campaign', 'completed')
            manifest = json.loads((root / 'receipts/evidence-manifest.json').read_text())
            manifest.update(pipeline_complete=True, sources=evidence.sources(project))
            manifest['proofs'].update({name: evidence.digest(root / name) for name in
                ('facts/source-snapshot.json', 'logs/stages.jsonl', 'receipts/execution.json')})
            c.write_json(root / 'receipts/evidence-manifest.json', manifest)
            with patch.object(verifier, 'checkpoint', return_value=root), patch.object(verifier, 'PROJECT', project), patch.object(verifier, 'COMPONENTS', {}):
                self.assertEqual(verifier.verify(), len(section4.REQUIRED))
                for replacement in (values[:-1], values + [values[0]],
                                    [dict(v, status='fail') if i == 0 else v for i, v in enumerate(values)]):
                    proof.write_text('\n'.join(json.dumps(value) for value in replacement) + '\n')
                    manifest = json.loads((root / 'receipts/evidence-manifest.json').read_text())
                    manifest['proofs']['logs/section4.jsonl'] = hashlib.sha256(proof.read_bytes()).hexdigest()
                    c.write_json(root / 'receipts/evidence-manifest.json', manifest)
                    with self.assertRaises(RuntimeError):
                        verifier.verify()
                proof.write_text('tampered\n')
                with self.assertRaises(RuntimeError):
                    verifier.verify()
            with patch.object(verifier, 'checkpoint', return_value=root):
                with self.assertRaises(RuntimeError):
                    verifier.verify()  # empty component scope is never acceptable


if __name__ == '__main__':
    unittest.main()
