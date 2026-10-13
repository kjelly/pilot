#!/usr/bin/env python3
"""Resource-policy fixtures never provision or contact a VM."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
TEAM = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("resource_guard", TEAM / "resource_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
DEFAULT = json.loads((TEAM / "resource-policy.json").read_text())


def good(available=1048576, pressure=0, oom=0, boot="fixture"):
    return {"valid": True, "sampled_at": time.time(), "mem_total_kib": 2097152,
            "mem_available_kib": available, "pressure_full_avg60_percent": pressure,
            "oom_kill": oom, "boot_id": boot}


class ResourceTests(unittest.TestCase):
    def test_policy_rejects_unknown_invalid_and_ambiguous_values(self):
        for override in ({"unknown": 1}, {"consecutive_samples": True},
                         {"pressure_full_avg60_percent": float("nan")},
                         {"stop_vms_on_resource_failure": "true"}, {"version": 2}):
            with self.subTest(override=override), patch.dict(os.environ, HUFU_RESOURCE_POLICY=json.dumps(override)):
                with self.assertRaises(ValueError):
                    guard.load_policy()

    def test_policy_rejects_duplicate_fields(self):
        with patch.dict(os.environ, HUFU_RESOURCE_POLICY='{"consecutive_samples":3,"consecutive_samples":4}'):
            with self.assertRaisesRegex(ValueError, "duplicate"):
                guard.load_policy()

    def test_unknown_observations_do_not_count_as_low_memory(self):
        decision = guard.ResourceDecision(DEFAULT)
        snapshot = {'host': good(), 'guests': {'nexus': {'valid': False}}}
        for _ in range(DEFAULT['max_unknown_guest_samples'] - 1):
            self.assertEqual(decision.observe(snapshot), [])
        snapshot['guests']['nexus'] = good(available=1)
        self.assertEqual(decision.observe(snapshot), [])

    def test_stale_guest_balloon_is_not_available_memory_evidence(self):
        output = ("MemTotal: 2097152 kB\nMemAvailable: 102400 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
                  "full avg10=0 avg60=0 avg300=0 total=0\noom_kill 0\n"
                  "__HUFU_BOOT_ID=fixture\n__HUFU_RESOURCE_RC=0\n")
        with patch.object(guard, "probe", side_effect=["last_update 1\navailable 12238632\nrss 12361688\n", output]):
            observed = guard.sample_guest("nexus", DEFAULT)
        self.assertFalse(observed["balloon"]["fresh"])
        self.assertEqual(observed["mem_available_kib"], 102400)
        self.assertEqual(observed["source"], "guest_proc")

    def test_guest_remote_failure_is_unknown_not_zero_or_success(self):
        with patch.object(guard, "probe", side_effect=["last_update 1\n", "connection failed\n"]):
            result = guard.sample_guest("nexus", DEFAULT)
        self.assertFalse(result["valid"])
        self.assertNotIn("mem_available_kib", result)

    def test_pressure_requires_consecutive_fresh_observations(self):
        decision = guard.ResourceDecision(DEFAULT)
        snapshot = {"host": good(), "guests": {"nexus": good(pressure=40)}}
        self.assertEqual(decision.observe(snapshot), [])
        self.assertEqual(decision.observe(snapshot), [])
        self.assertEqual(decision.observe(snapshot), ["nexus:sustained_memory_pressure"])
        snapshot["guests"]["nexus"] = good()
        self.assertEqual(decision.observe(snapshot), [])
        snapshot["guests"]["nexus"] = good(pressure=40)
        snapshot["guests"]["nexus"]["sampled_at"] = 1
        self.assertEqual(decision.observe(snapshot), [])

    def test_oom_counter_is_bound_to_boot_identity(self):
        decision = guard.ResourceDecision(DEFAULT)
        snapshot = {"host": good(), "guests": {"nexus": good(oom=5)}}
        self.assertEqual(decision.observe(snapshot), [])
        snapshot["guests"]["nexus"] = good(oom=6)
        self.assertEqual(decision.observe(snapshot), ["nexus:oom_kill"])
        snapshot["guests"]["nexus"] = good(oom=50, boot="new-boot")
        self.assertEqual(decision.observe(snapshot), [])

    def test_preflight_stops_before_starting_a_mutating_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "must-not-exist"
            snapshot = {"host": good(available=1), "guests": {}}
            with patch.object(guard, "PROJECT", root):
                code, result = guard.supervise(["touch", str(marker)], DEFAULT, root,
                    sampler=lambda *_: snapshot, stopper=lambda *_: self.fail("preflight stopped a VM"))
            self.assertEqual(code, 75)
            self.assertEqual(result["status"], "stopped")
            self.assertFalse(marker.exists())
            self.assertFalse((root / "receipts/execution.json").exists())

    def test_resource_stop_kills_child_tree_and_persists_failure_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "late-write"
            policy = dict(DEFAULT, sample_interval_seconds=0.02)
            snapshots = [{"host": good(), "guests": {"nexus": good(oom=0)}},
                         {"host": good(), "guests": {"nexus": good(oom=1)}}]
            stopped = []
            def stop_fixture(_):
                partial = json.loads((root / 'receipts/resource-stop.json').read_text())
                self.assertEqual(partial['vm_shutdown_state'], 'pending')
                self.assertTrue(partial['workflow_stop_confirmed'])
                stopped.append(True)
                return {'nexus': {'state': 'shut off'}}
            with patch.object(guard, "PROJECT", root):
                code, result = guard.supervise(["/bin/sh", "-c", '(sleep 0.5; touch "$1") & wait', "fixture", str(marker)],
                    policy, root, sampler=lambda *_: snapshots.pop(0),
                    stopper=stop_fixture)
            self.assertEqual(code, 75)
            self.assertEqual(stopped, [True])
            self.assertEqual(result["reasons"], ["nexus:oom_kill"])
            self.assertEqual(json.loads((root / "receipts/resource-stop.json").read_text()), result)
            time.sleep(0.6)
            self.assertFalse(marker.exists())
            self.assertEqual(len((root / "logs/resource-samples.jsonl").read_text().splitlines()), 2)

    def test_policy_drift_fails_before_running_a_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guard.write_json(root / "facts/resource-policy.json", dict(DEFAULT, consecutive_samples=4))
            with self.assertRaisesRegex(ValueError, "changed"):
                guard.supervise(["false"], DEFAULT, root)


if __name__ == "__main__":
    unittest.main()
