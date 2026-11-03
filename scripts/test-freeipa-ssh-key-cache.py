#!/usr/bin/env python3
"""Journal/crash tests. Real SSSD/SSH acceptance is a separate VM gate."""
import base64
import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import subprocess
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "playbooks/apply/files/freeipa-ssh-key-cache.py"
SPEC = importlib.util.spec_from_file_location("ssh_cache", SOURCE)
cache = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cache)


def key(comment="test"):
    # A wire-format key for normalization tests, not a CLI-output fixture.
    raw = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"x" * 32
    return "ssh-ed25519 " + base64.b64encode(raw).decode() + " " + comment


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.state = {"version": 1, "domain": "ipa.test", "users": {}}

    def prepare(self, keys, hosts=None):
        return cache.update(self.state, "prepare", {
            "domain": "ipa.test", "hosts": hosts or ["a", "b"],
            "users": [{"name": "alice", "ssh_keys": keys}]})["prepared"]

    def settle(self, prepared, changed=False):
        return cache.update(self.state, "settle", {
            "domain": "ipa.test", "prepared": prepared,
            "changed_users": ["alice"] if changed else []})["work"]

    def ack(self, pairs):
        return cache.update(self.state, "ack", {
            "domain": "ipa.test", "verified": pairs})["pending"]

    def test_add_revoke_noop_and_unaffected_hosts(self):
        work = self.settle(self.prepare([key()]), True)
        self.assertEqual(2, len(work))
        self.assertEqual([], self.ack(work))
        self.assertEqual([], self.settle(self.prepare([key("new comment")])) )
        work = self.settle(self.prepare([]), True)
        self.assertTrue(all(pair["keys"] == [] for pair in work))
        self.assertEqual([], self.ack(work))
        self.assertEqual([], self.settle(self.prepare([])))
        self.assertEqual(["c"], [p["host"] for p in self.settle(self.prepare([], ["a", "b", "c"]))])

    def test_partial_retry_does_not_repeat_success(self):
        pairs = self.settle(self.prepare([key()]), True)
        self.assertEqual([{"host": "b", "user": "alice"}], self.ack(pairs[:1]))
        retry = self.settle(self.prepare([key()]))
        self.assertEqual(["b"], [p["host"] for p in retry])
        self.assertEqual([], self.ack(retry))

    def test_crash_before_settle_cannot_lose_work(self):
        self.ack(self.settle(self.prepare([key()]), True))
        self.prepare([])  # IPA may have completed; process stops here.
        self.assertEqual(2, len(self.settle(self.prepare([]))))

    def test_crash_during_noop_safely_retries(self):
        self.ack(self.settle(self.prepare([key()]), True))
        self.prepare([key()])
        self.assertEqual(2, len(self.settle(self.prepare([key()]))))

    def test_aba_and_late_ack_cannot_reuse_old_receipt(self):
        old = self.settle(self.prepare([key()]), True)
        self.ack(old)
        self.settle(self.prepare([]), True)  # B fails on both hosts.
        current = self.settle(self.prepare([key()]), True)
        self.assertEqual(2, len(current))
        with self.assertRaisesRegex(ValueError, "stale"):
            self.ack(old)
        self.assertEqual([], self.ack(current))

    def test_drift_changed_even_if_desired_digest_unchanged(self):
        self.ack(self.settle(self.prepare([key()]), True))
        self.assertEqual(2, len(self.settle(self.prepare([key()]), True)))

    def test_unmanaged_user_does_not_drop_existing_pending(self):
        self.settle(self.prepare([]), True)
        planned = cache.update(self.state, "prepare", {
            "domain": "ipa.test", "hosts": ["a", "b"], "users": []})
        self.assertEqual(2, len(self.settle(planned["prepared"])))

    def test_removed_enrollment_host_remains_pending_for_authorization(self):
        self.settle(self.prepare([key()], ["a", "old-prod"]), True)
        retry = self.settle(self.prepare([key()], ["a"]))
        self.assertEqual(["a", "old-prod"], [p["host"] for p in retry])
        # Changing desired keys also cannot silently acknowledge the old host.
        retry = self.settle(self.prepare([], ["a"]), True)
        self.assertEqual(["a", "old-prod"], [p["host"] for p in retry])

    def test_concurrent_prepare_cannot_settle_older_run(self):
        first = self.prepare([key()])
        self.prepare([])
        before = copy.deepcopy(self.state)
        with self.assertRaisesRegex(ValueError, "concurrent"):
            self.settle(first)
        self.assertEqual(before, self.state)

    def retirement(self, **overrides):
        return dict(alias="b", fqdn="retired.ipa.test", stage="sandbox",
                    reason="approved permanent retirement", origin="plan-226", **overrides)

    def retire(self, items=None):
        return cache.update(self.state, "retire", {"domain": "ipa.test",
            "stage": "sandbox", "retirements": items or [self.retirement()]})

    def test_retirement_exact_omitted_users_and_stable_audit(self):
        self.settle(self.prepare([key()], ["a", "b", "b-10", "offline"]), True)
        self.state["users"]["omitted"] = copy.deepcopy(self.state["users"]["alice"])
        self.state["auth_pending"] = True
        before = copy.deepcopy(self.state)
        result = self.retire()
        self.assertTrue(result["changed"])
        self.assertEqual(2, result["retired"]["b"]["discharged"])
        self.assertEqual("retired", result["retired"]["b"]["result"])
        self.assertTrue(self.state["auth_pending"])
        for name, entry in self.state["users"].items():
            self.assertEqual(["a", "b-10", "offline"], entry["pending"])
            self.assertEqual(before["users"][name]["keys"], entry["keys"])
            self.assertEqual(before["users"][name]["hosts"], entry["hosts"])
            self.assertNotEqual(before["users"][name]["epoch"], entry["epoch"])
        settled = copy.deepcopy(self.state)
        self.assertFalse(self.retire()["changed"])
        self.assertEqual(settled, self.state)

    def test_retirement_rejects_late_settle_ack_and_resurrection(self):
        prepared = self.prepare([key()])
        pairs = self.settle(prepared, True)
        self.retire()
        before = copy.deepcopy(self.state)
        with self.assertRaisesRegex(ValueError, "concurrent"):
            self.settle(prepared)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.ack(pairs)
        with self.assertRaisesRegex(ValueError, "retired alias reuse"):
            self.prepare([])
        self.assertEqual(before, self.state)
        # A fresh live receipt can still finish remaining work.
        self.assertEqual([], self.ack(self.settle(self.prepare([key()], ["a"])) ))

    def test_retirement_mapping_is_exact_and_stage_bound(self):
        self.prepare([key()])
        data = {"domain": "ipa.test", "stage": "sandbox",
            "absent": [{"name": "RETIRED.ipa.test"}], "inventory": [
                {"alias": "b", "fqdn": "retired.ipa.test", "stage": "sandbox"},
                {"alias": "b-10", "fqdn": "other.ipa.test", "stage": "sandbox"}]}
        self.assertEqual(["b"], [r["alias"] for r in cache.update(self.state, "plan", data)["retirements"]])
        self.assertEqual(2, len(cache.work(self.state)))
        duplicate = copy.deepcopy(data)
        duplicate["inventory"].append(dict(duplicate["inventory"][0], alias="other"))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            cache.update(self.state, "plan", duplicate)
        data["inventory"] = []
        self.assertEqual([], cache.update(self.state, "plan", data)["retirements"])
        data["retirements"] = [self.retirement()]
        self.assertEqual([self.retirement()], cache.update(self.state, "plan", data)["retirements"])
        data["retirements"][0]["stage"] = "prod"
        with self.assertRaisesRegex(ValueError, "authorized stage"):
            cache.update(self.state, "plan", data)
        self.assertEqual(["a", "b"], self.state["users"]["alice"]["pending"])

    def test_readonly_inspection_and_atomic_retirement_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "missing", "journal.json")
            self.assertEqual([], cache.journal(path, "inspect", {"domain": "ipa.test"})["work"])
            self.assertFalse(Path(path).parent.exists())
            self.assertFalse(cache.journal(path, "retirement_status", {
                "domain": "ipa.test", "fqdn": "retired.ipa.test", "alias": "b", "stage": "sandbox"})["settled"])
            self.assertFalse(Path(path).parent.exists())
            self.prepare([key()])
            path = os.path.join(directory, "journal.json")
            Path(path).write_text(json.dumps(self.state))
            data = {"domain": "ipa.test", "stage": "sandbox", "retirements": [self.retirement()]}
            original = Path(path).read_bytes()
            with mock.patch.object(cache.os, "replace", side_effect=OSError("injected before commit")):
                with self.assertRaisesRegex(OSError, "before commit"):
                    cache.journal(path, "retire", data)
            self.assertEqual(original, Path(path).read_bytes())
            # A fresh process recovers and commits; retry observes one receipt.
            command = ["python3", str(SOURCE), "retire", path]
            first = subprocess.run(command, input=json.dumps(data), text=True, capture_output=True, check=True)
            self.assertTrue(json.loads(first.stdout)["changed"])
            second = subprocess.run(command, input=json.dumps(data), text=True, capture_output=True, check=True)
            self.assertFalse(json.loads(second.stdout)["changed"])
            self.assertEqual(1, len(json.loads(Path(path).read_text())["retired"]))

    def test_retirement_uses_process_lock_and_recovers_after_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            self.prepare([key()])
            path = os.path.join(directory, "journal.json")
            Path(path).write_text(json.dumps(self.state))
            data = {"domain": "ipa.test", "stage": "sandbox", "retirements": [self.retirement()]}
            with open(path + ".lock", "w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                process = subprocess.Popen(["python3", str(SOURCE), "retire", path],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    process.stdin.write(json.dumps(data))
                    process.stdin.close()
                    process.stdin = None
                    with self.assertRaises(subprocess.TimeoutExpired):
                        process.wait(timeout=0.15)
                    self.assertNotIn("retired", json.loads(Path(path).read_text()))
                    fcntl.flock(lock, fcntl.LOCK_UN)
                    out, err = process.communicate(timeout=5)
                    self.assertEqual(0, process.returncode, err)
                    self.assertTrue(json.loads(out)["changed"])
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
            # A directory-fsync failure occurs after the atomic replacement.
            Path(path).write_text(json.dumps(self.state))
            real_fsync = cache.os.fsync
            calls = 0
            def fail_directory(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected after replace")
                real_fsync(fd)
            with mock.patch.object(cache.os, "fsync", side_effect=fail_directory):
                with self.assertRaisesRegex(OSError, "after replace"):
                    cache.journal(path, "retire", data)
            before = Path(path).read_bytes()
            self.assertFalse(cache.journal(path, "retire", data)["changed"])
            self.assertEqual(before, Path(path).read_bytes())

    def test_retirement_receipt_identity_and_stage_are_exact(self):
        self.prepare([key()])
        self.retire()
        query = {"domain": "ipa.test", "fqdn": "RETIRED.ipa.test", "alias": "b", "stage": "sandbox"}
        self.assertTrue(cache.update(self.state, "retirement_status", query)["settled"])
        for field, other in (("fqdn", "other.ipa.test"), ("alias", "b-10"), ("stage", "prod")):
            self.assertFalse(cache.update(self.state, "retirement_status", dict(query, **{field: other}))["settled"])
        reuse = {"domain": "ipa.test", "stage": "sandbox", "absent": [{"name": "retired.ipa.test"}],
                 "inventory": [{"alias": "b", "fqdn": "new.ipa.test", "stage": "sandbox"}]}
        with self.assertRaisesRegex(ValueError, "identity/stage mismatch"):
            cache.update(self.state, "plan", reuse)

    def auth(self, action, **data):
        return cache.update(self.state, action, dict(data, domain="ipa.test"))

    def test_authorization_refresh_obligation(self):
        # Adoption cannot prove earlier runs refreshed every client.
        self.assertTrue(self.auth("auth_prepare")["previous"])
        self.assertTrue(self.auth("auth_settle", previous=True, changed=False)["dirty"])
        self.auth("auth_ack")
        # Completed no-op: nothing owed, nothing refreshed.
        previous = self.auth("auth_prepare")["previous"]
        self.assertFalse(previous)
        self.assertFalse(self.auth("auth_settle", previous=previous, changed=False)["dirty"])
        # A change settled without a refresh (tagged run) stays owed.
        self.auth("auth_prepare")
        self.assertTrue(self.auth("auth_settle", previous=False, changed=True)["dirty"])
        previous = self.auth("auth_prepare")["previous"]
        self.assertTrue(previous)
        self.assertTrue(self.auth("auth_settle", previous=previous, changed=False)["dirty"])
        # Interrupted before settle: prepare alone leaves it owed.
        self.auth("auth_ack")
        self.auth("auth_prepare")
        self.assertTrue(self.auth("auth_prepare")["previous"])
        # SSH-key journal entries alone do not record authorization state.
        self.state = {"version": 1, "domain": "ipa.test", "users": {}}
        self.prepare([key()])
        self.assertTrue(self.auth("auth_prepare")["previous"])

    def test_atomic_private_journal_and_corruption_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "state", "cache.json")
            cache.journal(path, "prepare", {"domain": "ipa.test", "hosts": ["a"], "users": []})
            self.assertEqual(0o600, os.stat(path).st_mode & 0o777)
            Path(path).write_text("not json")
            with self.assertRaises(ValueError):
                cache.journal(path, "ack", {"domain": "ipa.test", "verified": []})
            self.assertEqual("not json", Path(path).read_text())

    def test_malformed_and_extra_key_rejected(self):
        with self.assertRaises(ValueError):
            cache.keyset(["diagnostic text"])
        self.assertEqual(cache.keyset([key("a")]), cache.keyset([key("b"), key("c")]))
        result = mock.Mock(returncode=0, stdout=key())
        with mock.patch.object(cache.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                cache.refresh({"user": "alice", "domain": "ipa.test", "keys": []})

    def test_command_failure_and_shared_timeout_budget(self):
        results = [mock.Mock(returncode=0), mock.Mock(returncode=1, stdout="")]
        with mock.patch.object(cache.subprocess, "run", side_effect=results) as run:
            with self.assertRaisesRegex(RuntimeError, "lookup failed"):
                cache.refresh({"user": "alice", "domain": "ipa.test", "keys": []})
            self.assertLessEqual(run.call_args.kwargs["timeout"], 30)
            self.assertGreater(run.call_args.kwargs["timeout"], 0)


if __name__ == "__main__":
    unittest.main()
