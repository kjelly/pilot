#!/usr/bin/env python3
"""Journal/crash tests. Real SSSD/SSH acceptance is a separate VM gate."""
import base64
import copy
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
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
