# -*- coding: utf-8 -*-
"""Unit tests for the pilot_result Ansible callback plugin.

Pure-Python stdlib tests only — no real ansible-playbook run, no external
libraries. Run:

    cd ansible_callback
    python3 -m unittest test_pilot_result.py -v
    # or with make:
    make test-callback
"""
from __future__ import absolute_import, division, print_function

import json
import os
import sys
import tempfile
import unittest

# Make the plugin importable as a module, exactly like test_pilot_diagnose.py.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pilot_result as plugin  # noqa: E402


class _FakeHost(object):
    def __init__(self, name):
        self._name = name

    def get_name(self):
        return self._name


class _FakeTask(object):
    def __init__(self, name):
        self._name = name

    def get_name(self):
        return self._name


class _FakeResult(object):
    def __init__(self, host, task=None, result=None):
        self._host = _FakeHost(host)
        self._task = _FakeTask(task or "(unknown)")
        self._result = result or {}


class _FakeStats(object):
    def __init__(self, per_host):
        self.processed = {h: 1 for h in per_host}
        self._per_host = per_host

    def summarize(self, host):
        base = dict(
            ok=0, changed=0, failures=0, unreachable=0, skipped=0, rescued=0, ignored=0
        )
        base.update(self._per_host[host])
        return base


class TestClassifyUnreachableReason(unittest.TestCase):
    def test_tolerated_reasons(self):
        cases = {
            "connection_refused": "Failed to connect to the host via ssh: ssh: connect to host 10.0.0.5 port 22: Connection refused",
            "connection_timeout": "ssh: connect to host 10.0.0.5 port 22: Operation timed out",
            "network_unreachable": "ssh: connect to host 10.0.0.5 port 22: Network is unreachable",
            "host_unreachable": "Host is unreachable",
            "no_route": "ssh: connect to host 10.0.0.5 port 22: No route to host",
            "connection_reset": "Connection reset by peer during handshake",
            "connection_closed": "Shared connection to 10.0.0.5 closed.",
        }
        for expected, message in cases.items():
            self.assertEqual(
                plugin.classify_unreachable_reason(message), expected, msg=message
            )

    def test_fatal_reasons(self):
        cases = {
            "authentication_failed": "Permission denied (publickey,password).",
            "permission_denied": "Permission denied (sudo).",
            "host_key_verification_failed": "Host key verification failed.",
            "identity_file_error": "Warning: Identity file /home/x/.ssh/id_missing not accessible: No such file or directory.",
            "unknown": "some completely novel error text nobody has seen before",
        }
        for expected, message in cases.items():
            self.assertEqual(
                plugin.classify_unreachable_reason(message), expected, msg=message
            )

    def test_unsupported_connection(self):
        self.assertEqual(
            plugin.classify_unreachable_reason(
                "the connection type winrm is not supported on this host"
            ),
            "unsupported_connection",
        )

    def test_empty_message_is_unknown(self):
        self.assertEqual(plugin.classify_unreachable_reason(""), "unknown")
        self.assertEqual(plugin.classify_unreachable_reason(None), "unknown")

    def test_tolerated_and_fatal_sets_are_disjoint(self):
        self.assertEqual(
            set(plugin.TOLERATED_REASONS) & set(plugin.FATAL_REASONS), set()
        )


class TestCallbackModuleEvents(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.copy()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)

    def _new_module(self, path):
        os.environ[plugin.RESULT_FILE_ENV] = path
        cb = plugin.CallbackModule()
        cb._path = path
        return cb

    def _read_events(self, path):
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_unreachable_event_written_with_classified_reason(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            cb = self._new_module(path)
            result = _FakeResult(
                "dev-vm-01", result={"msg": "Connection refused"}
            )
            cb.v2_runner_on_unreachable(result)
            events = self._read_events(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event"], "unreachable")
            self.assertEqual(events[0]["host"], "dev-vm-01")
            self.assertEqual(events[0]["reason"], "connection_refused")
            self.assertEqual(set(events[0].keys()), {"event", "host", "reason"})
        finally:
            os.unlink(path)

    def test_failed_event_written_without_task_args_or_secrets(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            cb = self._new_module(path)
            result = _FakeResult(
                "dev-vm-02",
                task="Install package",
                result={
                    "msg": "boom",
                    "password": "should-never-appear",
                    "some_module_arg": "also-should-never-appear",
                },
            )
            cb.v2_runner_on_failed(result)
            events = self._read_events(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event"], "failed")
            self.assertEqual(events[0]["host"], "dev-vm-02")
            self.assertEqual(events[0]["task"], "Install package")
            self.assertEqual(set(events[0].keys()), {"event", "host", "task"})
            with open(path) as f:
                raw = f.read()
            self.assertNotIn("should-never-appear", raw)
            self.assertNotIn("also-should-never-appear", raw)
        finally:
            os.unlink(path)

    def test_failed_event_skipped_when_ignore_errors(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            cb = self._new_module(path)
            cb.v2_runner_on_failed(_FakeResult("dev-vm-02"), ignore_errors=True)
            self.assertEqual(self._read_events(path), [])
        finally:
            os.unlink(path)

    def test_final_stats_event(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            cb = self._new_module(path)
            stats = _FakeStats(
                {
                    "ipa-1": {"ok": 5, "changed": 1},
                    "dev-vm-01": {"unreachable": 1},
                }
            )
            cb.v2_playbook_on_stats(stats)
            events = self._read_events(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event"], "stats")
            self.assertEqual(events[0]["hosts"]["ipa-1"]["changed"], 1)
            self.assertEqual(events[0]["hosts"]["dev-vm-01"]["unreachable"], 1)
            self.assertEqual(events[0]["hosts"]["dev-vm-01"]["failures"], 0)
        finally:
            os.unlink(path)

    def test_noop_when_env_var_unset(self):
        os.environ.pop(plugin.RESULT_FILE_ENV, None)
        cb = plugin.CallbackModule()
        cb._path = ""
        # Must not raise even though no file path was ever configured.
        cb.v2_runner_on_unreachable(_FakeResult("dev-vm-01"))
        cb.v2_runner_on_failed(_FakeResult("dev-vm-01"))
        cb.v2_playbook_on_stats(_FakeStats({}))

    def test_write_never_raises_on_unwritable_path(self):
        cb = plugin.CallbackModule()
        cb._path = "/nonexistent-directory-xyz/result.jsonl"
        # Must not raise — evidence-writing failures must never break the
        # actual playbook run (spec §17.2).
        cb._write({"event": "unreachable", "host": "h", "reason": "unknown"})


if __name__ == "__main__":
    unittest.main()
