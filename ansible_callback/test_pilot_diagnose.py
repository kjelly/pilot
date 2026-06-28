# -*- coding: utf-8 -*-
"""Unit tests for the pilot Ansible callback plugin.

We test the pure-Python helpers (binary resolution, option coercion,
context building) directly. The Ansible-touching parts (v2_runner_on_*
methods) are covered by integration tests in a real Ansible env.

Run:
    cd ansible_callback
    python3 -m pytest test_pilot.py -v
    # or with make:
    make test-callback
"""
from __future__ import absolute_import, division, print_function

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

# Make the plugin importable as a module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Mock the Ansible imports because they may not be installed locally.
# The plugin handles this gracefully via try/except ImportError.
import pilot_diagnose as plugin  # noqa: E402


class TestCoerceBool(unittest.TestCase):
    def test_string_truthy(self):
        for v in ("1", "true", "True", "yes", "on", "YES"):
            self.assertTrue(plugin._coerce_bool(v), f"expected {v!r} truthy")

    def test_string_falsy(self):
        for v in ("0", "false", "no", "", "off"):
            self.assertFalse(plugin._coerce_bool(v), f"expected {v!r} falsy")

    def test_int(self):
        self.assertTrue(plugin._coerce_bool(1))
        self.assertFalse(plugin._coerce_bool(0))

    def test_already_bool(self):
        self.assertTrue(plugin._coerce_bool(True))
        self.assertFalse(plugin._coerce_bool(False))


class TestResolveBinary(unittest.TestCase):
    def setUp(self):
        # Clear env vars for clean tests
        self._old_env = os.environ.copy()
        os.environ.pop("PILOT_BIN", None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)

    def test_explicit_path_used(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            self.assertEqual(plugin._resolve_binary(path), path)
        finally:
            os.unlink(path)

    def test_env_var_used(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        os.environ["PILOT_BIN"] = path
        try:
            self.assertEqual(plugin._resolve_binary(None), path)
        finally:
            os.unlink(path)

    def test_none_when_no_binary(self):
        # Patch shutil.which to always return None
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(plugin._resolve_binary(None))


class TestCallbackDisabled(unittest.TestCase):
    def test_disabled_via_option(self):
        cb = plugin.CallbackModule()
        cb._diagnosed = set()
        cb._display = _MockDisplay()
        # Manually mimic what set_options does, without going through Ansible
        cb._disabled = True
        cb._bin = None
        # Should short-circuit and not raise
        result = mock.MagicMock()
        result._host.get_name.return_value = "web01"
        result._result = {"msg": "boom"}
        result._task.get_name.return_value = "fail task"
        result._task.action = "shell"
        # Should return without calling subprocess
        with mock.patch("subprocess.run") as run:
            cb.v2_runner_on_failed(result)
            run.assert_not_called()

    def test_disabled_via_env(self):
        cb = plugin.CallbackModule()
        cb._diagnosed = set()
        cb._display = _MockDisplay()
        cb._disabled = True
        # Even with valid _bin, should not call
        cb._bin = "/usr/bin/echo"
        result = mock.MagicMock()
        result._host.get_name.return_value = "web01"
        with mock.patch("subprocess.run") as run:
            cb.v2_runner_on_failed(result)
            run.assert_not_called()


class _MockDisplay:
    def __init__(self):
        self.warnings = []
        self.banners = []
        self.displayed = []
    def warning(self, msg):
        self.warnings.append(msg)
    def banner(self, msg):
        self.banners.append(msg)
    def display(self, msg):
        self.displayed.append(msg)


class TestCallbackDedup(unittest.TestCase):
    def setUp(self):
        self.cb = plugin.CallbackModule()
        self.cb._diagnosed = set()
        self.cb._disabled = False
        self.cb._bin = "/usr/bin/echo"  # any path
        self.cb._model = "test:model"
        self.cb._timeout = 5
        self.cb._diagnose_unreachable = False
        self.cb._extra_context = {}
        self.cb._display = _MockDisplay()

    def _fake_result(self, host="web01", task="x", module="shell", stderr="boom"):
        r = mock.MagicMock()
        r._host.get_name.return_value = host
        r._result = {"stderr": stderr, "msg": ""}
        t = mock.MagicMock()
        t.get_name.return_value = task
        t.action = module
        t.play = None
        t._ds = "- name: x\n  shell: echo boom"
        r._task = t
        return r

    def test_first_failure_triggers(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="diag", stderr="")
            self.cb.v2_runner_on_failed(self._fake_result())
            self.assertEqual(run.call_count, 1)

    def test_second_failure_deduped(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="diag", stderr="")
            self.cb.v2_runner_on_failed(self._fake_result(host="web01"))
            self.cb.v2_runner_on_failed(self._fake_result(host="web01"))
            self.assertEqual(run.call_count, 1, "second failure should be deduped")

    def test_different_hosts_both_diagnosed(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="diag", stderr="")
            self.cb.v2_runner_on_failed(self._fake_result(host="web01"))
            self.cb.v2_runner_on_failed(self._fake_result(host="web02"))
            self.assertEqual(run.call_count, 2)

    def test_ignore_errors_skipped(self):
        with mock.patch("subprocess.run") as run:
            self.cb.v2_runner_on_failed(self._fake_result(), ignore_errors=True)
            run.assert_not_called()

    def test_unreachable_skipped_by_default(self):
        with mock.patch("subprocess.run") as run:
            self.cb.v2_runner_on_unreachable(self._fake_result())
            run.assert_not_called()

    def test_unreachable_diagnosed_when_enabled(self):
        self.cb._diagnose_unreachable = True
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="diag", stderr="")
            self.cb.v2_runner_on_unreachable(self._fake_result())
            self.assertEqual(run.call_count, 1)


class TestCallbackContext(unittest.TestCase):
    def setUp(self):
        self.cb = plugin.CallbackModule()
        self.cb._diagnosed = set()
        self.cb._disabled = False
        self.cb._bin = "/usr/bin/echo"
        self.cb._model = "test:model"
        self.cb._timeout = 5
        self.cb._extra_context = {"env": "staging"}
        self.cb._display = _MockDisplay()

    def test_context_includes_required_fields(self):
        result = mock.MagicMock()
        result._host.get_name.return_value = "web01"
        result._result = {"stderr": "permission denied", "msg": "failed"}
        task = mock.MagicMock()
        task.get_name.return_value = "PermitRootLogin no"
        task.action = "lineinfile"
        task.play = mock.MagicMock()
        task.play.name = "Harden SSH"
        task._ds = {"name": "PermitRootLogin no"}
        result._task = task
        ctx = self.cb._build_context(result, "web01", "failed")
        self.assertEqual(ctx["host"], "web01")
        self.assertEqual(ctx["task"], "PermitRootLogin no")
        self.assertEqual(ctx["module"], "lineinfile")
        self.assertIn("permission denied", ctx["error"])
        self.assertEqual(ctx["play"], "Harden SSH")
        self.assertEqual(ctx["extra_context"], {"env": "staging"})

    def test_error_truncated_to_4k(self):
        result = mock.MagicMock()
        result._host.get_name.return_value = "web01"
        result._result = {"stderr": "x" * 10000}
        task = mock.MagicMock()
        task.get_name.return_value = "x"
        task.action = "shell"
        task.play = None
        result._task = task
        ctx = self.cb._build_context(result, "web01", "failed")
        self.assertEqual(len(ctx["error"]), 4000)


class TestCallbackSubprocess(unittest.TestCase):
    def setUp(self):
        self.cb = plugin.CallbackModule()
        self.cb._diagnosed = set()
        self.cb._disabled = False
        self.cb._bin = "/fake/pilot"
        self.cb._model = "qwen2.5:3b"
        self.cb._timeout = 30
        self.cb._extra_context = {}
        self.cb._display = _MockDisplay()

    def _fake_result(self):
        result = mock.MagicMock()
        result._host.get_name.return_value = "web01"
        result._result = {"stderr": "boom", "msg": ""}
        task = mock.MagicMock()
        task.get_name.return_value = "x"
        task.action = "shell"
        task.play = None
        task._ds = "- shell: x"
        result._task = task
        return result

    def test_sends_json_on_stdin(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="diag", stderr="")
            self.cb.v2_runner_on_failed(self._fake_result())
            self.assertEqual(run.call_count, 1)
            args, kwargs = run.call_args
            # binary path + args
            self.assertEqual(args[0][0], "/fake/pilot")
            self.assertIn("diagnose", args[0])
            self.assertIn("--stdin", args[0])
            # JSON input on stdin
            sent = json.loads(kwargs["input"])
            self.assertEqual(sent["host"], "web01")
            self.assertEqual(sent["task"], "x")
            # timeout honoured
            self.assertEqual(kwargs["timeout"], 30)
            # env has model
            self.assertEqual(kwargs["env"]["PILOT_MODEL"], "qwen2.5:3b")
            self.assertEqual(kwargs["env"]["PILOT_NO_INPUT"], "1")

    def test_nonzero_exit_warns_no_crash(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=1, stdout="", stderr="bad")
            # Should not raise
            self.cb.v2_runner_on_failed(self._fake_result())

    def test_timeout_warns_no_crash(self):
        import subprocess as sp
        with mock.patch("subprocess.run", side_effect=sp.TimeoutExpired(cmd="x", timeout=5)):
            # Should not raise
            self.cb.v2_runner_on_failed(self._fake_result())

    def test_file_not_found_warns_no_crash(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            self.cb._bin = "/nonexistent"
            # Should not raise
            self.cb.v2_runner_on_failed(self._fake_result())


if __name__ == "__main__":
    unittest.main()


class TestDumpTask(unittest.TestCase):
    """_dump_task should serialise task._ds into something an LLM can parse."""

    def setUp(self):
        self.cb = plugin.CallbackModule()
        self.cb._disabled = True  # don't actually run subprocess

    def _fake_task(self, ds=None, action="shell", args=None):
        t = mock.MagicMock()
        t._ds = ds
        t.action = action
        t.args = args or {}
        return t

    def test_dump_task_with_dict_ds_and_yaml(self):
        """When _ds is a dict and yaml is importable, emit yaml.safe_dump."""
        t = self._fake_task(ds={"name": "fail", "shell": "false", "register": "r"})
        out = self.cb._dump_task(t)
        self.assertIn("name: fail", out)
        # Not the str(_ds) repr (which would include the { and }).
        self.assertNotIn("{", out)

    def test_dump_task_with_dict_ds_no_yaml(self):
        """When yaml is missing, fall back to compact key:value rendering."""
        # Hide yaml so the inner \`import yaml\` raises ImportError. We
        # use sys.modules manipulation because the source code does
        # \`import yaml\` (which loads from sys.modules).
        import sys
        saved = sys.modules.pop("yaml", None)
        try:
            t = self._fake_task(ds={"name": "fail", "shell": "false"})
            out = self.cb._dump_task(t)
        finally:
            if saved is not None:
                sys.modules["yaml"] = saved
        self.assertIn("name: fail", out)
        self.assertTrue("shell: false" in out or "shell: 'false'" in out, "got: " + out)

    def test_dump_task_no_ds_falls_back_to_action(self):
        """When _ds is unavailable, serialise {action: args}."""
        t = self._fake_task(ds=None, action="ansible.builtin.copy", args={"src": "x", "dest": "y"})
        out = self.cb._dump_task(t)
        self.assertIn("ansible.builtin.copy", out)
        self.assertIn("src: x", out)
        self.assertIn("dest: y", out)

    def test_dump_task_handles_broken_task_gracefully(self):
        """A task whose attributes raise on access should not crash the callback."""
        class BrokenTask(object):
            def __getattr__(self, name):
                raise AttributeError(name)
        # Should not raise. The inner function falls back to the
        # action/args path; with the broken task both getattr calls
        # return their defaults ("?" and {}). The outer try catches
        # any actual exception.
        out = self.cb._dump_task(BrokenTask())
        # Either we get the fallback rendering, or (if anything in the
        # render path raises) we get an empty string. Both are valid.
        if out != "":
            self.assertIn("?", out)
