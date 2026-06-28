# -*- coding: utf-8 -*-
# Ansible callback plugin: pilot
#
# Sends Ansible task failures to pilot, which calls an Ollama LLM
# to produce a root-cause analysis. The diagnosis is printed inline in
# the playbook output.
#
# pilot is a Go binary from https://github.com/anomalyco/pilot
#
# Install:
#   User:   make install-callback-user      (~/.ansible/plugins/callback/)
#   System: sudo make install-callback-system  (/etc/ansible/plugins/callback/)
#
# Enable in ansible.cfg:
#   [defaults]
#   callbacks_enabled = pilot
#
# Or invoke ad-hoc:
#   ANSIBLE_CALLBACKS_ENABLED=pilot ansible-playbook site.yml
#
# Configuration (precedence: env > ansible.cfg > default):
#   PILOT_BIN       path to pilot binary (default: search PATH, fallback /usr/local/bin/pilot)
#   PILOT_MODEL     Ollama model name   (default: qwen3.5:cloud)
#   PILOT_TIMEOUT   seconds             (default: 60)
#   PILOT_DISABLE   1 to disable        (default: 0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
callback: pilot
short_description: AI diagnosis of Ansible failures via pilot + Ollama
version_added: "0.1.0"
description:
  - When a task fails, sends context (host, task, module, error, task YAML)
    to the pilot binary.
  - pilot sanitises the input and forwards it to an Ollama LLM for
    root-cause analysis and fix suggestions.
  - The diagnosis is displayed inline in the playbook output, under a
    "🤖 pilot 診斷" banner.
  - The plugin is no-op when the pilot binary cannot be found.
options:
  binary:
    description: Path to the pilot binary.
    default: /usr/local/bin/pilot
    env:
      - name: PILOT_BIN
  model:
    description: Ollama model name to use.
    default: qwen3.5:cloud
    env:
      - name: PILOT_MODEL
  timeout:
    description: Subprocess timeout in seconds.
    default: 60
    type: int
    env:
      - name: PILOT_TIMEOUT
  diagnose_unreachable:
    description: Also diagnose unreachable hosts.
    default: false
    type: bool
  disable:
    description: Disable the plugin (no-op).
    default: false
    env:
      - name: PILOT_DISABLE
  extra_context:
    description: Extra context fields to include in the AI prompt (key/value map).
    type: dict
    default: {}
requirements:
  - pilot installed and on PATH (or pointed to by PILOT_BIN)
"""

import json
import os
import shutil
import subprocess
import sys

# Ansible may be unavailable in test contexts; guard imports.
try:
    from ansible.plugins.callback import CallbackBase
    from ansible.errors import AnsibleError
except ImportError:  # pragma: no cover
    CallbackBase = object
    AnsibleError = Exception


_IS_PY3 = sys.version_info[0] >= 3
_DEFAULT_BIN = "/usr/local/bin/pilot"


def _coerce_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() in ("1", "true", "yes", "on")
    if isinstance(v, int):
        return bool(v)
    return False


def _resolve_binary(option_value):
    """Resolve pilot binary path. Precedence: option > env > PATH > default."""
    if option_value and os.path.isfile(option_value):
        return option_value
    env = os.environ.get("PILOT_BIN")
    if env and os.path.isfile(env):
        return env
    on_path = shutil.which("pilot")
    if on_path:
        return on_path
    if os.path.isfile(_DEFAULT_BIN):
        return _DEFAULT_BIN
    return None


class CallbackModule(CallbackBase):
    """Ansible callback that calls pilot for AI failure diagnosis."""

    CALLBACK_NAME = "pilot"
    CALLBACK_TYPE = "notification"
    CALLBACK_NEEDS_ENABLED = False  # the wrapper turns us on/off; we always run unless disabled

    def __init__(self):
        if CallbackBase is object:
            return  # test stub
        super(CallbackModule, self).__init__()
        self._diagnosed = set()  # per-host dedup, in-memory
        self._bin = None
        self._model = None
        self._timeout = 60
        self._diagnose_unreachable = False
        self._disabled = False
        self._extra_context = {}

    # ---- Ansible option plumbing ------------------------------------------

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super(CallbackModule, self).set_options(
            task_keys=task_keys, var_options=var_options, direct=direct
        )
        # Resolve disable first
        opt_disable = self.get_option("disable")
        env_disable = os.environ.get("PILOT_DISABLE") == "1"
        self._disabled = _coerce_bool(opt_disable) or env_disable
        if self._disabled:
            return

        self._bin = _resolve_binary(self.get_option("binary"))
        if not self._bin:
            self._display.warning(
                "[pilot] binary not found; callback will be a no-op. "
                "Set PILOT_BIN or install pilot."
            )
            self._disabled = True
            return

        self._model = (
            self.get_option("model") or os.environ.get("PILOT_MODEL", "qwen3.5:cloud")
        )
        self._timeout = int(
            self.get_option("timeout") or os.environ.get("PILOT_TIMEOUT", 60)
        )
        self._diagnose_unreachable = _coerce_bool(self.get_option("diagnose_unreachable"))
        try:
            self._extra_context = dict(self.get_option("extra_context") or {})
        except (KeyError, TypeError, ValueError):
            self._extra_context = {}

    # ---- Ansible event hooks ----------------------------------------------

    def v2_runner_on_failed(self, result, ignore_errors=False):
        if self._disabled or ignore_errors:
            return
        host = self._host_name(result)
        if not host or host in self._diagnosed:
            return
        self._diagnosed.add(host)
        self._diagnose(result, host, "failed")
        self._prompt_and_fix(host)

    def v2_runner_on_unreachable(self, result):
        if self._disabled or not self._diagnose_unreachable:
            return
        host = self._host_name(result)
        if not host or host in self._diagnosed:
            return
        self._diagnosed.add(host)
        self._diagnose(result, host, "unreachable")

    def v2_playbook_on_stats(self, stats):
        # Reset dedup at end-of-run so subsequent runs re-diagnose.
        self._diagnosed.clear()

    # ---- Internals --------------------------------------------------------

    def _host_name(self, result):
        try:
            return result._host.get_name()
        except Exception:
            return "localhost"

    def _dump_task(self, task):
        """Serialise the failing task for the LLM prompt.

        Prefers task._ds (the original parsed dict) and falls back to a
        hand-rolled {action, args} view if _ds is unavailable. Uses
        yaml.safe_dump when PyYAML is importable; otherwise emits a
        compact repr that the LLM can still parse.
        """
        try:
            return self._dump_task_inner(task)
        except Exception:
            return ""

    def _dump_task_inner(self, task):
        try:
            ds = getattr(task, "_ds", None)
            if isinstance(ds, dict):
                try:
                    import yaml
                    return yaml.safe_dump(ds, default_flow_style=False, sort_keys=False)
                except ImportError:
                    # No yaml — emit a compact "key: value" rendering.
                    parts = []
                    for k, v in ds.items():
                        if isinstance(v, (list, dict)):
                            parts.append("%s: %r" % (k, v))
                        else:
                            parts.append("%s: %s" % (k, v))
                    return "\n".join(parts)
            action = getattr(task, "action", "?")
            args = getattr(task, "args", {}) or {}
            try:
                import yaml
                return yaml.safe_dump({action: args}, default_flow_style=False, sort_keys=False)
            except ImportError:
                parts = ["%s:" % action]
                for k, v in sorted(args.items()):
                    parts.append("  %s: %s" % (k, v))
                return "\n".join(parts)
        except Exception:
            return ""

    def _build_context(self, result, host, kind):
        task = result._task
        ctx = {
            "host": host,
            "kind": kind,
            "task": task.get_name() if hasattr(task, "get_name") else "(unknown)",
            "module": getattr(task, "action", ""),
            "error": (result._result.get("stderr", "") or
                      result._result.get("msg", "") or
                      result._result.get("module_stderr", "") or "")[:4000],
            "task_yaml": self._dump_task(task),
            "play": task.play.name if getattr(task, "play", None) else "",
        }
        if self._extra_context:
            ctx["extra_context"] = dict(self._extra_context)
        return ctx

    def _diagnose(self, result, host, kind):
        ctx = self._build_context(result, host, kind)
        env = os.environ.copy()
        env["PILOT_MODEL"] = self._model or "qwen3.5:cloud"
        env["PILOT_NO_INPUT"] = "1"
        bin_path = self._bin
        if not bin_path:
            return
        try:
            proc = subprocess.run(
                [bin_path, "diagnose", "--stdin", "--quiet", "--output", "stdout"],
                input=json.dumps(ctx),
                text=True,
                capture_output=True,
                timeout=self._timeout,
                env=env,
            )
        except FileNotFoundError:
            self._display.warning(
                "[pilot] binary %r vanished; skipping" % self._bin
            )
            return
        except subprocess.TimeoutExpired:
            self._display.warning(
                "[pilot] timed out after %ds for %s" % (self._timeout, host)
            )
            return
        except Exception as e:  # noqa: BLE001
            self._display.warning("[pilot] call failed: %s" % e)
            return

        if proc.returncode != 0:
            self._display.warning(
                "[pilot] exited %d: %s" % (proc.returncode, proc.stderr.strip()[:200])
            )
            return

        diagnosis = proc.stdout.strip()
        if not diagnosis:
            return

        try:
            self._display.banner("🤖 pilot 診斷 (%s / %s)" % (host, kind))
            # display() expects a string or list-of-strings; some Ansible
            # versions also accept "\n".join for multi-line.
            self._display.display(diagnosis)
        except Exception as e:  # noqa: BLE001
            # Last-resort: write to stderr so the user sees it.
            sys.stderr.write("\n🤖 pilot 診斷 (%s / %s):\n%s\n" % (host, kind, diagnosis))

    def _prompt_and_fix(self, host):
        if not sys.stdin.isatty():
            return
        try:
            # Python 2/3 compatibility
            prompt_func = input if sys.version_info[0] >= 3 else raw_input
            ans = prompt_func("\n⚠️  Ansible task failed! Would you like pilot to try to automatically fix this failure? [y/N]: ")
            if ans.strip().lower() in ("y", "yes"):
                playbook = None
                for arg in sys.argv:
                    if arg.endswith('.yml') or arg.endswith('.yaml'):
                        if os.path.exists(arg):
                            playbook = arg
                            break
                if playbook and self._bin:
                    cmd = [self._bin, "run", playbook]
                    if host:
                        cmd.extend(["--limit", host])
                    for i, arg in enumerate(sys.argv):
                        if arg in ("-i", "--inventory") and i + 1 < len(sys.argv):
                            cmd.extend(["-i", sys.argv[i+1]])
                            break
                    print("\n▶ Launching pilot to resolve the failure...")
                    subprocess.run(cmd)
        except Exception as e:
            self._display.warning("[pilot] prompt-and-fix failed: %s" % e)
