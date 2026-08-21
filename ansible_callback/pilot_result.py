# -*- coding: utf-8 -*-
# Ansible callback plugin: pilot_result
#
# Writes a machine-readable JSON-lines record of unreachable/failed events
# and final per-host stats for one ansible-playbook run, so pilot (the Go
# CLI) can safely tell "an optional host went offline mid-run" apart from
# a real configuration failure. See spec.md, "Pilot Optional-Host
# Deployment Availability Specification", §17.
#
# This callback NEVER replaces the default stdout callback (CALLBACK_TYPE
# = "notification") — the operator keeps seeing normal streaming
# ansible-playbook output. It is also inert unless explicitly enabled, so
# it never changes the behavior of a direct, manually invoked
# ansible-playbook run outside pilot's own deploy/reconcile flows.
#
# Enable ad-hoc (no ansible.cfg change needed):
#   ANSIBLE_CALLBACK_PLUGINS=/path/to/ansible_callback \
#   ANSIBLE_CALLBACKS_ENABLED=pilot_result \
#   PILOT_ANSIBLE_RESULT_FILE=/path/to/result.jsonl \
#   ansible-playbook site.yml
#
# Configuration:
#   PILOT_ANSIBLE_RESULT_FILE   path to the JSON-lines output file.
#                               If unset, the callback is a silent no-op.
#
# Written events never include module arguments, secret values, task
# result payloads, vault content, or environment secrets — only host
# name, task name, event type, a classified unreachable reason, and
# per-host stat counts.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
callback: pilot_result
short_description: Structured, secret-free per-run result events for pilot's deployment-availability feature
version_added: "0.1.0"
description:
  - Writes JSON-lines events (unreachable / failed / final stats) to the
    file named by the PILOT_ANSIBLE_RESULT_FILE environment variable.
  - No-op when that environment variable is unset.
  - Never replaces the default stdout callback.
options: {}
requirements:
  - none (Python standard library only)
"""

import json
import os

# Ansible may be unavailable in test contexts; guard the import exactly
# like ansible_callback/pilot_diagnose.py does.
try:
    from ansible.plugins.callback import CallbackBase
except ImportError:  # pragma: no cover
    CallbackBase = object

RESULT_FILE_ENV = "PILOT_ANSIBLE_RESULT_FILE"

# Tolerated transport-offline classes (spec §17.4) — the only reasons an
# optional host's unreachable result may later be treated as an expected
# offline VM rather than a real defect.
TOLERATED_REASONS = (
    "connection_refused",
    "connection_timeout",
    "network_unreachable",
    "host_unreachable",
    "no_route",
    "connection_reset",
    "connection_closed",
)

# Explicitly fatal classes (spec §17.4) — never tolerated, regardless of
# deployment_availability policy.
FATAL_REASONS = (
    "authentication_failed",
    "host_key_verification_failed",
    "identity_file_error",
    "permission_denied",
    "unsupported_connection",
    "unknown",
)


def classify_unreachable_reason(message):
    """Classify an Ansible unreachable result message into one of
    TOLERATED_REASONS + FATAL_REASONS.

    Conservative by design (spec §17.4): any message this function does
    not recognize classifies as "unknown", which is fatal. Silently
    tolerating an unrecognized unreachable reason could hide a real
    defect (bad credentials, broken DNS, a misconfigured firewall rule)
    behind "it's just an offline optional VM".
    """
    text = (message or "").lower()

    if "host key verification failed" in text:
        return "host_key_verification_failed"
    if "permission denied" in text and ("publickey" in text or "password" in text):
        return "authentication_failed"
    if "permission denied" in text:
        return "permission_denied"
    if (
        "no such identity" in text
        or "identity file" in text
        or ("could not find" in text and "identity" in text)
    ):
        return "identity_file_error"
    if "unsupported connection" in text or (
        "connection type" in text and "not supported" in text
    ):
        return "unsupported_connection"
    if "no route to host" in text:
        return "no_route"
    if "network is unreachable" in text:
        return "network_unreachable"
    if "connection refused" in text:
        return "connection_refused"
    if "connection reset" in text:
        return "connection_reset"
    if (
        "connection timed out" in text
        or "operation timed out" in text
        or "timed out" in text
        or "timeout" in text
    ):
        return "connection_timeout"
    if ("connection closed" in text) or (
        "shared connection to" in text and "closed" in text
    ):
        return "connection_closed"
    if "host is unreachable" in text:
        return "host_unreachable"
    return "unknown"


class CallbackModule(CallbackBase):
    """Ansible callback that records structured, secret-free result
    events for pilot's deployment-availability feature."""

    CALLBACK_NAME = "pilot_result"
    CALLBACK_TYPE = "notification"
    CALLBACK_NEEDS_ENABLED = True  # inert unless ANSIBLE_CALLBACKS_ENABLED=pilot_result

    def __init__(self):
        if CallbackBase is object:
            return  # test stub
        super(CallbackModule, self).__init__()
        self._path = os.environ.get(RESULT_FILE_ENV, "")

    # ---- internals ---------------------------------------------------------

    def _write(self, event):
        if not self._path:
            return
        try:
            with open(self._path, "a") as f:
                f.write(json.dumps(event, sort_keys=True))
                f.write("\n")
        except OSError:
            # Writing evidence must never break the actual playbook run.
            pass

    def _host_name(self, result):
        try:
            return result._host.get_name()
        except Exception:
            return "unknown"

    def _task_name(self, result):
        try:
            return result._task.get_name()
        except Exception:
            return "(unknown)"

    def _result_message(self, result):
        try:
            return result._result.get("msg", "") or ""
        except Exception:
            return ""

    # ---- Ansible event hooks ------------------------------------------------

    def v2_runner_on_unreachable(self, result):
        self._write(
            {
                "event": "unreachable",
                "host": self._host_name(result),
                "reason": classify_unreachable_reason(self._result_message(result)),
            }
        )

    def v2_runner_on_failed(self, result, ignore_errors=False):
        if ignore_errors:
            return
        self._write(
            {
                "event": "failed",
                "host": self._host_name(result),
                "task": self._task_name(result),
            }
        )

    def v2_playbook_on_stats(self, stats):
        hosts = {}
        try:
            for host in stats.processed.keys():
                hosts[host] = stats.summarize(host)
        except Exception:
            hosts = {}
        self._write({"event": "stats", "hosts": hosts})
