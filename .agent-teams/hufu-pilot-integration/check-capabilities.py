#!/usr/bin/env python3
"""Read-only AUDIT gate, before any target teardown or configuration."""
import json
import sys
from workflow_contract import checkpoint

schema = json.load(sys.stdin) if sys.argv[1:] == ["--stdin"] else json.loads((checkpoint() / "discovery/pilot-capabilities.json").read_text())["action_schema"]
actions = {a["name"]: a for a in schema["actions"]}
required = {"create_host", "set_host_field", "enable_role", "add_extra_var", "edit_extra_var", "save_hosts",
            "set_vault_value", "save_vault", "set_group_var", "save_group_vars", "create_user",
            "set_user_field", "set_user_password", "create_group", "set_group_members_users",
            "create_hostgroup", "set_hostgroup_field", "create_hbac_rule", "set_hbac_disable_allow_all",
            "create_sudo_command_group", "create_sudo_rule", "set_sudo_command_group_commands",
            "create_dns_manifest", "create_dns_zone", "create_dns_record", "create_internal_endpoint_manifest",
            "create_internal_endpoint", "set_internal_endpoint_route_proxy", "set_internal_endpoint_tls_freeipa",
            "deploy", "reconcile"}
if required - set(actions):
    raise SystemExit("missing required Pilot actions: " + ", ".join(sorted(required - set(actions))))
choices = set()
for kind in ("deploy", "reconcile"):
    definitions = actions[kind]["prompt_schema"]["prompts"]
    choices.update(next(p for p in definitions if p["id"] == "component")["accepted_values"])
    for prompt in ("preflight", "execution.preview", "execution.confirm_preview", "execution.apply_after_preview", "execution.confirm_apply"):
        if not any(p["id"] == prompt for p in definitions):
            raise SystemExit("missing required prompt: " + kind + "/" + prompt)
for component in ("freeipa-identity", "freeipa-dns", "freeipa-dns-client", "freeipa-ca-trust", "reverse-proxy", "internal-endpoint"):
    if component not in choices:
        raise SystemExit("missing required Pilot component: " + component)
if "users" not in actions["create_hbac_rule"].get("optional", []):
    raise SystemExit("Pilot must support named admin HBAC subjects")
print("complete runbook capabilities passed")
