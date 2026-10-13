#!/usr/bin/env python3
"""Complete the fixed runbook scenario using Pilot's exported action contracts."""
import json
from workflow_contract import checkpoint, write_json, LOGIN_GROUP, SUDO_GROUP, SUDO_COMMAND, DRIFT_COMMAND

root = checkpoint()
actions = root / "actions"
edit = json.loads((actions / "edit.json").read_text())
steps = []
for user, first in (("alice", "Alice"), ("bob", "Bob")):
    steps.extend([
        {"action": "create_user", "user": user},
        {"action": "set_user_field", "user": user, "field": "first", "value": first},
        {"action": "set_user_field", "user": user, "field": "last", "value": "PoC"},
        {"action": "set_user_password", "user": user, "value_env": f"PILOT_{user.upper()}_INITIAL_PASSWORD"},
    ])
for group, category, users in ((LOGIN_GROUP, "team", ["alice"]),
                               (SUDO_GROUP, "role", ["alice"]),
                               ("data-sysops-rw", "filesystem", ["alice"])):
    steps.extend([{"action": "create_group", "name": group, "category": category},
                  {"action": "set_group_members_users", "name": group, "users": users}])
steps.extend([
    {"action": "create_hostgroup", "name": "poc-nexus"},
    {"action": "set_hostgroup_field", "name": "poc-nexus", "field": "membership.hosts",
     "value": "nexus.ipa.pilot.internal"},
    {"action": "create_hostgroup", "name": "nfsclients"},
    {"action": "set_hostgroup_field", "name": "nfsclients", "field": "membership.hosts",
     "value": "client-vm.ipa.pilot.internal"},
    {"action": "create_hbac_rule", "name": "poc-sysops", "groups": [LOGIN_GROUP],
     "hostgroups": ["poc-nexus"], "services": ["sshd", "sudo", "sudo-i"]},
    {"action": "create_hbac_rule", "name": "breakglass-admin-access", "users": ["admin"],
     "hosts": ["ipa1.ipa.pilot.internal", "nexus.ipa.pilot.internal", "client-vm.ipa.pilot.internal"],
     "services": ["sshd", "sudo", "sudo-i"]},
    {"action": "create_sudo_command_group", "name": "poc-service-read", "value": SUDO_COMMAND},
    {"action": "create_sudo_rule", "name": "poc-service-admin", "groups": [SUDO_GROUP],
     "command_groups": ["poc-service-read"]},
    {"action": "create_dns_manifest", "domain": "ipa.pilot.internal", "realm": "IPA.PILOT.INTERNAL",
     "server": "ipa1.ipa.pilot.internal"},
    {"action": "create_dns_zone", "zone": "it.pilot.internal."},
    {"action": "create_dns_record", "zone": "it.pilot.internal.", "record_type": "A",
     "record_name": "wazuh", "target_host": "nexus"},
    {"action": "create_dns_record", "zone": "it.pilot.internal.", "record_type": "A",
     "record_name": "thanos", "target_host": "nexus"},
    {"action": "create_internal_endpoint_manifest"},
    {"action": "create_internal_endpoint", "fqdn": "grafana.it.pilot.internal",
     "zone": "it.pilot.internal.", "target_host": "nexus"},
    {"action": "set_internal_endpoint_route_proxy", "fqdn": "grafana.it.pilot.internal",
     "proxy_host": "nexus", "upstream_scheme": "http", "upstream_host": "nexus", "upstream_port": "3000"},
    {"action": "set_internal_endpoint_tls_freeipa", "fqdn": "grafana.it.pilot.internal"},
])
write_json(actions / "roster.json", {"version": 1, "steps": steps})
write_json(actions / "cycle/disable-allow-all.json", {"version": 1, "steps": [{"action": "set_hbac_disable_allow_all", "value": "true"}]})

deploy = json.loads((actions / "deploy.json").read_text())
# Include all detected host pointers declared by current Pilot source, rather
# than assuming that the original seven are the entire conditional prompt set.
import re
from workflow_contract import PROJECT
variables = re.findall(r'Var:\s*"([a-z0-9_]+)"', (PROJECT / "cmd/pilot/cmd/deploy_catalog.go").read_text())
for var in sorted(set(variables)):
    prompt_id = f"auto_host_var.{var}.use_detected"
    if not any(a["prompt_id"] == prompt_id for a in deploy["steps"][0]["answers"]):
        deploy["steps"][0]["answers"].append({"prompt_id": prompt_id, "confirm": True})
write_json(actions / "deploy.json", deploy)
schema = json.loads((root / "discovery/pilot-capabilities.json").read_text())["action_schema"]
def choices(kind):
    contract = next(a for a in schema["actions"] if a["name"] == kind)
    return next(p for p in contract["prompt_schema"]["prompts"] if p["id"] == "component")["accepted_values"]
for component in ("freeipa-dns-client", "freeipa-ca-trust", "reverse-proxy"):
    if component in choices("deploy"):
        plan = json.loads(json.dumps(deploy))
        answers = plan["steps"][0]["answers"]
        next(a for a in answers if a["prompt_id"] == "scope")["select"] = "component"
        answers.extend([{"prompt_id": "component", "select": component},
                        {"prompt_id": "target_group", "text": ""}])
    elif component in choices("reconcile"):
        plan = json.loads((actions / "reconcile/freeipa-dns.json").read_text())
        next(a for a in plan["steps"][0]["answers"] if a["prompt_id"] == "component")["select"] = component
    else:
        raise SystemExit(f"Pilot does not expose required component {component}")
    write_json(actions / "components" / (component + ".json"), plan)
plan = json.loads((actions / "reconcile/freeipa-dns.json").read_text())
next(a for a in plan["steps"][0]["answers"] if a["prompt_id"] == "component")["select"] = "internal-endpoint"
write_json(actions / "reconcile/internal-endpoint.json", plan)
for name, users in (("revoke", []), ("restore", ["alice"])):
    cycle = [{"action": "set_group_members_users", "name": group, "users": users}
             for group in (LOGIN_GROUP, SUDO_GROUP)]
    if name == "restore":
        cycle.append({"action": "set_sudo_command_group_commands", "name": "poc-service-read",
                      "value": SUDO_COMMAND + "," + DRIFT_COMMAND})
    write_json(actions / "cycle" / (name + ".json"), {"version": 1, "steps": cycle})
