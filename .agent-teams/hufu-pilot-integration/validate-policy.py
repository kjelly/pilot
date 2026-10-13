#!/usr/bin/env python3
"""Reject incomplete scope, unsafe prompt branches, or unrecognized action inputs."""
import json
from workflow_contract import checkpoint, SCENARIOS, HOSTS, PROJECT, bundle_hash, write_json
import yaml

root = checkpoint()
schema = json.loads((root / "discovery/pilot-capabilities.json").read_text())["action_schema"]
contracts = {a["name"]: a for a in schema["actions"]}
try:
    for name in SCENARIOS:
        scenario = json.loads((root / "actions" / name).read_text())
        if scenario.get("version") != 1 or not scenario.get("steps"):
            raise ValueError(f"{name}: missing scenario steps")
        for step in scenario["steps"]:
            contract = contracts[step["action"]]
            allowed = {"action"} | set(contract.get("required", [])) | set(contract.get("optional", []))
            if set(step) - allowed:
                raise ValueError(f"{name}: unknown fields {sorted(set(step) - allowed)}")
            if set(contract.get("required", [])) - set(step):
                raise ValueError(f"{name}: missing required action field")
            for field, values in contract.get("values", {}).items():
                if field in step and step[field] not in values:
                    raise ValueError(f"{name}: invalid {field}")
            if contract.get("secret_handling") == "value_env_required":
                if not step.get("value_env") or "value" in step:
                    raise ValueError(f"{name}: plaintext secret or missing value_env")
            if step["action"] not in ("deploy", "reconcile"):
                continue
            definitions = contract["prompt_schema"]["prompts"]
            answers = step["answers"]
            ids = [a["prompt_id"] for a in answers]
            if len(ids) != len(set(ids)):
                raise ValueError(f"{name}: duplicate prompt answer")
            for answer in answers:
                key = answer["prompt_id"]
                matches = [d for d in definitions if d["id"] == key or
                           (d.get("id_pattern") == "auto_host_var.*.use_detected" and
                            key.startswith("auto_host_var.") and key.endswith(".use_detected"))]
                if len(matches) != 1:
                    raise ValueError(f"{name}: unsupported prompt ID {key}")
                definition = matches[0]
                kind = definition["kind"]
                if set(answer) != {"prompt_id", kind}:
                    raise ValueError(f"{name}: wrong answer kind {key}")
                if kind == "confirm" and not isinstance(answer[kind], bool):
                    raise ValueError(f"{name}: non-boolean confirmation")
                if kind != "confirm" and not isinstance(answer[kind], str):
                    raise ValueError(f"{name}: non-string answer")
                if definition.get("accepted_values") and answer[kind] not in definition["accepted_values"]:
                    raise ValueError(f"{name}: unsupported answer {key}")
            required = {d["id"] for d in definitions if d["requirement"] == "always"}
            if not required <= set(ids):
                raise ValueError(f"{name}: missing required prompt answers")
            values = {a["prompt_id"]: a.get("text", a.get("select", a.get("confirm"))) for a in answers}
            expected = {"inventory": str(root / "inventory.yml"), "preflight": "full",
                        "stage": "sandbox", "limit": "", "tags": "", "extra_vars": "",
                        "execution.preview": True, "execution.confirm_preview": True,
                        "execution.apply_after_preview": True, "execution.confirm_apply": True}
            if any(values.get(k) != v for k, v in expected.items()):
                raise ValueError(f"{name}: unsafe scope, skipped preflight, or missing preview")
    edit = json.loads((root / "actions/edit.json").read_text())["steps"]
    topology = yaml.safe_load((PROJECT / "docs/topologies/minimal-poc-topology.yaml").read_text())
    for node in topology["nodes"]:
        actual = {s["role"] for s in edit if s["action"] == "enable_role" and s["host"] == node["name"]}
        if actual != set(node["groups"]):
            raise ValueError(f"role placement differs from topology for {node['name']}")
    if {s["host"] for s in edit if s["action"] == "create_host"} != set(HOSTS):
        raise ValueError("host set differs from Minimal PoC")
    write_json(root / "receipts/scenario-audit.json",
               {"version": 1, "status": "passed", "bundle_sha256": bundle_hash(root),
                "reconcile_scenarios": 3, "full_runbook_scope": True})
    print("structured-action policy audit passed")
except (KeyError, ValueError, OSError, TypeError) as error:
    write_json(root / "receipts/scenario-audit.json",
               {"version": 1, "status": "failed", "error": {"code": "runbook_policy", "message": str(error)}})
    raise SystemExit(str(error))
