#!/usr/bin/env python3
"""All Pilot actions and active acceptance experiments live in EXECUTE."""
import hashlib
import json
import os
from campaign_evidence import verify_sources, install_signal_handlers
from workflow_contract import (checkpoint, PROJECT, TEAM, HOSTS, COMPONENTS, SECTIONS,
                               run, remote, scenario, recap, write_json, bundle_hash)
from section4 import Checks, REQUIRED, require

root = checkpoint()
install_signal_handlers()
source_hashes = verify_sources(root, PROJECT)
audit = json.loads((root / "receipts/scenario-audit.json").read_text())
require(audit["status"] == "passed" and audit["bundle_sha256"] == bundle_hash(root), "bundle changed after audit")

def edit(name):
    run("structured-" + name.replace("/", "-"), [str(PROJECT / "pilot"), "edit", "--dir", str(root),
        "--actions", str(root / "actions" / (name + ".json")),
        "--trace-out", str(root / "logs" / (name.replace("/", "-") + "-trace.jsonl"))])


def exceptions(mode):
    run("roster-exceptions-" + mode, ["python3", str(TEAM / "roster-exceptions.py"), mode])
    run("roster-lint-" + mode, [str(PROJECT / "pilot"), "roster", "lint", str(root / ".vault/ipa-identity.yaml")])


edit("edit")
exceptions("hosts")
edit("roster")
exceptions("onboard")
edit("cycle/disable-allow-all")
run("roster-lint-final", [str(PROJECT / "pilot"), "roster", "lint", str(root / ".vault/ipa-identity.yaml")])
run("inventory-generate", [str(PROJECT / "pilot"), "inventory", "generate", "--dir", str(root)])
run("inventory-lint", [str(PROJECT / "pilot"), "inventory", "lint", "--in", str(root / "hosts.yml")])
require(recap(scenario("deploy.json", "deploy", "deploy-pass-1")) == set(HOSTS), "site deploy omitted a host")
recap(scenario("reconcile/freeipa-identity.json", "reconcile", "reconcile-freeipa-identity-pass-1"))
for user in ("alice", "bob"):
    initial = os.environ[f"PILOT_{user.upper()}_INITIAL_PASSWORD"]
    password = os.environ[f"PILOT_{user.upper()}_PASSWORD"]
    require(initial != password, "personalized password must differ from initial password")
    remote("personalize-" + user, "freeipa-server", "kinit " + user,
           input_text=f"{initial}\n{password}\n{password}\n")
exceptions("preserve")
recap(scenario("reconcile/freeipa-dns.json", "reconcile", "reconcile-freeipa-dns-pass-1"))
for name in ("freeipa-dns-client", "freeipa-ca-trust", "reverse-proxy"):
    file = "components/" + name + ".json"
    kind = json.loads((root / "actions" / file).read_text())["steps"][0]["action"]
    recap(scenario(file, kind, "component-" + name + "-pass-1"))
recap(scenario("reconcile/internal-endpoint.json", "reconcile", "reconcile-internal-endpoint-pass-1"))
remote("sudo-cache-prerequisite", "nexus", "sss_cache -E && systemctl restart sssd")
checks = Checks()
checks.authorization()
checks.observability()
checks.backups_and_fim()
checks.identity_cycle()
checks.endpoint()

# Second full pass has converged identity, DNS and endpoints. Prove actual
# changed=0 rather than inferring idempotency from a command's exit code.
require(recap(scenario("deploy.json", "deploy", "deploy-pass-2"), idempotent=True) == set(HOSTS),
        "idempotency pass omitted a host")
for name in ("freeipa-identity", "freeipa-dns", "internal-endpoint"):
    recap(scenario("reconcile/" + name + ".json", "reconcile", "reconcile-" + name + "-pass-2"), idempotent=True)
for name in ("freeipa-dns-client", "freeipa-ca-trust", "reverse-proxy"):
    file = "components/" + name + ".json"
    kind = json.loads((root / "actions" / file).read_text())["steps"][0]["action"]
    recap(scenario(file, kind, "component-" + name + "-pass-2"), idempotent=True)

suite = {}
for component, group in COMPONENTS.items():
    report = root / "reports" / component
    report.mkdir(parents=True, exist_ok=False)
    run("verify-" + component, [str(PROJECT / "pilot"), "verify",
        "docs/verification/" + component + ".md", "--inventory", str(root / "inventory.yml"),
        "--limit", group, "--timeout", "60", "--report-dir", str(report),
        "--vault-vars-file", str(root / ".vault/main.yaml")], timeout=1800)
    files = list(report.glob("*.ndjson"))
    require(len(files) == 1, "missing or ambiguous component report: " + component)
    rows = [json.loads(line) for line in files[0].read_text().splitlines() if line.strip()]
    require(rows and all(r["status"] == "pass" for r in rows), "non-passing or skipped component rows: " + component)
    suite[component] = {"report": str(files[0].relative_to(root)), "rows": len(rows)}

observed = [json.loads(line) for line in checks.output.read_text().splitlines()]
require({r["id"] for r in observed} == REQUIRED and len(observed) == len(REQUIRED) and
        all(r["status"] == "pass" for r in observed), "incomplete §4 coverage")
verify_sources(root, PROJECT)
write_json(root / "receipts/execution.json", {
    "version": 1, "status": "passed", "bundle_sha256": bundle_hash(root),
    "topology_rebuilt": True, "edit_passed": True, "inventory_passed": True,
    "deploy_passes": 2, "reconcile_passes": 2, "idempotent": True,
    "sections": list(SECTIONS), "component_specs": suite,
    "fixture_bound_specs": {"freeipa-client": "covered by live PoC authorization checks",
                            "freeipa-identity": "covered by live revoke/restore cycle",
                            "freeipa-dns": "covered by live authoritative DNS queries"},
})
# Seal the actual evidence and the execution-affecting reference documents.
proofs = list((root / "logs").glob("*.log")) + list((root / "reports").rglob("*.ndjson"))
proofs.append(checks.output)
write_json(root / "receipts/evidence-manifest.json", {
    "version": 1, "pipeline_complete": False, "bundle_sha256": bundle_hash(root),
    "proofs": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in proofs},
    "sources": source_hashes,
})
print("complete Minimal PoC structured-action execution passed")
