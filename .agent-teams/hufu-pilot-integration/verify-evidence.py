#!/usr/bin/env python3
"""Read-only gate: require exact scope, passing probes and sealed real evidence."""
import hashlib
import json
import re
import yaml
from workflow_contract import checkpoint, PROJECT, COMPONENTS, SECTIONS, bundle_hash
from section4 import REQUIRED, require
from campaign_evidence import verify_sources, verify_pipeline


def verify():
    root = checkpoint()
    execution = json.loads((root / "receipts/execution.json").read_text())
    manifest = json.loads((root / "receipts/evidence-manifest.json").read_text())
    require(execution["status"] == "passed" and set(execution["sections"]) == set(SECTIONS), "incomplete section scope")
    require(set(execution["component_specs"]) == set(COMPONENTS), "incomplete component scope")
    require(manifest["version"] == 1 and manifest["bundle_sha256"] == execution["bundle_sha256"] == bundle_hash(root),
            "bundle drift between audit, execution and verification")
    require(manifest.get("pipeline_complete") is True, "pipeline has not completed")
    verify_pipeline(root)
    require(manifest["sources"] == verify_sources(root, PROJECT), "manifest does not bind pinned sources")
    require("facts/source-snapshot.json" in manifest["proofs"] and "logs/stages.jsonl" in manifest["proofs"] and
            "receipts/execution.json" in manifest["proofs"], "campaign metadata is unsealed")
    require(manifest["proofs"] and manifest["sources"], "missing evidence/source manifest")
    required_sources = {'docs/runbooks/minimal-poc-architecture.md', 'docs/topologies/minimal-poc-topology.yaml'}
    required_sources.update('docs/verification/' + c + '.md' for c in COMPONENTS)
    require(required_sources <= set(manifest['sources']), 'reference source manifest incomplete')
    require('logs/section4.jsonl' in manifest['proofs'], 'section proof is unsealed')
    for base, values in ((root, manifest["proofs"]), (PROJECT, manifest["sources"])):
        for relative, digest in values.items():
            path = base / relative
            require(path.resolve().is_relative_to(base.resolve()), "evidence path escapes its root")
            require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, "evidence/source changed: " + relative)
    observed = [json.loads(line) for line in (root / "logs/section4.jsonl").read_text().splitlines()]
    require({r["id"] for r in observed} == REQUIRED and len(observed) == len(REQUIRED) and
            all(r["status"] == "pass" for r in observed), "missing, duplicated or failed §4 proof")
    for component, report in execution["component_specs"].items():
        path = root / report["report"]
        require(report["report"] in manifest["proofs"], "unsealed component report")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        require(rows and len(rows) == report["rows"] and all(r["status"] == "pass" for r in rows),
                "incomplete or non-passing component report: " + component)
        spec = PROJECT / "docs/verification" / (component + ".md")
        ids = set(re.findall(r"(?m)^\|\s*(C\d+[a-z0-9_.-]*)\s*\|", spec.read_text()))
        require(len(rows) == len({(r["id"], r.get("host")) for r in rows}), "duplicated component rows")
        require(ids and ids <= {r["id"] for r in rows}, "component report omitted spec rows: " + component)
        topology = yaml.safe_load((PROJECT / "docs/topologies/minimal-poc-topology.yaml").read_text())
        group = COMPONENTS[component]
        expected_hosts = {n['name'] for n in topology['nodes'] if group == 'all' or group in n['groups']}
        require(expected_hosts, 'component resolves no hosts: ' + component)
        require({r.get('host') for r in rows} == expected_hosts, 'component omitted target hosts: ' + component)
        require(all({r['id'] for r in rows if r.get('host') == host} >= ids for host in expected_hosts),
                'component omitted per-host rows: ' + component)
    return len(observed)


if __name__ == "__main__":
    print(f"sealed full-runbook evidence passed: {verify()} section checks")
