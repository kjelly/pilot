#!/usr/bin/env python3
"""Persist one exact control/evidence/credential binding for explicit resume."""
import json
import os
from pathlib import Path
import secrets
import shlex
import sys

control, evidence, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
path = control / "pilot-launch.json"
names = ["IPA_ADMIN_PASSWORD", "GRAFANA_ADMIN_PASSWORD", "RESTIC_AWS_ACCESS_KEY_ID",
         "RESTIC_AWS_SECRET_ACCESS_KEY", "RESTIC_PASSWORD", "THANOS_AWS_ACCESS_KEY_ID",
         "THANOS_AWS_SECRET_ACCESS_KEY", "NODE_EXPORTER_BASIC_AUTH_PASSWORD", "DCGM_EXPORTER_BASIC_AUTH_PASSWORD",
         "ALICE_INITIAL_PASSWORD", "BOB_INITIAL_PASSWORD", "ALICE_PASSWORD", "BOB_PASSWORD"]
if mode == "resume":
    record = json.loads(path.read_text())
    if record.get("version") != 1 or record.get("control") != str(control):
        raise SystemExit("invalid campaign binding")
    if record.get("checkpoint") != str(evidence) or not evidence.is_dir():
        raise SystemExit("resume must reuse the bound checkpoint workspace")
    if set(record.get("secrets", {})) != {"PILOT_" + name for name in names}:
        raise SystemExit("resume credential binding is incomplete")
else:
    if path.exists() or any(control.iterdir()) or evidence.exists():
        raise SystemExit("fresh campaign requires empty control and absent checkpoint directories")
    evidence.mkdir(parents=True, mode=0o700)
    record = {"version": 1, "control": str(control), "checkpoint": str(evidence),
              "secrets": {"PILOT_" + name: os.environ.get("PILOT_" + name) or secrets.token_hex(24)
                          for name in names}}
    # The PoC's SeaweedFS publishes one signed identity. Both clients must use it.
    for suffix in ('ACCESS_KEY_ID', 'SECRET_ACCESS_KEY'):
        restic = record['secrets']['PILOT_RESTIC_AWS_' + suffix]
        requested = os.environ.get('PILOT_THANOS_AWS_' + suffix)
        if requested and requested != restic:
            raise SystemExit('Thanos and restic must share the PoC SeaweedFS identity')
        record['secrets']['PILOT_THANOS_AWS_' + suffix] = restic
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(record, stream)
for key, value in record["secrets"].items():
    print("export " + key + "=" + shlex.quote(value))
for key, value in {"HUFU_CHECKPOINT_WORKSPACE": str(evidence),
                   "PILOT_FREEIPA_ROSTER_FILE": str(evidence / ".vault/ipa-identity.yaml"),
                   "PILOT_FREEIPA_DNS_MANIFEST_FILE": str(evidence / "freeipa-dns.yaml"),
                   "PILOT_INTERNAL_ENDPOINT_MANIFEST_FILE": str(evidence / "internal-endpoints.yaml"),
                   "PILOT_PROMETHEUS_SITE_LABEL": "site-nexus"}.items():
    print("export " + key + "=" + shlex.quote(value))
