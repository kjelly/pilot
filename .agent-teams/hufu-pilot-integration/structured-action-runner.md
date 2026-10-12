---
name: structured-action-runner
description: Owns the runtime-bound Pilot structured-action execution contract.
role: worker
tools: bash,submit_result
model: ollama/minimax-m2.7:cloud
temperature: "0.1"
timeout: 28800
max-steps: 8
side_effect: infra_mutation
recovery: never
requires:
  tools: [bash]
  environment:
    - HUFU_CHECKPOINT_WORKSPACE
    - PILOT_ALICE_INITIAL_PASSWORD
    - PILOT_BOB_INITIAL_PASSWORD
    - PILOT_BOB_PASSWORD
    - PILOT_INTERNAL_ENDPOINT_MANIFEST_FILE
    - PILOT_ALICE_PASSWORD
    - PILOT_IPA_ADMIN_PASSWORD
    - PILOT_GRAFANA_ADMIN_PASSWORD
    - PILOT_RESTIC_AWS_ACCESS_KEY_ID
    - PILOT_RESTIC_AWS_SECRET_ACCESS_KEY
    - PILOT_RESTIC_PASSWORD
    - PILOT_THANOS_AWS_ACCESS_KEY_ID
    - PILOT_THANOS_AWS_SECRET_ACCESS_KEY
    - PILOT_NODE_EXPORTER_BASIC_AUTH_PASSWORD
    - PILOT_DCGM_EXPORTER_BASIC_AUTH_PASSWORD
    - PILOT_FREEIPA_ROSTER_FILE
    - PILOT_FREEIPA_DNS_MANIFEST_FILE
    - PILOT_PROMETHEUS_SITE_LABEL
  paths: [/home/ubuntu/nfs/github/pilot]
---

This role is not started as a model worker. Its static task contract is a
runtime-owned `pilot-structured-actions` action, so Hufu invokes the configured
adapter only during EXECUTE. It exists to make the action owner explicit in the
team roster and to prevent a coordinator from substituting an ad-hoc shell task.

If this role is ever exposed as a worker because the runtime contract has been
changed, stop and report `INVALID_TASK`; do not run Pilot commands yourself.
