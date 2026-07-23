#!/usr/bin/env bash
# scripts/topology-checkmode-test.sh — full ephemeral, fresh-host topology test
# (L1 syntax, L3 check-mode dry-run, L4 apply, L5 verify, L6 idempotency; see
# AGENTS.md §1.4 and `pilot vm-target topology test --help`).
#
# Unlike `pilot vm-target topology test --ephemeral` alone, this wrapper also
# discovers each node's real IP after `topology up` and forwards them as the
# site-wide `-e <var>=<ip>` values this specific topology's apply playbook
# needs (wazuh_manager_host, restic_s3_target_host, etc.) — the topology YAML
# format only carries VM shape and group membership, not group_vars/vault.
#
# Usage:
#   TOPOLOGY=docs/topologies/minimal-poc-topology.yaml \
#   PLAYBOOK=playbooks/site.yml \
#   VAULT=~/.vault/minimal-poc-sandbox.yaml \
#   ./scripts/topology-checkmode-test.sh
#
# Required env:
#   VAULT     — path to an ansible-vault-compatible vars file supplying
#               ipa_admin_password, grafana_admin_password, restic_*,
#               thanos_*, alertmanager_config (see runbook §2). Never commit
#               this file; keep it outside the repo.
#
# Optional env (defaults match docs/runbooks/minimal-poc-architecture.md):
#   TOPOLOGY  — topology spec (default docs/topologies/minimal-poc-topology.yaml)
#   PLAYBOOK  — playbook under test (default playbooks/site.yml)
#   STAGE     — stage var (default sandbox)
#   NEXUS_NODE — name of the node whose IP feeds wazuh_manager_host /
#               restic_s3_target_host / thanos_*_target_host (default nexus)
#
# Also hardcodes -e prometheus_site_label=site-checkmode-test: it is required
# with no default (docs/verification/prometheus.md §1.5 — deliberately, to
# avoid two sites silently colliding) and, unlike the *_target_host values
# above, isn't derivable from any node's IP. The topology YAML format has no
# group_vars equivalent, so anything a real `pilot edit` run would normally
# put in group_vars must be supplied here as -e. Confirmed live 2026-07-23:
# the new L3 check-mode step correctly fails fast on this before any
# mutation — if a future site.yml component adds another required-with-no-
# default var, expect the same failure mode here, not a check-mode bug.
#   ROSTER    — path to a canonical freeipa-identity roster (schema_version:
#               1; see playbooks/apply/freeipa-identity.roster.example.yaml).
#               freeipa-nfs-server-apply.yml reads this unconditionally
#               (include_vars with no `when:` guard) even though this
#               topology never runs the separate freeipa-identity reconcile
#               — omitting ROSTER makes the run fail at that task with
#               "'freeipa_roster_file' is undefined" before any mutation
#               (confirmed live 2026-07-23). If unset, this script skips
#               forwarding -e freeipa_roster_file, which only works for a
#               PLAYBOOK that doesn't touch freeipa-nfs-server.

set -euo pipefail

TOPOLOGY="${TOPOLOGY:-docs/topologies/minimal-poc-topology.yaml}"
PLAYBOOK="${PLAYBOOK:-playbooks/site.yml}"
STAGE="${STAGE:-sandbox}"
NEXUS_NODE="${NEXUS_NODE:-nexus}"
VAULT="${VAULT:-}"
ROSTER="${ROSTER:-}"

if [ -z "$VAULT" ]; then
  echo "ERROR: VAULT=<path> is required (ansible-vault-compatible vars file; see AGENTS.md §1.4 / runbook §2)." >&2
  exit 2
fi
if [ ! -f "$VAULT" ]; then
  echo "ERROR: vault file not found: $VAULT" >&2
  exit 2
fi
if [ -n "$ROSTER" ] && [ ! -f "$ROSTER" ]; then
  echo "ERROR: roster file not found: $ROSTER" >&2
  exit 2
fi

VERIFY_ARGS=(
  --verify "docs/verification/freeipa-server.md=freeipa-server"
  --verify "docs/verification/freeipa-client.md=freeipa-client"
  --verify "docs/verification/freeipa-nfs-server.md=freeipa-nfs-server"
  --verify "docs/verification/freeipa-nfs-client.md=freeipa-nfs-client"
  --verify "docs/verification/docker.md=docker"
  --verify "docs/verification/audit-log-forwarding.md=audit-log-forwarding"
  --verify "docs/verification/wazuh-manager.md=wazuh-manager"
  --verify "docs/verification/wazuh-fim.md=wazuh-fim"
  --verify "docs/verification/seaweedfs-s3.md=seaweedfs-s3"
  --verify "docs/verification/restic-backup.md=restic-backup"
  --verify "docs/verification/alertmanager.md=alertmanager"
  --verify "docs/verification/prometheus.md=prometheus"
  --verify "docs/verification/thanos-query.md=thanos-query"
  --verify "docs/verification/dashboard.md=dashboard"
  --verify "docs/verification/log-shipping.md=wazuh-manager"
)

echo "=== provisioning topology: $TOPOLOGY ==="
./pilot vm-target topology up --topology "$TOPOLOGY"

cleanup() {
  echo "=== tearing down topology: $TOPOLOGY ==="
  ./pilot vm-target topology down --topology "$TOPOLOGY" || true
}
trap cleanup EXIT

NEXUS_IP="$(./pilot vm-target topology status --topology "$TOPOLOGY" | awk -v n="$NEXUS_NODE" '$1==n {print $3}')"
if [ -z "$NEXUS_IP" ]; then
  echo "ERROR: could not resolve IP for node '$NEXUS_NODE' from 'topology status'; check the output format hasn't changed." >&2
  exit 1
fi
echo "=== resolved $NEXUS_NODE -> $NEXUS_IP ==="

EXTRA_ROSTER_ARGS=()
if [ -n "$ROSTER" ]; then
  EXTRA_ROSTER_ARGS=(-e "freeipa_roster_file=$ROSTER")
fi

./pilot vm-target topology test \
  --topology "$TOPOLOGY" \
  --playbook "$PLAYBOOK" \
  "${VERIFY_ARGS[@]}" \
  -- \
  -e "stage=$STAGE" \
  -e "prometheus_site_label=site-checkmode-test" \
  -e "wazuh_manager_host=$NEXUS_IP" \
  -e "restic_s3_target_host=$NEXUS_IP" \
  -e "loki_target_host=$NEXUS_IP" \
  -e "thanos_s3_target_host=$NEXUS_IP" \
  -e "alertmanager_target_host=$NEXUS_IP" \
  -e "thanos_query_target_host=$NEXUS_IP" \
  "${EXTRA_ROSTER_ARGS[@]}" \
  -e "@$VAULT"
