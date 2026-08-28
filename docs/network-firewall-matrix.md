# Minimal PoC Network Firewall Matrix

This document defines the network access required by the three-node architecture in
[`runbooks/minimal-poc-architecture.md`](runbooks/minimal-poc-architecture.md).

The firewall must allow stateful return traffic for the connections below. The source and
destination names are the three nodes in that runbook, not Ansible inventory group names from a
different deployment. Restrict management and user-facing ports to the deployment/admin networks;
do not expose the service ports to the public Internet.

## Required inter-node connections

| Source | Destination | Protocol/port | Required use |
|---|---|---|---|
| Deployment controller | `freeipa-server`, `nexus`, `client-vm` | TCP `22` | Ansible SSH and sanctioned `pilot` operations |
| `nexus`, `client-vm` | `freeipa-server` | TCP `80, 443, 389, 636, 88, 464` | FreeIPA HTTP/HTTPS, LDAP/LDAPS, Kerberos and kpasswd |
| `nexus`, `client-vm` | `freeipa-server` | UDP `88, 464` | Kerberos and kpasswd |
| `nexus`, `client-vm` | `freeipa-server` | TCP/UDP `53` | FreeIPA DNS, when clients use the server for DNS rather than only `/etc/hosts` pins |
| `client-vm` | `nexus` | TCP `2049` | Kerberos NFSv4 mount and access |
| `freeipa-server`, `nexus`, `client-vm` | `nexus` | TCP `1514` | Wazuh agent event channel |
| `freeipa-server`, `nexus`, `client-vm` | `nexus` | TCP `1515` | Wazuh agent enrollment (`agent-auth`) |
| `freeipa-server`, `nexus`, `client-vm` | `nexus` | TCP `8333` | SeaweedFS S3 endpoint for restic and Thanos |

## Co-located observability services

The compact topology co-locates Prometheus, Thanos, Alertmanager, Grafana, Loki and SeaweedFS on
`nexus`; their internal Docker-network traffic does not require inter-node firewall rules.

If these roles are split across hosts later, allow these additional flows:

| Source | Destination | Protocol/port | Use |
|---|---|---|---|
| Prometheus | Alertmanager | TCP `9093` | Alert delivery |
| Grafana | Thanos Query | TCP `10912` | Prometheus-compatible dashboard queries |
| Thanos Query | Each Prometheus sidecar | TCP `10901` | Thanos StoreAPI discovery/query |
| Detection Engine | Thanos Query | TCP `10912` | Adaptive anomaly detection metrics ingestion (never `10902` — see below) |
| Detection Engine | Alertmanager | TCP `9093` | SignalEvent delivery |
| Promtail | Loki | TCP `3100` | Log shipping |
| Metrics/backup clients | SeaweedFS | TCP `8333` | S3 API |

The current published Thanos Query port is **10912**. Port `10902` is the container/internal or
site sidecar HTTP port, not the central Thanos Query host port.

## Wazuh management and optional logging ports

Wazuh's official compose also exposes UDP `514`, TCP `443`, TCP `9200`, and TCP `55000`, but they
are not required for this PoC's agent/FIM path:

- UDP `514` is not used because no separate `log-server` is deployed.
- TCP `443`, `9200`, and `55000` are dashboard/indexer/API management surfaces and should be
  restricted to an approved admin network.
- If a separate `log-server` is enabled, add Wazuh manager → log-server UDP `514` or the explicitly
  configured TCP `6514`.

## Controlled outbound access

For provisioning and image/package installation, permit controlled outbound TCP `443` from hosts
that install packages or pull Docker images: APT/YUM repositories, Wazuh packages and container
registries.

Permit UDP `123` only to the actual NTP source when external time sync is used. The
`freeipa-client-apply.yml` playbook uses `--no-ntp`, so UDP `123` is not an enrollment prerequisite.

## Maintenance rule

This matrix is derived from the runbook role placement, component contracts, and current apply
playbooks. Re-check it whenever a role is moved, a published port is overridden, or the inventory
gains a separate `log-server`, Prometheus site, or FreeIPA replica.
