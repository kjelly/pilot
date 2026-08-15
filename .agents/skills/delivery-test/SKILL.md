---
name: delivery-test
description: RETIRED 2026-08-14 — merged into minimal-poc-update / docs/runbooks/minimal-poc-architecture.md. Use minimal-poc-update instead.
---

# delivery-test (retired)

**This skill is retired as of 2026-08-14.** Its scope — `internal-endpoint`, `reverse-proxy`,
`freeipa-ca-trust`, `freeipa-dns-client`, and `host-monitoring` — has been merged into
[`docs/runbooks/minimal-poc-architecture.md`](../../../docs/runbooks/minimal-poc-architecture.md)
(§0.5, §3.7, §3.8, §4.2, §4.5), and the acceptance-run mechanics into the
[`minimal-poc-update`](../minimal-poc-update/SKILL.md) skill.

This was a user decision to keep **one canonical 3-VM topology definition** for this class of
FreeIPA+Wazuh+Grafana PoC, instead of two independently-drifting scenarios with different host
naming (`freeipa`/`nexus`/`client` here vs. `freeipa-server`/`nexus`/`client-vm` in
`minimal-poc-architecture`) and diverging feature coverage — this skill had accumulated
`host-monitoring`/`internal-endpoint`/`reverse-proxy`/`freeipa-ca-trust`/`freeipa-dns-client`
coverage that `minimal-poc-architecture.md` lacked, while `minimal-poc-architecture.md` had NFS
Kerberos automount and a more exhaustive identity-reconciler cycle that this skill lacked.

**Do not use this skill going forward.** Invoke `minimal-poc-update` instead, which now covers
this scope as part of `docs/runbooks/minimal-poc-architecture.md`'s own maintained procedure.

As of the merge, the newly-added sections in that runbook are explicitly marked DRAFT / not yet
executed against the merged topology — the mechanics below were this skill's own last-confirmed
state before retirement, preserved here only for historical/git-blame reference. Do not treat this
file as current guidance.

<details>
<summary>Historical content (pre-retirement, for reference only)</summary>

> Recipe for executing a full integration and delivery test of the pilot codebase, using KVM VMs managed by `pilot vm-target`. It validated that all components (FreeIPA, Prometheus/Thanos/Grafana, Loki/Promtail, Restic S3 Backups, Wazuh FIM, and the internal-endpoint DNS/TLS/reverse-proxy reconciler) deploy together and interoperate correctly across a multi-node layout, using the host names `freeipa`/`nexus`/`client`. See `docs/runbooks/minimal-poc-architecture.md`'s round-24 evidence and the merge note at its own top-of-file status block for what carried over and what still needs live re-verification under the new merged topology.

</details>
