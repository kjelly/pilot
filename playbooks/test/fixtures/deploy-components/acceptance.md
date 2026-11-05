# Native selected-component topology fixture

This fixture reuses public catalog IDs solely to exercise the production CLI
router with minimal native Ansible tasks. It does not install those products.
Use dedicated disposable hosts. Consumer A has `fixture-consumer` and
`fixture-leaf`; provider B has `fixture-provider`, `fixture-leaf` and
`fixture-unrelated`. `fixture-support` contains A only. The consumer/provider
groups must each contain exactly one distinct host.

The selected `dns` consumer requires the managed `docker` provider, whose
same-host `host-monitoring` leaf must apply only to B. Its support-only
`dcgm-exporter` edge must never execute; neither may `os-patch-sla` on B.
Preview leaves all markers absent. Apply creates consumer on A and leaf/provider
on B. A second apply must report zero changes. `playbooks/probe.yml` reads this
effective remote state and fails on any wrong host placement.

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | command | Native fixture host is reachable | 0 | true |
