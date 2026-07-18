---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: docker container engine
  source: production container runtime acceptance contract
  maintainer: sre
targets:
  roles: [docker]
  hostScope: per-host
  platforms:
    - {os: ubuntu, versions: ["22.04", "24.04"]}
inputs: []
traceability: {components: [docker]}
defaults:
  become: true
  timeout: 60s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — docker container engine

This v2 acceptance contract verifies effective package, service, socket,
runtime, network, Compose, and cgroup behavior. C5 is the only mutating probe:
it creates an automatically removed test container and then verifies cleanup.

## Checks

```yaml
- id: C1
  category: pkg
  check: docker.io package is installed
  probe: |
    dpkg-query -W -f='${Package}\n' docker.io 2>/dev/null | awk "/^docker\\.io$/ {f=1} END{print f+0}"
  expect: {stdout: {equals: "1"}}
  tags: [docker-C1]
- id: C2
  category: service
  check: docker.service is active
  probe: |
    systemctl is-active docker 2>&1 | head -n1
  expect: {stdout: {equals: active}}
  tags: [docker-C2]
- id: C3
  category: cli
  check: docker CLI reports its version
  probe: |
    docker --version 2>&1 | head -n1
  expect: {stdout: {contains: "Docker version"}}
  verifyOnly: true
- id: C4
  category: socket
  check: docker socket exists and belongs to the docker group
  probe: |
    stat -c '%a %U %G %n' /var/run/docker.sock 2>/dev/null | head -n1
  expect: {stdout: {regex: '^[0-7]+ [^ ]+ docker /var/run/docker\.sock$'}}
  tags: [docker-C4]
- id: C5
  category: hello-world
  check: docker can pull, run, and automatically remove a test container
  probe: |
    docker run --rm hello-world 2>&1 | grep -m1 -oE 'Hello from Docker' | head -n1
  expect: {stdout: {equals: "Hello from Docker"}}
  timeout: 120s
  action:
    mode: isolatedMutation
    authorization: explicit
    residualRisk: hello-world image remains in the local image cache
    cleanup:
      required: true
      probe: |
        test "$(docker ps -aq --filter ancestor=hello-world | wc -l)" -eq 0
      expect: {exitCode: 0}
  verifyOnly: true
- id: C6
  category: network
  check: the default bridge network exists
  probe: |
    docker network ls 2>/dev/null | awk '$2 == "bridge" {print $2; exit}'
  expect: {stdout: {equals: bridge}}
  verifyOnly: true
- id: C7
  category: compose
  check: Docker Compose v2 is installed
  probe: |
    docker compose version 2>&1 | head -n1
  expect: {stdout: {contains: "Docker Compose"}}
  verifyOnly: true
- id: C8
  category: cgroup
  check: docker reports an effective cgroup driver or version
  probe: |
    docker info 2>/dev/null | grep -m1 -E 'Cgroup (Driver|Version)' | head -n1
  expect: {stdout: {regex: '^ Cgroup (Driver|Version): .+'}}
  verifyOnly: true
```

## PASS / FAIL

All applicable C1–C8 rows must pass. An unresolved host, runner error,
timeout, failed cleanup, or matcher failure makes the deployment transaction
fail. `not_applicable` is not used by this contract.

## Traceability

- C1, C2, and C4 map directly to `docker-C1`, `docker-C2`, and `docker-C4`.
- C3, C5, C6, C7, and C8 verify effective behavior derived from installation
  and are intentionally verification-only.

## Actual-run evidence

2026-07-18T10:27Z, the disposable VM inventory exposed one `docker` role
alias. The following command was executed against that role; the VM name is
redacted for publication. `--allow-isolated-mutation` authorized C5 and its
mandatory cleanup probe.

```bash
go run ./cmd/pilot vm-target verify --name <redacted-vm> \
  docs/verification/docker.md -l docker --allow-isolated-mutation
```

Actual output (exit 0):

```text
▶ pilot verify docs/verification/docker.md -i /tmp/pilot-inv-<redacted>.yaml -l docker --allow-isolated-mutation
✔ NDJSON:   <redacted-report-dir>/docker-20260718-102728.ndjson
✔ Report:   <redacted-report-dir>/docker-20260718-102728.md

verdict: **PASS**  (pass=8 fail=0 skip=0)
```

## Actual-run evidence

Target inventory was rendered from `tmp/docker-v2-topology.yaml`; its `docker`
group contained only the disposable Ubuntu 24.04 VM `pilot-docker-v2`
(`192.168.122.5`). The following command was run on 2026-07-18:

```bash
go run ./cmd/pilot vm-target topology test \
  --topology tmp/docker-v2-topology.yaml \
  --playbook playbooks/apply/docker-apply.yml \
  --verify docs/verification/docker.md=docker \
  --verify-timeout 150 \
  -- -e stage=sandbox
```

The first run stopped before C5 because the topology frontend had not
propagated explicit isolated-mutation authorization. The shared transaction
rolled the VM back to `pre-test-1784370128`. After adding the explicit
authorization flag, the same command completed:

```text
PLAY RECAP *********************************************************************
pilot-docker-v2 : ok=5 changed=2 unreachable=0 failed=0 skipped=2 rescued=0 ignored=0

verdict: **PASS**  (pass=8 fail=0 skip=0)

PLAY RECAP *********************************************************************
pilot-docker-v2 : ok=5 changed=0 unreachable=0 failed=0 skipped=2 rescued=0 ignored=0

✓ Idempotency check passed (changed=0)
🎉 ALL TESTS PASSED SUCCESSFULLY!
```

The C5 observation was `Hello from Docker`; its declared cleanup probe also
passed. Cleanup status is persisted as a separate append-only `cleanup`
delivery event, so an isolated mutation cannot be audited as successful
without cleanup evidence.

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-07-18 | v2.0 | Migrated to strict Spec v2, strengthened C1/C2/C4/C5 matchers, and declared C5 isolated-mutation cleanup. |
