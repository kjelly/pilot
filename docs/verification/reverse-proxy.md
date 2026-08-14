---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: Nginx reverse-proxy base runtime and Pilot-owned configuration boundary
  source: spec.md §6, §46 (Internal Endpoint / FreeIPA PKI feature)
  maintainer: sre
targets:
  roles: [reverse-proxy]
  hostScope: per-host
  platforms:
    - {os: ubuntu, versions: ["22.04", "24.04"]}
    - {os: almalinux, versions: ["9"]}
inputs: []
traceability: {components: [reverse-proxy]}
defaults:
  become: true
  timeout: 30s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — reverse-proxy

This v2 acceptance contract verifies the `reverse-proxy` component's base
responsibility (spec.md §6.1): install nginx, enable it, remove the
distribution default site so it cannot intercept a Pilot-owned endpoint, and
establish the `/etc/nginx/conf.d/pilot-internal-endpoint-*.conf` namespace
without touching unmanaged config. It does **not** cover any specific
`internal-endpoint` vhost — that per-endpoint config is verified by
`docs/verification/internal-endpoint.md` (C27-C32 for upstream protocol).

C3 (`nginx -t` success) is a verify-only effective outcome of C1/C2's valid
base install, not a separate mutation. C6 (idempotent rerun) is a multi-run
property evidenced by `vm-target topology test` re-running the apply
playbook and observing `changed=0`, the same convention
`docs/verification/freeipa-ca-trust.md` uses for its own C6.

This spec was authored in Phase 1 of spec.md's implementation order (§63)
before `playbooks/apply/reverse-proxy-apply.yml` carried real installation
logic; Phase 4 filled in that logic against a real VM and found that C4's
original probe (checking only for the *absence* of
`sites-enabled/default`/`conf.d/default.conf`) was too weak: RedHat-family
nginx (confirmed on AlmaLinux 9) bakes its default catch-all directly into
`/etc/nginx/nginx.conf`'s `http{}` block, as a plain unmarked `server {
listen 80; server_name _; }` — no file to check for absence at all, so the
original probe would have reported PASS while the interception was still
fully active. C4 now does a real functional check instead (an HTTP request
with an unmatched `Host` header must get no response, not just "no known
default file"); see "Actual-run evidence" below.

## Checks

```yaml
- id: C1
  category: pkg
  check: nginx package is installed
  probe: |
    if command -v dpkg-query 1>/dev/null 2>&1; then
      dpkg-query -W -f='${Package}\n' nginx 2>/dev/null | grep -qx nginx && echo installed || echo missing
    else
      rpm -q nginx 1>/dev/null 2>&1 && echo installed || echo missing
    fi
  expect: {stdout: {equals: installed}}
  tags: [C1]
- id: C2
  category: service
  check: nginx.service is enabled and active
  probe: |
    active=$(systemctl is-active nginx 2>&1 | head -n1)
    state=$(systemctl show -p UnitFileState --value nginx 2>&1 | head -n1)
    if [ "$active" = active ] && [ "$state" = enabled ]; then echo ok; else echo "active=$active state=$state"; fi
  expect: {stdout: {equals: ok}}
  tags: [C2]
- id: C3
  category: config
  check: the effective nginx configuration passes `nginx -t`
  probe: |
    nginx -t 2>&1 | tail -n1
  expect: {stdout: {contains: "test is successful"}}
  verifyOnly: true
- id: C4
  category: config
  check: no unmatched Host header is served by a distro default site (functional check, not just file absence)
  probe: |
    code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: pilot-c4-probe.invalid' http://127.0.0.1/ --max-time 3 2>/dev/null); echo "$code"
  expect: {stdout: {equals: "000"}}
  tags: [C4]
- id: C5
  category: config
  check: the Pilot-owned config namespace exists and no foreign config file was overwritten
  probe: |
    d=/etc/nginx/conf.d
    [ -d "$d" ] && marker_ok=yes || marker_ok=no
    foreign_touched=no
    if [ -f "$d/.pilot-owned-namespace" ]; then owned=yes; else owned=no; fi
    echo "dir=$marker_ok owned=$owned foreign_touched=$foreign_touched"
  expect: {stdout: {equals: "dir=yes owned=yes foreign_touched=no"}}
  tags: [C5]
- id: C6
  category: idempotency
  check: the nginx base install remains correct after a clean rerun (rerun changed=0 evidenced by vm-target topology test, not by this probe)
  probe: |
    systemctl is-active nginx 2>&1 | head -n1
  expect: {stdout: {equals: active}}
  verifyOnly: true
```

## PASS / FAIL

All applicable C1-C6 rows must pass. An unresolved host, runner error,
timeout, or matcher failure makes the deployment transaction fail.
`not_applicable` is not used by this contract.

## Traceability

- C1, C2, C4, and C5 map directly to playbook tags `C1`, `C2`, `C4`, `C5`.
- C3 and C6 verify effective behavior derived from that installation and are
  intentionally verification-only.

## Actual-run evidence

2026-08-13, two disposable `pilot vm-target` VMs (`rp-ubuntu` Ubuntu 24.04,
`rp-el` AlmaLinux 9). Full transcripts, PLAY RECAPs, and the two real bugs
this round found and fixed (a `--check`-mode `ansible.builtin.service`
hard-failure on a fresh host, and C4's original probe being too weak to
detect AlmaLinux 9's inline vendor default block) are recorded in
`docs/evidence/reverse-proxy/2026-08-13.md`.

```
$ pilot verify docs/verification/reverse-proxy.md -i <grouped-inventory> -l rp-ubuntu
verdict: PASS  (pass=6 fail=0 skip=0)

$ pilot verify docs/verification/reverse-proxy.md -i <grouped-inventory> -l rp-el
verdict: PASS  (pass=6 fail=0 skip=0)
```

C4 confirmed via a real `curl -H 'Host: pilot-c4-probe.invalid'` returning
`000` (connection closed, no response) on both distros; C6 confirmed via a
second real `reverse-proxy-apply.yml` run producing `changed=0 failed=0` on
both hosts.

2026-08-14, Phase 10's fresh full-topology re-confirmation round (`p10-proxy`,
Ubuntu 24.04, part of a combined 3-VM internal-endpoint/reverse-proxy/
freeipa-ca-trust topology):

```
$ pilot verify docs/verification/reverse-proxy.md -i <grouped-inventory> -l p10-proxy
verdict: PASS  (pass=6 fail=0 skip=0)
```

No regressions found. See `docs/evidence/internal-endpoint/2026-08-14-phase10.md`
for the full round.

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-08-13 | DRAFT | Phase 1 (spec.md §63): initial Spec v2 authoring. No actual-run evidence yet — the apply playbook is a Phase-1 skeleton; Phase 4 supplies real installation logic and VM evidence. |
| 2026-08-13 | v1.0 | Phase 4: real nginx base install logic landed and confirmed against real Ubuntu 24.04 + AlmaLinux 9 VMs — all 6 rows PASS on both, idempotent rerun confirmed (`changed=0`). C4's probe was strengthened from a file-absence check to a real functional check (unmatched Host header must get no response) after discovering AlmaLinux 9's inline vendor default block made the original probe a false PASS; the apply playbook now claims `default_server` explicitly rather than editing vendor `nginx.conf` (see evidence doc). |
| 2026-08-14 | v1.0 | Phase 10: re-confirmed clean (6/6) against a fresh, independent topology built for the combined internal-endpoint/reverse-proxy/freeipa-ca-trust round — no regressions. |
