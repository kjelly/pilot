---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: FreeIPA integrated CA trust installed on every managed host's OS trust store
  source: spec.md §5, §45 (Internal Endpoint / FreeIPA PKI feature)
  maintainer: sre
targets:
  roles: [all]
  hostScope: per-host
  platforms:
    - {os: ubuntu, versions: ["22.04", "24.04"]}
    - {os: almalinux, versions: ["9"]}
inputs:
  - name: expected_ca_sha256
    required: true
    validation: '^[0-9a-f]{64}$'
traceability: {components: [freeipa-ca-trust]}
defaults:
  become: true
  timeout: 30s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — freeipa-ca-trust

This v2 acceptance contract verifies that the FreeIPA integrated CA's trust
chain is installed on a managed host's OS trust store, independent of
whether that host is itself a FreeIPA (AAA) client (spec.md §5.1-§5.2).

C1, C3, C4, and C5 observe effective trust-store behavior that is a direct
side effect of the single installation mutation covered by C2 — they do not
correspond to a separate apply task (same reasoning docker.md uses for its
own C3/C5/C6/C7/C8). C6 (idempotent rerun) is a multi-run property that
`vm-target topology test` evidences by literally re-running the apply
playbook and observing `changed=0`; a single-host probe cannot exercise a
second run by itself, so this row is verify-only here and re-confirms trust
still holds rather than re-asserting the rerun property directly (see
docker.md's evidence section for what that second-run evidence looks like
in practice).

This spec was authored in Phase 1 of spec.md's implementation order (§63);
Phase 3 supplied the real installation logic and confirmed all six rows
against a real 3-VM topology (freeipa-server + two unenrolled clients, one
Debian-family and one RedHat-family) without changing any row ID, tag, or
expectation — see "Actual-run evidence" below.

## Checks

```yaml
- id: C1
  category: trust
  check: the installed CA certificate is a self-signed root (issuer == subject)
  probe: |
    f=/usr/local/share/ca-certificates/pilot-freeipa-ca.crt
    [ -f "$f" ] || f=/etc/pki/ca-trust/source/anchors/pilot-freeipa-ca.crt
    issuer=$(openssl x509 -in "$f" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    subject=$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject=//')
    if [ -n "$issuer" ] && [ "$issuer" = "$subject" ]; then echo self-signed; else echo not-self-signed; fi
  expect: {stdout: {equals: self-signed}}
  verifyOnly: true
- id: C2
  category: trust
  check: the installed CA bundle's SHA-256 fingerprint matches the designated freeipa-server source
  probe: |
    f=/usr/local/share/ca-certificates/pilot-freeipa-ca.crt
    [ -f "$f" ] || f=/etc/pki/ca-trust/source/anchors/pilot-freeipa-ca.crt
    got=$(openssl x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//' | tr -d ':' | tr 'A-F' 'a-f')
    if [ "$got" = "$PILOT_VAR_EXPECTED_CA_SHA256" ]; then echo match; else echo "mismatch got=$got"; fi
  expect: {stdout: {equals: match}}
  tags: [C2]
- id: C3
  category: trust
  check: Debian/Ubuntu system trust (openssl default store) verifies the installed CA
  probe: |
    [ -f /etc/debian_version ] || { echo skip; exit 0; }
    f=/usr/local/share/ca-certificates/pilot-freeipa-ca.crt
    openssl verify "$f" 2>&1 | grep -q ': OK$' && echo trusted || echo untrusted
  expect: {stdout: {regex: '^(trusted|skip)$'}}
  verifyOnly: true
- id: C4
  category: trust
  check: RedHat-family system trust (openssl default store) verifies the installed CA
  probe: |
    [ -f /etc/redhat-release ] || { echo skip; exit 0; }
    f=/etc/pki/ca-trust/source/anchors/pilot-freeipa-ca.crt
    openssl verify "$f" 2>&1 | grep -q ': OK$' && echo trusted || echo untrusted
  expect: {stdout: {regex: '^(trusted|skip)$'}}
  verifyOnly: true
- id: C5
  category: trust
  check: a host without FreeIPA (AAA) enrollment still has the CA trust file installed
  probe: |
    f=/usr/local/share/ca-certificates/pilot-freeipa-ca.crt
    [ -f "$f" ] || f=/etc/pki/ca-trust/source/anchors/pilot-freeipa-ca.crt
    if [ -f /etc/ipa/default.conf ]; then echo enrolled; elif [ -f "$f" ]; then echo trust-without-enrollment; else echo missing; fi
  expect: {stdout: {regex: '^(enrolled|trust-without-enrollment)$'}}
  verifyOnly: true
- id: C6
  category: idempotency
  check: trust remains correctly installed after a clean rerun (rerun changed=0 evidenced by vm-target topology test, not by this probe)
  probe: |
    f=/usr/local/share/ca-certificates/pilot-freeipa-ca.crt
    [ -f "$f" ] || f=/etc/pki/ca-trust/source/anchors/pilot-freeipa-ca.crt
    [ -f "$f" ] && echo present || echo absent
  expect: {stdout: {equals: present}}
  verifyOnly: true
```

## PASS / FAIL

All applicable C1-C6 rows must pass. An unresolved host, runner error,
timeout, or matcher failure makes the deployment transaction fail.
`not_applicable` is not used by this contract; C3/C4 self-skip with a
`skip` marker on the non-matching OS family instead, since v2 does not
filter hosts by `targets.platforms` at runtime.

## Traceability

- C2 maps directly to playbook tag `C2` (the CA bundle install/update task).
- C1, C3, C4, C5, and C6 verify effective trust-store behavior derived from
  that same installation and are intentionally verification-only.

## Actual-run evidence

2026-08-13, a disposable 3-VM `pilot vm-target` topology (`ca-trust-ipa`
AlmaLinux 9 as the freeipa-server, `ca-trust-ubuntu` Ubuntu 24.04 and
`ca-trust-el` AlmaLinux 9 as two managed hosts with no FreeIPA/AAA
enrollment). Full transcripts, PLAY RECAPs, and the real bug this round
found and fixed (a `--check`-mode assert crash caused by an
`ansible.builtin.command` task missing `check_mode: false`) are recorded in
`docs/evidence/freeipa-ca-trust/2026-08-13.md`.

```
$ pilot vm-target verify --name ca-trust-ubuntu docs/verification/freeipa-ca-trust.md \
    --input expected_ca_sha256=bb5e337a84469a97a3bb5baa1759169b9f3d5a14653b545a652fe9716db589b3
verdict: PASS  (pass=6 fail=0 skip=0)

$ pilot vm-target verify --name ca-trust-el docs/verification/freeipa-ca-trust.md --input ...
verdict: PASS  (pass=6 fail=0 skip=0)

$ pilot vm-target verify --name ca-trust-ipa docs/verification/freeipa-ca-trust.md --input ...
verdict: PASS  (pass=6 fail=0 skip=0)
```

C3/C4 confirmed to self-skip on the non-matching OS family and `trusted` on
the matching one; C5 confirmed `trust-without-enrollment` on both unenrolled
clients and `enrolled` on the freeipa-server itself; C6 confirmed via a
second real `freeipa-ca-trust-apply.yml` run producing `changed=0 failed=0`
on all three hosts.

2026-08-14, Phase 10's fresh full-topology re-confirmation round (3 new
disposable VMs: `p10-ipa` AlmaLinux 9 FreeIPA server, `p10-app` Ubuntu 24.04
never FreeIPA-enrolled, `p10-proxy` Ubuntu 24.04 freeipa-client +
reverse-proxy). One grouped-inventory `pilot verify` run against all three
hosts at once (rather than three separate `vm-target verify` calls):

```
$ pilot verify docs/verification/freeipa-ca-trust.md -i <grouped-inventory> \
    --input expected_ca_sha256=b99d559c307a74df1204736c87093cc2a25c7f73151de464c4634c2571aac95a
verdict: PASS  (pass=18 fail=0 skip=0)
```

No regressions found. See `docs/evidence/internal-endpoint/2026-08-14-phase10.md`
for the full round (this spec's own re-confirmation is one part of a larger
combined internal-endpoint/reverse-proxy/freeipa-ca-trust topology round).

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-08-13 | DRAFT | Phase 1 (spec.md §63): initial Spec v2 authoring. No actual-run evidence yet — the apply playbook is a Phase-1 skeleton; Phase 3 supplies real installation logic and VM evidence. |
| 2026-08-13 | v1.0 | Phase 3: real installation logic (`tasks/freeipa-ca-trust.yml`, spec.md §5.6) landed and confirmed against a real 3-VM topology — all 6 rows PASS on both Debian- and RedHat-family hosts, idempotent rerun confirmed (`changed=0`). Fixed a real `--check`-mode assert crash found by the first dry-run (see evidence doc). |
| 2026-08-14 | v1.0 | Phase 10: re-confirmed clean (18/18) against a fresh, independent 3-VM topology built for the combined internal-endpoint/reverse-proxy/freeipa-ca-trust round — no regressions. |
