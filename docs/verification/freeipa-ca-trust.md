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

Latest: 2026-10-01, candidate `d175489` (tree `83a20d0996001915bea56aba393baef09da10db8`),
**PASS**. Summary: [`docs/evidence/freeipa-ca-trust/2026-10-01-d175489.md`](../evidence/freeipa-ca-trust/2026-10-01-d175489.md).

- Targets: 2 fresh disposable vm-targets, an AlmaLinux 9 FreeIPA server and an
  Ubuntu 24.04 host without FreeIPA enrollment; chain `freeipa-server-apply.yml`
  → `freeipa-ca-trust-apply.yml`.
- `vm-target topology test`: L3 check mode on the fresh VMs `failed=0` (the CA
  trust preview stops with a message, because check mode does not install
  FreeIPA); L4 `failed=0`; L6 `changed=0`.
- `pilot verify` of this spec on both hosts, `expected_ca_sha256` read from the
  server after the install: pass=12 fail=0 skip=0.
- A real run whose `freeipa-server` host has no `/etc/ipa/ca.crt` still fails
  closed at the gate (§5.4 message).

Earlier records: `docs/evidence/freeipa-ca-trust/2026-08-13.md` (Phase 3) and
`docs/evidence/internal-endpoint/2026-08-14-phase10.md` (Phase 10).

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-08-13 | DRAFT | Phase 1 (spec.md §63): initial Spec v2 authoring. No actual-run evidence yet — the apply playbook is a Phase-1 skeleton; Phase 3 supplies real installation logic and VM evidence. |
| 2026-08-13 | v1.0 | Phase 3: real installation logic (`tasks/freeipa-ca-trust.yml`, spec.md §5.6) landed and confirmed against a real 3-VM topology — all 6 rows PASS on both Debian- and RedHat-family hosts, idempotent rerun confirmed (`changed=0`). Fixed a real `--check`-mode assert crash found by the first dry-run (see evidence doc). |
| 2026-08-14 | v1.0 | Phase 10: re-confirmed clean (18/18) against a fresh, independent 3-VM topology built for the combined internal-endpoint/reverse-proxy/freeipa-ca-trust round — no regressions. |
| 2026-10-01 | v1.0 | Check mode on a fresh chain no longer fails at the root-CA gate: the include prints why the preview stops and skips the rest, while a real run still fails closed. No row changes. Re-confirmed against 2 fresh VMs (`docs/evidence/freeipa-ca-trust/2026-10-01-d175489.md`); the evidence section now keeps only the latest summary. |
