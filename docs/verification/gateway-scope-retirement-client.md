---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: gateway scope host retirement client acceptance for Issue 227
  source: https://github.com/kjelly/pilot/issues/227
  maintainer: sre
targets:
  roles: [freeipa-client]
  hostScope: per-host
  platforms:
    - {os: almalinux, versions: ["9"]}
inputs: []
traceability: {components: []}
defaults:
  become: true
  timeout: 30s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Gateway scope retirement — client acceptance

This is a disposable lifecycle fixture for domain `ipa227.test`, scope
`i227-owned`, retiring host `retire.ipa227.test`, survivor
`keep.ipa227.test`, and fixture user `pilotuser`. It is an effective-state
acceptance contract for the shared gateway-scope / identity lifecycle.

## Target and prerequisites

The actual inventory must place only the surviving enrolled client `keep.ipa227.test`
in the verification limit `freeipa-client`. The retiring host is not a target of
this client spec. The scope and scoped HBAC/sudo fixture must exist before
retirement, and both enrolled clients must first have demonstrated real access.
The identity absent reconcile or formal host decommission must remove only the
retiring member while preserving the group, rules and survivor's effective access.

## Checks

```yaml
- id: C1
  category: authorization
  check: surviving client permits the fixture user's sshd PAM account
  probe: |
    python3 -c 'import subprocess; r=subprocess.run(["sssctl","user-checks","-a","acct","-s","sshd","pilotuser"],capture_output=True,text=True); assert r.returncode==0 and "pam_acct_mgmt: Success" in r.stdout+r.stderr; print("survivor-sshd-account-allowed")'
  expect: {exitCode: 0, stdout: {equals: "survivor-sshd-account-allowed"}}
  verifyOnly: true
- id: C2
  category: authorization
  check: surviving client permits actual passwordless root sudo
  probe: |
    runuser -u pilotuser -- sudo -n /usr/bin/id -u
  expect: {exitCode: 0, stdout: {equals: "0"}}
  verifyOnly: true
```

## Validation boundaries

Every row must pass with exit code zero and exact stdout. Server checks read
live LDAP through local SASL EXTERNAL without the publisher's ticket or ledger.
Client checks exercise SSSD's sshd PAM account decision and an actual sudo
invocation. Real SSH, shared rule immutable IDs/targets, unknown ownership,
missing retirement mappings, pending/lost-reply recovery, automember rebuild,
stale publication and second-apply idempotency are separate required target arms;
these four rows alone do not prove those arms.

These exact commands first executed successfully on the dedicated disposable
FreeIPA topology on 2026-11-04, before this document was written. Formal
candidate/tree, actual inventory, counts and failure arms belong in
[the current lifecycle evidence](../evidence/gateway-scope-retirement/LATEST.md).
