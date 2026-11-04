---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: gateway scope host retirement server acceptance for Issue 227
  source: https://github.com/kjelly/pilot/issues/227
  maintainer: sre
targets:
  roles: [freeipa-server]
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

# Gateway scope retirement — server acceptance

This is a disposable lifecycle fixture for domain `ipa227.test`, scope
`i227-owned`, retiring host `retire.ipa227.test`, survivor
`keep.ipa227.test`, and fixture user `pilotuser`. It is an effective-state
acceptance contract for the shared gateway-scope / identity lifecycle.

## Target and prerequisites

The actual inventory must place only the designated authority `ipa.ipa227.test`
in the verification limit `freeipa-server`. The retiring host is not a target of
this server spec. The scope and scoped HBAC/sudo fixture must exist before
retirement, and both enrolled clients must first have demonstrated real access.
The identity absent reconcile or formal host decommission must remove only the
retiring member while preserving the group, rules and survivor's effective access.

## Checks

```yaml
- id: C1
  category: retirement
  check: scope survives with keeper membership and retiring membership absent
  probe: |
    python3 -c 'import ldap,ldap.sasl; c=ldap.initialize("ldapi://%2Frun%2Fslapd-IPA227-TEST.socket"); c.sasl_interactive_bind_s("",ldap.sasl.external()); r=c.search_s("cn=pilot-target-i227-owned,cn=hostgroups,cn=accounts,dc=ipa227,dc=test",ldap.SCOPE_BASE,"(objectClass=*)",["member"]); assert len(r)==1; m=r[0][1].get("member",[]); assert b"fqdn=keep.ipa227.test,cn=computers,cn=accounts,dc=ipa227,dc=test" in m; assert b"fqdn=retire.ipa227.test,cn=computers,cn=accounts,dc=ipa227,dc=test" not in m; print("scope-preserved-retiring-member-absent")'
  expect: {exitCode: 0, stdout: {equals: "scope-preserved-retiring-member-absent"}}
  verifyOnly: true
- id: C2
  category: retirement
  check: retiring host object is absent
  probe: |
    python3 -c 'import ldap,ldap.sasl; c=ldap.initialize("ldapi://%2Frun%2Fslapd-IPA227-TEST.socket"); c.sasl_interactive_bind_s("",ldap.sasl.external()); r=c.search_s("cn=computers,cn=accounts,dc=ipa227,dc=test",ldap.SCOPE_ONELEVEL,"(fqdn=retire.ipa227.test)",["fqdn"]); assert r==[]; print("retiring-host-absent")'
  expect: {exitCode: 0, stdout: {equals: "retiring-host-absent"}}
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
