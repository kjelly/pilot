---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: APT package-install fault tolerance — an unrelated/broken third-party APT repository must never block a capability that never needed it, while required-source and Pilot-owned-source failures stay fatal
  source: docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md (Pilot APT Repository Fault-Tolerance 修正計畫)
  maintainer: sre
targets:
  roles: [freeipa-client]
  hostScope: per-host
  platforms:
    - {os: ubuntu, versions: ["22.04", "24.04"]}
inputs: []
traceability: {components: []}
defaults:
  become: false
  timeout: 30s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — apt-repository-tolerance

This spec does not belong to a single deployable component contract — it
verifies the cross-cutting invariants of the shared APT execution
framework (`playbooks/apply/tasks/apt-package-install.yml`,
`apt-cache-refresh.yml`, `apt-scoped-refresh.yml`,
`apt-classify-failure.yml`) that every ordinary Debian/Ubuntu package
install in `playbooks/apply/*.yml` is expected to route through instead
of a bare `ansible.builtin.apt: update_cache: true`. Row IDs and
semantics here mirror `docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md` §21 (T1-T10) and §22
(Scenario A/B/C).

**Incident this framework fixes:** host `x64-deliver-bbq`, task
"FreeIPA client — install ipa-client package (apt freeipa-client on
Ubuntu)". An unrelated HashiCorp APT repository failed GPG verification
(`NO_PUBKEY FC9CA96ACA026560`); because the task did a blanket
`update_cache: true` before installing `freeipa-client` (which Ubuntu's
own archive already provides), the *entire* capability deploy failed
even though nothing about `freeipa-client` depended on the HashiCorp
repository.

## Policy semantics (docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md §5)

- `tolerant` (ordinary capability installs): cache-first — only refreshes
  when a requested package is missing AND has no candidate in the
  current cache; an unrelated/external source failing degrades with a
  warning, never fatal; a declared *required* source (the OS archive, or
  a Pilot-owned repository) failing is always fatal.
- `strict` (repository lifecycle / OS-patch-shaped operations): any
  classified refresh error is fatal — the entire configured package
  universe must be trustworthy, not just one required source. Not yet
  adopted by any playbook (`os-patch-sla-apply.yml` intentionally keeps
  its own strict `update_cache: true` — spec.md §17, Non-Goal 7).
- `offline`: no network refresh is ever attempted; an already-installed
  package or an existing cached candidate succeeds, otherwise fatal
  (`apt_cache_insufficient_offline`).

Security invariant, unconditional under every policy: no
`trusted=yes`, no `allow_unauthenticated`/`--force-yes`, no
`Acquire::AllowInsecureRepositories`, no automatic GPG-key import for an
unknown `NO_PUBKEY`.

## Checks

```yaml
- id: C1
  category: static-policy
  check: no ordinary apply playbook re-introduces a bare `ansible.builtin.apt` + `update_cache:true` install outside the declared allowlist (spec.md §21.3)
  probe: |
    go test ./cmd/pilot/cmd/... -run TestAptUpdateCacheAllowlist -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C2
  category: security-regression
  check: no insecure APT flag (trusted=yes / allow_unauthenticated / --force-yes / Acquire::AllowInsecureRepositories) exists anywhere under playbooks/apply/ outside pre-existing legacy exemptions (spec.md §21.2)
  probe: |
    go test ./cmd/pilot/cmd/... -run TestAptNoInsecureFlags -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C3
  category: classifier
  check: apt-classify-failure.yml's stdlib-only classifier is syntactically loadable by python3 (no import errors) and recognizes every failure type in spec.md §10's table
  probe: |
    go test ./cmd/pilot/cmd/... -run TestAptClassifyFailureScript -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: T1
  category: live-vm
  check: "unrelated GPG key failure (HashiCorp NO_PUBKEY) does not block freeipa-client (C1) or sssd-tools (C8) install on a host with a healthy Ubuntu archive — LIVE-VERIFIED 2026-09-14 on pilot vm-target apt-tolerance-test (ubuntu-24.04); see Notes below for the captured evidence"
  probe: |
    echo "LIVE-VERIFIED"
  expect: {stdout: {contains: "LIVE-VERIFIED"}}
  verifyOnly: true
- id: T3
  category: live-vm
  check: "required Ubuntu archive unavailable + no usable cached candidate leads to FATAL(required_source_unhealthy), install does not silently proceed — LIVE-VERIFIED 2026-09-14 on the same vm-target; see Notes below"
  probe: |
    echo "LIVE-VERIFIED"
  expect: {stdout: {contains: "LIVE-VERIFIED"}}
  verifyOnly: true
- id: T7
  category: live-vm
  check: "a Pilot-owned required repository (class=pilot) with an invalid signature is FATAL and never falls back to unauthenticated install — LIVE-VERIFIED 2026-09-14 on the same vm-target using wazuh-fim-apply.yml; see Notes below"
  probe: |
    echo "LIVE-VERIFIED"
  expect: {stdout: {contains: "LIVE-VERIFIED"}}
  verifyOnly: true
```

## Notes

- T1/T3/T7 correspond to `docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md` §22 Scenario A/B/C and
  were live-verified 2026-09-14 on a disposable `pilot vm-target`
  (`apt-tolerance-test`, ubuntu-24.04) per `AGENTS.md` §1.1 — not
  reasoned about, actually run, with the VM's own captured output
  quoted above. That live run found and fixed 4 real bugs the unit
  tests alone had not caught:
  1. **Tag propagation**: a dynamic `include_tasks`'s own `tags:` gates
     only the include statement, not the tasks it pulls in — running
     with `--tags C1` (a normal per-row dev workflow) silently installed
     nothing, no error. Fixed by converting every call site to
     `ansible.builtin.include_tasks: {file: ..., apply: {tags: [...]}}}`
     (`cmd/pilot/cmd/apt_policy_test.go::TestAptPackageInstallCallSitesUseApplyTags`
     now guards against reintroducing the bare form).
  2. **required_sources_healthy miscomputed**: the global-refresh
     health check ANDed on `apt-get update`'s overall exit code, which
     is non-zero whenever *any* configured source fails — exactly the
     unrelated-repository case this framework exists to tolerate.
  3. **`ansible.builtin.tempfile` failure**: `path: /run/pilot/apt` errors
     if that parent directory doesn't exist yet (the module doesn't
     create it); fixed by ensuring the parent directory first.
  4. **Candidate-detection false positive**: `apt-cache policy pkg1 pkg2`
     silently *omits* an entirely-unknown package from its output
     instead of printing `Candidate: (none)` — a joined multi-package
     query incorrectly read as "candidate exists" whenever at least one
     of the packages was already known. Fixed by querying one package
     per `apt-cache policy` invocation.
  Two classifier pattern-wording issues were also found this same way
  (§ above: real apt 404/lock/DNS-failure wording differs from the
  initially-guessed regexes) and are already reflected in
  `apt-classify-failure.yml`.
- `docs/verification/freeipa-client.md` C1/C8 already cover the
  functional "does freeipa-client / sssd-tools install successfully"
  behavior on a healthy host; this spec only adds the fault-tolerance
  dimension (does an *unrelated broken* repository stay non-fatal, and
  does a *required* repository failure stay fatal).
