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
  when a requested package is missing AND either has no candidate in the
  current cache or its cached candidate's `--download-only` probe hits a
  package-download 404 (stale metadata, spec.md §5's "install 顯示
  metadata stale" branch); an unrelated/external source failing degrades with a
  warning, never fatal; a declared *required* source (the OS archive, or
  a Pilot-owned repository) failing is always fatal. On the stale-metadata
  path the old candidate is trusted again only after a refresh that was
  healthy for the required sources **and** a re-probe without 404s;
  otherwise `FATAL reason=stale_metadata_unrecovered`. Every `apt-get update`
  (`pilot_apt_update_timeout_seconds`, default 300) and every download probe
  (`pilot_apt_download_timeout_seconds`, default 900) runs under a wall
  clock. A timed-out refresh is recorded as `type=refresh_timeout` and never
  counts as healthy; a timed-out probe is `FATAL reason=apt_download_timeout`.
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
- id: C4
  category: stale-metadata
  check: a cached candidate is probed with apt-get --download-only before the single sanctioned install, and a package-download 404 (stale metadata) takes the global-refresh path; the probe's regex matches a real stale-index capture and does not match real non-404 failures
  probe: |
    go test ./cmd/pilot/cmd/... -run TestAptPackageInstallStaleMetadataProbe -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C5
  category: refresh-bounds
  check: every apt-get network step (global/scoped update, download probe) runs under coreutils timeout with its documented default; a timeout (rc 124, or -9 when the KILL was needed, as Python's subprocess reports it — checked against the real coreutils timeout) is never a healthy refresh; on the stale-metadata path the install needs a healthy refresh plus a 404-free re-probe, else FATAL(stale_metadata_unrecovered)
  probe: |
    go test ./cmd/pilot/cmd/... -run 'TestAptNetworkStepsHaveWallClock|TestAptTimeoutExitCodes|TestAptStaleMetadataNeedsWorkingRefresh' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: T8
  category: live-vm
  check: "a host whose apt lists predate the mirror (cached Candidate exists, its .debs 404) refreshes once and installs, instead of failing with 'E: Failed to fetch ... 404' — LIVE-VERIFIED 2026-09-23 on pilot vm-target apt-stale-probe (fresh ubuntu-24.04 golden image); see Notes below"
  probe: |
    echo "LIVE-VERIFIED"
  expect: {stdout: {contains: "LIVE-VERIFIED"}}
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
- T8 (2026-09-23): found while provisioning a fresh ubuntu-24.04 vm-target
  for the captive-transport E2E — `freeipa-client` had a cached
  `Candidate: 4.11.1-2`, so the old cache-first check never refreshed,
  and the install failed on 26 dependency `.deb`s (krb5 1.20.1-6ubuntu2.6,
  sssd 2.9.4-1.1ubuntu6.5, tzdata-legacy) that the mirror had already
  superseded (`E: Failed to fetch <url>  404  Not Found`). Any real host
  whose lists sit unrefreshed for weeks hits the same thing. With the
  `--download-only` probe, the same kind of stale host ran
  `apt_mode=global_refresh stale_metadata=True` → `changed=1`; the second
  run was `apt_mode=already_present` (`changed=0`); and on the now-fresh
  index a not-yet-installed package ran `apt_mode=cache_hit
  stale_metadata=False` with no `apt-get update`.
- T11/T12 and C5 (2026-09-23, candidate `5b735ee`): live on a disposable
  vm-target whose lists were stale, using a local test proxy.
  - Index requests that never answer: both refreshes were ended by the wall
    clock (`rc=124`, `type=refresh_timeout`) →
    `FATAL reason=stale_metadata_unrecovered` in 46 s, nothing installed.
    The pre-fix code ran 726 s and then installed into the same 404s.
  - Index requests that get 503: `apt-get update` exits 0, and the
    classifier sees no error. The re-probes still hit 404 →
    `FATAL reason=stale_metadata_unrecovered`. The pre-fix code installed
    straight into the 404s.
  - A download that never answers: `FATAL reason=apt_download_timeout
    stage=cache_hit`.
  - The real mirror: `global_refresh stale_metadata=True` → install, then
    `already_present` (`changed=0`).
  Evidence: [`docs/evidence/apt-repository-tolerance/2026-09-23-5b735ee.md`](../evidence/apt-repository-tolerance/2026-09-23-5b735ee.md).
- `docs/verification/freeipa-client.md` C1/C8 already cover the
  functional "does freeipa-client / sssd-tools install successfully"
  behavior on a healthy host; this spec only adds the fault-tolerance
  dimension (does an *unrelated broken* repository stay non-fatal, and
  does a *required* repository failure stay fatal).
- Scoped refresh in check mode (2026-09-24, `07b44f7`): the scoped refresh
  runs for real during `--check`, but four tasks touching its temp dir were
  simulated, so the real `cp` into a never-created `sources.list.d` failed
  in L3 on a fresh vm-target (reached because security.ubuntu.com
  intermittently served a BADSIG `noble-security` InRelease). Every task
  touching `_pilot_apt_scoped_dir` is now `check_mode: false`
  (`cmd/pilot/cmd/apt_policy_test.go::TestAptScopedRefreshTempDirTasksRunInCheckMode`).
  The same migration moved the remaining direct Debian installs (auditd,
  NFS client/server packages, dcgm-exporter's apache2-utils) onto the
  framework (`TestAptDirectInstallAllowlist`). Evidence:
  `docs/evidence/include-apply-tags-apt-framework/2026-09-24-dfb58a5.md`.
