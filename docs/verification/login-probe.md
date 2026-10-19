---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: login-probe (per-site external SSH/PAM login canary for FreeIPA-enrolled hosts, GitHub issue kjelly/pilot#11)
  source: docs/superpowers/plans/2026-10-13-issue-11-login-probe-io-pressure-evaluation.md §3.1 (A) and §4 Phase 1-4
  maintainer: sre
targets:
  roles: [login-probe]
  hostScope: per-host
  platforms:
    - {os: ubuntu, versions: ["24.04"]}
inputs: []
traceability: {components: [login-probe]}
defaults:
  become: true
  timeout: 15s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — login-probe

Decommission acceptance: absence from the rendered target list alone does
not prove that a running daemon stopped contacting a retired host. A clean
query must either observe a never-installed service with no managed runtime
files, or prove that an active, stable service invocation matches the
root-owned activation record and current binary/config/unit hashes. Missing,
unsafe, unreadable or inconsistent proof must request reconciliation or fail
explicitly. After an interrupted render, the production provider's
Inspect → Execute → Verify path must activate the new config, stop retired
SSH attempts, retain healthy targets, and converge without another mutation.
The query itself must remain read-only.

Acceptance for the per-site login probe (`pilot-login-probe` binary,
`playbooks/apply/login-probe-apply.yml`). The probe host is itself a
`freeipa-client` and a `host-monitoring` host (both `sameHosts`
dependencies in `contracts/login-probe.yaml`): every `login_probe_interval`
(default 60 s) it spawns the system OpenSSH client with a pinned
`ssh_config` and logs in to every configured target as the least-privileged
FreeIPA canary account (`login_probe_user`, default `pilot-login-canary`,
public-key only, no sudo, non-interactive `login_probe_command`, default
`/bin/true`). Host-key trust is **not** re-implemented: the `ssh_config`
uses `ProxyCommand /usr/bin/sss_ssh_knownhostsproxy` with
`StrictHostKeyChecking yes` and `GlobalKnownHostsFile
/var/lib/sss/pubconf/known_hosts`, the same SSSD/FreeIPA path
`pilot-access-gateway` uses (AGENTS.md §5.9: never an apply-time
`ssh-keyscan` snapshot, never TOFU).

Every attempt ends in exactly one **stage**, published as
`pilot_login_probe_last_stage{probe_target,stage}` through the
node_exporter textfile collector (`probe_target` is the target's lower-case
inventory name, never its address — AGENTS.md §5.13). The stage set and the
OpenSSH client signatures behind it were captured on a real four-node
vm-target topology on 2026-10-13 (docs/evidence/login-probe/, Phase 0),
not inferred from documentation (AGENTS.md §5.6):

| stage | what was observed (OpenSSH `-v` client side) | injected cause |
|---|---|---|
| `ok` | `Server accepts key` → `Authenticated to … using "publickey"` → `Exit status 0` | — |
| `session` | `Authenticated to …` then non-zero `Exit status N`, rc = N | probe command exited 1 / 127 |
| `auth` | `Offering public key` → `No more authentication methods to try.` → `Permission denied (publickey,…)`, rc 255, **no** `Server accepts key` | unknown account; key not published on the account |
| `account` | `Server accepts key` → `Connection closed by UNKNOWN port 65535`, rc 255, **no** `Authenticated to`; target sshd logs `pam_sss(sshd:account): Access denied … fatal: Access denied for user … by PAM account configuration` | HBAC rule disabled (observed within 1 s of the change, no `sss_cache`); `ipa user-disable` (observed after ≤ 6 s) |
| `timeout` | transport established, then `Connection to UNKNOWN port 65535 timed out` (OpenSSH `ServerAliveInterval 5`/`ServerAliveCountMax 2`, ≈ 15 s) or the daemon's own `login_probe_total_timeout` | `sssd_be`, `sssd_pam` or `sssd_nss` stopped with SIGSTOP while `sssd.service` stays `active` — the issue's "service active but logins hang" case |
| `hostkey` | `Host key verification failed.` | host re-keyed without re-enrollment; name not enrolled in IPA |
| `transport` | `Connection timed out`/`Connection refused`/`Could not resolve hostname`/proxy failure before any authentication exchange | sshd stopped, port dropped/rejected, unresolvable name |

The probe never records stdout of the probe command, never logs OpenSSH
output beyond one redacted summary line, and never publishes anything but
fixed-enum labels. The canary account, its public key and the sshd-only
HBAC rule are directory objects managed by the `freeipa-identity` roster in
production (`playbooks/test/fixtures/login-probe-fixtures.yml` is the
test-side equivalent). The probe host generates its own ed25519 key pair
at apply time unless `login_probe_ssh_private_key` is supplied from the
vault; the private key never leaves the host otherwise.

C13 is `verifyOnly` for the same reason as `detection-engine.md`'s C11: a
single already-applied host cannot inject HBAC denial, a frozen SSSD
backend or a dropped port against itself — that scenario evidence comes
from the login-probe topology drills (docs/evidence/login-probe/), and
this row's own probe only confirms every stage series is structurally
published for every target. C14 (idempotent re-apply) is the usual
multi-run property.

Applying a binary (C1), configuration (C3), or unit (C6/C12) update must
activate it in the running daemon, including a tagged apply and a retry
after files were written without a completed restart. Removed targets
must disappear from the daemon's SSH attempts and metrics; added targets,
the canary user and the interval must match the new configuration. An
unchanged healthy activation remains idempotent. A replacement process
must rewrite its metrics before apply records it as healthy; an existing
textfile alone cannot prove that replacement healthy. Failed updates
restore the prior managed files and service state and remain retryable.
These are multi-run acceptance properties, covered by the runtime
regression and disposable VM update/failure scenarios in the latest
evidence; C3's single-host probe independently validates the disk schema.

## Checks

```yaml
- id: C1
  category: artifact
  check: the installed binary is the expected artifact and reports a valid version string (controller-side sha256/version equality is enforced by the apply playbook's preflight gate before this host is mutated)
  probe: |
    /usr/local/bin/pilot-login-probe version
  expect: {stdout: {regex: '^pilot-login-probe \S+ \(\S+\)'}}
  tags: [C1]
- id: C2
  category: service
  check: dedicated pilot-login-probe system account (nologin) runs an active pilot-login-probe.service
  probe: |
    getent passwd pilot-login-probe | grep -q '/usr/sbin/nologin$' || exit 1
    systemctl is-active pilot-login-probe.service
  expect: {stdout: {equals: active}}
  tags: [C2]
- id: C3
  category: config
  check: the rendered config.yml passes `config validate` (unknown keys, timing order, label-safe target names and FQDN hosts are all enforced by the binary's loader)
  probe: |
    /usr/local/bin/pilot-login-probe config validate --config /etc/pilot/login-probe/config.yml
  expect: {stdout: {equals: "config valid"}}
  tags: [C3]
- id: C4
  category: identity
  check: the canary private key is readable only by the service account (0600) and its public key sits beside it for the operator to publish on the canary user
  probe: |
    test -s /etc/pilot/login-probe/id_ed25519.pub || exit 1
    stat -c '%U:%G %a' /etc/pilot/login-probe/id_ed25519
  expect: {stdout: {equals: "pilot-login-probe:pilot-login-probe 600"}}
  tags: [C4]
- id: C5
  category: trust
  check: the pinned ssh_config takes host-key trust from SSSD/FreeIPA (sss_ssh_knownhostsproxy + StrictHostKeyChecking) and disables every interactive, forwarding and non-pubkey path
  probe: |
    f=/etc/pilot/login-probe/ssh_config; missing=""
    while IFS= read -r want; do
      grep -qxE "[[:space:]]*${want}" "$f" || missing="$missing [$want]"
    done <<'DIRECTIVES'
    ProxyCommand /usr/bin/sss_ssh_knownhostsproxy -p %p %h
    StrictHostKeyChecking yes
    GlobalKnownHostsFile /var/lib/sss/pubconf/known_hosts
    UserKnownHostsFile /dev/null
    IdentitiesOnly yes
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    GSSAPIAuthentication no
    BatchMode yes
    ForwardAgent no
    ClearAllForwardings yes
    RequestTTY no
    DIRECTIVES
    [ -z "$missing" ] && echo all-pinned || echo "missing:$missing"
  expect: {stdout: {equals: all-pinned}}
  tags: [C5]
- id: C6
  category: network
  check: the probe has no TCP/UDP listener of its own (it only ever dials out through OpenSSH)
  probe: |
    pid=$(systemctl show -p MainPID --value pilot-login-probe.service)
    ss -H -tulnp 2>/dev/null | grep -q "pid=${pid}," && echo listening || echo no-listener
  expect: {stdout: {equals: no-listener}}
  tags: [C6]
- id: C7
  category: observability
  check: the textfile collector file is present, declares the probe's metric families and was rewritten within the last 120 s; apply also authenticates to the same-host node_exporter and proves a temporary textfile sample is exposed before removing the sample
  probe: |
    f=/var/lib/node_exporter/textfile/pilot_login_probe.prom
    grep -q '^# TYPE pilot_login_probe_success gauge$' "$f" || exit 1
    grep -q '^# TYPE pilot_login_probe_last_stage gauge$' "$f" || exit 1
    lw=$(awk '/^pilot_login_probe_metrics_last_write_timestamp_seconds /{print int($2)}' "$f")
    now=$(date +%s)
    [ -n "$lw" ] && [ $((now - lw)) -lt 120 ] && echo fresh || echo "stale:${lw:-none}"
  expect: {stdout: {equals: fresh}}
  tags: [C7]
- id: C8
  category: secret
  check: neither the textfile nor the service journal carries key material (issue #11 R2 — credentials and private keys stay out of logs and metrics)
  probe: |
    f=/var/lib/node_exporter/textfile/pilot_login_probe.prom
    if { cat "$f"; journalctl -u pilot-login-probe.service --since -30min --no-pager 2>/dev/null; } | grep -qE 'PRIVATE KEY|ssh-ed25519 AAAA|AAAAC3NzaC1'; then echo leaked; else echo clean; fi
  expect: {stdout: {equals: clean}}
  tags: [C8]
- id: C9
  category: canary
  check: the canary account resolves through SSSD on this host and has no sudo rule anywhere (issue #11 R1 — least-privileged, no sudo); captured 2026-10-13 on a real freeipa-client as `User pilot-login-canary is not allowed to run sudo on <host>.`
  probe: |
    user=$(awk '/^user:/{print $2}' /etc/pilot/login-probe/config.yml); user=${user:-pilot-login-canary}
    getent passwd "$user" | grep -q "^${user}:" || { echo "unresolvable:$user"; exit 0; }
    sudo -n -l -U "$user" 2>&1 | grep -q 'is not allowed to run sudo' && echo least-privileged || echo "has-sudo:$user"
  expect: {stdout: {equals: least-privileged}}
  tags: [C9]
- id: C10
  category: login
  check: the daemon's own rounds reach a full login (stage ok) on at least one target within two intervals — the canary key must already be published on the canary user and the HBAC rule must allow sshd (roster or fixtures), otherwise every target stays in auth/account
  probe: |
    f=/var/lib/node_exporter/textfile/pilot_login_probe.prom
    for i in $(seq 1 30); do
      if grep -qE '^pilot_login_probe_success\{probe_target="[^"]+"\} 1$' "$f" 2>/dev/null; then echo ok; exit 0; fi
      sleep 5
    done
    grep -E '^pilot_login_probe_last_stage\{[^}]*\} 1$' "$f" 2>/dev/null | sed 's/^/no-success: /' | head -n 10
  expect: {stdout: {equals: ok}}
  timeout: 180s
  tags: [C10]
- id: C11
  category: diagnostic
  check: the one-shot `probe --json` round (the runbook's first diagnostic command, also what `pilot diagnose` runs) succeeds against at least one target and reports every target with a stage from the fixed enum
  probe: |
    out=$(/usr/local/bin/pilot-login-probe probe --config /etc/pilot/login-probe/config.yml --json 2>/dev/null; true)
    printf '%s' "$out" | grep -q '"stage": "ok"' || { echo no-ok; exit 0; }
    printf '%s' "$out" | grep -o '"stage": "[a-z]*"' | grep -vqE '"stage": "(ok|transport|hostkey|auth|account|session|timeout)"' && echo unknown-stage || echo ok
  expect: {stdout: {equals: ok}}
  timeout: 90s
  tags: [C11]
- id: C12
  category: hardening
  check: the unit runs as the dedicated account with NoNewPrivileges and ProtectSystem=strict (only the textfile directory and its state directory are writable)
  probe: |
    systemctl show -p User -p NoNewPrivileges -p ProtectSystem pilot-login-probe.service | sort | tr '\n' ' '
  expect: {stdout: {equals: "NoNewPrivileges=yes ProtectSystem=strict User=pilot-login-probe "}}
  tags: [C12]
- id: C13
  category: fixture
  check: every configured target publishes the complete stage enum (ok, transport, hostkey, auth, account, session, timeout) so the account/auth/transport/stall/stale alert rules always have a series to read — the scenario evidence (HBAC denial while sssd.service is active, frozen SSSD backend, dropped port, probe daemon stopped) comes from the login-probe topology drills in docs/evidence/login-probe/, not from this single host
  probe: |
    f=/var/lib/node_exporter/textfile/pilot_login_probe.prom
    targets=$(awk '/^pilot_login_probe_targets /{print int($2)}' "$f")
    series=$(grep -cE '^pilot_login_probe_last_stage\{probe_target="[^"]+",stage="(ok|transport|hostkey|auth|account|session|timeout)"\} [01]$' "$f")
    [ "${targets:-0}" -ge 1 ] && [ "$series" -eq $((targets * 7)) ] && echo complete || echo "incomplete:targets=${targets:-0},series=${series}"
  expect: {stdout: {equals: complete}}
  verifyOnly: true
- id: C14
  category: idempotency
  check: a second apply of the same candidate is a no-op (`changed=0`) — multi-run evidence recorded in docs/evidence/login-probe/; this probe only confirms the unit stays enabled across re-applies
  probe: |
    systemctl show -p UnitFileState --value pilot-login-probe.service
  expect: {stdout: {equals: enabled}}
  verifyOnly: true
```

## PASS / FAIL

All C1-C14 rows must pass for the component to be VERIFICATION_READY. C10
and C11 require the canary key to be published on the canary user and the
HBAC rule to allow sshd on at least one target: in production that is the
`freeipa-identity` roster, in the vm-target chain
`playbooks/test/fixtures/login-probe-fixtures.yml` (run after the apply,
because the apply generates the key the fixture publishes).

## Traceability

- C1-C12 map to their playbook tags (same names) in
  `playbooks/apply/login-probe-apply.yml`.
- C13 and C14 are intentionally `verifyOnly` — see the note above.
- The Prometheus alert rules that consume these metrics
  (`PilotLoginProbeAccountDenied`, `PilotLoginProbeAuthFailed`,
  `PilotLoginProbeLoginStalled`, `PilotLoginProbeTransportFailed`,
  `PilotLoginProbeStale`, `PilotLoginProbeNoTargets`, `HostMetricsMissing`)
  and the host I/O pressure rules live in `docs/verification/prometheus.md`
  (host-health rule file) and `docs/verification/alertmanager.md`
  (inhibit rules).

## Actual-run evidence

Phase 0 capture (stage signatures, HBAC/disable propagation without
`sss_cache`, `sss_ssh_authorizedkeys` dropping key options, PSI absent on
AlmaLinux 9): `docs/evidence/login-probe/2026-10-13-phase0-ssh-capture.md`.
Apply/verify/idempotency and the four issue #11 drills: see the latest
`docs/evidence/login-probe/` record referenced from
`docs/runbooks/login-probe.md` §0.5.

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-10-13 | DRAFT | Initial Spec v2 authoring after the Phase 0 real capture (issue #11, evaluation report §4 Phase 1). |
