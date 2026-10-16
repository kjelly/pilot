# login-probe — Phase 0 real capture (2026-10-13)

Sanitized record of the Phase 0 capture the issue #11 evaluation report
(`docs/superpowers/plans/2026-10-13-issue-11-login-probe-io-pressure-evaluation.md` §4)
requires before any classifier is written (AGENTS.md §5.6). The captured
`ssh -v` stderr and exit codes the classifier is tested against live in
`internal/loginprobe/testdata/capture/` (26 captures, copied verbatim; they
contain public-key fingerprints, host names and lab addresses only, no key
material).

This is an exploratory capture, not a candidate evidence run: it ran
against the uncommitted working tree on top of `db10268`. It is the input
the classifier, spec and playbook were written from. The candidate run
that proves them is a separate record.

## Target

| Item | Value |
|---|---|
| Topology | `docs/topologies/login-probe-topology.yaml` (first version: `lp-mon` without docker/seaweedfs), brought up with `pilot vm-target topology up` |
| `lp-ipa` | AlmaLinux 9.8, `ipa-server-4.13.4-1.el9_8` |
| `lp-mon` (probe host) | Ubuntu 24.04, OpenSSH 9.6p1 (`1:9.6p1-3ubuntu13.16`), SSSD `2.9.4-1.1ubuntu6.8`, `freeipa-client 4.11.1-2` |
| `lp-target` | Ubuntu 24.04, same packages as `lp-mon` |
| `lp-target-el` | AlmaLinux 9.8, `openssh-server-9.9p1-7.el9_8.alma.1`, `sssd-client-2.9.8-4.el9_8` |
| Apply chain | `playbooks/test/login-probe-chain.yml` (freeipa-server, freeipa-client, host-monitoring, canary fixtures) — PLAY RECAP `failed=0` on all four nodes |
| Canary | `pilot-login-canary`, created through `playbooks/test/fixtures/freeipa-client-fixtures.yml` with `ipa_fixture_manage_sudorule: false`; HBAC rule `login-probe-canary` (user canary, service sshd, the three client hosts) |
| Client | system OpenSSH run as an unprivileged `pilot-login-probe` account with the pinned `ssh_config` that `login-probe-apply.yml` now renders (`ProxyCommand /usr/bin/sss_ssh_knownhostsproxy -p %p %h`, `StrictHostKeyChecking yes`, publickey only, `BatchMode yes`, `ServerAliveInterval 5`, `ServerAliveCountMax 2`) and `-v` |

## Stage signatures (classifier input)

| Injected condition | Targets | rc | Markers observed | Stage |
|---|---|---|---|---|
| none | lp-target, lp-target-el, lp-mon | 0 | `Server accepts key` → `Authenticated to … (via proxy) using "publickey".` → `Exit status 0` | `ok` |
| probe command exits 1 / is missing | lp-target | 1 / 127 | `Authenticated to …`, then the command's exit status | `session` |
| unknown account | lp-target, lp-target-el | 255 | `Offering public key` → `No more authentication methods to try.` → `Permission denied (publickey,…)`; no `Server accepts key`; sshd logs `Invalid user` | `auth` |
| key not published on the account | lp-target, lp-target-el | 255 | same as unknown account | `auth` |
| HBAC rules `login-probe-canary` and `allow_all` disabled | lp-target, lp-target-el | 255 | `Server accepts key`, no `Authenticated to`, `Connection closed by UNKNOWN port 65535` within 0.1 s; sshd logs `pam_sss(sshd:account): Access denied … fatal: Access denied for user … by PAM account configuration [preauth]` | `account` |
| `ipa user-disable pilot-login-canary` | lp-target, lp-target-el | 255 | same as HBAC denial | `account` |
| `pkill -STOP sssd_be` (sssd.service stays `active`) | lp-target, lp-target-el | 255 | banner + key exchange, `Server accepts key`, then `Connection to UNKNOWN port 65535 timed out` after 10 s | `timeout` |
| `pkill -STOP sssd_pam` (service `active`) | lp-target | 255 | same as `sssd_be` | `timeout` |
| `pkill -STOP sssd_nss` (service `active`) | lp-target | 255 | banner + key exchange, no `Server accepts key`, timed out after 10 s | `timeout` |
| `systemctl stop sssd` | lp-target | 255 | same as `sssd_nss` | `timeout` |
| host keys regenerated without re-enrollment | lp-target | 255 | `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` … `Host key verification failed.` | `hostkey` |
| name resolves but is not an enrolled host | (lp-ipa address under another name) | 255 | `No ED25519 host key is known for … and you have requested strict checking.` / `Host key verification failed.` | `hostkey` |
| sshd stopped | lp-target, lp-target-el | 255 | `sss_ssh_knownhostsproxy: connect to host … port 22: Connection refused`, `kex_exchange_identification: Connection closed by remote host`; no banner | `transport` |
| tcp/22 REJECT (tcp-reset) from the probe host | lp-target | 255 | same as sshd stopped | `transport` |
| tcp/22 DROP from the probe host | lp-target | 255 | `Connection timed out during banner exchange` after `ConnectTimeout` (10 s); no banner | `transport` |
| name does not resolve | — | 255 | `sss_ssh_knownhostsproxy: Could not resolve hostname …`; no banner | `transport` |
| FreeIPA server stopped (`ipactl stop`) | lp-target, lp-target-el | 0 | logins keep working; `sssctl domain-status` reports `Online status: Offline` | `ok` |

Decisions taken from these captures:

- The report's open question U5 holds: `Server accepts key` without
  `Authenticated to` separates a PAM account denial from an authentication
  refusal on both distributions. `ipa user-disable` lands in `account`
  (SSSD still serves the disabled user's key), not in `auth`.
- A frozen SSSD process does **not** produce a PAM denial: the login hangs
  until the client's server-alive limit. That is the issue's "sssd.service is
  active but logins fail" case, so it gets its own stage (`timeout`) and its
  own critical alert (`PilotLoginProbeLoginStalled`) next to
  `PilotLoginProbeAccountDenied`.
- `transport` is "no SSH banner was ever received"; a timeout after the
  banner is `timeout`. Both 10-second outcomes (DROP and frozen SSSD) are
  therefore told apart by the banner line, not by duration.
- A full FreeIPA outage is not a login failure for already-cached users
  (SSSD offline mode). The alert-storm drill therefore uses a site-wide HBAC
  change (every target denied at once), not `ipactl stop`.
- Connecting by IP address instead of the FQDN **also verified**
  (`sss_ssh_knownhostsproxy` found the enrolled key for the address). The
  evaluation report's claim that an IP always fails host-key verification was
  wrong; the probe still connects by FQDN because that is the host's identity
  in FreeIPA, and the playbook refuses targets whose FQDN does not resolve.

## Propagation and caching (no `sss_cache` was run at any point)

| Change | Observed |
|---|---|
| HBAC rules disabled / re-enabled | denial on the first attempt 1 s after the change; recovery on the first attempt 1 s after re-enabling |
| `ipa user-disable` / `user-enable` | the first attempt 2 s after the change still succeeded; denial within 6 s; recovery within 6 s |
| canary SSH public key replaced in FreeIPA (probe key regenerated) | **not** picked up by targets whose SSSD had already cached the canary: `sss_ssh_authorizedkeys` kept serving the old key (`Cache entry expiration time` = last refresh + 90 min, the default `entry_cache_timeout`). Failed pubkey logins do not refresh the entry; a successful login does. On `lp-target` the first success followed a `sssctl user-checks -a acct -s sshd pilot-login-canary` run (07:11:40; last failed attempt 07:11:37, first success 07:12:37). `lp-mon` refreshed at about the same time without any canary-specific action; the trigger was not identified. `lp-target-el` was left alone: its entry (cached 06:46:11, expiry 08:16:11) kept the old key until the probe attempt at 07:32:24 and served the new key from the next attempt at 07:33:24 — the first lookup after half of `entry_cache_timeout`, consistent with SSSD's default `entry_cache_nowait_percentage=50` background refresh |

Consequence: rotating the probe key must publish the new key **next to** the
old one, wait at least half of `entry_cache_timeout` (conservatively all of
it), then switch the probe and
remove the old key (`docs/runbooks/login-probe.md`). The chain publishes the
key before the canary is ever looked up on a target, so a fresh deployment
is not affected.

## Canary hardening

`ipa user-mod --sshpubkey='command="/bin/true",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding <key>'`
is accepted and stored by FreeIPA, but `sss_ssh_authorizedkeys` returns the
key **without** its options and sshd reports
`key options: agent-forwarding port-forwarding pty user-rc x11-forwarding`;
a probe run with `/bin/false` as the command exited 1, so the forced command
was not applied. Key options cannot restrict the canary on SSSD clients; the
remaining controls are the sshd-only HBAC rule, no sudo rule
(`sudo -l -U pilot-login-canary` → `User pilot-login-canary is not allowed
to run sudo on lp-mon.`), and an optional sshd `Match User` drop-in on
targets (evaluation report §3.1.6 fallback, not implemented in this
delivery). The original key without options was restored afterwards.

`pam_mkhomedir` created `/home/pilot-login-canary` on first login on both
distributions (Ubuntu 0750, AlmaLinux 0700).

## `sssctl user-checks -a acct -s sshd <user>` (issue #11 R4 diagnostic)

| Case | rc | stdout | stderr |
|---|---|---|---|
| allowed | 0 | user/action/service header, NSS and InfoPipe lookups, `testing pam_acct_mgmt` | `pam_acct_mgmt: Success` |
| HBAC denied | 0 | same as allowed | `pam_acct_mgmt: Permission denied` |
| unknown user | 0 | header, `testing pam_acct_mgmt` | lookup failures, `pam_acct_mgmt: Authentication failure` |

The exit status is 0 in every case and the verdict is on stderr, so
`pilot diagnose`'s login check parses the stderr line
(`internal/diagnose/login.go`); an rc- or stdout-based check would always pass.

## I/O pressure (PSI) availability

| Host | Kernel | `/proc/pressure/io` | `CONFIG_PSI_DEFAULT_DISABLED` |
|---|---|---|---|
| lp-target, lp-mon (Ubuntu 24.04) | 6.8.0-124-generic | readable | not set |
| lp-target-el (AlmaLinux 9.8) | 5.14.0-687.5.3.el9_8 | `No such file or directory` | `y` (no `psi=1` on the command line) |

Decision: no kernel command-line change in this delivery (evaluation report
U6). EL9 hosts are covered by `HostDiskLatencyHigh`/`HostDiskQueueDeep`, and
`HostPSIUnavailable` (info) makes the missing PSI coverage visible.

## Operational findings during the capture

- With `sssd.service` stopped on an Ubuntu FreeIPA client, **root**
  public-key logins to that host also hung until sshd's 120 s
  `LoginGraceTime`. The capture script lost access to `lp-target` this way
  and the VM was rebooted to restore `sssd` (it is enabled at boot); the
  journal from that window was not persistent. Disruptive drills now arm a
  systemd timer on the target that undoes the change on its own.
- Transient `systemd-run --on-active=` timers fire with one-minute accuracy
  by default: a "25 s" sshd restart fired after 62 s.
