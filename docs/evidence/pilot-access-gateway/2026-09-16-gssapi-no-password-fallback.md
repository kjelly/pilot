# Pure-GSSAPI end-to-end connect (no password fallback anywhere) — vm-target Evidence (2026-09-16)

Question this answers: if password authentication is disabled site-wide, does
`pilot-access-gateway` still work — both the user→gateway login and the
gateway→target "Connect" hop? Answer: **yes, but only if the connecting
client explicitly requests GSSAPI credential delegation** — this was
previously untested (Phase 5 evidence only checked `ssh -G` config content,
never a live GSSAPI negotiation).

## Topology

Reused Phase 7/8 vm-targets:

- `ag-spike-ipa` (FreeIPA server), `ag-gw01` (gateway, `gateway_id=gpu-01`,
  `gateway_scope=gpu`, ForceCommand **on** — current default), `ag-target01`
  (real enrolled member of `pilot-target-gpu`, alice has HBAC+sudo access via
  `pilot-grant-login-gpu-test`/`pilot-grant-sudo-gpu-test` → group
  `gpu-users`).
- `ag-gw02` used as a stand-in for "the portal user's own client machine" —
  just needs to be FreeIPA-enrolled with `kinit` available, nothing
  gateway-specific about it. Wired to resolve `ag-gw01`/`ag-target01` by FQDN
  (`pilot vm-target wire --name ag-gw02 --peer ag-gw01=ag-gw01.ipa.pilot.internal --peer ag-target01=ag-target01.ipa.pilot.internal`).

## Setup: force zero fallback on both hops

Reset alice's password (`ipa passwd alice`), did the mandatory one-time
change via `kinit -f alice` from `ag-gw02` (get a **forwardable** TGT —
`Flags: FIA`).

On **both** `ag-gw01` and `ag-target01`, added a same-day-removed
`/etc/ssh/sshd_config.d/00-test-gssapi-only.conf`:

```
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication no
```

This has to sort *before* `04-ipa.conf` (which sets
`ChallengeResponseAuthentication yes`) and `05-freeipa-client-password-auth.conf`
(which forces `PasswordAuthentication yes`/`KbdInteractiveAuthentication yes`
back on — needed for password-only accounts, see that file's own comment) —
sshd's Include uses first-match-wins, so a `05-*` override alone is not
enough; `00-*` is required to actually win. Confirmed via `sshd -T`:
`passwordauthentication no`, `kbdinteractiveauthentication no`,
`pubkeyauthentication no`, `gssapiauthentication yes` — GSSAPI was the only
method left standing on both hosts.

## Hop 1 — client → gateway, real capture

```
$ ssh -o GSSAPIAuthentication=yes -o GSSAPIDelegateCredentials=yes \
      -o PreferredAuthentications=gssapi-with-mic,gssapi-keyex \
      alice@ag-gw01.ipa.pilot.internal -- "echo HOP1_OK; whoami; klist -f"
...
debug1: Authentications that can continue: gssapi-keyex,gssapi-with-mic
debug1: Next authentication method: gssapi-with-mic
debug1: Delegating credentials
Authenticated to ag-gw01.ipa.pilot.internal (via proxy) using "gssapi-with-mic".
...
HOP1_OK
alice
Ticket cache: FILE:/tmp/krb5cc_261200004_edePGjYMu1
Default principal: alice@IPA.PILOT.INTERNAL
Valid starting     Expires            Service principal
09/16/26 03:34:07  09/17/26 03:25:12  krbtgt/IPA.PILOT.INTERNAL@IPA.PILOT.INTERNAL
	Flags: FfAT
```

`Authentications that can continue` lists only GSSAPI — password/pubkey/
keyboard-interactive are gone from the offer entirely (not just refused).
Login succeeded, and alice's session on the gateway has a **delegated**
ticket (`Flags: FfAT` — forwarded).

## Hop 2 — gateway → target, using the real `/etc/pilot/ssh_config`

From inside that same session (same command chained through hop 1), using
the exact invocation `cmd/pilot/cmd/portal_ssh.go`'s `buildConnectSSHCmd`
uses (`ssh -F /etc/pilot/ssh_config <fqdn>`, no other flags):

```
$ ssh ...alice@ag-gw01... -- "ssh -F /etc/pilot/ssh_config ag-target01.ipa.pilot.internal -- 'echo HOP2_OK; whoami; hostname -f'"
HOP2_OK
alice
ag-target01.ipa.pilot.internal
```

Succeeded — the delegated ticket from hop 1 carried through `/etc/pilot/ssh_config`'s
own `GSSAPIAuthentication`/`GSSAPIDelegateCredentials yes` to authenticate
hop 2, against a target host with password/pubkey/kbd-interactive **all**
disabled too.

## Negative control — delegation is required, not incidental

Same hop 1 command but `-o GSSAPIDelegateCredentials=no` (the default):

```
$ klist -f   # inside the gateway session
klist: Credentials cache keyring 'persistent:...' not found
$ ssh -F /etc/pilot/ssh_config ag-target01... -- whoami
alice@ag-target01.ipa.pilot.internal: Permission denied (gssapi-keyex,gssapi-with-mic).
```

Without delegation, alice's gateway session has **no** ticket cache at all,
and hop 2 fails outright (exit 255). Confirms the mechanism only works when
the client explicitly opts in to `GSSAPIDelegateCredentials=yes`.

## Practical precondition (why this isn't "free")

Checked `ag-gw02`'s own `/etc/ssh/ssh_config.d/04-ipa.conf` (what
`ipa-client-install` gives an enrolled client by default): it sets
`PubkeyAuthentication yes` and a known-hosts proxy command, but **does not**
turn on `GSSAPIAuthentication`/`GSSAPIDelegateCredentials`. Neither is on by
default in stock OpenSSH client config either. So even a fully FreeIPA-
enrolled client machine does not get pure-GSSAPI connect-through "for free" —
the portal user (or their machine's managed `~/.ssh/config` /
`/etc/ssh/ssh_config.d/`) has to explicitly request
`GSSAPIAuthentication yes` + `GSSAPIDelegateCredentials yes` for the gateway's
domain, and the user must hold a forwardable ticket (`kinit -f`, or
SSSD-managed desktop login that already does this) before connecting.

## Conclusion

Disabling password authentication does **not** inherently break
`pilot-access-gateway`'s ability to reach other hosts — both hops work purely
over GSSAPI when the client is Kerberos-ready and requests delegation. The
risk flagged earlier (before this test existed) was correct that this path
was *untested*, not that it was broken. The real remaining requirement to
document/operationalize before disabling password auth site-wide: every
portal user's client environment must (a) be able to `kinit` a forwardable
ticket for the realm, and (b) have `GSSAPIAuthentication yes` +
`GSSAPIDelegateCredentials yes` configured for the gateway's domain — neither
of which is a default anywhere in this chain.

## Incident during testing — accidental self-lockout, recovered

Disabling `PubkeyAuthentication` (needed to prove *zero* fallback, not just
no password) also broke `pilot vm-target exec`'s own access to `ag-gw01`/
`ag-target01`, since it authenticates as root via SSH key. Recovery required
powering off both VMs (`virsh shutdown`, run by the user directly — the
auto-mode classifier correctly blocks an agent from power-cycling a running
VM without explicit human action) and editing the sshd config offline via
`sudo virt-customize -a <overlay.qcow2> --run-command ...` against the
qcow2 disk, then `virsh start` to boot back up. `pilot-access-gateway.socket`
came up `failed` on the reboot (`Failed to resolve group
role-pilot-portal-user: Connection refused` — SSSD wasn't up yet when the
socket unit's `sd-chown` control process ran, a boot-ordering race unrelated
to this test); `systemctl reset-failed` + `systemctl start` once SSSD caught
up fixed it, confirmed via `/v1/health` → `"status":"ok"`.

**Takeaway for future GSSAPI-only testing on vm-target**: never disable
`PubkeyAuthentication` on a vm-target you still need `pilot vm-target exec`
access to recover from — restrict the "no fallback" test to
`PasswordAuthentication`/`KbdInteractiveAuthentication`/
`ChallengeResponseAuthentication` only, which is sufficient to prove the
GSSAPI-only claim without cutting off the management path.

## Cleanup

Removed `00-test-gssapi-only.conf` and restored the original
`05-freeipa-client-password-auth.conf` (both hosts) and
`90-pilot-access-gateway.conf` (`ag-gw01`) via the offline `virt-customize`
edit above — verified byte-identical to their pre-test content via
`guestfish --ro`. Left the `ag-gw02` `/etc/hosts` wire block in place
(harmless, reusable for future cross-VM tests). Alice's FreeIPA password is
now `TestGss456!` (changed during this test) — the account itself is
otherwise unchanged (still only member of `ipausers`, `role-pilot-portal-user`,
`gpu-users`).
