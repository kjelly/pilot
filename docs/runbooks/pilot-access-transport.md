# Runbook — Pilot Access Gateway captive SSH transport

> Status: VERIFIED (disposable vm-target topology)
> Aligned specs: `docs/verification/pilot-access-gateway.md` (AG41–AG73),
> `docs/verification/pilot-access-target-policy.md` (TP01–TP12)
> Design: `docs/superpowers/specs/2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md`
> Automation: `playbooks/apply/pilot-access-gateway-apply.yml`,
> `playbooks/apply/pilot-access-target-policy-apply.yml`
> Maintainer: SRE

## 0. Goal

Let a workstation that can only reach a Pilot Access Gateway use ordinary
OpenSSH tools — `ssh`, `sftp`, `scp`, `rsync`, and OpenSSH-based editors such
as VS Code Remote-SSH — against authorized targets. The gateway carries the
inner SSH connection as an opaque TCP/22 byte stream (`pilot-transport-v1`).
It never gives the user a shell on the gateway, never opens sshd forwarding
on the gateway, and never accepts a caller-chosen port or address.

## 0.5 Current fact summary

Snapshot of the reference environment used for the latest verified run
(2026-09-24, candidate `fcd3c03`). Full results are in the evidence record in
§6.

| Item | Current fact |
|---|---|
| Target environment | a per-run copy of `docs/topologies/pilot-access-transport-topology.yaml` with the node names changed from `tx-` to `mx-` (VMs named `tx-*` belonged to another run), brought up with `pilot vm-target topology up`: `mx-ipa` 192.168.122.12 (AlmaLinux 9), `mx-gw` 192.168.122.13, `mx-target` 192.168.122.9, `mx-store` 192.168.122.10, `mx-ws` 192.168.122.5, all Ubuntu 24.04.4 LTS with OpenSSH 9.6p1. Torn down with `topology down` after the run |
| Inventory groups (`ansible-inventory --graph`) | `freeipa-server`: `mx-ipa`; `freeipa-client`: `mx-gw`, `mx-target`, `mx-store`; `pilot-access-gateway`: `mx-gw`; `pilot-access-target-policy`: `mx-target`; `pilot-session-store`: `mx-store`; `pilot-transport-workstation`: `mx-ws` |
| Gateway identity | `gateway_id=gpu-01`, `gateway_scope=gpu`; `mx-target` published in `pilot-target-gpu` |
| Component state after the last run | gateway transport **enabled**, no recording default (built-in `metadata`), session store URL `https://mx-store.ipa.pilot.internal:8443`; `mx-target` policy `strict`, a member of `pilot-transport-ready`, host recording policy `inherit` |
| External state | vault file with `ipa_admin_password`, `pilot_session_store_master_key`, `pilot_session_store_ingest_signing_key` and `transport_fixture_user_password` (names only); FreeIPA user `transportuser`; FreeIPA hostgroup `pilot-transport-ready` |
| Site isolation | simulated by `playbooks/test/fixtures/pilot-access-transport-isolation-fixtures.yml` (nftables drops `mx-ws` → `mx-target` tcp/22) |
| Alignment decision | **A (inventory matches the specs)**: the gateway spec runs on `pilot-access-gateway`, the target-policy spec on `pilot-access-target-policy` and the store spec on `pilot-session-store`, and all three groups exist in the topology inventory as listed above |

## 1. Scope and prerequisites

- The gateway is a working `pilot-access-gateway` host (FreeIPA client, scope
  published with `pilot gateway-scope`, ForceCommand installed).
- Every target that should be reachable is a FreeIPA client, is in the
  gateway's `pilot-target-<scope>` hostgroup, and has
  `pilot-access-target-policy` applied. Only a successful apply puts the host
  into the FreeIPA hostgroup `pilot-transport-ready`, and the gateway refuses
  a transport to any host outside it.
- `pilot_access_target_gateway_addresses` lists the source IP(s) the gateway
  uses to reach targets.
- The user is a portal user (`gateway_portal_user_group`) with FreeIPA HBAC
  access to the target. The inner SSH login is authenticated by the target's
  own sshd with the user's key or FreeIPA password; the gateway holds no
  target credential.
- Operator-owned, outside this runbook (spec §5.3): the site network must
  block workstation → target:22, must accept target:22 only from gateway
  addresses, and must block target → workstation connections. Until that is
  verified, do not describe a deployment as "target cannot reach the
  workstation".
- Recording: an opaque transport carries only metadata. A gateway whose
  `pilot_access_gateway_recording_mode` is `terminal_output` or
  `terminal_io` refuses transports. Users there keep using `pilot-connect`.

## 2. Current procedure

1. Read the real inventory first: `ansible-inventory -i <inventory> --graph`.
   For the test topology, write it with `pilot vm-target topology inventory
   --topology docs/topologies/pilot-access-transport-topology.yaml >
   <inventory>`. Confirm the gateway host is in `pilot-access-gateway`, each
   target is in `pilot-access-target-policy`, and no host is in both.
2. Apply the target policy to the targets. Start with `strict`; use
   `remote-dev` only where VS Code Remote-SSH is needed. The playbook
   validates the drop-in, verifies the effective `sshd -T -C` values per
   gateway address, and checks that non-gateway sessions are byte-identical
   to the baseline. On any mismatch it restores the previous state.

   ```bash
   ansible-playbook -i <inventory> playbooks/apply/pilot-access-target-policy-apply.yml \
       -l <target> -e '{"pilot_access_target_gateway_addresses": ["<gateway-ip>"]}' \
       -e @<vault-file>
   ```

   `strict` is the default. For `remote-dev`, add
   `-e pilot_access_target_forwarding_profile=remote-dev`. The addresses must
   be passed as JSON: Ansible treats `-e key=[...]` as a plain string.

3. Enable transport on the gateway. The recording policy must be expressed
   in group vars; the apply refuses to lower an installed policy unless you
   pass `pilot_access_gateway_recording_allow_downgrade=true`.

   ```bash
   ansible-playbook -i <inventory> playbooks/apply/pilot-access-gateway-apply.yml \
       -l <gateway> -e gateway_id=<id> -e gateway_scope=<scope> \
       -e pilot_binary_path=dist/pilot-linux-amd64 \
       -e pilot_access_gateway_binary_path=dist/pilot-access-gateway-linux-amd64 \
       -e pilot_access_gateway_transport_enabled=true -e @<vault-file>
   ```

4. Give users this workstation `ssh_config`. Both commands must be absolute
   paths: OpenSSH rejects a relative `KnownHostsCommand`. A wildcard target
   pattern must exclude the gateway alias (`!pilot-gw`).

   ```sshconfig
   Host pilot-gw
       HostName <gateway-fqdn>
       User <freeipa-user>
       ForwardAgent no
       ClearAllForwardings yes
       ControlMaster auto
       ControlPath ~/.ssh/cm-%C
       ControlPersist 10m

   Host *.<target-domain> !pilot-gw
       User <freeipa-user>
       ProxyCommand /usr/bin/ssh -T pilot-gw -- pilot-transport-v1 %h
       KnownHostsCommand /usr/bin/ssh -T pilot-gw -- pilot-known-hosts-v1 %h
       StrictHostKeyChecking yes
       UserKnownHostsFile /dev/null
       GlobalKnownHostsFile /dev/null
       UpdateHostKeys no
       CheckHostIP no
       ForwardAgent no
       ForwardX11 no
   ```

   The gateway's own host key goes in the normal `~/.ssh/known_hosts`;
   verify it the way you would for any SSH server before the first use.
   Target host keys come only from FreeIPA (`ipaSshPubKey`), so there is no
   TOFU and nothing about a target is written to `known_hosts`. On an OpenSSH
   older than 8.5 (no `KnownHostsCommand`), export the keys once instead:
   `ssh -T pilot-gw -- pilot-known-hosts-v1 <fqdn> >> ~/.ssh/pilot_known_hosts`.
   Then replace the `KnownHostsCommand` and `UserKnownHostsFile` lines with
   `UserKnownHostsFile ~/.ssh/pilot_known_hosts`.

## 3. Verification

- `pilot verify docs/verification/pilot-access-gateway.md -i <inventory> -l
  <gateway> --input gateway_id=<id> --input gateway_scope=<scope>` (includes
  AG41–AG44; AG01 compares the deployed id/scope with those inputs) and `pilot verify
  docs/verification/pilot-access-target-policy.md -i <inventory> -l <target>`
  (TP01–TP05).
- On a disposable copy of the topology only:
  `scripts/pilot-access-gateway-lockout-test.sh` (with `TRANSPORT_TARGET=`) and
  `scripts/pilot-access-gateway-transport-e2e.sh --phase <state>`. Both
  require `CONFIRM_DISPOSABLE=yes` and must never be pointed at a real host.
  The `recording` phase records into the topology's session store (`tx-store`):
  set `pilot_access_gateway_recording_mode=terminal_output` and
  `pilot_access_gateway_recording_session_store_url=https://tx-store.ipa.pilot.internal:8443`
  on the gateway, and give the script `STORE_HOST`/`STORE_ADMIN_KEY`.
- Audit: `journalctl -t pilot-access-gateway -o cat` on the gateway shows one
  JSON line per event. Each session produces
  `gateway_transport_requested` → `connected` → `closed` (target IP, bytes,
  duration). Refusals produce `gateway_transport_denied`.

## 4. Rollback

- Stop new transports: re-apply the gateway without
  `pilot_access_gateway_transport_enabled` (or with `=false`). Portal,
  `pilot-connect`, and the ForceCommand lockout are unaffected. Established
  sessions run until they close; authorization is checked per connection.
- Remove a target from transport: re-apply the target policy with
  `pilot_access_target_policy_state=absent`. It leaves
  `pilot-transport-ready` first and removes the drop-in second, so a target
  never stays reachable after its restrictions are gone.

## 5. Current gotchas

- **`KnownHostsCommand` needs an absolute path.** With `KnownHostsCommand
  ssh …`, OpenSSH prints `KnownHostsCommand-ORDER path is not absolute`, then
  `No ED25519 host key is known for <target>`, and refuses the connection. Use
  `/usr/bin/ssh` in both `ProxyCommand` and `KnownHostsCommand`.
- **A config kept in its own file must be passed down.** When users run
  `ssh -F <file>`, the nested `ssh` in `ProxyCommand`/`KnownHostsCommand`
  does not inherit it and fails with `ssh: Could not resolve hostname
  pilot-gw`. Write `-F <absolute path>` in both commands, or put the block in
  `~/.ssh/config` (or an `Include` from it).
- **A wildcard target pattern must exclude the gateway alias** (for example
  `Host * !pilot-gw`, as the E2E config does). Otherwise the `ProxyCommand`
  would also apply to the gateway hop itself.
- **The transport and host-key verbs refuse a TTY.** Use `ssh -T`. `ssh -tt …
  pilot-transport-v1` fails with `a TTY is not allowed for transport`. The
  portal and `pilot-connect` are the opposite: they need a TTY and fail
  without one (`a TTY is required for this session`).
- **Stable refusal messages** (stderr, exit 1). The user sees them directly:
  `pilot-transport: transport not enabled for this target` (transport off, or
  target not in `pilot-transport-ready`),
  `pilot-transport: transport disabled by recording policy`,
  `pilot-transport: access denied` (no HBAC, or out of scope), and `usage: …`
  (IP address, `host:port`, `user@host`, or anything that is not a single
  FQDN). `pilot-known-hosts-v1` answers `access denied` for every target it
  may not open. The "not enabled" message covers both reasons on purpose.
  The exact reason is in the `result` field of the `gateway_transport_denied`
  audit event (`journalctl -t pilot-access-gateway -o cat`). Values seen in
  the verified run: `transport_disabled`, `transport_target_not_ready`,
  `recording_incompatible`, and `authorize_denied`.
- **Recording downgrades are refused.** A group-vars change from
  `terminal_output`/`terminal_io` to `metadata` stops the apply with
  `Refusing to lower`, and the installed config stays unchanged. Pass
  `pilot_access_gateway_recording_allow_downgrade=true` only for a deliberate
  downgrade.
- **VS Code Remote-SSH needs `remote-dev`.** It reaches its server through a
  local or dynamic forward to target loopback, which `strict` refuses.
  `remote-dev` allows only `-L`/`-D` to target loopback. `-R`, agent, X11,
  tunnel devices, and forwards to other hosts stay refused. Only the OpenSSH
  behavior is verified (TP08), not VS Code itself.
- **Portal group membership is read from the peer's kernel groups.** A user
  whom automember adds to the portal group after the gateway's SSSD cached the
  group's member list is served at once (fixed in `f1d1552`). Before that fix,
  the gateway API answered such a user with `{"error":"unauthorized"}` until
  the SSSD cache expired.

## 6. Latest verified evidence

- 2026-09-24 — [`docs/evidence/pilot-access-gateway/2026-09-24-fcd3c03.md`](../evidence/pilot-access-gateway/2026-09-24-fcd3c03.md).
  Candidate `fcd3c03` (tree `59aa59ee…`), after the merge with per-host SSH
  session recording. Topology test on never-applied VMs: L1–L6 pass (verify
  32/32, 5/5 and store 27/27, L6 `changed=0`); there, a host recording policy
  of `terminal_output` refuses the transport and records `pilot-connect`, and
  an invalid one refuses connect, transport and known-hosts. On an earlier
  topology re-applied at `fcd3c03`: E2E strict 20/20, remote-dev 5/5,
  recording 2/2 (recorded into the session store), not-ready 4/4, disabled
  4/4 (both explicit `false` and unset); lockout 29/29 (transport on) and
  28/28 (off); AG60 refuse/allow. TP12 was not re-run. **PASS**.
- 2026-09-23 — [`docs/evidence/pilot-access-gateway/2026-09-23-0f1a5c1.md`](../evidence/pilot-access-gateway/2026-09-23-0f1a5c1.md).
  The topology test used candidate `875066d` (tree `a8990ef5…`), and the E2E,
  lockout, and TP12 runs used `0f1a5c1` (tree `13dfd3af…`). The VMs had never
  been applied. Results: L1–L6 pass (verify 16/16 and 5/5, L6 `changed=0`); E2E
  strict 20/20, remote-dev 5/5, recording 2/2, not-ready 4/4, disabled 4/4 (both
  explicit `false` and unset); lockout 29/29 (transport on) and 28/28 (off);
  TP12 7/7 refused with the `sshd_config.d` checksum unchanged. **PASS**.
