# Three portal/gateway fixes found while investigating GSSAPI delegation — vm-target Evidence (2026-09-16)

Found while manually driving the real `pilot portal` TUI (via `trec`) to
verify GSSAPI ticket reuse across multiple Connect actions — three
independent issues surfaced, all fixed and re-verified live on `ag-gw01`/
`ag-target01`/`ag-gw02` (the reused Phase 7/8 vm-targets).

## 1. "My Identity" / "Refresh" offered a meaningless Yes/No

Both `portalMenuMyIdentity` and `portalMenuRefresh` in
`cmd/pilot/cmd/portal_tui.go` called `runConfirmPrompt(...)` purely to
display read-only text and dismiss — the returned bool was discarded, so
Yes and No did exactly the same thing. Only Logout's confirm is a real
decision.

Fix: new `runAcknowledgePrompt(message)` (a single-choice `["OK"]`
`runSelectPrompt`) used for both. `portal_tui_test.go`'s scripted answers
changed from `Confirm: boolPtr(true)` to `Select: "OK"`.

**Live vm-target proof** (fresh `pilot portal` session over pure GSSAPI,
via `trec`, after rebuilding and redeploying `dist/pilot-linux-amd64`):

```
┃ My Identity
┃
┃ Username  alice
┃ UID       261200004
┃ Gateway   gpu-01
┃ Scope     gpu
┃ Target    pilot-target-gpu
┃ > OK
```

```
┃ Access refreshed at 05:03:02.
┃ > OK
```

`Logout` still shows a real `Yes  No` toggle, confirmed unchanged in the
same session.

**Gotcha**: replacing the on-disk `/usr/bin/pilot` binary via a fresh
`pilot-access-gateway-apply.yml` run does **not** affect an
already-running `pilot portal` process for a session that's still
connected — the fix only shows up on the *next* SSH login (a new process,
new binary loaded). Re-verifying a portal-side fix requires fully
disconnecting (Logout, or closing the SSH session) and reconnecting, not
just navigating within the same still-open session.

## 2. Dead `cache_ttl`/`connect_max_age` config fields

`cmd/pilot-access-gateway/config.go`'s `FreeIPASection` parsed
`cache_ttl`/`connect_max_age` (from spec.md §26's original example
config), and every `pilot-access-gateway-apply.yml` run wrote them into
`/etc/pilot/access-gateway.yaml` unconditionally — but no resolver,
client, or connect path anywhere in the codebase ever read either field
(`grep` for `.CacheTTL`/`.ConnectMaxAge` outside `config.go` returned
nothing; `internal/accessportal.LoadUserAccess` has always hit FreeIPA
fresh on every `/v1/access` call). An operator reading the generated
config would reasonably conclude access decisions are cached — they
never were, which is also *why* Refresh (item 1) has to exist as a manual
action in the first place.

Deliberately **not** implemented as real caching in this pass: giving
these fields actual behavior is a feature with a genuine
revocation-latency trade-off (how stale can a portal user's access view
get before Refresh) that spec.md never defined and nobody asked for —
conflating "remove a misleading dead config surface" with "design new
caching semantics" would be scope creep on a bug fix.

Fix: removed both fields from `FreeIPASection` and from Step 11's
`access-gateway.yaml` template. Both the Go binary and the generated
config always change together in the same apply run (this component has
no supported "swap the binary without re-running apply" upgrade path), so
there's no window where an old config with these keys meets a new binary
that would reject them via `KnownFields(true)`.

**Live vm-target proof**: rebuilt `dist/pilot-access-gateway-linux-amd64`,
re-ran the apply playbook against `ag-gw01` — `/etc/pilot/access-gateway.yaml`
no longer has either key, `pilot-access-gateway.socket` stayed `active`,
and `/v1/health` still reports `{"status":"ok",...}` (config still parses
and the service still runs correctly with the trimmed schema).

## 3. Connect used a stale, apply-time known_hosts snapshot

`/etc/pilot/ssh_config`'s `Host *` block had `GlobalKnownHostsFile
/etc/pilot/ssh_known_hosts`, a file Step 13 populated once per apply via
`ssh-keyscan` against whatever hosts were in `pilot-target-<scope>` *at
that moment*. Two real problems: (1) a host added to the scope afterward
had no entry and failed `StrictHostKeyChecking` until the next re-apply;
(2) `ssh-keyscan` is blind TOFU — it trusts whatever key a host presents
at scan time with zero verification, weaker than the host's actual
enrollment-time `ipaSshPubKey` FreeIPA already has on file.

Fix: switched to `sss_ssh_knownhostsproxy` (the same SSSD-provided tool
`freeipa-client-apply.yml`'s own `ssh_config.d/04-ipa.conf` already uses
for this exact purpose) as `ProxyCommand`, dynamically relaying the
connection. Step 13's `ssh-keyscan`/parse-hosts/install-known_hosts tasks
were removed (its one surviving task, the `ipa hostgroup-show` existence
check, stays — Step 18's gate still needs it, unrelated to known_hosts).

**Bug found while testing the fix itself**: dropping
`GlobalKnownHostsFile` entirely, on the assumption `ProxyCommand` alone
was sufficient, produced a real failure:

```
No ED25519 host key is known for ag-target01.ipa.pilot.internal and you have requested strict checking.
Host key verification failed.
```

`ProxyCommand` only relays bytes — it does not itself satisfy
`StrictHostKeyChecking`. The actual fix needed `GlobalKnownHostsFile
/var/lib/sss/pubconf/known_hosts`, the file SSSD itself keeps current as
it resolves each host's `ipaSshPubKey` (confirmed present and correctly
populated for `ag-target01` before writing the fix).

**Live vm-target proof**, via the real `pilot portal` TUI (not a manual
`ssh -F` replica) over pure GSSAPI (no password anywhere in the chain):

```
$ echo FIX_VERIFIED; whoami; hostname -f
FIX_VERIFIED
alice
ag-target01.ipa.pilot.internal
```

Also removed the now-stale `/etc/pilot/ssh_known_hosts` file on any
gateway set up before this change (a new cleanup task, `state: absent`).

## Test/lint status

`go build ./...`, `ansible-playbook --syntax-check`, and the affected
package tests (`cmd/pilot/cmd` — `TestRunPortal*`, `TestPilotSSHConfig*`;
`cmd/pilot-access-gateway` — `TestLoadConfig*`) all pass. Full `go test
./...` run separately for the whole-repo regression check.

## Cleanup

Destroyed the test Kerberos ticket caches on `ag-gw02` after each trec
session. `ag-gw01`/`ag-gw02`/`ag-target01`/`ag-spike-ipa` left running
(reused Phase 7/8 fixtures, per this repo's convention).
