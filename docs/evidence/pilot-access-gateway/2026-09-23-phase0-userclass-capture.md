# Phase 0 — FreeIPA userClass real captures (2026-09-23)

Scope: `docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md`
§9 (Phase 0). A spike that captures real FreeIPA output before any parser is
written (AGENTS.md §5.6), and decides the GER branch. It is not a formal
candidate target test.

## Tested revision

- Repository revision: `7735724` (Phase 1 committed). The client enrollment
  run also included the not-yet-committed Phase 2 draft
  `playbooks/apply/tasks/freeipa-host-access-policy.yml`.
- The capture driver was a per-run playbook under `tmp/` (not committed).

## Topology

Disposable `pilot vm-target` topology on the local libvirt `default` network:

| VM | Image | Role |
|---|---|---|
| `phr-ipa` | AlmaLinux 9, `ipa-server-4.13.1-3.el9_8.2` | FreeIPA server (`freeipa-server-apply.yml`: `ok=40 changed=16 failed=0`) |
| `phr-gw`, `phr-ta`, `phr-tb`, `phr-store` | Ubuntu 24.04 | FreeIPA clients (`freeipa-client-apply.yml`: each `ok=161 changed=17 failed=0`) |

Before enrolling, the Ubuntu VMs needed `apt-get update`. Their package
indexes were stale, and fetches through the local apt proxy returned 404.

## Captures

Committed as sanitized fixtures. Public-key and Kerberos blob values are
replaced with `<redacted>`; everything else is verbatim.

| Capture | Fixture | Result |
|---|---|---|
| `host-show --all --raw`, host with a foreign value, an annotation and a valid marker | `internal/spec/testdata/freeipa-host-show-raw-userclass-valid.txt` | rc=0. Each value is on its own line as `  userclass: <value>`, two-space indented, lowercase `userclass` |
| same, with `=off` and `=terminal_output` both present | `…-duplicate.txt` | rc=0, both values listed |
| same, only `Pilot.Policy.SSH-Recording=terminal_output` | `…-casevariant.txt` | rc=0, the value's case is preserved as written |
| `host-show` of a non-existent host | `internal/spec/testdata/freeipa-host-show-not-found.txt` | rc=2, stderr `ipa: ERROR: <fqdn>: host not found` |
| `host-show` with an unreachable `xmlrpc_uri` | `internal/spec/testdata/freeipa-host-show-unreachable.txt` | rc=1, stderr `ipa: ERROR: cannot connect to '…': …`, which does not contain `host not found` |
| JSON-RPC `host_show` `{"all": true}` as `pilot-access-gateway/phr-gw…` (keytab, session login HTTP 200) | `internal/freeipaaccess/testdata/host_show_userclass.json` | `userclass` is a JSON list of the three values; no `attributelevelrights` |
| JSON-RPC `host_show` `{"all": true, "rights": true}`, same principal | `internal/freeipaaccess/testdata/host_show_userclass_rights.json` | `attributelevelrights.userclass = "rsc"` |

The playbook's extraction regex `(?im)^[ \t]*userclass: (.+)$` matches the
real `--raw` format. The not-found stderr and the unreachable stderr can be
told apart by the `host not found` text.

## GER branch decision: **branch R**

`rights: true` works for the gateway service principal. The response carries
`attributelevelrights.userclass = "rsc"`, which includes read. Per spec §9,
the gateway requests `rights: true` on every `host_show`. When `userclass`
rights do not include `r`, policy is treated as unavailable
(`Known=false` → `recording_policy_unavailable`). The canary path (branch N)
does not apply and is not implemented.

## Cleanup

- The driver removed every userClass value it added. A final
  `host-show --all --raw` of `phr-ta` showed no `userclass` line.
- It deleted the temporary `pilot-access-gateway/phr-gw…` service principal,
  along with its keytab, ccache and cookie jar.
- Raw outputs stay in the gitignored `.verification/phase0/`.
