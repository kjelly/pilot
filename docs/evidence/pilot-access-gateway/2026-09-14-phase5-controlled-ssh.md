# pilot-access-gateway Phase 5 — controlled SSH evidence — 2026-09-14

- Spec: `docs/tmp/now/spec.md` §16, §25, §31, §32, §36, §40 (S2, S5), §60 Phase 5
- Operator: Claude Code (kjelly, jellykao@linkervision.com)
- Files: `cmd/pilot/cmd/portal_ssh.go` (+ test), `portal_tui.go` (Connect wiring)

## What was built

- `pilotSSHConfig`: spec.md §32's exact root-owned SSH client config,
  kept as a Go string constant so it is both the thing this phase's own
  test verifies against real OpenSSH and the literal content Phase 7's
  apply playbook will install at `/etc/pilot/ssh_config`.
- `buildConnectSSHCmd`/`connectToHost`: a fixed-argv
  `/usr/bin/ssh -F <config> <target>` launch. `connectToHost` re-checks
  `POST /v1/connect/authorize` immediately before every connect (spec.md
  §16 — never trusts the My Hosts snapshot's cached `SSH.Allowed`), and
  only proceeds using the **response's** `Target` field, never the raw
  string a user selected.
- Host Detail (Phase 4) now offers **Connect** alongside Back.

## A spec-vs-architecture deviation, found and resolved

spec.md §60 Phase 5 says "tea.ExecProcess" — Bubble Tea's suspend-a-
continuous-Program-for-a-subprocess mechanism. This repo's Portal
(Phase 4) is not built that way: like `pilot deploy` (see
`deploy_tui.go`'s own package doc comment), it is a sequence of
short-lived, one-shot `tea.NewProgram(...).Run()` calls with plain Go
code in between — never one continuous Program that could need
suspending. Between any two prompts there is no active raw-mode Program
at all, so a plain blocking `exec.Cmd.Run()` already leaves the terminal
in the right state for the next prompt to render correctly; introducing
`tea.ExecProcess` here would add real complexity for a suspend/resume
problem this architecture doesn't have. `connectToHost` is therefore a
plain blocking call, not a `tea.Cmd`.

## Real verification, not just documentation-trust

spec.md §32 itself prescribes the verification method: *"每個 option要
在 supported OpenSSH執行: `ssh -G -F /etc/pilot/ssh_config target` 驗
證。"* `TestPilotSSHConfigDirectives` does exactly that — writes
`pilotSSHConfig` to a temp file and runs the real, locally-installed
`ssh -G` against it (OpenSSH_9.6p1), asserting every directive took
effect:

```
forwardagent no             clearallforwardings yes
permitlocalcommand no       enableescapecommandline no
escapechar none              stricthostkeychecking true   (ssh -G's own
                                                            normalization
                                                            of "yes")
userknownhostsfile /dev/null
globalknownhostsfile /etc/pilot/ssh_known_hosts
gssapiauthentication yes    gssapidelegatecredentials yes
kbdinteractiveauthentication yes
passwordauthentication yes  requesttty force
```

`ProxyJump none` / `ProxyCommand none` were expected to appear as literal
"none" in `-G` output; real OpenSSH instead **omits them from the output
entirely** once set to "none" (their absence is the pass condition, not
a "none" string — corrected in the test after checking real `-G` output
rather than assuming).

**spec.md §40 S5 (user SSH config escape), verified for real, not
assumed:** the same test plants a "poisoned" `~/.ssh/config`
(`ProxyCommand /bin/echo POISONED`, `ForwardAgent yes`) under a fake
`$HOME` and re-runs `ssh -F <our config> -G` with that `$HOME` — the
poisoned file has **zero** effect: `forwardagent` is still `no`, and no
`proxycommand` line appears at all. `-F` genuinely replaces the user's
own config rather than merging with it; this was verified empirically
(both ad hoc on the command line and in the committed test), not taken
on the man page's word alone.

**spec.md §40 S2 (target injection):** `TestBuildConnectSSHCmdNeverUsesAShell`
confirms `buildConnectSSHCmd` never invokes a shell (`cmd.Path` is always
the real `ssh` binary, argv is a Go string slice) — a
`gpu01.example.com; rm -rf /tmp/x`-style target survives as one inert
argv element, never interpreted.

**spec.md §40 S3 (alternate user, `root@host`) / S4 (IP literal):**
`TestConnectToHostRejectsAlternateUserAndIPTargets` proves both are
denied by the exact same mechanism as any other out-of-scope string —
the gateway's access list only ever contains bare FQDNs, so
`"root@gpu-a.ipa.pilot.internal"` and `"10.0.0.1"` simply match nothing.
There is no special-case parsing of either syntax anywhere in this path
to bypass.

**spec.md §40 S6 (forwarding):** not a separate test — already proven by
the exact-argv assertions in `TestConnectToHostAllowed`/
`TestBuildConnectSSHCmdNeverUsesAShell` (`ssh -F <config> <target>`,
nothing else): since no `-L`/`-R`/`-D`/`-A`/`-X` flag is ever in the argv
this code constructs, none can ever be requested, structurally — and
`ClearAllForwardings yes` plus the OpenSSH-default `ForwardX11 no`
(confirmed in the plain `ssh -G` baseline captured while writing this
config) close the rest.

## Deliberately not done in this phase

A full live SSH session (real GSSAPI/Kerberos negotiation, real
`known_hosts`, an actual reachable target) was **not** attempted here:
Phase 0-4's FreeIPA fixture hosts (`gpu-a.ipa.pilot.internal`,
`gpu-b.ipa.pilot.internal`) are `ipa host-add --force` placeholder
entries with no real machine behind them — there is nothing for a real
`ssh` connection to reach. Spec.md §60 Phase 8's Multi-Gateway E2E is
where a real reachable target host is set up and where a real end-to-end
connect (through real `known_hosts`, and eventually real `ForceCommand`)
belongs; wiring that in now, against fixtures built for a different
purpose, would prove less than it appears to. What Phase 5 owns —
correct SSH config content, fixed-argv construction, fresh re-authorize,
injection-inertness — is fully verified above with the real OpenSSH
client.

## Automated tests

```
go build ./cmd/pilot/...                                  → clean
go test ./cmd/pilot/cmd/ -run \
  "TestRunPortal|TestConnectToHost|TestPortalHostDetailConnectFlow|
   TestBuildConnectSSHCmd|TestPilotSSHConfigDirectives|TestPortalClient" → 11 passed
```
