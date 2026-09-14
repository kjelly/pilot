# pilot-access-gateway Phase 4 — Portal read UI evidence — 2026-09-14

- Spec: `docs/tmp/now/spec.md` §27, §28, §36, §60 Phase 4
- Operator: Claude Code (kjelly, jellykao@linkervision.com)
- Target: same `ag-spike-ipa` vm-target as Phase 0-3 (reused, real `pilot-access-gateway`
  from Phase 3 still running against the real FreeIPA data)
- Files: `cmd/pilot/cmd/portal.go`, `portal_client.go`, `portal_tui.go` (+ tests)

## What was built

`pilot portal` — a read-only Bubble Tea/Huh TUI reusing this repo's
existing screen factory and prompt-automation testing hooks
(`deployUIFactory`/`runSelectPrompt`/`runConfirmPrompt`/
`activePromptAutomation`, already used by `pilot deploy`) rather than
inventing new UI machinery: Gateway/Scope/User header, **My Hosts** (a
select list of exactly the hosts `/v1/access` returned — no client-side
re-filtering), **Host Detail** (SSH allowed/rules, sudo scope/allow/deny
commands/rules — a Confirm screen used as a "press enter to go back"
info display, spec.md's Factory has no dedicated message-only screen
type), **My Identity**, **Refresh** (a real second `/v1/access` call, not
a replay), **Logout**. No scope switcher, per spec.md §27 — enforced both
structurally (`portalTopMenuItems` has exactly these four entries, guarded
by `TestRunPortalNoScopeSwitcher`) and by the fact that `runPortal` never
takes a scope/gateway argument at all; it only ever knows whatever
`--socket` points at.

`portal_client.go` reuses `internal/gatewayapi`'s own response types
(`IdentityResponse`, `AccessResponse`, ...) as the wire contract, so
client and server can never silently drift apart.

Phase 5 (Controlled SSH) is **not** built here — `portalClient.ConnectAuthorize`
exists (ready for Phase 5 to call) but nothing in this phase's TUI offers
a "Connect" action; Host Detail is read-only, exactly matching spec.md's
own Phase 4/Phase 5 split.

## Real, live end-to-end verification (trec over SSH, real alice, real FreeIPA)

Built `pilot` (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`), copied to the
vm-target, and drove it with `trec` exactly as
`ssh -tt ... runuser -u alice -- /tmp/pilot portal --socket /tmp/access-gateway.sock`
against the same live `pilot-access-gateway` process from Phase 3 (real
Kerberos session to the real FreeIPA server, real HBAC/sudo rules). Full
walk recorded via `terminal_read_screen`:

```
┃ Pilot Portal
┃
┃ Gateway  gpu-01
┃ Scope    gpu
┃ User     alice
┃ ────────────────────────
┃ > My Hosts
┃   My Identity
┃   Refresh
┃   Logout
```

— matches spec.md §27's mockup exactly, with real values. Then, in order:

- **My Hosts** → `gpu-a.ipa.pilot.internal`, `gpu-b.ipa.pilot.internal`,
  `« Back` (the real two hosts from Phase 0-3's FreeIPA fixtures).
- Selecting `gpu-a.ipa.pilot.internal` → **Host Detail**:
  ```
  Host: gpu-a.ipa.pilot.internal
  SSH allowed: true
  SSH rules: pilot-grant-login-gpu-test
  Sudo scope: limited
  Allow commands: /usr/bin/systemctl status nginx
  Deny commands: /usr/bin/reboot
  Sudo rules: pilot-grant-sudo-gpu-test
  ```
  — matches Phase 2/3's resolved data exactly; Enter returns to the top menu.
- **My Identity**:
  ```
  Username  alice
  UID       261200004
  Gateway   gpu-01
  Scope     gpu
  Target    pilot-target-gpu
  ```
- **Refresh** → returns to the top menu after a real round-trip (screen
  briefly redraws from the top, confirming a fresh render rather than an
  instant no-op).
- **Logout** → the `pilot portal` process exits (`exit_code: 0`), and
  since it was the remote command of an interactive SSH session, the SSH
  connection itself closes right after ("Connection to 192.168.122.2
  closed") — the same mechanism spec.md §33's `pilot-session` ForceCommand
  wrapper will rely on in Phase 8, confirmed here one layer down (without
  ForceCommand yet).

## Gotchas found

1. **`/root` traversal, again** (same class of issue as Phase 3's finding,
   different binary): copying `pilot` to `/root/pilot` and running it via
   `runuser -u alice` failed with `Permission denied` — not a bug, `/root`
   isn't traversable by a non-root UID. Copied to `/tmp/pilot` (mode 755)
   instead and it worked immediately. Two phases in a row hitting the
   same class of mistake made this worth calling out explicitly rather
   than assuming it was learned after Phase 3: **never stage a gateway or
   portal test artifact under `/root/` when a non-root user needs to
   reach it** — use `/tmp` (or, in production, the real `/etc/pilot`,
   `/usr/local/libexec` paths spec.md §25 already specifies, which are
   root-owned but world-*traversable* directories, unlike `/root`).

2. **`pkill -f <pattern>` self-matching killed the SSH session issuing
   it.** Restarting the Phase 3 gateway with
   `ssh ... 'pkill -f "pilot-access-gateway serve"; ...'` closed the SSH
   connection immediately (exit 255, no further output) — `pkill -f`
   matches against the full command line of every process, including the
   remote shell that is itself executing a command line containing that
   exact string, so it killed its own invoking shell. Fixed by not
   pre-killing at all: `rm -f` the socket path before starting a new
   `nohup`'d instance is sufficient (the old orphaned process, if any,
   holds no conflicting resource once its socket path is gone). This is a
   generic operational trap for any future restart script/playbook task
   for this component — a real systemd `systemctl restart` is unaffected
   (it targets a unit name, not a command-line substring) and remains the
   right way to restart this service in production.

3. **`trec`'s automatic pointer detection (`terminal_choose`/
   `terminal_focus`) did not locate the menu pointer** on this screen
   (`SELECT "My Hosts": not reached after 90 presses (no pointer row
   found)`), even though the pointer (`>`) was visibly moving correctly on
   each read. Likely cause: every rendered line carries a `┃ ` box-border
   prefix from Huh's default styling before the pointer/indent, which may
   not match trec's default pointer-detection pattern. Manual
   navigation — `terminal_key UP`/`DOWN` a computed number of times,
   confirmed via `terminal_read_screen` between presses, then
   `terminal_key ENTER` — worked reliably and is what this phase's live
   walk above actually used throughout. Worth revisiting (an explicit
   `pointer` regex argument to `terminal_focus`/`terminal_choose` was not
   tried) before assuming every future Portal trec script needs manual
   navigation, but manual navigation is a fully adequate fallback in the
   meantime.

## Automated tests

```
go build ./cmd/pilot/...                         → clean
go vet ./cmd/pilot/...                            → clean
go test ./cmd/pilot/cmd/ -run TestPortalClient    → 2 passed (real gatewayapi.Server, real Unix socket)
go test ./cmd/pilot/cmd/ -run TestRunPortal       → 4 passed (full menu loop, back-navigation,
                                                      refresh, no-scope-switcher structural guard —
                                                      all via activePromptAutomation, the same
                                                      mechanism pilot deploy's own tests use)
go test ./cmd/pilot/cmd/...                       → full existing suite still green (no regressions)
```

The `TestPortalClient*`/`TestRunPortal*` tests start a real
`internal/gatewayapi.Server` over a real Unix socket with a small fake
`freeipaaccess.Provider` (recognizing this test process's own OS
username, since the server derives identity via real `SO_PEERCRED`, not
from anything the test tells it) — the same "real wire protocol, fake
data source" pattern Phase 3's own tests established.
