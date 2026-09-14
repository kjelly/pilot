# pilot-access-gateway Phase 3 — peer identity + Gateway API evidence — 2026-09-14

- Spec: `docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md` §10.1, §22, §26, §29, §30, §36, §60 Phase 3
- Operator: Claude Code (kjelly, jellykao@linkervision.com)
- Target: same `ag-spike-ipa` vm-target as Phase 0/1/2 (reused)
- Packages: `internal/peercred`, `internal/identity`, `internal/systemdactivation`,
  `internal/gatewayapi`, `cmd/pilot-access-gateway`

## What was built

- `internal/peercred`: `SO_PEERCRED` extraction from a `*net.UnixConn` via
  `SyscallConn` (stdlib `syscall.GetsockoptUcred`, no new dependency).
- `internal/identity`: UID→username via `getent passwd <uid>` — **not**
  Go's `os/user`. Verified live on this same FreeIPA vm-target:
  `grep alice /etc/passwd` finds nothing (exit 1), while
  `getent passwd alice` / `getent passwd <uid>` resolve her correctly
  through SSSD. A `CGO_ENABLED=0` `os/user.LookupId` only parses
  `/etc/passwd` directly and would never find a FreeIPA user — spec.md
  §10.1's insistence on `getent` over a library call is a real, load-
  bearing requirement, not a stylistic preference.
- `internal/systemdactivation`: the `sd_listen_fds(3)` protocol (fd 3 +
  `LISTEN_PID`/`LISTEN_FDS`), with the documented `LISTEN_PID` safety
  check.
- `internal/gatewayapi`: the full §22 API (`/v1/identity`, `/v1/access`,
  `/v1/access/{fqdn}`, `/v1/connect/authorize`, `/v1/health`) over an
  HTTP server bound to a Unix socket, using Go's method-aware
  `http.ServeMux` patterns and `ConnContext` to extract the trusted peer
  identity once per connection (never per request, never from anything
  client-supplied).
- `cmd/pilot-access-gateway`: `serve` (+ `version`) subcommands, YAML
  config loading (`KnownFields(true)` — an unknown field like
  `roster_file` is rejected, not merely unread), and a `--systemd-socket`
  flag.

## Real API responses (curl over a real Unix socket, real FreeIPA data, real binary)

Built with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64` (confirmed statically
linked), copied to the vm-target, run as `serve --config ...` against the
real `pilot-access-gateway/ipa1.ipa.pilot.internal` reader keytab from
Phase 0/1, and queried with plain `curl --unix-socket` as the real user
`alice` (via `runuser -u alice`, a genuinely different UID/process than
the server) — not Go's own `http.Client` in a unit test:

```
$ runuser -u alice -- curl -s --unix-socket $S http://localhost/v1/identity
{"uid":261200004,"username":"alice","gateway":{"id":"gpu-01","scope":"gpu","target_hostgroup":"pilot-target-gpu"}}

$ runuser -u alice -- curl -s --unix-socket $S http://localhost/v1/access
{"user":"alice", ... ,"hosts":[
  {"fqdn":"gpu-a.ipa.pilot.internal","ssh":{"allowed":true,"rules":["pilot-grant-login-gpu-test"]},
   "sudo":{"scope":"limited","allow_commands":["/usr/bin/systemctl status nginx"],
           "deny_commands":["/usr/bin/reboot"],"rules":["pilot-grant-sudo-gpu-test"]}},
  {"fqdn":"gpu-b.ipa.pilot.internal", ... same ...}
]}

$ runuser -u alice -- curl -s -o /dev/null -w '%{http_code}\n' --unix-socket $S \
    http://localhost/v1/access/dmz-host.example.com
404

$ runuser -u alice -- curl -s -X POST -d '{"target":"gpu-a.ipa.pilot.internal"}' \
    --unix-socket $S http://localhost/v1/connect/authorize
{"allowed":true, ... ,"rules":["pilot-grant-login-gpu-test"]}

$ runuser -u alice -- curl -s -X POST -d '{"target":"dmz-host.example.com"}' \
    --unix-socket $S http://localhost/v1/connect/authorize
{"allowed":false, ... ,"rules":null}

# $USER/$LOGNAME spoof (spec.md §40 S1) — SO_PEERCRED must win:
$ runuser -u alice -- env USER=root LOGNAME=root curl -s --unix-socket $S http://localhost/v1/identity
{"uid":261200004,"username":"alice", ...}   # still alice, not root

# extra field injection (spec.md §22.4, SI-07):
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST \
    -d '{"target":"gpu-a.ipa.pilot.internal","username":"admin"}' --unix-socket $S ...
400
```

Every one of these matches the design exactly: sudo command-group
expansion (`test-sudocmdgroup` → the nginx command) and the deny command
both show up correctly end-to-end through the real resolver; an
out-of-scope host is a 404 for detail and a denial for connect; identity
spoofing via environment variables has zero effect (the handler never
reads them); and the strict JSON decoder rejects a smuggled field with
400 rather than silently accepting it.

## Also verified live: real systemd socket activation

```
$ systemd-socket-activate -l /tmp/gw-activated.sock \
    /root/pilot-access-gateway serve --config ... --systemd-socket
Listening on /tmp/gw-activated.sock as 3.
Communication attempt on fd 3.
Execing /root/pilot-access-gateway (...)
{"level":"INFO","msg":"pilot-access-gateway serving", ..., "systemd_socket":true}
$ runuser -u alice -- curl -s --unix-socket /tmp/gw-activated.sock http://localhost/v1/identity
{"uid":261200004,"username":"alice", ...}
```

`systemd-socket-activate` (shipped with systemd, used here instead of
writing a real `.socket`/`.service` unit pair) genuinely execs the binary
with `LISTEN_PID`/`LISTEN_FDS` set and the bound socket at fd 3 — this is
the real protocol, not a simulation, and it worked without any code
changes beyond what `internal/systemdactivation` already implements
(verified independently first via the `TestHelperProcess` subprocess test
in `internal/systemdactivation`, itself using the identical
`ExtraFiles`/env-var mechanism).

## A gotcha found (operational, not a code defect)

The very first live run put the socket at `/root/access-gateway.sock` and
`alice`'s `curl` got no response at all (not even a curl error visible
through the test harness). Cause: `/root` is not traversable by a
non-root user, so `connect()` to a Unix socket path under it fails for
anyone but root — nothing to do with `SO_PEERCRED`, `getent`, or this
package's own code. Moving the socket to `/tmp` (world-traversable) fixed
it immediately. **This is exactly why spec.md §29's systemd unit
(`RuntimeDirectory=pilot`, default mode 0755) puts the socket under
`/run/pilot/` instead of somewhere root-only** — the real default
(`/run/pilot/access-gateway.sock`, per §26) was never at risk; this only
bit an ad hoc test config that used `/root` as a shortcut. Recorded here
so a future debugging session doesn't have to rediscover it.

## A spec gap found and fixed: no `realm` config field

spec.md §26's example YAML has no `gateway.freeipa.realm` field, but
`internal/freeipaaccess.Config` (Phase 1) requires a `Realm` to build a
Kerberos principal. Fix: `NewClient` now defaults `Realm` from the loaded
`krb5.conf`'s `default_realm` when the config doesn't set one explicitly
— a correctly `ipa-client`-enrolled (or, as here, `ipa-server-install`ed)
host's `krb5.conf` already names its realm authoritatively, so no new
required config field was added.

Also re-verified live with the config's `service_principal` in the exact
form spec.md §26's example uses, `@REALM` embedded
(`pilot-access-gateway/ipa1.ipa.pilot.internal@IPA.PILOT.INTERNAL`) rather
than the bare form used above — `splitPrincipalRealm` correctly strips it
and alice's identity still resolves correctly through the same live run.

## Tooling note (not a code defect)

`golangci-lint` (locally installed, built with go1.24.13) cannot analyze
`internal/freeipaaccess` once it uses a go1.26-only stdlib API
(`errors.AsType`, adopted per this repo's modern-go-guidelines skill in
Phase 1): "the Go language version used to build golangci-lint is lower
than the targeted Go version." `go build`/`go vet`/`go test` (the
authoritative checks, and what this environment's actual `go1.26.4`
toolchain runs) are all clean. Worth a local golangci-lint upgrade at some
point; not addressed here since it is out of scope for the gateway
feature itself.

## Verification run

```
go build ./...                          → clean
go vet ./...                            → clean
go test ./internal/peercred/...         → 1 passed  (real self-connect SO_PEERCRED)
go test ./internal/identity/...         → 2 passed
go test ./internal/systemdactivation/...→ 3 passed  (real fd-3 subprocess inheritance)
go test ./internal/gatewayapi/...       → 8 passed  (real Unix socket, real SO_PEERCRED, this test process as peer)
go test ./cmd/pilot-access-gateway/...  → 4 passed  (config load/validate)
gofmt -l ...                            → clean
```

Plus the live vm-target runs above (real binary, real FreeIPA, real
external `curl` client, real second Linux user `alice`, real systemd
socket activation) — none of which are part of the automated test suite,
consistent with this phase's landing gate (unit tests need no live IPA;
live verification here is extra, done because the goal directive asked
for real testing wherever something was uncertain, and connection-level
identity plumbing over a real socket is exactly that kind of thing).

## Known gaps carried forward

- No in-memory TTL cache yet (spec.md §20) — every request does a fully
  fresh resolve. This trivially satisfies "never stale" but not yet the
  performance target (spec.md §49); deferred, since correctness came
  first and adding a cache later does not change the API contract.
- `/v1/access/{fqdn}` and `/v1/connect/authorize` each call
  `LoadUserAccess` independently (a full resolve each), rather than
  computing HBAC for a single host directly — correct, but more RPC work
  than strictly necessary for a single-host query. Worth revisiting once
  there's a real latency measurement to justify it.
