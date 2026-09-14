# pilot-access-gateway Phase 0 — FreeIPA transport spike evidence — 2026-09-14

- Spec: `docs/tmp/now/spec.md` §0 G1 / §11.1 (exit criteria) / §60 Phase 0
- Operator: Claude Code (kjelly, jellykao@linkervision.com)
- Target: `pilot vm-target` `ag-spike-ipa`, AlmaLinux 9, `playbooks/apply/freeipa-server-apply.yml`
  applied via `-e target_group=all -e ipa_server_ip=192.168.122.2 -e @~/.vault/main.yaml`
  (`ok=40 changed=16 failed=0`)
- FreeIPA: realm `IPA.PILOT.INTERNAL`, domain `ipa.pilot.internal`,
  FQDN `ipa1.ipa.pilot.internal`, server version 4.13.1 / API 2.257

## What was tested

Question: can `internal/freeipaaccess` be a pure-Go (`CGO_ENABLED=0`) Kerberos/SPNEGO
JSON-RPC client, as §11.1 prefers, or must it fall back to `kinit`+`curl --negotiate`?

Steps, all against the real FreeIPA server above (not mocked):

1. `ipa service-add pilot-access-gateway/ipa1.ipa.pilot.internal` (admin, one-time setup —
   this is the same reader-style service principal §10.3 describes, created here with no
   extra role/privilege grants at all, to also observe the *default* ACI a bare service
   principal gets).
2. `ipa-getkeytab -s ipa1.ipa.pilot.internal -p pilot-access-gateway/ipa1.ipa.pilot.internal
   -k /root/pilot-access-gateway.keytab`.
3. A throwaway Go program (not part of the `pilot` module; source kept at
   `/tmp/.../scratchpad/ag-spike/main.go` for this session, reproduced in "Spike source
   shape" below for the next phase to reconstruct) built with
   `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build`, using
   `github.com/jcmturner/gokrb5/v8` (`client`, `config`, `keytab`, `spnego` packages,
   MIT-licensed, no cgo — confirmed statically linked via `file`), copied onto the VM and
   run there directly (avoids cross-host Kerberos/DNS complications; running from a
   separate "gateway" host is a network/DNS concern, not a transport-feasibility one, and
   is deferred to Phase 3+).

## Result — exit criteria (§11.1) all met

| # | Criterion | Result |
|---|---|---|
| 1 | Service principal Kerberos auth (AS-REQ from keytab) | **PASS** — `client.NewWithKeytab(...).Login()` succeeded |
| 2 | ≥1 successful read-only JSON-RPC call, parsed | **PASS** — SPNEGO `login_kerberos` (HTTP 200) then `ping()` (HTTP 200), body parsed as JSON |
| 3 | `CGO_ENABLED=0` maintained | **PASS** — `file ag-spike-bin` → `statically linked`, `go build` used no cgo |
| 4 | Evidence usable as Phase 1 fixture basis | **PASS** — this file + raw responses below |

Raw output (own run, redacted nothing sensitive — keytab/tickets never leave the VM):

```
OK  step1 kerberos AS-REQ login succeeded (TGT acquired from keytab)
OK  step2 SPNEGO negotiate + /ipa/session/login_kerberos succeeded (HTTP 200, cookies=1)
OK  step3 read-only JSON-RPC ping succeeded (HTTP 200)
RESPONSE: {"result": {"summary": "IPA server version 4.13.1. API version 2.257", ...},
           "error": null, "id": 0,
           "principal": "pilot-access-gateway/ipa1.ipa.pilot.internal@IPA.PILOT.INTERNAL",
           "version": "4.13.1"}
INFO step4 mutation probe (user_add) HTTP 200
RESPONSE: {"result": null,
           "error": {"code": 2100, "message": "Insufficient access: Could not read UPG
                      Definition originfilter. Check your permissions.",
                      "name": "ACIError"},
           "id": 1, ...}
```

Step 4 (not a Phase 0 exit criterion, but directly relevant to SI-10/AG08) shows a bare
service principal — created with **zero** extra role/privilege assignment — already gets
`ACIError: Insufficient access` on a write call. FreeIPA's default ACI baseline is
deny-by-default for services; Phase 1/§10.3's "Pilot Access Gateway Reader" role only needs
to *grant* the specific reads listed there, not separately *revoke* writes.

## Decision

**Adopt direct Go SPNEGO (`github.com/jcmturner/gokrb5/v8`) as the `internal/freeipaaccess`
transport.** The `kinit`+`curl --negotiate` fallback in §11.1 is not needed and should not
be built. `go.mod` gets this dependency added in Phase 1 (when real consuming code lands),
not in this evidence-only commit.

## Gotcha found (feeds Phase 1)

FreeIPA's httpd rejects **any** `/ipa/session/*` request that lacks a `Referer` header —
including `login_kerberos` itself, not just the JSON-RPC call — with
`400 Bad Request: denied` / server log line `ipa: ERROR: Rejecting request with missing
Referer`. This was not obvious from the JSON-RPC usage docs cited in spec §63 (which show
the JSON-RPC call's Referer but not the login call's). `internal/freeipaaccess`'s HTTP
layer must set `Referer: https://<fqdn>/ipa` on every request to `/ipa/session/*`, no
exceptions, or every call — including the initial login — fails closed with a generic 400
that has nothing to do with Kerberos.

## Cleanup

VM `ag-spike-ipa` left up (not torn down) for reuse as the FreeIPA fixture source in
Phase 1. The `pilot-access-gateway/ipa1.ipa.pilot.internal` service principal and its
keytab exist only on this disposable VM; nothing was copied into the repository.
