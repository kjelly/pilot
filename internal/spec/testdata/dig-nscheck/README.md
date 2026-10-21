# dig nameserver-check captures

The original `.txt` fixtures were captured on the disposable pr92 topology on
2026-10-15; their provenance is recorded in the Go regression test.

The `tier_{a,aaaa}_servfail` captures were collected on 2026-10-21 with dig
9.20.24-1ubuntu0.4-Ubuntu and unbound 1.24.2 on the development host. Each `.txt` is unmodified
stdout; `.stderr` preserves stderr (empty), and `.rc` preserves exit status (0).
The isolated unbound listened on `127.0.0.1@15353`, used `module-config:
"iterator"`, `do-not-query-localhost: no`, `infra-cache-min-rtt: 50` and
`infra-cache-max-rtt: 250`, and forwarded `ipa.pilot.internal.` exclusively to
the unavailable endpoint `127.0.0.2@15354` (`forward-first: no`). The bounded
upstream retry timings make SERVFAIL arrive before the production probe timeout.
This reproduces an unbound tier whose configured FreeIPA upstream is unavailable
without deploying a directory server or changing the host resolver.

Capture argv: `dig +time=2 +tries=2 +noall +comments +answer -p 15353
@127.0.0.1 ipa1.ipa.pilot.internal. A` (and `AAAA`). The query options match the
production resolver probe, with only the isolated test listener port added.

The committed `playbooks/test/fixtures/freeipa-dns-client-servfail.yml` reproduces
the real upstream failure and executes the production classifier on a disposable
VM, paired with a healthy DNS server and an all-SERVFAIL rejection case.
