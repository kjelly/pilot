---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: internal-endpoint day-2 reconciler — DNS + FreeIPA service certificates + optional nginx
  source: spec.md §7, §47 (Internal Endpoint / FreeIPA PKI feature)
  maintainer: sre
targets:
  roles: [freeipa-server]
  hostScope: per-host
  platforms:
    - {os: almalinux, versions: ["9"]}
inputs:
  - {name: manifest_fixture_dir, required: true}
  - {name: freeipa_dns_manifest_path, required: true}
  - {name: pilot_inventory_path, required: true}
  - {name: test_dns_zone, required: true}
  - {name: test_direct_owner, required: true}
  - {name: test_direct_target_ip, required: true}
  - {name: test_proxy_owner, required: true}
  - {name: test_proxy_host_ip, required: true}
  - {name: test_upstream_ip, required: true}
  - {name: test_endpoint_fqdn, required: true}
  - {name: test_expected_cert_owner, required: true}
  - {name: test_nonenrolled_endpoint_fqdn, required: true}
  - {name: test_cert_file, required: true}
  - {name: test_key_file, required: true}
  - {name: test_proxy_endpoint_url, required: true}
  - {name: test_backend_marker, required: true}
  - {name: test_direct_endpoint_url, required: true}
  - {name: test_nginx_vhost_conf, required: true}
  - {name: test_verified_upstream_endpoint_url, required: true}
  - {name: test_insecure_upstream_endpoint_url, required: true}
  - {name: test_insecure_upstream_host, required: true}
  - {name: test_insecure_upstream_port, required: true}
  - {name: test_upstream_sni, required: true}
traceability: {components: [internal-endpoint]}
defaults:
  become: true
  timeout: 30s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — internal-endpoint

This v2 acceptance contract verifies the `internal-endpoint` day-2
reconciler (spec.md §7, §28): FQDN → DNS/TLS/route resolution, FreeIPA
service-certificate lifecycle, optional nginx reverse-proxy generation, and
ownership/deletion safety. It intentionally does not re-verify the
per-host baselines that `docs/verification/freeipa-ca-trust.md` and
`freeipa-dns-client.md` already own in full (CA trust, DNS resolver
config) — C9/C10 here confirm those baselines actually land on every
managed host as a side effect of this reconciler's own apply sequence
(spec.md §28 Phase 2-3), not duplicate that per-host coverage.

**Scope of this Phase-1 draft.** This spec was authored in Phase 1 of
spec.md's implementation order (§63), before the Go manifest validator
(Phase 2), the FreeIPA certificate lifecycle (Phase 5), or the reconciler
CLI surface exist. Every row below is a real, intended acceptance check —
not a placeholder — but most rows cannot pass yet because the behavior
they check does not exist yet. `pilot internal-endpoint validate` and
`pilot reconcile internal-endpoint` in the probes below are the CLI shape
Phase 2 is expected to add; if Phase 2 lands a different flag or
subcommand name, update the probe text here rather than the row's intent.
Phase 10 supplies the first actual-run evidence against a real disposable
topology (spec.md §52-§55) and corrects any probe that real hosts prove
wrong.

**Scope split.** C1, C2, C3, and C30 are pure Go-manifest-validator
behavior with no live host involved (`scope: aggregate`, run once from
wherever `pilot verify` executes, using fixture manifests under
`manifest_fixture_dir`). C9 and C10 are genuinely fleet-wide claims
(`scope: aggregate`, fan out via one `ansible all` ad-hoc call against
`pilot_inventory_path`). Every other row runs per-host against the single
`freeipa-server` control host, including the DNS/certificate/nginx checks,
since that is where the reconciler itself executes and where its ledger
and rendered artifacts live.

**C25's test procedure** requires two reconcile runs: the fixture direct
endpoint's `route.target.inventory_host` keeps the same `inventory_host`
while `ansible_host` (the IP) changes between the two runs. The probe
alone only confirms the record matches the *current* expected IP — the
meaningful assertion is that this spec still passes unmodified after that
second run, proving the IP change (not a route-owner change) reconciled
cleanly.

## Checks

```yaml
- id: C1
  category: schema
  check: a manifest with an unknown top-level or nested key is rejected
  probe: |
    out=$(pilot internal-endpoint validate --manifest "$PILOT_VAR_MANIFEST_FIXTURE_DIR/unknown-key.yaml" 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi unknown; then echo rejected; else echo "accepted rc=$rc"; fi
  expect: {stdout: {equals: rejected}}
  scope: aggregate
  verifyOnly: true
- id: C2
  category: schema
  check: a nested FQDN (e.g. aaa.xxx.<zone>) normalizes to the correct relative owner
  probe: |
    pilot internal-endpoint validate --manifest "$PILOT_VAR_MANIFEST_FIXTURE_DIR/nested-fqdn.yaml" --print-normalized 2>/dev/null | grep -c '^aaa\.xxx '
  expect: {stdout: {equals: "1"}}
  scope: aggregate
  verifyOnly: true
- id: C3
  category: schema
  check: two endpoints with the same canonical FQDN are rejected
  probe: |
    out=$(pilot internal-endpoint validate --manifest "$PILOT_VAR_MANIFEST_FIXTURE_DIR/duplicate-fqdn.yaml" 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi duplicate; then echo rejected; else echo "accepted rc=$rc"; fi
  expect: {stdout: {equals: rejected}}
  scope: aggregate
  verifyOnly: true
- id: C4
  category: dns
  check: a direct route's A/AAAA record points at route.target's resolved address
  probe: |
    got=$(ipa dnsrecord-show "$PILOT_VAR_TEST_DNS_ZONE" "$PILOT_VAR_TEST_DIRECT_OWNER" --raw 2>/dev/null | grep -oE 'arecord: [0-9.]+' | awk '{print $2}' | head -n1)
    if [ "$got" = "$PILOT_VAR_TEST_DIRECT_TARGET_IP" ]; then echo match; else echo "got=$got want=$PILOT_VAR_TEST_DIRECT_TARGET_IP"; fi
  expect: {stdout: {equals: match}}
  tags: [C4]
- id: C5
  category: dns
  check: a reverse_proxy route's A/AAAA record points at the proxy host, never the upstream
  probe: |
    got=$(ipa dnsrecord-show "$PILOT_VAR_TEST_DNS_ZONE" "$PILOT_VAR_TEST_PROXY_OWNER" --raw 2>/dev/null | grep -oE 'arecord: [0-9.]+' | awk '{print $2}' | head -n1)
    if [ "$got" = "$PILOT_VAR_TEST_PROXY_HOST_IP" ] && [ "$got" != "$PILOT_VAR_TEST_UPSTREAM_IP" ]; then echo correct; else echo "got=$got proxy=$PILOT_VAR_TEST_PROXY_HOST_IP upstream=$PILOT_VAR_TEST_UPSTREAM_IP"; fi
  expect: {stdout: {equals: correct}}
  tags: [C5]
- id: C6
  category: dns
  check: the generated DNS value never carries a port suffix
  probe: |
    val=$(ipa dnsrecord-show "$PILOT_VAR_TEST_DNS_ZONE" "$PILOT_VAR_TEST_DIRECT_OWNER" --raw 2>/dev/null | grep -oE 'arecord: [0-9.]+' | awk '{print $2}' | head -n1)
    echo "$val" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && echo no-port || echo "invalid val=$val"
  expect: {stdout: {equals: no-port}}
  tags: [C6]
- id: C7
  category: dns
  check: the endpoint's dns.zone exists in the freeipa-dns manifest and is effectively records_mode merge
  # scope: aggregate — freeipa_dns_manifest_path is a path on the machine
  # driving ansible (the same file internal-endpoint-apply.yml's own
  # `ansible.builtin.include_vars` reads, which always resolves on the
  # control node regardless of the play's `hosts:`), not on a managed
  # host. Per-host dispatch tried to open this path ON THE REMOTE VM and
  # got FileNotFoundError — caught for real on 2026-08-14 once the
  # per-host $PILOT_VAR_* substitution bug (see this round's evidence) was
  # fixed and stopped masking it. Also fixed a second, previously-masked
  # bug in this same probe: zones live under `dns.zones` in a real
  # freeipa-dns manifest, not a bogus top-level `zones` key — the old
  # `d.get('zones', [])` always returned `[]` and always printed
  # `zone-not-found`, never actually reading the real zone list.
  probe: |
    python3 -c "
    import yaml
    d = yaml.safe_load(open('$PILOT_VAR_FREEIPA_DNS_MANIFEST_PATH'))
    dns = d.get('dns', {}) if isinstance(d, dict) else {}
    default_mode = (dns.get('defaults') or {}).get('records_mode', 'merge')
    zones = dns.get('zones', [])
    for z in zones:
        if z.get('name') == '$PILOT_VAR_TEST_DNS_ZONE':
            print(z.get('records_mode', default_mode))
            break
    else:
        print('zone-not-found')
    "
  expect: {stdout: {equals: merge}}
  scope: aggregate
  tags: [C7]
- id: C8
  category: dns
  check: a manifest claiming a (zone, owner, type) already explicitly managed by freeipa-dns.yaml is rejected
  probe: |
    out=$(pilot internal-endpoint validate --manifest "$PILOT_VAR_MANIFEST_FIXTURE_DIR/dns-collision.yaml" --freeipa-dns-manifest "$PILOT_VAR_FREEIPA_DNS_MANIFEST_PATH" 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi 'ownership conflict'; then echo rejected; else echo "accepted rc=$rc"; fi
  expect: {stdout: {equals: rejected}}
  tags: [C8]
- id: C9
  category: resolver
  check: every managed host resolves via the FreeIPA DNS resolver baseline applied by this reconciler
  # `grep -c '| SUCCESS'` never matches ad-hoc `command`/`shell` module
  # output — those modules always report `| CHANGED | rc=0` (or `|
  # FAILED`), never `| SUCCESS` (that label is only for idempotent-aware
  # modules like `ping`), so this probe always undercounted to 0 —
  # previously masked by the same per-host $PILOT_VAR_* substitution bug
  # this round's evidence documents (an always-empty
  # PILOT_VAR_PILOT_INVENTORY_PATH failed for an unrelated reason first).
  # Caught for real on 2026-08-14 once that bug was fixed and this probe's
  # own bug was the next thing blocking a clean run. Fixed by counting
  # `rc=0` directly, which is what a real success actually looks like for
  # these module types.
  probe: |
    got=$(ansible all -i "$PILOT_VAR_PILOT_INVENTORY_PATH" -m command -a "resolvectl status" 2>&1 | grep -c '| rc=0' || true)
    want=$(ansible all -i "$PILOT_VAR_PILOT_INVENTORY_PATH" --list-hosts 2>/dev/null | tail -n +2 | wc -l)
    if [ "$got" = "$want" ] && [ "$want" -gt 0 ]; then echo "all $want hosts ok"; else echo "got=$got want=$want"; fi
  expect: {stdout: {regex: '^all [0-9]+ hosts ok$'}}
  scope: aggregate
  tags: [C9]
- id: C10
  category: trust
  check: every managed host trusts the FreeIPA CA baseline applied by this reconciler
  # Same `| SUCCESS` -> `rc=0` fix as C9 above.
  probe: |
    got=$(ansible all -i "$PILOT_VAR_PILOT_INVENTORY_PATH" -m shell -a "test -f /usr/local/share/ca-certificates/pilot-freeipa-ca.crt -o -f /etc/pki/ca-trust/source/anchors/pilot-freeipa-ca.crt" 2>&1 | grep -c '| rc=0' || true)
    want=$(ansible all -i "$PILOT_VAR_PILOT_INVENTORY_PATH" --list-hosts 2>/dev/null | tail -n +2 | wc -l)
    if [ "$got" = "$want" ] && [ "$want" -gt 0 ]; then echo "all $want hosts ok"; else echo "got=$got want=$want"; fi
  expect: {stdout: {regex: '^all [0-9]+ hosts ok$'}}
  scope: aggregate
  tags: [C10]
- id: C11
  category: cert
  check: the certificate owner recorded in the ownership ledger matches the derivation rule (spec.md §15)
  probe: |
    got=$(python3 -c "import json;d=json.load(open('/var/lib/pilot/internal-endpoint/state.json'));print(d.get('endpoints',{}).get('$PILOT_VAR_TEST_ENDPOINT_FQDN',{}).get('certificate_owner',''))" 2>/dev/null)
    if [ "$got" = "$PILOT_VAR_TEST_EXPECTED_CERT_OWNER" ]; then echo match; else echo "got=$got want=$PILOT_VAR_TEST_EXPECTED_CERT_OWNER"; fi
  expect: {stdout: {equals: match}}
  verifyOnly: true
- id: C12
  category: cert
  check: a certificate owner host without live FreeIPA enrollment fails before any mutation
  probe: |
    ledger=/var/lib/pilot/internal-endpoint/state.json
    python3 -c "import json,sys;d=json.load(open('$ledger'));sys.exit(0 if '$PILOT_VAR_TEST_NONENROLLED_ENDPOINT_FQDN' in d.get('endpoints',{}) else 1)" 2>/dev/null && echo unexpected-mutation || echo no-mutation
  expect: {stdout: {equals: no-mutation}}
  tags: [C12]
- id: C13
  category: cert
  check: the HTTP/<fqdn> service principal exists and is managedBy the derived certificate owner host
  # Real `ipa ... --all --raw` output indents every attribute line with 2
  # spaces ("  dn: ...", not "dn: ..."); an unanchored-at-start `^dn:` never
  # matches. Same leading-whitespace class of bug already documented for
  # freeipa-dns (see its own evidence record) — caught here for real on
  # 2026-08-13's Phase 5 vm-target run (exists=0 despite the principal
  # genuinely existing, confirmed by manual inspection).
  probe: |
    show=$(ipa service-show "HTTP/$PILOT_VAR_TEST_ENDPOINT_FQDN" --all --raw 2>/dev/null)
    exists=$(printf '%s' "$show" | grep -c '^[[:space:]]*dn:')
    managed=$(printf '%s' "$show" | grep -c "managedby.*$PILOT_VAR_TEST_EXPECTED_CERT_OWNER")
    if [ "$exists" -ge 1 ] && [ "$managed" -ge 1 ]; then echo correct; else echo "exists=$exists managed=$managed"; fi
  expect: {stdout: {equals: correct}}
  tags: [C13]
- id: C14
  category: cert
  check: the issued certificate's SAN contains the exact endpoint FQDN
  # scope: aggregate — corrected 2026-08-13 (Phase 5 real-run evidence): the
  # cert file lives on the certificate owner host, which is frequently NOT
  # the freeipa-server this spec's per-host rows otherwise run on (proven by
  # this feature's own worked example — see spec.md §11.4, DNS never points
  # at the same host that owns every cert). Running this per-host on
  # freeipa-server silently inspected the wrong filesystem whenever owner !=
  # freeipa-server. Fixed the same way C9/C10 already do: aggregate scope,
  # dispatched to the real owner host via one ansible ad-hoc call.
  probe: |
    ansible "$PILOT_VAR_TEST_EXPECTED_CERT_OWNER" -i "$PILOT_VAR_PILOT_INVENTORY_PATH" -b -m shell \
      -a "openssl x509 -in $PILOT_VAR_TEST_CERT_FILE -noout -ext subjectAltName 2>/dev/null | grep -q 'DNS:$PILOT_VAR_TEST_ENDPOINT_FQDN' && echo present || echo absent" \
      2>/dev/null | tail -n1
  expect: {stdout: {equals: present}}
  scope: aggregate
  verifyOnly: true
- id: C15
  category: cert
  check: certmonger reports the endpoint certificate as status MONITORING
  # scope: aggregate — same fix as C14: certmonger's tracking state is local
  # to the certificate owner host, not freeipa-server.
  probe: |
    ansible "$PILOT_VAR_TEST_EXPECTED_CERT_OWNER" -i "$PILOT_VAR_PILOT_INVENTORY_PATH" -b -m shell \
      -a "getcert list -f $PILOT_VAR_TEST_CERT_FILE 2>/dev/null | grep -m1 '^[[:space:]]*status:' | awk '{print \$2}'" \
      2>/dev/null | tail -n1
  expect: {stdout: {equals: MONITORING}}
  scope: aggregate
  tags: [C15]
- id: C16
  category: cert
  check: the private key file exists only on the certificate owner host with owner-only permissions
  # scope: aggregate — same fix as C14/C15: the key file lives on the
  # certificate owner host.
  probe: |
    ansible "$PILOT_VAR_TEST_EXPECTED_CERT_OWNER" -i "$PILOT_VAR_PILOT_INVENTORY_PATH" -b -m shell \
      -a "[ -f $PILOT_VAR_TEST_KEY_FILE ] || { echo missing; exit 0; }; perm=\$(stat -c '%a' $PILOT_VAR_TEST_KEY_FILE 2>/dev/null); case \$perm in 600|640) echo ok;; *) echo perm=\$perm;; esac" \
      2>/dev/null | tail -n1
  expect: {stdout: {equals: ok}}
  scope: aggregate
  verifyOnly: true
- id: C17
  category: proxy
  check: the reverse_proxy endpoint completes an HTTPS handshake without -k/--insecure
  probe: |
    curl -sS -o /dev/null -w '%{http_code}' "$PILOT_VAR_TEST_PROXY_ENDPOINT_URL" 2>/dev/null
  expect: {stdout: {regex: '^(200|301|302|401|403|404)$'}}
  verifyOnly: true
- id: C18
  category: proxy
  check: the proxy forwards to the declared backend port (backend-specific marker observed through the proxy)
  probe: |
    curl -sS "$PILOT_VAR_TEST_PROXY_ENDPOINT_URL" 2>/dev/null | grep -qF "$PILOT_VAR_TEST_BACKEND_MARKER" && echo forwarded || echo not-forwarded
  expect: {stdout: {equals: forwarded}}
  verifyOnly: true
- id: C19
  category: direct
  check: the direct endpoint completes an HTTPS handshake without -k/--insecure
  probe: |
    curl -sS -o /dev/null -w '%{http_code}' "$PILOT_VAR_TEST_DIRECT_ENDPOINT_URL" 2>/dev/null
  expect: {stdout: {regex: '^(200|301|302|401|403|404)$'}}
  verifyOnly: true
- id: C20
  category: direct
  check: a non-443 direct TLS endpoint is only reachable as https://fqdn:port, never bare https://fqdn
  probe: |
    case "$PILOT_VAR_TEST_DIRECT_ENDPOINT_URL" in
      https://*:443|https://*:443/*) echo "unexpected-443";;
      https://*:*) curl -sS -o /dev/null -w '%{http_code}' "$PILOT_VAR_TEST_DIRECT_ENDPOINT_URL" 2>/dev/null;;
      *) echo no-explicit-port;;
    esac
  expect: {stdout: {regex: '^(200|301|302|401|403|404)$'}}
  verifyOnly: true
- id: C21
  category: delete
  check: state:absent without both manifest safety.allow_endpoint_delete and runtime confirm_endpoint_delete performs no mutation
  probe: |
    out=$(pilot reconcile internal-endpoint --manifest "$PILOT_VAR_MANIFEST_FIXTURE_DIR/absent-no-confirm.yaml" 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi confirm; then echo blocked; else echo "not-blocked rc=$rc"; fi
  expect: {stdout: {equals: blocked}}
  tags: [C21]
- id: C22
  category: delete
  check: deleting an endpoint's A/AAAA record never removes a foreign record type at the same owner
  # `^[[:space:]]*txtrecord` (not a bare `^txtrecord`) — the same
  # leading-whitespace class of bug already documented multiple times in
  # this project (C13's `dn:` probe, freeipa-dns's own attribute regexes):
  # real `ipa ... --all --raw`/`--raw` output indents every attribute line
  # with 2 spaces, so an unanchored-at-start regex never matches. Caught
  # for real on 2026-08-14's Phase 8 vm-target run before wasting a verify
  # attempt on it — the fix was applied preemptively, mirroring the
  # already-known pattern rather than discovering it fresh a third time.
  probe: |
    ipa dnsrecord-show "$PILOT_VAR_TEST_DNS_ZONE" "$PILOT_VAR_TEST_DIRECT_OWNER" --raw 2>/dev/null | grep -q '^[[:space:]]*txtrecord' && echo foreign-record-intact || echo foreign-record-missing
  expect: {stdout: {equals: foreign-record-intact}}
  tags: [C22]
- id: C23
  category: delete
  check: a destructive request for an endpoint absent from the ownership ledger fails closed
  probe: |
    out=$(pilot reconcile internal-endpoint --manifest "$PILOT_VAR_MANIFEST_FIXTURE_DIR/absent-no-ledger.yaml" --ledger /nonexistent/state.json 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi ledger; then echo blocked; else echo "not-blocked rc=$rc"; fi
  expect: {stdout: {equals: blocked}}
  tags: [C23]
- id: C24
  category: delete
  check: an in-place route-owner migration (direct<->reverse_proxy, or target/proxy host change) is rejected in v1
  probe: |
    out=$(pilot reconcile internal-endpoint --manifest "$PILOT_VAR_MANIFEST_FIXTURE_DIR/route-owner-migration.yaml" 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi 'route owner'; then echo blocked; else echo "not-blocked rc=$rc"; fi
  expect: {stdout: {equals: blocked}}
  tags: [C24]
- id: C25
  category: dns
  check: an inventory host IP change (same inventory_host, new ansible_host) reconciles the DNS record cleanly
  probe: |
    got=$(ipa dnsrecord-show "$PILOT_VAR_TEST_DNS_ZONE" "$PILOT_VAR_TEST_DIRECT_OWNER" --raw 2>/dev/null | grep -oE 'arecord: [0-9.]+' | awk '{print $2}' | head -n1)
    if [ "$got" = "$PILOT_VAR_TEST_DIRECT_TARGET_IP" ]; then echo current; else echo "stale got=$got want=$PILOT_VAR_TEST_DIRECT_TARGET_IP"; fi
  expect: {stdout: {equals: current}}
  tags: [C4]
- id: C26
  category: idempotency
  check: the endpoint remains present in the ownership ledger after a clean rerun (rerun changed=0 evidenced by vm-target topology test, not by this probe)
  probe: |
    python3 -c "import json,sys;d=json.load(open('/var/lib/pilot/internal-endpoint/state.json'));sys.exit(0 if '$PILOT_VAR_TEST_ENDPOINT_FQDN' in d.get('endpoints',{}) else 1)" 2>/dev/null && echo present || echo absent
  expect: {stdout: {equals: present}}
  verifyOnly: true
- id: C27
  category: proxy
  check: "the reverse_proxy route supports an HTTPS upstream (upstream.scheme=https)"
  # scope: aggregate — same fix as C14/C15/C16 (Phase 5/6): the rendered
  # nginx vhost file lives on the PROXY host (spec.md §15's cert_owner for
  # reverse_proxy — route.proxy.inventory_host — happens to be the same
  # host, so $PILOT_VAR_TEST_EXPECTED_CERT_OWNER doubles as "which host has
  # this file"), not on freeipa-server. Running this per-host on
  # freeipa-server would silently inspect the wrong filesystem — caught for
  # real during Phase 7's own authoring (2026-08-14), before it ever ran
  # against a live 3-VM topology, by re-checking the C14-family pattern
  # this same file already established.
  probe: |
    ansible "$PILOT_VAR_TEST_EXPECTED_CERT_OWNER" -i "$PILOT_VAR_PILOT_INVENTORY_PATH" -b -m shell \
      -a "grep -q 'proxy_pass https://' '$PILOT_VAR_TEST_NGINX_VHOST_CONF' 2>/dev/null && echo https-upstream || echo no-https-upstream" \
      2>/dev/null | tail -n1
  expect: {stdout: {equals: https-upstream}}
  scope: aggregate
  tags: [C27]
- id: C28
  category: proxy
  check: an HTTPS upstream with tls.verify=true completes a verified handshake to a valid backend certificate
  probe: |
    curl -sS -o /dev/null -w '%{http_code}' "$PILOT_VAR_TEST_VERIFIED_UPSTREAM_ENDPOINT_URL" 2>/dev/null
  expect: {stdout: {regex: '^(200|301|302|401|403|404)$'}}
  verifyOnly: true
- id: C29
  category: proxy
  check: an HTTPS upstream with tls.verify=false still serves the frontend correctly against a self-signed/untrusted backend
  probe: |
    curl -sS -o /dev/null -w '%{http_code}' "$PILOT_VAR_TEST_INSECURE_UPSTREAM_ENDPOINT_URL" 2>/dev/null
  expect: {stdout: {regex: '^(200|301|302|401|403|404)$'}}
  verifyOnly: true
- id: C30
  category: schema
  check: an HTTPS upstream without an explicit tls.verify is rejected (fail closed, no implicit default)
  probe: |
    out=$(pilot internal-endpoint validate --manifest "$PILOT_VAR_MANIFEST_FIXTURE_DIR/https-upstream-missing-verify.yaml" 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi verify; then echo rejected; else echo "accepted rc=$rc"; fi
  expect: {stdout: {equals: rejected}}
  scope: aggregate
  verifyOnly: true
- id: C31
  category: proxy
  check: an insecure (verify=false) HTTPS upstream connection is still real TLS on the wire, not downgraded to plaintext HTTP
  probe: |
    echo | openssl s_client -connect "$PILOT_VAR_TEST_INSECURE_UPSTREAM_HOST:$PILOT_VAR_TEST_INSECURE_UPSTREAM_PORT" -brief 2>&1 | grep -qi 'Protocol version' && echo tls || echo no-tls
  expect: {stdout: {equals: tls}}
  verifyOnly: true
- id: C32
  category: proxy
  check: an explicit upstream tls.server_name (SNI) is rendered into the generated nginx config
  # scope: aggregate — same fix as C27 above (the vhost file lives on the
  # proxy host, not freeipa-server).
  probe: |
    ansible "$PILOT_VAR_TEST_EXPECTED_CERT_OWNER" -i "$PILOT_VAR_PILOT_INVENTORY_PATH" -b -m shell \
      -a "grep -q 'proxy_ssl_name $PILOT_VAR_TEST_UPSTREAM_SNI;' '$PILOT_VAR_TEST_NGINX_VHOST_CONF' 2>/dev/null && echo sni-configured || echo sni-missing" \
      2>/dev/null | tail -n1
  expect: {stdout: {equals: sni-configured}}
  scope: aggregate
  verifyOnly: true
```

## PASS / FAIL

All applicable C1-C32 rows must pass. An unresolved host, runner error,
timeout, or matcher failure makes the deployment transaction fail.
`not_applicable` is not used by this contract.

## Traceability

- C4, C5, C6, C7, C8, C9, C10, C12, C13, C15, C21, C22, C23, C24, C25, and
  C27 map to real apply-playbook tags (row C25 shares tag `C4` — it is a
  second-run assertion about the same DNS-write task C4 implements, not a
  distinct mutation).
- C1, C2, C3, C11, C14, C16, C17, C18, C19, C20, C26, C28, C29, C30, C31,
  and C32 verify derived or end-to-end effective behavior — either a pure
  Go-validator outcome (C1, C2, C3, C30) or an emergent property of one of
  the tagged mutation tasks above — and are intentionally verification-only.

## Actual-run evidence

2026-08-13, two disposable `pilot vm-target` KVM VMs (`p5-ipa` AlmaLinux 9 FreeIPA server,
`p5-client` Ubuntu 24.04 enrolled FreeIPA client, playing the certificate-owner role per
spec.md §11.4's direct-mode worked example). Phase 5 (spec.md §63) implements only the
certificate-lifecycle mechanism — C12 (enrollment preflight), C13 (host/service principal +
managedBy delegation), C14-C16 (certificate SAN/status/key-permission, plus a real renewal
smoke test via `getcert resubmit`). Full transcripts, PLAY RECAPs, and the real bugs this
round found and fixed (two check-mode gaps, a real FreeIPA CLI-output-format bug in C13's
probe, a wrong-host design flaw in C14-C16, and an Ansible `-e` value-splitting gotcha) are
recorded in `docs/evidence/internal-endpoint/2026-08-13.md`.

```
$ pilot verify docs/verification/internal-endpoint.md -i <grouped-inventory> -l p5-ipa --input ...
verdict: FAIL  (pass=6 fail=26 skip=0)

C1  pass   C12 pass   C13 pass   C14 pass   C15 pass   C16 pass
C2-C11, C17-C32: fail (DNS/nginx reconciler logic — Phase 6-9 scope, still Phase-1 placeholders)
```

This is the expected partial-coverage result: every row Phase 5 implements (C12-C16) is
green, confirmed via real FreeIPA host/service delegation, a real certmonger-tracked
certificate, and a real renewal-hook smoke test (a `getcert resubmit` advanced the post-save
marker file's mtime, proving the hook fires with its full argument intact). The spec is
**not** promoted to v1.0 by this round — C2-C11 and C17-C32 still depend on Phase 6-9
features (DNS write, nginx vhost render, deletion safety, upstream TLS modes) that remain
unimplemented; full promotion is Phase 10's job per spec.md's own phased authoring intent.

2026-08-14, two fresh disposable `pilot vm-target` KVM VMs (`p6-ipa` AlmaLinux 9 FreeIPA
server, `p6-app01` Ubuntu 24.04 enrolled FreeIPA client — spec.md §52/§53's `app01`).
Phase 6 (spec.md §63) retired Phase 5's single-endpoint `-e internal_endpoint_test_*`
scaffolding entirely and replaced it with the real manifest-driven per-endpoint reconcile
loop, covering C4, C6, C7 (DNS write + preflight) end-to-end alongside C12/C13/C15
(now driven from the manifest, not hand-fed vars) for spec.md §53's endpoint A
(`direct.apps.pilot.internal`, direct + tls.freeipa, non-standard port 8443) and endpoint B
(`aaa.xxx.apps.pilot.internal`, nested FQDN, direct + tls.disabled). This round also found
and fixed a previously-unknown, project-wide `pilot verify` bug (per-host rows never
actually received their declared `$PILOT_VAR_*` inputs — see the evidence doc for the full
mechanism) plus two bugs in this spec's own C7/C9/C10 probes that bug had been masking.
Full transcripts, PLAY RECAPs, and every bug found+fixed (a certmonger flag-meaning
mistake, a placeholder-cert/certmonger-adoption trap, the `pilot verify` bug, and the
C7/C9/C10 probe bugs) are recorded in `docs/evidence/internal-endpoint/2026-08-14.md`.

```
$ pilot verify docs/verification/internal-endpoint.md -i <grouped-inventory> -l p6-ipa --input ...
verdict: FAIL  (pass=12 fail=20 skip=0)

C1 C4 C6 C7 C10 C12 C13 C14 C15 C16 C19 C20 C25: pass
C2 C3 C5 C8 C9 C11 C17 C18 C21-C24 C26-C32: fail (Phase 2/7/8/9 scope — CLI surface,
  reverse_proxy DNS/nginx, ownership ledger, TUI/MCP — still unimplemented)
```

Nested FQDN proven via real `dig` against the FreeIPA server's own resolver
(`aaa.xxx.apps.pilot.internal` → `192.168.122.6`, endpoint B's target). Endpoint A's
renewal hook proven via a real `getcert resubmit` — same PID before/after, journal shows
`Reloading... / reloaded TLS context / Reloaded`, confirming a genuine graceful reload
(not a restart). Idempotency confirmed via a second full reconcile: `changed=0 failed=0`
on both hosts. Still DRAFT overall — C2/C3/C5/C8/C9/C11/C17-C24/C26-C32 remain
unimplemented or CLI-dependent pending Phase 7-9; full promotion is Phase 10's job.

2026-08-14, a fresh 3-VM topology (`p7-ipa` AlmaLinux 9 FreeIPA server, `p7-app01` Ubuntu
24.04 direct target + reverse_proxy upstream backend, `p7-proxy01` Ubuntu 24.04
reverse-proxy — spec.md §52's minimum topology). Phase 7 (spec.md §63) implemented the
nginx vhost render + reload + local backend readiness check (C27) and extended the DNS
write (C4/C6) to also cover reverse_proxy routes (C5), covering spec.md §53's endpoint C
(`proxy.apps.pilot.internal`, HTTP upstream) and endpoint D (`legacy.apps.pilot.internal`,
insecure HTTPS upstream against a genuinely self-signed backend, explicit SNI). Full
transcripts, PLAY RECAPs, and every bug found+fixed (two more ansible-core 2.19
lazy-dict AttributeErrors, a hand-rolled backup mechanism that broke idempotency, and the
C27/C32 wrong-host probe bug) are recorded in
`docs/evidence/internal-endpoint/2026-08-14-phase7.md`.

```
$ pilot verify docs/verification/internal-endpoint.md -i <grouped-inventory> -l p7-ipa --input ...
verdict: FAIL  (pass=21 fail=11)

C1 C4 C5 C6 C7 C10 C12 C13 C14 C15 C16 C17 C18 C19 C20 C25 C27 C28 C29 C31 C32: pass
C2 C3 C8 C9 C11 C21 C22 C23 C24 C26 C30: fail (Phase 8/9 scope — ownership ledger,
  deletion gates, a `pilot internal-endpoint validate` CLI that doesn't exist yet)
```

Both endpoints proven end-to-end with real client `curl` through nginx (no `-k` needed —
real FreeIPA-issued frontend certs), real DNS pointing at the proxy host never the
upstream, real certificate ownership derivation (proxy host, not upstream, per spec.md
§15) with OS-family-correct key-group permissions, and a real `openssl s_client` proving
endpoint D's insecure upstream is genuine TLS on the wire, not silently downgraded to
plaintext. Idempotent rerun confirmed (`changed=0 failed=0`) only after fixing a
hand-rolled snapshot mechanism that had made every rerun report spurious changes — see the
evidence doc. Still DRAFT overall — C2/C3/C8/C9/C11/C21-C24/C26/C30 remain unimplemented
or CLI-dependent pending Phase 8-9; full promotion is Phase 10's job.

2026-08-14, a fresh 2-VM topology (`p8-ipa` AlmaLinux 9 FreeIPA server, `p8-app01` Ubuntu
24.04 direct target/certificate owner). Phase 8 (spec.md §63) implemented the ownership
ledger (§29), the route-ownership-migration gate (§30, C24), the dual-confirmation +
ledger-presence delete gates (§31/§32, C21/C23), and the full 9-step delete sequence
(§32) with FreeIPA identity delete safety (§33) and DNS delete safety (§34, C22). Full
transcripts and every bug found+fixed (a real `ipa host-del --updatedns` CLI-flag
mistake, and C22's own leading-whitespace probe bug) are recorded in
`docs/evidence/internal-endpoint/2026-08-14-phase8.md`.

```
$ pilot verify docs/verification/internal-endpoint.md -i <grouped-inventory> -l p8-ipa --input ...
verdict: FAIL  (pass=16 fail=16)

C1 C4 C6 C7 C10 C11 C12 C13 C14 C15 C16 C19 C20 C22 C25 C26: pass
C2 C3 C5 C8 C9 C17 C18 C21 C23 C24 C27 C28 C29 C30 C31 C32: fail (C21/C23/C24 remain
  CLI-dependent same as C2/C3/C8/C30; C5/C17/C18/C27-C32 fail only because this round's
  2-VM topology has no reverse_proxy endpoint, already proven in Phase 7)
```

The 3 rows whose own probes don't depend on a nonexistent CLI (C11, C22, C26) all
genuinely pass. C21/C23/C24's REAL Ansible-side mechanism was independently proven via 3
real negative-path VM tests (dual-confirmation, ledger-presence, route-migration, all
fail closed with the exact expected error messages) — the same precedent already
established for C8 in Phase 6. The full 9-step delete sequence was proven for real:
DNS RRset removed (foreign TXT record at the same owner survived, C22), certmonger
tracking stopped, certificate genuinely revoked at the FreeIPA CA
(`Revoked: True, Revocation reason: 5`), local cert/key files removed, service principal
and virtual host object removed, ledger entry removed (empty `endpoints: {}` after
deletion). Idempotent rerun confirmed (`changed=0 failed=0`) after recreating the
endpoint. Still DRAFT overall — C2/C3/C5/C8/C9/C17/C18/C21/C23/C24/C27-C32 remain
unimplemented, CLI-dependent, or out of this round's topology pending Phase 9; full
promotion is Phase 10's job.

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-08-13 | DRAFT | Phase 1 (spec.md §63): initial Spec v2 authoring covering the v1.0 acceptance rows (C1-C26) plus the v1.1 reverse-proxy HTTPS-upstream revision (C27-C32, spec.md §67 Revision Log). No actual-run evidence yet — the Go validator, reconciler CLI, and apply playbook are all Phase-1 skeletons; Phase 2/5/6/7/10 supply real behavior and VM evidence. |
| 2026-08-13 | DRAFT (partial evidence) | Phase 5: real certificate-lifecycle logic landed and confirmed against real AlmaLinux 9 (FreeIPA server) + Ubuntu 24.04 (enrolled client/certificate-owner) VMs — C12-C16 all PASS, idempotent rerun confirmed (`changed=0`), renewal hook confirmed via a real `getcert resubmit`. C13's probe was fixed for a leading-whitespace regex bug in `ipa --all --raw` output; C14-C16 were fixed from per-host (`freeipa-server`) to `scope: aggregate` dispatched to the real certificate-owner host, mirroring C9/C10's existing pattern. Still DRAFT overall — C1-C11 and C17-C32 remain unimplemented pending Phase 6-9; see the evidence doc for the full bug list, including an Ansible `-e KEY=VALUE` space-splitting gotcha unrelated to this repo's own code. |
| 2026-08-14 | DRAFT (partial evidence) | Phase 6: the manifest-driven per-endpoint reconcile loop replaced Phase 5's single-endpoint scaffolding — C4, C6, C7 (DNS write + zone/collision preflight) now real, alongside C12/C13/C15 driven from the manifest. Confirmed against fresh AlmaLinux 9 + Ubuntu 24.04 VMs: spec.md §53 endpoint A (direct + tls.freeipa, non-standard port, real FreeIPA cert, real graceful renewal reload — same PID, proven via `getcert resubmit`) and endpoint B (nested FQDN + tls.disabled, DNS-only) both PASS; C8's collision gate confirmed to fail closed on a real negative-path VM test; idempotent rerun confirmed (`changed=0`). Also found and fixed a previously-unknown, project-wide `pilot verify` bug (`internal/tools/per_host_verify.go`'s `posixEnvironmentPrefix`: per-host rows never actually received their `$PILOT_VAR_*` inputs, silently false-passing whenever both sides of an `equals` check happened to be empty) plus two bugs in this spec's own C7/C9/C10 probes that bug had been masking (wrong manifest dict path in C7, wrong host in C7, `| SUCCESS` never matching ad-hoc `command`/`shell` output in C9/C10). C10 now genuinely passes for the first time. Still DRAFT overall — C2/C3/C5/C8/C9/C11/C17-C24/C26-C32 remain unimplemented or CLI-dependent pending Phase 7-9; see the evidence doc for the full bug list. |
| 2026-08-14 | DRAFT (partial evidence) | Phase 7: nginx vhost render/reload/local-backend-check (C27) landed, and the DNS-write task extended to cover reverse_proxy routes too (C5). Confirmed against a fresh 3-VM topology (AlmaLinux 9 FreeIPA server + 2 Ubuntu 24.04 hosts, one reverse-proxy): spec.md §53 endpoint C (HTTP upstream) and endpoint D (insecure HTTPS upstream against a genuinely self-signed, non-FreeIPA backend cert, explicit SNI) both PASS end-to-end via real client `curl` through nginx — no `-k` needed on the frontend, real `openssl s_client` confirming the insecure upstream is genuine TLS on the wire (not downgraded to plaintext). Found and fixed 2 more ansible-core 2.19 lazy-dict AttributeErrors (dot-notation on a `default({})` result), a hand-rolled vhost-backup mechanism that broke idempotency (replaced with `ansible.builtin.template`'s native `backup: true`), and the same wrong-host probe bug already fixed for C14-C16/C9-C10 recurring in C27/C32 (fixed the same way — `scope: aggregate` dispatched to the real proxy host). Idempotent rerun confirmed (`changed=0 failed=0`) after the backup-mechanism fix. Still DRAFT overall — C2/C3/C8/C9/C11/C21-C24/C26/C30 remain unimplemented or CLI-dependent pending Phase 8-9; see the evidence doc for the full bug list. |
| 2026-08-14 | DRAFT (partial evidence) | Phase 8: the ownership ledger (C11/C26), route-ownership-migration gate (C24), dual-confirmation + ledger-presence delete gates (C21/C23), and the full 9-step delete sequence with FreeIPA/DNS delete safety (C22) all landed real. Confirmed against a fresh 2-VM topology: the ledger writes correctly (real cert serial, root:root 0600); all 3 negative-path gates fail closed with real VM tests (dual confirmation, ledger-presence, route-migration, same precedent as C8); a real deletion completed all 9 steps — DNS RRset removed with a foreign TXT record at the same owner surviving intact (C22), certmonger tracking stopped, certificate genuinely revoked at the FreeIPA CA (`Revoked: True`), local cert/key removed, service principal and virtual host object removed, ledger entry removed. Found and fixed a real `ipa host-del --updatedns` CLI-flag mistake (bare boolean, not key=value — and wrong to pass at all here, since step 1 already did the surgical DNS removal) and C22's own leading-whitespace probe bug (same class already fixed for C13, caught proactively this time). Idempotent rerun confirmed (`changed=0 failed=0`) after recreating the endpoint. Still DRAFT overall — C2/C3/C5/C8/C9/C17/C18/C21/C23/C24/C27-C32 remain unimplemented, CLI-dependent, or outside this round's topology pending Phase 9; see the evidence doc for the full bug list and known follow-ups. |
