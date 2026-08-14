package inventory

import "testing"

func iepRuleNames(violations []InternalEndpointViolation) []string {
	out := make([]string, len(violations))
	for i, v := range violations {
		out[i] = v.Rule
	}
	return out
}

func mustParseIEPManifest(t *testing.T, doc string) map[string]any {
	t.Helper()
	return decodeIEPManifest(t, doc)
}

// TestValidateInternalEndpointManifest_UnitMatrix implements spec.md §51's
// validator unit-test matrix (the original v1.0 list plus the v1.1
// reverse-proxy HTTPS-upstream revision additions, spec.md §67). Every case
// that doesn't need external facts (hostvars, freeipa-dns zones, live
// enrollment) lives here as one table entry; cases needing
// InternalEndpointValidateOptions have their own dedicated test below the
// table so the fixture wiring stays readable.
func TestValidateInternalEndpointManifest_UnitMatrix(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		wantRule string // "" means the manifest must pass with zero violations
	}{
		{
			name: "valid direct IPv4",
			doc: `
schema_version: 1
endpoints:
  - fqdn: direct.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.20.30.40}}
    tls: {mode: disabled}
`,
		},
		{
			name: "valid direct IPv6",
			doc: `
schema_version: 1
endpoints:
  - fqdn: direct6.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: "2001:db8::1"}}
    tls: {mode: disabled}
`,
		},
		{
			name: "valid explicit address",
			doc: `
schema_version: 1
endpoints:
  - fqdn: appliance.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.20.30.40}}
    tls: {mode: disabled}
`,
		},
		{
			name: "valid reverse proxy",
			doc: `
schema_version: 1
endpoints:
  - fqdn: grafana.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream: {scheme: http, inventory_host: grafana01, port: 3000}
    tls: {mode: disabled}
`,
		},
		{
			name: "valid nested FQDN",
			doc: `
schema_version: 1
endpoints:
  - fqdn: aaa.xxx.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {inventory_host: app01}}
    tls: {mode: disabled}
`,
		},
		{
			name: "valid zone apex",
			doc: `
schema_version: 1
endpoints:
  - fqdn: linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`,
		},
		{
			name: "duplicate fqdn",
			doc: `
schema_version: 1
endpoints:
  - fqdn: dup.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
  - fqdn: DUP.linker.internal.
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.2}}
    tls: {mode: disabled}
`,
			wantRule: "unique fqdn",
		},
		{
			name: "wildcard fqdn",
			doc: `
schema_version: 1
endpoints:
  - fqdn: "*.linker.internal"
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`,
			wantRule: "fqdn shape",
		},
		{
			name: "fqdn with URL scheme",
			doc: `
schema_version: 1
endpoints:
  - fqdn: "https://foo.linker.internal"
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`,
			wantRule: "fqdn shape",
		},
		{
			name: "fqdn with port",
			doc: `
schema_version: 1
endpoints:
  - fqdn: "foo.linker.internal:8443"
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`,
			wantRule: "fqdn shape",
		},
		{
			name: "fqdn outside zone",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.example.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`,
			wantRule: "dns.zone",
		},
		{
			name: "direct both address + inventory_host",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1, inventory_host: app01}}
    tls: {mode: disabled}
`,
			wantRule: "route.target",
		},
		{
			name: "direct neither",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {}}
    tls: {mode: disabled}
`,
			wantRule: "route.target",
		},
		{
			name: "literal address + freeipa TLS",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: freeipa}
`,
			wantRule: "tls direct owner",
		},
		{
			name: "proxy host missing",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx}
      upstream: {scheme: http, address: 10.0.0.5, port: 3000}
    tls: {mode: disabled}
`,
			wantRule: "route.proxy",
		},
		{
			name: "upstream port 0",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream: {scheme: http, address: 10.0.0.5, port: 0}
    tls: {mode: disabled}
`,
			wantRule: "route.upstream.port",
		},
		{
			name: "upstream port 65536",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream: {scheme: http, address: 10.0.0.5, port: 65536}
    tls: {mode: disabled}
`,
			wantRule: "route.upstream.port",
		},
		{
			name: "unknown route mode",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: bogus}
    tls: {mode: disabled}
`,
			wantRule: "route.mode",
		},
		{
			name: "unknown TLS mode",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: bogus}
`,
			wantRule: "tls.mode",
		},
		{
			name: "relative cert path",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {inventory_host: app01}}
    tls:
      mode: freeipa
      sink:
        cert_file: etc/app/tls/server.crt
        key_file: /etc/app/tls/server.key
        reload: {mode: systemd, unit: app.service}
`,
			wantRule: "tls.sink.cert_file",
		},
		{
			name: "cert path == key path",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {inventory_host: app01}}
    tls:
      mode: freeipa
      sink:
        cert_file: /etc/app/tls/server.pem
        key_file: /etc/app/tls/server.pem
        reload: {mode: systemd, unit: app.service}
`,
			wantRule: "tls.sink paths",
		},
		{
			name: "invalid systemd unit",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {inventory_host: app01}}
    tls:
      mode: freeipa
      sink:
        cert_file: /etc/app/tls/server.crt
        key_file: /etc/app/tls/server.key
        reload: {mode: systemd, unit: "not a unit"}
`,
			wantRule: "tls.sink.reload.unit",
		},
		{
			name: "unknown manifest key",
			doc: `
schema_version: 1
bogus_top_level: true
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`,
			wantRule: "top-level keys",
		},
		{
			name: "state absent without delete safety",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: absent
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`,
			wantRule: "delete safety",
		},

		// ---- v1.1 revision: reverse-proxy HTTP/HTTPS upstream (spec.md §67) ----

		{
			name: "reverse proxy upstream missing scheme",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream: {address: 10.0.0.5, port: 3000}
    tls: {mode: disabled}
`,
			wantRule: "route.upstream.scheme",
		},
		{
			name: "valid http upstream",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream: {scheme: http, address: 10.0.0.5, port: 3000}
    tls: {mode: disabled}
`,
		},
		{
			name: "valid https upstream verify=true",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream:
        scheme: https
        address: 10.0.0.5
        port: 8443
        tls: {verify: true, server_name: api.backend.internal}
    tls: {mode: disabled}
`,
		},
		{
			name: "valid https upstream verify=false",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream:
        scheme: https
        address: 10.0.0.5
        port: 8443
        tls: {verify: false}
    tls: {mode: disabled}
`,
		},
		{
			name: "https upstream missing tls.verify",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream: {scheme: https, address: 10.0.0.5, port: 8443}
    tls: {mode: disabled}
`,
			wantRule: "route.upstream.tls.verify",
		},
		{
			name: "http upstream with tls block",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream:
        scheme: http
        address: 10.0.0.5
        port: 3000
        tls: {verify: false}
    tls: {mode: disabled}
`,
			wantRule: "route.upstream.tls",
		},
		{
			name: "unknown upstream scheme",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream: {scheme: ftp, address: 10.0.0.5, port: 3000}
    tls: {mode: disabled}
`,
			wantRule: "route.upstream.scheme",
		},
		{
			name: "https upstream verify=true + explicit server_name",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream:
        scheme: https
        address: 10.0.0.5
        port: 8443
        tls: {verify: true, server_name: api.backend.internal}
    tls: {mode: disabled}
`,
		},
		{
			name: "https upstream verify=false + server_name",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream:
        scheme: https
        address: 10.0.0.5
        port: 8443
        tls: {verify: false, server_name: legacy01.internal}
    tls: {mode: disabled}
`,
		},
		{
			name: "https upstream verify=true + IP only + no SNI",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream: {scheme: https, address: 10.0.0.5, port: 8443, tls: {verify: true}}
    tls: {mode: disabled}
`,
			wantRule: "route.upstream.tls.server_name",
		},
		{
			name: "https upstream verify=false + IP only",
			doc: `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream: {scheme: https, address: 10.0.0.5, port: 8443, tls: {verify: false}}
    tls: {mode: disabled}
`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			v := ValidateInternalEndpointManifest(mustParseIEPManifest(t, tt.doc), InternalEndpointValidateOptions{})
			if tt.wantRule == "" {
				if len(v) != 0 {
					t.Fatalf("expected zero violations, got: %v", v)
				}
				return
			}
			if !contains(iepRuleNames(v), tt.wantRule) {
				t.Fatalf("expected a %q violation, got: %v", tt.wantRule, v)
			}
		})
	}
}

// ---- cases needing InternalEndpointValidateOptions ------------------------

func TestValidateInternalEndpointManifest_UnknownInventoryHost(t *testing.T) {
	doc := `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {inventory_host: ghost01}}
    tls: {mode: disabled}
`
	v := ValidateInternalEndpointManifest(mustParseIEPManifest(t, doc), InternalEndpointValidateOptions{
		Hostvars: map[string]map[string]any{"app01": {"ansible_host": "10.0.0.1"}},
	})
	if !contains(iepRuleNames(v), "inventory host") {
		t.Fatalf("expected an inventory host violation, got: %v", v)
	}
}

func TestValidateInternalEndpointManifest_ProxyHostWithoutReverseProxyRole(t *testing.T) {
	doc := `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: web01}
      upstream: {scheme: http, address: 10.0.0.5, port: 3000}
    tls: {mode: disabled}
`
	v := ValidateInternalEndpointManifest(mustParseIEPManifest(t, doc), InternalEndpointValidateOptions{
		Hostvars:          map[string]map[string]any{"web01": {"ansible_host": "10.0.0.10"}},
		ReverseProxyHosts: map[string]bool{"other-proxy": true},
	})
	if !contains(iepRuleNames(v), "route.proxy role") {
		t.Fatalf("expected a route.proxy role violation, got: %v", v)
	}
}

func TestValidateInternalEndpointManifest_TLSOwnerNotEnrolled(t *testing.T) {
	doc := `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {inventory_host: app01}}
    tls:
      mode: freeipa
      sink:
        cert_file: /etc/app/tls/server.crt
        key_file: /etc/app/tls/server.key
        reload: {mode: systemd, unit: app.service}
`
	v := ValidateInternalEndpointManifest(mustParseIEPManifest(t, doc), InternalEndpointValidateOptions{
		EnrolledHosts: map[string]bool{"other-host": true},
	})
	if !contains(iepRuleNames(v), "tls owner enrollment") {
		t.Fatalf("expected a tls owner enrollment violation, got: %v", v)
	}
}

func TestValidateInternalEndpointManifest_AuthoritativeDNSZone(t *testing.T) {
	doc := `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`
	v := ValidateInternalEndpointManifest(mustParseIEPManifest(t, doc), InternalEndpointValidateOptions{
		FreeIPADNSZones: map[string]FreeIPAZoneInfo{
			"linker.internal.": {Present: true, RecordsMode: "authoritative"},
		},
	})
	if !contains(iepRuleNames(v), "dns.zone records_mode") {
		t.Fatalf("expected a dns.zone records_mode violation, got: %v", v)
	}
}

func TestValidateInternalEndpointManifest_ValidZoneApexWithRealZoneCrossCheck(t *testing.T) {
	doc := `
schema_version: 1
endpoints:
  - fqdn: linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`
	v := ValidateInternalEndpointManifest(mustParseIEPManifest(t, doc), InternalEndpointValidateOptions{
		FreeIPADNSZones: map[string]FreeIPAZoneInfo{
			"linker.internal.": {Present: true, RecordsMode: "merge"},
		},
	})
	if len(v) != 0 {
		t.Fatalf("expected zero violations for a zone-apex endpoint against a real merge-mode zone, got: %v", v)
	}
}

func TestValidateInternalEndpointManifest_DNSOwnershipCollision(t *testing.T) {
	doc := `
schema_version: 1
endpoints:
  - fqdn: taken.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`
	v := ValidateInternalEndpointManifest(mustParseIEPManifest(t, doc), InternalEndpointValidateOptions{
		FreeIPADNSZones: map[string]FreeIPAZoneInfo{
			"linker.internal.": {
				Present:        true,
				RecordsMode:    "merge",
				ExplicitOwners: map[string]bool{"taken|a": true},
			},
		},
	})
	if !contains(iepRuleNames(v), "dns ownership conflict") {
		t.Fatalf("expected a dns ownership conflict violation, got: %v", v)
	}
}

func TestValidateInternalEndpointManifest_MissingLedgerDelete(t *testing.T) {
	doc := `
schema_version: 1
safety: {allow_endpoint_delete: true}
endpoints:
  - fqdn: gone.linker.internal
    state: absent
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`
	v := ValidateInternalEndpointManifest(mustParseIEPManifest(t, doc), InternalEndpointValidateOptions{
		LedgerFQDNs: map[string]bool{"other.linker.internal": true},
	})
	if !contains(iepRuleNames(v), "ledger presence") {
		t.Fatalf("expected a ledger presence violation, got: %v", v)
	}
}

func TestValidateInternalEndpointManifest_RouteOwnerMigrationFailsClosed(t *testing.T) {
	doc := `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {inventory_host: app02}}
    tls: {mode: disabled}
`
	v := ValidateInternalEndpointManifest(mustParseIEPManifest(t, doc), InternalEndpointValidateOptions{
		PreviousRoutes: map[string]PreviousRoute{
			"foo.linker.internal": {Mode: "direct", TargetHost: "app01"},
		},
	})
	if !contains(iepRuleNames(v), "route owner migration") {
		t.Fatalf("expected a route owner migration violation, got: %v", v)
	}
}

func TestValidateInternalEndpointManifest_InventoryIPChangeIsNotRouteOwnerMigration(t *testing.T) {
	doc := `
schema_version: 1
endpoints:
  - fqdn: foo.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {inventory_host: app01}}
    tls: {mode: disabled}
`
	v := ValidateInternalEndpointManifest(mustParseIEPManifest(t, doc), InternalEndpointValidateOptions{
		PreviousRoutes: map[string]PreviousRoute{
			// Same inventory_host as the current manifest — spec.md §30 says an
			// IP change alone (DHCP/ansible_host drift) must NOT be flagged.
			"foo.linker.internal": {Mode: "direct", TargetHost: "app01"},
		},
	})
	if contains(iepRuleNames(v), "route owner migration") {
		t.Fatalf("an unchanged inventory_host must not be flagged as a route-owner migration, got: %v", v)
	}
}
