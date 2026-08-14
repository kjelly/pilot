package inventory

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func decodeIEPManifest(t *testing.T, doc string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return root
}

const iepValidDirectManifest = `
schema_version: 1
endpoints:
  - fqdn: aaa.xxx.linker.internal
    state: present
    dns:
      zone: linker.internal.
    route:
      mode: direct
      target:
        inventory_host: app01
    tls:
      mode: freeipa
      port: 8443
      sink:
        cert_file: /etc/example/tls/server.crt
        key_file: /etc/example/tls/server.key
        key_group: example
        key_mode: "0640"
        reload:
          mode: systemd
          unit: example.service
`

func TestNormalizeInternalEndpointManifest_DirectResolvesNestedOwnerAndCertOwner(t *testing.T) {
	root := decodeIEPManifest(t, iepValidDirectManifest)
	hostvars := map[string]map[string]any{"app01": {"ansible_host": "10.20.30.40"}}

	got := NormalizeInternalEndpointManifest(root, hostvars)
	if len(got.Endpoints) != 1 {
		t.Fatalf("endpoints = %d, want 1", len(got.Endpoints))
	}
	e := got.Endpoints[0]
	if e.FQDN != "aaa.xxx.linker.internal" {
		t.Errorf("FQDN = %q", e.FQDN)
	}
	if e.DNSZone != "linker.internal." {
		t.Errorf("DNSZone = %q, want linker.internal.", e.DNSZone)
	}
	if e.DNSOwner != "aaa.xxx" {
		t.Errorf("DNSOwner = %q, want aaa.xxx", e.DNSOwner)
	}
	if e.RouteMode != "direct" || e.RouteOwnerHost != "app01" || e.RouteOwnerIP != "10.20.30.40" {
		t.Errorf("route = %+v", e)
	}
	if e.DNSRecordType != "A" || e.DNSValue != "10.20.30.40" {
		t.Errorf("DNS record = %s %s", e.DNSRecordType, e.DNSValue)
	}
	if e.ServicePrincipal != "HTTP/aaa.xxx.linker.internal" {
		t.Errorf("ServicePrincipal = %q", e.ServicePrincipal)
	}
	if e.CertificateOwner != "app01" {
		t.Errorf("CertificateOwner = %q, want app01 (spec.md §15)", e.CertificateOwner)
	}
	if e.CertFile != "/etc/example/tls/server.crt" || e.KeyFile != "/etc/example/tls/server.key" {
		t.Errorf("sink files = %s %s", e.CertFile, e.KeyFile)
	}
	if e.KeyOwner != "root" || e.KeyGroup != "example" || e.KeyMode != "0640" {
		t.Errorf("sink perms = owner=%s group=%s mode=%s", e.KeyOwner, e.KeyGroup, e.KeyMode)
	}
	if e.ReloadUnit != "example.service" {
		t.Errorf("ReloadUnit = %q", e.ReloadUnit)
	}
	if e.TLSPort != 8443 {
		t.Errorf("TLSPort = %d, want 8443", e.TLSPort)
	}
}

func TestNormalizeInternalEndpointManifest_ZoneApexOwnerIsAt(t *testing.T) {
	root := decodeIEPManifest(t, `
schema_version: 1
endpoints:
  - fqdn: linker.internal
    state: present
    dns:
      zone: linker.internal.
    route:
      mode: direct
      target:
        address: 10.0.0.1
    tls:
      mode: disabled
`)
	got := NormalizeInternalEndpointManifest(root, nil)
	if got.Endpoints[0].DNSOwner != "@" {
		t.Errorf("DNSOwner = %q, want @ at the zone apex (spec.md §10.3)", got.Endpoints[0].DNSOwner)
	}
	if got.Endpoints[0].RouteOwnerIP != "10.0.0.1" || got.Endpoints[0].RouteOwnerHost != "" {
		t.Errorf("literal address route = host=%q ip=%q", got.Endpoints[0].RouteOwnerHost, got.Endpoints[0].RouteOwnerIP)
	}
	if got.Endpoints[0].ServicePrincipal != "" || got.Endpoints[0].CertificateOwner != "" {
		t.Errorf("tls.mode=disabled must not derive a certificate owner or service principal, got %+v", got.Endpoints[0])
	}
}

func TestNormalizeInternalEndpointManifest_ReverseProxyDNSPointsAtProxyNotUpstream(t *testing.T) {
	root := decodeIEPManifest(t, `
schema_version: 1
endpoints:
  - fqdn: grafana.linker.internal
    state: present
    dns:
      zone: linker.internal.
    route:
      mode: reverse_proxy
      proxy:
        provider: nginx
        inventory_host: web01
      upstream:
        scheme: https
        inventory_host: grafana01
        port: 3000
        tls:
          verify: false
          server_name: grafana01.internal
    tls:
      mode: freeipa
`)
	hostvars := map[string]map[string]any{
		"web01":     {"ansible_host": "10.0.0.10"},
		"grafana01": {"ansible_host": "10.0.0.20"},
	}
	got := NormalizeInternalEndpointManifest(root, hostvars)
	e := got.Endpoints[0]
	if e.DNSValue != "10.0.0.10" {
		t.Errorf("DNS must point at the proxy host's IP, got %q (spec.md §11.4)", e.DNSValue)
	}
	if e.DNSValue == "10.0.0.20" {
		t.Fatal("DNS must never point at the upstream's IP")
	}
	if e.CertificateOwner != "web01" {
		t.Errorf("CertificateOwner = %q, want web01 (proxy host owns the frontend TLS socket)", e.CertificateOwner)
	}
	if e.UpstreamScheme != "https" || e.UpstreamHost != "grafana01" || e.UpstreamIP != "10.0.0.20" || e.UpstreamPort != 3000 {
		t.Errorf("upstream = %+v", e)
	}
	if e.UpstreamTLSVerify {
		t.Error("UpstreamTLSVerify = true, want false")
	}
	if e.UpstreamTLSServerName != "grafana01.internal" {
		t.Errorf("UpstreamTLSServerName = %q", e.UpstreamTLSServerName)
	}
}

func TestNormalizeInternalEndpointManifest_IPv6TargetProducesAAAA(t *testing.T) {
	root := decodeIEPManifest(t, `
schema_version: 1
endpoints:
  - fqdn: v6.linker.internal
    state: present
    dns:
      zone: linker.internal.
    route:
      mode: direct
      target:
        address: "2001:db8::1"
    tls:
      mode: disabled
`)
	got := NormalizeInternalEndpointManifest(root, nil)
	if got.Endpoints[0].DNSRecordType != "AAAA" {
		t.Errorf("DNSRecordType = %q, want AAAA", got.Endpoints[0].DNSRecordType)
	}
}

func TestNormalizeInternalEndpointManifest_ReResolvesAfterInventoryIPChange(t *testing.T) {
	root := decodeIEPManifest(t, iepValidDirectManifest)
	before := NormalizeInternalEndpointManifest(root, map[string]map[string]any{"app01": {"ansible_host": "10.0.0.1"}})
	after := NormalizeInternalEndpointManifest(root, map[string]map[string]any{"app01": {"ansible_host": "10.0.0.2"}})
	if before.Endpoints[0].DNSValue == after.Endpoints[0].DNSValue {
		t.Fatal("expected DNSValue to track ansible_host across an inventory IP change (spec.md §30)")
	}
	if before.Endpoints[0].RouteOwnerHost != after.Endpoints[0].RouteOwnerHost {
		t.Error("inventory_host identity must stay the same across an IP change — only the resolved IP should move")
	}
}

func TestNormalizeInternalEndpointManifest_SortsByFQDN(t *testing.T) {
	root := decodeIEPManifest(t, `
schema_version: 1
endpoints:
  - fqdn: zzz.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
  - fqdn: aaa.linker.internal
    state: present
    dns: {zone: linker.internal.}
    route: {mode: direct, target: {address: 10.0.0.2}}
    tls: {mode: disabled}
`)
	got := NormalizeInternalEndpointManifest(root, nil)
	if got.Endpoints[0].FQDN != "aaa.linker.internal" || got.Endpoints[1].FQDN != "zzz.linker.internal" {
		t.Errorf("endpoints not sorted by FQDN: %v", []string{got.Endpoints[0].FQDN, got.Endpoints[1].FQDN})
	}
}

func TestNormalizeInternalEndpointManifest_Deterministic(t *testing.T) {
	root := decodeIEPManifest(t, iepValidDirectManifest)
	hostvars := map[string]map[string]any{"app01": {"ansible_host": "10.20.30.40"}}
	a := NormalizeInternalEndpointManifest(root, hostvars)
	b := NormalizeInternalEndpointManifest(root, hostvars)
	if a.Endpoints[0] != b.Endpoints[0] {
		t.Errorf("normalize is not deterministic: %+v vs %+v", a.Endpoints[0], b.Endpoints[0])
	}
}
