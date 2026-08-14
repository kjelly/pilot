package cmd

import (
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func writeInternalEndpointTestHostsFile(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, dir+"/hosts.yml", `hosts:
  app01:
    ansible_host: 192.168.122.81
    ansible_user: ubuntu
    roles: []
  lb01:
    ansible_host: 192.168.122.82
    ansible_user: ubuntu
    roles: [reverse-proxy]
`)
}

// TestEditAutomationDriverInternalEndpointFlow_CreateManifestAndDirectEndpoint
// drives create_internal_endpoint_manifest, create_internal_endpoint,
// set_internal_endpoint_dns, set_internal_endpoint_tls_freeipa and
// set_internal_endpoint_tls_sink end to end through the real TUI (see
// edit_automation_driver_internal_endpoint.go's own doc comment: these
// replay scripted keystrokes against editRouterModel, not a mock
// execution path), then asserts on the resulting manifest file.
func TestEditAutomationDriverInternalEndpointFlow_CreateManifestAndDirectEndpoint(t *testing.T) {
	dir := t.TempDir()
	writeInternalEndpointTestHostsFile(t, dir)
	path := dir + "/internal-endpoints.yaml"

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_internal_endpoint_manifest"},
			{Action: "create_internal_endpoint", FQDN: "direct.svc.pilot.internal", Zone: "svc.pilot.internal.", TargetHost: "app01"},
			{Action: "set_internal_endpoint_dns", FQDN: "direct.svc.pilot.internal", Zone: "svc.pilot.internal.", DNSTTL: "600"},
			// tls.sink must be populated *before* tls.mode flips to freeipa:
			// checkIEPDirectTLSSink (spec.md §22) requires a direct-route
			// endpoint's sink to already be complete the instant tls.mode
			// becomes freeipa, so this order is the only one that validates.
			{Action: "set_internal_endpoint_tls_sink", FQDN: "direct.svc.pilot.internal",
				CertFile: "/etc/pilot/tls/direct.crt", KeyFile: "/etc/pilot/tls/direct.key",
				KeyOwner: "nginx", KeyGroup: "nginx", KeyMode: "0640", ReloadUnit: "nginx.service"},
			{Action: "set_internal_endpoint_tls_freeipa", FQDN: "direct.svc.pilot.internal", TLSPort: "8443"},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	fields, found, err := inventory.InternalEndpointManifestEndpoint(path, "direct.svc.pilot.internal")
	if err != nil {
		t.Fatalf("InternalEndpointManifestEndpoint() error = %v", err)
	}
	if !found {
		t.Fatal("expected endpoint direct.svc.pilot.internal to exist")
	}

	dns := iepMapField(fields, "dns")
	if iepStringValue(dns, "zone") != "svc.pilot.internal." || iepIntValue(dns, "ttl") != "600" {
		t.Fatalf("dns = %+v, want zone=svc.pilot.internal. ttl=600", dns)
	}

	route := iepMapField(fields, "route")
	if iepStringValue(route, "mode") != "direct" {
		t.Fatalf("route.mode = %q, want direct", iepStringValue(route, "mode"))
	}
	target := iepMapField(route, "target")
	if iepStringValue(target, "inventory_host") != "app01" {
		t.Fatalf("route.target.inventory_host = %q, want app01", iepStringValue(target, "inventory_host"))
	}

	tls := iepMapField(fields, "tls")
	if iepStringValue(tls, "mode") != "freeipa" || iepIntValue(tls, "port") != "8443" {
		t.Fatalf("tls = %+v, want mode=freeipa port=8443", tls)
	}
	sink := iepMapField(tls, "sink")
	if iepStringValue(sink, "cert_file") != "/etc/pilot/tls/direct.crt" || iepStringValue(sink, "key_file") != "/etc/pilot/tls/direct.key" {
		t.Fatalf("tls.sink = %+v, want cert_file/key_file set", sink)
	}
	if iepStringValue(sink, "key_owner") != "nginx" || iepStringValue(sink, "key_group") != "nginx" || iepStringValue(sink, "key_mode") != "0640" {
		t.Fatalf("tls.sink ownership = %+v, want nginx:nginx 0640", sink)
	}
	reload := iepMapField(sink, "reload")
	if iepStringValue(reload, "unit") != "nginx.service" {
		t.Fatalf("tls.sink.reload = %+v, want unit=nginx.service", reload)
	}
}

// TestEditAutomationDriverInternalEndpointFlow_ReverseProxyRouteAndState drives
// set_internal_endpoint_route_proxy (https upstream, tls_verify+sni) and
// set_internal_endpoint_state (present -> absent). The state write is
// expected to be safely rejected — checkIEPDeleteSafety requires the
// manifest's safety.allow_endpoint_delete: true, which no TUI screen can
// set (same as freeipa-dns's zone-delete gate, see
// TestEditAutomationDriverDNSFlow_SwitchRecordValueSourceAndZoneState) —
// so state must still read "present" afterward.
func TestEditAutomationDriverInternalEndpointFlow_ReverseProxyRouteAndState(t *testing.T) {
	dir := t.TempDir()
	writeInternalEndpointTestHostsFile(t, dir)
	path := dir + "/internal-endpoints.yaml"

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_internal_endpoint_manifest"},
			{Action: "create_internal_endpoint", FQDN: "proxy.svc.pilot.internal", Zone: "svc.pilot.internal.", TargetHost: "app01"},
			{Action: "set_internal_endpoint_route_proxy", FQDN: "proxy.svc.pilot.internal",
				ProxyHost: "lb01", UpstreamScheme: "https", UpstreamHost: "app01",
				UpstreamPort: "8443", UpstreamTLSVerify: "true", UpstreamSNI: "backend.internal"},
			{Action: "set_internal_endpoint_state", FQDN: "proxy.svc.pilot.internal", Value: "absent"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	fields, found, err := inventory.InternalEndpointManifestEndpoint(path, "proxy.svc.pilot.internal")
	if err != nil {
		t.Fatalf("InternalEndpointManifestEndpoint() error = %v", err)
	}
	if !found {
		t.Fatal("expected endpoint proxy.svc.pilot.internal to exist")
	}
	if iepStringValue(fields, "state") != "present" {
		t.Fatalf("state = %q, want present (state:absent must be safely rejected without safety.allow_endpoint_delete)", iepStringValue(fields, "state"))
	}

	route := iepMapField(fields, "route")
	if iepStringValue(route, "mode") != "reverse_proxy" {
		t.Fatalf("route.mode = %q, want reverse_proxy", iepStringValue(route, "mode"))
	}
	proxy := iepMapField(route, "proxy")
	if iepStringValue(proxy, "inventory_host") != "lb01" {
		t.Fatalf("route.proxy.inventory_host = %q, want lb01", iepStringValue(proxy, "inventory_host"))
	}
	upstream := iepMapField(route, "upstream")
	if iepStringValue(upstream, "scheme") != "https" || iepStringValue(upstream, "inventory_host") != "app01" || iepIntValue(upstream, "port") != "8443" {
		t.Fatalf("route.upstream = %+v, want scheme=https inventory_host=app01 port=8443", upstream)
	}
	utls := iepMapField(upstream, "tls")
	if verify, _ := utls["verify"].(bool); !verify {
		t.Fatalf("route.upstream.tls.verify = %v, want true", utls["verify"])
	}
	if iepStringValue(utls, "server_name") != "backend.internal" {
		t.Fatalf("route.upstream.tls.server_name = %q, want backend.internal", iepStringValue(utls, "server_name"))
	}
}

// TestEditAutomationDriverInternalEndpointFlow_RouteDirectByAddressAndTLSDisabled
// drives set_internal_endpoint_route_direct with a literal target_address
// (no inventory host) and set_internal_endpoint_tls_disabled.
func TestEditAutomationDriverInternalEndpointFlow_RouteDirectByAddressAndTLSDisabled(t *testing.T) {
	dir := t.TempDir()
	writeInternalEndpointTestHostsFile(t, dir)
	path := dir + "/internal-endpoints.yaml"

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_internal_endpoint_manifest"},
			{Action: "create_internal_endpoint", FQDN: "literal.svc.pilot.internal", Zone: "svc.pilot.internal.", TargetHost: "app01"},
			{Action: "set_internal_endpoint_route_direct", FQDN: "literal.svc.pilot.internal", TargetAddress: "10.0.0.42"},
			{Action: "set_internal_endpoint_tls_disabled", FQDN: "literal.svc.pilot.internal"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	fields, found, err := inventory.InternalEndpointManifestEndpoint(path, "literal.svc.pilot.internal")
	if err != nil {
		t.Fatalf("InternalEndpointManifestEndpoint() error = %v", err)
	}
	if !found {
		t.Fatal("expected endpoint literal.svc.pilot.internal to exist")
	}
	target := iepMapField(iepMapField(fields, "route"), "target")
	if iepStringValue(target, "address") != "10.0.0.42" {
		t.Fatalf("route.target.address = %q, want 10.0.0.42", iepStringValue(target, "address"))
	}
	if _, hasHost := target["inventory_host"]; hasHost {
		t.Fatalf("expected route.target.inventory_host to be cleared, got %+v", target)
	}
	if iepStringValue(iepMapField(fields, "tls"), "mode") != "disabled" {
		t.Fatalf("tls.mode = %q, want disabled", iepStringValue(iepMapField(fields, "tls"), "mode"))
	}
}

func TestEditAutomationDriverInternalEndpointFlow_ValidationRejectsBadInput(t *testing.T) {
	if err := validateCreateInternalEndpoint(editAction{Action: "create_internal_endpoint"}); err == nil {
		t.Fatal("expected validateCreateInternalEndpoint to reject missing fqdn/zone/target_host")
	}
	if err := validateFQDNOnly("set_internal_endpoint_tls_disabled")(editAction{}); err == nil {
		t.Fatal("expected validateFQDNOnly to reject an empty fqdn")
	}
	if err := validateSetInternalEndpointState(editAction{FQDN: "f", Value: "not-a-state"}); err == nil {
		t.Fatal("expected validateSetInternalEndpointState to reject an invalid value")
	}
	if err := validateSetInternalEndpointDNS(editAction{FQDN: "f", Zone: "z", DNSTTL: "not-a-number"}); err == nil {
		t.Fatal("expected validateSetInternalEndpointDNS to reject a non-numeric dns_ttl")
	}
	if err := validateSetInternalEndpointRouteDirect(editAction{FQDN: "f"}); err == nil {
		t.Fatal("expected validateSetInternalEndpointRouteDirect to reject neither target_host nor target_address set")
	}
	if err := validateSetInternalEndpointRouteDirect(editAction{FQDN: "f", TargetHost: "h", TargetAddress: "1.2.3.4"}); err == nil {
		t.Fatal("expected validateSetInternalEndpointRouteDirect to reject both target_host and target_address set")
	}
	if err := validateSetInternalEndpointRouteProxy(editAction{FQDN: "f", ProxyHost: "p", UpstreamScheme: "http", UpstreamPort: "80", UpstreamHost: "h", UpstreamTLSVerify: "true"}); err == nil {
		t.Fatal("expected validateSetInternalEndpointRouteProxy to reject upstream_tls_verify set with an http upstream_scheme")
	}
	if err := validateSetInternalEndpointRouteProxy(editAction{FQDN: "f", ProxyHost: "p", UpstreamScheme: "https", UpstreamPort: "80", UpstreamHost: "h"}); err == nil {
		t.Fatal("expected validateSetInternalEndpointRouteProxy to reject a missing upstream_tls_verify with an https upstream_scheme")
	}
	if err := validateSetInternalEndpointRouteProxy(editAction{FQDN: "f", ProxyHost: "p", UpstreamScheme: "http", UpstreamPort: "not-a-port", UpstreamHost: "h"}); err == nil {
		t.Fatal("expected validateSetInternalEndpointRouteProxy to reject a non-numeric upstream_port")
	}
	if err := validateSetInternalEndpointTLSFreeIPA(editAction{FQDN: "f", TLSPort: "not-a-port"}); err == nil {
		t.Fatal("expected validateSetInternalEndpointTLSFreeIPA to reject a non-numeric tls_port")
	}
	if err := validateSetInternalEndpointTLSSink(editAction{FQDN: "f", CertFile: "c", KeyFile: "k"}); err == nil {
		t.Fatal("expected validateSetInternalEndpointTLSSink to reject a missing reload_unit")
	}
}
