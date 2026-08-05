package cmd

import (
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestEditAutomationDriverDNSFlow_CreateManifestZoneAndRecords(t *testing.T) {
	dir := t.TempDir()
	writeDNSTestHostsFile(t, dir)
	path := dir + "/freeipa-dns.yaml"

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_dns_manifest", Domain: "ipa.pilot.internal", Realm: "IPA.PILOT.INTERNAL", Server: "ipa1.ipa.pilot.internal"},
			{Action: "create_dns_zone", Zone: "svc.pilot.internal."},
			{Action: "set_dns_zone_field", Zone: "svc.pilot.internal.", Field: "acknowledge_split_horizon", Value: "true"},
			{Action: "create_dns_record", Zone: "svc.pilot.internal.", RecordType: "A", RecordName: "grafana", TargetHost: "nexus"},
			{Action: "create_dns_record", Zone: "svc.pilot.internal.", RecordType: "CNAME", RecordName: "www", Values: []string{"nexus.svc.pilot.internal."}},
			{Action: "set_dns_record_field", Zone: "svc.pilot.internal.", RecordName: "grafana", RecordType: "A", Field: "ttl", Value: "120"},
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

	zone, found, err := inventory.DNSManifestZone(path, "svc.pilot.internal.")
	if err != nil {
		t.Fatalf("DNSManifestZone() error = %v", err)
	}
	if !found {
		t.Fatal("expected zone svc.pilot.internal. to exist")
	}
	if zone["acknowledge_split_horizon"] != true {
		t.Fatalf("acknowledge_split_horizon = %v, want true", zone["acknowledge_split_horizon"])
	}

	grafana, found, err := inventory.DNSManifestRecord(path, "svc.pilot.internal.", "grafana", "A")
	if err != nil {
		t.Fatalf("DNSManifestRecord(grafana,A) error = %v", err)
	}
	if !found {
		t.Fatal("expected record grafana/A to exist")
	}
	target, _ := grafana["target"].(map[string]any)
	if target == nil || target["inventory_host"] != "nexus" {
		t.Fatalf("target = %+v, want inventory_host=nexus", target)
	}
	if ttl, ok := grafana["ttl"].(int); !ok || ttl != 120 {
		t.Fatalf("ttl = %v (%T), want int 120", grafana["ttl"], grafana["ttl"])
	}

	www, found, err := inventory.DNSManifestRecord(path, "svc.pilot.internal.", "www", "CNAME")
	if err != nil {
		t.Fatalf("DNSManifestRecord(www,CNAME) error = %v", err)
	}
	if !found {
		t.Fatal("expected record www/CNAME to exist")
	}
	values, _ := www["values"].([]any)
	if len(values) != 1 || values[0] != "nexus.svc.pilot.internal." {
		t.Fatalf("values = %+v, want [nexus.svc.pilot.internal.]", values)
	}
}

func TestEditAutomationDriverDNSFlow_SwitchRecordValueSourceAndZoneState(t *testing.T) {
	dir := t.TempDir()
	writeDNSTestHostsFile(t, dir)
	path := dir + "/freeipa-dns.yaml"

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_dns_manifest", Domain: "ipa.pilot.internal", Realm: "IPA.PILOT.INTERNAL", Server: "ipa1.ipa.pilot.internal"},
			{Action: "create_dns_zone", Zone: "svc.pilot.internal."},
			{Action: "create_dns_record", Zone: "svc.pilot.internal.", RecordType: "A", RecordName: "grafana", TargetHost: "nexus"},
			{Action: "set_dns_record_values", Zone: "svc.pilot.internal.", RecordName: "grafana", RecordType: "A", Values: []string{"10.0.0.99"}},
			{Action: "create_dns_record", Zone: "svc.pilot.internal.", RecordType: "A", RecordName: "wazuh", Values: []string{"10.0.0.5"}},
			{Action: "set_dns_record_target_host", Zone: "svc.pilot.internal.", RecordName: "wazuh", RecordType: "A", TargetHost: "nexus"},
			{Action: "set_dns_record_field", Zone: "svc.pilot.internal.", RecordName: "grafana", RecordType: "A", Field: "state", Value: "absent"},
			// Zone-level state:absent requires dns.safety.allow_zone_delete:
			// true, which no TUI screen can set on this manifest — the same
			// gate a human using the interactive wizard would hit. This step
			// must navigate safely and leave the zone's state untouched
			// (asserted below), not error and not silently rewrite the file.
			{Action: "set_dns_zone_field", Zone: "svc.pilot.internal.", Field: "state", Value: "absent"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	grafana, _, err := inventory.DNSManifestRecord(path, "svc.pilot.internal.", "grafana", "A")
	if err != nil {
		t.Fatalf("DNSManifestRecord(grafana,A) error = %v", err)
	}
	if _, hasTarget := grafana["target"]; hasTarget {
		t.Fatalf("expected target to be cleared after set_dns_record_values, got %+v", grafana["target"])
	}
	values, _ := grafana["values"].([]any)
	if len(values) != 1 || values[0] != "10.0.0.99" {
		t.Fatalf("values = %+v, want [10.0.0.99]", values)
	}
	if grafana["state"] != "absent" {
		t.Fatalf("state = %v, want absent", grafana["state"])
	}

	wazuh, _, err := inventory.DNSManifestRecord(path, "svc.pilot.internal.", "wazuh", "A")
	if err != nil {
		t.Fatalf("DNSManifestRecord(wazuh,A) error = %v", err)
	}
	if _, hasValues := wazuh["values"]; hasValues {
		t.Fatalf("expected values to be cleared after set_dns_record_target_host, got %+v", wazuh["values"])
	}
	target, _ := wazuh["target"].(map[string]any)
	if target == nil || target["inventory_host"] != "nexus" {
		t.Fatalf("target = %+v, want inventory_host=nexus", target)
	}

	// The zone delete safety gate (checkDNSSafetyFlags) rejected the write —
	// state must still read "present", matching what a human hitting the
	// same violation banner in the interactive wizard would see.
	zone, _, err := inventory.DNSManifestZone(path, "svc.pilot.internal.")
	if err != nil {
		t.Fatalf("DNSManifestZone() error = %v", err)
	}
	if zone["state"] != "present" {
		t.Fatalf("zone state = %v, want present (state:absent must be safely rejected without dns.safety.allow_zone_delete)", zone["state"])
	}
}

func TestEditAutomationDriverDNSFlow_ValidationRejectsBadInput(t *testing.T) {
	if err := validateCreateDNSManifest(editAction{Action: "create_dns_manifest"}); err == nil {
		t.Fatal("expected validateCreateDNSManifest to reject missing domain/realm/server")
	}
	if err := validateDNSZoneNameOnly("create_dns_zone")(editAction{Action: "create_dns_zone"}); err == nil {
		t.Fatal("expected validateDNSZoneNameOnly to reject an empty zone")
	}
	cases := []editAction{
		{Action: "set_dns_zone_field", Zone: "z", Field: "not_a_field", Value: "y"},
		{Action: "set_dns_zone_field", Zone: "z", Field: "state", Value: "not-a-state"},
		{Action: "set_dns_zone_field", Zone: "z", Field: "records_mode", Value: "not-a-mode"},
		{Action: "set_dns_zone_field", Zone: "z", Field: "acknowledge_split_horizon", Value: "yes"},
	}
	for _, step := range cases {
		if err := validateSetDNSZoneField(step); err == nil {
			t.Fatalf("expected validateSetDNSZoneField to reject %+v", step)
		}
	}
	if err := validateCreateDNSRecord(editAction{Action: "create_dns_record", Zone: "z", RecordName: "n", RecordType: "A"}); err == nil {
		t.Fatal("expected validateCreateDNSRecord to reject neither target_host nor values set")
	}
	if err := validateCreateDNSRecord(editAction{Action: "create_dns_record", Zone: "z", RecordName: "n", RecordType: "A", TargetHost: "h", Values: []string{"v"}}); err == nil {
		t.Fatal("expected validateCreateDNSRecord to reject both target_host and values set")
	}
	if err := validateCreateDNSRecord(editAction{Action: "create_dns_record", Zone: "z", RecordName: "n", RecordType: "CNAME", TargetHost: "h"}); err == nil {
		t.Fatal("expected validateCreateDNSRecord to reject CNAME with target_host")
	}
	if err := validateCreateDNSRecord(editAction{Action: "create_dns_record", Zone: "z", RecordName: "n", RecordType: "CNAME"}); err == nil {
		t.Fatal("expected validateCreateDNSRecord to reject CNAME without values")
	}
	if err := validateSetDNSRecordTargetHost(editAction{Action: "set_dns_record_target_host", Zone: "z", RecordName: "n", RecordType: "CNAME", TargetHost: "h"}); err == nil {
		t.Fatal("expected validateSetDNSRecordTargetHost to reject CNAME")
	}
	if err := validateSetDNSRecordField(editAction{Action: "set_dns_record_field", Zone: "z", RecordName: "n", RecordType: "A", Field: "ttl", Value: "not-a-number"}); err == nil {
		t.Fatal("expected validateSetDNSRecordField to reject a non-numeric ttl")
	}
}
