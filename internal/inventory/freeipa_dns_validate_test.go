package inventory

import (
	"strconv"
	"testing"
)

func dnsRuleNames(violations []DNSViolation) []string {
	out := make([]string, len(violations))
	for i, v := range violations {
		out[i] = v.Rule
	}
	return out
}

func TestValidateDNSManifest_MinimalValidManifestPassesClean(t *testing.T) {
	root := mustParseDNSManifest(t, minimalValidDNSManifest)
	v := ValidateDNSManifest(root, DNSValidateOptions{Hostvars: nexusHostvars("192.168.122.81")})
	if len(v) != 0 {
		t.Fatalf("expected minimalValidDNSManifest to pass clean, got: %v", v)
	}
}

func TestValidateDNSManifest_MissingSchemaVersion(t *testing.T) {
	v := ValidateDNSManifest(mustParseDNSManifest(t, "freeipa: {}\ndns: {}\n"), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "schema_version") {
		t.Fatalf("expected a schema_version violation, got: %v", v)
	}
}

func TestValidateDNSManifest_UnknownTopLevelKey(t *testing.T) {
	doc := minimalValidDNSManifest + "\nbogus_top_level: true\n"
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "top-level keys") {
		t.Fatalf("expected a top-level keys violation, got: %v", v)
	}
}

func TestValidateDNSManifest_ForbidsAdminPasswordUnderFreeIPA(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal, admin: {password: hunter2}}
dns: {zones: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "freeipa keys") {
		t.Fatalf("expected a freeipa keys violation (admin.password forbidden), got: %v", v)
	}
}

func TestValidateDNSManifest_DuplicateZoneName(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  zones:
    - {name: example.com., records: []}
    - {name: EXAMPLE.COM, records: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "unique zone names") {
		t.Fatalf("expected a unique zone names violation, got: %v", v)
	}
}

func TestValidateDNSManifest_DuplicateRecordIdentity(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: grafana, type: A, values: [10.0.0.1]}
        - {name: grafana, type: A, values: [10.0.0.2]}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "unique record identity") {
		t.Fatalf("expected a unique record identity violation, got: %v", v)
	}
}

func TestValidateDNSManifest_InvalidZoneFQDN(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  zones:
    - {name: "not..valid", records: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "zone name") {
		t.Fatalf("expected a zone name violation, got: %v", v)
	}
}

func TestValidateDNSManifest_RootZoneForbidden(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  zones:
    - {name: ".", records: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "zone name") {
		t.Fatalf("expected a zone name violation for root zone, got: %v", v)
	}
}

func TestValidateDNSManifest_ReverseZonesForbidden(t *testing.T) {
	for _, name := range []string{"1.168.192.in-addr.arpa.", "1.0.0.0.ip6.arpa."} {
		doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  zones:
    - {name: "` + name + `", records: []}
`
		v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
		if !contains(dnsRuleNames(v), "zone name") {
			t.Fatalf("%s: expected a zone name violation, got: %v", name, v)
		}
	}
}

func TestValidateDNSManifest_InvalidIPv4Value(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: bad, type: A, values: ["not-an-ip"]}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "record value format") {
		t.Fatalf("expected a record value format violation, got: %v", v)
	}
}

func TestValidateDNSManifest_ARecordPointingToIPv6(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: bad, type: A, values: ["2001:db8::1"]}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "record value family") {
		t.Fatalf("expected a record value family violation (A -> IPv6), got: %v", v)
	}
}

func TestValidateDNSManifest_AAAARecordPointingToIPv4(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: bad, type: AAAA, values: ["10.0.0.1"]}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "record value family") {
		t.Fatalf("expected a record value family violation (AAAA -> IPv4), got: %v", v)
	}
}

func TestValidateDNSManifest_ValidAAAARecordPassesClean(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: v6, type: AAAA, values: ["2001:db8::1"]}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if len(v) != 0 {
		t.Fatalf("expected a valid AAAA record to pass clean, got: %v", v)
	}
}

func TestValidateDNSManifest_InvalidCNAMENotFQDN(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: www, type: CNAME, values: ["nexus.ipa.pilot.internal"]}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "cname value") {
		t.Fatalf("expected a cname value violation (missing trailing dot), got: %v", v)
	}
}

func TestValidateDNSManifest_CNAMEValueCannotBeIP(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: www, type: CNAME, values: ["10.0.0.1"]}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "cname value") {
		t.Fatalf("expected a cname value violation (IP not allowed), got: %v", v)
	}
}

func TestValidateDNSManifest_CNAMEAndARecordSameOwner(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: www, type: A, values: ["10.0.0.1"]}
        - {name: www, type: CNAME, values: ["nexus.ipa.pilot.internal."]}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "cname exclusivity") {
		t.Fatalf("expected a cname exclusivity violation, got: %v", v)
	}
}

func TestValidateDNSManifest_ApexCNAMEForbidden(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: "@", type: CNAME, values: ["nexus.ipa.pilot.internal."]}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "cname apex") {
		t.Fatalf("expected a cname apex violation, got: %v", v)
	}
}

func TestValidateDNSManifest_NonexistentInventoryHost(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: grafana, type: A, target: {inventory_host: does-not-exist}}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{Hostvars: nexusHostvars("192.168.122.81")})
	if !contains(dnsRuleNames(v), "target inventory host") {
		t.Fatalf("expected a target inventory host violation, got: %v", v)
	}
}

func TestValidateDNSManifest_InventoryHostMissingAnsibleHost(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - name: example.com.
      records:
        - {name: grafana, type: A, target: {inventory_host: nexus}}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{Hostvars: map[string]map[string]any{"nexus": {}}})
	if !contains(dnsRuleNames(v), "target ansible_host") {
		t.Fatalf("expected a target ansible_host violation, got: %v", v)
	}
}

func TestValidateDNSManifest_TTLOutOfRange(t *testing.T) {
	for _, ttl := range []int{10, 999999} {
		doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  zones:
    - name: example.com.
      records:
        - {name: grafana, type: A, ttl: ` + strconv.Itoa(ttl) + `, values: ["10.0.0.1"]}
`
		v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
		if !contains(dnsRuleNames(v), "record ttl") {
			t.Fatalf("ttl=%d: expected a record ttl violation, got: %v", ttl, v)
		}
	}
}

func TestValidateDNSManifest_UnconfirmedAuthoritativePrune(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  safety: {allow_authoritative_prune: false}
  zones:
    - {name: svc.example.com., records_mode: authoritative, records: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "authoritative prune safety") {
		t.Fatalf("expected an authoritative prune safety violation, got: %v", v)
	}
}

func TestValidateDNSManifest_ConfirmedAuthoritativePrunePassesThatGate(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  safety: {allow_authoritative_prune: true}
  zones:
    - {name: svc.example.com., records_mode: authoritative, records: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if contains(dnsRuleNames(v), "authoritative prune safety") {
		t.Fatalf("did not expect an authoritative prune safety violation, got: %v", v)
	}
}

func TestValidateDNSManifest_UnconfirmedZoneDelete(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  safety: {allow_zone_delete: false}
  zones:
    - {name: old-svc.example.com., state: absent, records: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{})
	if !contains(dnsRuleNames(v), "zone delete safety") {
		t.Fatalf("expected a zone delete safety violation, got: %v", v)
	}
}

func TestValidateDNSManifest_ProtectedZoneDeleteRejectedEvenWithSafetyFlags(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  safety: {allow_zone_delete: true}
  zones:
    - {name: ipa.pilot.internal., state: absent, records: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{ProtectedZones: []string{"ipa.pilot.internal."}})
	if !contains(dnsRuleNames(v), "protected zone delete") {
		t.Fatalf("expected a protected zone delete violation even with allow_zone_delete: true, got: %v", v)
	}
}

func TestValidateDNSManifest_ProtectedZoneAuthoritativePruneRejected(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  safety: {allow_authoritative_prune: true}
  zones:
    - {name: ipa.pilot.internal., records_mode: authoritative, records: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{ProtectedZones: []string{"ipa.pilot.internal."}})
	if !contains(dnsRuleNames(v), "protected zone prune") {
		t.Fatalf("expected a protected zone prune violation even with allow_authoritative_prune: true, got: %v", v)
	}
}

func TestValidateDNSManifest_UnacknowledgedSplitHorizon(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - {name: example.com., acknowledge_split_horizon: false, records: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{
		ShadowedZones: map[string]bool{"example.com.": true},
	})
	if !contains(dnsRuleNames(v), "split-horizon safety") {
		t.Fatalf("expected a split-horizon safety violation, got: %v", v)
	}
}

func TestValidateDNSManifest_AcknowledgedSplitHorizonPassesThatGate(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300}
  zones:
    - {name: example.com., acknowledge_split_horizon: true, records: []}
`
	v := ValidateDNSManifest(mustParseDNSManifest(t, doc), DNSValidateOptions{
		ShadowedZones: map[string]bool{"example.com.": true},
	})
	if contains(dnsRuleNames(v), "split-horizon safety") {
		t.Fatalf("did not expect a split-horizon safety violation, got: %v", v)
	}
}
