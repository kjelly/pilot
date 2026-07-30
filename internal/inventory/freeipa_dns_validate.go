package inventory

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// DNSViolation is one structural or semantic problem found in a
// freeipa-dns manifest. Rule names cross-reference the corresponding
// "Gate: ..." assert task in playbooks/apply/freeipa-dns-apply.yml, so a
// manifest that passes ValidateDNSManifest should also pass those gates —
// see docs/specs/freeipa-dns.md §5-§8.2 for the authoritative rules this
// replicates ahead of any kinit/mutation.
type DNSViolation struct {
	Rule   string
	Detail string
}

func (v DNSViolation) String() string {
	return fmt.Sprintf("[%s] %s", v.Rule, v.Detail)
}

// DNSValidateOptions supplies the external facts ValidateDNSManifest needs
// beyond the manifest text itself. All fields are optional; a nil/empty
// value simply skips the gate that needs it (e.g. unit tests exercising
// pure schema shape don't need Hostvars).
type DNSValidateOptions struct {
	// Hostvars maps inventory hostname -> its vars (only "ansible_host" is
	// read). Required to validate target.inventory_host references.
	Hostvars map[string]map[string]any

	// ProtectedZones lists normalized (lowercase, trailing-dot) zone names
	// that must never be deleted or authoritative-pruned, regardless of
	// manifest safety flags — the FreeIPA identity domain plus any
	// installer-protected zone.
	ProtectedZones []string

	// ShadowedZones maps normalized zone name -> true when a live upstream
	// DNS lookup (docs/specs/freeipa-dns.md §7.1's `dig ... SOA`, run by the
	// apply playbook, not this package) confirmed the zone already exists
	// externally. Nil/empty skips the split-horizon gate entirely, since
	// that detection requires live network access this package doesn't have.
	ShadowedZones map[string]bool
}

var (
	dnsZoneNameRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.$`)
	dnsRecordNameRe = regexp.MustCompile(`^@$|^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

	dnsKnownTopLevelKeys   = []string{"schema_version", "freeipa", "dns"}
	dnsKnownFreeIPAKeys    = []string{"domain", "realm", "server"}
	dnsKnownDNSKeys        = []string{"defaults", "safety", "zones"}
	dnsKnownDefaultsKeys   = []string{"ttl", "records_mode"}
	dnsKnownSafetyKeys     = []string{"allow_shadow_existing_zone", "allow_authoritative_prune", "allow_zone_delete"}
	dnsKnownZoneKeys       = []string{"name", "state", "records_mode", "acknowledge_split_horizon", "delegation", "records"}
	dnsKnownDelegationKeys = []string{"verify", "expected_nameservers"}
	dnsKnownRecordKeys     = []string{"name", "type", "state", "ttl", "values", "target"}
	dnsKnownTargetKeys     = []string{"inventory_host"}
)

// ValidateDNSManifestFile reads and validates the manifest at path.
func ValidateDNSManifestFile(path string, opts DNSValidateOptions) ([]DNSViolation, error) {
	root, err := LoadDNSManifest(path)
	if err != nil {
		return nil, err
	}
	return ValidateDNSManifest(root, opts), nil
}

// ValidateDNSManifest runs every structural/semantic gate from
// docs/specs/freeipa-dns.md §5-§8.2 against an already-parsed manifest
// document (a plain map[string]any, e.g. from LoadDNSManifest).
func ValidateDNSManifest(root map[string]any, opts DNSValidateOptions) []DNSViolation {
	var v []DNSViolation
	v = append(v, checkDNSSchemaVersion(root)...)
	v = append(v, checkDNSTopLevelKeys(root)...)

	dns := mapField(root, "dns")
	defaults := mapField(dns, "defaults")
	safety := mapField(dns, "safety")
	zones := listField(dns, "zones")

	v = append(v, checkDNSUniqueZones(zones)...)
	for _, rawZone := range zones {
		zone := asMap(rawZone)
		v = append(v, checkDNSZoneShape(zone)...)
		v = append(v, checkDNSUniqueRecords(zone)...)
		v = append(v, checkDNSRecordShape(zone, defaults)...)
		v = append(v, checkDNSCNAMEExclusivity(zone)...)
		v = append(v, checkDNSTargetResolution(zone, opts.Hostvars)...)
		v = append(v, checkDNSSafetyFlags(zone, safety)...)
		v = append(v, checkDNSProtectedZone(zone, opts.ProtectedZones)...)
		v = append(v, checkDNSSplitHorizon(zone, opts.ShadowedZones)...)
	}
	return v
}

// ---- Gate: schema_version -------------------------------------------------

func checkDNSSchemaVersion(root map[string]any) []DNSViolation {
	v, ok := root["schema_version"]
	if !ok {
		return []DNSViolation{{Rule: "schema_version", Detail: "schema_version is required (must be 1)"}}
	}
	n, ok := toInt(v)
	if !ok || n != 1 {
		return []DNSViolation{{Rule: "schema_version", Detail: fmt.Sprintf("schema_version must be 1, got %v", v)}}
	}
	return nil
}

// ---- Gate: only known top-level and nested keys ---------------------------

func checkDNSTopLevelKeys(root map[string]any) []DNSViolation {
	var out []DNSViolation
	if unk := unknownKeys(root, dnsKnownTopLevelKeys); len(unk) > 0 {
		out = append(out, DNSViolation{Rule: "top-level keys", Detail: fmt.Sprintf("unknown top-level key(s): %s", strings.Join(unk, ", "))})
	}
	freeipa := mapField(root, "freeipa")
	if unk := unknownKeys(freeipa, dnsKnownFreeIPAKeys); len(unk) > 0 {
		out = append(out, DNSViolation{Rule: "freeipa keys", Detail: fmt.Sprintf("unknown freeipa field(s): %s (admin passwords are forbidden in this manifest)", strings.Join(unk, ", "))})
	}
	for _, key := range []string{"domain", "realm", "server"} {
		if stringField(freeipa, key) == "" {
			out = append(out, DNSViolation{Rule: "freeipa keys", Detail: fmt.Sprintf("freeipa.%s is required", key)})
		}
	}

	dns := mapField(root, "dns")
	if unk := unknownKeys(dns, dnsKnownDNSKeys); len(unk) > 0 {
		out = append(out, DNSViolation{Rule: "dns keys", Detail: fmt.Sprintf("unknown dns field(s): %s", strings.Join(unk, ", "))})
	}
	defaults := mapField(dns, "defaults")
	if unk := unknownKeys(defaults, dnsKnownDefaultsKeys); len(unk) > 0 {
		out = append(out, DNSViolation{Rule: "dns.defaults keys", Detail: fmt.Sprintf("unknown dns.defaults field(s): %s", strings.Join(unk, ", "))})
	}
	safety := mapField(dns, "safety")
	if unk := unknownKeys(safety, dnsKnownSafetyKeys); len(unk) > 0 {
		out = append(out, DNSViolation{Rule: "dns.safety keys", Detail: fmt.Sprintf("unknown dns.safety field(s): %s", strings.Join(unk, ", "))})
	}
	for _, rawZone := range listField(dns, "zones") {
		zone := asMap(rawZone)
		label := labelOf(zone)
		if unk := unknownKeys(zone, dnsKnownZoneKeys); len(unk) > 0 {
			out = append(out, DNSViolation{Rule: "zone keys", Detail: fmt.Sprintf("zone %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}
		if unk := unknownKeys(mapField(zone, "delegation"), dnsKnownDelegationKeys); len(unk) > 0 {
			out = append(out, DNSViolation{Rule: "zone delegation keys", Detail: fmt.Sprintf("zone %q: unknown delegation field(s) %s", label, strings.Join(unk, ", "))})
		}
		for _, rawRecord := range listField(zone, "records") {
			record := asMap(rawRecord)
			rlabel := labelOf(record)
			if unk := unknownKeys(record, dnsKnownRecordKeys); len(unk) > 0 {
				out = append(out, DNSViolation{Rule: "record keys", Detail: fmt.Sprintf("zone %q record %q: unknown field(s) %s", label, rlabel, strings.Join(unk, ", "))})
			}
			if unk := unknownKeys(mapField(record, "target"), dnsKnownTargetKeys); len(unk) > 0 {
				out = append(out, DNSViolation{Rule: "record target keys", Detail: fmt.Sprintf("zone %q record %q: unknown target field(s) %s", label, rlabel, strings.Join(unk, ", "))})
			}
		}
	}
	return out
}

// ---- Gate: zone identity is unique and FQDN-shaped -------------------------

func checkDNSUniqueZones(zones []any) []DNSViolation {
	names := make([]string, 0, len(zones))
	for _, rawZone := range zones {
		names = append(names, normalizeZoneName(stringField(asMap(rawZone), "name")))
	}
	if dupes := findDuplicates(names); len(dupes) > 0 {
		return []DNSViolation{{Rule: "unique zone names", Detail: fmt.Sprintf("duplicate zone name(s): %s", strings.Join(dupes, ", "))}}
	}
	return nil
}

func checkDNSZoneShape(zone map[string]any) []DNSViolation {
	var out []DNSViolation
	label := labelOf(zone)
	raw := stringField(zone, "name")
	name := normalizeZoneName(raw)

	switch {
	case strings.TrimSpace(raw) == "":
		out = append(out, DNSViolation{Rule: "zone name", Detail: "zone name is required"})
	case name == ".":
		out = append(out, DNSViolation{Rule: "zone name", Detail: "root zone \".\" is forbidden"})
	case strings.HasSuffix(name, "in-addr.arpa."):
		out = append(out, DNSViolation{Rule: "zone name", Detail: fmt.Sprintf("zone %q: in-addr.arpa. reverse zones are forbidden in this version", label)})
	case strings.HasSuffix(name, "ip6.arpa."):
		out = append(out, DNSViolation{Rule: "zone name", Detail: fmt.Sprintf("zone %q: ip6.arpa. reverse zones are forbidden in this version", label)})
	case !dnsZoneNameRe.MatchString(name):
		out = append(out, DNSViolation{Rule: "zone name", Detail: fmt.Sprintf("zone %q: name must be a valid absolute FQDN", label)})
	}

	state := stateOrDefault(zone, "present")
	if state != "present" && state != "absent" {
		out = append(out, DNSViolation{Rule: "zone state", Detail: fmt.Sprintf("zone %q: state %q must be present/absent", label, state)})
	}

	mode := stringField(zone, "records_mode")
	if mode != "" && mode != "merge" && mode != "authoritative" {
		out = append(out, DNSViolation{Rule: "zone records_mode", Detail: fmt.Sprintf("zone %q: records_mode %q must be merge/authoritative", label, mode)})
	}

	delegation := mapField(zone, "delegation")
	if boolFieldDefault(delegation, "verify", false) && len(stringListField(delegation, "expected_nameservers")) == 0 {
		out = append(out, DNSViolation{Rule: "zone delegation", Detail: fmt.Sprintf("zone %q: delegation.verify requires expected_nameservers", label)})
	}
	return out
}

// ---- Gate: record identity is unique within its zone -----------------------

func checkDNSUniqueRecords(zone map[string]any) []DNSViolation {
	label := labelOf(zone)
	var keys []string
	for _, rawRecord := range listField(zone, "records") {
		record := asMap(rawRecord)
		keys = append(keys, strings.ToLower(stringField(record, "name"))+"|"+strings.ToUpper(stringField(record, "type")))
	}
	if dupes := findDuplicates(keys); len(dupes) > 0 {
		return []DNSViolation{{Rule: "unique record identity", Detail: fmt.Sprintf("zone %q: duplicate (name,type) pair(s): %s", label, strings.Join(dupes, ", "))}}
	}
	return nil
}

// ---- Gate: record shape (name/type/state/ttl/values-vs-target) -----------

func checkDNSRecordShape(zone, defaults map[string]any) []DNSViolation {
	var out []DNSViolation
	zoneLabel := labelOf(zone)
	for _, rawRecord := range listField(zone, "records") {
		record := asMap(rawRecord)
		label := labelOf(record)
		who := fmt.Sprintf("zone %q record %q", zoneLabel, label)

		name := stringField(record, "name")
		if !dnsRecordNameRe.MatchString(strings.ToLower(strings.TrimSpace(name))) {
			out = append(out, DNSViolation{Rule: "record name", Detail: fmt.Sprintf("%s: name must be a zone-relative owner or \"@\"", who)})
		}

		rtype := strings.ToUpper(stringField(record, "type"))
		if rtype != "A" && rtype != "AAAA" && rtype != "CNAME" {
			out = append(out, DNSViolation{Rule: "record type", Detail: fmt.Sprintf("%s: type %q must be A/AAAA/CNAME", who, rtype)})
		}

		state := stateOrDefault(record, "present")
		if state != "present" && state != "absent" {
			out = append(out, DNSViolation{Rule: "record state", Detail: fmt.Sprintf("%s: state %q must be present/absent", who, state)})
		}

		if ttlRaw, has := record["ttl"]; has {
			ttl, ok := toInt(ttlRaw)
			if !ok || ttl < 60 || ttl > 86400 {
				out = append(out, DNSViolation{Rule: "record ttl", Detail: fmt.Sprintf("%s: ttl %v must be an integer between 60 and 86400", who, ttlRaw)})
			}
		} else if _, has := defaults["ttl"]; !has {
			out = append(out, DNSViolation{Rule: "record ttl", Detail: fmt.Sprintf("%s: no ttl set and dns.defaults.ttl is missing", who)})
		}

		values := stringListField(record, "values")
		target := mapField(record, "target")
		hasValues := len(values) > 0
		hasTarget := stringField(target, "inventory_host") != ""
		switch {
		case hasValues && hasTarget:
			out = append(out, DNSViolation{Rule: "record values-vs-target", Detail: fmt.Sprintf("%s: values and target are mutually exclusive", who)})
		case state == "present" && !hasValues && !hasTarget:
			out = append(out, DNSViolation{Rule: "record values-vs-target", Detail: fmt.Sprintf("%s: state present requires values or target", who)})
		}

		if rtype == "CNAME" {
			out = append(out, checkDNSCNAMERecord(zone, record, who, values, hasTarget)...)
		} else if hasValues {
			out = append(out, checkDNSIPFamily(who, rtype, values)...)
		}
	}
	return out
}

func checkDNSCNAMERecord(zone, record map[string]any, who string, values []string, hasTarget bool) []DNSViolation {
	var out []DNSViolation
	name := strings.ToLower(strings.TrimSpace(stringField(record, "name")))
	if name == "@" {
		out = append(out, DNSViolation{Rule: "cname apex", Detail: fmt.Sprintf("%s: CNAME cannot be declared at the zone apex \"@\"", who)})
	}
	if hasTarget {
		out = append(out, DNSViolation{Rule: "cname target", Detail: fmt.Sprintf("%s: CNAME must use values, not target.inventory_host (a CNAME value is a hostname, not an IP)", who)})
	}
	if len(values) != 1 {
		out = append(out, DNSViolation{Rule: "cname values", Detail: fmt.Sprintf("%s: CNAME requires exactly one value", who)})
		return out
	}
	value := strings.TrimSpace(values[0])
	zoneName := normalizeZoneName(stringField(zone, "name"))
	self := name + "." + zoneName
	switch {
	case !strings.HasSuffix(value, "."):
		out = append(out, DNSViolation{Rule: "cname value", Detail: fmt.Sprintf("%s: CNAME value %q must be a fully-qualified name ending in \".\"", who, value)})
	case net.ParseIP(strings.TrimSuffix(value, ".")) != nil:
		out = append(out, DNSViolation{Rule: "cname value", Detail: fmt.Sprintf("%s: CNAME value %q must not be an IP address", who, value)})
	case strings.EqualFold(value, self):
		out = append(out, DNSViolation{Rule: "cname value", Detail: fmt.Sprintf("%s: CNAME value cannot equal its own owner name", who)})
	}
	return out
}

func checkDNSIPFamily(who, rtype string, values []string) []DNSViolation {
	var out []DNSViolation
	for _, raw := range values {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			out = append(out, DNSViolation{Rule: "record value format", Detail: fmt.Sprintf("%s: value %q is not a valid IP address", who, raw)})
			continue
		}
		isV4 := ip.To4() != nil
		if rtype == "A" && !isV4 {
			out = append(out, DNSViolation{Rule: "record value family", Detail: fmt.Sprintf("%s: A record value %q must be IPv4", who, raw)})
		}
		if rtype == "AAAA" && isV4 {
			out = append(out, DNSViolation{Rule: "record value family", Detail: fmt.Sprintf("%s: AAAA record value %q must be IPv6", who, raw)})
		}
	}
	return out
}

// ---- Gate: same owner cannot mix CNAME with A/AAAA -------------------------

func checkDNSCNAMEExclusivity(zone map[string]any) []DNSViolation {
	label := labelOf(zone)
	hasCNAME := map[string]bool{}
	hasAddress := map[string]bool{}
	for _, rawRecord := range listField(zone, "records") {
		record := asMap(rawRecord)
		name := strings.ToLower(strings.TrimSpace(stringField(record, "name")))
		switch strings.ToUpper(stringField(record, "type")) {
		case "CNAME":
			hasCNAME[name] = true
		case "A", "AAAA":
			hasAddress[name] = true
		}
	}
	var out []DNSViolation
	var owners []string
	for name := range hasCNAME {
		if hasAddress[name] {
			owners = append(owners, name)
		}
	}
	if len(owners) > 0 {
		sort.Strings(owners)
		out = append(out, DNSViolation{Rule: "cname exclusivity", Detail: fmt.Sprintf("zone %q: owner(s) %s declare both CNAME and A/AAAA", label, strings.Join(owners, ", "))})
	}
	return out
}

// ---- Gate: inventory target resolution -------------------------------------

func checkDNSTargetResolution(zone map[string]any, hostvars map[string]map[string]any) []DNSViolation {
	if hostvars == nil {
		return nil
	}
	var out []DNSViolation
	zoneLabel := labelOf(zone)
	for _, rawRecord := range listField(zone, "records") {
		record := asMap(rawRecord)
		target := mapField(record, "target")
		host := stringField(target, "inventory_host")
		if host == "" {
			continue
		}
		who := fmt.Sprintf("zone %q record %q", zoneLabel, labelOf(record))
		hv, ok := hostvars[host]
		if !ok {
			out = append(out, DNSViolation{Rule: "target inventory host", Detail: fmt.Sprintf("%s: target.inventory_host %q does not exist in inventory", who, host)})
			continue
		}
		ansibleHost, _ := hv["ansible_host"].(string)
		if strings.TrimSpace(ansibleHost) == "" {
			out = append(out, DNSViolation{Rule: "target ansible_host", Detail: fmt.Sprintf("%s: inventory host %q has no ansible_host", who, host)})
			continue
		}
		out = append(out, checkDNSIPFamily(who, strings.ToUpper(stringField(record, "type")), []string{ansibleHost})...)
	}
	return out
}

// ---- Gate: authoritative prune / zone delete require explicit safety flags -

func checkDNSSafetyFlags(zone, safety map[string]any) []DNSViolation {
	var out []DNSViolation
	label := labelOf(zone)
	mode := recordsModeOrDefault(zone, map[string]any{})
	if mode == "authoritative" && !boolFieldDefault(safety, "allow_authoritative_prune", false) {
		out = append(out, DNSViolation{Rule: "authoritative prune safety", Detail: fmt.Sprintf("zone %q: records_mode: authoritative requires dns.safety.allow_authoritative_prune: true", label)})
	}
	if stateOrDefault(zone, "present") == "absent" && !boolFieldDefault(safety, "allow_zone_delete", false) {
		out = append(out, DNSViolation{Rule: "zone delete safety", Detail: fmt.Sprintf("zone %q: state: absent requires dns.safety.allow_zone_delete: true", label)})
	}
	return out
}

// ---- Gate: protected zones can never be deleted or authoritative-pruned ----

func checkDNSProtectedZone(zone map[string]any, protected []string) []DNSViolation {
	if len(protected) == 0 {
		return nil
	}
	name := normalizeZoneName(stringField(zone, "name"))
	isProtected := false
	for _, p := range protected {
		if normalizeZoneName(p) == name {
			isProtected = true
			break
		}
	}
	if !isProtected {
		return nil
	}
	var out []DNSViolation
	if stateOrDefault(zone, "present") == "absent" {
		out = append(out, DNSViolation{Rule: "protected zone delete", Detail: fmt.Sprintf("zone %q is protected and cannot be deleted", name)})
	}
	if recordsModeOrDefault(zone, map[string]any{}) == "authoritative" {
		out = append(out, DNSViolation{Rule: "protected zone prune", Detail: fmt.Sprintf("zone %q is protected and cannot use records_mode: authoritative", name)})
	}
	return out
}

// ---- Gate: unacknowledged split-horizon zone creation ----------------------

func checkDNSSplitHorizon(zone map[string]any, shadowed map[string]bool) []DNSViolation {
	if len(shadowed) == 0 {
		return nil
	}
	name := normalizeZoneName(stringField(zone, "name"))
	if !shadowed[name] {
		return nil
	}
	if boolFieldDefault(zone, "acknowledge_split_horizon", false) {
		return nil
	}
	return []DNSViolation{{Rule: "split-horizon safety", Detail: fmt.Sprintf("zone %q already exists upstream; set acknowledge_split_horizon: true to confirm the split-horizon zone deliberately", name)}}
}
