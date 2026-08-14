package inventory

import (
	"fmt"
	"net"
	"path"
	"regexp"
	"strings"
)

// InternalEndpointViolation is one structural or semantic problem found in
// an internal-endpoints manifest. Rule names cross-reference the
// corresponding preflight gate in playbooks/apply/internal-endpoint-apply.yml
// once Phase 6-8 (spec.md §63) fill those in, so a manifest that passes
// ValidateInternalEndpointManifest should also pass those gates — see
// spec.md §10-§22, §30-§32 for the authoritative rules this replicates
// ahead of any live mutation (spec.md §36 "Validator Must Mirror Apply
// Gates").
type InternalEndpointViolation struct {
	Rule   string
	Detail string
}

func (v InternalEndpointViolation) String() string {
	return fmt.Sprintf("[%s] %s", v.Rule, v.Detail)
}

// FreeIPAZoneInfo is the slice of a freeipa-dns.yaml zone's effective state
// that internal-endpoint validation needs to enforce spec.md §11's DNS
// ownership rules. Callers build this from the *already validated and
// normalized* freeipa-dns manifest (LoadDNSManifest + NormalizeDNSManifest,
// or a fixture in tests) — this package never reads that file itself, to
// stay decoupled from freeipa-dns's raw schema shape.
type FreeIPAZoneInfo struct {
	// Present mirrors the zone's `state: present` in freeipa-dns.yaml.
	Present bool
	// RecordsMode is the zone's effective records_mode (merge|authoritative).
	RecordsMode string
	// ExplicitOwners is the set of (owner, record type) pairs freeipa-dns.yaml
	// already manages explicitly at this zone, keyed "<lowercase owner>|<lowercase type>"
	// (owner "@" for the apex). Used to detect ownership collisions (spec.md
	// §11.3) — internal-endpoint only ever writes A/AAAA (spec.md §6.6).
	ExplicitOwners map[string]bool
}

// PreviousRoute is a prior reconcile's recorded route shape for one
// endpoint, used to detect an in-place route-owner migration (spec.md §30).
// Callers build this from the ownership ledger (spec.md §29), not from live
// host state.
type PreviousRoute struct {
	Mode          string // direct|reverse_proxy
	TargetHost    string // route.target.inventory_host, direct mode only
	TargetAddress string // route.target.address, direct mode only
	ProxyHost     string // route.proxy.inventory_host, reverse_proxy mode only
}

// InternalEndpointValidateOptions supplies the external facts
// ValidateInternalEndpointManifest needs beyond the manifest text itself.
// Every field is optional; a nil value simply skips the gate that needs it
// (e.g. unit tests exercising pure schema shape need none of these) — same
// convention as DNSValidateOptions.
type InternalEndpointValidateOptions struct {
	// Hostvars maps inventory hostname -> its vars (only "ansible_host" is
	// read). Required to validate inventory_host references.
	Hostvars map[string]map[string]any

	// ReverseProxyHosts maps inventory hostname -> true when that host
	// carries the reverse-proxy role (spec.md §6.2). Required to enforce
	// that route.proxy.inventory_host actually runs nginx.
	ReverseProxyHosts map[string]bool

	// EnrolledHosts maps inventory hostname -> true when live preflight has
	// confirmed that host completed FreeIPA enrollment (spec.md §16). This
	// package never performs that preflight itself (Phase 2 does not touch
	// live hosts) — callers populate it from a live check elsewhere.
	EnrolledHosts map[string]bool

	// FreeIPADNSZones maps normalized zone name (lowercase, trailing dot) ->
	// its effective state in freeipa-dns.yaml (spec.md §11).
	FreeIPADNSZones map[string]FreeIPAZoneInfo

	// LedgerFQDNs maps normalized fqdn -> true when the ownership ledger
	// (spec.md §29) already has an entry for it. Required to enforce
	// spec.md §32's "missing ledger entry" fail-closed delete gate.
	LedgerFQDNs map[string]bool

	// PreviousRoutes maps normalized fqdn -> its previously reconciled route
	// shape, from the ownership ledger. Required to enforce spec.md §30's
	// route-owner-migration fail-closed gate.
	PreviousRoutes map[string]PreviousRoute
}

var (
	iepFQDNLabelRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	iepOctalModeRe   = regexp.MustCompile(`^[0-7]{3,4}$`)
	iepSystemdUnitRe = regexp.MustCompile(`^[A-Za-z0-9@._-]+\.(service|socket|timer|path|mount|target)$`)

	iepKnownTopLevelKeys    = []string{"schema_version", "defaults", "safety", "endpoints"}
	iepKnownDefaultsKeys    = []string{"dns"}
	iepKnownDefaultsDNSKeys = []string{"ttl"}
	iepKnownSafetyKeys      = []string{"allow_endpoint_delete"}
	iepKnownEndpointKeys    = []string{"fqdn", "state", "dns", "route", "tls"}
	iepKnownEndpointDNSKeys = []string{"zone", "ttl"}
	iepKnownRouteKeys       = []string{"mode", "target", "proxy", "upstream"}
	iepKnownTargetKeys      = []string{"inventory_host", "address"}
	iepKnownProxyKeys       = []string{"provider", "inventory_host"}
	iepKnownUpstreamKeys    = []string{"scheme", "inventory_host", "address", "port", "tls"}
	iepKnownUpstreamTLSKeys = []string{"verify", "server_name"}
	iepKnownTLSKeys         = []string{"mode", "port", "sink"}
	iepKnownSinkKeys        = []string{"cert_file", "key_file", "key_owner", "key_group", "key_mode", "reload"}
	iepKnownReloadKeys      = []string{"mode", "unit"}
)

// ValidateInternalEndpointManifestFile reads and validates the manifest at path.
func ValidateInternalEndpointManifestFile(path string, opts InternalEndpointValidateOptions) ([]InternalEndpointViolation, error) {
	root, err := LoadInternalEndpointManifest(path)
	if err != nil {
		return nil, err
	}
	return ValidateInternalEndpointManifest(root, opts), nil
}

// ValidateInternalEndpointManifest runs every structural/semantic gate from
// spec.md §10-§22 and §30-§32 against an already-parsed manifest document (a
// plain map[string]any, e.g. from LoadInternalEndpointManifest).
func ValidateInternalEndpointManifest(root map[string]any, opts InternalEndpointValidateOptions) []InternalEndpointViolation {
	var v []InternalEndpointViolation
	v = append(v, checkIEPSchemaVersion(root)...)
	v = append(v, checkIEPTopLevelKeys(root)...)

	endpoints := listField(root, "endpoints")
	v = append(v, checkIEPUniqueFQDNs(endpoints)...)
	for _, raw := range endpoints {
		e := asMap(raw)
		v = append(v, checkIEPFQDNShape(e)...)
		v = append(v, checkIEPDNSZoneShape(e, opts.FreeIPADNSZones)...)
		v = append(v, checkIEPDNSOwnershipCollision(e, opts.FreeIPADNSZones)...)
		v = append(v, checkIEPRouteShape(e)...)
		v = append(v, checkIEPRouteHostResolution(e, opts.Hostvars, opts.ReverseProxyHosts)...)
		v = append(v, checkIEPTLSShape(e)...)
		v = append(v, checkIEPTLSOwnerEnrollment(e, opts.EnrolledHosts)...)
		v = append(v, checkIEPDirectTLSSink(e)...)
		v = append(v, checkIEPDeleteSafety(root, e)...)
		v = append(v, checkIEPMissingLedgerDelete(e, opts.LedgerFQDNs)...)
		v = append(v, checkIEPRouteOwnerMigration(e, opts.PreviousRoutes)...)
	}
	return v
}

// ---- Gate: schema_version --------------------------------------------------

func checkIEPSchemaVersion(root map[string]any) []InternalEndpointViolation {
	raw, ok := root["schema_version"]
	if !ok {
		return []InternalEndpointViolation{{Rule: "schema_version", Detail: "schema_version is required (must be 1)"}}
	}
	n, ok := toInt(raw)
	if !ok || n != 1 {
		return []InternalEndpointViolation{{Rule: "schema_version", Detail: fmt.Sprintf("schema_version must be 1, got %v", raw)}}
	}
	return nil
}

// ---- Gate: only known top-level and nested keys (spec.md §10.1) -----------

func checkIEPTopLevelKeys(root map[string]any) []InternalEndpointViolation {
	var out []InternalEndpointViolation
	if unk := unknownKeys(root, iepKnownTopLevelKeys); len(unk) > 0 {
		out = append(out, InternalEndpointViolation{Rule: "top-level keys", Detail: fmt.Sprintf("unknown top-level key(s): %s", strings.Join(unk, ", "))})
	}

	defaults := mapField(root, "defaults")
	if unk := unknownKeys(defaults, iepKnownDefaultsKeys); len(unk) > 0 {
		out = append(out, InternalEndpointViolation{Rule: "defaults keys", Detail: fmt.Sprintf("unknown defaults field(s): %s", strings.Join(unk, ", "))})
	}
	if unk := unknownKeys(mapField(defaults, "dns"), iepKnownDefaultsDNSKeys); len(unk) > 0 {
		out = append(out, InternalEndpointViolation{Rule: "defaults.dns keys", Detail: fmt.Sprintf("unknown defaults.dns field(s): %s", strings.Join(unk, ", "))})
	}

	if unk := unknownKeys(mapField(root, "safety"), iepKnownSafetyKeys); len(unk) > 0 {
		out = append(out, InternalEndpointViolation{Rule: "safety keys", Detail: fmt.Sprintf("unknown safety field(s): %s", strings.Join(unk, ", "))})
	}

	for _, raw := range listField(root, "endpoints") {
		e := asMap(raw)
		ref := formatEndpointRef(e)
		if unk := unknownKeys(e, iepKnownEndpointKeys); len(unk) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "endpoint keys", Detail: fmt.Sprintf("endpoint %q: unknown field(s) %s", ref, strings.Join(unk, ", "))})
		}
		if unk := unknownKeys(mapField(e, "dns"), iepKnownEndpointDNSKeys); len(unk) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "endpoint dns keys", Detail: fmt.Sprintf("endpoint %q: unknown dns field(s) %s", ref, strings.Join(unk, ", "))})
		}

		route := mapField(e, "route")
		if unk := unknownKeys(route, iepKnownRouteKeys); len(unk) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "route keys", Detail: fmt.Sprintf("endpoint %q: unknown route field(s) %s", ref, strings.Join(unk, ", "))})
		}
		if unk := unknownKeys(mapField(route, "target"), iepKnownTargetKeys); len(unk) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "route.target keys", Detail: fmt.Sprintf("endpoint %q: unknown route.target field(s) %s", ref, strings.Join(unk, ", "))})
		}
		if unk := unknownKeys(mapField(route, "proxy"), iepKnownProxyKeys); len(unk) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "route.proxy keys", Detail: fmt.Sprintf("endpoint %q: unknown route.proxy field(s) %s", ref, strings.Join(unk, ", "))})
		}
		upstream := mapField(route, "upstream")
		if unk := unknownKeys(upstream, iepKnownUpstreamKeys); len(unk) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "route.upstream keys", Detail: fmt.Sprintf("endpoint %q: unknown route.upstream field(s) %s", ref, strings.Join(unk, ", "))})
		}
		if unk := unknownKeys(mapField(upstream, "tls"), iepKnownUpstreamTLSKeys); len(unk) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "route.upstream.tls keys", Detail: fmt.Sprintf("endpoint %q: unknown route.upstream.tls field(s) %s", ref, strings.Join(unk, ", "))})
		}

		tls := mapField(e, "tls")
		if unk := unknownKeys(tls, iepKnownTLSKeys); len(unk) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "tls keys", Detail: fmt.Sprintf("endpoint %q: unknown tls field(s) %s", ref, strings.Join(unk, ", "))})
		}
		sink := mapField(tls, "sink")
		if unk := unknownKeys(sink, iepKnownSinkKeys); len(unk) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "tls.sink keys", Detail: fmt.Sprintf("endpoint %q: unknown tls.sink field(s) %s", ref, strings.Join(unk, ", "))})
		}
		if unk := unknownKeys(mapField(sink, "reload"), iepKnownReloadKeys); len(unk) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "tls.sink.reload keys", Detail: fmt.Sprintf("endpoint %q: unknown tls.sink.reload field(s) %s", ref, strings.Join(unk, ", "))})
		}
	}
	return out
}

// ---- Gate: fqdn identity is unique (spec.md §10.2) -------------------------

func checkIEPUniqueFQDNs(endpoints []any) []InternalEndpointViolation {
	names := make([]string, 0, len(endpoints))
	for _, raw := range endpoints {
		names = append(names, normalizeFQDN(stringField(asMap(raw), "fqdn")))
	}
	if dupes := findDuplicates(names); len(dupes) > 0 {
		return []InternalEndpointViolation{{Rule: "unique fqdn", Detail: fmt.Sprintf("duplicate canonical fqdn(s): %s", strings.Join(dupes, ", "))}}
	}
	return nil
}

// ---- Gate: fqdn shape (spec.md §10.2) ---------------------------------------

func checkIEPFQDNShape(e map[string]any) []InternalEndpointViolation {
	ref := formatEndpointRef(e)
	raw := strings.TrimSpace(stringField(e, "fqdn"))
	if raw == "" {
		return []InternalEndpointViolation{{Rule: "fqdn", Detail: fmt.Sprintf("endpoint %q: fqdn is required", ref)}}
	}
	candidate := strings.TrimSuffix(strings.ToLower(raw), ".")

	switch {
	case strings.Contains(candidate, "://"):
		return []InternalEndpointViolation{{Rule: "fqdn shape", Detail: fmt.Sprintf("endpoint %q: fqdn must not include a URL scheme", ref)}}
	case strings.Contains(candidate, ":"):
		return []InternalEndpointViolation{{Rule: "fqdn shape", Detail: fmt.Sprintf("endpoint %q: fqdn must not include a port", ref)}}
	case net.ParseIP(candidate) != nil:
		return []InternalEndpointViolation{{Rule: "fqdn shape", Detail: fmt.Sprintf("endpoint %q: fqdn must not be an IP literal", ref)}}
	case strings.Contains(candidate, "*"):
		return []InternalEndpointViolation{{Rule: "fqdn shape", Detail: fmt.Sprintf("endpoint %q: wildcard fqdn is not supported in v1", ref)}}
	case len(candidate) > 253:
		return []InternalEndpointViolation{{Rule: "fqdn shape", Detail: fmt.Sprintf("endpoint %q: fqdn exceeds 253 characters", ref)}}
	}
	for _, label := range strings.Split(candidate, ".") {
		if !iepFQDNLabelRe.MatchString(label) {
			return []InternalEndpointViolation{{Rule: "fqdn shape", Detail: fmt.Sprintf("endpoint %q: label %q is not a valid DNS label", ref, label)}}
		}
	}
	return nil
}

// ---- Gate: dns.zone shape and ownership (spec.md §10.3, §11.1, §11.2) ------

func checkIEPDNSZoneShape(e map[string]any, zones map[string]FreeIPAZoneInfo) []InternalEndpointViolation {
	ref := formatEndpointRef(e)
	dns := mapField(e, "dns")
	rawZone := stringField(dns, "zone")
	if strings.TrimSpace(rawZone) == "" {
		return []InternalEndpointViolation{{Rule: "dns.zone", Detail: fmt.Sprintf("endpoint %q: dns.zone is required", ref)}}
	}
	zone := normalizeZoneName(rawZone)
	fqdn := normalizeFQDN(stringField(e, "fqdn"))

	var out []InternalEndpointViolation
	if relativeOwner(fqdn, zone) == "" {
		out = append(out, InternalEndpointViolation{Rule: "dns.zone", Detail: fmt.Sprintf("endpoint %q: fqdn is not the zone apex or a descendant of dns.zone %q", ref, zone)})
	}
	if zones == nil {
		return out
	}
	info, ok := zones[zone]
	if !ok || !info.Present {
		out = append(out, InternalEndpointViolation{Rule: "dns.zone existence", Detail: fmt.Sprintf("endpoint %q: dns.zone %q is not declared present in the freeipa-dns manifest", ref, zone)})
		return out
	}
	if info.RecordsMode != "merge" {
		out = append(out, InternalEndpointViolation{Rule: "dns.zone records_mode", Detail: fmt.Sprintf("endpoint %q: dns.zone %q must be records_mode merge, got %q", ref, zone, info.RecordsMode)})
	}
	return out
}

// ---- Gate: DNS ownership collision (spec.md §11.3) -------------------------

func checkIEPDNSOwnershipCollision(e map[string]any, zones map[string]FreeIPAZoneInfo) []InternalEndpointViolation {
	if zones == nil {
		return nil
	}
	dns := mapField(e, "dns")
	zone := normalizeZoneName(stringField(dns, "zone"))
	info, ok := zones[zone]
	if !ok || info.ExplicitOwners == nil {
		return nil
	}
	fqdn := normalizeFQDN(stringField(e, "fqdn"))
	owner := relativeOwner(fqdn, zone)
	if owner == "" {
		return nil
	}
	// internal-endpoint v1 only ever writes A/AAAA (spec.md §6.6).
	for _, rtype := range []string{"a", "aaaa"} {
		if info.ExplicitOwners[strings.ToLower(owner)+"|"+rtype] {
			return []InternalEndpointViolation{{Rule: "dns ownership conflict", Detail: fmt.Sprintf("endpoint %q: (%s, %s, %s) is already explicitly managed by freeipa-dns.yaml", formatEndpointRef(e), zone, owner, strings.ToUpper(rtype))}}
		}
	}
	return nil
}

// ---- Gate: route shape (spec.md §12) ---------------------------------------

func checkIEPRouteShape(e map[string]any) []InternalEndpointViolation {
	ref := formatEndpointRef(e)
	route := mapField(e, "route")
	switch mode := stringField(route, "mode"); mode {
	case "direct":
		return checkIEPDirectTarget(ref, mapField(route, "target"))
	case "reverse_proxy":
		var out []InternalEndpointViolation
		out = append(out, checkIEPProxyTarget(ref, mapField(route, "proxy"))...)
		out = append(out, checkIEPUpstreamShape(ref, mapField(route, "upstream"))...)
		return out
	case "":
		return []InternalEndpointViolation{{Rule: "route.mode", Detail: fmt.Sprintf("endpoint %q: route.mode is required", ref)}}
	default:
		return []InternalEndpointViolation{{Rule: "route.mode", Detail: fmt.Sprintf("endpoint %q: route.mode %q must be direct or reverse_proxy", ref, mode)}}
	}
}

func checkIEPDirectTarget(ref string, target map[string]any) []InternalEndpointViolation {
	host := stringField(target, "inventory_host")
	address := stringField(target, "address")
	switch {
	case host != "" && address != "":
		return []InternalEndpointViolation{{Rule: "route.target", Detail: fmt.Sprintf("endpoint %q: route.target must set exactly one of inventory_host or address, not both", ref)}}
	case host == "" && address == "":
		return []InternalEndpointViolation{{Rule: "route.target", Detail: fmt.Sprintf("endpoint %q: route.target must set inventory_host or address", ref)}}
	case address != "" && net.ParseIP(address) == nil:
		return []InternalEndpointViolation{{Rule: "route.target.address", Detail: fmt.Sprintf("endpoint %q: route.target.address %q must be an IP literal", ref, address)}}
	}
	return nil
}

func checkIEPProxyTarget(ref string, proxy map[string]any) []InternalEndpointViolation {
	var out []InternalEndpointViolation
	if provider := stringField(proxy, "provider"); provider != "" && provider != "nginx" {
		out = append(out, InternalEndpointViolation{Rule: "route.proxy.provider", Detail: fmt.Sprintf("endpoint %q: route.proxy.provider %q is not supported in v1 (only nginx)", ref, provider)})
	}
	if stringField(proxy, "inventory_host") == "" {
		out = append(out, InternalEndpointViolation{Rule: "route.proxy", Detail: fmt.Sprintf("endpoint %q: route.proxy.inventory_host is required", ref)})
	}
	if stringField(proxy, "address") != "" {
		out = append(out, InternalEndpointViolation{Rule: "route.proxy", Detail: fmt.Sprintf("endpoint %q: route.proxy does not support a literal address, only inventory_host", ref)})
	}
	return out
}

func checkIEPUpstreamTarget(ref string, upstream map[string]any) []InternalEndpointViolation {
	host := stringField(upstream, "inventory_host")
	address := stringField(upstream, "address")
	switch {
	case host != "" && address != "":
		return []InternalEndpointViolation{{Rule: "route.upstream", Detail: fmt.Sprintf("endpoint %q: route.upstream must set exactly one of inventory_host or address, not both", ref)}}
	case host == "" && address == "":
		return []InternalEndpointViolation{{Rule: "route.upstream", Detail: fmt.Sprintf("endpoint %q: route.upstream must set inventory_host or address", ref)}}
	case address != "" && net.ParseIP(address) == nil:
		return []InternalEndpointViolation{{Rule: "route.upstream.address", Detail: fmt.Sprintf("endpoint %q: route.upstream.address %q must be an IP literal", ref, address)}}
	}
	return nil
}

// checkIEPUpstreamShape implements spec.md §12.3/§12.4 (the v1.1 HTTP/HTTPS
// upstream revision, spec.md §67): scheme is required, port must be
// 1..65535, and an https scheme routes into checkIEPUpstreamTLS.
func checkIEPUpstreamShape(ref string, upstream map[string]any) []InternalEndpointViolation {
	var out []InternalEndpointViolation
	out = append(out, checkIEPUpstreamTarget(ref, upstream)...)

	port, hasPort := toInt(upstream["port"])
	switch {
	case !hasPort:
		out = append(out, InternalEndpointViolation{Rule: "route.upstream.port", Detail: fmt.Sprintf("endpoint %q: route.upstream.port is required", ref)})
	case port < 1 || port > 65535:
		out = append(out, InternalEndpointViolation{Rule: "route.upstream.port", Detail: fmt.Sprintf("endpoint %q: route.upstream.port %s must be between 1 and 65535", ref, formatPort(port))})
	}

	tls := mapField(upstream, "tls")
	switch scheme := stringField(upstream, "scheme"); scheme {
	case "":
		out = append(out, InternalEndpointViolation{Rule: "route.upstream.scheme", Detail: fmt.Sprintf("endpoint %q: route.upstream.scheme is required (http|https)", ref)})
	case "http":
		if len(tls) > 0 {
			out = append(out, InternalEndpointViolation{Rule: "route.upstream.tls", Detail: fmt.Sprintf("endpoint %q: route.upstream.tls is only valid when route.upstream.scheme=https", ref)})
		}
	case "https":
		out = append(out, checkIEPUpstreamTLS(ref, upstream, tls)...)
	default:
		out = append(out, InternalEndpointViolation{Rule: "route.upstream.scheme", Detail: fmt.Sprintf("endpoint %q: route.upstream.scheme %q must be http or https", ref, scheme)})
	}
	return out
}

// checkIEPUpstreamTLS implements spec.md §12.4.1 (tls.verify is mandatory,
// no implicit default) and §12.4.6 (a verified upstream using a literal
// address has no derivable SNI and must set tls.server_name explicitly).
// The inventory_host + no-server_name + verify=true case MAY derive SNI
// from that host's canonical FQDN per §12.4.6 "only when resolvable" —
// this package does not yet have an inventory convention for a host's
// canonical FQDN, so that refinement is deferred; it is not exercised by
// spec.md §51's validator matrix (which only covers the address-literal
// case), so deferring it does not weaken Phase 2's required coverage.
func checkIEPUpstreamTLS(ref string, upstream, tls map[string]any) []InternalEndpointViolation {
	verifyRaw, hasVerify := tls["verify"]
	verify, isBool := verifyRaw.(bool)
	if !hasVerify || !isBool {
		return []InternalEndpointViolation{{Rule: "route.upstream.tls.verify", Detail: fmt.Sprintf("endpoint %q: HTTPS upstream requires explicit tls.verify=true or tls.verify=false", ref)}}
	}
	if verify && stringField(tls, "server_name") == "" && stringField(upstream, "inventory_host") == "" {
		return []InternalEndpointViolation{{Rule: "route.upstream.tls.server_name", Detail: fmt.Sprintf("endpoint %q: verified HTTPS upstream using an IP address requires tls.server_name", ref)}}
	}
	return nil
}

// ---- Gate: route host resolution (spec.md §12, §6.2) -----------------------

func checkIEPRouteHostResolution(e map[string]any, hostvars map[string]map[string]any, reverseProxyHosts map[string]bool) []InternalEndpointViolation {
	if hostvars == nil {
		return nil
	}
	ref := formatEndpointRef(e)
	route := mapField(e, "route")
	var out []InternalEndpointViolation
	checkHost := func(label, host string) bool {
		if host == "" {
			return false
		}
		if _, ok := hostvars[host]; !ok {
			out = append(out, InternalEndpointViolation{Rule: "inventory host", Detail: fmt.Sprintf("endpoint %q: %s references unknown inventory host %q", ref, label, host)})
			return false
		}
		return true
	}
	switch stringField(route, "mode") {
	case "direct":
		checkHost("route.target.inventory_host", stringField(mapField(route, "target"), "inventory_host"))
	case "reverse_proxy":
		proxyHost := stringField(mapField(route, "proxy"), "inventory_host")
		if checkHost("route.proxy.inventory_host", proxyHost) && reverseProxyHosts != nil && !reverseProxyHosts[proxyHost] {
			out = append(out, InternalEndpointViolation{Rule: "route.proxy role", Detail: fmt.Sprintf("endpoint %q: route.proxy.inventory_host %q does not carry the reverse-proxy role", ref, proxyHost)})
		}
		checkHost("route.upstream.inventory_host", stringField(mapField(route, "upstream"), "inventory_host"))
	}
	return out
}

// ---- Gate: tls.mode shape (spec.md §14, §12.2) -----------------------------

func checkIEPTLSShape(e map[string]any) []InternalEndpointViolation {
	ref := formatEndpointRef(e)
	tls := mapField(e, "tls")
	route := mapField(e, "route")
	routeMode := stringField(route, "mode")

	switch mode := stringField(tls, "mode"); mode {
	case "disabled":
		return nil
	case "":
		return []InternalEndpointViolation{{Rule: "tls.mode", Detail: fmt.Sprintf("endpoint %q: tls.mode is required (disabled|freeipa)", ref)}}
	case "freeipa":
		if routeMode != "direct" {
			return nil
		}
		if stringField(mapField(route, "target"), "inventory_host") == "" {
			return []InternalEndpointViolation{{Rule: "tls direct owner", Detail: fmt.Sprintf("endpoint %q: tls.mode=freeipa with route.mode=direct requires route.target.inventory_host (Pilot cannot derive a certificate owner from a literal address)", ref)}}
		}
		return nil
	default:
		return []InternalEndpointViolation{{Rule: "tls.mode", Detail: fmt.Sprintf("endpoint %q: tls.mode %q must be disabled or freeipa", ref, mode)}}
	}
}

// ---- Gate: TLS certificate owner has live FreeIPA enrollment (spec.md §16) -

func checkIEPTLSOwnerEnrollment(e map[string]any, enrolled map[string]bool) []InternalEndpointViolation {
	if enrolled == nil {
		return nil
	}
	tls := mapField(e, "tls")
	if stringField(tls, "mode") != "freeipa" {
		return nil
	}
	route := mapField(e, "route")
	var ownerHost string
	switch stringField(route, "mode") {
	case "direct":
		ownerHost = stringField(mapField(route, "target"), "inventory_host")
	case "reverse_proxy":
		ownerHost = stringField(mapField(route, "proxy"), "inventory_host")
	}
	if ownerHost == "" || enrolled[ownerHost] {
		return nil
	}
	return []InternalEndpointViolation{{Rule: "tls owner enrollment", Detail: fmt.Sprintf("endpoint %q: certificate owner host %q has no live FreeIPA enrollment", formatEndpointRef(e), ownerHost)}}
}

// ---- Gate: direct TLS certificate sink (spec.md §22) -----------------------

func checkIEPDirectTLSSink(e map[string]any) []InternalEndpointViolation {
	tls := mapField(e, "tls")
	if stringField(tls, "mode") != "freeipa" {
		return nil
	}
	route := mapField(e, "route")
	if stringField(route, "mode") != "direct" {
		return nil
	}
	ref := formatEndpointRef(e)
	sink := mapField(tls, "sink")
	var out []InternalEndpointViolation

	certFile := stringField(sink, "cert_file")
	keyFile := stringField(sink, "key_file")
	switch {
	case certFile == "":
		out = append(out, InternalEndpointViolation{Rule: "tls.sink.cert_file", Detail: fmt.Sprintf("endpoint %q: tls.sink.cert_file is required", ref)})
	case !path.IsAbs(certFile):
		out = append(out, InternalEndpointViolation{Rule: "tls.sink.cert_file", Detail: fmt.Sprintf("endpoint %q: tls.sink.cert_file %q must be an absolute path", ref, certFile)})
	}
	switch {
	case keyFile == "":
		out = append(out, InternalEndpointViolation{Rule: "tls.sink.key_file", Detail: fmt.Sprintf("endpoint %q: tls.sink.key_file is required", ref)})
	case !path.IsAbs(keyFile):
		out = append(out, InternalEndpointViolation{Rule: "tls.sink.key_file", Detail: fmt.Sprintf("endpoint %q: tls.sink.key_file %q must be an absolute path", ref, keyFile)})
	}
	if certFile != "" && keyFile != "" && certFile == keyFile {
		out = append(out, InternalEndpointViolation{Rule: "tls.sink paths", Detail: fmt.Sprintf("endpoint %q: tls.sink.cert_file and key_file must not be the same path", ref)})
	}
	if mode := stringField(sink, "key_mode"); mode != "" && !iepOctalModeRe.MatchString(mode) {
		out = append(out, InternalEndpointViolation{Rule: "tls.sink.key_mode", Detail: fmt.Sprintf("endpoint %q: tls.sink.key_mode %q must be a 3-4 digit octal file mode", ref, mode)})
	}

	reload := mapField(sink, "reload")
	if mode := stringField(reload, "mode"); mode != "systemd" {
		out = append(out, InternalEndpointViolation{Rule: "tls.sink.reload.mode", Detail: fmt.Sprintf("endpoint %q: tls.sink.reload.mode must be systemd, got %q", ref, mode)})
	}
	switch unit := stringField(reload, "unit"); {
	case unit == "":
		out = append(out, InternalEndpointViolation{Rule: "tls.sink.reload.unit", Detail: fmt.Sprintf("endpoint %q: tls.sink.reload.unit is required", ref)})
	case !iepSystemdUnitRe.MatchString(unit):
		out = append(out, InternalEndpointViolation{Rule: "tls.sink.reload.unit", Detail: fmt.Sprintf("endpoint %q: tls.sink.reload.unit %q is not a valid systemd unit name", ref, unit)})
	}
	return out
}

// ---- Gate: deletion requires manifest safety flag (spec.md §31) -----------

func checkIEPDeleteSafety(root, e map[string]any) []InternalEndpointViolation {
	if stateOrDefault(e, "present") != "absent" {
		return nil
	}
	if boolFieldDefault(mapField(root, "safety"), "allow_endpoint_delete", false) {
		return nil
	}
	return []InternalEndpointViolation{{Rule: "delete safety", Detail: fmt.Sprintf("endpoint %q: state: absent requires safety.allow_endpoint_delete: true", formatEndpointRef(e))}}
}

// ---- Gate: destructive request missing from the ownership ledger (spec.md §32) -

func checkIEPMissingLedgerDelete(e map[string]any, ledger map[string]bool) []InternalEndpointViolation {
	if ledger == nil || stateOrDefault(e, "present") != "absent" {
		return nil
	}
	fqdn := normalizeFQDN(stringField(e, "fqdn"))
	if ledger[fqdn] {
		return nil
	}
	return []InternalEndpointViolation{{Rule: "ledger presence", Detail: fmt.Sprintf("endpoint %q: state: absent requested but %q is absent from the ownership ledger — fail closed", formatEndpointRef(e), fqdn)}}
}

// ---- Gate: route-owner migration fails closed in v1 (spec.md §30) ---------

func checkIEPRouteOwnerMigration(e map[string]any, previous map[string]PreviousRoute) []InternalEndpointViolation {
	if previous == nil {
		return nil
	}
	fqdn := normalizeFQDN(stringField(e, "fqdn"))
	prev, ok := previous[fqdn]
	if !ok {
		return nil
	}
	ref := formatEndpointRef(e)
	route := mapField(e, "route")
	mode := stringField(route, "mode")
	if prev.Mode != mode {
		return []InternalEndpointViolation{{Rule: "route owner migration", Detail: fmt.Sprintf("endpoint %q: route owner change is not supported in-place (mode %s -> %s)", ref, prev.Mode, mode)}}
	}
	switch mode {
	case "direct":
		target := mapField(route, "target")
		host := stringField(target, "inventory_host")
		address := stringField(target, "address")
		hostChanged := prev.TargetHost != "" && prev.TargetHost != host
		addressChanged := prev.TargetHost == "" && prev.TargetAddress != "" && prev.TargetAddress != address
		if hostChanged || addressChanged {
			return []InternalEndpointViolation{{Rule: "route owner migration", Detail: fmt.Sprintf("endpoint %q: route.target owner change is not supported in-place", ref)}}
		}
	case "reverse_proxy":
		proxyHost := stringField(mapField(route, "proxy"), "inventory_host")
		if prev.ProxyHost != "" && prev.ProxyHost != proxyHost {
			return []InternalEndpointViolation{{Rule: "route owner migration", Detail: fmt.Sprintf("endpoint %q: route.proxy owner change is not supported in-place", ref)}}
		}
	}
	return nil
}
