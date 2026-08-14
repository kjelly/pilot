package inventory

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadInternalEndpointManifest reads and YAML-decodes an internal-endpoints
// manifest into a plain map, the same representation
// ValidateInternalEndpointManifest and NormalizeInternalEndpointManifest
// operate on. The manifest is never ansible-vault encrypted (schema forbids
// secrets — spec.md §8), so unlike the roster loader there is no
// encrypted-file detection to perform here.
func LoadInternalEndpointManifest(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse internal-endpoints manifest %s: %w", path, err)
	}
	return root, nil
}

// NormalizedInternalEndpointManifest is the deterministic desired-state view
// of a manifest that has already passed ValidateInternalEndpointManifest
// with zero violations. Like NormalizedDNSManifest, this is a read-only plan
// artifact: what SHOULD exist, fully resolved (inventory_host targets turned
// into concrete IPs, certificate ownership derived), before any comparison
// against FreeIPA/nginx/DNS live state — spec.md §35, §36.
type NormalizedInternalEndpointManifest struct {
	Endpoints []NormalizedInternalEndpoint
}

// NormalizedInternalEndpoint is one endpoint's fully-resolved desired state.
// Field set matches spec.md §35's suggested struct, extended per §67 v1.1
// (Upstream* fields) for reverse-proxy HTTPS upstream support.
type NormalizedInternalEndpoint struct {
	FQDN  string
	State string

	DNSZone       string // lowercase, trailing-dot
	DNSOwner      string // zone-relative owner, lowercase ("@" for apex)
	DNSRecordType string // A|AAAA
	DNSValue      string // resolved IP of the route owner (target host for direct, proxy host for reverse_proxy)
	TTL           int

	RouteMode      string // direct|reverse_proxy
	RouteOwnerHost string // inventory_host that owns the DNS destination, "" when route.target/proxy used a literal address
	RouteOwnerIP   string // resolved IP of the route owner

	// Upstream* is only meaningful when RouteMode == "reverse_proxy".
	UpstreamScheme        string // http|https
	UpstreamHost          string // inventory_host, "" when upstream used a literal address
	UpstreamIP            string
	UpstreamPort          int
	UpstreamTLSVerify     bool // meaningful only when UpstreamScheme == "https"
	UpstreamTLSServerName string

	TLSMode string // disabled|freeipa
	TLSPort int    // 0 means "use the scheme default (443)"

	// CertificateOwner and ServicePrincipal are only meaningful when
	// TLSMode == "freeipa" — derived per spec.md §15, never user-supplied.
	CertificateOwner string
	ServicePrincipal string // HTTP/<fqdn>

	// Sink* is only meaningful when RouteMode == "direct" && TLSMode == "freeipa".
	CertFile   string
	KeyFile    string
	KeyOwner   string
	KeyGroup   string
	KeyMode    string
	ReloadUnit string
}

// NormalizeInternalEndpointManifest resolves and sorts a manifest into
// deterministic desired state. Callers must run
// ValidateInternalEndpointManifest first and only normalize when it returns
// zero violations — this function assumes the input already satisfies the
// schema contract (spec.md §9-§22) and does not re-validate it.
func NormalizeInternalEndpointManifest(root map[string]any, hostvars map[string]map[string]any) NormalizedInternalEndpointManifest {
	endpointsIn := listField(root, "endpoints")
	out := make([]NormalizedInternalEndpoint, 0, len(endpointsIn))
	for _, rawEndpoint := range endpointsIn {
		e := asMap(rawEndpoint)
		out = append(out, normalizeOneEndpoint(e, hostvars))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FQDN < out[j].FQDN })
	return NormalizedInternalEndpointManifest{Endpoints: out}
}

func normalizeOneEndpoint(e map[string]any, hostvars map[string]map[string]any) NormalizedInternalEndpoint {
	fqdn := normalizeFQDN(stringField(e, "fqdn"))
	dns := mapField(e, "dns")
	zone := normalizeZoneName(stringField(dns, "zone"))
	route := mapField(e, "route")
	routeMode := stringField(route, "mode")
	tls := mapField(e, "tls")
	tlsMode := stringField(tls, "mode")

	n := NormalizedInternalEndpoint{
		FQDN:      fqdn,
		State:     stateOrDefault(e, "present"),
		DNSZone:   zone,
		DNSOwner:  relativeOwner(fqdn, zone),
		TTL:       dnsTTLOrDefault(dns),
		RouteMode: routeMode,
		TLSMode:   tlsMode,
		TLSPort:   intFieldDefault(tls, "port", 0),
	}

	switch routeMode {
	case "direct":
		host, address := resolveTargetLike(mapField(route, "target"), hostvars)
		n.RouteOwnerHost = host
		n.RouteOwnerIP = address
	case "reverse_proxy":
		host, address := resolveTargetLike(mapField(route, "proxy"), hostvars)
		n.RouteOwnerHost = host
		n.RouteOwnerIP = address

		upstream := mapField(route, "upstream")
		n.UpstreamScheme = stringField(upstream, "scheme")
		n.UpstreamHost, n.UpstreamIP = resolveTargetLike(upstream, hostvars)
		n.UpstreamPort = intFieldDefault(upstream, "port", 0)
		if n.UpstreamScheme == "https" {
			upstreamTLS := mapField(upstream, "tls")
			n.UpstreamTLSVerify = boolFieldDefault(upstreamTLS, "verify", false)
			n.UpstreamTLSServerName = stringField(upstreamTLS, "server_name")
		}
	}

	n.DNSValue = n.RouteOwnerIP
	if n.DNSValue != "" {
		if ip := net.ParseIP(n.DNSValue); ip != nil && ip.To4() != nil {
			n.DNSRecordType = "A"
		} else if ip != nil {
			n.DNSRecordType = "AAAA"
		}
	}

	if tlsMode == "freeipa" {
		n.ServicePrincipal = "HTTP/" + fqdn
		n.CertificateOwner = deriveCertificateOwner(routeMode, n.RouteOwnerHost)
		if routeMode == "direct" {
			sink := mapField(tls, "sink")
			n.CertFile = stringField(sink, "cert_file")
			n.KeyFile = stringField(sink, "key_file")
			n.KeyOwner = stringFieldDefault(sink, "key_owner", "root")
			n.KeyGroup = stringFieldDefault(sink, "key_group", "root")
			n.KeyMode = stringFieldDefault(sink, "key_mode", "0600")
			n.ReloadUnit = stringField(mapField(sink, "reload"), "unit")
		}
	}

	return n
}

// deriveCertificateOwner implements spec.md §15: the certificate owner is
// never user-supplied, it is always the inventory host that physically owns
// the endpoint's frontend TLS socket — route.target.inventory_host for
// direct, route.proxy.inventory_host for reverse_proxy.
func deriveCertificateOwner(routeMode, routeOwnerHost string) string {
	if routeMode == "direct" || routeMode == "reverse_proxy" {
		return routeOwnerHost
	}
	return ""
}

// resolveTargetLike resolves any route sub-object shaped like {inventory_host}
// or {address} (route.target, route.proxy, route.upstream) into the
// inventory host name (if any) and its concrete IP address. When
// inventory_host is set, the address comes from hostvars[host].ansible_host;
// an unknown host or a host with no ansible_host resolves to "" (validation
// is expected to have already rejected such manifests before normalize runs).
func resolveTargetLike(m map[string]any, hostvars map[string]map[string]any) (host, address string) {
	if h := stringField(m, "inventory_host"); h != "" {
		hv := hostvars[h]
		if hv == nil {
			return h, ""
		}
		ansibleHost, _ := hv["ansible_host"].(string)
		return h, strings.TrimSpace(ansibleHost)
	}
	if a := stringField(m, "address"); a != "" {
		return "", strings.TrimSpace(a)
	}
	return "", ""
}

// normalizeFQDN applies spec.md §10.2's normalization: lowercase, trailing
// dot stripped (the manifest's primary key is the dotless canonical form).
func normalizeFQDN(fqdn string) string {
	fqdn = strings.ToLower(strings.TrimSpace(fqdn))
	return strings.TrimSuffix(fqdn, ".")
}

// relativeOwner implements spec.md §10.3: fqdn must be the zone apex or a
// strict descendant; the owner is "@" at the apex, or the leading labels
// otherwise (e.g. fqdn=aaa.xxx.linker.internal, zone=linker.internal. ->
// owner=aaa.xxx).
func relativeOwner(fqdn, zone string) string {
	zoneName := strings.TrimSuffix(zone, ".")
	if zoneName == "" {
		return ""
	}
	if strings.EqualFold(fqdn, zoneName) {
		return "@"
	}
	suffix := "." + zoneName
	if strings.HasSuffix(fqdn, suffix) {
		return strings.TrimSuffix(fqdn, suffix)
	}
	return ""
}

func dnsTTLOrDefault(dns map[string]any) int {
	if ttl, ok := toInt(dns["ttl"]); ok {
		return ttl
	}
	return 0
}

func intFieldDefault(m map[string]any, key string, def int) int {
	if m == nil {
		return def
	}
	if n, ok := toInt(m[key]); ok {
		return n
	}
	return def
}

func stringFieldDefault(m map[string]any, key, def string) string {
	if v := stringField(m, key); v != "" {
		return v
	}
	return def
}

// formatEndpointRef renders a human-readable identifier for error messages:
// the raw fqdn field (pre-normalization) so a typo'd manifest still points
// the operator at what they wrote.
func formatEndpointRef(e map[string]any) string {
	if fqdn := stringField(e, "fqdn"); fqdn != "" {
		return fqdn
	}
	return "unnamed endpoint"
}

// formatPort renders a port number for error messages without pulling in
// fmt.Sprintf at every call site.
func formatPort(port int) string {
	return strconv.Itoa(port)
}
