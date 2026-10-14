package diagnose

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/networkcheck"
)

// This file is pilot_diagnose_dns_architecture's "effective" layer: what the
// canonical playbook rules compute from the inventory, before anything is
// asked of a live host. It mirrors, rule for rule:
//
//   - playbooks/apply/tasks/freeipa-server-pool.yml   (providers, FQDNs, gates)
//   - playbooks/apply/tasks/dns-tier-endpoints.yml    (tier service addresses)
//   - playbooks/apply/dns-apply.yml pre_tasks         (tier mode, upstream, zones)
//   - playbooks/apply/tasks/freeipa-dns-client-resolver.yml (resolver selection)
//   - playbooks/apply/freeipa-server-apply.yml        (global forwarders)
//   - playbooks/apply/freeipa-server-replica-apply.yml (install-time forwarders)
//
// The playbooks stay the single source: internal/spec's
// TestRegression_DNSArchitectureModelMatchesPlaybooks runs those exact tasks
// with ansible-playbook on fixture inventories and fails when this file
// computes anything different (AGENTS.md §5.7).

// DNSArchitectureGroups are the inventory groups the DNS topology reads.
const (
	DNSTierGroup          = "dns"
	FreeIPAServerGroup    = "freeipa-server"
	FreeIPAReplicaGroup   = "freeipa-server-replica"
	FreeIPADNSClientGroup = "freeipa-dns-client"
)

// dnsArchDefaultDomain is the FreeIPA domain every playbook falls back to.
const dnsArchDefaultDomain = "ipa.pilot.internal"

// MaxDNSArchResolvers bounds how many per-host resolver selections one
// report carries.
const MaxDNSArchResolvers = 50

// DNSArchVar is one inventory variable as the operator declared it. State is
// "set" or "unset"; Templated marks a Jinja expression that ansible-inventory
// returns unrendered, so the model cannot evaluate it.
type DNSArchVar struct {
	Host      string `json:"host"`
	Name      string `json:"name"`
	State     string `json:"state"`
	Value     any    `json:"value,omitempty"`
	Templated bool   `json:"templated,omitempty"`
	Evidence  string `json:"evidence"`
}

// DNSArchProvider is one member of the FreeIPA server pool. DNSProvider is
// freeipa_setup_dns, default true on the primary and on a replica: the
// install playbooks run FreeIPA DNS then, and the server pool and the
// resolver task send tier stubs and client queries to it (issue #67 aligned
// the replica default of the latter two).
type DNSArchProvider struct {
	InventoryHost string `json:"inventory_host"`
	Kind          string `json:"kind"`
	FQDN          string `json:"fqdn"`
	IP            string `json:"ip"`
	DNSProvider   bool   `json:"dns_provider"`
	// DNSProviderExplicit is whether freeipa_setup_dns is set on the host.
	DNSProviderExplicit bool `json:"dns_provider_explicit"`
	// LeftOut marks a replica that leaves freeipa_setup_dns unset and
	// that FreeIPA's own NS records do not list as a DNS server: dns-apply
	// and the resolver task leave it out (tasks/freeipa-dns-providers-live.yml),
	// so the model does too.
	LeftOut bool `json:"left_out,omitempty"`
}

// DNSArchZone is one stub zone a tier host sends to an authoritative server.
type DNSArchZone struct {
	Name   string   `json:"name"`
	Addrs  []string `json:"addrs"`
	Source string   `json:"source"`
}

// DNSArchTierHost is one dns tier host's effective unbound configuration.
// State is "computed", or "unknown" when an input was a Jinja template.
type DNSArchTierHost struct {
	Host                string        `json:"host"`
	State               string        `json:"state"`
	Addr                string        `json:"addr,omitempty"`
	Mode                string        `json:"mode,omitempty"`
	Upstream            []string      `json:"upstream,omitempty"`
	FreeIPAServers      []string      `json:"freeipa_servers,omitempty"`
	StubZones           []DNSArchZone `json:"stub_zones,omitempty"`
	LocalZones          []string      `json:"local_zones,omitempty"`
	CacheMaxTTL         string        `json:"cache_max_ttl,omitempty"`
	CacheMaxNegativeTTL string        `json:"cache_max_negative_ttl,omitempty"`
	DNSSECValidation    bool          `json:"dnssec_validation"`
	Errors              []string      `json:"errors,omitempty"`
	Unevaluated         []string      `json:"unevaluated,omitempty"`
}

// DNSArchResolver is the resolver list the shared resolver task would write
// on one host. Selection is explicit_override, provider_self, tier_first,
// freeipa_only or none.
type DNSArchResolver struct {
	Host        string   `json:"host"`
	State       string   `json:"state"`
	ManagedBy   []string `json:"managed_by,omitempty"`
	Selection   string   `json:"selection,omitempty"`
	Servers     []string `json:"servers,omitempty"`
	Options     []string `json:"options,omitempty"`
	Error       string   `json:"error,omitempty"`
	Unevaluated []string `json:"unevaluated,omitempty"`
}

// DNSArchForwarding is the FreeIPA-side forwarding pilot declares. Pilot
// manages the global forwarder list (ipa dnsconfig-mod, on every
// freeipa-server apply) and the --forwarder flags each DNS server is
// installed with, which FreeIPA keeps as that server's own forwarder
// setting; forward policy and forward zones are not pilot-managed, so they
// have no effective value here and are only observed.
type DNSArchForwarding struct {
	State                   string                    `json:"state"`
	GlobalForwarders        []string                  `json:"global_forwarders,omitempty"`
	Source                  string                    `json:"source,omitempty"`
	ForwardPolicy           string                    `json:"forward_policy"`
	ForwardZones            string                    `json:"forward_zones"`
	ServerInstallForwarders []DNSArchServerInstallFwd `json:"server_install_forwarders,omitempty"`
	Unevaluated             []string                  `json:"unevaluated,omitempty"`
}

// DNSArchServerInstallFwd is the --forwarder list a DNS server was
// installed with (none means --no-forwarders) and where it came from.
// Error is set when the install playbook could not turn the input into
// that list.
type DNSArchServerInstallFwd struct {
	Host       string   `json:"host"`
	Forwarders []string `json:"forwarders"`
	Source     string   `json:"source"`
	Error      string   `json:"error,omitempty"`
}

// DNSArchModel is the effective, inventory-derived DNS topology.
type DNSArchModel struct {
	FreeIPAPresent     bool              `json:"freeipa_present"`
	FreeIPADomain      string            `json:"freeipa_domain,omitempty"`
	Providers          []DNSArchProvider `json:"providers,omitempty"`
	ProviderErrors     []string          `json:"provider_errors,omitempty"`
	Forwarding         DNSArchForwarding `json:"forwarding"`
	TierAssigned       bool              `json:"tier_assigned"`
	Tier               []DNSArchTierHost `json:"tier,omitempty"`
	Resolvers          []DNSArchResolver `json:"resolvers,omitempty"`
	ResolversTruncated bool              `json:"resolvers_truncated,omitempty"`
	Unevaluated        []string          `json:"unevaluated,omitempty"`
	Declared           []DNSArchVar      `json:"-"`
}

// DNSProviderIPs returns the addresses of every DNS-providing pool member
// that is not left out.
func (m DNSArchModel) DNSProviderIPs() []string {
	var out []string
	for _, p := range m.Providers {
		if p.DNSProvider && !p.LeftOut && p.IP != "" {
			out = append(out, p.IP)
		}
	}
	return out
}

// Provider returns the pool member for an inventory host.
func (m DNSArchModel) Provider(host string) (DNSArchProvider, bool) {
	for _, p := range m.Providers {
		if p.InventoryHost == host {
			return p, true
		}
	}
	return DNSArchProvider{}, false
}

// ---- Jinja/Ansible value semantics -----------------------------------------

var dnsArchTemplateRe = regexp.MustCompile(`\{\{|\{%`)

// varReader reads host vars the way the playbooks do and records every
// read that hit an unrendered Jinja template or the declared value.
type varReader struct {
	inv         networkcheck.ResolvedInventory
	unevaluated []string
	declared    map[string]DNSArchVar
}

func newVarReader(inv networkcheck.ResolvedInventory) *varReader {
	return &varReader{inv: inv, declared: map[string]DNSArchVar{}}
}

func dnsArchVarRef(host, name string) string {
	return fmt.Sprintf("inventory:hostvars[%s].%s", host, name)
}

// get returns the raw value and whether the variable is defined. A value
// ansible-inventory left as a Jinja template is reported as defined but
// recorded as unevaluated.
func (r *varReader) get(host, name string) (any, bool) {
	ref := dnsArchVarRef(host, name)
	v, ok := r.inv.HostVars[host][name]
	decl := DNSArchVar{Host: host, Name: name, State: "unset", Evidence: ref}
	if ok {
		decl.State, decl.Value = "set", v
		if isTemplated(v) {
			decl.Templated = true
			r.unevaluated = append(r.unevaluated, ref)
		}
	}
	r.declared[host+"\x00"+name] = decl
	return v, ok
}

// take returns and clears the unevaluated refs recorded since the last call.
func (r *varReader) take() []string {
	out := uniqueStrings(r.unevaluated)
	r.unevaluated = nil
	return out
}

func isTemplated(v any) bool {
	switch t := v.(type) {
	case string:
		return dnsArchTemplateRe.MatchString(t)
	case []any:
		for _, item := range t {
			if isTemplated(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range t {
			if isTemplated(item) {
				return true
			}
		}
	}
	return false
}

// jinjaTruthy mirrors Python truthiness, which `default(x, true)` uses.
func jinjaTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case int:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

// ansibleBool mirrors Ansible's `bool` filter.
func ansibleBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(t) {
		case "yes", "on", "1", "true":
			return true
		}
	case float64:
		return t == 1
	case int:
		return t == 1
	}
	return false
}

// jinjaString mirrors `| string` for the scalar values an inventory holds.
func jinjaString(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	}
	return fmt.Sprintf("%v", v)
}

// def mirrors `x | default(fallback)` (only an undefined x falls back).
func (r *varReader) def(host, name string, fallback any) any {
	if v, ok := r.get(host, name); ok {
		return v
	}
	return fallback
}

// defTrue mirrors `x | default(fallback, true)` (falsy values fall back too).
func (r *varReader) defTrue(host, name string, fallback any) any {
	if v, ok := r.get(host, name); ok && jinjaTruthy(v) {
		return v
	}
	return fallback
}

func isNonStringSequence(v any) bool {
	_, ok := v.([]any)
	return ok
}

// stringItems mirrors `(raw if raw is sequence and raw is not string else
// [raw]) | map('string')`.
func stringItems(raw any) []string {
	if list, ok := raw.([]any); ok {
		out := make([]string, 0, len(list))
		for _, item := range list {
			out = append(out, jinjaString(item))
		}
		return out
	}
	return []string{jinjaString(raw)}
}

var dnsArchSplitRe = regexp.MustCompile(`[,\s]+`)

// splitListSetting mirrors dns-apply.yml's list normalization: a list is
// taken as is; a string is split on commas and whitespace. Items are
// stringified, trimmed and empties dropped.
func splitListSetting(raw any) []string {
	var items []string
	if isNonStringSequence(raw) {
		items = stringItems(raw)
	} else {
		items = strings.Split(strings.TrimSpace(dnsArchSplitRe.ReplaceAllString(jinjaString(raw), " ")), " ")
	}
	return trimNonEmpty(items)
}

func trimNonEmpty(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func normalizeZoneName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func stringIn(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// ---- model ------------------------------------------------------------------

// BuildDNSArchitectureModel computes the effective DNS topology of inv.
// extraResolverHosts are hosts whose resolver selection is wanted even
// though they are not in the freeipa-dns-client group (the diagnosis's
// client_host).
func BuildDNSArchitectureModel(inv networkcheck.ResolvedInventory, extraResolverHosts ...string) DNSArchModel {
	return BuildDNSArchitectureModelLeavingOut(inv, nil, extraResolverHosts...)
}

// BuildDNSArchitectureModelLeavingOut is BuildDNSArchitectureModel with
// the replicas in leftOut (inventory hosts, from DNSArchUnregisteredReplicas)
// left out of the tier's stubs and the resolver lists, as the playbooks
// leave them out once FreeIPA's NS records show they serve no DNS.
func BuildDNSArchitectureModelLeavingOut(inv networkcheck.ResolvedInventory, leftOut []string, extraResolverHosts ...string) DNSArchModel {
	r := newVarReader(inv)
	m := DNSArchModel{}

	primaries := inv.OrderedGroupHosts(FreeIPAServerGroup)
	replicas := inv.OrderedGroupHosts(FreeIPAReplicaGroup)
	m.FreeIPAPresent = len(primaries) > 0

	if m.FreeIPAPresent {
		primary := primaries[0]
		// dns-apply.yml: hostvars[groups['freeipa-server'][0]].freeipa_domain
		// | default('ipa.pilot.internal', true), lowered, trailing dot dropped.
		m.FreeIPADomain = normalizeZoneName(jinjaString(r.defTrue(primary, "freeipa_domain", dnsArchDefaultDomain)))
		m.Providers, m.ProviderErrors = buildProviderPool(r, primaries, replicas)
		for i := range m.Providers {
			m.Providers[i].LeftOut = m.Providers[i].Kind == "replica" && stringIn(leftOut, m.Providers[i].InventoryHost)
		}
		m.Forwarding = buildForwarding(r, primary, replicas)
	} else {
		m.Forwarding = DNSArchForwarding{State: "not_applicable", ForwardPolicy: "not_applicable", ForwardZones: "not_applicable"}
	}
	m.Unevaluated = append(m.Unevaluated, r.take()...)

	tierHosts := inv.OrderedGroupHosts(DNSTierGroup)
	m.TierAssigned = len(tierHosts) > 0
	endpoints, endpointsUnevaluated := tierEndpoints(r, tierHosts)
	for _, host := range tierHosts {
		m.Tier = append(m.Tier, buildTierHost(r, m, host, endpoints[host], endpointsUnevaluated))
	}

	resolverHosts := append([]string(nil), inv.OrderedGroupHosts(FreeIPADNSClientGroup)...)
	for _, host := range extraResolverHosts {
		if host != "" && !stringIn(resolverHosts, host) {
			resolverHosts = append(resolverHosts, host)
		}
	}
	if len(resolverHosts) > MaxDNSArchResolvers {
		resolverHosts = resolverHosts[:MaxDNSArchResolvers]
		m.ResolversTruncated = true
	}
	clientGroup := inv.GroupHosts[FreeIPADNSClientGroup]
	for _, host := range resolverHosts {
		res := buildResolver(r, inv, host, tierHosts, leftOut)
		if stringIn(clientGroup, host) {
			res.ManagedBy = []string{"freeipa-dns-client"}
		}
		m.Resolvers = append(m.Resolvers, res)
	}

	m.Unevaluated = uniqueStrings(m.Unevaluated)
	for _, decl := range r.declared {
		m.Declared = append(m.Declared, decl)
	}
	sortDeclared(m.Declared)
	return m
}

// buildProviderPool mirrors tasks/freeipa-server-pool.yml, with each
// member's FQDN taken from that server's own vars — the name
// freeipa-server-apply.yml / freeipa-server-replica-apply.yml install it
// under. The pool's fail-closed gates are returned as errors instead of
// stopping the diagnosis.
func buildProviderPool(r *varReader, primaries, replicas []string) ([]DNSArchProvider, []string) {
	var errs []string
	if len(primaries) != 1 {
		errs = append(errs, fmt.Sprintf("freeipa-server-pool expects exactly one freeipa-server host, found %d", len(primaries)))
	}
	primary := primaries[0]
	domain := jinjaString(r.def(primary, "freeipa_domain", dnsArchDefaultDomain))
	pool := []DNSArchProvider{{
		InventoryHost: primary,
		Kind:          "primary",
		FQDN:          jinjaString(r.def(primary, "freeipa_server_fqdn", "ipa1."+domain)),
		IP:            jinjaString(r.def(primary, "ansible_host", "")),
		DNSProvider:   ansibleBool(r.def(primary, "freeipa_setup_dns", true)),
	}}
	_, pool[0].DNSProviderExplicit = r.get(primary, "freeipa_setup_dns")
	for _, host := range replicas {
		replicaDomain := jinjaString(r.def(host, "freeipa_domain", dnsArchDefaultDomain))
		if _, ok := r.get(host, "freeipa_replica_fqdn"); !ok && len(replicas) > 1 {
			errs = append(errs, fmt.Sprintf("%s: more than one freeipa-server-replica host, so each needs its own freeipa_replica_fqdn", host))
		}
		pool = append(pool, DNSArchProvider{
			InventoryHost: host,
			Kind:          "replica",
			FQDN:          jinjaString(r.def(host, "freeipa_replica_fqdn", "ipa2."+replicaDomain)),
			IP:            jinjaString(r.def(host, "ansible_host", "")),
			DNSProvider:   ansibleBool(r.def(host, "freeipa_setup_dns", true)),
		})
		_, pool[len(pool)-1].DNSProviderExplicit = r.get(host, "freeipa_setup_dns")
	}
	fqdns, ips := map[string]bool{}, map[string]bool{}
	for _, p := range pool {
		if fqdns[p.FQDN] {
			errs = append(errs, fmt.Sprintf("duplicate FreeIPA FQDN %s in the server pool", p.FQDN))
		}
		fqdns[p.FQDN] = true
		if p.IP != "" {
			if ips[p.IP] {
				errs = append(errs, fmt.Sprintf("IP %s is used by more than one FreeIPA server", p.IP))
			}
			ips[p.IP] = true
		}
	}
	return pool, errs
}

// The address patterns tasks/freeipa-dns-forwarders.yml checks every
// forwarder against (the same regular expressions, so a value passes or
// fails both).
var (
	forwarderIPv4Re = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])[.]){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`)
	forwarderIPv6Re = regexp.MustCompile(`^([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$`)
)

// normalizeForwarders mirrors tasks/freeipa-dns-forwarders.yml, which both
// install playbooks use: null is no forwarders, a string starting with '['
// is a YAML list, any other string is split on whitespace, a list is
// kept, and every item must be an IPv4 or IPv6 address. Anything else is
// the error the playbook's gates fail with.
func normalizeForwarders(raw any) ([]string, error) {
	var items []string
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case string:
		t := strings.TrimSpace(v)
		if !strings.HasPrefix(t, "[") {
			items = strings.Fields(t)
			break
		}
		if !strings.HasSuffix(t, "]") {
			return nil, fmt.Errorf("forwarders %q start with [ but are not a YAML list", v)
		}
		var list []any
		if err := yaml.Unmarshal([]byte(t), &list); err != nil {
			return nil, fmt.Errorf("forwarders %q are not a YAML list: %v", v, err)
		}
		for _, e := range list {
			items = append(items, fmt.Sprint(e))
		}
	case []any:
		for _, e := range v {
			items = append(items, fmt.Sprint(e))
		}
	default:
		return nil, fmt.Errorf("forwarders value %v is neither a list nor a string", raw)
	}
	var bad []string
	for _, item := range items {
		if !forwarderIPv4Re.MatchString(item) && !forwarderIPv6Re.MatchString(item) {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("forwarders %q are not IPv4 or IPv6 addresses (separate several with spaces or write a YAML list; a port is not supported)", bad)
	}
	return items, nil
}

// forwarderInput mirrors the shared task's choice: ipa_dns_forwarders if
// defined (empty included), else freeipa_dns_forwarders if defined, else
// the caller's default.
func forwarderInput(r *varReader, host string, fallback []any, fallbackSource string) (any, string) {
	if v, ok := r.get(host, "ipa_dns_forwarders"); ok {
		return v, dnsArchVarRef(host, "ipa_dns_forwarders")
	}
	if v, ok := r.get(host, "freeipa_dns_forwarders"); ok {
		return v, dnsArchVarRef(host, "freeipa_dns_forwarders")
	}
	return fallback, fallbackSource
}

func buildForwarding(r *varReader, primary string, replicas []string) DNSArchForwarding {
	f := DNSArchForwarding{ForwardPolicy: "not_managed_by_pilot", ForwardZones: "not_managed_by_pilot"}
	if !ansibleBool(r.def(primary, "freeipa_setup_dns", true)) {
		f.State = "not_applicable"
		f.Source = dnsArchVarRef(primary, "freeipa_setup_dns") + " is false: the primary runs no named"
	} else {
		var raw any
		raw, f.Source = forwarderInput(r, primary, []any{"8.8.8.8"}, "default ['8.8.8.8'] in playbooks/apply/freeipa-server-apply.yml")
		list, err := normalizeForwarders(raw)
		switch {
		case err != nil:
			f.State = "invalid"
			f.Source += ": " + err.Error()
		case len(list) == 0:
			f.State = "no_forwarders"
		default:
			f.State = "configured"
			f.GlobalForwarders = list
		}
		// ipa-server-install gets the same list as --forwarder flags
		// (or --no-forwarders).
		if err == nil {
			f.ServerInstallForwarders = append(f.ServerInstallForwarders, DNSArchServerInstallFwd{Host: primary, Forwarders: list, Source: f.Source})
		}
	}
	for _, host := range replicas {
		// freeipa-server-replica-apply.yml: ipa_setup_dns =
		// freeipa_setup_dns | default(true); the forwarders go through the
		// same tasks/freeipa-dns-forwarders.yml as the primary's, with []
		// as the default, and are passed as one --forwarder per item (or
		// --no-forwarders when empty) to ipa-replica-install and
		// ipa-dns-install.
		if !ansibleBool(r.def(host, "freeipa_setup_dns", true)) {
			continue
		}
		install := DNSArchServerInstallFwd{Host: host}
		raw, source := forwarderInput(r, host, []any{}, "default [] in playbooks/apply/freeipa-server-replica-apply.yml")
		install.Source = source
		list, err := normalizeForwarders(raw)
		if err != nil {
			install.Error = err.Error()
		} else {
			install.Forwarders = list
		}
		f.ServerInstallForwarders = append(f.ServerInstallForwarders, install)
	}
	f.Unevaluated = r.take()
	if len(f.Unevaluated) > 0 {
		f.State = "unknown"
		f.GlobalForwarders = nil
		f.ServerInstallForwarders = nil
	}
	return f
}

// tierEndpoints mirrors tasks/dns-tier-endpoints.yml: dns_listen_addr |
// default(ansible_host | default(<inventory name>), true) | string | trim.
func tierEndpoints(r *varReader, tierHosts []string) (map[string]string, []string) {
	out := map[string]string{}
	for _, host := range tierHosts {
		out[host] = tierAddr(r, host)
	}
	return out, r.take()
}

func tierAddr(r *varReader, host string) string {
	fallback := r.def(host, "ansible_host", host)
	return strings.TrimSpace(jinjaString(r.defTrue(host, "dns_listen_addr", fallback)))
}

// buildTierHost mirrors dns-apply.yml's pre_tasks for one tier host.
func buildTierHost(r *varReader, m DNSArchModel, host, addr string, endpointsUnevaluated []string) DNSArchTierHost {
	t := DNSArchTierHost{Host: host, State: "computed", Addr: addr}
	t.Upstream = splitListSetting(r.defTrue(host, "dns_upstream", []any{"1.1.1.1"}))
	t.CacheMaxTTL = strings.TrimSpace(jinjaString(r.def(host, "dns_cache_max_ttl", 300)))
	t.CacheMaxNegativeTTL = strings.TrimSpace(jinjaString(r.def(host, "dns_cache_max_negative_ttl", 60)))
	t.DNSSECValidation = ansibleBool(r.def(host, "dns_dnssec_validation", true))

	var freeipaZones []string
	for _, z := range stringItems(r.defTrue(host, "dns_freeipa_zones", []any{})) {
		if z = normalizeZoneName(z); z != "" {
			freeipaZones = append(freeipaZones, z)
		}
	}
	if m.FreeIPAPresent {
		t.FreeIPAServers = m.DNSProviderIPs()
	}
	t.Mode = "forward-only"
	if len(t.FreeIPAServers) > 0 {
		t.Mode = "freeipa-split"
		for _, zone := range append([]string{m.FreeIPADomain}, freeipaZones...) {
			t.StubZones = append(t.StubZones, DNSArchZone{Name: zone, Addrs: t.FreeIPAServers, Source: "FreeIPA"})
		}
	} else if len(freeipaZones) > 0 {
		t.Errors = append(t.Errors, fmt.Sprintf("dns_freeipa_zones %v is only valid when the inventory has FreeIPA DNS (G4)", freeipaZones))
	}

	for _, item := range trimNonEmpty(stringItems(r.defTrue(host, "dns_stub_zones", []any{}))) {
		name, addrs, found := strings.Cut(item, "=")
		if !found {
			t.Errors = append(t.Errors, fmt.Sprintf("dns_stub_zones entry %q has no '=' (G4)", item))
		}
		t.StubZones = append(t.StubZones, DNSArchZone{
			Name:   normalizeZoneName(name),
			Addrs:  trimNonEmpty(strings.Split(addrs, ",")),
			Source: "dns_stub_zones",
		})
	}
	if zones, ok := r.defTrue(host, "dns_zones", []any{}).([]any); ok {
		for _, raw := range zones {
			zone, ok := raw.(map[string]any)
			if !ok {
				t.Errors = append(t.Errors, fmt.Sprintf("dns_zones entry %v is not a mapping", raw))
				continue
			}
			name := normalizeZoneName(jinjaString(zone["name"]))
			stub, hasStub := zone["stub_addr"]
			if !hasStub {
				t.LocalZones = append(t.LocalZones, name)
				continue
			}
			var addrs []string
			if s, isString := stub.(string); isString {
				addrs = []string{strings.TrimSpace(s)}
			} else {
				for _, a := range stringItems(stub) {
					addrs = append(addrs, strings.TrimSpace(a))
				}
			}
			t.StubZones = append(t.StubZones, DNSArchZone{Name: name, Addrs: addrs, Source: "dns_zones"})
		}
	}
	t.Unevaluated = uniqueStrings(append(append([]string(nil), endpointsUnevaluated...), r.take()...))
	if len(t.Unevaluated) > 0 {
		return DNSArchTierHost{Host: host, State: "unknown", Unevaluated: t.Unevaluated}
	}
	return t
}

// buildResolver mirrors tasks/freeipa-dns-client-resolver.yml's provider
// detection and "compute effective nameserver list for THIS host".
func buildResolver(r *varReader, inv networkcheck.ResolvedInventory, host string, tierHosts, leftOut []string) DNSArchResolver {
	res := DNSArchResolver{Host: host, State: "computed"}

	type provider struct{ host, ip string }
	var providers []provider
	for _, p := range inv.OrderedGroupHosts(FreeIPAServerGroup) {
		if ansibleBool(r.def(p, "freeipa_setup_dns", true)) {
			providers = append(providers, provider{p, jinjaString(r.defTrue(p, "ansible_host", p))})
		}
	}
	for _, p := range inv.OrderedGroupHosts(FreeIPAReplicaGroup) {
		if ansibleBool(r.def(p, "freeipa_setup_dns", true)) && !stringIn(leftOut, p) {
			providers = append(providers, provider{p, jinjaString(r.defTrue(p, "ansible_host", p))})
		}
	}
	var providerIPs []string
	isProvider := false
	for _, p := range providers {
		providerIPs = append(providerIPs, p.ip)
		if p.host == host {
			isProvider = true
		}
	}
	var tierAddrs []string
	for _, t := range tierHosts {
		tierAddrs = append(tierAddrs, tierAddr(r, t))
	}

	explicit := r.defTrue(host, "freeipa_dns_client_servers", []any{})
	explicitList, isList := explicit.([]any)
	switch {
	case !isList:
		res.Error = fmt.Sprintf("freeipa_dns_client_servers must be a list, got %v (the resolver task's gate fails)", explicit)
	case len(explicitList) > 0:
		res.Selection = "explicit_override"
		res.Servers = stringItems(explicitList)
	case isProvider:
		res.Selection = "provider_self"
		res.Servers = []string{"127.0.0.1"}
		for _, p := range providers {
			if p.host != host {
				res.Servers = append(res.Servers, p.ip)
			}
		}
	case len(tierAddrs) > 0:
		res.Selection = "tier_first"
		res.Servers = uniqueStrings(append(append([]string(nil), tierAddrs...), providerIPs...))
		if len(res.Servers) > 3 {
			res.Servers = res.Servers[:3]
		}
	default:
		res.Selection = "freeipa_only"
		res.Servers = providerIPs
	}
	if res.Error == "" && len(res.Servers) == 0 {
		res.Selection = "none"
		res.Error = "no FreeIPA DNS-providing host and no explicit freeipa_dns_client_servers (the resolver task's gate fails)"
	}
	if len(res.Servers) > 1 {
		res.Options = []string{"timeout:1", "attempts:2"}
	}
	res.Unevaluated = r.take()
	if len(res.Unevaluated) > 0 {
		return DNSArchResolver{Host: host, State: "unknown", Unevaluated: res.Unevaluated}
	}
	return res
}

func sortDeclared(vars []DNSArchVar) {
	sort.Slice(vars, func(i, j int) bool {
		if vars[i].Host != vars[j].Host {
			return vars[i].Host < vars[j].Host
		}
		return vars[i].Name < vars[j].Name
	})
}
