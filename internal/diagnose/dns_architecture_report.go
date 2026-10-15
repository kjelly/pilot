package diagnose

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Fact states. "absent" means pilot looked and the thing is not there;
// "unknown" means pilot could not tell. They are never merged.
// KerberosRefusedPrivileged is the Kerberos state when the approved
// principal's rights on the global DNS configuration (cn=dns) include
// write.
const KerberosRefusedPrivileged = "refused_privileged"

const (
	FactObserved         = "observed"
	FactAbsent           = "absent"
	FactUnknown          = "unknown"
	FactAuthRequired     = "auth_required"
	FactPermissionDenied = "permission_denied"
	FactUnreachable      = "unreachable"
	FactNotApplicable    = "not_applicable"
	FactError            = "error"
)

// DNSArchFact is one observed fact with the evidence it came from.
// Evidence entries are "step:<step id>#<section>" for live output (the step
// is in the report's steps list and the audit record) and
// "inventory:hostvars[<host>].<var>" for declared values.
type DNSArchFact struct {
	State    string   `json:"state"`
	Value    any      `json:"value,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

func dnsArchEvidence(stepID, section string) []string {
	return []string{"step:" + stepID + "#" + section}
}

// DNSArchKerberos is the authenticated-read status. State is
// not_configured, available, auth_required, refused_privileged (the
// approved principal can write FreeIPA's DNS configuration, so pilot does
// not use what it read), unreachable or not_applicable.
type DNSArchKerberos struct {
	State     string   `json:"state"`
	Principal string   `json:"principal,omitempty"`
	Keytab    string   `json:"keytab,omitempty"`
	Host      string   `json:"host,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Evidence  []string `json:"evidence,omitempty"`
}

// DNSArchObservedProvider is one FreeIPA DNS provider's live state.
type DNSArchObservedProvider struct {
	Host string `json:"host"`
	// LeftOut says why the playbooks leave this replica out (FreeIPA does
	// not list it as a DNS server yet); its failing probes are expected.
	LeftOut     string      `json:"left_out,omitempty"`
	IP          string      `json:"ip"`
	Reachable   DNSArchFact `json:"reachable"`
	RemoteUser  string      `json:"remote_user,omitempty"`
	NamedActive DNSArchFact `json:"named_active"`
	SOA         DNSArchFact `json:"soa"`
	NS          DNSArchFact `json:"ns"`
	LDAPSRV     DNSArchFact `json:"ldap_srv"`
	KerberosSRV DNSArchFact `json:"kerberos_srv"`
	Internal    DNSArchFact `json:"internal_name"`
}

// DNSArchServerForwarders is one FreeIPA DNS server's own forwarder
// setting (ipa dnsserver-find), which takes precedence over the global
// list for queries that server answers.
type DNSArchServerForwarders struct {
	Server        string   `json:"server"`
	Forwarders    []string `json:"forwarders,omitempty"`
	ForwardPolicy string   `json:"forward_policy,omitempty"`
}

// DNSArchForwardZone is one FreeIPA forward zone.
type DNSArchForwardZone struct {
	Zone          string   `json:"zone"`
	Active        string   `json:"active,omitempty"`
	Forwarders    []string `json:"forwarders,omitempty"`
	ForwardPolicy string   `json:"forward_policy,omitempty"`
}

// DNSArchObservedFreeIPA is FreeIPA's DNS configuration as read through
// the approved principal.
type DNSArchObservedFreeIPA struct {
	QueriedOn        string      `json:"queried_on,omitempty"`
	GlobalForwarders DNSArchFact `json:"global_forwarders"`
	ForwardPolicy    DNSArchFact `json:"forward_policy"`
	ServerForwarders DNSArchFact `json:"server_forwarders"`
	ForwardZones     DNSArchFact `json:"forward_zones"`
	Zones            DNSArchFact `json:"zones"`
}

// DNSArchObservedTier is one dns tier host's live state.
type DNSArchObservedTier struct {
	Host               string        `json:"host"`
	Addr               string        `json:"addr,omitempty"`
	InternalName       string        `json:"internal_name,omitempty"`
	ExternalName       string        `json:"external_name,omitempty"`
	Reachable          DNSArchFact   `json:"reachable"`
	RemoteUser         string        `json:"remote_user,omitempty"`
	UnboundActive      DNSArchFact   `json:"unbound_active"`
	Forwards           DNSArchFact   `json:"forwards"`
	Stubs              DNSArchFact   `json:"stubs"`
	Identity           DNSArchFact   `json:"identity"`
	InternalResolution DNSArchFact   `json:"internal_resolution"`
	ExternalResolution DNSArchFact   `json:"external_resolution"`
	ProviderAuthority  []DNSArchFact `json:"provider_authority,omitempty"`
}

// DNSArchObservedClient is the requested client host's live resolver.
type DNSArchObservedClient struct {
	Host           string      `json:"host"`
	Reachable      DNSArchFact `json:"reachable"`
	RemoteUser     string      `json:"remote_user,omitempty"`
	Nameservers    DNSArchFact `json:"nameservers"`
	Options        DNSArchFact `json:"options"`
	ResolvedActive DNSArchFact `json:"systemd_resolved_active"`
	ResolvedDNS    DNSArchFact `json:"resolvectl_dns"`
	FirstHop       DNSArchFact `json:"first_hop_identity"`
	Lookup         DNSArchFact `json:"lookup"`
}

// DNSArchObserved is the live layer.
type DNSArchObserved struct {
	// Skipped lists probes pilot planned but did not run, and why
	// (bounds, names it would not pass to a probe); each makes the
	// report partial.
	Skipped   []string                  `json:"skipped,omitempty"`
	Kerberos  DNSArchKerberos           `json:"kerberos"`
	Providers []DNSArchObservedProvider `json:"providers,omitempty"`
	FreeIPA   DNSArchObservedFreeIPA    `json:"freeipa"`
	Tier      []DNSArchObservedTier     `json:"tier,omitempty"`
	Client    *DNSArchObservedClient    `json:"client,omitempty"`
}

// DNSArchDifference compares one effective (declared and derived) value
// with what was observed. Status is match, mismatch, unknown, absent,
// auth_required or not_applicable.
type DNSArchDifference struct {
	Subject  string   `json:"subject"`
	Expected any      `json:"expected,omitempty"`
	Observed any      `json:"observed,omitempty"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence"`
}

// ---- observed builders ----------------------------------------------------------

func unreachableFact(r StepResult) (DNSArchFact, bool) {
	evidence := []string{"step:" + r.Step.ID}
	switch {
	case r.Result.RunErr != nil:
		return DNSArchFact{State: FactUnknown, Detail: r.Result.RunErr.Error(), Evidence: evidence}, false
	case r.Result.Unreachable:
		return DNSArchFact{State: FactUnreachable, Detail: firstLine(r.Result.Stdout), Evidence: evidence}, false
	}
	return DNSArchFact{State: FactObserved, Value: true, Evidence: evidence}, true
}

func sectionFact(stepID string, sections map[string]DNSArchSection, key string, ok bool, fn func(DNSArchSection) DNSArchFact) DNSArchFact {
	if !ok {
		return DNSArchFact{State: FactUnknown, Detail: "not observed: the step did not reach the host", Evidence: []string{"step:" + stepID}}
	}
	s, found := sections[key]
	if !found || !s.Complete {
		return DNSArchFact{State: FactUnknown, Detail: "no complete output (step timed out or stopped)", Evidence: dnsArchEvidence(stepID, key)}
	}
	f := fn(s)
	if f.Evidence == nil {
		f.Evidence = dnsArchEvidence(stepID, key)
	}
	return f
}

func commandMissing(s DNSArchSection) bool {
	return s.RC == 127 || (strings.Contains(s.Output, "not found") && strings.Contains(s.Output, "command"))
}

// activeFact reads `systemctl is-active <unit>`. It exits 0 for a running
// unit, also while it reloads ("reloading"), and 3 with "inactive" or
// "failed" for one that is stopped or not installed. Anything else, such
// as "Failed to connect to bus" (rc 1) or "activating", says nothing about
// whether the service answers, so it is unknown, not "not running".
func activeFact(s DNSArchSection) DNSArchFact {
	state := strings.TrimSpace(s.Output)
	switch {
	case commandMissing(s):
		return DNSArchFact{State: FactUnknown, Detail: firstLine(s.Output)}
	case s.RC == 0:
		return DNSArchFact{State: FactObserved, Value: true, Detail: state}
	case s.RC == 3 && (state == "inactive" || state == "failed"):
		return DNSArchFact{State: FactObserved, Value: false, Detail: state}
	}
	return DNSArchFact{State: FactUnknown, Detail: fmt.Sprintf("systemctl is-active exited %d: %s", s.RC, firstLine(s.Output))}
}

func digFact(server, name, qtype string) func(DNSArchSection) DNSArchFact {
	return func(s DNSArchSection) DNSArchFact {
		if commandMissing(s) {
			return DNSArchFact{State: FactUnknown, Detail: "dig is not installed: " + firstLine(s.Output)}
		}
		q := ParseDigComments(server, name, qtype, s.Output, s.RC)
		if q.Error != "" {
			return DNSArchFact{State: FactUnknown, Value: q, Detail: "no answer from " + server + ": " + q.Error}
		}
		switch {
		case q.Status == "NXDOMAIN":
			return DNSArchFact{State: FactAbsent, Value: q, Detail: "NXDOMAIN"}
		case q.Status == "NOERROR" && len(q.Answers) == 0:
			return DNSArchFact{State: FactAbsent, Value: q, Detail: "NOERROR, no " + qtype + " record"}
		case q.Status != "NOERROR":
			// The server answered, with an error rcode (SERVFAIL,
			// REFUSED, ...): the lookup failed.
			return DNSArchFact{State: FactError, Value: q, Detail: server + " answered " + q.Status}
		}
		return DNSArchFact{State: FactObserved, Value: q}
	}
}

// dnsAnswered reports whether a dig fact is a successful answer: the
// server replied NOERROR with at least one record. A fact can be observed
// without that: digFact keeps a received SERVFAIL or REFUSED as observed
// (the server did answer), and that is a failed lookup, not a resolution.
func dnsAnswered(f DNSArchFact) (DNSQueryResult, bool) {
	q, ok := f.Value.(DNSQueryResult)
	return q, ok && f.State == FactObserved && q.Error == "" && q.Status == "NOERROR" && len(q.Answers) > 0
}

func remoteUser(sections map[string]DNSArchSection) string {
	if s, ok := sections["whoami"]; ok && s.Complete && s.RC == 0 {
		return strings.TrimSpace(s.Output)
	}
	return ""
}

// BuildDNSArchObservedProvider interprets one provider step.
func BuildDNSArchObservedProvider(p DNSArchProvider, domain, internalName string, r StepResult) DNSArchObservedProvider {
	out := DNSArchObservedProvider{Host: p.InventoryHost, IP: p.IP}
	reach, ok := unreachableFact(r)
	out.Reachable = reach
	sections := ParseDNSArchSections(r.Result.Stdout)
	if ok {
		out.RemoteUser = remoteUser(sections)
	}
	id := r.Step.ID
	out.NamedActive = sectionFact(id, sections, "named", ok, activeFact)
	out.SOA = sectionFact(id, sections, "soa", ok, digFact(p.IP, domain+".", "SOA"))
	out.NS = sectionFact(id, sections, "ns", ok, digFact(p.IP, domain+".", "NS"))
	out.LDAPSRV = sectionFact(id, sections, "srv_ldap", ok, digFact(p.IP, "_ldap._tcp."+domain+".", "SRV"))
	out.KerberosSRV = sectionFact(id, sections, "srv_kerberos", ok, digFact(p.IP, "_kerberos._udp."+domain+".", "SRV"))
	if internalName == "" || internalName == "-" {
		out.Internal = DNSArchFact{State: FactNotApplicable, Detail: "no valid internal name to resolve (see skipped)"}
	} else {
		out.Internal = sectionFact(id, sections, "internal", ok, digFact(p.IP, internalName, "A"))
	}
	return out
}

// BuildDNSArchObservedFreeIPA interprets the authenticated step and the
// Kerberos state it implies.
func BuildDNSArchObservedFreeIPA(host, principal, keytab string, r StepResult) (DNSArchObservedFreeIPA, DNSArchKerberos) {
	out := DNSArchObservedFreeIPA{QueriedOn: host}
	k := DNSArchKerberos{Principal: principal, Keytab: keytab, Host: host}
	reach, ok := unreachableFact(r)
	id := r.Step.ID
	gate := func(state, detail string) {
		f := DNSArchFact{State: state, Detail: detail, Evidence: []string{"step:" + id}}
		out.GlobalForwarders, out.ForwardPolicy, out.ServerForwarders, out.ForwardZones, out.Zones = f, f, f, f, f
	}
	if !ok {
		k.State, k.Detail, k.Evidence = FactUnreachable, reach.Detail, reach.Evidence
		gate(reach.State, reach.Detail)
		return out, k
	}
	sections := ParseDNSArchSections(r.Result.Stdout)
	kinit, found := sections["kinit"]
	switch {
	case !found || !kinit.Complete:
		k.State, k.Detail = FactUnknown, "kinit did not finish"
		gate(FactUnknown, k.Detail)
		k.Evidence = dnsArchEvidence(id, "kinit")
		return out, k
	case kinit.RC != 0:
		k.State, k.Detail = FactAuthRequired, "kinit with the approved keytab failed: "+firstLine(kinit.Output)
		k.Evidence = dnsArchEvidence(id, "kinit")
		gate(FactAuthRequired, k.Detail)
		return out, k
	}
	k.State, k.Evidence = "available", dnsArchEvidence(id, "kinit")

	// FreeIPA hides what a principal may not read instead of refusing:
	// without the DNS read permissions `ipa dnsconfig-show` prints "Global
	// DNS configuration is empty" and every -find prints "Number of entries
	// returned 0" with rc 1, exactly as when there is nothing to show
	// (captured on FreeIPA 4.13.4, docs/evidence/dns-architecture-diagnose/).
	// So "empty" is only reported as absent when pilot can show the
	// principal could have read it: --rights for the global configuration,
	// and for the -find results the DNS servers FreeIPA lists in
	// "IPA DNS servers" (readable without those permissions) — a FreeIPA
	// that serves DNS always has its own server entry and its domain zone.
	cfg := firstIPAEntry(sections["dnsconfig"])
	dnsServers := SplitIPAList(cfg["IPA DNS servers"])
	rights := ParseIPARights(cfg["attributelevelrights"])
	// The principal must be read-only. --rights shows what it may do to
	// the global DNS configuration; any write right (w, o, or the self
	// forms W, O) means it is not the reader the operator should approve,
	// and nothing it read is reported.
	var writable []string
	for attr, r := range rights {
		if strings.ContainsAny(r, "woWO") {
			writable = append(writable, attr+"="+r)
		}
	}
	if len(writable) > 0 {
		sort.Strings(writable)
		k.State = KerberosRefusedPrivileged
		k.Detail = fmt.Sprintf("%s is not read-only: FreeIPA grants it %s on the DNS configuration; approve a principal that only has the read permissions (docs/runbooks/dns-architecture-diagnose.md §2)", principal, strings.Join(writable, ", "))
		gate(FactAuthRequired, k.Detail)
		return out, k
	}
	readable := func(attr, permission string, f DNSArchFact) DNSArchFact {
		r, known := rights[attr]
		switch {
		case f.State != FactObserved && f.State != FactAbsent:
			return f
		case !known:
			return DNSArchFact{State: FactUnknown, Detail: "FreeIPA did not report the principal's rights on " + attr + ", so an empty value cannot be told from a hidden one", Evidence: f.Evidence}
		case !strings.Contains(r, "r"):
			return DNSArchFact{State: FactPermissionDenied, Detail: "the principal cannot read " + attr + " (grant " + permission + ")", Evidence: f.Evidence}
		}
		return f
	}
	findEmpty := func(s DNSArchSection) bool {
		return s.RC == 1 && strings.Contains(s.Output, "Number of entries returned 0")
	}
	ipaFact := func(key string, fn func([]map[string]string) DNSArchFact) DNSArchFact {
		return sectionFact(id, sections, key, true, func(s DNSArchSection) DNSArchFact {
			if s.RC != 0 && !findEmpty(s) {
				state, detail := classifyIPAError(s.Output)
				return DNSArchFact{State: state, Detail: detail}
			}
			return fn(ParseIPAAttributes(s.Output))
		})
	}
	out.GlobalForwarders = readable("idnsforwarders", "System: Read DNS Configuration", ipaFact("dnsconfig", func(entries []map[string]string) DNSArchFact {
		if len(entries) == 0 || entries[0]["Global forwarders"] == "" {
			return DNSArchFact{State: FactAbsent, Detail: "no global forwarders"}
		}
		return DNSArchFact{State: FactObserved, Value: SplitIPAList(entries[0]["Global forwarders"])}
	}))
	out.ForwardPolicy = readable("idnsforwardpolicy", "System: Read DNS Configuration", ipaFact("dnsconfig", func(entries []map[string]string) DNSArchFact {
		if len(entries) == 0 || entries[0]["Forward policy"] == "" {
			return DNSArchFact{State: FactAbsent, Detail: "no global forward policy set (FreeIPA's default applies)"}
		}
		return DNSArchFact{State: FactObserved, Value: entries[0]["Forward policy"]}
	}))
	hidden := func(f DNSArchFact, what, permission string) DNSArchFact {
		if f.State == FactAbsent && len(dnsServers) > 0 {
			return DNSArchFact{State: FactPermissionDenied, Detail: fmt.Sprintf("FreeIPA serves DNS on %s but no %s is visible to the principal (grant %s)", strings.Join(dnsServers, ", "), what, permission), Evidence: f.Evidence}
		}
		return f
	}
	out.ServerForwarders = hidden(ipaFact("dnsserver", func(entries []map[string]string) DNSArchFact {
		var servers []DNSArchServerForwarders
		for _, e := range entries {
			if e["Server name"] == "" {
				continue
			}
			servers = append(servers, DNSArchServerForwarders{Server: e["Server name"], Forwarders: SplitIPAList(e["Forwarders"]), ForwardPolicy: e["Forward policy"]})
		}
		if len(servers) == 0 {
			return DNSArchFact{State: FactAbsent, Detail: "no DNS servers listed"}
		}
		return DNSArchFact{State: FactObserved, Value: servers}
	}), "DNS server entry", "System: Read DNS Servers Configuration")
	out.Zones = hidden(ipaFact("zones", func(entries []map[string]string) DNSArchFact {
		var zones []string
		for _, e := range entries {
			if z := e["Zone name"]; z != "" {
				zones = append(zones, z)
			}
		}
		if len(zones) == 0 {
			return DNSArchFact{State: FactAbsent, Detail: "no authoritative zones"}
		}
		return DNSArchFact{State: FactObserved, Value: zones}
	}), "DNS zone", "System: Read DNS Entries")
	out.ForwardZones = ipaFact("forwardzones", func(entries []map[string]string) DNSArchFact {
		var zones []DNSArchForwardZone
		for _, e := range entries {
			if e["Zone name"] == "" {
				continue
			}
			zones = append(zones, DNSArchForwardZone{Zone: e["Zone name"], Active: e["Active zone"], Forwarders: SplitIPAList(e["Zone forwarders"]), ForwardPolicy: e["Forward policy"]})
		}
		if len(zones) == 0 {
			return DNSArchFact{State: FactAbsent, Detail: "no forward zones"}
		}
		return DNSArchFact{State: FactObserved, Value: zones}
	})
	// Forward zones and zones are both idnsname=* entries under one
	// permission (System: Read DNS Entries), so hidden zones mean hidden
	// forward zones; an empty forward zone list proves nothing then.
	if out.Zones.State == FactPermissionDenied && out.ForwardZones.State == FactAbsent {
		out.ForwardZones = DNSArchFact{State: FactPermissionDenied, Detail: out.Zones.Detail, Evidence: out.ForwardZones.Evidence}
	}
	return out, k
}

// BuildDNSArchObservedTier interprets one tier step.
func BuildDNSArchObservedTier(t DNSArchTierHost, internalName, externalName string, providerIPs []string, domain string, r StepResult) DNSArchObservedTier {
	out := DNSArchObservedTier{Host: t.Host, Addr: t.Addr, InternalName: internalName, ExternalName: externalName}
	reach, ok := unreachableFact(r)
	out.Reachable = reach
	sections := ParseDNSArchSections(r.Result.Stdout)
	if ok {
		out.RemoteUser = remoteUser(sections)
	}
	id := r.Step.ID
	out.UnboundActive = sectionFact(id, sections, "unbound", ok, activeFact)
	zoneList := func(kind string) func(DNSArchSection) DNSArchFact {
		return func(s DNSArchSection) DNSArchFact {
			if s.RC != 0 {
				return DNSArchFact{State: FactUnknown, Detail: "unbound-control failed: " + firstLine(s.Output)}
			}
			zones := ParseUnboundZoneList(s.Output, kind)
			if len(zones) == 0 {
				return DNSArchFact{State: FactAbsent, Detail: "no " + kind + " zones"}
			}
			return DNSArchFact{State: FactObserved, Value: zones}
		}
	}
	out.Forwards = sectionFact(id, sections, "forwards", ok, zoneList("forward"))
	out.Stubs = sectionFact(id, sections, "stubs", ok, zoneList("stub"))
	out.Identity = sectionFact(id, sections, "identity", ok, func(s DNSArchSection) DNSArchFact {
		v := strings.Trim(strings.TrimSpace(s.Output), `"`)
		if s.RC != 0 || v == "" || strings.HasPrefix(v, ";;") {
			return DNSArchFact{State: FactUnknown, Detail: firstNonEmptyString(firstLine(s.Output), "no id.server CH TXT answer")}
		}
		return DNSArchFact{State: FactObserved, Value: v}
	})
	if internalName == "" {
		out.InternalResolution = DNSArchFact{State: FactNotApplicable, Detail: "no internal name to test (no FreeIPA in the inventory and none given)"}
	} else {
		out.InternalResolution = sectionFact(id, sections, "internal", ok, digFact("127.0.0.1", internalName, "A"))
	}
	extName, extType := externalName, "A"
	if externalName == "." {
		extType = "NS"
	}
	out.ExternalResolution = sectionFact(id, sections, "external", ok, func(s DNSArchSection) DNSArchFact {
		f := digFact("127.0.0.1", extName, extType)(s)
		q, _ := f.Value.(DNSQueryResult)
		switch f.State {
		case FactError:
			// The tier answered with an error rcode (SERVFAIL, REFUSED):
			// it did not resolve the name.
			f.Detail = fmt.Sprintf("the tier answered %s %s with %s", extName, extType, q.Status)
		case FactAbsent:
			// NXDOMAIN, or NOERROR without a record of the asked type
			// (for example a CNAME whose target has none).
			f.Detail = fmt.Sprintf("the tier answered %s %s with %s and no %s record", extName, extType, q.Status, extType)
		case FactObserved:
			f.Detail = "an answer proves the tier can resolve external names, not which upstream answered; the configured forwarders are in forwards"
		}
		return f
	})
	if domain != "" {
		for _, ip := range providerIPs {
			key := "authority@" + ip
			out.ProviderAuthority = append(out.ProviderAuthority, sectionFact(id, sections, key, ok, func(s DNSArchSection) DNSArchFact {
				f := digFact(ip, domain+".", "SOA")(s)
				if q, isQuery := f.Value.(DNSQueryResult); isQuery && q.Error == "" {
					f.State = FactObserved
					f.Detail = fmt.Sprintf("%s answered %s, authoritative=%t", ip, q.Status, q.Authoritative)
				}
				return f
			}))
		}
	}
	return out
}

// BuildDNSArchObservedClient interprets the client step. tierAddrs are the
// addresses of the dns tier hosts the client may use (DNSArchModel.TierAddrs):
// a first nameserver among them that answers id.server with an error rcode
// is a failed query; any other resolver that does is simply not a tier host.
func BuildDNSArchObservedClient(host string, r StepResult, tierAddrs []string) DNSArchObservedClient {
	out := DNSArchObservedClient{Host: host}
	reach, ok := unreachableFact(r)
	out.Reachable = reach
	sections := ParseDNSArchSections(r.Result.Stdout)
	if ok {
		out.RemoteUser = remoteUser(sections)
	}
	id := r.Step.ID
	lines := func(s DNSArchSection) []string { return trimNonEmpty(strings.Split(s.Output, "\n")) }
	out.Nameservers = sectionFact(id, sections, "nameservers", ok, func(s DNSArchSection) DNSArchFact {
		if s.RC != 0 {
			return DNSArchFact{State: FactUnknown, Detail: firstLine(s.Output)}
		}
		if ns := lines(s); len(ns) > 0 {
			return DNSArchFact{State: FactObserved, Value: ns}
		}
		return DNSArchFact{State: FactAbsent, Detail: "no nameserver line in /etc/resolv.conf"}
	})
	out.Options = sectionFact(id, sections, "options", ok, func(s DNSArchSection) DNSArchFact {
		if s.RC != 0 {
			return DNSArchFact{State: FactUnknown, Detail: firstLine(s.Output)}
		}
		if opts := lines(s); len(opts) > 0 {
			return DNSArchFact{State: FactObserved, Value: opts}
		}
		return DNSArchFact{State: FactAbsent}
	})
	out.ResolvedActive = sectionFact(id, sections, "resolved", ok, activeFact)
	out.ResolvedDNS = sectionFact(id, sections, "resolvectl", ok, func(s DNSArchSection) DNSArchFact {
		if s.RC != 0 {
			if out.ResolvedActive.State == FactObserved && out.ResolvedActive.Value == false {
				// resolvectl has nothing to ask when systemd-resolved
				// is not running; that is not a gap in the evidence.
				return DNSArchFact{State: FactNotApplicable, Detail: "systemd-resolved is " + out.ResolvedActive.Detail + ": " + firstLine(s.Output)}
			}
			return DNSArchFact{State: FactUnknown, Detail: firstLine(s.Output)}
		}
		return DNSArchFact{State: FactObserved, Value: lines(s)}
	})
	if _, probed := sections["first_hop"]; probed || !ok {
		ns := ""
		if v, isList := out.Nameservers.Value.([]string); isList && len(v) > 0 {
			ns = v[0]
		}
		out.FirstHop = sectionFact(id, sections, "first_hop", ok, func(s DNSArchSection) DNSArchFact {
			f := digFact(ns, "id.server", "TXT")(s)
			q, _ := f.Value.(DNSQueryResult)
			switch f.State {
			case FactObserved:
				v := strings.Trim(q.Answers[0], `"`)
				if strings.HasPrefix(v, "pilot-dns:") {
					return DNSArchFact{State: FactObserved, Value: v, Detail: "the first nameserver is a pilot dns tier host"}
				}
				return DNSArchFact{State: FactObserved, Value: v, Detail: "the first nameserver is not a pilot dns tier host"}
			case FactAbsent:
				// A pilot dns tier host always answers id.server; a
				// server that answers without it is something else.
				return DNSArchFact{State: FactObserved, Value: "", Detail: "the first nameserver is not a pilot dns tier host (" + f.Detail + " for id.server CH TXT)"}
			case FactError:
				if !slices.Contains(tierAddrs, ns) {
					// An error rcode from a resolver that is not a tier
					// address: unbound answers id.server itself, so this
					// is something else. systemd-resolved's stub
					// (127.0.0.53) answers SERVFAIL, libvirt's dnsmasq
					// NOTIMP.
					return DNSArchFact{State: FactObserved, Value: "", Detail: "the first nameserver is not a pilot dns tier host (" + f.Detail + " for id.server CH TXT)"}
				}
				// A tier address that answers with an error: a tier
				// whose access-control excludes this host refuses it.
			}
			// No answer, or an error rcode from a tier address.
			return f
		})
	} else {
		out.FirstHop = DNSArchFact{State: FactNotApplicable, Detail: "no nameserver to ask"}
	}
	out.Lookup = sectionFact(id, sections, "lookup", ok, func(s DNSArchSection) DNSArchFact {
		if s.RC == 0 {
			return DNSArchFact{State: FactObserved, Value: lines(s)}
		}
		if s.RC == 2 {
			return DNSArchFact{State: FactAbsent, Detail: "getent: name not found"}
		}
		return DNSArchFact{State: FactUnknown, Detail: firstLine(s.Output)}
	})
	return out
}

// DNSArchUnregisteredReplicas mirrors tasks/freeipa-dns-providers-live.yml:
// the NS set FreeIPA answers authoritatively (from any provider's NS
// probe), and the replicas that leave freeipa_setup_dns unset, did not
// answer for the zone authoritatively themselves (their own NS probe,
// +norec, as tasks/freeipa-dns-providers-live.yml asks) and are not in
// that set. Nothing is left out when
// no provider answered.
func DNSArchUnregisteredReplicas(m DNSArchModel, observed []DNSArchObservedProvider) (leftOut, registered []string) {
	seen := map[string]bool{}
	selfAnswered := map[string]bool{}
	for _, op := range observed {
		if q, ok := dnsAnswered(op.NS); ok && q.Status == "NOERROR" && q.Authoritative {
			selfAnswered[op.Host] = true
		}
		if q, ok := dnsAnswered(op.NS); ok && q.Authoritative {
			for _, a := range q.Answers {
				n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
				if !seen[n] {
					seen[n] = true
					registered = append(registered, n)
				}
			}
		}
	}
	if len(registered) == 0 {
		return nil, nil
	}
	for _, p := range m.Providers {
		if p.Kind == "replica" && p.DNSProvider && !p.DNSProviderExplicit && !selfAnswered[p.InventoryHost] && !seen[strings.TrimSuffix(strings.ToLower(p.FQDN), ".")] {
			leftOut = append(leftOut, p.InventoryHost)
		}
	}
	return leftOut, registered
}

// ---- differences -----------------------------------------------------------------

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sameSet(a, b []string) bool {
	return strings.Join(sortedCopy(uniqueStrings(a)), ",") == strings.Join(sortedCopy(uniqueStrings(b)), ",")
}

func compareFact(subject string, expected []string, f DNSArchFact, observed []string, ordered bool, declaredEvidence []string) DNSArchDifference {
	d := DNSArchDifference{Subject: subject, Expected: expected, Evidence: append(append([]string(nil), declaredEvidence...), f.Evidence...)}
	switch f.State {
	case FactObserved:
		d.Observed = observed
		same := sameSet(expected, observed)
		if ordered {
			same = strings.Join(expected, ",") == strings.Join(observed, ",")
		}
		if same {
			d.Status = "match"
		} else {
			d.Status = "mismatch"
		}
	case FactAbsent:
		if len(expected) == 0 {
			d.Status = "match"
		} else {
			d.Status = "absent"
		}
		d.Detail = f.Detail
	case FactAuthRequired:
		d.Status, d.Detail = FactAuthRequired, f.Detail
	default:
		d.Status, d.Detail = FactUnknown, f.Detail
	}
	return d
}

func zoneServers(f DNSArchFact, zone string) ([]string, bool) {
	zones, _ := f.Value.([]DNSArchZoneServers)
	for _, z := range zones {
		if strings.TrimSuffix(z.Zone, ".") == strings.TrimSuffix(zone, ".") {
			return z.Servers, true
		}
	}
	return nil, false
}

func tierVarEvidence(host string, names ...string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, dnsArchVarRef(host, n))
	}
	return out
}

// BuildDNSArchDifferences compares the effective model with the live layer.
func BuildDNSArchDifferences(m DNSArchModel, o DNSArchObserved) []DNSArchDifference {
	var diffs []DNSArchDifference
	effTier := map[string]DNSArchTierHost{}
	for _, t := range m.Tier {
		effTier[t.Host] = t
	}
	for _, ot := range o.Tier {
		t := effTier[ot.Host]
		if t.State != "computed" {
			diffs = append(diffs, DNSArchDifference{Subject: "tier " + ot.Host + " configuration", Status: FactUnknown, Detail: "the declared settings are Jinja templates the model cannot evaluate", Evidence: t.Unevaluated})
			continue
		}
		// Forward zone ".": exactly the upstream list.
		f := ot.Forwards
		observed, found := zoneServers(f, ".")
		if f.State == FactObserved && !found {
			f = DNSArchFact{State: FactAbsent, Detail: "no forward zone for .", Evidence: f.Evidence}
		}
		diffs = append(diffs, compareFact("tier "+ot.Host+" forward zone . (external upstream)", t.Upstream, f, observed, false, tierVarEvidence(ot.Host, "dns_upstream")))
		// Every stub zone with exactly its servers.
		for _, z := range t.StubZones {
			s := ot.Stubs
			observed, found := zoneServers(s, z.Name)
			if s.State == FactObserved && !found {
				s = DNSArchFact{State: FactAbsent, Detail: "no stub zone " + z.Name, Evidence: s.Evidence}
			}
			evidence := tierVarEvidence(ot.Host, "dns_freeipa_zones", "dns_stub_zones", "dns_zones")
			if z.Source == "FreeIPA" {
				evidence = []string{"inventory:groups[freeipa-server]", "inventory:groups[freeipa-server-replica]"}
			}
			diffs = append(diffs, compareFact("tier "+ot.Host+" stub zone "+z.Name+" ("+z.Source+")", z.Addrs, s, observed, false, evidence))
		}
		// Stub zones the tier serves that pilot does not declare. unbound
		// always lists its built-in root hints as `. IN stub prime
		// <root servers>`; the forward zone for . overrides it, so it is
		// not a declaration gap.
		if zones, isList := ot.Stubs.Value.([]DNSArchZoneServers); isList {
			for _, z := range zones {
				if z.Zone == "." {
					continue
				}
				declared := false
				for _, ez := range t.StubZones {
					if strings.TrimSuffix(z.Zone, ".") == ez.Name {
						declared = true
					}
				}
				if !declared {
					diffs = append(diffs, DNSArchDifference{Subject: "tier " + ot.Host + " stub zone " + z.Zone, Observed: z.Servers, Status: "mismatch", Detail: "served by unbound but not declared in the inventory", Evidence: ot.Stubs.Evidence})
				}
			}
		}
		// The tier answers as itself.
		wantID := "pilot-dns:" + ot.Host
		idDiff := DNSArchDifference{Subject: "tier " + ot.Host + " identity (id.server CH TXT)", Expected: wantID, Evidence: ot.Identity.Evidence}
		switch ot.Identity.State {
		case FactObserved:
			idDiff.Observed = ot.Identity.Value
			if ot.Identity.Value == wantID {
				idDiff.Status = "match"
			} else {
				idDiff.Status = "mismatch"
			}
		default:
			idDiff.Status, idDiff.Detail = FactUnknown, ot.Identity.Detail
		}
		diffs = append(diffs, idDiff)
	}

	// FreeIPA providers answer authoritatively for the domain.
	for _, op := range o.Providers {
		p, _ := m.Provider(op.Host)
		d := DNSArchDifference{Subject: "FreeIPA " + op.Host + " authoritative for " + m.FreeIPADomain, Expected: true, Evidence: append([]string{dnsArchVarRef(op.Host, "freeipa_setup_dns")}, op.SOA.Evidence...)}
		q, isQuery := op.SOA.Value.(DNSQueryResult)
		switch {
		case !p.DNSProvider || p.LeftOut:
			continue
		case (op.SOA.State == FactObserved || op.SOA.State == FactError) && isQuery:
			d.Observed = q.Authoritative
			if q.Authoritative && q.Status == "NOERROR" {
				d.Status = "match"
			} else {
				d.Status = "mismatch"
				d.Detail = fmt.Sprintf("status %s, flags %v", q.Status, q.Flags)
			}
		case op.SOA.State == FactAbsent:
			d.Status, d.Detail = "absent", op.SOA.Detail
		default:
			d.Status, d.Detail = FactUnknown, op.SOA.Detail
		}
		diffs = append(diffs, d)
	}

	// Global forwarders.
	if m.FreeIPAPresent {
		ev := []string{}
		if strings.HasPrefix(m.Forwarding.Source, "inventory:") {
			ev = append(ev, m.Forwarding.Source)
		}
		switch m.Forwarding.State {
		case "configured", "no_forwarders":
			diffs = append(diffs, compareFact("FreeIPA global forwarders", m.Forwarding.GlobalForwarders, o.FreeIPA.GlobalForwarders, factStrings(o.FreeIPA.GlobalForwarders), false, ev))
		case "unknown":
			diffs = append(diffs, DNSArchDifference{Subject: "FreeIPA global forwarders", Status: FactUnknown, Detail: "the declared forwarders are Jinja templates the model cannot evaluate", Evidence: m.Forwarding.Unevaluated})
		}
		// Each DNS server has its own forwarder setting, which its named
		// prefers over the global list: set by the installer's
		// --forwarder, and on every apply since 2026-10-15 by
		// freeipa-server-apply.yml / freeipa-server-replica-apply.yml
		// (ipa dnsserver-mod), so a mismatch means no apply since the
		// inventory changed.
		servers, _ := o.FreeIPA.ServerForwarders.Value.([]DNSArchServerForwarders)
		for _, sf := range m.Forwarding.ServerInstallForwarders {
			p, _ := m.Provider(sf.Host)
			if sf.Error != "" || p.LeftOut {
				continue
			}
			f := o.FreeIPA.ServerForwarders
			var ev []string
			if strings.HasPrefix(sf.Source, "inventory:") {
				ev = []string{sf.Source}
			}
			subject := "FreeIPA " + sf.Host + " server forwarders (ipa dnsserver-mod)"
			var observed []string
			if f.State == FactObserved {
				found := false
				for _, s := range servers {
					if strings.EqualFold(strings.TrimSuffix(s.Server, "."), p.FQDN) {
						observed, found = s.Forwarders, true
					}
				}
				if !found {
					// The server itself is missing, which an empty
					// expected forwarder list must not turn into a match.
					diffs = append(diffs, DNSArchDifference{Subject: subject, Expected: sf.Forwarders, Status: "absent",
						Detail: "FreeIPA lists no DNS server entry for " + p.FQDN, Evidence: append(ev, f.Evidence...)})
					continue
				}
			}
			d := compareFact(subject, sf.Forwarders, f, observed, false, ev)
			if d.Status == "mismatch" {
				d.Detail = "the server's own forwarder setting differs from the inventory's; re-apply freeipa-server-apply.yml (primary) or freeipa-server-replica-apply.yml (replica), which set it with ipa dnsserver-mod on every run"
			}
			diffs = append(diffs, d)
		}
	}

	// Internal names through the tier equal FreeIPA's authoritative answer.
	var authoritative *DNSArchObservedProvider
	for i := range o.Providers {
		// Only an authoritative answer is a reference: a SERVFAIL from
		// the provider would otherwise "match" a SERVFAIL through the
		// tier.
		if q, ok := dnsAnswered(o.Providers[i].Internal); ok && q.Authoritative {
			authoritative = &o.Providers[i]
			break
		}
	}
	for _, ot := range o.Tier {
		if ot.InternalResolution.State == FactNotApplicable {
			continue
		}
		tierQ, _ := ot.InternalResolution.Value.(DNSQueryResult)
		d := DNSArchDifference{Subject: "tier " + ot.Host + " answer for " + ot.InternalName + " equals FreeIPA's authoritative answer", Evidence: append([]string(nil), ot.InternalResolution.Evidence...)}
		switch {
		case authoritative == nil:
			d.Status, d.Detail = FactUnknown, "no FreeIPA provider returned an authoritative answer to compare with"
		case ot.InternalResolution.State == FactObserved || ot.InternalResolution.State == FactAbsent || ot.InternalResolution.State == FactError:
			authQ := authoritative.Internal.Value.(DNSQueryResult)
			d.Evidence = append(d.Evidence, authoritative.Internal.Evidence...)
			d.Expected, d.Observed = authQ.Answers, tierQ.Answers
			if tierQ.Status == authQ.Status && sameSet(tierQ.Answers, authQ.Answers) {
				d.Status = "match"
			} else {
				d.Status = "mismatch"
				d.Detail = fmt.Sprintf("tier %s %v, FreeIPA %s %s %v", ot.Host, tierQ.Status, authoritative.Host, authQ.Status, authQ.Answers)
			}
		default:
			d.Status, d.Detail = FactUnknown, ot.InternalResolution.Detail
		}
		diffs = append(diffs, d)
	}

	// Every other DNS provider answers the internal name the way the
	// reference does: a replica whose data diverged answers differently.
	if authoritative != nil {
		refQ := authoritative.Internal.Value.(DNSQueryResult)
		for _, op := range o.Providers {
			p, _ := m.Provider(op.Host)
			if op.Host == authoritative.Host || !p.DNSProvider || p.LeftOut || op.Internal.State == FactNotApplicable {
				continue
			}
			q, isQuery := op.Internal.Value.(DNSQueryResult)
			d := DNSArchDifference{Subject: "FreeIPA " + op.Host + " answer for " + refQ.Name + " equals " + authoritative.Host + "'s", Expected: refQ.Answers,
				Evidence: append(append([]string(nil), op.Internal.Evidence...), authoritative.Internal.Evidence...)}
			switch {
			case isQuery && (op.Internal.State == FactObserved || op.Internal.State == FactAbsent || op.Internal.State == FactError):
				d.Observed = q.Answers
				if q.Status == refQ.Status && q.Authoritative && sameSet(q.Answers, refQ.Answers) {
					d.Status = "match"
				} else {
					d.Status = "mismatch"
					d.Detail = fmt.Sprintf("%s %s aa=%t %v, %s %s %v", op.Host, q.Status, q.Authoritative, q.Answers, authoritative.Host, refQ.Status, refQ.Answers)
				}
			default:
				d.Status, d.Detail = FactUnknown, op.Internal.Detail
			}
			diffs = append(diffs, d)
		}
	}

	// The client's resolver list, in order.
	if o.Client != nil {
		for _, res := range m.Resolvers {
			if res.Host != o.Client.Host {
				continue
			}
			if res.State != "computed" || res.Error != "" {
				detail := res.Error
				if detail == "" {
					detail = "the declared settings are Jinja templates the model cannot evaluate"
				}
				diffs = append(diffs, DNSArchDifference{Subject: "client " + res.Host + " nameservers", Status: FactUnknown, Detail: detail, Evidence: res.Unevaluated})
				continue
			}
			d := compareFact("client "+res.Host+" nameservers ("+res.Selection+")", res.Servers, o.Client.Nameservers, factStrings(o.Client.Nameservers), true, []string{dnsArchVarRef(res.Host, "freeipa_dns_client_servers"), "inventory:groups[dns]"})
			if len(res.ManagedBy) == 0 {
				d.Detail = strings.TrimSpace(d.Detail + " (this host is not in freeipa-dns-client; only internal-endpoint's fleet-wide baseline would write this list)")
			}
			diffs = append(diffs, d)
		}
	}
	return diffs
}

func factStrings(f DNSArchFact) []string {
	v, _ := f.Value.([]string)
	return v
}

// ---- status, findings, paths --------------------------------------------------

// BuildDNSArchStatus returns the report status and its findings. Status is
// auth_required when FreeIPA serves DNS but its configuration could not be
// read with an approved credential (every other fact is still reported),
// partial when any live fact of a reachable host or any comparison is
// unknown, and complete otherwise. Complete means every fact was seen, not
// that DNS works: a failed lookup is a finding. Findings are short
// machine-readable codes with a subject.
func BuildDNSArchStatus(m DNSArchModel, o DNSArchObserved, diffs []DNSArchDifference) (string, []string) {
	var findings []string
	partial := len(m.Unevaluated) > 0
	if !m.TierAssigned {
		findings = append(findings, "dns_tier_not_assigned: the dns role (contracts/dns.yaml) is available but no inventory host is in the dns group; consumers query FreeIPA DNS directly")
	}
	for _, e := range m.ProviderErrors {
		findings = append(findings, "freeipa_pool_invalid: "+e)
	}
	if m.Forwarding.State == "invalid" {
		findings = append(findings, "freeipa_forwarders_invalid: "+m.Forwarding.Source)
	}
	for _, sf := range m.Forwarding.ServerInstallForwarders {
		if sf.Error != "" {
			findings = append(findings, "freeipa_forwarders_invalid: "+sf.Host+": "+sf.Error)
		}
	}
	for _, t := range m.Tier {
		for _, e := range t.Errors {
			findings = append(findings, "dns_tier_settings_invalid: "+t.Host+": "+e)
		}
	}
	if len(m.Unevaluated) > 0 {
		findings = append(findings, "declared_value_unevaluated: "+strings.Join(m.Unevaluated, ", ")+" are Jinja templates the model cannot evaluate")
	}
	for _, sk := range o.Skipped {
		partial = true
		findings = append(findings, "probe_skipped: "+sk)
	}
	// liveFacts names, for one reachable host, every live fact pilot could
	// not determine (live_fact_unknown, which makes the report partial)
	// and every DNS query that got an answer saying the lookup failed
	// (dns_query_failed: an error rcode, NXDOMAIN, or no record of the
	// asked type).
	type namedFact struct {
		name  string
		fact  DNSArchFact
		query bool
	}
	withDetail := func(name, detail string) string {
		if detail == "" {
			return name
		}
		return name + " (" + detail + ")"
	}
	liveFacts := func(host string, facts []namedFact) {
		var unknown, failed []string
		for _, nf := range facts {
			switch {
			case nf.fact.State == FactUnknown || nf.fact.State == FactUnreachable:
				unknown = append(unknown, withDetail(nf.name, nf.fact.Detail))
			case nf.query && (nf.fact.State == FactAbsent || nf.fact.State == FactError):
				failed = append(failed, withDetail(nf.name, nf.fact.Detail))
			}
		}
		if len(unknown) > 0 {
			partial = true
			findings = append(findings, "live_fact_unknown: "+host+": "+strings.Join(unknown, "; "))
		}
		if len(failed) > 0 {
			findings = append(findings, "dns_query_failed: "+host+": "+strings.Join(failed, "; "))
		}
	}
	for _, p := range o.Providers {
		if p.LeftOut != "" {
			// Its failing probes are expected: FreeIPA does not list it
			// as a DNS server, and the playbooks leave it out.
			findings = append(findings, "freeipa_replica_not_dns_server: "+p.LeftOut)
			continue
		}
		if p.Reachable.State == FactNotApplicable {
			continue // not probed: named in probe_skipped
		}
		if p.Reachable.State != FactObserved {
			partial = true
			findings = append(findings, "freeipa_dns_provider_unreachable: "+p.Host+" ("+p.Reachable.Detail+")")
			continue
		}
		if p.NamedActive.State == FactObserved && p.NamedActive.Value == false {
			findings = append(findings, "freeipa_named_not_running: "+p.Host+": named is "+p.NamedActive.Detail)
		}
		liveFacts(p.Host, []namedFact{{"named_active", p.NamedActive, false}, {"soa", p.SOA, true}, {"ns", p.NS, true}, {"ldap_srv", p.LDAPSRV, true}, {"kerberos_srv", p.KerberosSRV, true}, {"internal_name", p.Internal, true}})
	}
	for _, t := range o.Tier {
		if t.Reachable.State != FactObserved {
			partial = true
			findings = append(findings, "dns_tier_host_unreachable: "+t.Host+" ("+t.Reachable.Detail+")")
			continue
		}
		if t.UnboundActive.State == FactObserved && t.UnboundActive.Value == false {
			findings = append(findings, "dns_tier_not_running: "+t.Host+" is in the dns group but unbound is "+t.UnboundActive.Detail+" (assigned, not deployed or stopped)")
		}
		liveFacts(t.Host, []namedFact{{"unbound_active", t.UnboundActive, false}, {"forwards", t.Forwards, false}, {"stubs", t.Stubs, false}, {"identity", t.Identity, false}, {"internal_resolution", t.InternalResolution, true}})
		for _, a := range t.ProviderAuthority {
			q, ok := a.Value.(DNSQueryResult)
			if a.State == FactObserved && ok && q.Status == "NOERROR" && q.Authoritative {
				continue
			}
			if a.State != FactObserved {
				partial = true
			}
			findings = append(findings, "freeipa_dns_not_authoritative_from_tier: "+t.Host+": "+a.Detail)
		}
		ext := t.ExternalResolution
		switch q, resolved := dnsAnswered(ext); {
		case resolved:
			findings = append(findings, "external_resolution_forwarder_unproven: "+t.Host+" resolved "+q.Name+" "+q.Type+"; which upstream answered is not observable, only the configured forward zone is")
		case ext.State == FactUnknown || ext.State == FactUnreachable:
			partial = true
			findings = append(findings, "external_resolution_unknown: "+t.Host+" ("+ext.Detail+")")
		case ext.State != FactNotApplicable:
			findings = append(findings, "external_resolution_failed: "+t.Host+" did not resolve "+t.ExternalName+" ("+ext.Detail+")")
		}
	}
	if o.Client != nil {
		c := o.Client
		if c.Reachable.State != FactObserved {
			partial = true
			findings = append(findings, "client_unreachable: "+c.Host+" ("+c.Reachable.Detail+")")
		} else {
			liveFacts(c.Host, []namedFact{{"nameservers", c.Nameservers, false}, {"options", c.Options, false}, {"systemd_resolved_active", c.ResolvedActive, false}, {"resolvectl_dns", c.ResolvedDNS, false}, {"first_hop_identity", c.FirstHop, true}, {"lookup", c.Lookup, true}})
		}
	}

	// FreeIPA's configuration. kinit can succeed and FreeIPA still refuse
	// the ticket ("did not receive Kerberos credentials"): that is
	// auth_required as well, not a complete report.
	authRequired := o.Kerberos.State == "not_configured" || o.Kerberos.State == FactAuthRequired || o.Kerberos.State == KerberosRefusedPrivileged
	authFinding := "auth_required: " + o.Kerberos.Detail
	if o.Kerberos.State == KerberosRefusedPrivileged {
		authFinding = "freeipa_principal_not_read_only: " + o.Kerberos.Detail
	}
	var configUnknown []string
	permissionReported := false
	for _, nf := range []namedFact{{"global_forwarders", o.FreeIPA.GlobalForwarders, false}, {"forward_policy", o.FreeIPA.ForwardPolicy, false}, {"server_forwarders", o.FreeIPA.ServerForwarders, false}, {"forward_zones", o.FreeIPA.ForwardZones, false}, {"zones", o.FreeIPA.Zones, false}} {
		switch f := nf.fact; f.State {
		case FactPermissionDenied:
			partial = true
			if !permissionReported {
				findings = append(findings, "freeipa_read_permission_missing: "+f.Detail)
				permissionReported = true
			}
		case FactAuthRequired:
			if !authRequired {
				authRequired = true
				authFinding = "auth_required: kinit with the approved keytab succeeded, but FreeIPA did not accept the ticket for " + nf.name + ": " + f.Detail
			}
		case FactUnknown, FactError, FactUnreachable:
			configUnknown = append(configUnknown, withDetail(nf.name, f.Detail))
		}
	}
	if len(configUnknown) > 0 {
		partial = true
		host := o.FreeIPA.QueriedOn
		if host == "" {
			host = "FreeIPA"
		}
		findings = append(findings, "live_fact_unknown: "+host+" (FreeIPA configuration): "+strings.Join(configUnknown, "; "))
	}
	if authRequired {
		findings = append(findings, authFinding)
	}

	var comparisonsUnknown []string
	for _, d := range diffs {
		switch d.Status {
		case "match", FactNotApplicable:
		case "mismatch", "absent":
			findings = append(findings, "declared_live_"+d.Status+": "+d.Subject)
		case FactAuthRequired:
			if !authRequired {
				comparisonsUnknown = append(comparisonsUnknown, withDetail(d.Subject, d.Detail))
			}
		default:
			comparisonsUnknown = append(comparisonsUnknown, withDetail(d.Subject, d.Detail))
		}
	}
	if len(comparisonsUnknown) > 0 {
		partial = true
		findings = append(findings, "comparison_unknown: "+strings.Join(comparisonsUnknown, "; "))
	}
	switch {
	case authRequired:
		return FactAuthRequired, findings
	case partial:
		return "partial", findings
	}
	return "complete", findings
}

func factSummary(f DNSArchFact, render func(any) string) string {
	switch f.State {
	case FactObserved:
		return render(f.Value)
	case FactAbsent:
		return "none"
	}
	return f.State
}

func joinStrings(v any) string {
	if s, ok := v.([]string); ok {
		return strings.Join(s, ", ")
	}
	return fmt.Sprint(v)
}

// BuildDNSArchPaths renders the resolution paths as short lines: which
// hosts send internal names to FreeIPA and external names to which
// upstream, live values first and the inventory's where no live value is
// available.
func BuildDNSArchPaths(m DNSArchModel, o DNSArchObserved) []string {
	var paths []string
	obsTier := map[string]DNSArchObservedTier{}
	for _, t := range o.Tier {
		obsTier[t.Host] = t
	}
	for _, t := range m.Tier {
		if t.State != "computed" {
			paths = append(paths, fmt.Sprintf("dns tier %s: settings are Jinja templates; see observed.tier", t.Host))
			continue
		}
		var internal []string
		for _, z := range t.StubZones {
			internal = append(internal, fmt.Sprintf("%s → %s (%s)", z.Name, strings.Join(z.Addrs, ", "), z.Source))
		}
		live := "live: unknown"
		if ot, ok := obsTier[t.Host]; ok {
			live = "live forward . → " + factSummary(ot.Forwards, func(v any) string {
				servers, _ := zoneServers(DNSArchFact{Value: v}, ".")
				return strings.Join(servers, ", ")
			})
		}
		if len(internal) == 0 {
			internal = []string{"no internal zones"}
		}
		paths = append(paths, fmt.Sprintf("dns tier %s (%s, %s): internal %s; external . → %s (%s)", t.Host, t.Addr, t.Mode, strings.Join(internal, "; "), strings.Join(t.Upstream, ", "), live))
	}
	if !m.TierAssigned {
		paths = append(paths, "dns tier: not assigned (the dns role exists in contracts/dns.yaml; no host is in the dns group)")
	}
	for _, p := range m.Providers {
		if !p.DNSProvider {
			paths = append(paths, fmt.Sprintf("FreeIPA %s %s (%s): no DNS (freeipa_setup_dns false)", p.Kind, p.FQDN, p.IP))
			continue
		}
		if p.LeftOut {
			paths = append(paths, fmt.Sprintf("FreeIPA %s %s (%s): left out of the DNS paths (freeipa_setup_dns unset, and FreeIPA does not list it as a DNS server)", p.Kind, p.FQDN, p.IP))
			continue
		}
		line := fmt.Sprintf("FreeIPA DNS %s %s (%s): authoritative for %s", p.Kind, p.FQDN, p.IP, m.FreeIPADomain)
		for _, op := range o.Providers {
			if op.Host == p.InventoryHost {
				line += "; live SOA " + liveAuthority(op.SOA)
			}
		}
		if servers, ok := o.FreeIPA.ServerForwarders.Value.([]DNSArchServerForwarders); ok {
			for _, s := range servers {
				if strings.EqualFold(strings.TrimSuffix(s.Server, "."), p.FQDN) && len(s.Forwarders) > 0 {
					line += fmt.Sprintf("; server forwarders %s (policy %s)", strings.Join(s.Forwarders, ", "), s.ForwardPolicy)
				}
			}
		}
		paths = append(paths, line)
	}
	if m.FreeIPAPresent && m.Forwarding.State != "not_applicable" {
		paths = append(paths, fmt.Sprintf("FreeIPA global forwarders: declared %s; live %s, policy %s; forward zones live %s",
			strings.Join(m.Forwarding.GlobalForwarders, ", "),
			factSummary(o.FreeIPA.GlobalForwarders, joinStrings),
			strings.Replace(factSummary(o.FreeIPA.ForwardPolicy, func(v any) string { return fmt.Sprint(v) }), "none", "unset (FreeIPA default)", 1),
			factSummary(o.FreeIPA.ForwardZones, func(v any) string {
				zones, _ := v.([]DNSArchForwardZone)
				var names []string
				for _, z := range zones {
					names = append(names, fmt.Sprintf("%s → %s (%s)", z.Zone, strings.Join(z.Forwarders, ", "), z.ForwardPolicy))
				}
				return strings.Join(names, "; ")
			})))
	}
	for _, r := range m.Resolvers {
		if r.State != "computed" || r.Error != "" {
			paths = append(paths, fmt.Sprintf("resolver %s: %s", r.Host, firstNonEmptyString(r.Error, "settings are Jinja templates")))
			continue
		}
		managed := "not managed by freeipa-dns-client"
		if len(r.ManagedBy) > 0 {
			managed = strings.Join(r.ManagedBy, ", ")
		}
		paths = append(paths, fmt.Sprintf("resolver %s (%s, %s) → %s", r.Host, managed, r.Selection, strings.Join(r.Servers, ", ")))
	}
	return paths
}

// liveAuthority summarises a provider's observed SOA for the paths: the
// effective claim "authoritative for" is only a plan until the live
// answer says so.
func liveAuthority(f DNSArchFact) string {
	q, isQuery := f.Value.(DNSQueryResult)
	switch {
	case !isQuery || (f.State != FactObserved && f.State != FactAbsent && f.State != FactError):
		return f.State
	case q.Status == "NOERROR" && q.Authoritative && len(q.Answers) > 0:
		return "authoritative"
	}
	return fmt.Sprintf("%s, authoritative=%t", q.Status, q.Authoritative)
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
