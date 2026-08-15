package inventory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/contract"
)

// InternalEndpointCandidate is one auto-provision suggestion: a ready-to-append
// internal-endpoints.yaml entry, plus the component/endpoint it was derived
// from, for display before a human decides to actually create it.
type InternalEndpointCandidate struct {
	Component string
	Endpoint  string
	FQDN      string
	Manifest  map[string]any
}

// InternalEndpointSkip explains why an autoPublish-eligible endpoint was not
// suggested.
type InternalEndpointSkip struct {
	Component string
	Endpoint  string
	Reason    string
}

// InternalEndpointSuggestResult is SuggestInternalEndpoints' full report.
type InternalEndpointSuggestResult struct {
	Candidates []InternalEndpointCandidate
	Skipped    []InternalEndpointSkip
}

// SuggestInternalEndpoints proposes internal-endpoints.yaml entries for every
// contract endpoint marked autoPublish.eligible: true, given which ansible
// inventory group each component (and the reverse-proxy) resolves to in this
// topology. It never touches disk or live hosts — same pure, host-state-free
// character as ValidateInternalEndpointManifest.
//
// Callers (the `pilot internal-endpoint suggest` CLI, the edit-TUI's endpoint
// menu) still route every accepted candidate through
// SimulateAddInternalEndpoint + AppendInternalEndpoint, exactly like a
// manually authored entry — this function only proposes, never writes, and
// never bypasses the DNS-ownership-collision gate those two already enforce.
//
// proxyHost and zone must already be resolved to a single concrete value by
// the caller (erroring out or prompting interactively when the reverse-proxy
// group has more than one host, or the freeipa-dns manifest declares more
// than one zone) — this function does not guess between ambiguous options.
func SuggestInternalEndpoints(contracts []contract.Contract, groups map[string][]string, proxyHost, zone string, existing map[string]any) InternalEndpointSuggestResult {
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	var result InternalEndpointSuggestResult
	published := publishedUpstreams(existing)
	claimedSubdomains := map[string]string{} // subdomain -> component that claimed it

	for _, c := range contracts {
		for _, ep := range c.Endpoints {
			if ep.AutoPublish == nil || !ep.AutoPublish.Eligible {
				continue
			}
			skip := func(reason string) {
				result.Skipped = append(result.Skipped, InternalEndpointSkip{Component: c.ID, Endpoint: ep.Name, Reason: reason})
			}

			hosts := groups[c.Role]
			if len(hosts) == 0 {
				skip(fmt.Sprintf("component %q is not present in this inventory (group %q is empty)", c.ID, c.Role))
				continue
			}
			if len(hosts) > 1 {
				skip(fmt.Sprintf("ambiguous: group %q has %d hosts (%s) — pick one manually", c.Role, len(hosts), strings.Join(hosts, ", ")))
				continue
			}
			host := hosts[0]

			if published[upstreamKey(host, ep.Port)] {
				skip(fmt.Sprintf("upstream %s:%d is already published by an existing endpoint", host, ep.Port))
				continue
			}

			subdomain := ep.AutoPublish.Subdomain
			if subdomain == "" {
				subdomain = ep.Name
			}
			if owner, exists := claimedSubdomains[subdomain]; exists {
				skip(fmt.Sprintf("subdomain %q already claimed by %s — choose an explicit subdomain", subdomain, owner))
				continue
			}
			claimedSubdomains[subdomain] = c.ID

			fqdn := subdomain
			if zone != "" {
				fqdn = subdomain + "." + zone
			}

			upstream := map[string]any{
				"inventory_host": host,
				"port":           ep.Port,
				"scheme":         ep.Scheme,
			}
			if ep.Scheme == "https" {
				upstream["tls"] = map[string]any{"verify": false}
			}

			manifestEntry := map[string]any{
				"fqdn":  fqdn,
				"state": "present",
				"dns":   map[string]any{"zone": zone + "."},
				"route": map[string]any{
					"mode":     "reverse_proxy",
					"proxy":    map[string]any{"inventory_host": proxyHost, "provider": "nginx"},
					"upstream": upstream,
				},
				"tls": map[string]any{"mode": "freeipa"},
			}

			result.Candidates = append(result.Candidates, InternalEndpointCandidate{
				Component: c.ID,
				Endpoint:  ep.Name,
				FQDN:      fqdn,
				Manifest:  manifestEntry,
			})
		}
	}

	sort.Slice(result.Candidates, func(i, j int) bool { return result.Candidates[i].FQDN < result.Candidates[j].FQDN })
	sort.Slice(result.Skipped, func(i, j int) bool {
		if result.Skipped[i].Component != result.Skipped[j].Component {
			return result.Skipped[i].Component < result.Skipped[j].Component
		}
		return result.Skipped[i].Endpoint < result.Skipped[j].Endpoint
	})
	return result
}

func upstreamKey(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// publishedUpstreams collects every present reverse_proxy endpoint's
// route.upstream inventory_host:port pair already in the manifest, so a
// second suggest run doesn't propose a duplicate entry for the same backend
// under a different name.
func publishedUpstreams(root map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, raw := range listField(root, "endpoints") {
		e := asMap(raw)
		if stringFieldDefault(e, "state", "present") != "present" {
			continue
		}
		route := mapField(e, "route")
		if stringField(route, "mode") != "reverse_proxy" {
			continue
		}
		upstream := mapField(route, "upstream")
		host := stringField(upstream, "inventory_host")
		if host == "" {
			continue
		}
		port, _ := toInt(upstream["port"])
		out[upstreamKey(host, port)] = true
	}
	return out
}
