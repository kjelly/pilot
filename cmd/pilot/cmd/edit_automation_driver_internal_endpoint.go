// edit_automation_driver_internal_endpoint.go is edit_automation_driver_dns.go's
// counterpart for the internal-endpoints manifest screens
// (edit_tui_internal_endpoints.go): it turns each of the 9 semantic
// actions spec.md §39 requires into scripted keypresses against the real
// `editRouterModel` Bubble Tea model — driving the actual TUI screens
// (choose/typeText/enter), not a separate mock execution path. This same
// mechanism backs both `pilot edit --actions <scenario.json>` and any test
// harness driving the TUI.
package cmd

import (
	"fmt"
	"strconv"

	"github.com/kjelly/pilot/internal/tui"
)

// ---- navigation chains (ensure*) ----------------------------------------

func (d *automationDriver) ensureInternalEndpointManifestManager(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "iep.manager":
			return nil
		case "edit.top":
			if err := d.choose(r, "internal-endpoints manifest"); err != nil {
				return err
			}
		case "iep.path":
			// Only reachable when the manifest already exists — see
			// pushInternalEndpointManifestPathPrompt.
			if err := d.enter(r); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to internal-endpoint manifest manager from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to internal-endpoint manifest manager")
}

func (d *automationDriver) ensureInternalEndpointsList(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "iep.list":
			return nil
		case "edit.top":
			if err := d.choose(r, "internal-endpoints manifest"); err != nil {
				return err
			}
		case "iep.path":
			if err := d.enter(r); err != nil {
				return err
			}
		case "iep.manager":
			if err := d.choose(r, "🔌 Endpoints"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to internal-endpoints list from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to internal-endpoints list")
}

// listTitleNamesInternalEndpoint reports whether title is
// pushInternalEndpointDetail's title for exactly this fqdn — `Endpoint
// "fqdn" — path`.
func listTitleNamesInternalEndpoint(title, fqdn string) bool {
	return len(title) > 0 && fmt.Sprintf("Endpoint %q ", fqdn) == title[:min(len(title), len(fmt.Sprintf("Endpoint %q ", fqdn)))]
}

func (d *automationDriver) ensureInternalEndpointDetail(r *editRouterModel, fqdn string) error {
	if automationScreenID(r) == "iep.detail" {
		if st := automationState(r); st.Kind == tui.ScreenSelect && listTitleNamesInternalEndpoint(st.Title, fqdn) {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureInternalEndpointsList(r); err != nil {
		return err
	}
	return d.choose(r, "🔌 "+fqdn)
}

func (d *automationDriver) ensureInternalEndpointTLSMenu(r *editRouterModel, fqdn string) error {
	if automationScreenID(r) == "iep.tls.menu" {
		return nil
	}
	if err := d.ensureInternalEndpointDetail(r, fqdn); err != nil {
		return err
	}
	return d.choose(r, "tls")
}

// ---- actions (spec.md §39) -----------------------------------------------

func (d *automationDriver) createInternalEndpointManifest(r *editRouterModel) error {
	if err := d.ensureInternalEndpointManifestManagerPathOnly(r); err != nil {
		return err
	}
	if err := d.enter(r); err != nil { // accept the prefilled default path
		return err
	}
	return d.confirmYesNo(r, true)
}

// ensureInternalEndpointManifestManagerPathOnly gets to iep.path without
// assuming the manifest already exists (unlike ensureInternalEndpointManifestManager,
// which is only ever called once a manifest is known to be present) —
// createInternalEndpointManifest is the ONE action whose whole point is
// that the manifest does NOT exist yet.
func (d *automationDriver) ensureInternalEndpointManifestManagerPathOnly(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "iep.path":
			return nil
		case "edit.top":
			if err := d.choose(r, "internal-endpoints manifest"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to internal-endpoint path prompt from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to internal-endpoint path prompt")
}

// createInternalEndpoint replays the minimal creation wizard: fqdn ->
// dns.zone -> direct route target -> create (spec.md §39's
// create_internal_endpoint, always starts tls.mode: disabled — see
// pushInternalEndpointAddTargetHost's own doc comment for why a
// partial/minimal shape isn't possible here the way a bare freeipa-dns
// zone name is).
func (d *automationDriver) createInternalEndpoint(r *editRouterModel, fqdn, zone, targetHost string) error {
	if err := d.ensureInternalEndpointsList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 endpoint"); err != nil {
		return err
	}
	if err := d.typeText(r, fqdn, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	// replace: true — pushInternalEndpointAddZone now pre-fills a detected
	// zone (see iepDefaultZoneForFQDN) whenever fqdn matches one already
	// declared in freeipa-dns.yaml, so this must overwrite it rather than
	// append after it when the scenario names a different zone.
	if err := d.typeText(r, zone, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	// pushInternalEndpointAddTargetHost is a select list of real hosts.yml
	// entries, not free text (see edit_tui_internal_endpoints.go).
	return d.choose(r, targetHost)
}

func (d *automationDriver) setInternalEndpointState(r *editRouterModel, fqdn, state string) error {
	if err := d.ensureInternalEndpointDetail(r, fqdn); err != nil {
		return err
	}
	if err := d.choose(r, "state"); err != nil {
		return err
	}
	return d.choose(r, state)
}

// setInternalEndpointDNS sets both dns.zone and dns.ttl in one pass — the
// two fields share a single action (set_internal_endpoint_dns, spec.md
// §39), matching pushInternalEndpointDNSZoneField ->
// pushInternalEndpointDNSTTLField's own chained-screen shape. ttl == ""
// leaves the manifest default in place.
func (d *automationDriver) setInternalEndpointDNS(r *editRouterModel, fqdn, zone, ttl string) error {
	if err := d.ensureInternalEndpointDetail(r, fqdn); err != nil {
		return err
	}
	if err := d.choose(r, "dns"); err != nil {
		return err
	}
	if err := d.typeText(r, zone, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if ttl != "" {
		if err := d.typeText(r, ttl, true); err != nil {
			return err
		}
	}
	return d.enter(r)
}

// setInternalEndpointRouteDirect sets route.mode: direct with exactly one
// of targetHost/targetAddress (the other must be "").
func (d *automationDriver) setInternalEndpointRouteDirect(r *editRouterModel, fqdn, targetHost, targetAddress string) error {
	if err := d.ensureInternalEndpointDetail(r, fqdn); err != nil {
		return err
	}
	if err := d.choose(r, "route"); err != nil {
		return err
	}
	if err := d.choose(r, "direct"); err != nil {
		return err
	}
	// The "從 inventory host 解析" branch lands on a select list of real
	// hosts.yml entries; "手動輸入 IP" stays free text (see
	// pushInternalEndpointRouteDirectHostPicker / -Address).
	if targetHost == "" {
		if err := d.choose(r, "手動輸入 IP"); err != nil {
			return err
		}
		if err := d.typeText(r, targetAddress, false); err != nil {
			return err
		}
		return d.enter(r)
	}
	if err := d.choose(r, "從 inventory host 解析"); err != nil {
		return err
	}
	return d.choose(r, targetHost)
}

// setInternalEndpointRouteProxy sets route.mode: reverse_proxy. verify
// must be "" when scheme is "http" (spec.md §12.4.4) and "true"/"false"
// when scheme is "https" (spec.md §12.4.1). sni is optional in both cases.
func (d *automationDriver) setInternalEndpointRouteProxy(r *editRouterModel, fqdn, proxyHost, scheme, upstreamHost, upstreamAddress, port, verify, sni string) error {
	if err := d.ensureInternalEndpointDetail(r, fqdn); err != nil {
		return err
	}
	if err := d.choose(r, "route"); err != nil {
		return err
	}
	if err := d.choose(r, "reverse_proxy"); err != nil {
		return err
	}
	// replace: true — pushInternalEndpointRouteProxyHost now pre-fills the
	// single detected reverse-proxy host as a default (see
	// iepDefaultReverseProxyHost), so this must overwrite it rather than
	// append after it when the scenario names a different host.
	if err := d.typeText(r, proxyHost, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.choose(r, scheme); err != nil {
		return err
	}
	// Same host-picker-select-vs-free-text-address split as
	// setInternalEndpointRouteDirect above.
	if upstreamHost == "" {
		if err := d.choose(r, "手動輸入 IP"); err != nil {
			return err
		}
		if err := d.typeText(r, upstreamAddress, false); err != nil {
			return err
		}
		if err := d.enter(r); err != nil {
			return err
		}
	} else {
		if err := d.choose(r, "從 inventory host 解析"); err != nil {
			return err
		}
		if err := d.choose(r, upstreamHost); err != nil {
			return err
		}
	}
	if err := d.typeText(r, port, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if scheme != "https" {
		return nil
	}
	if err := d.choose(r, verify); err != nil {
		return err
	}
	if sni != "" {
		if err := d.typeText(r, sni, false); err != nil {
			return err
		}
	}
	return d.enter(r)
}

func (d *automationDriver) setInternalEndpointTLSDisabled(r *editRouterModel, fqdn string) error {
	if err := d.ensureInternalEndpointTLSMenu(r, fqdn); err != nil {
		return err
	}
	if err := d.choose(r, "mode"); err != nil {
		return err
	}
	return d.choose(r, "disabled")
}

// setInternalEndpointTLSFreeIPA sets tls.mode: freeipa and, if port != "",
// also tls.port — two screens in sequence (mode lands back on the tls
// menu; port is only reachable once mode is already freeipa).
func (d *automationDriver) setInternalEndpointTLSFreeIPA(r *editRouterModel, fqdn, port string) error {
	if err := d.ensureInternalEndpointTLSMenu(r, fqdn); err != nil {
		return err
	}
	if err := d.choose(r, "mode"); err != nil {
		return err
	}
	if err := d.choose(r, "freeipa"); err != nil {
		return err
	}
	if port == "" {
		return nil
	}
	if err := d.ensureInternalEndpointTLSMenu(r, fqdn); err != nil {
		return err
	}
	if err := d.choose(r, "port"); err != nil {
		return err
	}
	if err := d.typeText(r, port, true); err != nil {
		return err
	}
	return d.enter(r)
}

// setInternalEndpointTLSSink sets tls.sink — only reachable once
// route.mode == direct and tls.mode == freeipa (spec.md §22); the tls menu
// itself flashes a warning and refuses to navigate here otherwise, which
// this driver call surfaces as a real error rather than silently
// no-op'ing (the caller is expected to have set route/tls correctly
// first).
func (d *automationDriver) setInternalEndpointTLSSink(r *editRouterModel, fqdn, certFile, keyFile, keyOwner, keyGroup, keyMode, reloadUnit string) error {
	if err := d.ensureInternalEndpointTLSMenu(r, fqdn); err != nil {
		return err
	}
	if err := d.choose(r, "sink"); err != nil {
		return err
	}
	if err := d.typeText(r, certFile, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, keyFile, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if keyOwner != "" {
		if err := d.typeText(r, keyOwner, true); err != nil {
			return err
		}
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if keyGroup != "" {
		if err := d.typeText(r, keyGroup, true); err != nil {
			return err
		}
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if keyMode != "" {
		if err := d.typeText(r, keyMode, true); err != nil {
			return err
		}
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, reloadUnit, true); err != nil {
		return err
	}
	return d.enter(r)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// atoiOrZero parses value as an int, defaulting to 0 on any error —
// used where an action's optional numeric field arrives as a string and
// an empty/invalid value should behave like "unset" rather than fail.
func atoiOrZero(value string) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return n
}
