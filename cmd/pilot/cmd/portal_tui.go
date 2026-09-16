package cmd

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kjelly/pilot/internal/gatewayapi"
)

// Portal's top-menu items (spec.md §27) — no scope switcher, ever.
const (
	portalMenuMyHosts    = "My Hosts"
	portalMenuMyIdentity = "My Identity"
	portalMenuRefresh    = "Refresh"
	portalMenuLogout     = "Logout"
)

var portalTopMenuItems = []string{portalMenuMyHosts, portalMenuMyIdentity, portalMenuRefresh, portalMenuLogout}

// portalResolveHost is net.DefaultResolver.LookupHost, indirected so tests
// can substitute a fast fake instead of depending on real DNS/network
// access (startFakeGateway installs a default stub — see
// portal_client_test.go).
var portalResolveHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// portalDNSCheckTimeout bounds a single My Hosts DNS reachability probe —
// short enough that a handful of stale/placeholder entries can't stall
// the menu noticeably, since every host is probed concurrently anyway.
const portalDNSCheckTimeout = 800 * time.Millisecond

// portalBreadcrumb renders a screen's nesting path under the fixed "Pilot
// Portal" root, so a user several menus deep can tell where Back leads
// without having to remember the navigation history themselves.
func portalBreadcrumb(steps ...string) string {
	return strings.Join(append([]string{"Pilot Portal"}, steps...), " › ")
}

// runPortal is `pilot portal`'s main loop (spec.md §27): Gateway/Scope/
// User header, My Hosts, Host Detail (with Phase 5's Connect action), My
// Identity, Refresh, Logout. Esc/ctrl+c at the top menu exits the same as
// choosing Logout — this loop only ever leaves via one of those two
// paths, never mid-submenu without returning here first.
func runPortal(ctx context.Context, client *portalClient) error {
	return runPortalWithSSHConfig(ctx, client, defaultSSHConfigPath)
}

func runPortalWithSSHConfig(ctx context.Context, client *portalClient, sshConfigPath string) error {
	identity, err := client.Identity(ctx)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	access, err := client.Access(ctx)
	if err != nil {
		return fmt.Errorf("load access: %w", err)
	}
	for {
		header := portalHeader(identity, access.User)
		choice, err := runSelectPrompt("", header, portalTopMenuItems)
		if err != nil {
			return nil
		}
		switch portalTopMenuItems[choice] {
		case portalMenuMyHosts:
			if err := runPortalMyHosts(ctx, client, sshConfigPath, access); err != nil {
				return err
			}
		case portalMenuMyIdentity:
			runAcknowledgePrompt(portalIdentityDetail(identity))
		case portalMenuRefresh:
			access, err = client.Access(ctx)
			if err != nil {
				return fmt.Errorf("refresh access: %w", err)
			}
			runAcknowledgePrompt(fmt.Sprintf("Access refreshed at %s.", time.Now().Format("15:04:05")))
		case portalMenuLogout:
			if runConfirmPrompt("", "Log out of Pilot Portal?", false) {
				return nil
			}
		}
	}
}

func portalHeader(identity gatewayapi.IdentityResponse, user string) string {
	return fmt.Sprintf(
		"Pilot Portal\n\nGateway  %s\nScope    %s\nUser     %s\n────────────────────────",
		identity.Gateway.ID, identity.Gateway.Scope, user)
}

func portalIdentityDetail(identity gatewayapi.IdentityResponse) string {
	return fmt.Sprintf(
		"My Identity\n\nUsername  %s\nUID       %d\nGateway   %s\nScope     %s\nTarget    %s",
		identity.Username, identity.UID, identity.Gateway.ID, identity.Gateway.Scope, identity.Gateway.TargetHostgroup)
}

// runAcknowledgePrompt shows a read-only info screen with a single
// dismiss action. My Identity and Refresh have nothing to confirm — they
// only ever display information — so unlike Logout (a real Yes/No
// decision, via runConfirmPrompt) they must never offer two choices that
// both do the same thing.
func runAcknowledgePrompt(message string) {
	_, _ = runSelectPrompt("", message, []string{"OK"})
}

const portalBackChoice = "« Back"

// portalHostEntry pairs a My Hosts row with a live DNS reachability probe
// and the addresses returned by that probe (authorization != reachability:
// spec.md §9.3's server-side filter only guarantees "SSH allowed", never
// that the FQDN actually resolves — found live when a demo's placeholder
// fixture host, authorized but with no DNS record, could only be told apart
// from a real target after a failed Connect attempt).
type portalHostEntry struct {
	host       gatewayapi.HostJSON
	addresses  []string
	resolvable bool
}

// resolvePortalHostEntries probes every host concurrently (bounded by
// portalDNSCheckTimeout each) so a handful of dead entries add at most
// one timeout's worth of latency to the whole list, not one per host.
// Unresolvable hosts sort after resolvable ones, stably, so a user's
// most-likely-useful choices come first. The returned addresses are kept for
// the My Hosts label so the user can see which IP the FQDN currently resolves
// to without changing the authorized FQDN used by Connect.
func resolvePortalHostEntries(ctx context.Context, hosts []gatewayapi.HostJSON) []portalHostEntry {
	entries := make([]portalHostEntry, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		entries[i].host = h
		wg.Add(1)
		go func(i int, fqdn string) {
			defer wg.Done()
			lookupCtx, cancel := context.WithTimeout(ctx, portalDNSCheckTimeout)
			defer cancel()
			addresses, err := portalResolveHost(lookupCtx, fqdn)
			entries[i].addresses = append([]string(nil), addresses...)
			entries[i].resolvable = err == nil
		}(i, h.FQDN)
	}
	wg.Wait()
	sort.SliceStable(entries, func(a, b int) bool {
		return entries[a].resolvable && !entries[b].resolvable
	})
	return entries
}

func portalHostListLabel(e portalHostEntry) string {
	label := e.host.FQDN
	switch {
	case e.resolvable && len(e.addresses) > 0:
		label += fmt.Sprintf("  [IP: %s]", strings.Join(e.addresses, ", "))
	case !e.resolvable:
		label += "  ⚠ DNS lookup failed"
	}
	if summary := portalAnnotationsSummary(e.host.Annotations); summary != "" {
		label += "  [" + summary + "]"
	}
	return label
}

// portalAnnotationsSummary renders a host's annotations (owner/project/
// location/... — docs/superpowers/specs/2026-09-09-host-annotations-
// freeipa-sync-spec.md) as a compact, deterministically ordered one-line
// hint for the My Hosts list row. The full key/value block lives in
// portalHostDetail; this is purely a "does this host have notes worth
// opening the detail screen for" signal.
func portalAnnotationsSummary(annotations map[string]string) string {
	if len(annotations) == 0 {
		return ""
	}
	keys := make([]string, 0, len(annotations))
	for k := range annotations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+annotations[k])
	}
	return strings.Join(parts, ", ")
}

// runPortalMyHosts lists exactly the hosts spec.md §9.3 says My Hosts
// must: hosts already filtered server-side to "effective FreeIPA SSH
// allow AND in gateway scope" — this function never re-filters or
// second-guesses that list. It does add a live, client-side DNS
// reachability hint per host (see portalHostEntry) since that is real
// signal the gateway's authorization data can't express.
func runPortalMyHosts(ctx context.Context, client *portalClient, sshConfigPath string, access gatewayapi.AccessResponse) error {
	if len(access.Hosts) == 0 {
		runAcknowledgePrompt("My Hosts\n\n(no accessible hosts in this gateway's scope)")
		return nil
	}
	entries := resolvePortalHostEntries(ctx, access.Hosts)
	items := make([]string, 0, len(entries)+1)
	for _, e := range entries {
		items = append(items, portalHostListLabel(e))
	}
	items = append(items, portalBackChoice)
	choice, err := runSelectPrompt("", portalBreadcrumb("My Hosts"), items)
	if err != nil || choice == len(entries) {
		return nil
	}
	return runPortalHostDetail(ctx, client, sshConfigPath, entries[choice].host)
}

const (
	portalActionConnect = "Connect"
)

// runPortalHostDetail shows the host's SSH/sudo detail and offers Connect
// (spec.md §60 Phase 5) alongside Back. Connect always asks for a final
// confirmation first — defaulting to "no" when the host's sudo scope is
// broad (root-equivalent) — since a single wrong row picked from My Hosts
// used to drop straight into a live session with no chance to back out.
func runPortalHostDetail(ctx context.Context, client *portalClient, sshConfigPath string, h gatewayapi.HostJSON) error {
	choice, err := runSelectPrompt("", portalHostDetail(h), []string{portalActionConnect, portalBackChoice})
	if err != nil || choice == 1 {
		return nil
	}
	if !runConfirmPrompt("", portalConnectConfirmQuestion(h), !portalSudoScopeIsBroad(h.Sudo.Scope)) {
		return nil
	}
	return connectToHost(ctx, client, sshConfigPath, h.FQDN)
}

// portalSudoScopeIsBroad reports whether scope grants root-equivalent
// access (accessportal.sudoDisplayScope's "all"/"all_with_deny" values) —
// the case worth an extra, deliberately-defaulted-to-no confirmation.
func portalSudoScopeIsBroad(scope string) bool {
	return scope == "all" || scope == "all_with_deny"
}

func portalConnectConfirmQuestion(h gatewayapi.HostJSON) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Connect to %s?\n\nSudo scope: %s", h.FQDN, h.Sudo.Scope)
	if portalSudoScopeIsBroad(h.Sudo.Scope) {
		b.WriteString("\n⚠ Broad sudo access — this session can run any command as root.")
	}
	if len(h.Sudo.DenyCommands) > 0 {
		fmt.Fprintf(&b, "\nDeny commands: %s", strings.Join(h.Sudo.DenyCommands, ", "))
	}
	return b.String()
}

func portalHostDetail(h gatewayapi.HostJSON) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", portalBreadcrumb("My Hosts", h.FQDN))
	fmt.Fprintf(&b, "Host: %s\n\n", h.FQDN)
	fmt.Fprintf(&b, "SSH allowed: %v\n", h.SSH.Allowed)
	if len(h.SSH.Rules) > 0 {
		fmt.Fprintf(&b, "SSH rules: %s\n", strings.Join(h.SSH.Rules, ", "))
	}
	fmt.Fprintf(&b, "\nSudo scope: %s\n", h.Sudo.Scope)
	if portalSudoScopeIsBroad(h.Sudo.Scope) {
		b.WriteString("⚠ Broad sudo access (root-equivalent)\n")
	}
	if len(h.Sudo.AllowCommands) > 0 {
		fmt.Fprintf(&b, "✓ Allow: %s\n", strings.Join(h.Sudo.AllowCommands, ", "))
	}
	if len(h.Sudo.DenyCommands) > 0 {
		fmt.Fprintf(&b, "✗ Deny:  %s\n", strings.Join(h.Sudo.DenyCommands, ", "))
	}
	if len(h.Sudo.Rules) > 0 {
		fmt.Fprintf(&b, "Sudo rules: %s\n", strings.Join(h.Sudo.Rules, ", "))
	}
	if len(h.Annotations) > 0 {
		b.WriteString("\nAnnotations:\n")
		keys := make([]string, 0, len(h.Annotations))
		for k := range h.Annotations {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s: %s\n", k, h.Annotations[k])
		}
	}
	return b.String()
}
