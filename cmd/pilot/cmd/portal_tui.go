package cmd

import (
	"context"
	"fmt"
	"strings"

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

// runPortal is `pilot portal`'s read-only main loop (Phase 4 — spec.md
// §27/§60 Phase 4): Gateway/Scope/User header, My Hosts, Host Detail, My
// Identity, Refresh, Logout. No Connect action yet — that is Phase 5's
// controlled SSH, deliberately not built here (portalClient.ConnectAuthorize
// already exists for it to use). Esc/ctrl+c at the top menu exits the same
// as choosing Logout — this loop only ever leaves via one of those two
// paths, never mid-submenu without returning here first.
func runPortal(ctx context.Context, client *portalClient) error {
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
			runPortalMyHosts(access)
		case portalMenuMyIdentity:
			runConfirmPrompt("", portalIdentityDetail(identity), true)
		case portalMenuRefresh:
			access, err = client.Access(ctx)
			if err != nil {
				return fmt.Errorf("refresh access: %w", err)
			}
		case portalMenuLogout:
			return nil
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

const portalBackChoice = "« Back"

// runPortalMyHosts lists exactly the hosts spec.md §9.3 says My Hosts
// must: hosts already filtered server-side to "effective FreeIPA SSH
// allow AND in gateway scope" — this function never re-filters or
// second-guesses that list.
func runPortalMyHosts(access gatewayapi.AccessResponse) {
	if len(access.Hosts) == 0 {
		runConfirmPrompt("", "My Hosts\n\n(no accessible hosts in this gateway's scope)", true)
		return
	}
	items := make([]string, 0, len(access.Hosts)+1)
	for _, h := range access.Hosts {
		items = append(items, h.FQDN)
	}
	items = append(items, portalBackChoice)
	choice, err := runSelectPrompt("", "My Hosts", items)
	if err != nil || choice == len(access.Hosts) {
		return
	}
	runConfirmPrompt("", portalHostDetail(access.Hosts[choice]), true)
}

func portalHostDetail(h gatewayapi.HostJSON) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host: %s\n\n", h.FQDN)
	fmt.Fprintf(&b, "SSH allowed: %v\n", h.SSH.Allowed)
	if len(h.SSH.Rules) > 0 {
		fmt.Fprintf(&b, "SSH rules: %s\n", strings.Join(h.SSH.Rules, ", "))
	}
	fmt.Fprintf(&b, "\nSudo scope: %s\n", h.Sudo.Scope)
	if len(h.Sudo.AllowCommands) > 0 {
		fmt.Fprintf(&b, "Allow commands: %s\n", strings.Join(h.Sudo.AllowCommands, ", "))
	}
	if len(h.Sudo.DenyCommands) > 0 {
		fmt.Fprintf(&b, "Deny commands: %s\n", strings.Join(h.Sudo.DenyCommands, ", "))
	}
	if len(h.Sudo.Rules) > 0 {
		fmt.Fprintf(&b, "Sudo rules: %s\n", strings.Join(h.Sudo.Rules, ", "))
	}
	return b.String()
}
