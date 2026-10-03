package cmd

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/directoryapi"
	"github.com/kjelly/pilot/internal/sessionaudit"
)

// Directory's top-menu items (spec.md §13.1) — same four-item shape as
// Portal's, no scope switcher (there is nothing to switch: Directory IS
// the cross-scope view).
const (
	directoryMenuMyHosts    = "My Hosts"
	directoryMenuMyIdentity = "My Identity"
	directoryMenuRefresh    = "Refresh"
	directoryMenuLogout     = "Logout"
)

var directoryTopMenuItems = []string{directoryMenuMyHosts, directoryMenuMyIdentity, directoryMenuRefresh, directoryMenuLogout}

// directoryRouteStatusReady matches internal/directoryapi's own
// RouteJSON.RouteStatus "ready" literal (spec.md §10.2) — duplicated
// here rather than imported as a constant since directoryapi does not
// export one; kept as a single named constant so every comparison in
// this file stays in sync if that literal ever changes.
const directoryRouteStatusReady = "ready"

// runDirectoryWithSSHConfig is `pilot directory`'s main loop (spec.md
// §13.1): Directory/User header, My Hosts, My Identity, Refresh, Logout.
// Esc/ctrl+c at the top menu exits the same as choosing Logout.
func runDirectoryWithSSHConfig(ctx context.Context, client *directoryClient, sshConfigPath string) error {
	credentials := newPortalKerberosSessionWithPrefix("pilot-directory-")
	defer credentials.Close()
	// NewEmitter is fail-soft (see its doc comment): an unreachable local
	// syslog never blocks the interactive Directory TUI from starting.
	emitter, _ := sessionaudit.NewEmitter("pilot-access-directory")
	return runDirectoryWithCredentials(ctx, client, credentials, emitter, sshConfigPath)
}

func runDirectoryWithCredentials(ctx context.Context, client *directoryClient, credentials portalCredentialSession, emitter *sessionaudit.Emitter, sshConfigPath string) error {
	identity, err := client.Identity(ctx)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	access, err := client.Access(ctx)
	if err != nil {
		return fmt.Errorf("load access: %w", err)
	}
	for {
		header := directoryHeader(identity, access.User)
		choice, err := runSelectPrompt("", header, directoryTopMenuItems)
		if err != nil {
			return nil
		}
		switch directoryTopMenuItems[choice] {
		case directoryMenuMyHosts:
			if err := runDirectoryMyHosts(ctx, client, credentials, emitter, sshConfigPath, access); err != nil {
				return err
			}
		case directoryMenuMyIdentity:
			runAcknowledgePrompt(directoryIdentityDetail(identity))
		case directoryMenuRefresh:
			access, err = client.Access(ctx)
			if err != nil {
				return fmt.Errorf("refresh access: %w", err)
			}
			runAcknowledgePrompt(fmt.Sprintf("Access refreshed at %s.", time.Now().Format("15:04:05")))
		case directoryMenuLogout:
			if runConfirmPrompt("", "Log out of Pilot Access Directory?", false) {
				return nil
			}
		}
	}
}

func directoryHeader(identity directoryapi.IdentityResponse, user string) string {
	return fmt.Sprintf(
		"Pilot Access Directory\n\nDirectory %s\nUser      %s\n────────────────────────",
		identity.Directory.ID, user)
}

func directoryIdentityDetail(identity directoryapi.IdentityResponse) string {
	return fmt.Sprintf(
		"My Identity\n\nUsername  %s\nUID       %d\nDirectory %s",
		identity.Username, identity.UID, identity.Directory.ID)
}

const directoryBackChoice = "« Back"

// directoryTargetIsReady reports whether at least one of t's routes is
// route_status=ready — spec.md §13.1: a target with NO ready route must
// still be shown (the user genuinely has policy access to it) but with
// Connect disabled, so they can tell "have access, no route" apart from
// "no access at all".
func directoryTargetIsReady(t directoryapi.TargetJSON) bool {
	for _, r := range t.Routes {
		if r.RouteStatus == directoryRouteStatusReady {
			return true
		}
	}
	return false
}

func directoryRouteScopesSummary(t directoryapi.TargetJSON) string {
	scopes := make([]string, 0, len(t.Routes))
	for _, r := range t.Routes {
		scopes = append(scopes, r.Scope)
	}
	sort.Strings(scopes)
	return strings.Join(scopes, ", ")
}

// directoryTargetListLabel renders one My Hosts row: FQDN, the scope(s)
// it is reachable through, and a "no gateway available" marker (spec.md
// §13.1) when nothing is currently ready.
func directoryTargetListLabel(t directoryapi.TargetJSON) string {
	label := fmt.Sprintf("%s  [%s]", t.FQDN, directoryRouteScopesSummary(t))
	if badge := directoryRecordingBadge(t.Recording); badge != "" {
		label += "  " + badge
	}
	if !directoryTargetIsReady(t) {
		label += "  ⚠ no gateway available"
	}
	return label
}

// directoryRecordingBadge marks a target whose host policy records (per-host
// recording spec §24.2). The Directory only knows the host override, not
// each gateway's default, so [REC] means "this host asks for recording" and
// [REC ?] means its policy could not be read or is invalid. The notice the
// gateway prints before SSH is the authoritative answer.
func directoryRecordingBadge(r directoryapi.DirectoryRecordingJSON) string {
	switch r.Status {
	case "terminal_output":
		return "[REC]"
	case "unknown", "invalid":
		return "[REC ?]"
	default:
		return ""
	}
}

// runDirectoryMyHosts lists exactly the targets spec.md §10.3 says My
// Hosts must: every target merged across every scope the user has access
// to, already filtered server-side to "SSH-allowed" — this function never
// re-filters or second-guesses that list, only decides whether Connect is
// reachable for the chosen row.
func runDirectoryMyHosts(ctx context.Context, client *directoryClient, credentials portalCredentialSession, emitter *sessionaudit.Emitter, sshConfigPath string, access directoryapi.AccessResponse) error {
	if len(access.Targets) == 0 {
		runAcknowledgePrompt("My Hosts\n\n(no accessible targets across any scope)")
		return nil
	}
	items := make([]string, 0, len(access.Targets)+1)
	for _, t := range access.Targets {
		items = append(items, directoryTargetListLabel(t))
	}
	items = append(items, directoryBackChoice)
	choice, err := runSelectPrompt("", directoryBreadcrumb("My Hosts"), items)
	if err != nil || choice == len(access.Targets) {
		return nil
	}
	return runDirectoryTargetDetail(ctx, client, credentials, emitter, sshConfigPath, access.User, access.Targets[choice])
}

func directoryBreadcrumb(steps ...string) string {
	return strings.Join(append([]string{"Pilot Access Directory"}, steps...), " › ")
}

const directoryActionConnect = "Connect"

// runDirectoryTargetDetail shows the target's routes/SSH/sudo detail. If
// no route is ready, Connect is not offered at all (spec.md §13.1:
// "Connect disabled") — selecting the row only ever gets the operator to
// this read-only detail, never a launch attempt that would just fail.
func runDirectoryTargetDetail(ctx context.Context, client *directoryClient, credentials portalCredentialSession, emitter *sessionaudit.Emitter, sshConfigPath, username string, t directoryapi.TargetJSON) error {
	if !directoryTargetIsReady(t) {
		runAcknowledgePrompt(directoryTargetDetail(t) + "\n\n⚠ No gateway currently serves this target's scope(s) — Connect is disabled.")
		return nil
	}
	choice, err := runSelectPrompt("", directoryTargetDetail(t), []string{directoryActionConnect, directoryBackChoice})
	if err != nil || choice == 1 {
		return nil
	}
	if !runConfirmPrompt("", directoryConnectConfirmQuestion(t), !portalSudoScopeIsBroad(t.Sudo.Scope)) {
		return nil
	}
	return connectToGateway(ctx, client, credentials, emitter, sshConfigPath, username, t.FQDN)
}

func directoryConnectConfirmQuestion(t directoryapi.TargetJSON) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Connect to %s?\n\nSudo scope: %s", t.FQDN, t.Sudo.Scope)
	if portalSudoScopeIsBroad(t.Sudo.Scope) {
		b.WriteString("\n⚠ Broad sudo access — this session can run any command as root.")
	}
	if len(t.Sudo.DenyCommands) > 0 {
		fmt.Fprintf(&b, "\nDeny commands: %s", strings.Join(t.Sudo.DenyCommands, ", "))
	}
	return b.String()
}

func directoryTargetDetail(t directoryapi.TargetJSON) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", directoryBreadcrumb("My Hosts", t.FQDN))
	fmt.Fprintf(&b, "Host: %s\n\n", t.FQDN)
	fmt.Fprintf(&b, "SSH allowed: %v\n", t.SSH.Allowed)
	if len(t.SSH.Rules) > 0 {
		fmt.Fprintf(&b, "SSH rules: %s\n", strings.Join(t.SSH.Rules, ", "))
	}
	fmt.Fprintf(&b, "\nSudo scope: %s\n", t.Sudo.Scope)
	if portalSudoScopeIsBroad(t.Sudo.Scope) {
		b.WriteString("⚠ Broad sudo access (root-equivalent)\n")
	}
	if len(t.Sudo.AllowCommands) > 0 {
		fmt.Fprintf(&b, "✓ Allow: %s\n", strings.Join(t.Sudo.AllowCommands, ", "))
	}
	if len(t.Sudo.DenyCommands) > 0 {
		fmt.Fprintf(&b, "✗ Deny:  %s\n", strings.Join(t.Sudo.DenyCommands, ", "))
	}
	if len(t.Sudo.Rules) > 0 {
		fmt.Fprintf(&b, "Sudo rules: %s\n", strings.Join(t.Sudo.Rules, ", "))
	}
	b.WriteString("\nRoutes:\n")
	for _, r := range t.Routes {
		status := r.RouteStatus
		if status == directoryRouteStatusReady {
			fmt.Fprintf(&b, "  ✓ scope=%s via %s\n", r.Scope, strings.Join(r.GatewayCandidates, ", "))
		} else {
			fmt.Fprintf(&b, "  ⚠ scope=%s (%s)\n", r.Scope, status)
		}
	}
	return b.String()
}
