// projection.go builds a UserHostAccessSnapshotV1 from Pilot's canonical
// declarative sources (design spec §11, §12): hosts.yml (inventory) and
// the workspace's FreeIPA identity roster, if any. It never guesses a
// FreeIPA FQDN from an inventory hostname (§11.4) and never merges an
// inventory host with a roster host, even when their address matches.
package outbound

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kjelly/pilot/internal/inventory"
)

// ErrorClass is the bounded, allowlisted reason a projection is
// unavailable (design spec §15.1.1's `state.error_class`). Only the two
// values below can originate from BuildProjection itself;
// serialization_failed/payload_too_large are set later, by the event/
// envelope layer (Phase 3), never here.
type ErrorClass string

const (
	ErrorClassProjectionUnavailable ErrorClass = "projection_unavailable"
	ErrorClassMultipleRosterSources ErrorClass = "multiple_roster_sources"
)

// ProjectionRequest is BuildProjection's input. HostVars is the
// already-resolved per-host variable map the caller's terminal workflow
// computed for this operation (design spec §11.5) — this package never
// shells out to ansible-inventory itself, keeping it decoupled from
// Ansible execution and safe to unit test with plain fixtures.
type ProjectionRequest struct {
	WorkspaceDir          string
	HostsYMLPath          string // defaults to <WorkspaceDir>/hosts.yml when empty
	HostVars              map[string]map[string]any
	VaultPasswordFile     string
	BreakglassActivations []inventory.BreakglassActivationInput
	Now                   time.Time
}

// ProjectionResult is BuildProjection's typed output. Available=false is
// an expected, non-error outcome (design spec §11.7): the caller still
// publishes a terminal event, just without Snapshot.
type ProjectionResult struct {
	Available  bool
	ErrorClass ErrorClass // set iff !Available
	Snapshot   UserHostAccessSnapshotV1
}

func unavailable(class ErrorClass) ProjectionResult {
	return ProjectionResult{Available: false, ErrorClass: class}
}

// BuildProjection materializes the current user_host_access_v1 snapshot.
// It never returns a Go error for an expected degradation (unreadable/
// encrypted-without-password roster, multiple distinct roster sources,
// dangling access-host reference, duplicate stable keys) — those are
// reported via ProjectionResult.Available/ErrorClass so the caller can
// still send a metadata-only terminal event (design spec §11.7, §33).
func BuildProjection(req ProjectionRequest) ProjectionResult {
	hostsYMLPath := req.HostsYMLPath
	if hostsYMLPath == "" {
		hostsYMLPath = filepath.Join(req.WorkspaceDir, "hosts.yml")
	}

	inventoryHosts, err := buildInventoryHosts(hostsYMLPath)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}

	source := ResolveRosterSource(req.HostVars)
	switch source.Kind {
	case RosterSourceMultiple:
		return unavailable(ErrorClassMultipleRosterSources)
	case RosterSourceAbsent:
		return ProjectionResult{
			Available: true,
			Snapshot: UserHostAccessSnapshotV1{
				Hosts:      inventoryHosts,
				Users:      []ProjectedUser{},
				Groups:     []ProjectedGroup{},
				Hostgroups: []ProjectedHostgroup{},
				Access:     ProjectedAccess{Login: []ProjectedLoginAccess{}, Sudo: []ProjectedSudoAccess{}},
			},
		}
	}

	rosterPath := source.Paths[0]
	if !filepath.IsAbs(rosterPath) {
		rosterPath = filepath.Join(req.WorkspaceDir, rosterPath)
	}
	root, err := inventory.ReadRosterAsMapWithVault(rosterPath, req.VaultPasswordFile)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}

	rosterHosts, hostIDSet := buildRosterHosts(root)

	users, err := buildUsers(root, req.Now)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}
	groups, err := buildGroups(root)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}
	hostgroups, err := buildHostgroups(root, hostIDSet)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}
	login, sudo, err := buildAccess(root, req.Now, req.BreakglassActivations, hostIDSet)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}

	return ProjectionResult{
		Available: true,
		Snapshot: UserHostAccessSnapshotV1{
			Hosts:      append(inventoryHosts, rosterHosts...),
			Users:      users,
			Groups:     groups,
			Hostgroups: hostgroups,
			Access:     ProjectedAccess{Login: login, Sudo: sudo},
		},
	}
}

func buildInventoryHosts(hostsYMLPath string) ([]ProjectedHost, error) {
	data, err := os.ReadFile(hostsYMLPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []ProjectedHost{}, nil
		}
		return nil, err
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return nil, err
	}
	out := make([]ProjectedHost, 0, len(hf.Hosts))
	seen := map[string]bool{}
	for _, h := range hf.Hosts {
		id := inventoryHostID(h.Name)
		if seen[id] {
			return nil, fmt.Errorf("duplicate inventory host id %q", id)
		}
		seen[id] = true
		out = append(out, ProjectedHost{
			ID:                     id,
			Name:                   h.Name,
			Source:                 "inventory",
			Address:                h.AnsibleHost,
			Env:                    h.Env,
			Roles:                  append([]string(nil), h.Roles...),
			DeploymentAvailability: string(h.EffectiveDeploymentAvailability()),
			Annotations:            h.Annotations,
		})
	}
	return out, nil
}

func buildRosterHosts(root map[string]any) ([]ProjectedHost, map[string]bool) {
	rosterHosts := inventory.ExternalRosterHosts(root)
	out := make([]ProjectedHost, 0, len(rosterHosts))
	idSet := make(map[string]bool, len(rosterHosts))
	for _, h := range rosterHosts {
		id := rosterHostID(h.Name)
		idSet[id] = true
		out = append(out, ProjectedHost{
			ID:      id,
			Name:    h.Name,
			Source:  "freeipa_roster",
			FQDN:    h.Name,
			Address: h.Address,
			Roles:   []string{},
		})
	}
	return out, idSet
}

func buildUsers(root map[string]any, now time.Time) ([]ProjectedUser, error) {
	users, err := inventory.ExternalUsers(root, now)
	if err != nil {
		return nil, err
	}
	out := make([]ProjectedUser, 0, len(users))
	seen := map[string]bool{}
	for _, u := range users {
		if seen[u.Name] {
			return nil, fmt.Errorf("duplicate user name %q", u.Name)
		}
		seen[u.Name] = true
		out = append(out, ProjectedUser{
			Name:            u.Name,
			DisplayName:     u.DisplayName,
			Email:           u.Email,
			Enabled:         u.Enabled,
			UID:             u.UID,
			GID:             u.GID,
			EffectiveGroups: u.EffectiveGroups,
		})
	}
	return out, nil
}

func buildGroups(root map[string]any) ([]ProjectedGroup, error) {
	groups := inventory.ExternalGroups(root)
	out := make([]ProjectedGroup, 0, len(groups))
	seen := map[string]bool{}
	for _, g := range groups {
		if seen[g.Name] {
			return nil, fmt.Errorf("duplicate group name %q", g.Name)
		}
		seen[g.Name] = true
		out = append(out, ProjectedGroup{
			Name:        g.Name,
			Category:    g.Category,
			Type:        g.Type,
			Description: g.Description,
			Users:       g.Users,
			Groups:      g.Groups,
		})
	}
	return out, nil
}

func buildHostgroups(root map[string]any, hostIDSet map[string]bool) ([]ProjectedHostgroup, error) {
	hostgroups := inventory.ExternalHostgroups(root)
	out := make([]ProjectedHostgroup, 0, len(hostgroups))
	seen := map[string]bool{}
	for _, hg := range hostgroups {
		if seen[hg.Name] {
			return nil, fmt.Errorf("duplicate hostgroup name %q", hg.Name)
		}
		seen[hg.Name] = true
		hostIDs, err := namespaceHostRefs(hg.HostIDs, hostIDSet)
		if err != nil {
			return nil, err
		}
		effectiveHostIDs, err := namespaceHostRefs(hg.EffectiveHostIDs, hostIDSet)
		if err != nil {
			return nil, err
		}
		out = append(out, ProjectedHostgroup{
			Name:             hg.Name,
			Description:      hg.Description,
			HostIDs:          hostIDs,
			Hostgroups:       hg.Hostgroups,
			EffectiveHostIDs: effectiveHostIDs,
		})
	}
	return out, nil
}

// namespaceHostRefs converts roster host FQDNs into their namespaced
// freeipa: IDs, failing closed (design spec §11.4) if any does not
// resolve to a present roster host.
func namespaceHostRefs(names []string, hostIDSet map[string]bool) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, name := range names {
		id := rosterHostID(name)
		if !hostIDSet[id] {
			return nil, fmt.Errorf("dangling host reference %q: no present roster host", name)
		}
		out = append(out, id)
	}
	return out, nil
}

func buildAccess(root map[string]any, now time.Time, breakglass []inventory.BreakglassActivationInput, hostIDSet map[string]bool) ([]ProjectedLoginAccess, []ProjectedSudoAccess, error) {
	loginIn, sudoIn, err := inventory.ExternalEffectiveAccess(root, now, breakglass)
	if err != nil {
		return nil, nil, err
	}

	login := make([]ProjectedLoginAccess, 0, len(loginIn))
	seenLogin := map[string]bool{}
	for _, l := range loginIn {
		id, err := loginAccessID(l.Source, l.Rule)
		if err != nil {
			return nil, nil, err
		}
		if seenLogin[id] {
			return nil, nil, fmt.Errorf("duplicate login access id %q", id)
		}
		seenLogin[id] = true
		var hostIDs []string
		if !l.AllHosts {
			hostIDs, err = namespaceHostRefs(l.HostIDs, hostIDSet)
			if err != nil {
				return nil, nil, err
			}
		}
		login = append(login, ProjectedLoginAccess{
			ID:         id,
			Source:     l.Source,
			Rule:       l.Rule,
			Users:      l.Users,
			AllHosts:   l.AllHosts,
			HostIDs:    hostIDs,
			Services:   l.Services,
			ValidUntil: l.ValidUntil,
		})
	}

	sudo := make([]ProjectedSudoAccess, 0, len(sudoIn))
	seenSudo := map[string]bool{}
	for _, s := range sudoIn {
		id, err := sudoAccessID(s.Source, s.Rule)
		if err != nil {
			return nil, nil, err
		}
		if seenSudo[id] {
			return nil, nil, fmt.Errorf("duplicate sudo access id %q", id)
		}
		seenSudo[id] = true
		var hostIDs []string
		if !s.AllHosts {
			hostIDs, err = namespaceHostRefs(s.HostIDs, hostIDSet)
			if err != nil {
				return nil, nil, err
			}
		}
		sudo = append(sudo, ProjectedSudoAccess{
			ID:             id,
			Source:         s.Source,
			Rule:           s.Rule,
			Users:          s.Users,
			AllHosts:       s.AllHosts,
			HostIDs:        hostIDs,
			AllCommands:    s.AllCommands,
			Commands:       s.Commands,
			DeniedCommands: s.DeniedCommands,
			RunAsUsers:     s.RunAsUsers,
			RunAsGroups:    s.RunAsGroups,
			Options:        s.Options,
			ValidNotBefore: s.ValidNotBefore,
			ValidNotAfter:  s.ValidNotAfter,
		})
	}

	return login, sudo, nil
}

// loginAccessID/sudoAccessID implement design spec §12.2/§12.3's stable
// ID tables.
func loginAccessID(source, rule string) (string, error) {
	switch source {
	case "static_hbac":
		return "static_hbac:" + rule, nil
	case "temporary_grant":
		return "temporary_grant:" + rule, nil
	case "breakglass":
		return "breakglass:" + rule, nil
	default:
		return "", fmt.Errorf("unknown login access source %q", source)
	}
}

func sudoAccessID(source, rule string) (string, error) {
	switch source {
	case "static_sudo":
		return "static_sudo:" + rule, nil
	case "sudo_grant":
		return "sudo_grant:" + rule, nil
	default:
		return "", fmt.Errorf("unknown sudo access source %q", source)
	}
}
