// projection.go builds a UserHostAccessSnapshotV1 from Pilot's canonical
// declarative sources (design spec §11, §12): hosts.yml supplies the host
// entities, while the FreeIPA identity roster supplies users, groups,
// hostgroups, and access rules. Roster host FQDNs are resolved to inventory
// host IDs by an exact address match; an absent or ambiguous match fails
// closed instead of creating a second host entity.
package outbound

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	rosterHosts := inventory.ExternalRosterHosts(root)
	rosterToInventoryID, err := mapRosterHostsToInventory(rosterHosts, inventoryHosts)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}

	users, err := buildUsers(root, req.Now)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}
	groups, err := buildGroups(root)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}
	hostgroups, err := buildHostgroups(root, rosterToInventoryID)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}
	login, sudo, err := buildAccess(root, req.Now, req.BreakglassActivations, rosterToInventoryID)
	if err != nil {
		return unavailable(ErrorClassProjectionUnavailable)
	}

	return ProjectionResult{
		Available: true,
		Snapshot: UserHostAccessSnapshotV1{
			Hosts:      inventoryHosts,
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

func mapRosterHostsToInventory(rosterHosts []inventory.ExternalRosterHost, inventoryHosts []ProjectedHost) (map[string]string, error) {
	byAddress := make(map[string][]string, len(inventoryHosts))
	for _, host := range inventoryHosts {
		address := strings.TrimSpace(host.Address)
		if address == "" {
			continue
		}
		byAddress[address] = append(byAddress[address], host.ID)
	}

	mapping := make(map[string]string, len(rosterHosts))
	for _, rosterHost := range rosterHosts {
		address := strings.TrimSpace(rosterHost.Address)
		matches := byAddress[address]
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("roster host %q with address %q has no matching hosts.yml host", rosterHost.Name, address)
		case 1:
			mapping[rosterHostID(rosterHost.Name)] = matches[0]
		default:
			return nil, fmt.Errorf("roster host %q with address %q matches multiple hosts.yml hosts", rosterHost.Name, address)
		}
	}
	return mapping, nil
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

func buildHostgroups(root map[string]any, rosterToInventoryID map[string]string) ([]ProjectedHostgroup, error) {
	hostgroups := inventory.ExternalHostgroups(root)
	out := make([]ProjectedHostgroup, 0, len(hostgroups))
	seen := map[string]bool{}
	for _, hg := range hostgroups {
		if seen[hg.Name] {
			return nil, fmt.Errorf("duplicate hostgroup name %q", hg.Name)
		}
		seen[hg.Name] = true
		hostIDs, err := namespaceHostRefs(hg.HostIDs, rosterToInventoryID)
		if err != nil {
			return nil, err
		}
		effectiveHostIDs, err := namespaceHostRefs(hg.EffectiveHostIDs, rosterToInventoryID)
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

// namespaceHostRefs converts roster host FQDNs into the corresponding
// inventory IDs, failing closed if any does not resolve to a present roster
// host with an unambiguous hosts.yml address match.
func namespaceHostRefs(names []string, rosterToInventoryID map[string]string) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, name := range names {
		id, ok := rosterToInventoryID[rosterHostID(name)]
		if !ok {
			return nil, fmt.Errorf("dangling host reference %q: no matching present hosts.yml host", name)
		}
		out = append(out, id)
	}
	return out, nil
}

func buildAccess(root map[string]any, now time.Time, breakglass []inventory.BreakglassActivationInput, rosterToInventoryID map[string]string) ([]ProjectedLoginAccess, []ProjectedSudoAccess, error) {
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
			hostIDs, err = namespaceHostRefs(l.HostIDs, rosterToInventoryID)
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
			hostIDs, err = namespaceHostRefs(s.HostIDs, rosterToInventoryID)
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
