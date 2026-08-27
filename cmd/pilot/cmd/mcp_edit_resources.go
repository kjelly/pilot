// mcp_edit_resources.go exposes the same read-only data pilot_edit_inspect
// serves as MCP *resources* (pilot:// URIs). Agents probe both surfaces —
// some clients try resources/list before (or instead of) guessing which
// tool answers a read query — so the data is reachable either way, built
// by one shared set of builders (also used by inspectHandler) rather than
// two diverging read paths. Resources are read-only by nature, so they are
// registered unconditionally, independent of --allow-write.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/groupvars"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/monitoring"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---- shared builders (pilot_edit_inspect + pilot:// resources) -------------

// buildInspectHosts reads the workspace's ansible inventory (hosts.yml).
// Like all inspect reads it is lenient: a missing or unparsable file yields
// an empty list, never an error — inspect summarizes what exists.
func buildInspectHosts(dir string) []inspectHost {
	var hosts []inspectHost
	if data, err := os.ReadFile(filepath.Join(dir, "hosts.yml")); err == nil {
		if hf, err := inventory.Parse(data); err == nil {
			for _, h := range hf.Hosts {
				hosts = append(hosts, inspectHost{
					Name:        h.Name,
					AnsibleHost: h.AnsibleHost,
					AnsibleUser: h.AnsibleUser,
					Env:         h.Env,
					Roles:       h.Roles,
				})
			}
		}
	}
	return hosts
}

// inspectRosterData is the roster's full non-secret graph plus the
// server-resolved effective views — the payload of pilot://roster, and the
// source of inspectOutput's Roster*/HBAC*/Sudo*/Effective* fields.
type inspectRosterData struct {
	Users               []inspectRosterUser             `json:"users"`
	Groups              []inspectRosterGroup            `json:"groups,omitempty"`
	Hostgroups          []inspectRosterHostgroup        `json:"hostgroups,omitempty"`
	HBACRules           []inspectHBACRule               `json:"hbac_rules,omitempty"`
	SudoCommandGroups   []inspectSudoCommandGroup       `json:"sudo_command_groups,omitempty"`
	SudoRules           []inspectSudoRule               `json:"sudo_rules,omitempty"`
	Grants              []inspectRosterGrant            `json:"grants,omitempty"`
	EffectiveHBACAccess []inventory.EffectiveHBACAccess `json:"effective_hbac_access,omitempty"`
	EffectiveSudoAccess []inventory.EffectiveSudoAccess `json:"effective_sudo_access,omitempty"`
	// PasswordPolicies/CredentialPolicies/PrivilegedIdentity are v3.2's
	// identity-hardening sections (spec.md §7/§10/§11/§9, Phase 6 read
	// side) — structural roster data only, the same posture as Grants
	// above; live capability/hygiene/drift data needs a real FreeIPA
	// probe and stays CLI-only (`pilot identity hygiene`/`drift`) rather
	// than joining this roster-file-only read path.
	PasswordPolicies   []inspectPasswordPolicy    `json:"password_policies,omitempty"`
	CredentialPolicies []inspectCredentialPolicy  `json:"credential_policies,omitempty"`
	PrivilegedIdentity *inspectPrivilegedIdentity `json:"privileged_identity,omitempty"`
}

// buildInspectRoster locates the roster file among the workspace's managed
// files (by its top-level "users" key — see looksLikeRosterFile) and reads
// its full non-secret graph. Never password.initial, never ssh_keys.values.
func buildInspectRoster(dir string) inspectRosterData {
	var out inspectRosterData
	entries, err := managedFileEntries(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsSecret || !looksLikeRosterFile(e.Content) {
			continue
		}
		fullPath := filepath.Join(dir, filepath.FromSlash(e.RelPath))
		names, err := inventory.RosterUserNames(fullPath)
		if err != nil {
			continue // encrypted or unreadable — skip rather than fail the whole read
		}
		for _, name := range names {
			fields, found, err := inventory.RosterUser(fullPath, name)
			if err != nil || !found {
				continue
			}
			ru := inspectRosterUser{
				Name:        name,
				State:       rosterStringOr(fields, "state", "present"),
				Email:       rosterStringValue(fields, "email"),
				DisplayName: rosterStringValue(fields, "display_name"),
				Enabled:     rosterBoolFieldOr(fields, "enabled", true),
			}
			if s := rosterIntValue(fields, "uid"); s != "" {
				if n, err := strconv.Atoi(s); err == nil {
					ru.UID = &n
				}
			}
			if s := rosterIntValue(fields, "gid"); s != "" {
				if n, err := strconv.Atoi(s); err == nil {
					ru.GID = &n
				}
			}
			out.Users = append(out.Users, ru)
		}

		if groupNames, err := inventory.RosterGroupNames(fullPath); err == nil {
			for _, name := range groupNames {
				fields, found, err := inventory.RosterGroup(fullPath, name)
				if err != nil || !found {
					continue
				}
				membership := rosterSubmap(fields, "membership")
				out.Groups = append(out.Groups, inspectRosterGroup{
					Name:         name,
					State:        rosterStringOr(fields, "state", "present"),
					Category:     rosterStringValue(fields, "category"),
					Type:         rosterStringOr(fields, "type", "posix"),
					Description:  rosterStringValue(fields, "description"),
					MemberUsers:  rosterStringSlice(membership, "users"),
					MemberGroups: rosterStringSlice(membership, "groups"),
				})
			}
		}

		if hostgroupNames, err := inventory.RosterHostgroupNames(fullPath); err == nil {
			for _, name := range hostgroupNames {
				fields, found, err := inventory.RosterHostgroup(fullPath, name)
				if err != nil || !found {
					continue
				}
				membership := rosterSubmap(fields, "membership")
				out.Hostgroups = append(out.Hostgroups, inspectRosterHostgroup{
					Name:             name,
					State:            rosterStringOr(fields, "state", "present"),
					Description:      rosterStringValue(fields, "description"),
					MemberHosts:      rosterStringSlice(membership, "hosts"),
					MemberHostgroups: rosterStringSlice(membership, "hostgroups"),
				})
			}
		}

		if ruleNames, err := inventory.RosterHBACRuleNames(fullPath); err == nil {
			for _, name := range ruleNames {
				fields, found, err := inventory.RosterHBACRule(fullPath, name)
				if err != nil || !found {
					continue
				}
				subjects := rosterSubmap(fields, "subjects")
				targets := rosterSubmap(fields, "targets")
				out.HBACRules = append(out.HBACRules, inspectHBACRule{
					Name:             name,
					State:            rosterStringOr(fields, "state", "present"),
					Enabled:          rosterBoolFieldOr(fields, "enabled", true),
					SubjectUsers:     rosterStringSlice(subjects, "users"),
					SubjectGroups:    rosterStringSlice(subjects, "groups"),
					AllHosts:         rosterStringValue(targets, "hostcat") == "all",
					TargetHosts:      rosterStringSlice(targets, "hosts"),
					TargetHostgroups: rosterStringSlice(targets, "hostgroups"),
					Services:         rosterStringSlice(fields, "services"),
				})
			}
		}

		if cgNames, err := inventory.RosterSudoCommandGroupNames(fullPath); err == nil {
			for _, name := range cgNames {
				fields, found, err := inventory.RosterSudoCommandGroup(fullPath, name)
				if err != nil || !found {
					continue
				}
				out.SudoCommandGroups = append(out.SudoCommandGroups, inspectSudoCommandGroup{
					Name:     name,
					Commands: rosterStringSlice(fields, "commands"),
				})
			}
		}

		if sudoRuleNames, err := inventory.RosterSudoRuleNames(fullPath); err == nil {
			for _, name := range sudoRuleNames {
				fields, found, err := inventory.RosterSudoRule(fullPath, name)
				if err != nil || !found {
					continue
				}
				subjects := rosterSubmap(fields, "subjects")
				targets := rosterSubmap(fields, "targets")
				allow := rosterSubmap(fields, "allow")
				deny := rosterSubmap(fields, "deny")
				out.SudoRules = append(out.SudoRules, inspectSudoRule{
					Name:               name,
					State:              rosterStringOr(fields, "state", "present"),
					SubjectUsers:       rosterStringSlice(subjects, "users"),
					SubjectGroups:      rosterStringSlice(subjects, "groups"),
					AllHosts:           rosterStringValue(targets, "hostcat") == "all",
					TargetHosts:        rosterStringSlice(targets, "hosts"),
					TargetHostgroups:   rosterStringSlice(targets, "hostgroups"),
					AllCommands:        rosterStringValue(allow, "command_category") == "all",
					AllowCommands:      rosterStringSlice(allow, "commands"),
					AllowCommandGroups: rosterStringSlice(allow, "command_groups"),
					DenyCommandGroups:  rosterStringSlice(deny, "command_groups"),
				})
			}
		}

		out.Grants = buildInspectGrantsFromFile(fullPath)
		out.PasswordPolicies = buildInspectPasswordPoliciesFromFile(fullPath)
		out.CredentialPolicies = buildInspectCredentialPoliciesFromFile(fullPath)
		out.PrivilegedIdentity = buildInspectPrivilegedIdentityFromFile(fullPath)

		if resolved, err := inventory.EffectiveHBACAccessList(fullPath); err == nil {
			out.EffectiveHBACAccess = resolved
		}
		if resolved, err := inventory.EffectiveSudoAccessList(fullPath); err == nil {
			out.EffectiveSudoAccess = resolved
		}

		break // only one roster file is expected per workspace
	}
	return out
}

// inspectRosterGrant is one grants[] entry (spec.md §5/§6) — the v3.0
// access-governance analog of inspectHBACRule/inspectSudoRule. Fields are
// kind-conditional in the roster itself (roster_grants.go's checkGrants);
// here they are simply omitted (via omitempty) when the grant's kind
// doesn't carry them, e.g. MaxDuration is only ever non-empty for
// kind: breakglass. Lifecycle/NextTransition mirror `pilot access status`
// (inventory.EvaluateGrantStatuses) — empty/nil for breakglass, which has
// no validity-driven lifecycle (§6.3/§8); breakglass's actual
// currently-granting-or-not state is separate runtime activation state,
// see inspectBreakglassStatus/buildInspectBreakglassStatus instead.
type inspectRosterGrant struct {
	Name                   string     `json:"name"`
	State                  string     `json:"state"`
	Kind                   string     `json:"kind"`
	SubjectUsers           []string   `json:"subject_users,omitempty"`
	SubjectGroups          []string   `json:"subject_groups,omitempty"`
	TargetHosts            []string   `json:"target_hosts,omitempty"`
	TargetHostgroups       []string   `json:"target_hostgroups,omitempty"`
	Services               []string   `json:"services,omitempty"`
	ValidityNotBefore      string     `json:"validity_not_before,omitempty"`
	ValidityNotAfter       string     `json:"validity_not_after,omitempty"`
	JustificationReason    string     `json:"justification_reason,omitempty"`
	JustificationTicket    string     `json:"justification_ticket,omitempty"`
	PrivilegeCommandGroups []string   `json:"privilege_command_groups,omitempty"`
	MaxDuration            string     `json:"max_duration,omitempty"`
	Lifecycle              string     `json:"lifecycle,omitempty"`
	NextTransition         *time.Time `json:"next_transition,omitempty"`
}

// buildInspectGrantsFromFile reads every grants[] entry from an already-
// located roster file. Like every other inspect builder it is lenient: an
// unreadable/unparsable roster yields an empty list rather than an error.
func buildInspectGrantsFromFile(fullPath string) []inspectRosterGrant {
	names, err := inventory.RosterGrantNames(fullPath)
	if err != nil {
		return nil
	}
	statusByName := map[string]inventory.GrantStatus{}
	if statuses, err := inventory.EvaluateGrantStatusesFile(fullPath, time.Now()); err == nil {
		for _, s := range statuses {
			statusByName[s.Name] = s
		}
	}
	var out []inspectRosterGrant
	for _, name := range names {
		f, found, err := inventory.RosterGrant(fullPath, name)
		if err != nil || !found {
			continue
		}
		subjects := rosterSubmap(f, "subjects")
		targets := rosterSubmap(f, "targets")
		validity := rosterSubmap(f, "validity")
		justification := rosterSubmap(f, "justification")
		privilege := rosterSubmap(f, "privilege")
		activation := rosterSubmap(f, "activation")
		g := inspectRosterGrant{
			Name:                   name,
			State:                  rosterStringOr(f, "state", "present"),
			Kind:                   rosterStringValue(f, "kind"),
			SubjectUsers:           rosterStringSlice(subjects, "users"),
			SubjectGroups:          rosterStringSlice(subjects, "groups"),
			TargetHosts:            rosterStringSlice(targets, "hosts"),
			TargetHostgroups:       rosterStringSlice(targets, "hostgroups"),
			Services:               rosterStringSlice(f, "services"),
			ValidityNotBefore:      rosterStringValue(validity, "not_before"),
			ValidityNotAfter:       rosterStringValue(validity, "not_after"),
			JustificationReason:    rosterStringValue(justification, "reason"),
			JustificationTicket:    rosterStringValue(justification, "ticket"),
			PrivilegeCommandGroups: rosterStringSlice(privilege, "command_groups"),
			MaxDuration:            rosterStringValue(activation, "max_duration"),
		}
		if status, ok := statusByName[name]; ok {
			g.Lifecycle = string(status.Lifecycle)
			g.NextTransition = status.NextTransition
		}
		out = append(out, g)
	}
	return out
}

// inspectPasswordPolicy is one password_policies[] entry (spec.md v3.2
// §7). Int fields are pointers so an unset field (no opinion — see
// CompiledPasswordPolicy's doc comment, internal/inventory/
// password_policy_compile.go) renders as JSON `null`/absent rather than a
// fabricated zero.
type inspectPasswordPolicy struct {
	Name                        string `json:"name"`
	State                       string `json:"state"`
	Group                       string `json:"group,omitempty"`
	Priority                    *int   `json:"priority,omitempty"`
	MinLength                   *int   `json:"min_length,omitempty"`
	HistorySize                 *int   `json:"history_size,omitempty"`
	MaxLife                     string `json:"max_life,omitempty"`
	MinLife                     string `json:"min_life,omitempty"`
	LockoutMaxFailures          *int   `json:"lockout_max_failures,omitempty"`
	LockoutFailureResetInterval string `json:"lockout_failure_reset_interval,omitempty"`
	LockoutLockoutDuration      string `json:"lockout_lockout_duration,omitempty"`
}

// buildInspectPasswordPoliciesFromFile reads every password_policies[]
// entry from an already-located roster file. Lenient like every other
// inspect builder: an unreadable/unparsable roster yields nil.
func buildInspectPasswordPoliciesFromFile(fullPath string) []inspectPasswordPolicy {
	names, err := inventory.RosterPasswordPolicyNames(fullPath)
	if err != nil {
		return nil
	}
	var out []inspectPasswordPolicy
	for _, name := range names {
		f, found, err := inventory.RosterPasswordPolicy(fullPath, name)
		if err != nil || !found {
			continue
		}
		lockout := rosterSubmap(f, "lockout")
		out = append(out, inspectPasswordPolicy{
			Name:                        name,
			State:                       rosterStringOr(f, "state", "present"),
			Group:                       rosterStringValue(f, "group"),
			Priority:                    rosterIntPtr(f, "priority"),
			MinLength:                   rosterIntPtr(f, "min_length"),
			HistorySize:                 rosterIntPtr(f, "history_size"),
			MaxLife:                     rosterStringValue(f, "max_life"),
			MinLife:                     rosterStringValue(f, "min_life"),
			LockoutMaxFailures:          rosterIntPtr(lockout, "max_failures"),
			LockoutFailureResetInterval: rosterStringValue(lockout, "failure_reset_interval"),
			LockoutLockoutDuration:      rosterStringValue(lockout, "lockout_duration"),
		})
	}
	return out
}

// rosterIntPtr is rosterIntValue's pointer-returning counterpart, for a
// JSON payload where "field not set" (nil, omitted) must be distinct from
// "field set to a value" — rosterIntDisplay/rosterIntValue's string
// return can't represent that distinction cleanly.
func rosterIntPtr(m map[string]any, key string) *int {
	switch v := m[key].(type) {
	case int:
		return &v
	case int64:
		n := int(v)
		return &n
	case float64:
		n := int(v)
		return &n
	}
	return nil
}

// inspectCredentialPolicy is one credential_policies[] entry (spec.md
// v3.2 §10/§11). ReviewInterval/ReviewLastReviewedAt/ReviewReviewedBy are
// exposed for visibility only — `pilot identity review mark` remains the
// sanctioned way to update them (§11), never a structured write action.
type inspectCredentialPolicy struct {
	Name                 string   `json:"name"`
	State                string   `json:"state"`
	MatchUsers           []string `json:"match_users,omitempty"`
	MatchGroups          []string `json:"match_groups,omitempty"`
	SSHAllowedAlgorithms []string `json:"ssh_allowed_algorithms,omitempty"`
	SSHRequireComment    bool     `json:"ssh_require_comment,omitempty"`
	SSHMaxAge            string   `json:"ssh_max_age,omitempty"`
	ReviewInterval       string   `json:"review_interval,omitempty"`
	ReviewLastReviewedAt string   `json:"review_last_reviewed_at,omitempty"`
	ReviewReviewedBy     string   `json:"review_reviewed_by,omitempty"`
}

func buildInspectCredentialPoliciesFromFile(fullPath string) []inspectCredentialPolicy {
	names, err := inventory.RosterCredentialPolicyNames(fullPath)
	if err != nil {
		return nil
	}
	var out []inspectCredentialPolicy
	for _, name := range names {
		f, found, err := inventory.RosterCredentialPolicy(fullPath, name)
		if err != nil || !found {
			continue
		}
		match := rosterSubmap(f, "match")
		ssh := rosterSubmap(f, "ssh")
		review := rosterSubmap(f, "review")
		out = append(out, inspectCredentialPolicy{
			Name:                 name,
			State:                rosterStringOr(f, "state", "present"),
			MatchUsers:           rosterStringSlice(match, "users"),
			MatchGroups:          rosterStringSlice(match, "groups"),
			SSHAllowedAlgorithms: rosterStringSlice(ssh, "allowed_algorithms"),
			SSHRequireComment:    ssh["require_comment"] == true,
			SSHMaxAge:            rosterStringValue(ssh, "max_age"),
			ReviewInterval:       rosterStringValue(review, "interval"),
			ReviewLastReviewedAt: rosterStringValue(review, "last_reviewed_at"),
			ReviewReviewedBy:     rosterStringValue(review, "reviewed_by"),
		})
	}
	return out
}

// inspectPrivilegedIdentity is security.privileged_identity (spec.md v3.2
// §9) — a singleton, unlike every other inspect list above, since the
// roster declares at most one baseline.
type inspectPrivilegedIdentity struct {
	MatchGroups    []string `json:"match_groups,omitempty"`
	AuthTypes      []string `json:"auth_types,omitempty"`
	NoPasswordOnly bool     `json:"no_password_only,omitempty"`
	SSHKeyPolicy   string   `json:"ssh_key_policy,omitempty"`
}

// buildInspectPrivilegedIdentityFromFile returns nil when the roster
// declares no privileged_identity block — matching PrivilegedIdentity's
// nil-able *inspectPrivilegedIdentity field on inspectRosterData (opt-in,
// spec.md §9).
func buildInspectPrivilegedIdentityFromFile(fullPath string) *inspectPrivilegedIdentity {
	f, found, err := inventory.RosterPrivilegedIdentity(fullPath)
	if err != nil || !found {
		return nil
	}
	require := rosterSubmap(f, "require")
	return &inspectPrivilegedIdentity{
		MatchGroups:    rosterStringSlice(f, "match_groups"),
		AuthTypes:      rosterStringSlice(require, "auth_types"),
		NoPasswordOnly: require["no_password_only"] == true,
		SSHKeyPolicy:   rosterStringValue(require, "ssh_key_policy"),
	}
}

// inspectBreakglassActivation is one recorded activate (and, if it
// happened, deactivate) event — accessgrants.Activation's MCP-facing
// mirror, adding the server-computed Active flag so a caller never needs
// to reimplement Activation.IsActive(now) itself.
type inspectBreakglassActivation struct {
	ActivatedAt time.Time `json:"activated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Reason      string    `json:"reason,omitempty"`
	Ticket      string    `json:"ticket,omitempty"`
	ActivatedBy string    `json:"activated_by,omitempty"`
	Deactivated bool      `json:"deactivated"`
	Active      bool      `json:"active"`
}

// inspectBreakglassStatus is one kind: breakglass grant's full activation
// history (most recent last, matching accessgrants' own append-only
// statefile ordering) — the MCP-facing counterpart of
// `pilot access breakglass status`.
type inspectBreakglassStatus struct {
	Name        string                        `json:"name"`
	Activations []inspectBreakglassActivation `json:"activations,omitempty"`
}

// buildInspectBreakglassStatus reports activation history for every
// kind: breakglass grant in the roster. Unlike buildInspectGrantsFromFile,
// this reads local activation state (internal/accessgrants' statefile,
// under dataDir) rather than the roster itself — see breakglass.go's own
// "activation MUST NOT rewrite the definition" invariant for why the two
// are deliberately separate stores.
func buildInspectBreakglassStatus(dir string) []inspectBreakglassStatus {
	grants := buildInspectGrants(dir)
	dataDir := resolveDataDir()
	var out []inspectBreakglassStatus
	for _, g := range grants {
		if g.Kind != "breakglass" {
			continue
		}
		activations, err := accessgrants.Status(dataDir, g.Name)
		if err != nil {
			continue
		}
		now := time.Now()
		entry := inspectBreakglassStatus{Name: g.Name}
		for _, a := range activations {
			entry.Activations = append(entry.Activations, inspectBreakglassActivation{
				ActivatedAt: a.ActivatedAt,
				ExpiresAt:   a.ExpiresAt,
				Reason:      a.Reason,
				Ticket:      a.Ticket,
				ActivatedBy: a.ActivatedBy,
				Deactivated: a.Deactivated,
				Active:      a.IsActive(now),
			})
		}
		out = append(out, entry)
	}
	return out
}

// buildInspectGrants locates the roster file the same way buildInspectRoster
// does and returns its grants — a standalone entry point for callers (like
// buildInspectBreakglassStatus) that want only the grants, not the full
// roster graph.
func buildInspectGrants(dir string) []inspectRosterGrant {
	entries, err := managedFileEntries(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsSecret || !looksLikeRosterFile(e.Content) {
			continue
		}
		return buildInspectGrantsFromFile(filepath.Join(dir, filepath.FromSlash(e.RelPath)))
	}
	return nil
}

// inspectExplainSource mirrors inventory.ExplainSource field-for-field
// with proper JSON tags (that type has none — it's an internal domain
// type, not a wire contract) — same posture as inspectMonitoringTarget.
// See spec.md §16: static_hbac/temporary_grant/sudo_grant/breakglass are
// the only four Kind values.
type inspectExplainSource struct {
	Kind           string     `json:"kind"`
	Rule           string     `json:"rule"`
	DirectUserHit  bool       `json:"direct_user_hit"`
	GroupPath      []string   `json:"group_path,omitempty"`
	DirectHostHit  bool       `json:"direct_host_hit"`
	HostgroupPath  []string   `json:"hostgroup_path,omitempty"`
	AllHosts       bool       `json:"all_hosts"`
	Service        string     `json:"service,omitempty"`
	Lifecycle      string     `json:"lifecycle,omitempty"`
	ValidityAfter  *time.Time `json:"validity_after,omitempty"`
	NextTransition *time.Time `json:"next_transition,omitempty"`
}

// buildInspectExplain answers spec.md §16's "which sources currently grant
// (user, host, service), and through what provenance" for the located
// roster file. Unlike every other inspect builder, an invalid roster
// yields an empty list rather than being silently skipped — explain's
// accessgrants.Explain requires an already-validated roster file, so this
// validates first rather than letting a malformed roster panic deeper in
// the call chain.
func buildInspectExplain(dir, user, host, service string) []inspectExplainSource {
	entries, err := managedFileEntries(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsSecret || !looksLikeRosterFile(e.Content) {
			continue
		}
		fullPath := filepath.Join(dir, filepath.FromSlash(e.RelPath))
		if violations, err := inventory.ValidateRosterFile(fullPath); err != nil || len(violations) > 0 {
			return nil
		}
		sources, err := accessgrants.Explain(fullPath, resolveDataDir(), user, host, service, time.Now())
		if err != nil {
			return nil
		}
		out := make([]inspectExplainSource, 0, len(sources))
		for _, s := range sources {
			item := inspectExplainSource{
				Kind: s.Kind, Rule: s.Rule,
				DirectUserHit: s.DirectUserHit, GroupPath: s.GroupPath,
				DirectHostHit: s.DirectHostHit, HostgroupPath: s.HostgroupPath, AllHosts: s.AllHosts,
				Service: s.Service, Lifecycle: string(s.Lifecycle), NextTransition: s.NextTransition,
			}
			if !s.ValidityAfter.IsZero() {
				validityAfter := s.ValidityAfter
				item.ValidityAfter = &validityAfter
			}
			out = append(out, item)
		}
		return out
	}
	return nil
}

// buildInspectDNSZones reads the freeipa-dns.yaml manifest, cross-resolving
// each record's target.inventory_host against hosts (the ansible inventory)
// into ResolvedIP.
func buildInspectDNSZones(dir string, hosts []inspectHost) []inspectDNSZone {
	entries, err := managedFileEntries(dir)
	if err != nil {
		return nil
	}
	hostIPs := map[string]string{}
	for _, h := range hosts {
		if h.AnsibleHost != "" {
			hostIPs[h.Name] = h.AnsibleHost
		}
	}
	var dnsZones []inspectDNSZone
	for _, e := range entries {
		if e.IsSecret || filepath.Base(e.RelPath) != "freeipa-dns.yaml" {
			continue
		}
		fullPath := filepath.Join(dir, filepath.FromSlash(e.RelPath))
		zoneNames, err := inventory.DNSManifestZoneNames(fullPath)
		if err != nil {
			break // unreadable — skip rather than fail the whole read
		}
		for _, zoneName := range zoneNames {
			zf, found, err := inventory.DNSManifestZone(fullPath, zoneName)
			if err != nil || !found {
				continue
			}
			zone := inspectDNSZone{
				Name:                    zoneName,
				State:                   rosterStringOr(zf, "state", "present"),
				RecordsMode:             rosterStringValue(zf, "records_mode"),
				AcknowledgeSplitHorizon: rosterBoolFieldOr(zf, "acknowledge_split_horizon", false),
			}
			records, err := inventory.DNSManifestRecords(fullPath, zoneName)
			if err == nil {
				for _, rf := range records {
					target := rosterSubmap(rf, "target")
					targetHost := rosterStringValue(target, "inventory_host")
					ttl := 0
					if s := rosterIntValue(rf, "ttl"); s != "" {
						if n, err := strconv.Atoi(s); err == nil {
							ttl = n
						}
					}
					rec := inspectDNSRecord{
						Name:       rosterStringValue(rf, "name"),
						Type:       rosterStringValue(rf, "type"),
						State:      rosterStringOr(rf, "state", "present"),
						TTL:        ttl,
						Values:     rosterStringSlice(rf, "values"),
						TargetHost: targetHost,
					}
					if targetHost != "" {
						rec.ResolvedIP = hostIPs[targetHost]
					}
					zone.Records = append(zone.Records, rec)
				}
			}
			dnsZones = append(dnsZones, zone)
		}
		break // only one DNS manifest is expected per workspace
	}
	return dnsZones
}

// inspectInternalEndpointTarget is route.target (direct mode)'s host
// reference, cross-resolved to its inventory IP the same way
// inspectDNSRecord.ResolvedIP is.
type inspectInternalEndpointTarget struct {
	InventoryHost string `json:"inventory_host,omitempty"`
	Address       string `json:"address,omitempty"`
	ResolvedIP    string `json:"resolved_ip,omitempty"`
}

// inspectInternalEndpointProxy is route.proxy (reverse_proxy mode)'s
// nginx-host reference.
type inspectInternalEndpointProxy struct {
	Provider      string `json:"provider,omitempty"`
	InventoryHost string `json:"inventory_host,omitempty"`
	ResolvedIP    string `json:"resolved_ip,omitempty"`
}

type inspectInternalEndpointUpstreamTLS struct {
	Verify     *bool  `json:"verify,omitempty"`
	ServerName string `json:"server_name,omitempty"`
}

type inspectInternalEndpointUpstream struct {
	Scheme        string                              `json:"scheme,omitempty"`
	InventoryHost string                              `json:"inventory_host,omitempty"`
	Address       string                              `json:"address,omitempty"`
	ResolvedIP    string                              `json:"resolved_ip,omitempty"`
	Port          int                                 `json:"port,omitempty"`
	TLS           *inspectInternalEndpointUpstreamTLS `json:"tls,omitempty"`
}

type inspectInternalEndpointRoute struct {
	Mode     string                           `json:"mode,omitempty"`
	Target   *inspectInternalEndpointTarget   `json:"target,omitempty"`
	Proxy    *inspectInternalEndpointProxy    `json:"proxy,omitempty"`
	Upstream *inspectInternalEndpointUpstream `json:"upstream,omitempty"`
}

// inspectInternalEndpointTLSSink's fields are all filesystem paths/POSIX
// ownership metadata, never key material — spec.md §40 prohibits secrets
// in any MCP output, but a certificate/key *path* isn't the secret itself
// (same reasoning as inspectVaultFile.Keys never carrying values).
type inspectInternalEndpointTLSSink struct {
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	KeyOwner   string `json:"key_owner,omitempty"`
	KeyGroup   string `json:"key_group,omitempty"`
	KeyMode    string `json:"key_mode,omitempty"`
	ReloadMode string `json:"reload_mode,omitempty"`
	ReloadUnit string `json:"reload_unit,omitempty"`
}

type inspectInternalEndpointTLS struct {
	Mode string                          `json:"mode,omitempty"`
	Port int                             `json:"port,omitempty"`
	Sink *inspectInternalEndpointTLSSink `json:"sink,omitempty"`
}

type inspectInternalEndpoint struct {
	FQDN    string                       `json:"fqdn"`
	State   string                       `json:"state"`
	DNSZone string                       `json:"dns_zone,omitempty"`
	DNSTTL  int                          `json:"dns_ttl,omitempty"`
	Route   inspectInternalEndpointRoute `json:"route"`
	TLS     inspectInternalEndpointTLS   `json:"tls"`
}

// buildInspectInternalEndpoints reads the internal-endpoints.yaml manifest,
// cross-resolving every inventory_host reference (route.target,
// route.proxy, route.upstream) against hosts the same way
// buildInspectDNSZones resolves DNS record targets.
func buildInspectInternalEndpoints(dir string, hosts []inspectHost) []inspectInternalEndpoint {
	entries, err := managedFileEntries(dir)
	if err != nil {
		return nil
	}
	hostIPs := map[string]string{}
	for _, h := range hosts {
		if h.AnsibleHost != "" {
			hostIPs[h.Name] = h.AnsibleHost
		}
	}
	var endpoints []inspectInternalEndpoint
	for _, e := range entries {
		if e.IsSecret || filepath.Base(e.RelPath) != "internal-endpoints.yaml" {
			continue
		}
		fullPath := filepath.Join(dir, filepath.FromSlash(e.RelPath))
		fqdns, err := inventory.InternalEndpointManifestFQDNs(fullPath)
		if err != nil {
			break // unreadable — skip rather than fail the whole read
		}
		for _, fqdn := range fqdns {
			fields, found, err := inventory.InternalEndpointManifestEndpoint(fullPath, fqdn)
			if err != nil || !found {
				continue
			}
			dns := iepMapField(fields, "dns")
			ep := inspectInternalEndpoint{
				FQDN:    fqdn,
				State:   rosterStringOr(fields, "state", "present"),
				DNSZone: iepStringValue(dns, "zone"),
			}
			if ttl := iepIntValue(dns, "ttl"); ttl != "" {
				if n, err := strconv.Atoi(ttl); err == nil {
					ep.DNSTTL = n
				}
			}

			route := iepMapField(fields, "route")
			ep.Route.Mode = iepStringValue(route, "mode")
			if target := iepMapField(route, "target"); target != nil {
				t := &inspectInternalEndpointTarget{
					InventoryHost: iepStringValue(target, "inventory_host"),
					Address:       iepStringValue(target, "address"),
				}
				if t.InventoryHost != "" {
					t.ResolvedIP = hostIPs[t.InventoryHost]
				}
				ep.Route.Target = t
			}
			if proxy := iepMapField(route, "proxy"); proxy != nil {
				p := &inspectInternalEndpointProxy{
					Provider:      iepStringValue(proxy, "provider"),
					InventoryHost: iepStringValue(proxy, "inventory_host"),
				}
				if p.InventoryHost != "" {
					p.ResolvedIP = hostIPs[p.InventoryHost]
				}
				ep.Route.Proxy = p
			}
			if upstream := iepMapField(route, "upstream"); upstream != nil {
				u := &inspectInternalEndpointUpstream{
					Scheme:        iepStringValue(upstream, "scheme"),
					InventoryHost: iepStringValue(upstream, "inventory_host"),
					Address:       iepStringValue(upstream, "address"),
				}
				if u.InventoryHost != "" {
					u.ResolvedIP = hostIPs[u.InventoryHost]
				}
				if port := iepIntValue(upstream, "port"); port != "" {
					if n, err := strconv.Atoi(port); err == nil {
						u.Port = n
					}
				}
				if utls := iepMapField(upstream, "tls"); utls != nil {
					t := &inspectInternalEndpointUpstreamTLS{ServerName: iepStringValue(utls, "server_name")}
					if v, ok := utls["verify"].(bool); ok {
						t.Verify = &v
					}
					u.TLS = t
				}
				ep.Route.Upstream = u
			}

			tls := iepMapField(fields, "tls")
			ep.TLS.Mode = rosterStringOr(tls, "mode", "disabled")
			if port := iepIntValue(tls, "port"); port != "" {
				if n, err := strconv.Atoi(port); err == nil {
					ep.TLS.Port = n
				}
			}
			if sink := iepMapField(tls, "sink"); sink != nil {
				reload := iepMapField(sink, "reload")
				ep.TLS.Sink = &inspectInternalEndpointTLSSink{
					CertFile:   iepStringValue(sink, "cert_file"),
					KeyFile:    iepStringValue(sink, "key_file"),
					KeyOwner:   iepStringValue(sink, "key_owner"),
					KeyGroup:   iepStringValue(sink, "key_group"),
					KeyMode:    iepStringValue(sink, "key_mode"),
					ReloadMode: iepStringValue(reload, "mode"),
					ReloadUnit: iepStringValue(reload, "unit"),
				}
			}

			endpoints = append(endpoints, ep)
		}
		break // only one internal-endpoints manifest is expected per workspace
	}
	return endpoints
}

// buildInspectGroupVars reads each group_vars/*.yml file's active
// (non-commented) top-level key/value pairs.
func buildInspectGroupVars(dir string) map[string]map[string]string {
	groupVars := map[string]map[string]string{}
	entries, err := managedFileEntries(dir)
	if err != nil {
		return groupVars
	}
	for _, e := range entries {
		if filepath.Dir(e.RelPath) != "group_vars" {
			continue
		}
		values := map[string]string{}
		for _, entry := range groupvars.Parse(e.Content).Entries() {
			if entry.Active {
				values[entry.Key] = entry.Value
			}
		}
		groupVars[filepath.Base(e.RelPath)] = values
	}
	return groupVars
}

// ---- pilot:// resources ------------------------------------------------

const (
	resourceURIHosts              = "pilot://hosts"
	resourceURIRoster             = "pilot://roster"
	resourceURIEffectiveAccess    = "pilot://roster/effective-access"
	resourceURIGrants             = "pilot://roster/grants"
	resourceURIBreakglass         = "pilot://roster/breakglass"
	resourceURIDNS                = "pilot://dns"
	resourceURIInternalEndpoints  = "pilot://internal-endpoints"
	resourceURIMonitoringTargets  = "pilot://monitoring/targets"
	resourceURIMonitoringProfiles = "pilot://monitoring/scrape-profiles"
)

// inspectMonitoringTarget/-Profile mirror internal/monitoring.Target/Profile
// field-for-field (see spec.md §8/§10) rather than reusing those types
// directly: an MCP output type is a public wire contract this package owns
// independently of internal/monitoring's own struct tags, same posture as
// every other inspect* type in this file.
type inspectMonitoringTarget struct {
	Name    string            `json:"name"`
	Address string            `json:"address"`
	Profile string            `json:"profile"`
	Site    string            `json:"site,omitempty"`
	Enabled bool              `json:"enabled"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type inspectMonitoringProfile struct {
	JobName        string `json:"job_name"`
	Scheme         string `json:"scheme"`
	MetricsPath    string `json:"metrics_path"`
	ScrapeInterval string `json:"scrape_interval,omitempty"`
	ScrapeTimeout  string `json:"scrape_timeout,omitempty"`
	AuthRef        string `json:"auth_ref,omitempty"`
	// TLS is omitted entirely (not even an empty struct) when the profile
	// declares none — same "omit the whole nested block, not just zero its
	// fields" convention as inspectInternalEndpoint's own TLS handling.
	Name string                       `json:"name"`
	TLS  *inspectMonitoringProfileTLS `json:"tls,omitempty"`
}

type inspectMonitoringProfileTLS struct {
	ServerName         string `json:"server_name,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

// buildInspectMonitoringTargets/-Profiles read straight through
// internal/monitoring's own typed Load functions — unlike
// buildInspectInternalEndpoints, this feature has no raw-map/yaml.Node
// parsing step to duplicate here at all.
func buildInspectMonitoringTargets(dir string) []inspectMonitoringTarget {
	tf, err := monitoring.LoadTargets(monitoringTargetsPath(dir))
	if err != nil {
		return nil
	}
	out := make([]inspectMonitoringTarget, 0, len(tf.Targets))
	for _, t := range tf.Targets {
		out = append(out, inspectMonitoringTarget{
			Name: t.Name, Address: t.Address, Profile: t.Profile, Site: t.Site,
			Enabled: t.IsEnabled(), Labels: t.Labels,
		})
	}
	return out
}

func buildInspectMonitoringProfiles(dir string) []inspectMonitoringProfile {
	pf, err := monitoring.LoadProfiles(monitoringProfilesPath(dir))
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(pf.Profiles))
	for name := range pf.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]inspectMonitoringProfile, 0, len(names))
	for _, name := range names {
		p := pf.Profiles[name]
		item := inspectMonitoringProfile{
			Name: name, JobName: p.JobName, Scheme: p.EffectiveScheme(), MetricsPath: p.EffectiveMetricsPath(),
			ScrapeInterval: p.ScrapeInterval, ScrapeTimeout: p.ScrapeTimeout, AuthRef: p.AuthRef,
		}
		if p.TLS != nil {
			item.TLS = &inspectMonitoringProfileTLS{ServerName: p.TLS.ServerName, InsecureSkipVerify: p.TLS.InsecureSkipVerify}
		}
		out = append(out, item)
	}
	return out
}

// effectiveAccessResource is pilot://roster/effective-access's payload —
// just the two server-resolved views, for callers that only want the
// "who can reach/sudo what" answer without the rest of the roster graph.
type effectiveAccessResource struct {
	EffectiveHBACAccess []inventory.EffectiveHBACAccess `json:"effective_hbac_access"`
	EffectiveSudoAccess []inventory.EffectiveSudoAccess `json:"effective_sudo_access"`
}

// registerEditResources registers the pilot:// read-only resources. Data is
// re-read from the workspace on every resources/read call — same freshness
// contract as pilot_edit_inspect.
func registerEditResources(server *mcp.Server, opts editMCPToolsOptions) {
	add := func(uri, name, description string, build func() any) {
		server.AddResource(&mcp.Resource{
			URI:         uri,
			Name:        name,
			Description: description,
			MIMEType:    "application/json",
		}, func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			data, err := json.MarshalIndent(build(), "", "  ")
			if err != nil {
				return nil, fmt.Errorf("marshal %s: %w", uri, err)
			}
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
				URI:      uri,
				MIMEType: "application/json",
				Text:     string(data),
			}}}, nil
		})
	}

	add(resourceURIHosts, "hosts",
		"ansible inventory hosts: name, IP (ansible_host), user, env, roles",
		func() any { return buildInspectHosts(opts.Dir) })
	add(resourceURIRoster, "roster",
		"FreeIPA roster (non-secret): users, groups, hostgroups, HBAC rules, sudo command groups and rules, plus server-resolved effective_hbac_access/effective_sudo_access",
		func() any { return buildInspectRoster(opts.Dir) })
	add(resourceURIEffectiveAccess, "roster-effective-access",
		"server-resolved access views only: per-rule lists of concrete usernames and host FQDNs (nested group/hostgroup membership already expanded), answering 'which users can log in to / run sudo on which hosts'",
		func() any {
			roster := buildInspectRoster(opts.Dir)
			return effectiveAccessResource{
				EffectiveHBACAccess: roster.EffectiveHBACAccess,
				EffectiveSudoAccess: roster.EffectiveSudoAccess,
			}
		})
	add(resourceURIGrants, "roster-grants",
		"v3.0 access-governance grants[] (temporary_grant/sudo_grant/breakglass — spec.md §6), each with its lifecycle (pending/active/expired) and next_transition where applicable",
		func() any { return buildInspectGrants(opts.Dir) })
	add(resourceURIBreakglass, "roster-breakglass-status",
		"every kind: breakglass grant's activation history (spec.md §14) — local runtime state, never the roster definition itself",
		func() any { return buildInspectBreakglassStatus(opts.Dir) })
	add(resourceURIDNS, "dns",
		"FreeIPA DNS zones and records, each record's target_host cross-resolved to its inventory IP (resolved_ip)",
		func() any { return buildInspectDNSZones(opts.Dir, buildInspectHosts(opts.Dir)) })
	add(resourceURIInternalEndpoints, "internal-endpoints",
		"internal-endpoint manifest entries (dns/route/tls), every inventory_host reference cross-resolved to its inventory IP (resolved_ip)",
		func() any { return buildInspectInternalEndpoints(opts.Dir, buildInspectHosts(opts.Dir)) })
	add(resourceURIMonitoringTargets, "monitoring-targets",
		"external Prometheus monitoring targets Pilot does not manage via Ansible (spec.md §7-8)",
		func() any { return buildInspectMonitoringTargets(opts.Dir) })
	add(resourceURIMonitoringProfiles, "monitoring-scrape-profiles",
		"scrape profiles referenced by name from monitoring targets (spec.md §9-11)",
		func() any { return buildInspectMonitoringProfiles(opts.Dir) })
}
