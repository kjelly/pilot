// Package accessportal resolves a specific gateway's scoped access for a
// specific user: group/hostgroup closures, HBAC/sudo intersection with
// gateway.target_hostgroup, per spec.md §13-§21. It depends only on
// internal/freeipaaccess.Provider — never on roster, inventory, or any
// local state (SI-01/SI-02/SI-03).
package accessportal

import "time"

// GatewayConfig is one gateway instance's immutable identity (spec.md
// §10.2/§26): scope and target_hostgroup are the machine-readable policy
// reference, never derived from the hostname.
type GatewayConfig struct {
	ID              string
	Scope           string
	TargetHostgroup string
}

// UserContext is a user's identity plus effective (direct ∪ FreeIPA-
// computed-indirect) group membership — spec.md §13.
type UserContext struct {
	Username        string
	DirectGroups    []string
	EffectiveGroups []string
}

// GatewayScope is a gateway's fully expanded target host set (spec.md
// §14): MemberHosts ∪ IndirectMemberHosts from a single hostgroup_show
// call — see internal/freeipaaccess.Hostgroup's doc comment for why no
// recursive walk is needed.
type GatewayScope struct {
	GatewayID       string
	Scope           string
	TargetHostgroup string
	Hosts           map[string]struct{}
}

// UserAccess is the top-level per-user result (spec.md §19), scoped to
// exactly one gateway. Only hosts the user can actually SSH to are
// listed — see spec.md §9.3.
type UserAccess struct {
	User        string
	GeneratedAt time.Time
	Hosts       []HostAccess
}

// HostAccess is one host's SSH/sudo access summary within this gateway's scope.
type HostAccess struct {
	FQDN string
	SSH  SSHAccess
	Sudo SudoAccess
}

// SSHAccess reports HBAC(sshd)-derived access to one host.
type SSHAccess struct {
	Allowed bool
	Rules   []RuleSource
}

// SudoAccess reports sudo rule-derived access to one host (spec.md §17.3
// display-scope enum: none | limited | all | all_with_deny).
type SudoAccess struct {
	Scope         string
	AllowCommands []string
	DenyCommands  []string
	Rules         []SudoRuleSource
}

// RuleSource explains why an HBAC rule matched (spec.md §19), for Portal
// host-detail display (spec.md §27).
type RuleSource struct {
	Rule          string
	DirectUser    bool
	ViaGroups     []string
	DirectHost    bool
	ViaHostgroups []string
}

// SudoRuleSource names a sudo rule that matched, for the same display purpose.
type SudoRuleSource struct {
	Rule string
}
