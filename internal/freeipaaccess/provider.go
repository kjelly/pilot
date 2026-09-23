// Package freeipaaccess is the read-only FreeIPA JSON-RPC/Kerberos client
// for pilot-access-gateway (spec.md §11). It never reads roster, inventory,
// or any local persistent state (SI-01/SI-02/SI-03) — every fact it returns
// comes from a live call against a real FreeIPA server.
//
// This package deliberately stays at the "one object per call" level: it
// does not walk group/hostgroup membership closures, and it does not
// intersect HBAC/sudo data with a gateway's target scope. That resolution
// logic belongs to internal/accessportal (Phase 2, spec.md §36 package
// layout) and is built on top of the Provider interface below. Spec.md §11
// originally sketched a higher-level Provider (LoadUserContext /
// LoadAccessSnapshot / CheckSSH returning fully-resolved data) — Phase 1
// splits that into these primitives instead, so this package's tests never
// need a live FreeIPA server (only the fixtures in testdata/), and the
// closure/graph logic (which does need cycle guards, dedupe, etc.) lives
// in one place. See docs/evidence/pilot-access-gateway/ for the Phase 1
// evidence recording this deviation.
package freeipaaccess

import (
	"context"
	"time"
)

// Provider is the FreeIPA read surface every caller in this repo must use —
// never a raw HTTP/JSON-RPC call built ad hoc elsewhere. It mirrors exactly
// the operations spec.md §10.3 lists for the "Pilot Access Gateway Reader"
// FreeIPA role; anything not listed here has no business being called by
// pilot-access-gateway.
type Provider interface {
	// Ping verifies Kerberos auth and connectivity without touching any
	// application data (spec.md §10.3, §58 doctor).
	Ping(ctx context.Context) (PingResult, error)

	UserShow(ctx context.Context, username string) (User, error)
	GroupShow(ctx context.Context, name string) (Group, error)
	HostShow(ctx context.Context, fqdn string) (Host, error)
	HostgroupShow(ctx context.Context, name string) (Hostgroup, error)

	// HBACRuleFind returns every HBAC rule (spec.md §15: hbacrule_find(all=true)).
	HBACRuleFind(ctx context.Context) ([]HBACRule, error)
	HBACServiceGroupShow(ctx context.Context, name string) (HBACServiceGroup, error)

	// SudoRuleFind returns every sudo rule (spec.md §17: sudorule_find(all=true)).
	SudoRuleFind(ctx context.Context) ([]SudoRule, error)
	SudoCommandShow(ctx context.Context, name string) (SudoCommand, error)
	SudoCommandGroupShow(ctx context.Context, name string) (SudoCommandGroup, error)

	// HBACTest is the optional fresh-connect verification path (spec.md §16).
	HBACTest(ctx context.Context, req HBACTestRequest) (HBACTestResult, error)
}

// PingResult is a minimal liveness/version signal, never anything from
// which access policy could be derived.
type PingResult struct {
	ServerVersion string
}

// User is a normalized user_show(all=true) result.
//
// DirectGroups and IndirectGroups are two separate raw FreeIPA attributes
// (memberof_group / memberofindirect_group) from the SAME user_show call —
// not the result of this package walking anything. FreeIPA's own memberof
// plugin already computes the full transitive group closure server-side
// (verified live: a 3-level nested-group chain's leaf member shows up in
// the top group's memberofindirect_group with no recursive lookups on our
// part, and this holds even across a deliberately-created group cycle —
// see docs/evidence/pilot-access-gateway/2026-09-14-phase2-accessportal.md).
// internal/accessportal's EffectiveGroups is therefore just
// DirectGroups ∪ IndirectGroups, not a graph walk.
type User struct {
	Username       string
	Enabled        bool
	DirectGroups   []string
	IndirectGroups []string
}

// Group is a normalized group_show(all=true) result. MemberGroups is the
// set of other groups directly nested inside this one (for closure
// resolution in Phase 2); it is empty whenever a group has no nested-group
// members, which is the common case and not itself an error.
type Group struct {
	Name         string
	MemberUsers  []string
	MemberGroups []string
}

// Host is a normalized host_show(all=true) result.
//
// Annotations is parsed from the host's userClass values that carry the
// "pilot.annotation." prefix (docs/superpowers/specs/2026-09-09-host-
// annotations-freeipa-sync-spec.md) — non-secret asset metadata like
// owner/project/location an operator attached via `pilot edit`. This
// package deliberately does not import internal/inventory (spec.md §17/
// §18: pilot-access-gateway has no roster/inventory dependency), so the
// prefix and parsing are duplicated locally in normalize.go rather than
// shared with internal/inventory.SerializeAnnotation's counterpart.
//
// SSHRecording is the host's parsed `pilot.policy.ssh-recording=` userClass
// marker (per-host recording spec §7/§10) — a runtime policy input, kept
// strictly apart from the descriptive Annotations. Its zero value is NOT
// "absent": Valid is false, so a code path that forgets to parse the policy
// fails closed instead of silently meaning "do not record".
type Host struct {
	FQDN         string
	Annotations  map[string]string
	SSHRecording HostRecordingPolicy
}

// HostRecordingPolicy is the parsed pilot.policy.ssh-recording marker state
// of one FreeIPA host (per-host recording spec §10).
type HostRecordingPolicy struct {
	// Present reports whether at least one managed value exists.
	Present bool
	// Mode is "off" or "terminal_output" when Valid && Present.
	Mode string
	// Valid is true for "absent" or exactly one well-formed known value.
	Valid bool
	// Unreadable is set when attributelevelrights shows the reading
	// principal cannot read userclass (spec §9 branch R): the absence of a
	// marker then proves nothing.
	Unreadable bool
	// Reason is one of the fixed codes "duplicate", "malformed",
	// "unknown_value", "userclass_unreadable" — never raw LDAP data.
	Reason string
}

// NewHostWithoutPolicy returns a Host whose recording policy is explicitly
// absent-and-valid (inherit), for fakes and tests that model a host with no
// pilot.policy.ssh-recording marker.
func NewHostWithoutPolicy(fqdn string) Host {
	return Host{FQDN: fqdn, SSHRecording: HostRecordingPolicy{Valid: true}}
}

// Hostgroup is a normalized hostgroup_show(all=true) result.
// MemberHostgroups holds directly nested hostgroups (diagnostic use only).
//
// IndirectMemberHosts is FreeIPA's own server-computed transitive host
// closure (memberindirect_host) — every host reachable through any depth
// of nested hostgroups, from this one call. spec.md §14's gateway target
// host expansion is therefore MemberHosts ∪ IndirectMemberHosts, not a
// recursive hostgroup_show walk with its own cycle guard: verified live
// against a deliberately cyclic hostgroup pair (hg-parent ⊂ hg-child ⊂
// hg-parent) that FreeIPA itself does not reject — it still computed a
// correct, terminating memberindirect_host (the cycle only causes a
// hostgroup to show up in its own memberindirect_hostgroup, a field this
// package does not use for the host set). See
// docs/evidence/pilot-access-gateway/2026-09-14-phase2-accessportal.md.
type Hostgroup struct {
	Name                string
	MemberHosts         []string
	MemberHostgroups    []string
	IndirectMemberHosts []string
}

// HostgroupSummary is a normalized hostgroup_find(all=true) row — one entry
// per matched hostgroup, name only. It is deliberately not a full
// Hostgroup: hostgroup_find does not return memberindirect_host (verified
// live against ag-spike-ipa, spec.md/docs/tmp/now/spec.md §8.2), so a
// caller that needs the transitive host closure for a discovered group
// must still call HostgroupShow for that name — HostgroupFind only answers
// "which hostgroups exist under this prefix".
type HostgroupSummary struct {
	Name string
}

// HostgroupFinder is a narrow, additive read capability: hostgroup listing
// by name-substring criteria (hostgroup_find). It is deliberately NOT
// folded into Provider — every existing accessportal fake provider and
// test would otherwise be forced to implement a method it has no use for.
// A caller (pilot-access-directory) that needs both hostgroup discovery
// and the rest of Provider depends on both interfaces separately.
type HostgroupFinder interface {
	// HostgroupFind returns every hostgroup whose cn contains criteria as a
	// substring (FreeIPA's own *_find semantics — not a prefix-only match,
	// though "pilot-target-"/"pilot-gateway-" style criteria behave like a
	// prefix match in practice since cn never contains that string
	// elsewhere).
	HostgroupFind(ctx context.Context, criteria string) ([]HostgroupSummary, error)
}

// HBACRule is a normalized hbacrule_show/hbacrule_find(all=true) entry.
// Deliberately parsed from FreeIPA's non-raw representation (member*_user,
// member*_group, ... suffixed fields with plain resolved names), not
// raw=true LDAP DNs — see normalize.go's doc comment for why.
type HBACRule struct {
	Name    string
	Enabled bool

	UserCategoryAll bool
	Users           []string
	Groups          []string

	HostCategoryAll bool
	Hosts           []string
	Hostgroups      []string

	ServiceCategoryAll bool
	Services           []string
	ServiceGroups      []string
}

// HBACServiceGroup is a normalized hbacsvcgroup_show(all=true) result.
type HBACServiceGroup struct {
	Name     string
	Services []string
}

// SudoRule is a normalized sudorule_show/sudorule_find(all=true) entry.
//
// RunAsUsers/RunAsGroups/Options from spec.md §17 are intentionally
// omitted here: Phase 1's live capture never exercised them, and per this
// repo's fixture-must-be-real-capture rule they are not being guessed at.
// Add them (and a testdata fixture) when a phase actually needs them.
type SudoRule struct {
	Name    string
	Enabled bool

	UserCategoryAll bool
	Users           []string
	Groups          []string

	HostCategoryAll bool
	Hosts           []string
	Hostgroups      []string

	CommandCategoryAll bool
	AllowCommands      []string
	AllowCommandGroups []string
	DenyCommands       []string
	DenyCommandGroups  []string

	NotBefore *time.Time
	NotAfter  *time.Time
}

// SudoCommand is a normalized sudocmd_show(all=true) result.
type SudoCommand struct {
	Command string
}

// SudoCommandGroup is a normalized sudocmdgroup_show(all=true) result.
type SudoCommandGroup struct {
	Name     string
	Commands []string
}

// HBACTestRequest mirrors the subset of the hbactest RPC this package uses
// (spec.md §16): a specific user/host/service triple, never a caller-
// controlled rule list — every enabled rule is always considered.
type HBACTestRequest struct {
	User       string
	TargetHost string
	Service    string
}

// HBACTestResult is a normalized hbactest response.
type HBACTestResult struct {
	Access  bool
	Matched []string
}
