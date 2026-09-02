// Package decommission implements Pilot's host decommission planner: a
// read-only, resumable saga that replaces the old unsafe "delete a host
// from hosts.yml" action with plan -> approve -> clean -> verify ->
// finalize (docs/superpowers/specs/2026-09-02-host-decommission-spec.md).
//
// Phase 1 (this package's current scope, spec.md §37) delivers only the
// planner, the reverse-reference scanner, plan hashing/freshness, and the
// persisted saga store. No provider executes a live mutation yet — every
// component with external state is classified external_state_unsupported
// until a Phase 3/4/5 provider registers (see providers/provider.go).
package decommission

import (
	"crypto/rand"
	"encoding/hex"
)

// ReferenceClassification is how one discovered workspace reference to the
// target host is treated during planning (spec.md §12.1).
type ReferenceClassification string

const (
	AutoRemove          ReferenceClassification = "AUTO_REMOVE"
	RequiresReplacement ReferenceClassification = "REQUIRES_REPLACEMENT"
	Informational       ReferenceClassification = "INFORMATIONAL"
	ForeignUnknown      ReferenceClassification = "FOREIGN_UNKNOWN"
	HardBlockerRef      ReferenceClassification = "HARD_BLOCKER"
)

// Reference is one discovered workspace pointer at the target host,
// classified before any mutation (INV-6, spec.md §12).
type Reference struct {
	Source         string // e.g. "freeipa-roster", "internal-endpoints.yaml", "host_vars"
	Kind           string // e.g. "hostgroup_membership", "hbac_rule", "endpoint_target"
	Identity       string // the referencing object's name/path
	Classification ReferenceClassification
	Detail         string
}

// Blocker is a hard stop that prevents an executable plan (INV-7/INV-8/
// INV-13/etc). Code matches the taxonomy in errors.go.
type Blocker struct {
	Code   ErrorClass
	Detail string
}

// Warning is a non-blocking planning note.
type Warning struct {
	Code   string
	Detail string
}

// Reachability is the operator/transport-observed reachability signal fed
// into Plan() (spec.md §21). Phase 1 never probes a live host itself —
// callers may supply it; the default is Unknown.
type Reachability string

const (
	ReachabilityUnknown     Reachability = ""
	ReachabilityReachable   Reachability = "reachable"
	ReachabilityUnreachable Reachability = "unreachable"
)

// OfflineDisposition is the operator's explicit call on an unreachable host
// (spec.md §21.1).
type OfflineDisposition string

const (
	OfflineDispositionNone                   OfflineDisposition = ""
	OfflineDispositionTemporarilyUnreachable OfflineDisposition = "temporarily_unreachable"
	OfflineDispositionPermanentlyLost        OfflineDisposition = "permanently_lost"
)

// RetentionDisposition is the operator's explicit call for one stateful
// component with retention=required (spec.md §20.1).
type RetentionDisposition string

const (
	RetentionDispositionNone              RetentionDisposition = ""
	RetentionDispositionExported          RetentionDisposition = "exported"
	RetentionDispositionMigrated          RetentionDisposition = "migrated"
	RetentionDispositionRetainOnDisk      RetentionDisposition = "retain_on_disk"
	RetentionDispositionDestroyAuthorized RetentionDisposition = "destroy_authorized"
)

// LocalCleanupStatus records whether a component's local cleanup step
// actually ran/verified, or was attested-unavailable because the host is
// permanently lost. Never fabricated as "verified_removed" (spec.md §21.2).
type LocalCleanupStatus string

const (
	LocalCleanupNotPlanned          LocalCleanupStatus = ""
	LocalCleanupPlanned             LocalCleanupStatus = "planned"
	LocalCleanupUnavailableAttested LocalCleanupStatus = "local_cleanup_unavailable_attested"
)

// PlanStatus is the top-level planning outcome.
type PlanStatus string

const (
	PlanStatusExecutable PlanStatus = "executable"
	PlanStatusBlocked    PlanStatus = "blocked"
)

// HostSnapshot is the frozen, plan-bound copy of the target host's
// inventory record (spec.md §26/§9.1 host_snapshot_json).
type HostSnapshot struct {
	Name        string
	AnsibleHost string
	AnsibleUser string
	Env         string
	Roles       []string
	Extra       map[string]string
}

// ComponentPlan is one selected component's (role's) decommission planning
// outcome.
type ComponentPlan struct {
	Role                 string
	ComponentID          string // "" when no contract matched the role
	HasContract          bool
	DeclaresDecommission bool // Playbooks.Decommission != nil
	RetentionRequired    bool
	RetentionSatisfied   bool
	LocalCleanupStatus   LocalCleanupStatus
	Blockers             []Blocker
	Warnings             []Warning
}

// Blocked reports whether c currently blocks planning.
func (c ComponentPlan) Blocked() bool { return len(c.Blockers) > 0 }

// RetentionRequirement records one component's retention gate outcome.
type RetentionRequirement struct {
	ComponentID string
	Required    bool
	Disposition RetentionDisposition
	Satisfied   bool
}

// Plan is the full, hashable decommission plan for one host (spec.md
// §9.1/§26/§28).
type Plan struct {
	ID     string
	Status PlanStatus

	Host        HostSnapshot
	Environment string

	Components      []ComponentPlan
	TeardownOrder   []string // component IDs, consumers before providers
	DependencyCycle bool

	References []Reference

	RetentionRequirements []RetentionRequirement
	Reachability          Reachability
	OfflineDisposition    OfflineDisposition

	Blockers []Blocker
	Warnings []Warning

	PlanHash string

	// InventoryRevision is a canonical (order-independent) hash of the
	// parsed hosts.yml at plan time — not a raw-byte hash, so that
	// semantically identical YAML in different map/key order produces the
	// same value (HD3).
	InventoryRevision string

	CreatedAt string // RFC3339Nano
	ExpiresAt string // RFC3339Nano
}

// Blocked reports whether the plan has at least one blocker (plan- or
// component-level) — i.e. it is not currently executable (INV-7).
func (p *Plan) Blocked() bool {
	if p == nil {
		return true
	}
	if len(p.Blockers) > 0 {
		return true
	}
	for _, c := range p.Components {
		if c.Blocked() {
			return true
		}
	}
	return false
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read only fails on a broken system entropy source;
		// fall back to a fixed-but-distinguishable value rather than
		// panicking a planning call over ID uniqueness.
		for i := range b {
			b[i] = byte(i)
		}
	}
	return hex.EncodeToString(b)
}

func newPlanID() string     { return "hd-" + randomHex(12) }
func newApprovalID() string { return "hda-" + randomHex(8) }
