// breakglass.go implements spec.md §14 (Phase 3): activating and
// deactivating a kind: breakglass grant definition. A definition
// (roster_grants.go's checkGrantActivation already validates its shape —
// Phase 1) is not effective access; activation is the separate runtime
// step that creates a time-bounded managed authorization using the exact
// same compiler and rule-naming convention as a temporary_grant
// (inventory.CompileBreakglassActivation, spec.md §14's explicit "same
// mechanism as §9"), and records who/why/until-when in a local state
// file — never in the roster itself (§14: activation MUST NOT rewrite the
// definition, MUST NOT create access-*).
package accessgrants

import (
	"context"
	"fmt"
	"time"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/statefile"
)

// activationStateVersion is statefile's on-disk schema version for
// breakglass-activations.json. Bump it (and handle migration explicitly)
// if Activation's shape ever changes incompatibly.
const activationStateVersion = 1

// activationStateFilename is the statefile.New filename, shared by every
// caller so they all read/write the same file.
const activationStateFilename = "breakglass-activations.json"

// Activation is one activate (and, if it happened, deactivate) event for
// a named kind: breakglass grant. The file accumulates history rather
// than being overwritten in place — Deactivated{,At} marks an entry done
// without erasing it, so `pilot access breakglass status` can show recent
// history, not just current state.
type Activation struct {
	Name          string    `json:"name"`
	ActivatedAt   time.Time `json:"activated_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Reason        string    `json:"reason"`
	Ticket        string    `json:"ticket"`
	ActivatedBy   string    `json:"activated_by"`
	Deactivated   bool      `json:"deactivated"`
	DeactivatedAt time.Time `json:"deactivated_at,omitzero"`
}

// IsActive reports whether this activation is currently in effect at now:
// not explicitly deactivated, and not yet past ExpiresAt.
func (a Activation) IsActive(now time.Time) bool {
	return !a.Deactivated && now.Before(a.ExpiresAt)
}

func openActivationStore(stateDir string) (*statefile.Store[Activation], error) {
	return statefile.New[Activation](stateDir, activationStateFilename, activationStateVersion, "breakglass")
}

// ActivateOptions configures a single breakglass activation.
type ActivateOptions struct {
	RosterFile  string // MUST have already passed inventory.ValidateRosterFile
	Inventory   string
	StateDir    string
	Name        string
	Duration    time.Duration
	Reason      string
	Ticket      string
	ActivatedBy string

	Playbook          string
	VaultPasswordFile string
	Now               time.Time
	Runner            playbookRunner
}

// Activate looks up the named kind: breakglass grant, enforces its
// activation policy (max_duration, require_reason, require_ticket —
// roster_grants.go's checkGrantActivation already validated these are
// well-formed; this is the "are THIS call's actual values acceptable"
// check), compiles it into a managed HBAC rule the same way a
// temporary_grant compiles (inventory.CompileBreakglassActivation), and
// applies that one rule immediately — not through a full grants
// reconcile pass. On success it records the activation in stateDir's
// breakglass-activations.json.
func Activate(ctx context.Context, opts ActivateOptions) (Activation, error) {
	if opts.RosterFile == "" || opts.Inventory == "" || opts.StateDir == "" || opts.Name == "" {
		return Activation{}, fmt.Errorf("accessgrants: roster file, inventory, state dir, and name are all required")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	grant, ok, err := inventory.FindGrantFile(opts.RosterFile, opts.Name)
	if err != nil {
		return Activation{}, err
	}
	if !ok {
		return Activation{}, fmt.Errorf("accessgrants: no grant named %q", opts.Name)
	}
	// ValidateBreakglassActivationRequest checks the requested duration/
	// reason/ticket against the grant's own activation policy
	// (max_duration, require_reason, require_ticket — defaulting to true
	// when unset, applied "at activation time" per spec.md §7).
	if err := inventory.ValidateBreakglassActivationRequest(grant, opts.Duration, opts.Reason, opts.Ticket); err != nil {
		return Activation{}, fmt.Errorf("accessgrants: %w", err)
	}
	// spec.md §15's account-lifecycle dominance ("account expired -> no
	// grant may restore access") applies to breakglass activation too —
	// checkGrants already forbids subjects.groups for breakglass, so this
	// only ever inspects direct named users.
	for _, user := range subjectUserNames(grant) {
		active, policyName, lifecycle, err := inventory.AccountActiveForUserFile(opts.RosterFile, user, now)
		if err != nil {
			return Activation{}, err
		}
		if !active {
			return Activation{}, fmt.Errorf("accessgrants: cannot activate %q: account_policy %q says user %q's account is %s", opts.Name, policyName, user, lifecycle)
		}
	}

	rule := inventory.CompileBreakglassActivation(grant, true)
	playbook := opts.Playbook
	if playbook == "" {
		playbook = DefaultPlaybook
	}
	runner := resolveRunner(opts.Runner)
	if _, err := applyPlan(ctx, opts.RosterFile, playbook, opts.Inventory, opts.VaultPasswordFile, runner, Plan{HBACRules: []inventory.CompiledHBACRule{rule}}); err != nil {
		return Activation{}, err
	}

	record := Activation{
		Name:        opts.Name,
		ActivatedAt: now,
		ExpiresAt:   now.Add(opts.Duration),
		Reason:      opts.Reason,
		Ticket:      opts.Ticket,
		ActivatedBy: opts.ActivatedBy,
	}
	store, err := openActivationStore(opts.StateDir)
	if err != nil {
		return Activation{}, err
	}
	if err := store.Mutate(func(activations []Activation) ([]Activation, error) {
		return append(activations, record), nil
	}); err != nil {
		return Activation{}, fmt.Errorf("accessgrants: activation applied to FreeIPA but recording state failed: %w", err)
	}
	return record, nil
}

// DeactivateOptions configures ending a breakglass activation early.
type DeactivateOptions struct {
	RosterFile string
	Inventory  string
	StateDir   string
	Name       string

	Playbook          string
	VaultPasswordFile string
	Now               time.Time
	Runner            playbookRunner
}

// Deactivate marks every currently-active activation for name as
// deactivated and prunes its compiled HBAC rule from FreeIPA. It is a
// no-op (not an error) when name has no active activation — deactivating
// something already inactive is idempotent.
func Deactivate(ctx context.Context, opts DeactivateOptions) error {
	if opts.RosterFile == "" || opts.Inventory == "" || opts.StateDir == "" || opts.Name == "" {
		return fmt.Errorf("accessgrants: roster file, inventory, state dir, and name are all required")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	grant, ok, err := inventory.FindGrantFile(opts.RosterFile, opts.Name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("accessgrants: no grant named %q", opts.Name)
	}

	rule := inventory.CompileBreakglassActivation(grant, false)
	playbook := opts.Playbook
	if playbook == "" {
		playbook = DefaultPlaybook
	}
	runner := resolveRunner(opts.Runner)
	if _, err := applyPlan(ctx, opts.RosterFile, playbook, opts.Inventory, opts.VaultPasswordFile, runner, Plan{HBACRules: []inventory.CompiledHBACRule{rule}}); err != nil {
		return err
	}

	store, err := openActivationStore(opts.StateDir)
	if err != nil {
		return err
	}
	return store.Mutate(func(activations []Activation) ([]Activation, error) {
		for i, a := range activations {
			if a.Name == opts.Name && a.IsActive(now) {
				activations[i].Deactivated = true
				activations[i].DeactivatedAt = now
			}
		}
		return activations, nil
	})
}

// Status returns every recorded activation for name (or all names when
// name is ""), most recent first.
func Status(stateDir, name string) ([]Activation, error) {
	store, err := openActivationStore(stateDir)
	if err != nil {
		return nil, err
	}
	activations, err := store.Load()
	if err != nil {
		return nil, err
	}
	if name == "" {
		return reverse(activations), nil
	}
	var out []Activation
	for _, a := range activations {
		if a.Name == name {
			out = append(out, a)
		}
	}
	return reverse(out), nil
}

func reverse(activations []Activation) []Activation {
	out := make([]Activation, len(activations))
	for i, a := range activations {
		out[len(activations)-1-i] = a
	}
	return out
}

// subjectUserNames extracts grant["subjects"]["users"] as a []string.
// accessgrants has no access to inventory's unexported roster-map helpers
// (listField/stringListField), so this is the minimal local equivalent
// for the one map shape this package needs to read directly.
func subjectUserNames(grant map[string]any) []string {
	subjects, _ := grant["subjects"].(map[string]any)
	raw, _ := subjects["users"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
