// Package accessgrants drives spec.md §18 step 9 ("compile/reconcile
// grants") against a real FreeIPA target. internal/inventory's
// CompileGrants decides what should exist (pure, unit-tested, injected
// clock — see internal/inventory/grant_compile.go); this package is the
// other half of the "Go computes/decides, ansible-playbook mutates" split
// every other FreeIPA-mutating command in this codebase already follows
// (see internal/freeipa) — it turns that decision into an ansible-playbook
// invocation against playbooks/apply/freeipa-identity-apply.yml's
// `pilot_compiled_grant_*` extra-vars (that playbook's "Append v3.0
// compiled grant HBAC/sudo rules" tasks) rather than a separate playbook —
// this reuses its existing create/attach/detach/enable-disable reconcile
// machinery for compiled grants instead of duplicating it.
package accessgrants

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/inventory"
)

// DefaultPlaybook is the apply playbook ReconcileOnce invokes when
// ReconcileOptions.Playbook is unset.
const DefaultPlaybook = "playbooks/apply/freeipa-identity-apply.yml"

// playbookRunner is the seam ReconcileOnce runs through — satisfied by
// *ansible.Runner in production, and by a fake in tests that have no real
// FreeIPA server to talk to.
type playbookRunner interface {
	Run(ctx context.Context, args ...string) (*ansible.Result, error)
}

// ReconcileOptions configures a single grants reconcile pass.
type ReconcileOptions struct {
	// RosterFile and Inventory are required. RosterFile MUST have already
	// passed inventory.ValidateRosterFile — ReconcileOnce does not
	// re-validate it.
	RosterFile string
	Inventory  string

	// Playbook overrides DefaultPlaybook.
	Playbook string
	// VaultPasswordFile is required when RosterFile is ansible-vault
	// encrypted.
	VaultPasswordFile string
	// Now is the injected clock CompileGrants evaluates lifecycle against
	// (spec.md §8). Zero selects time.Now().
	Now time.Time

	// Runner overrides the ansible.Runner used to apply the plan. nil
	// selects a production ansible.NewRunner().
	Runner playbookRunner
}

func (o ReconcileOptions) runner() playbookRunner {
	if o.Runner != nil {
		return o.Runner
	}
	return ansible.NewRunner()
}

// Plan is every managed rule a reconcile pass decided on, before ansible
// ever runs — what `pilot access reconcile` prints, and what gets
// marshaled into the apply playbook's extra-vars.
type Plan struct {
	HBACRules []inventory.CompiledHBACRule
	SudoRules []inventory.CompiledSudoRule
}

// BuildPlan runs inventory.CompileGrants against the roster at rosterFile.
// Callers MUST have already run inventory.ValidateRosterFile successfully.
func BuildPlan(rosterFile string, now time.Time) (Plan, error) {
	hbac, sudo, err := inventory.CompileGrantsFile(rosterFile, now)
	if err != nil {
		return Plan{}, err
	}
	return Plan{HBACRules: hbac, SudoRules: sudo}, nil
}

// extraVarsHBACRule/extraVarsSudoRule/extraVars are the exact JSON shape
// playbooks/apply/freeipa-identity-apply.yml's `pilot_compiled_grant_*`
// extra-vars expect — see that playbook's header comment for how each
// field is consumed.
type extraVarsHBACRule struct {
	Name       string   `json:"name"`
	Users      []string `json:"users"`
	Groups     []string `json:"groups"`
	Hosts      []string `json:"hosts"`
	Hostgroups []string `json:"hostgroups"`
	Services   []string `json:"services"`
	Enabled    bool     `json:"enabled"`
}

type extraVarsSudoRule struct {
	Name               string   `json:"name"`
	Users              []string `json:"users"`
	Groups             []string `json:"groups"`
	Hosts              []string `json:"hosts"`
	Hostgroups         []string `json:"hostgroups"`
	AllowCommands      []string `json:"allow_commands,omitempty"`
	AllowCommandGroups []string `json:"allow_command_groups,omitempty"`
	Cmdcat             string   `json:"cmdcat,omitempty"`
	RunasUsers         []string `json:"runas_users"`
	RunasGroups        []string `json:"runas_groups"`
	Options            []string `json:"options"`
	SudoNotBefore      string   `json:"sudo_not_before,omitempty"`
	SudoNotAfter       string   `json:"sudo_not_after"`
}

type extraVars struct {
	FreeIPARosterFile           string              `json:"freeipa_roster_file"`
	PilotCompiledGrantHBACRules []extraVarsHBACRule `json:"pilot_compiled_grant_hbac_rules"`
	PilotCompiledGrantHBACPrune []string            `json:"pilot_compiled_grant_hbac_prune"`
	PilotCompiledGrantSudoRules []extraVarsSudoRule `json:"pilot_compiled_grant_sudo_rules"`
	PilotCompiledGrantSudoPrune []string            `json:"pilot_compiled_grant_sudo_prune"`
}

// buildExtraVars separates each compiled rule into either its
// present-and-desired list or its prune-by-name list (Present == false),
// per spec.md §9/§10's `absent -> absent` row.
func buildExtraVars(rosterFile string, plan Plan) extraVars {
	ev := extraVars{
		FreeIPARosterFile:           rosterFile,
		PilotCompiledGrantHBACRules: []extraVarsHBACRule{},
		PilotCompiledGrantHBACPrune: []string{},
		PilotCompiledGrantSudoRules: []extraVarsSudoRule{},
		PilotCompiledGrantSudoPrune: []string{},
	}
	for _, r := range plan.HBACRules {
		if !r.Present {
			ev.PilotCompiledGrantHBACPrune = append(ev.PilotCompiledGrantHBACPrune, r.Name)
			continue
		}
		ev.PilotCompiledGrantHBACRules = append(ev.PilotCompiledGrantHBACRules, extraVarsHBACRule{
			Name: r.Name, Users: emptyOr(r.Users), Groups: emptyOr(r.Groups),
			Hosts: emptyOr(r.Hosts), Hostgroups: emptyOr(r.Hostgroups),
			Services: emptyOr(r.Services), Enabled: r.Enabled,
		})
	}
	for _, r := range plan.SudoRules {
		if !r.Present {
			ev.PilotCompiledGrantSudoPrune = append(ev.PilotCompiledGrantSudoPrune, r.Name)
			continue
		}
		ev.PilotCompiledGrantSudoRules = append(ev.PilotCompiledGrantSudoRules, extraVarsSudoRule{
			Name: r.Name, Users: emptyOr(r.Users), Groups: emptyOr(r.Groups),
			Hosts: emptyOr(r.Hosts), Hostgroups: emptyOr(r.Hostgroups),
			AllowCommands: r.AllowCommands, AllowCommandGroups: r.AllowCommandGroups,
			Cmdcat:     r.CommandCategory,
			RunasUsers: emptyOr(r.RunAsUsers), RunasGroups: emptyOr(r.RunAsGroups),
			Options:       emptyOr(r.Options),
			SudoNotBefore: r.SudoNotBefore, SudoNotAfter: r.SudoNotAfter,
		})
	}
	return ev
}

// emptyOr returns a non-nil empty slice for a nil input, so the JSON
// encoding always emits [] rather than null. Ansible's `default([])`
// filter only substitutes for an *undefined* variable, not a defined-but-
// null one, so a bare `null` here would silently break every downstream
// `| length` / loop that assumes a list.
func emptyOr(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ReconcileOnce computes a Plan for opts.RosterFile against opts.Now (or
// time.Now() when zero) and applies it via opts.Playbook (or
// DefaultPlaybook) against opts.Inventory. It returns the Plan regardless
// of whether the apply run itself succeeds, so callers can report what was
// attempted even on failure.
func ReconcileOnce(ctx context.Context, opts ReconcileOptions) (Plan, *ansible.Result, error) {
	if opts.RosterFile == "" {
		return Plan{}, nil, fmt.Errorf("accessgrants: roster file is required")
	}
	if opts.Inventory == "" {
		return Plan{}, nil, fmt.Errorf("accessgrants: inventory is required")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	playbook := opts.Playbook
	if playbook == "" {
		playbook = DefaultPlaybook
	}

	plan, err := BuildPlan(opts.RosterFile, now)
	if err != nil {
		return Plan{}, nil, err
	}

	// freeipa_roster_file MUST be absolute: the apply playbook's own
	// `include_vars` resolves a relative path against the playbook file's
	// own directory, not this process's cwd (documented in
	// playbooks/apply/freeipa-identity.roster.example.yaml's header
	// comment, "-e freeipa_roster_file=/absolute/path") — confirmed live
	// on a vm-target, where a relative RosterFile made that task fail with
	// its no_log-censored error.
	absRosterFile, err := filepath.Abs(opts.RosterFile)
	if err != nil {
		return plan, nil, fmt.Errorf("accessgrants: resolve roster file path: %w", err)
	}
	ev := buildExtraVars(absRosterFile, plan)
	// Extra-vars go through a JSON @file, never a bare `-e k=v` command
	// line — a value containing whitespace silently truncates under
	// `-e k=v` (see internal/freeipa/probe.go's identical precaution).
	extraVarsFile, err := os.CreateTemp("", "pilot-access-reconcile-vars-*.json")
	if err != nil {
		return plan, nil, fmt.Errorf("accessgrants: create extra-vars file: %w", err)
	}
	extraVarsPath := extraVarsFile.Name()
	defer os.Remove(extraVarsPath)
	if err := json.NewEncoder(extraVarsFile).Encode(ev); err != nil {
		_ = extraVarsFile.Close()
		return plan, nil, fmt.Errorf("accessgrants: encode extra-vars: %w", err)
	}
	if err := extraVarsFile.Close(); err != nil {
		return plan, nil, fmt.Errorf("accessgrants: write extra-vars: %w", err)
	}

	args := []string{playbook, "-i", opts.Inventory, "-e", "@" + extraVarsPath}
	if opts.VaultPasswordFile != "" {
		args = append(args, "--vault-password-file", opts.VaultPasswordFile)
	}
	result, runErr := opts.runner().Run(ctx, args...)
	if runErr != nil {
		return plan, result, fmt.Errorf("accessgrants: ansible-playbook did not run: %w", runErr)
	}
	if result.ExitCode != 0 {
		return plan, result, fmt.Errorf("accessgrants: apply playbook %s exited %d", playbook, result.ExitCode)
	}
	return plan, result, nil
}
