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
	"strings"
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
	// StateDir enables spec.md §11's auth_policies prune tracking
	// (auth_policy_state.go) — a host Pilot previously set
	// krbPrincipalAuthInd on that drops out of the current roster's
	// auth_policies gets its indicators explicitly cleared. Empty skips
	// prune tracking entirely (no error) rather than failing the whole
	// reconcile — callers that only care about HBAC/sudo grants (or tests
	// with no auth_policies at all) are unaffected either way.
	StateDir string

	// Now is the injected clock CompileGrants evaluates lifecycle against
	// (spec.md §8). Zero selects time.Now().
	Now time.Time

	// Runner overrides the ansible.Runner used to apply the plan. nil
	// selects a production ansible.NewRunner().
	Runner playbookRunner
}

func (o ReconcileOptions) runner() playbookRunner {
	return resolveRunner(o.Runner)
}

// resolveRunner returns r if non-nil, otherwise a production
// ansible.NewRunner() — the shared "nil means real ansible-playbook"
// default every options struct in this package uses.
func resolveRunner(r playbookRunner) playbookRunner {
	if r != nil {
		return r
	}
	return ansible.NewRunner()
}

// Plan is every managed rule a reconcile pass decided on, before ansible
// ever runs — what `pilot access reconcile` prints, and what gets
// marshaled into the apply playbook's extra-vars.
type Plan struct {
	HBACRules []inventory.CompiledHBACRule
	SudoRules []inventory.CompiledSudoRule
	// AuthPolicyHosts is spec.md §11's compiled per-host authentication-
	// indicator requirement (auth_policies:), applied via `ipa host-mod
	// --auth-ind=`.
	AuthPolicyHosts []inventory.CompiledAuthPolicyHost
	// AccountExpirations is v3.1 §7's compiled per-user native
	// FreeIPA/Kerberos principal-expiration state (account_policies:),
	// applied via `ipa user-mod --setattr=krbprincipalexpiration=`.
	AccountExpirations []inventory.CompiledAccountExpiration
	// PasswordPolicies is v3.2 §7's compiled group password policies
	// (password_policies:), applied via `ipa pwpolicy-add/mod/remove`.
	PasswordPolicies []inventory.CompiledPasswordPolicy
	// UserAuthTypes is v3.2 §8's compiled per-user authentication.allowed
	// (users[].authentication:), applied via `ipa user-mod
	// --user-auth-type=`. Only users that declare an explicit
	// authentication: block are present here (see CompiledUserAuthType's
	// doc comment).
	UserAuthTypes []inventory.CompiledUserAuthType
}

// PolicyGate is the result of spec.md §18 steps 4/5 — Separation of Duties
// and grant security policy evaluation — plus §15's account-lifecycle
// dominance rule. All three are semantic checks that MUST fail before any
// mutation, run independently of the purely structural
// inventory.ValidateRosterFile gate.
type PolicyGate struct {
	SoDConflicts               []inventory.SoDConflict
	GrantPolicyViolations      []inventory.GrantPolicyViolation
	AccountLifecycleViolations []inventory.AccountLifecycleViolation
	// PrivilegedIdentityViolations is v3.2 §9's fail-before-write
	// baseline: an effectively-privileged user (security.
	// privileged_identity.match_groups, resolved through nested
	// membership) whose own authentication.allowed does not meet
	// require.auth_types/no_password_only.
	PrivilegedIdentityViolations []inventory.PrivilegedIdentityViolation
}

// Empty reports whether the gate found nothing to block on.
func (g PolicyGate) Empty() bool {
	return len(g.SoDConflicts) == 0 && len(g.GrantPolicyViolations) == 0 &&
		len(g.AccountLifecycleViolations) == 0 && len(g.PrivilegedIdentityViolations) == 0
}

// String renders every violation as one line, for an error message or log.
func (g PolicyGate) String() string {
	var b strings.Builder
	for _, c := range g.SoDConflicts {
		fmt.Fprintf(&b, "SoD conflict %q: user %q is in %v; ", c.RuleName, c.User, c.Groups)
	}
	for _, v := range g.GrantPolicyViolations {
		fmt.Fprintf(&b, "grant_policy %q: grant %q: %s; ", v.PolicyName, v.GrantName, v.Detail)
	}
	for _, v := range g.AccountLifecycleViolations {
		fmt.Fprintf(&b, "account lifecycle: grant %q reaches user %q whose account is %s (account_policy %q); ", v.GrantName, v.User, v.AccountLifecycle, v.AccountPolicyName)
	}
	for _, v := range g.PrivilegedIdentityViolations {
		fmt.Fprintf(&b, "privileged_identity: user %q %s; ", v.User, v.Detail)
	}
	return strings.TrimSuffix(b.String(), "; ")
}

// EvaluatePolicyGate runs all four semantic checks against the roster at
// rosterFile, evaluated against now. Callers MUST have already run
// inventory.ValidateRosterFile successfully.
func EvaluatePolicyGate(rosterFile string, now time.Time) (PolicyGate, error) {
	conflicts, err := inventory.EvaluateSoDFile(rosterFile)
	if err != nil {
		return PolicyGate{}, err
	}
	violations, err := inventory.EvaluateGrantPoliciesFile(rosterFile, now)
	if err != nil {
		return PolicyGate{}, err
	}
	accountViolations, err := inventory.EvaluateAccountLifecycleFile(rosterFile, now)
	if err != nil {
		return PolicyGate{}, err
	}
	privilegedIdentityViolations, err := inventory.EvaluatePrivilegedIdentityBaselineFile(rosterFile)
	if err != nil {
		return PolicyGate{}, err
	}
	return PolicyGate{
		SoDConflicts: conflicts, GrantPolicyViolations: violations,
		AccountLifecycleViolations: accountViolations, PrivilegedIdentityViolations: privilegedIdentityViolations,
	}, nil
}

// BuildPlan runs inventory.CompileGrants against the roster at rosterFile.
// Callers MUST have already run inventory.ValidateRosterFile successfully.
func BuildPlan(rosterFile string, now time.Time) (Plan, error) {
	hbac, sudo, err := inventory.CompileGrantsFile(rosterFile, now)
	if err != nil {
		return Plan{}, err
	}
	authPolicyHosts, err := inventory.CompileAuthPoliciesFile(rosterFile)
	if err != nil {
		return Plan{}, err
	}
	accountExpirations, err := inventory.CompileAccountPoliciesFile(rosterFile)
	if err != nil {
		return Plan{}, err
	}
	passwordPolicies, err := inventory.CompilePasswordPoliciesFile(rosterFile)
	if err != nil {
		return Plan{}, err
	}
	userAuthTypes, err := inventory.CompileUserAuthTypesFile(rosterFile)
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		HBACRules: hbac, SudoRules: sudo, AuthPolicyHosts: authPolicyHosts,
		AccountExpirations: accountExpirations, PasswordPolicies: passwordPolicies,
		UserAuthTypes: userAuthTypes,
	}, nil
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

type extraVarsAuthPolicyHost struct {
	Host       string   `json:"host"`
	Indicators []string `json:"indicators"`
}

// extraVarsAccountExpiration mirrors extraVarsAuthPolicyHost's clear
// convention: an empty Expiration is the explicit-clear signal the apply
// playbook's task keys off, rather than a separate boolean field on the
// wire (§7.4).
type extraVarsAccountExpiration struct {
	User       string `json:"user"`
	Expiration string `json:"expiration"`
}

// extraVarsPasswordPolicy is the exact JSON shape playbooks/apply/
// freeipa-identity-apply.yml's `pilot_compiled_password_policies`
// extra-var expects. Every optional field uses a nil-omitting pointer
// (json:",omitempty" on *int omits only on a nil pointer, never on a
// pointer to zero) so the playbook can tell "absent from the roster"
// (item.history_size is not defined) apart from "explicitly set to zero"
// (item.history_size == 0) — see CompiledPasswordPolicy's doc comment.
type extraVarsPasswordPolicy struct {
	Name                       string `json:"name"`
	State                      string `json:"state"`
	Group                      string `json:"group"`
	Priority                   *int   `json:"priority,omitempty"`
	MinLength                  *int   `json:"min_length,omitempty"`
	HistorySize                *int   `json:"history_size,omitempty"`
	MaxLifeDays                *int   `json:"max_life_days,omitempty"`
	MinLifeHours               *int   `json:"min_life_hours,omitempty"`
	LockoutMaxFailures         *int   `json:"lockout_max_failures,omitempty"`
	LockoutFailureResetSeconds *int   `json:"lockout_failure_reset_seconds,omitempty"`
	LockoutDurationSeconds     *int   `json:"lockout_duration_seconds,omitempty"`
}

// extraVarsUserAuthType is the exact JSON shape playbooks/apply/
// freeipa-identity-apply.yml's `pilot_compiled_user_auth_types` extra-var
// expects.
type extraVarsUserAuthType struct {
	User    string   `json:"user"`
	Allowed []string `json:"allowed"`
}

type extraVars struct {
	FreeIPARosterFile               string                       `json:"freeipa_roster_file"`
	PilotCompiledGrantHBACRules     []extraVarsHBACRule          `json:"pilot_compiled_grant_hbac_rules"`
	PilotCompiledGrantHBACPrune     []string                     `json:"pilot_compiled_grant_hbac_prune"`
	PilotCompiledGrantSudoRules     []extraVarsSudoRule          `json:"pilot_compiled_grant_sudo_rules"`
	PilotCompiledGrantSudoPrune     []string                     `json:"pilot_compiled_grant_sudo_prune"`
	PilotCompiledAuthPolicyHosts    []extraVarsAuthPolicyHost    `json:"pilot_compiled_auth_policy_hosts"`
	PilotCompiledAccountExpirations []extraVarsAccountExpiration `json:"pilot_compiled_account_expirations"`
	PilotCompiledPasswordPolicies   []extraVarsPasswordPolicy    `json:"pilot_compiled_password_policies"`
	PilotCompiledUserAuthTypes      []extraVarsUserAuthType      `json:"pilot_compiled_user_auth_types"`
}

// buildExtraVars separates each compiled rule into either its
// present-and-desired list or its prune-by-name list (Present == false),
// per spec.md §9/§10's `absent -> absent` row.
func buildExtraVars(rosterFile string, plan Plan) extraVars {
	ev := extraVars{
		FreeIPARosterFile:               rosterFile,
		PilotCompiledGrantHBACRules:     []extraVarsHBACRule{},
		PilotCompiledGrantHBACPrune:     []string{},
		PilotCompiledGrantSudoRules:     []extraVarsSudoRule{},
		PilotCompiledGrantSudoPrune:     []string{},
		PilotCompiledAuthPolicyHosts:    []extraVarsAuthPolicyHost{},
		PilotCompiledAccountExpirations: []extraVarsAccountExpiration{},
		PilotCompiledPasswordPolicies:   []extraVarsPasswordPolicy{},
		PilotCompiledUserAuthTypes:      []extraVarsUserAuthType{},
	}
	for _, h := range plan.AuthPolicyHosts {
		ev.PilotCompiledAuthPolicyHosts = append(ev.PilotCompiledAuthPolicyHosts, extraVarsAuthPolicyHost{Host: h.Host, Indicators: emptyOr(h.Indicators)})
	}
	for _, a := range plan.AccountExpirations {
		ev.PilotCompiledAccountExpirations = append(ev.PilotCompiledAccountExpirations, extraVarsAccountExpiration{User: a.User, Expiration: a.Expiration})
	}
	for _, p := range plan.PasswordPolicies {
		ev.PilotCompiledPasswordPolicies = append(ev.PilotCompiledPasswordPolicies, extraVarsPasswordPolicy{
			Name: p.Name, State: p.State, Group: p.Group,
			Priority: p.Priority, MinLength: p.MinLength, HistorySize: p.HistorySize,
			MaxLifeDays: p.MaxLifeDays, MinLifeHours: p.MinLifeHours,
			LockoutMaxFailures: p.LockoutMaxFailures, LockoutFailureResetSeconds: p.LockoutFailureResetSeconds,
			LockoutDurationSeconds: p.LockoutDurationSeconds,
		})
	}
	for _, a := range plan.UserAuthTypes {
		ev.PilotCompiledUserAuthTypes = append(ev.PilotCompiledUserAuthTypes, extraVarsUserAuthType{User: a.User, Allowed: emptyOr(a.Allowed)})
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

	// spec.md §18 steps 4/5 ("SoD evaluation", "grant policy evaluation")
	// are a hard gate before any mutation — a violation here MUST stop the
	// whole reconcile, not just the offending grant.
	gate, err := EvaluatePolicyGate(opts.RosterFile, now)
	if err != nil {
		return Plan{}, nil, err
	}
	if !gate.Empty() {
		return Plan{}, nil, fmt.Errorf("accessgrants: refusing to reconcile: %s", gate.String())
	}

	plan, err := BuildPlan(opts.RosterFile, now)
	if err != nil {
		return Plan{}, nil, err
	}

	// spec.md §13/§21.1: a capability-gated control (group password
	// policy, its lockout fields, or user auth types) may only be applied
	// once a live probe confirms FreeIPA actually supports it — an
	// unknown capability state fails closed exactly like a confirmed
	// unsupported one, never silently skipped.
	if err := requireFreeIPACapabilities(ctx, opts, plan); err != nil {
		return Plan{}, nil, err
	}

	// spec.md §11 prune: diff this reconcile's desired auth-policy hosts
	// against what Pilot last recorded, and append explicit-clear entries
	// for hosts that dropped out — captured before merging so
	// recordAuthPolicyState below persists only the true desired state,
	// not the temporary clear entries.
	desiredAuthPolicyHosts := plan.AuthPolicyHosts
	if opts.StateDir != "" {
		pruneHosts, err := planAuthPolicyPrune(opts.StateDir, desiredAuthPolicyHosts)
		if err != nil {
			return Plan{}, nil, err
		}
		if len(pruneHosts) > 0 {
			plan.AuthPolicyHosts = append(append([]inventory.CompiledAuthPolicyHost{}, desiredAuthPolicyHosts...), pruneHosts...)
		}
	}

	result, err := applyPlan(ctx, opts.RosterFile, playbook, opts.Inventory, opts.VaultPasswordFile, opts.runner(), plan)
	if err == nil && opts.StateDir != "" {
		if serr := recordAuthPolicyState(opts.StateDir, desiredAuthPolicyHosts); serr != nil {
			return plan, result, fmt.Errorf("accessgrants: reconcile applied but recording auth-policy state failed: %w", serr)
		}
	}

	// spec.md v3.1 §15: record this explicit reconcile regardless of
	// outcome. A failed audit write on an otherwise-successful reconcile
	// is itself worth surfacing (a gap in the audit trail); a failed audit
	// write on an already-failing reconcile must not mask the original
	// error — best-effort only in that branch.
	if opts.StateDir != "" {
		outcome := "success"
		if err != nil {
			outcome = "failure"
		}
		auditErr := AppendAuditEvent(opts.StateDir, AccessAuditEvent{
			Action:     AuditActionExplicitAccessReconcile,
			SourceKind: "temporary_grant,sudo_grant,auth_policy,account_policy",
			Resource:   opts.RosterFile,
			Outcome:    outcome,
		})
		if auditErr != nil && err == nil {
			return plan, result, fmt.Errorf("accessgrants: reconcile applied but recording the audit event failed: %w", auditErr)
		}
	}
	return plan, result, err
}

// applyPlan is ReconcileOnce's and ApplyAdHocHBACRule's shared "turn a Plan
// into extra-vars and invoke ansible-playbook" tail.
func applyPlan(ctx context.Context, rosterFile, playbook, inventoryPath, vaultPasswordFile string, runner playbookRunner, plan Plan) (*ansible.Result, error) {
	// freeipa_roster_file MUST be absolute: the apply playbook's own
	// `include_vars` resolves a relative path against the playbook file's
	// own directory, not this process's cwd (documented in
	// playbooks/apply/freeipa-identity.roster.example.yaml's header
	// comment, "-e freeipa_roster_file=/absolute/path") — confirmed live
	// on a vm-target, where a relative RosterFile made that task fail with
	// its no_log-censored error.
	absRosterFile, err := filepath.Abs(rosterFile)
	if err != nil {
		return nil, fmt.Errorf("accessgrants: resolve roster file path: %w", err)
	}
	ev := buildExtraVars(absRosterFile, plan)
	// Extra-vars go through a JSON @file, never a bare `-e k=v` command
	// line — a value containing whitespace silently truncates under
	// `-e k=v` (see internal/freeipa/probe.go's identical precaution).
	extraVarsFile, err := os.CreateTemp("", "pilot-access-reconcile-vars-*.json")
	if err != nil {
		return nil, fmt.Errorf("accessgrants: create extra-vars file: %w", err)
	}
	extraVarsPath := extraVarsFile.Name()
	defer os.Remove(extraVarsPath)
	if err := json.NewEncoder(extraVarsFile).Encode(ev); err != nil {
		_ = extraVarsFile.Close()
		return nil, fmt.Errorf("accessgrants: encode extra-vars: %w", err)
	}
	if err := extraVarsFile.Close(); err != nil {
		return nil, fmt.Errorf("accessgrants: write extra-vars: %w", err)
	}

	args := []string{playbook, "-i", inventoryPath, "-e", "@" + extraVarsPath}
	if vaultPasswordFile != "" {
		args = append(args, "--vault-password-file", vaultPasswordFile)
	}
	result, runErr := runner.Run(ctx, args...)
	if runErr != nil {
		return result, fmt.Errorf("accessgrants: ansible-playbook did not run: %w", runErr)
	}
	if result.ExitCode != 0 {
		return result, fmt.Errorf("accessgrants: apply playbook %s exited %d", playbook, result.ExitCode)
	}
	return result, nil
}
