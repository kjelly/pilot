// drift.go implements spec.md v3.1 §12's one-shot drift inspection. It
// probes live FreeIPA state via playbooks/check/freeipa-access-drift-probe.yml
// (read-only, never mutates) and diffs it against the same desired state
// internal/inventory's compilers already produce for apply (§18).
//
// Scope (see that playbook's header comment): this covers existence/
// orphan drift for compiled HBAC/sudo grants (§12.2/§12.3's orphan
// bullet), and native-attribute value drift for account expiration
// (§12.5) and authentication indicators (§12.4) — the two axes v3.1
// phases 1/3 built desired-state compilers for. Full subject/target/
// service attribute drift for HBAC/sudo rules (§12.1, and §12.2/§12.3's
// "subject/target mutation" bullets) is NOT covered here — it would need
// a full FreeIPA CLI `--raw` attribute parse whose exact field format
// this delivery had no live FreeIPA target to confirm; see that
// playbook's header comment for the reasoning. That remains open
// follow-up work, not a silently-dropped requirement.
package accessgrants

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/inventory"
)

// DriftProbePlaybook is the read-only check playbook DriftProbe invokes.
const DriftProbePlaybook = "playbooks/check/freeipa-access-drift-probe.yml"

// pilotGrantHBACPrefix/pilotGrantSudoPrefix identify Pilot's own compiled-
// rule namespace (internal/inventory's CompiledLoginRuleName/
// CompiledSudoRuleName) — the only live rules an orphan check may ever
// flag, per §13.1's ownership boundary. A hand-authored static rule never
// starts with these prefixes and is never touched here.
const (
	pilotGrantHBACPrefix = "pilot-grant-login-"
	pilotGrantSudoPrefix = "pilot-grant-sudo-"
)

// LiveState is freeipa-access-drift-probe.yml's parsed result — real
// FreeIPA state at probe time, for internal/inventory's desired state to
// be diffed against.
type LiveState struct {
	SchemaVersion  int                 `json:"schema_version"`
	LiveHBACNames  []string            `json:"live_hbac_names"`
	LiveSudoNames  []string            `json:"live_sudo_names"`
	HBACExists     map[string]bool     `json:"hbac_exists"`
	SudoExists     map[string]bool     `json:"sudo_exists"`
	UserExpiration map[string]string   `json:"user_expiration"`
	HostAuthInd    map[string][]string `json:"host_auth_ind"`
}

// DriftProbeOptions configures a single live-state probe.
type DriftProbeOptions struct {
	// RosterFile and Inventory are required. RosterFile MUST have already
	// passed inventory.ValidateRosterFile.
	RosterFile string
	Inventory  string

	// Playbook overrides DriftProbePlaybook.
	Playbook string
	// VaultPasswordFile is required when RosterFile is ansible-vault
	// encrypted.
	VaultPasswordFile string
	// TargetGroup overrides the probe playbook's default host-targeting
	// group ("freeipa-server").
	TargetGroup string

	// HBACNames/SudoNames/Users/Hosts are the desired-state identifiers to
	// probe existence/value for — the caller (DriftOnce) derives these
	// from internal/inventory's compilers before calling DriftProbe.
	HBACNames []string
	SudoNames []string
	Users     []string
	Hosts     []string

	// Now is the injected clock DriftOnce evaluates grant lifecycle
	// against when building the desired plan. Zero selects time.Now().
	Now time.Time

	// StateDir enables audit-event recording (§15). Empty skips it
	// entirely, same convention as ReconcileOptions.StateDir.
	StateDir string

	// Runner overrides the ansible.Runner used to run the probe. nil
	// selects a production ansible.NewRunner().
	Runner playbookRunner
}

// DriftProbe runs DriftProbePlaybook and returns the parsed live state. It
// never mutates FreeIPA.
func DriftProbe(ctx context.Context, opts DriftProbeOptions) (LiveState, error) {
	if opts.RosterFile == "" {
		return LiveState{}, fmt.Errorf("accessgrants: roster file is required")
	}
	if opts.Inventory == "" {
		return LiveState{}, fmt.Errorf("accessgrants: inventory is required")
	}
	playbook := opts.Playbook
	if playbook == "" {
		playbook = DriftProbePlaybook
	}

	absRosterFile, err := filepath.Abs(opts.RosterFile)
	if err != nil {
		return LiveState{}, fmt.Errorf("accessgrants: resolve roster file path: %w", err)
	}

	outputFile, err := os.CreateTemp("", "pilot-access-drift-output-*.json")
	if err != nil {
		return LiveState{}, fmt.Errorf("accessgrants: create drift-probe output file: %w", err)
	}
	outputPath := outputFile.Name()
	_ = outputFile.Close()
	defer os.Remove(outputPath)

	extraVars := map[string]any{
		"freeipa_roster_file":    absRosterFile,
		"pilot_drift_output":     outputPath,
		"pilot_drift_hbac_names": emptyOr(opts.HBACNames),
		"pilot_drift_sudo_names": emptyOr(opts.SudoNames),
		"pilot_drift_users":      emptyOr(opts.Users),
		"pilot_drift_hosts":      emptyOr(opts.Hosts),
	}
	if opts.TargetGroup != "" {
		extraVars["target_group"] = opts.TargetGroup
	}
	extraVarsFile, err := os.CreateTemp("", "pilot-access-drift-vars-*.json")
	if err != nil {
		return LiveState{}, fmt.Errorf("accessgrants: create drift-probe extra-vars file: %w", err)
	}
	extraVarsPath := extraVarsFile.Name()
	defer os.Remove(extraVarsPath)
	if err := json.NewEncoder(extraVarsFile).Encode(extraVars); err != nil {
		_ = extraVarsFile.Close()
		return LiveState{}, fmt.Errorf("accessgrants: encode drift-probe extra-vars: %w", err)
	}
	if err := extraVarsFile.Close(); err != nil {
		return LiveState{}, fmt.Errorf("accessgrants: write drift-probe extra-vars: %w", err)
	}

	args := []string{playbook, "-i", opts.Inventory, "-e", "@" + extraVarsPath}
	if opts.VaultPasswordFile != "" {
		args = append(args, "--vault-password-file", opts.VaultPasswordFile)
	}

	runner := opts.Runner
	if runner == nil {
		runner = ansible.NewRunner()
	}
	result, err := runner.Run(ctx, args...)
	if err != nil {
		return LiveState{}, fmt.Errorf("accessgrants: drift-probe playbook did not run: %w", err)
	}
	if result.ExitCode != 0 {
		detail := strings.TrimSpace(result.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(result.Stdout)
		}
		return LiveState{}, fmt.Errorf("accessgrants: drift-probe playbook exited %d: %s", result.ExitCode, detail)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		return LiveState{}, fmt.Errorf("accessgrants: read drift-probe result: %w", err)
	}
	var live LiveState
	if err := json.Unmarshal(data, &live); err != nil {
		return LiveState{}, fmt.Errorf("accessgrants: malformed drift-probe result JSON: %w", err)
	}
	if live.SchemaVersion != 1 {
		return LiveState{}, fmt.Errorf("accessgrants: unsupported drift-probe schema_version %d", live.SchemaVersion)
	}
	return live, nil
}

// DriftItem is one detected mismatch between desired and live state.
type DriftItem struct {
	// Category is one of: hbac_orphan, sudo_orphan, hbac_missing,
	// sudo_missing, account_expiration, auth_indicator.
	Category string
	// Name is the compiled rule name, username, or hostname the drift
	// concerns.
	Name string
	// Detail is a human-readable description of the mismatch.
	Detail string
}

// DriftReport is every DriftItem a single drift pass found.
type DriftReport struct {
	Items []DriftItem
}

// Empty reports whether no drift was found.
func (r DriftReport) Empty() bool { return len(r.Items) == 0 }

// CountByCategory returns how many DriftItems fall in each category —
// spec.md §16.1's per-category drift counts for `pilot access health`.
func (r DriftReport) CountByCategory() map[string]int {
	out := map[string]int{}
	for _, item := range r.Items {
		out[item.Category]++
	}
	return out
}

// ComputeDrift diffs desired compiled state against live, per this file's
// documented scope. desiredHBAC/desiredSudo are Present==true entries a
// caller wants to exist; live is DriftProbe's result for the SAME set of
// names/users/hosts the caller asked DriftProbeOptions to probe — a name
// this function was never asked to probe is invisible to it except via
// the orphan check, which uses live.LiveHBACNames/LiveSudoNames
// independently of what was probed.
func ComputeDrift(desiredHBAC []inventory.CompiledHBACRule, desiredSudo []inventory.CompiledSudoRule, desiredAuth []inventory.CompiledAuthPolicyHost, desiredAccounts []inventory.CompiledAccountExpiration, live LiveState) DriftReport {
	var items []DriftItem

	desiredHBACNames := map[string]bool{}
	for _, r := range desiredHBAC {
		if r.Present {
			desiredHBACNames[r.Name] = true
			if !live.HBACExists[r.Name] {
				items = append(items, DriftItem{Category: "hbac_missing", Name: r.Name, Detail: "desired compiled HBAC rule does not exist live"})
			}
		}
	}
	for _, name := range live.LiveHBACNames {
		if strings.HasPrefix(name, pilotGrantHBACPrefix) && !desiredHBACNames[name] {
			items = append(items, DriftItem{Category: "hbac_orphan", Name: name, Detail: "Pilot-managed HBAC rule exists live but no current grant compiles to it"})
		}
	}

	desiredSudoNames := map[string]bool{}
	for _, r := range desiredSudo {
		if r.Present {
			desiredSudoNames[r.Name] = true
			if !live.SudoExists[r.Name] {
				items = append(items, DriftItem{Category: "sudo_missing", Name: r.Name, Detail: "desired compiled sudo rule does not exist live"})
			}
		}
	}
	for _, name := range live.LiveSudoNames {
		if strings.HasPrefix(name, pilotGrantSudoPrefix) && !desiredSudoNames[name] {
			items = append(items, DriftItem{Category: "sudo_orphan", Name: name, Detail: "Pilot-managed sudo rule exists live but no current grant compiles to it"})
		}
	}

	for _, a := range desiredAccounts {
		want := ""
		if a.Present {
			want = a.Expiration
		}
		got := live.UserExpiration[a.User]
		if want != got {
			items = append(items, DriftItem{Category: "account_expiration", Name: a.User, Detail: fmt.Sprintf("desired krbPrincipalExpiration %q, live %q", orEmptyLabel(want), orEmptyLabel(got))})
		}
	}

	for _, h := range desiredAuth {
		want := append([]string{}, h.Indicators...)
		sort.Strings(want)
		got := append([]string{}, live.HostAuthInd[h.Host]...)
		sort.Strings(got)
		if !stringSlicesEqual(want, got) {
			items = append(items, DriftItem{Category: "auth_indicator", Name: h.Host, Detail: fmt.Sprintf("desired krbPrincipalAuthInd %v, live %v", want, got)})
		}
	}

	return DriftReport{Items: items}
}

func orEmptyLabel(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DriftOnce is the top-level entry point `pilot access drift` uses: build
// the desired plan (same compilers §18's apply path uses), probe live
// state for exactly those names/users/hosts, and diff.
func DriftOnce(ctx context.Context, opts DriftProbeOptions) (DriftReport, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	plan, err := BuildPlan(opts.RosterFile, now)
	if err != nil {
		return DriftReport{}, err
	}

	probeOpts := opts
	for _, r := range plan.HBACRules {
		if r.Present {
			probeOpts.HBACNames = append(probeOpts.HBACNames, r.Name)
		}
	}
	for _, r := range plan.SudoRules {
		if r.Present {
			probeOpts.SudoNames = append(probeOpts.SudoNames, r.Name)
		}
	}
	for _, a := range plan.AccountExpirations {
		probeOpts.Users = append(probeOpts.Users, a.User)
	}
	for _, h := range plan.AuthPolicyHosts {
		probeOpts.Hosts = append(probeOpts.Hosts, h.Host)
	}

	live, err := DriftProbe(ctx, probeOpts)
	if err != nil {
		return DriftReport{}, err
	}
	report := ComputeDrift(plan.HBACRules, plan.SudoRules, plan.AuthPolicyHosts, plan.AccountExpirations, live)

	if opts.StateDir != "" {
		if auditErr := AppendAuditEvent(opts.StateDir, AccessAuditEvent{
			Action:     AuditActionAccessDriftDetected,
			SourceKind: "static_hbac,temporary_grant,sudo_grant,auth_policy,account_policy",
			Resource:   opts.RosterFile,
			Outcome:    "success",
			Reason:     fmt.Sprintf("%d drift item(s) found", len(report.Items)),
		}); auditErr != nil {
			return report, fmt.Errorf("accessgrants: drift computed but recording the audit event failed: %w", auditErr)
		}
	}
	return report, nil
}

// RepairManaged detects drift via DriftOnce, and — only when drift was
// found — invokes ReconcileOnce to reconcile it away. §13: "repair" is
// just `pilot access reconcile`'s own convergent apply; ReconcileOnce
// already only ever touches Pilot-owned managed constructs (compiled
// grants via their pilot-grant-* namespace, and per-user/per-host roster-
// declared auth_policies/account_policies — §13.1's ownership boundary),
// so no separate narrower apply path is needed. It returns the drift
// found BEFORE repair (empty Plan/nil Result when there was none to
// repair) alongside ReconcileOnce's own result.
func RepairManaged(ctx context.Context, driftOpts DriftProbeOptions, reconcileOpts ReconcileOptions) (DriftReport, Plan, *ansible.Result, error) {
	before, err := DriftOnce(ctx, driftOpts)
	if err != nil {
		return DriftReport{}, Plan{}, nil, err
	}
	if before.Empty() {
		return before, Plan{}, nil, nil
	}

	plan, result, reconcileErr := ReconcileOnce(ctx, reconcileOpts)

	if driftOpts.StateDir != "" {
		outcome := "success"
		if reconcileErr != nil {
			outcome = "failure"
		}
		auditErr := AppendAuditEvent(driftOpts.StateDir, AccessAuditEvent{
			Action:     AuditActionAccessDriftRepaired,
			SourceKind: "static_hbac,temporary_grant,sudo_grant,auth_policy,account_policy",
			Resource:   driftOpts.RosterFile,
			Outcome:    outcome,
			Reason:     fmt.Sprintf("%d drift item(s) detected before repair", len(before.Items)),
		})
		if auditErr != nil && reconcileErr == nil {
			return before, plan, result, fmt.Errorf("accessgrants: repair applied but recording the audit event failed: %w", auditErr)
		}
	}
	return before, plan, result, reconcileErr
}
