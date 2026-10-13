// login_probe_targets.go implements the login-probe target cleanup for
// host decommission (docs/superpowers/specs/2026-09-02-host-decommission-spec.md
// §19, GitHub issue kjelly/pilot#11 follow-up).
//
// pilot-login-probe renders its target list at apply time from the
// inventory (playbooks/apply/login-probe-apply.yml), so a retiring host stays
// a probe target — and keeps raising PilotLoginProbe* alerts — until the
// login-probe hosts are re-rendered without it. That rendered list is an
// "active alert target mapping that attempts to contact the host" (§19):
// it must be reconciled before finalization, WITHOUT first removing the
// host from hosts.yml. This provider does that with the pattern §19 lists
// as acceptable — a validated after-state projection used only by this
// step: login-probe-apply.yml runs on the login-probe hosts with
// -e login_probe_exclude_targets=[<retiring host names>].
//
// Like the internal-endpoint provider this is reference-driven, not
// role-driven: the retiring host is a TARGET of other hosts' probes, it
// need not carry any particular role itself, and the step runs only on
// the login-probe hosts — so it does not need the retiring host to be
// reachable. Decommissioning a login-probe host itself is not handled
// here (that component has no local decommission support yet and stays
// fail-closed in planComponent).
package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/ansible"
)

// LoginProbeTargetsProviderID is this provider's stable ID. It is
// deliberately NOT the login-probe component ID: registering under that ID
// would make planComponent treat a retiring login-probe HOST as supported
// although its own daemon would be left running.
const LoginProbeTargetsProviderID = "login-probe-targets"

// ActionLoginProbeTargetRemove re-renders every login-probe host's target
// list without the retiring host.
const ActionLoginProbeTargetRemove = "login_probe_target_remove"

// LoginProbeTargetsProviderConfig configures a LoginProbeTargetsProvider.
// Every value is resolved by the caller from the workspace (never from an
// Agent/MCP-supplied path, INV-5).
type LoginProbeTargetsProviderConfig struct {
	Executor ansibleExecutor

	Inventory     string
	QueryPlaybook string // playbooks/decommission/login-probe-target-query.yml
	ApplyPlaybook string // playbooks/apply/login-probe-apply.yml

	// ProbeHosts are the inventory hosts carrying the login-probe role.
	ProbeHosts []string

	// ExtraArgs is appended verbatim to every ansible-playbook invocation —
	// non-secret plumbing only.
	ExtraArgs []string

	// ApplyStageArgs returns the stage -e arguments for the login-probe
	// hosts (decommission.StageScope). The read-only query gets none.
	ApplyStageArgs func() ([]string, error)
}

// LoginProbeTargetsProvider implements Provider and StepRunner.
type LoginProbeTargetsProvider struct {
	cfg LoginProbeTargetsProviderConfig
}

// NewLoginProbeTargetsProvider builds a LoginProbeTargetsProvider from cfg.
func NewLoginProbeTargetsProvider(cfg LoginProbeTargetsProviderConfig) *LoginProbeTargetsProvider {
	return &LoginProbeTargetsProvider{cfg: cfg}
}

// ID implements Provider.
func (p *LoginProbeTargetsProvider) ID() string { return LoginProbeTargetsProviderID }

// probeHostsFor returns the login-probe hosts other than the retiring host
// itself, sorted and de-duplicated.
func (p *LoginProbeTargetsProvider) probeHostsFor(hostName, fqdn string) []string {
	skip := map[string]bool{strings.ToLower(hostName): true}
	if fqdn != "" {
		skip[strings.ToLower(fqdn)] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, h := range p.cfg.ProbeHosts {
		if h == "" || skip[strings.ToLower(h)] || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// targetNames are the names a probe config may list the retiring host by:
// its inventory name and its FQDN, lower-cased (spec.md §5.13 / AGENTS.md
// §5.13: compare host identities case-insensitively).
func targetNames(hostName, fqdn string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range []string{hostName, fqdn} {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// Inspect reports whether any login-probe host still lists the host as a
// target. Read-only.
func (p *LoginProbeTargetsProvider) Inspect(ctx context.Context, in InspectInput) (Inspection, error) {
	probes := p.probeHostsFor(in.HostName, in.FQDN)
	if len(probes) == 0 {
		return Inspection{Provider: LoginProbeTargetsProviderID, Detail: "no login-probe hosts in the inventory"}, nil
	}
	present, err := p.query(ctx, probes, targetNames(in.HostName, in.FQDN))
	if err != nil {
		return Inspection{}, err
	}
	still := presentOn(present)
	if len(still) == 0 {
		return Inspection{Provider: LoginProbeTargetsProviderID, Detail: "no login-probe host lists " + in.HostName + " as a target"}, nil
	}
	return Inspection{Provider: LoginProbeTargetsProviderID, Found: true, Detail: in.HostName + " is still a probe target on: " + strings.Join(still, ", ")}, nil
}

// Plan returns one central step when at least one other host carries the
// login-probe role; nothing otherwise. It performs no live query — the
// step's own Inspect decides at execution time whether a re-render is
// still needed (resume-safe, INV-9).
func (p *LoginProbeTargetsProvider) Plan(ctx context.Context, in PlanInput) ([]Step, error) {
	if len(p.probeHostsFor(in.HostName, in.FQDN)) == 0 {
		return nil, nil
	}
	params := map[string]string{}
	if in.FQDN != "" {
		params["fqdn"] = in.FQDN
	}
	return []Step{{
		Provider:       LoginProbeTargetsProviderID,
		Phase:          "central_cleanup",
		Action:         ActionLoginProbeTargetRemove,
		TargetIdentity: in.HostName,
		Params:         params,
	}}, nil
}

// ExecutorForStep implements StepRunner.
func (p *LoginProbeTargetsProvider) ExecutorForStep(step Step) (StepExecutor, error) {
	if step.Action != ActionLoginProbeTargetRemove {
		return nil, fmt.Errorf("login-probe-targets: unknown planned step action %q — programming/version-skew error, not a normal runtime condition", step.Action)
	}
	return &loginProbeTargetRemoveStep{provider: p, hostName: step.TargetIdentity, fqdn: step.Params["fqdn"]}, nil
}

type loginProbeTargetRemoveStep struct {
	provider *LoginProbeTargetsProvider
	hostName string
	fqdn     string
}

// Inspect re-queries live state: converged when no login-probe host lists
// the retiring host any more.
func (e *loginProbeTargetRemoveStep) Inspect(ctx context.Context) (bool, error) {
	insp, err := e.provider.Inspect(ctx, InspectInput{HostName: e.hostName, FQDN: e.fqdn})
	if err != nil {
		return false, err
	}
	return !insp.Found, nil
}

// Execute re-renders the login-probe hosts with the retiring host excluded.
// It always targets every login-probe host (not only those that listed the
// host) so a probe host's config can never be left half-reconciled.
func (e *loginProbeTargetRemoveStep) Execute(ctx context.Context) error {
	p := e.provider
	probes := p.probeHostsFor(e.hostName, e.fqdn)
	if len(probes) == 0 {
		return nil
	}
	exclude, err := json.Marshal(map[string][]string{"login_probe_exclude_targets": targetNames(e.hostName, e.fqdn)})
	if err != nil {
		return fmt.Errorf("login-probe-targets exclude %s: %w", e.hostName, err)
	}
	args := []string{p.cfg.ApplyPlaybook}
	if p.cfg.Inventory != "" {
		args = append(args, "-i", p.cfg.Inventory)
	}
	args = append(args, "--limit", strings.Join(probes, ","))
	args = append(args, "-e", string(exclude))
	args = append(args, p.cfg.ExtraArgs...)
	args, stageErr := withStage(args, p.cfg.ApplyStageArgs)
	if stageErr != nil {
		return fmt.Errorf("login-probe-targets exclude %s: %w", e.hostName, stageErr)
	}
	res, err := p.exec(ctx, args)
	if err != nil {
		return fmt.Errorf("login-probe-targets exclude %s: %w", e.hostName, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("login-probe-targets exclude %s: ansible-playbook exited %d: %s", e.hostName, res.ExitCode, ansibleFailureDetail(res))
	}
	return nil
}

// Verify independently re-queries every login-probe host (INV-10).
func (p *LoginProbeTargetsProvider) Verify(ctx context.Context, in VerifyInput) ([]Verification, error) {
	probes := p.probeHostsFor(in.HostName, in.FQDN)
	if len(probes) == 0 {
		return []Verification{{
			Provider: LoginProbeTargetsProviderID, Kind: "login_probe_target", Identity: in.HostName,
			Status: "not_applicable", Detail: "no login-probe hosts in the inventory",
		}}, nil
	}
	present, err := p.query(ctx, probes, targetNames(in.HostName, in.FQDN))
	if err != nil {
		return nil, fmt.Errorf("login-probe-targets verify %s: %w", in.HostName, err)
	}
	out := make([]Verification, 0, len(probes))
	for _, probe := range probes {
		listed := present[probe]
		out = append(out, Verification{
			Provider: LoginProbeTargetsProviderID, Kind: "login_probe_target", Identity: in.HostName + "@" + probe,
			Status: statusForAbsence(!listed), Active: listed,
			Detail: "/etc/pilot/login-probe/config.yml targets on " + probe,
		})
	}
	return out, nil
}

// loginProbeTargetPresentPattern is the query playbook's output contract:
// one "LOGIN_PROBE_TARGET_PRESENT[<probe host>]=true|false" per probe host,
// printed through ansible.builtin.debug. Not anchored to line boundaries
// (debug output may carry literal "\n", see freeipa_client.go's
// fieldPattern note).
var loginProbeTargetPresentPattern = regexp.MustCompile(`LOGIN_PROBE_TARGET_PRESENT\[([^\]\s"]+)\]=(true|false)`)

// query runs the read-only query playbook and returns, per probe host,
// whether it still lists one of names. A probe host that did not report
// is an error, never "absent" (AGENTS.md §5.12): an unreachable probe host
// must not let the decommission conclude there is nothing to clean up.
func (p *LoginProbeTargetsProvider) query(ctx context.Context, probes, names []string) (map[string]bool, error) {
	nameArg, err := json.Marshal(map[string][]string{"pilot_decommission_target_names": names})
	if err != nil {
		return nil, err
	}
	args := []string{p.cfg.QueryPlaybook}
	if p.cfg.Inventory != "" {
		args = append(args, "-i", p.cfg.Inventory)
	}
	args = append(args, "--limit", strings.Join(probes, ","), "--tags", "target_query", "-e", string(nameArg))
	args = append(args, p.cfg.ExtraArgs...)
	res, err := p.exec(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("login-probe target query: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("login-probe target query: ansible-playbook exited %d: %s", res.ExitCode, ansibleFailureDetail(res))
	}
	present := map[string]bool{}
	reported := map[string]bool{}
	for _, m := range loginProbeTargetPresentPattern.FindAllStringSubmatch(res.Stdout, -1) {
		reported[m[1]] = true
		if m[2] == "true" {
			present[m[1]] = true
		}
	}
	var missing []string
	for _, probe := range probes {
		if !reported[probe] {
			missing = append(missing, probe)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("login-probe target query: no result from login-probe host(s) %s — refusing to treat them as clean", strings.Join(missing, ", "))
	}
	return present, nil
}

func presentOn(present map[string]bool) []string {
	var out []string
	for h, ok := range present {
		if ok {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func (p *LoginProbeTargetsProvider) exec(ctx context.Context, args []string) (*ansible.Result, error) {
	if p.cfg.Executor == nil {
		return nil, fmt.Errorf("login-probe-targets provider: no ansible executor configured")
	}
	return p.cfg.Executor.Run(ctx, args...)
}
