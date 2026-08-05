// mcp_diagnose_tools.go implements pilot_diagnose_sudo/pilot_diagnose_dns:
// live-host diagnostics, separate from the pilot_edit_* family (which is
// local-workspace-file read/write only and explicitly excludes any
// Ansible invocation — see docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md's
// "MVP 不包含"). These tools run a fixed, code-defined allow-list of
// read-only ansible ad-hoc commands (internal/diagnose) against exactly
// one real inventory host — never a client-suppliable module/args pair,
// never an ansible pattern/group — and are registered only when the
// server was started with --enable-diagnose.
//
// pilot_diagnose_run (below) is a deliberately separate, higher-risk tool:
// it runs a caller-supplied command via ansible's `command` module (never
// `shell`) against one real inventory host — NOT a fixed allow-list, so it
// is gated by its own --enable-diagnose-raw flag rather than
// --enable-diagnose, and its tool description says so plainly.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// diagnoseMCPToolsOptions is the canonicalized, server-lifetime config the
// diagnose tool handlers close over. AdHocRunner is nil in production —
// each call builds a real adapter — and injected only by tests.
type diagnoseMCPToolsOptions struct {
	Inventory      string
	AuditDir       string
	StepTimeout    time.Duration
	AnsibleRuntime deployAnsibleRuntime
	AdHocRunner    diagnose.AdHocRunner
}

func registerDiagnoseTools(server *mcp.Server, opts diagnoseMCPToolsOptions) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_sudo",
		Description: "run fixed, read-only ansible ad-hoc commands against one real inventory host to diagnose why a specific user can/cannot sudo there: sssd status, kerberos machine identity, account resolution, sssd access_provider, nsswitch sudoers routing, and whether a central FreeIPA sudo rule grants access (`sudo -l -U <user>`). Cross-reference the username against pilot://roster/effective-access's effective_sudo_access for the config-level (not live) view.",
	}, diagnoseSudoHandler(opts))
	mcp.AddTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_dns",
		Description: "run fixed, read-only ansible ad-hoc commands against one real inventory host to diagnose DNS resolution problems there: /etc/resolv.conf's nameserver, whether systemd-resolved is active, whether a local (non-stub) DNS daemon is listening on :53 and installed, and — when a name is supplied — whether it resolves both via NSS (getent hosts) and a direct query against the loopback resolver (dig @127.0.0.1), which separates an NSS/nsswitch misconfiguration from an unreachable/non-authoritative upstream.",
	}, diagnoseDNSHandler(opts))
}

// ---- shared plumbing --------------------------------------------------

// realDiagnoseAdHocRunner adapts deployAnsibleCommand (the same
// ANSIBLE_HOME-isolated exec.Cmd builder every other ansible invocation in
// this codebase uses) to diagnose.AdHocRunner's shape, capturing stdout
// even when the remote command's own nonzero rc makes the ansible process
// itself exit nonzero — that's expected and informative here (e.g.
// "systemctl is-active sssd" on a stopped service), not a run failure.
func realDiagnoseAdHocRunner() diagnose.AdHocRunner {
	return func(ctx context.Context, args []string, timeoutSeconds int) (string, int, error) {
		cctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
		command := deployAnsibleCommand(cctx, "ansible", args...)
		if command.Env == nil {
			command.Env = os.Environ()
		}
		command.Env = append(command.Env, "ANSIBLE_LOAD_CALLBACK_PLUGINS=1", "ANSIBLE_STDOUT_CALLBACK=ansible.posix.json")
		var stdout, stderr strings.Builder
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		exitCode := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			err = nil
		}
		if err != nil {
			return "", exitCode, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), exitCode, nil
	}
}

// diagnoseStepEvidence is one Step's evidence, surfaced alongside the
// synthesized verdict so a caller is never solely dependent on trusting
// the prose.
type diagnoseStepEvidence struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	OK          bool   `json:"ok"`
	RC          int    `json:"rc"`
	Stdout      string `json:"stdout,omitempty"`
	Error       string `json:"error,omitempty"`
}

func stepEvidenceList(results []diagnose.StepResult) []diagnoseStepEvidence {
	out := make([]diagnoseStepEvidence, len(results))
	for i, r := range results {
		ev := diagnoseStepEvidence{ID: r.Step.ID, Description: r.Step.Description}
		if r.Result.RunErr != nil {
			ev.Error = r.Result.RunErr.Error()
		} else {
			ev.RC = r.Result.RC
			ev.OK = r.Result.RC == 0 && !r.Result.Failed && !r.Result.Unreachable
			ev.Stdout = strings.TrimSpace(r.Result.Stdout)
		}
		out[i] = ev
	}
	return out
}

// diagnoseStepAudit is one Step's audit-trail record — the exact command
// run and its outcome, distinct from diagnoseStepEvidence (the MCP
// response shape) so the audit file's schema can evolve independently.
type diagnoseStepAudit struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	RC      int    `json:"rc,omitempty"`
	Error   string `json:"error,omitempty"`
}

func stepAuditList(results []diagnose.StepResult) []diagnoseStepAudit {
	out := make([]diagnoseStepAudit, len(results))
	for i, r := range results {
		a := diagnoseStepAudit{ID: r.Step.ID, Command: r.Step.Command}
		if r.Result.RunErr != nil {
			a.Error = r.Result.RunErr.Error()
		} else {
			a.RC = r.Result.RC
		}
		out[i] = a
	}
	return out
}

// diagnoseAuditRecord is the JSON record written under
// <AuditDir>/diagnose/ for every pilot_diagnose_* call — mandatory
// whenever --enable-diagnose is set (no off-switch, unlike --allow-write's
// --audit-dir which is about *where*, not *whether*): every call is a
// real, tool-triggered action against a live host, generating real
// auditd/PAM/journald events on the *target* itself.
type diagnoseAuditRecord struct {
	SessionID    string              `json:"session_id"`
	Check        string              `json:"check"`
	PilotVersion string              `json:"pilot_version"`
	GitRevision  string              `json:"git_revision,omitempty"`
	MCPClient    string              `json:"mcp_client,omitempty"`
	Inventory    string              `json:"inventory"`
	Host         string              `json:"host"`
	Params       map[string]string   `json:"params,omitempty"`
	Start        time.Time           `json:"start"`
	Finish       time.Time           `json:"finish"`
	Steps        []diagnoseStepAudit `json:"steps"`
}

// prepareDiagnoseAuditDir creates and returns
// <opts.AuditDir>/diagnose/<timestamp>-<sessionID>-<check> — the audit
// directory for one diagnose call.
func prepareDiagnoseAuditDir(opts diagnoseMCPToolsOptions, check, sessionID string, start time.Time) (string, error) {
	dir := filepath.Join(opts.AuditDir, "diagnose", fmt.Sprintf("%s-%s-%s", start.UTC().Format("20060102T150405Z"), sessionID, check))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func writeDiagnoseAudit(auditDir string, rec diagnoseAuditRecord) error {
	return writeJSONFile(filepath.Join(auditDir, "record.json"), rec)
}

func mcpClientString(req *mcp.CallToolRequest) string {
	if client := req.ClientInfo(); client != nil {
		return fmt.Sprintf("%s/%s", client.Name, client.Version)
	}
	return ""
}

// ---- pilot_diagnose_sudo ------------------------------------------------

type diagnoseSudoInput struct {
	Host string `json:"host" jsonschema:"exact inventory hostname — must be an exact ansible-inventory key, never a pattern/group/wildcard"`
	User string `json:"user" jsonschema:"OS/FreeIPA username to check sudo access for"`
}

type diagnoseSudoOutput struct {
	Host                        string                 `json:"host"`
	ResolvedAddr                string                 `json:"resolved_addr,omitempty"`
	User                        string                 `json:"user"`
	SssdActive                  bool                   `json:"sssd_active"`
	HasKerberosMachineIdentity  bool                   `json:"has_kerberos_machine_identity"`
	AccountResolvesViaSSSD      bool                   `json:"account_resolves_via_sssd"`
	AccessProviderIsIPA         bool                   `json:"access_provider_is_ipa"`
	SudoersRoutedThroughSSSD    bool                   `json:"sudoers_routed_through_sssd"`
	CentralSudoRuleGrantsAccess bool                   `json:"central_sudo_rule_grants_access"`
	Verdict                     string                 `json:"verdict"`
	Steps                       []diagnoseStepEvidence `json:"steps"`
	AuditDirectory              string                 `json:"audit_directory"`
}

func diagnoseSudoHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseSudoInput, diagnoseSudoOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseSudoInput) (*mcp.CallToolResult, diagnoseSudoOutput, error) {
		if !inventory.ValidRosterUserName(in.User) {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("user %q is not a valid username", in.User)}), diagnoseSudoOutput{}, nil
		}

		ctx = withDeployAnsibleRuntime(ctx, opts.AnsibleRuntime)
		resolved, err := resolveNetworkCheckInventory(ctx, opts.Inventory)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseSudoOutput{}, nil
		}
		if err := diagnose.ValidateHost(resolved, in.Host); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrHostNotFound, Message: err.Error()}), diagnoseSudoOutput{}, nil
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseSudoOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "sudo", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseSudoOutput{}, nil
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		steps := diagnose.SudoSteps(in.User)
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, in.Host, steps, opts.StepTimeout)
		sudoOut := diagnose.BuildSudoOutput(in.User, results)

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "sudo", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: in.Host, Params: map[string]string{"user": in.User},
			Start: start, Finish: time.Now(), Steps: stepAuditList(results),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseSudoOutput{
			Host: in.Host, ResolvedAddr: resolved.HostAddr(in.Host), User: in.User,
			SssdActive:                  sudoOut.SssdActive,
			HasKerberosMachineIdentity:  sudoOut.HasKerberosMachineIdentity,
			AccountResolvesViaSSSD:      sudoOut.AccountResolvesViaSSSD,
			AccessProviderIsIPA:         sudoOut.AccessProviderIsIPA,
			SudoersRoutedThroughSSSD:    sudoOut.SudoersRoutedThroughSSSD,
			CentralSudoRuleGrantsAccess: sudoOut.CentralSudoRuleGrantsAccess,
			Verdict:                     sudoOut.Verdict,
			Steps:                       stepEvidenceList(results),
			AuditDirectory:              auditDir,
		}
		return nil, out, nil
	}
}

// ---- pilot_diagnose_dns ------------------------------------------------

type diagnoseDNSInput struct {
	Host string `json:"host" jsonschema:"exact inventory hostname — must be an exact ansible-inventory key, never a pattern/group/wildcard"`
	Name string `json:"name,omitempty" jsonschema:"optional DNS name to test resolution for, via both NSS and a direct loopback query"`
}

type diagnoseDNSOutput struct {
	Host                   string                 `json:"host"`
	ResolvedAddr           string                 `json:"resolved_addr,omitempty"`
	Name                   string                 `json:"name,omitempty"`
	Nameserver             string                 `json:"nameserver,omitempty"`
	SystemdResolvedActive  bool                   `json:"systemd_resolved_active"`
	LocalDaemonListening   bool                   `json:"local_daemon_listening"`
	DNSDaemonInstalled     bool                   `json:"dns_daemon_installed"`
	NameQueried            bool                   `json:"name_queried"`
	ResolvesViaNSS         bool                   `json:"resolves_via_nss"`
	ResolvesViaDirectQuery bool                   `json:"resolves_via_direct_query"`
	Verdict                string                 `json:"verdict"`
	Steps                  []diagnoseStepEvidence `json:"steps"`
	AuditDirectory         string                 `json:"audit_directory"`
}

func diagnoseDNSHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseDNSInput, diagnoseDNSOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseDNSInput) (*mcp.CallToolResult, diagnoseDNSOutput, error) {
		if in.Name != "" && !inventory.ValidDNSRecordName(in.Name) {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("name %q is not a valid DNS record name", in.Name)}), diagnoseDNSOutput{}, nil
		}

		ctx = withDeployAnsibleRuntime(ctx, opts.AnsibleRuntime)
		resolved, err := resolveNetworkCheckInventory(ctx, opts.Inventory)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseDNSOutput{}, nil
		}
		if err := diagnose.ValidateHost(resolved, in.Host); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrHostNotFound, Message: err.Error()}), diagnoseDNSOutput{}, nil
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseDNSOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "dns", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseDNSOutput{}, nil
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		steps := diagnose.DNSSteps(in.Name)
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, in.Host, steps, opts.StepTimeout)
		dnsOut := diagnose.BuildDNSOutput(in.Name, results)

		params := map[string]string{}
		if in.Name != "" {
			params["name"] = in.Name
		}
		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "dns", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: in.Host, Params: params,
			Start: start, Finish: time.Now(), Steps: stepAuditList(results),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseDNSOutput{
			Host: in.Host, ResolvedAddr: resolved.HostAddr(in.Host), Name: in.Name,
			Nameserver:             dnsOut.Nameserver,
			SystemdResolvedActive:  dnsOut.SystemdResolvedActive,
			LocalDaemonListening:   dnsOut.LocalDaemonListening,
			DNSDaemonInstalled:     dnsOut.DNSDaemonInstalled,
			NameQueried:            dnsOut.NameQueried,
			ResolvesViaNSS:         dnsOut.ResolvesViaNSS,
			ResolvesViaDirectQuery: dnsOut.ResolvesViaDirectQuery,
			Verdict:                dnsOut.Verdict,
			Steps:                  stepEvidenceList(results),
			AuditDirectory:         auditDir,
		}
		return nil, out, nil
	}
}

// ---- pilot_diagnose_run --------------------------------------------------

// registerDiagnoseRunTool adds pilot_diagnose_run — kept separate from
// registerDiagnoseTools (and from its --enable-diagnose gate) since this
// tool is not a fixed allow-list: it runs whatever command string the
// caller supplies.
func registerDiagnoseRunTool(server *mcp.Server, opts diagnoseMCPToolsOptions) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_run",
		Description: "run a caller-supplied command against one real inventory host via ansible's `command` module (argv is exec'd directly — no shell, so pipes/redirects/chaining/expansion are not interpreted). UNLIKE pilot_diagnose_sudo/pilot_diagnose_dns this is NOT a fixed read-only allow-list: it runs anything the connecting ansible_user (and become, if the inventory configures it) is permitted to run, including commands that mutate the target. Only registered when the server was started with --enable-diagnose-raw. Every call is logged to the audit directory. Prefer pilot_diagnose_sudo/pilot_diagnose_dns when they already answer the question.",
	}, diagnoseRunHandler(opts))
}

type diagnoseRunInput struct {
	Host    string `json:"host" jsonschema:"exact inventory hostname — must be an exact ansible-inventory key, never a pattern/group/wildcard"`
	Command string `json:"command" jsonschema:"command and its arguments to run via ansible's command module — no shell interpretation, so pipes/redirects/chaining/expansion are not supported"`
}

type diagnoseRunOutput struct {
	Host           string `json:"host"`
	ResolvedAddr   string `json:"resolved_addr,omitempty"`
	Command        string `json:"command"`
	RC             int    `json:"rc"`
	Stdout         string `json:"stdout,omitempty"`
	Unreachable    bool   `json:"unreachable,omitempty"`
	Error          string `json:"error,omitempty"`
	AuditDirectory string `json:"audit_directory"`
}

func diagnoseRunHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseRunInput, diagnoseRunOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseRunInput) (*mcp.CallToolResult, diagnoseRunOutput, error) {
		if strings.TrimSpace(in.Command) == "" {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "command must not be empty"}), diagnoseRunOutput{}, nil
		}

		ctx = withDeployAnsibleRuntime(ctx, opts.AnsibleRuntime)
		resolved, err := resolveNetworkCheckInventory(ctx, opts.Inventory)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseRunOutput{}, nil
		}
		if err := diagnose.ValidateHost(resolved, in.Host); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrHostNotFound, Message: err.Error()}), diagnoseRunOutput{}, nil
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseRunOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "run", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseRunOutput{}, nil
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		step := diagnose.Step{ID: "run", Description: "caller-supplied command", Module: "command", Command: in.Command}
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, in.Host, []diagnose.Step{step}, opts.StepTimeout)

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "run", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: in.Host, Params: map[string]string{"command": in.Command},
			Start: start, Finish: time.Now(), Steps: stepAuditList(results),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseRunOutput{
			Host: in.Host, ResolvedAddr: resolved.HostAddr(in.Host), Command: in.Command,
			AuditDirectory: auditDir,
		}
		result := results[0].Result
		if result.RunErr != nil {
			out.Error = result.RunErr.Error()
		} else {
			out.RC = result.RC
			out.Stdout = strings.TrimSpace(result.Stdout)
			out.Unreachable = result.Unreachable
		}
		return nil, out, nil
	}
}
