// mcp_diagnose_tools.go implements pilot_diagnose_sudo/pilot_diagnose_dns/
// pilot_diagnose_logs/pilot_diagnose_metrics/pilot_diagnose_security_logs/
// pilot_diagnose_login/pilot_diagnose_detection: live-host diagnostics,
// separate from the pilot_edit_* family (which is local-workspace-file
// read/write only and explicitly excludes any Ansible invocation — see
// docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md's
// "MVP 不包含"). These tools run a fixed, code-defined allow-list of
// read-only ansible ad-hoc commands (internal/diagnose) against exactly
// one real inventory host — never a client-suppliable module/args pair,
// never an ansible pattern/group — and are registered only when the
// server was started with --enable-diagnose. pilot_diagnose_logs/_metrics
// query Loki/Thanos Query the same way sudo/dns query the OS: curl runs
// on the target's own loopback via ansible ad-hoc (SSH), not a direct
// HTTP client in the MCP server — docs/network-firewall-matrix.md only
// grants the deployment controller SSH into this topology, not direct
// HTTP to Loki/Thanos Query's ports. Both auto-resolve their singleton
// central host (dashboard/thanos-query) instead of taking a host
// parameter, since there's exactly one by contract.
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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/networkcheck"
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

// resolveDiagnoseInventory best-effort refreshes opts.Inventory from a
// sibling hosts.yml (autoRegenerateInventoryFromHosts, inventory.go)
// before resolving it — called fresh on every pilot_diagnose_*
// invocation, not cached from mcp serve startup, so a hosts.yml edited
// while this long-running server is up is picked up on the very next
// diagnose call rather than requiring a restart. A sibling hosts.yml that
// cannot be regenerated is surfaced as a tool error: silently falling back
// to an older inventory can direct a live-host diagnostic to the wrong
// machine.
//
// The explicit os.Stat below exists because `ansible-inventory --list -i
// <missing-file>` does not error — it warns on stderr and falls back to
// an empty "only implicit localhost is available" inventory (exit 0).
// Without this check, a missing/mistyped --diagnose-inventory path (or
// its <dir>/inventory.yml default, when hosts.yml has no dashboard/
// thanos-query role yet either) silently resolves to zero hosts, and the
// caller only ever sees a misleading "role not deployed"/"host not
// found" error indistinguishable from the inventory genuinely lacking
// that host.
func resolveDiagnoseInventory(ctx context.Context, opts diagnoseMCPToolsOptions) (networkcheck.ResolvedInventory, error) {
	if _, err := autoRegenerateInventoryFromHosts(io.Discard, opts.Inventory); err != nil {
		return networkcheck.ResolvedInventory{}, fmt.Errorf("refresh inventory from sibling hosts.yml: %w", err)
	}
	if _, statErr := os.Stat(opts.Inventory); statErr != nil {
		if os.IsNotExist(statErr) {
			return networkcheck.ResolvedInventory{}, fmt.Errorf("inventory file not found: %s", opts.Inventory)
		}
		return networkcheck.ResolvedInventory{}, fmt.Errorf("stat inventory file %s: %w", opts.Inventory, statErr)
	}
	resolveCtx, cancel := context.WithTimeout(ctx, opts.StepTimeout)
	defer cancel()
	return resolveNetworkCheckInventory(resolveCtx, opts.Inventory)
}

func registerDiagnoseTools(server *mcp.Server, opts diagnoseMCPToolsOptions) {
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_sudo",
		Description: "run fixed, read-only ansible ad-hoc commands against one real inventory host to diagnose why a specific user can/cannot sudo there: sssd status, kerberos machine identity, account resolution, sssd access_provider, nsswitch sudoers routing, and whether a central FreeIPA sudo rule grants access (`sudo -l -U <user>`). Cross-reference the username against pilot://roster/effective-access's effective_sudo_access for the config-level (not live) view.",
	}, diagnoseSudoHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_dns",
		Description: "run fixed, read-only ansible ad-hoc commands against one real inventory host to diagnose DNS resolution problems there: /etc/resolv.conf's nameserver, whether systemd-resolved is active, whether a local (non-stub) DNS daemon is listening on :53 and installed, and — when a name is supplied — whether it resolves both via NSS (getent hosts) and a direct query against the loopback resolver (dig @127.0.0.1), which separates an NSS/nsswitch misconfiguration from an unreachable/non-authoritative upstream.",
	}, diagnoseDNSHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_logs",
		Description: "run a LogQL query against Loki (the dashboard host's log store) via an ansible ad-hoc curl against its own loopback — no host parameter, since dashboard is this deployment's singleton central role. start/end accept RFC3339 or Unix seconds/milliseconds/microseconds/nanoseconds; when either is supplied pilot makes both UTC boundaries explicit and rejects start >= end before querying Loki. Omit both for Loki's default last hour. Returns the raw Loki JSON response body plus its HTTP status.",
	}, diagnoseLogsHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_metrics",
		Description: "run a PromQL query against Thanos Query (the cross-site metrics aggregator) via an ansible ad-hoc curl against its own loopback — no host parameter, since thanos-query is this deployment's singleton central role. Supplying both start and end runs a range query (/api/v1/query_range, with optional step); otherwise an instant query (/api/v1/query, with optional time). No range cap — the caller decides. Returns the raw Prometheus-compatible JSON response body plus its HTTP status.",
	}, diagnoseMetricsHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_security_logs",
		Description: "convenience wrapper over pilot_diagnose_logs for security/audit events specifically: automatically scopes the Loki query to job=\"pilot-siem\", which — by this deployment's own design — already covers nothing but security/audit-relevant log lines, from EITHER log-server's forwarded auth/authpriv/local6(auditd) logs OR a co-located wazuh-manager's alerts (whichever this deployment ships; both land under the same job label, no source parameter needed). host and search are both optional plain-substring filters against the log line content (not a regex, and not a precise scope like pilot_diagnose_sudo/dns's host — wazuh's JSON alerts carry the source agent's identity inside the line itself, not in a per-host file path, so a content search is the one mechanism that finds a host either way). start/end accept RFC3339 or Unix seconds/milliseconds/microseconds/nanoseconds; when either is supplied pilot makes both UTC boundaries explicit and rejects start >= end. Returns the raw Loki JSON response body plus its HTTP status and the exact LogQL query that was run.",
	}, diagnoseSecurityLogsHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_login",
		Description: "one-call composite for \"why can't these users log in / sudo on this host\": runs fixed, read-only ansible ad-hoc commands against one real inventory host for sssd status, sssd domain backend online/offline, Kerberos machine identity, and this host's own DNS self-resolution (a broken forward/reverse record here commonly breaks Kerberos), then for each user in users: NSS passwd resolution (getent passwd) and whether a live central FreeIPA sudo rule grants access (sudo -l -U). Also reads the workspace's FreeIPA roster (config-level, not live) to report each user's declared HBAC/sudo authorization on this host and flags any drift against what was just observed live (e.g. roster declares sudo but the live host has no rule yet, or vice versa). Best-effort also queries recent SSH/PAM login records for these users from Loki (job=\"pilot-siem\", like pilot_diagnose_security_logs, same default ansible-noise exclusion) over the last `lookback` (a Go duration, default 24h) — skipped with a note if the dashboard role isn't deployed in this inventory, never a hard failure. Replaces the usual manual sequence of pilot_diagnose_sudo/dns/security_logs plus a separate roster lookup with one call.",
	}, diagnoseLoginHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_detection",
		Description: "run fixed, read-only ansible ad-hoc commands against the central Detection Engine host (no host parameter — detection-engine is this deployment's singleton central role): engine status (`status --json`), the active SignalEvent episode list (`signals list --json`), and a bounded (`-n 200`) journal tail. At least one of signal_id or pilot_host must be supplied; when signal_id is given (must be a well-formed 26-character ULID) an additional `signals show <signal_id> --json` call returns that one episode's full detail. pilot_host is not a command parameter — the engine's CLI has no per-host filter — it is only recorded for audit/correlation against the returned signals_list_json's own pilot_host fields. Never accepts an arbitrary command.",
	}, diagnoseDetectionHandler(opts))
	registerDiagnoseCompositeTools(server, opts)
}

// normalizeLokiRange makes every caller-supplied log time unambiguous before
// it reaches Loki. Log lines may carry an incorrect timezone offset, so a
// client must never derive a range by comparing such text with Loki's implicit
// server-side "now". If either boundary is supplied, make both boundaries
// explicit in UTC and reject an empty or backwards range locally.
//
// Loki accepts RFC3339 and several Unix precisions. We deliberately accept
// seconds, milliseconds, microseconds, and nanoseconds here, then emit one
// canonical RFC3339Nano representation. The old pass-through behavior made a
// malformed or future timestamp surface only as Loki's opaque "end <= start"
// response.
func normalizeLokiRange(start, end string, now time.Time) (string, string, error) {
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)
	if start == "" && end == "" {
		return "", "", nil
	}

	now = now.UTC()
	endTime := now
	var err error
	if end != "" {
		endTime, err = parseLokiTime(end, now, false)
		if err != nil {
			return "", "", fmt.Errorf("invalid end %q: %w", end, err)
		}
	}

	startTime := endTime.Add(-time.Hour)
	if start != "" {
		startTime, err = parseLokiTime(start, now, true)
		if err != nil {
			return "", "", fmt.Errorf("invalid start %q: %w", start, err)
		}
	}
	if !startTime.Before(endTime) {
		return "", "", fmt.Errorf(
			"start (%s) must be before end (%s); use Loki entry timestamps or the dashboard host clock, not a timestamp embedded in a log line",
			startTime.Format(time.RFC3339Nano), endTime.Format(time.RFC3339Nano),
		)
	}
	return startTime.Format(time.RFC3339Nano), endTime.Format(time.RFC3339Nano), nil
}

func parseLokiTime(value string, now time.Time, isStart bool) (time.Time, error) {
	if value == "now" {
		return now, nil
	}
	if duration, err := time.ParseDuration(value); err == nil {
		if !isStart {
			return time.Time{}, fmt.Errorf("relative duration is only valid for start; use now or an absolute time for end")
		}
		return now.Add(-duration), nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}

	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 {
		return time.Time{}, fmt.Errorf("expected RFC3339 or a non-negative Unix timestamp in seconds, milliseconds, microseconds, or nanoseconds")
	}
	switch {
	case n < 10_000_000_000:
		return time.Unix(n, 0).UTC(), nil
	case n <= 9_223_372_036_854:
		return time.Unix(0, n*int64(time.Millisecond)).UTC(), nil
	case n <= 9_223_372_036_854_775:
		return time.Unix(0, n*int64(time.Microsecond)).UTC(), nil
	default:
		return time.Unix(0, n).UTC(), nil
	}
}

// ---- shared plumbing --------------------------------------------------

// scopedDiagnoseAnsibleRuntime derives a copy of base whose SSH
// ControlPath is unique to this one diagnose tool call. Every
// pilot_diagnose_* handler calls this exactly once per invocation and
// reuses the resulting runtime (via ctx) for every ad-hoc step that one
// call makes, so a single call's own sequential steps against the same
// host still share one multiplexed SSH connection (ControlPersist=60s).
//
// base's ControlPath is shared for the whole server's lifetime
// (prepareDeployAnsibleRuntime is called once, in mcp.go). Two DIFFERENT
// pilot_diagnose_* calls targeting the same host would otherwise race two
// independent `ansible` processes over the exact same control socket
// path — confirmed 2026-08-21 that these calls really do run
// concurrently (go-sdk dispatches every tool call in its own goroutine).
// OpenSSH's own control-socket creation is not guaranteed atomic across
// two unrelated processes hitting it at once, so this scopes the path
// per call instead of trying to prove that race is always benign.
//
// Keep the scoped socket under /tmp and use %C for the host tuple. Adding a
// per-call ID to the normal data-dir path can exceed OpenSSH's 108-byte
// Unix-domain socket limit. The full random scope remains in the path, so
// concurrent calls still get distinct sockets without embedding user, host,
// and port in the path a second time.
func scopedDiagnoseAnsibleRuntime(base deployAnsibleRuntime) deployAnsibleRuntime {
	scope, err := newID()
	if err != nil {
		// crypto/rand failure isn't realistically recoverable here; fall
		// back to the shared ControlPath rather than failing the call.
		return base
	}
	env := make([]string, 0, len(base.Env))
	for _, kv := range base.Env {
		if strings.HasPrefix(kv, "ANSIBLE_SSH_ARGS=") {
			continue
		}
		env = append(env, kv)
	}
	controlPath := filepath.Join("/tmp", "pilot-"+scope+"-%C")
	env = append(env, "ANSIBLE_SSH_ARGS=-o ControlMaster=auto -o ControlPath="+strconv.Quote(controlPath)+" -o ControlPersist=60s")
	return deployAnsibleRuntime{TempDir: base.TempDir, SSHControlDir: base.SSHControlDir, LogPath: base.LogPath, Env: env}
}

// realDiagnoseAdHocRunner adapts deployAnsibleCommand (the same
// ANSIBLE_HOME-isolated exec.Cmd builder every other ansible invocation in
// this codebase uses) to diagnose.AdHocRunner's shape, capturing stdout
// even when the remote command's own nonzero rc makes the ansible process
// itself exit nonzero — that's expected and informative here (e.g.
// "systemctl is-active sssd" on a stopped service), not a run failure.
func realDiagnoseAdHocRunner() diagnose.AdHocRunner {
	return func(ctx context.Context, args []string, timeoutSeconds int) (stdoutText string, exitCode int, runErr error) {
		logPath := deployAnsibleRuntimeFromContext(ctx).LogPath
		defer func() {
			if err := ansible.MaintainLog(logPath); err != nil && runErr == nil {
				runErr = fmt.Errorf("maintain Ansible log: %w", err)
			}
		}()
		releaseLog := ansible.HoldLogUse(logPath)
		defer releaseLog()
		cctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
		command := deployAnsibleCommand(cctx, "ansible", args...)
		// CommandContext kills only the direct ansible process. A descendant
		// ssh process can retain stdout/stderr after that kill, which otherwise
		// lets Cmd.Wait block indefinitely. Bound pipe draining so MCP always
		// returns a timeout result.
		command.WaitDelay = 2 * time.Second
		if command.Env == nil {
			command.Env = os.Environ()
		}
		command.Env = append(command.Env, "ANSIBLE_LOAD_CALLBACK_PLUGINS=1", "ANSIBLE_STDOUT_CALLBACK=ansible.posix.json")
		var stdout, stderr strings.Builder
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		exitCode = 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			err = nil
		}
		if cctx.Err() != nil {
			return stdout.String(), exitCode, fmt.Errorf("ansible diagnose step timed out after %ds: %w", timeoutSeconds, cctx.Err())
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

		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
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

		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
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

// ---- pilot_diagnose_logs --------------------------------------------------

type diagnoseLogsInput struct {
	Query               string `json:"query" jsonschema:"LogQL query, e.g. {job=\"pilot-siem\"} |= \"error\""`
	Start               string `json:"start,omitempty" jsonschema:"optional range start: RFC3339 or Unix seconds/milliseconds/microseconds/nanoseconds; a duration such as 1h means that far before now"`
	End                 string `json:"end,omitempty" jsonschema:"optional range end: RFC3339 or Unix seconds/milliseconds/microseconds/nanoseconds; now is accepted"`
	Limit               string `json:"limit,omitempty" jsonschema:"optional max entries, passed through verbatim to Loki — omit for Loki's default (100)"`
	Direction           string `json:"direction,omitempty" jsonschema:"optional forward|backward, passed through verbatim to Loki — omit for Loki's default (backward)"`
	IncludeAnsibleNoise bool   `json:"include_ansible_noise,omitempty" jsonschema:"set true to include log lines generated by pilot's own ansible activity (BECOME-SUCCESS sudo/become markers, SSH logins by this inventory's ansible_user automation accounts) — excluded by default since it is noise from pilot itself, not the system/user activity being investigated"`
}

type diagnoseLogsOutput struct {
	Host           string `json:"host"`
	ResolvedAddr   string `json:"resolved_addr,omitempty"`
	Query          string `json:"query"`
	HTTPStatus     int    `json:"http_status,omitempty"`
	ResultJSON     string `json:"result_json,omitempty"`
	Unreachable    bool   `json:"unreachable,omitempty"`
	Error          string `json:"error,omitempty"`
	AuditDirectory string `json:"audit_directory"`
}

// diagnoseLogsHandler auto-resolves diagnose.DashboardGroup's singleton
// host (see internal/diagnose.ResolveSingletonGroupHost) instead of
// taking a host parameter — unlike pilot_diagnose_sudo/dns/run, there is
// no arbitrary target here; Loki always lives on the one dashboard host.
func diagnoseLogsHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseLogsInput, diagnoseLogsOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseLogsInput) (*mcp.CallToolResult, diagnoseLogsOutput, error) {
		if strings.TrimSpace(in.Query) == "" {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "query must not be empty"}), diagnoseLogsOutput{}, nil
		}
		queryStart, queryEnd, err := normalizeLokiRange(in.Start, in.End, time.Now())
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseLogsOutput{}, nil
		}

		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseLogsOutput{}, nil
		}
		host, err := diagnose.ResolveSingletonGroupHost(resolved, diagnose.DashboardGroup)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseLogsOutput{}, nil
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseLogsOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "logs", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseLogsOutput{}, nil
		}

		query := in.Query
		if !in.IncludeAnsibleNoise {
			query = diagnose.ExcludeAnsibleNoise(query, diagnose.AnsibleAutomationUsers(resolved))
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		steps := diagnose.LogsSteps(query, queryStart, queryEnd, in.Limit, in.Direction)
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, host, steps, opts.StepTimeout)

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "logs", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: host,
			Params: map[string]string{"query": query, "start": queryStart, "end": queryEnd, "limit": in.Limit, "direction": in.Direction},
			Start:  start, Finish: time.Now(), Steps: stepAuditList(results),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseLogsOutput{
			Host: host, ResolvedAddr: resolved.HostAddr(host), Query: query,
			AuditDirectory: auditDir,
		}
		result := results[0].Result
		switch {
		case result.RunErr != nil:
			out.Error = result.RunErr.Error()
		case result.Unreachable:
			out.Unreachable = true
		default:
			if body, status, ok := diagnose.SplitHTTPStatus(result.Stdout); ok {
				out.ResultJSON = body
				out.HTTPStatus = status
			} else {
				out.ResultJSON = strings.TrimSpace(result.Stdout)
			}
		}
		return nil, out, nil
	}
}

// ---- pilot_diagnose_security_logs ------------------------------------------

type diagnoseSecurityLogsInput struct {
	Host                string `json:"host,omitempty" jsonschema:"optional hostname/agent name to filter for — a plain substring match against the log line (works against both log-server's syslog lines and wazuh-manager's JSON alerts), not a precise scope; omit to search across everything"`
	Search              string `json:"search,omitempty" jsonschema:"optional substring to filter log lines by — plain text match, not a regex (e.g. \"Failed password\", \"sudo\", a rule ID)"`
	Start               string `json:"start,omitempty" jsonschema:"optional range start: RFC3339 or Unix seconds/milliseconds/microseconds/nanoseconds; a duration such as 1h means that far before now"`
	End                 string `json:"end,omitempty" jsonschema:"optional range end: RFC3339 or Unix seconds/milliseconds/microseconds/nanoseconds; now is accepted"`
	Limit               string `json:"limit,omitempty" jsonschema:"max entries, passed through verbatim — omit for Loki's default (100)"`
	Direction           string `json:"direction,omitempty" jsonschema:"forward|backward, passed through verbatim — omit for Loki's default (backward)"`
	IncludeAnsibleNoise bool   `json:"include_ansible_noise,omitempty" jsonschema:"set true to include log lines generated by pilot's own ansible activity (BECOME-SUCCESS sudo/become markers, SSH logins by this inventory's ansible_user automation accounts) — excluded by default since it is noise from pilot itself, not a real security/audit event. Turning this on is useful when auditing pilot's own deploy/reconcile/diagnose activity specifically."`
}

type diagnoseSecurityLogsOutput struct {
	Host           string `json:"host"` // resolved dashboard-group host, informational only
	ResolvedAddr   string `json:"resolved_addr,omitempty"`
	Query          string `json:"query"` // the composed LogQL, so the caller can see/iterate on it
	HTTPStatus     int    `json:"http_status,omitempty"`
	ResultJSON     string `json:"result_json,omitempty"`
	Unreachable    bool   `json:"unreachable,omitempty"`
	Error          string `json:"error,omitempty"`
	AuditDirectory string `json:"audit_directory"`
}

// diagnoseSecurityLogsHandler is structurally identical to
// diagnoseLogsHandler (same dashboard-group auto-resolution, same Loki
// query_range/HTTP-status plumbing) except the LogQL query is composed
// from host/search via diagnose.SecurityLogsSteps rather than taken
// verbatim from the caller — so, unlike pilot_diagnose_logs, there is no
// required/non-empty input to validate: every field is optional.
func diagnoseSecurityLogsHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseSecurityLogsInput, diagnoseSecurityLogsOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseSecurityLogsInput) (*mcp.CallToolResult, diagnoseSecurityLogsOutput, error) {
		queryStart, queryEnd, err := normalizeLokiRange(in.Start, in.End, time.Now())
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseSecurityLogsOutput{}, nil
		}
		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseSecurityLogsOutput{}, nil
		}
		host, err := diagnose.ResolveSingletonGroupHost(resolved, diagnose.DashboardGroup)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseSecurityLogsOutput{}, nil
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseSecurityLogsOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "security_logs", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseSecurityLogsOutput{}, nil
		}

		query := diagnose.SecurityLogsQuery(in.Host, in.Search)
		if !in.IncludeAnsibleNoise {
			query = diagnose.ExcludeAnsibleNoise(query, diagnose.AnsibleAutomationUsers(resolved))
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		steps := diagnose.LogsSteps(query, queryStart, queryEnd, in.Limit, in.Direction)
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, host, steps, opts.StepTimeout)

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "security_logs", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: host,
			Params: map[string]string{
				"host": in.Host, "search": in.Search, "start": queryStart, "end": queryEnd,
				"limit": in.Limit, "direction": in.Direction, "query": query,
			},
			Start: start, Finish: time.Now(), Steps: stepAuditList(results),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseSecurityLogsOutput{
			Host: host, ResolvedAddr: resolved.HostAddr(host), Query: query,
			AuditDirectory: auditDir,
		}
		result := results[0].Result
		switch {
		case result.RunErr != nil:
			out.Error = result.RunErr.Error()
		case result.Unreachable:
			out.Unreachable = true
		default:
			if body, status, ok := diagnose.SplitHTTPStatus(result.Stdout); ok {
				out.ResultJSON = body
				out.HTTPStatus = status
			} else {
				out.ResultJSON = strings.TrimSpace(result.Stdout)
			}
		}
		return nil, out, nil
	}
}

// ---- pilot_diagnose_login ------------------------------------------------

type diagnoseLoginInput struct {
	Host                string   `json:"host" jsonschema:"exact inventory hostname — must be an exact ansible-inventory key, never a pattern/group/wildcard"`
	Users               []string `json:"users" jsonschema:"one or more OS/FreeIPA usernames to check login/sudo access for on this host"`
	Lookback            string   `json:"lookback,omitempty" jsonschema:"how far back to search recent SSH/PAM login records, as a Go duration (e.g. 1h, 24h, 168h) — default 24h"`
	IncludeAnsibleNoise bool     `json:"include_ansible_noise,omitempty" jsonschema:"set true to include log lines generated by this very call's own ansible ad-hoc activity against host — excluded by default, same as pilot_diagnose_logs/security_logs, since it is noise from pilot itself and not the login activity being investigated"`
}

type diagnoseLoginUserOutput struct {
	User                        string   `json:"user"`
	RosterHBACAuthorized        bool     `json:"roster_hbac_authorized"`
	RosterHBACRules             []string `json:"roster_hbac_rules,omitempty"`
	RosterSudoAuthorized        bool     `json:"roster_sudo_authorized"`
	RosterSudoRules             []string `json:"roster_sudo_rules,omitempty"`
	AccountResolvesViaSSSD      bool     `json:"account_resolves_via_sssd"`
	PasswdEntry                 string   `json:"passwd_entry,omitempty"`
	CentralSudoRuleGrantsAccess bool     `json:"central_sudo_rule_grants_access"`
	Verdict                     string   `json:"verdict"`
}

// diagnoseLoginSecurityLogs is deliberately best-effort: SkippedReason is
// set (and every other field left zero) when this inventory has no
// dashboard-group host to query Loki through, rather than failing the
// whole pilot_diagnose_login call over a section that only ever
// supplements the host/user-level findings above it.
type diagnoseLoginSecurityLogs struct {
	Query         string `json:"query,omitempty"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	ResultJSON    string `json:"result_json,omitempty"`
	Unreachable   bool   `json:"unreachable,omitempty"`
	Error         string `json:"error,omitempty"`
	SkippedReason string `json:"skipped_reason,omitempty"`
}

type diagnoseLoginOutput struct {
	Host                       string                    `json:"host"`
	ResolvedAddr               string                    `json:"resolved_addr,omitempty"`
	SssdActive                 bool                      `json:"sssd_active"`
	HasKerberosMachineIdentity bool                      `json:"has_kerberos_machine_identity"`
	SssdDomainStatusChecked    bool                      `json:"sssd_domain_status_checked"`
	SssdDomainOnline           bool                      `json:"sssd_domain_online"`
	SssdDomainStatusRaw        string                    `json:"sssd_domain_status_raw,omitempty"`
	DNSNameserver              string                    `json:"dns_nameserver,omitempty"`
	DNSResolvesViaNSS          bool                      `json:"dns_resolves_via_nss"`
	DNSResolvesViaDirectQuery  bool                      `json:"dns_resolves_via_direct_query"`
	HostVerdict                string                    `json:"host_verdict"`
	RosterAvailable            bool                      `json:"roster_available"`
	RosterNote                 string                    `json:"roster_note,omitempty"`
	Users                      []diagnoseLoginUserOutput `json:"users"`
	SecurityLogs               diagnoseLoginSecurityLogs `json:"security_logs"`
	Steps                      []diagnoseStepEvidence    `json:"steps"`
	AuditDirectory             string                    `json:"audit_directory"`
}

// discoverRosterFilePath finds the workspace's canonical FreeIPA roster
// path from any host's already-resolved freeipa_roster_file var — the
// same "look at whatever any host already carries" strategy
// autoFillFreeIPARosterFile (deploy.go) uses when deciding whether to
// auto-fill a deploy's -e, reused here purely for reading, never for
// deciding whether to inject anything into a deploy.
func discoverRosterFilePath(hostVars map[string]map[string]any) string {
	names := make([]string, 0, len(hostVars))
	for name := range hostVars {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if v, ok := hostVars[name]["freeipa_roster_file"].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// rosterRuleNamesFor filters already-resolved HBAC/sudo rules (group and
// hostgroup membership already expanded into Users/Hosts by
// EffectiveHBACAccessList/EffectiveSudoAccessList) down to the names of
// every rule that authorizes user on host.
func rosterRuleNamesFor(user, host string, hbac []inventory.EffectiveHBACAccess, sudo []inventory.EffectiveSudoAccess) (hbacRules, sudoRules []string) {
	contains := func(list []string, v string) bool {
		for _, item := range list {
			if item == v {
				return true
			}
		}
		return false
	}
	for _, r := range hbac {
		if !r.Enabled || !contains(r.Users, user) {
			continue
		}
		if !r.AllHosts && !contains(r.Hosts, host) {
			continue
		}
		hbacRules = append(hbacRules, r.Rule)
	}
	for _, r := range sudo {
		if !contains(r.Users, user) {
			continue
		}
		if !r.AllHosts && !contains(r.Hosts, host) {
			continue
		}
		sudoRules = append(sudoRules, r.Rule)
	}
	return hbacRules, sudoRules
}

func diagnoseLoginHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseLoginInput, diagnoseLoginOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseLoginInput) (*mcp.CallToolResult, diagnoseLoginOutput, error) {
		if len(in.Users) == 0 {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "users must contain at least one username"}), diagnoseLoginOutput{}, nil
		}
		for _, user := range in.Users {
			if !inventory.ValidRosterUserName(user) {
				return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("user %q is not a valid username", user)}), diagnoseLoginOutput{}, nil
			}
		}
		lookback := in.Lookback
		if lookback == "" {
			lookback = "24h"
		}
		queryStart, queryEnd, err := normalizeLokiRange(lookback, "", time.Now())
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("invalid lookback: %v", err)}), diagnoseLoginOutput{}, nil
		}

		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseLoginOutput{}, nil
		}
		if err := diagnose.ValidateHost(resolved, in.Host); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrHostNotFound, Message: err.Error()}), diagnoseLoginOutput{}, nil
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseLoginOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "login", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseLoginOutput{}, nil
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}

		steps := diagnose.LoginSteps(in.Host, in.Users)
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, in.Host, steps, opts.StepTimeout)
		hostOut := diagnose.BuildLoginHostOutput(in.Host, results)

		// Roster is a local workspace-file read, not an ad-hoc step —
		// best-effort, since a workspace might genuinely have no roster
		// wired up yet, or one that's vault-encrypted and unreadable
		// without a password this tool never asks for.
		var hbacRules []inventory.EffectiveHBACAccess
		var sudoRules []inventory.EffectiveSudoAccess
		rosterAvailable := false
		rosterNote := ""
		if rosterPath := discoverRosterFilePath(resolved.HostVars); rosterPath != "" {
			rosterPath = resolveRosterPath(filepath.Dir(opts.Inventory), rosterPath)
			hbac, hbacErr := inventory.EffectiveHBACAccessList(rosterPath)
			sudo, sudoErr := inventory.EffectiveSudoAccessList(rosterPath)
			switch {
			case hbacErr != nil:
				rosterNote = fmt.Sprintf("could not read roster %s: %v", rosterPath, hbacErr)
			case sudoErr != nil:
				rosterNote = fmt.Sprintf("could not read roster %s: %v", rosterPath, sudoErr)
			default:
				hbacRules, sudoRules, rosterAvailable = hbac, sudo, true
			}
		} else {
			rosterNote = "no host in this inventory declares freeipa_roster_file — roster HBAC/sudo comparison skipped"
		}

		users := make([]diagnoseLoginUserOutput, len(in.Users))
		for i, user := range in.Users {
			var hRules, sRules []string
			if rosterAvailable {
				hRules, sRules = rosterRuleNamesFor(user, in.Host, hbacRules, sudoRules)
			}
			u := diagnose.BuildLoginUserOutput(user, in.Host, hostOut, results, rosterAvailable, hRules, sRules)
			users[i] = diagnoseLoginUserOutput{
				User: u.User, RosterHBACAuthorized: u.RosterHBACAuthorized, RosterHBACRules: u.RosterHBACRules,
				RosterSudoAuthorized: u.RosterSudoAuthorized, RosterSudoRules: u.RosterSudoRules,
				AccountResolvesViaSSSD: u.AccountResolvesViaSSSD, PasswdEntry: u.PasswdEntry,
				CentralSudoRuleGrantsAccess: u.CentralSudoRuleGrantsAccess, Verdict: u.Verdict,
			}
		}

		allResults := results
		secLogs := diagnoseLoginSecurityLogs{}
		if dashboardHost, dashErr := diagnose.ResolveSingletonGroupHost(resolved, diagnose.DashboardGroup); dashErr != nil {
			secLogs.SkippedReason = dashErr.Error()
		} else {
			query := diagnose.LoginSecurityLogsQuery(in.Host, in.Users)
			if !in.IncludeAnsibleNoise {
				query = diagnose.ExcludeAnsibleNoise(query, diagnose.AnsibleAutomationUsers(resolved))
			}
			logSteps := diagnose.LogsSteps(query, queryStart, queryEnd, "", "")
			logResults := diagnose.RunSteps(ctx, runner, opts.Inventory, dashboardHost, logSteps, opts.StepTimeout)
			allResults = append(allResults, logResults...)
			secLogs.Query = query
			result := logResults[0].Result
			switch {
			case result.RunErr != nil:
				secLogs.Error = result.RunErr.Error()
			case result.Unreachable:
				secLogs.Unreachable = true
			default:
				if body, status, ok := diagnose.SplitHTTPStatus(result.Stdout); ok {
					secLogs.ResultJSON = body
					secLogs.HTTPStatus = status
				} else {
					secLogs.ResultJSON = strings.TrimSpace(result.Stdout)
				}
			}
		}

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "login", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: in.Host,
			Params: map[string]string{"users": strings.Join(in.Users, ","), "lookback": lookback},
			Start:  start, Finish: time.Now(), Steps: stepAuditList(allResults),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseLoginOutput{
			Host: in.Host, ResolvedAddr: resolved.HostAddr(in.Host),
			SssdActive: hostOut.SssdActive, HasKerberosMachineIdentity: hostOut.HasKerberosMachineIdentity,
			SssdDomainStatusChecked: hostOut.SssdDomainStatusChecked, SssdDomainOnline: hostOut.SssdDomainOnline,
			SssdDomainStatusRaw:       hostOut.SssdDomainStatusRaw,
			DNSNameserver:             hostOut.DNS.Nameserver,
			DNSResolvesViaNSS:         hostOut.DNS.ResolvesViaNSS,
			DNSResolvesViaDirectQuery: hostOut.DNS.ResolvesViaDirectQuery,
			HostVerdict:               hostOut.Verdict,
			RosterAvailable:           rosterAvailable, RosterNote: rosterNote,
			Users: users, SecurityLogs: secLogs,
			Steps:          stepEvidenceList(allResults),
			AuditDirectory: auditDir,
		}
		return nil, out, nil
	}
}

// ---- pilot_diagnose_metrics ------------------------------------------------

type diagnoseMetricsInput struct {
	Query string `json:"query" jsonschema:"PromQL query, e.g. up{job=\"prometheus\"}"`
	Time  string `json:"time,omitempty" jsonschema:"optional instant-query evaluation time — ignored if start/end are set"`
	Start string `json:"start,omitempty" jsonschema:"optional range-query start — set together with end to run a range query instead of an instant query"`
	End   string `json:"end,omitempty" jsonschema:"optional range-query end — required together with start"`
	Step  string `json:"step,omitempty" jsonschema:"optional range-query step, e.g. 30s or 5m — Thanos's default if omitted"`
}

type diagnoseMetricsOutput struct {
	Host           string `json:"host"`
	ResolvedAddr   string `json:"resolved_addr,omitempty"`
	Query          string `json:"query"`
	HTTPStatus     int    `json:"http_status,omitempty"`
	ResultJSON     string `json:"result_json,omitempty"`
	Unreachable    bool   `json:"unreachable,omitempty"`
	Error          string `json:"error,omitempty"`
	AuditDirectory string `json:"audit_directory"`
}

// diagnoseMetricsHandler auto-resolves diagnose.ThanosQueryGroup's
// singleton host, same reasoning as diagnoseLogsHandler.
func diagnoseMetricsHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseMetricsInput, diagnoseMetricsOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseMetricsInput) (*mcp.CallToolResult, diagnoseMetricsOutput, error) {
		if strings.TrimSpace(in.Query) == "" {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "query must not be empty"}), diagnoseMetricsOutput{}, nil
		}
		if (in.Start == "") != (in.End == "") {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "start and end must both be set together, or both omitted"}), diagnoseMetricsOutput{}, nil
		}

		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseMetricsOutput{}, nil
		}
		host, err := diagnose.ResolveSingletonGroupHost(resolved, diagnose.ThanosQueryGroup)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseMetricsOutput{}, nil
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseMetricsOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "metrics", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseMetricsOutput{}, nil
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		steps := diagnose.MetricsSteps(in.Query, in.Time, in.Start, in.End, in.Step)
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, host, steps, opts.StepTimeout)

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "metrics", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: host,
			Params: map[string]string{"query": in.Query, "time": in.Time, "start": in.Start, "end": in.End, "step": in.Step},
			Start:  start, Finish: time.Now(), Steps: stepAuditList(results),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseMetricsOutput{
			Host: host, ResolvedAddr: resolved.HostAddr(host), Query: in.Query,
			AuditDirectory: auditDir,
		}
		result := results[0].Result
		switch {
		case result.RunErr != nil:
			out.Error = result.RunErr.Error()
		case result.Unreachable:
			out.Unreachable = true
		default:
			if body, status, ok := diagnose.SplitHTTPStatus(result.Stdout); ok {
				out.ResultJSON = body
				out.HTTPStatus = status
			} else {
				out.ResultJSON = strings.TrimSpace(result.Stdout)
			}
		}
		return nil, out, nil
	}
}

// ---- pilot_diagnose_detection -----------------------------------------------

type diagnoseDetectionInput struct {
	SignalID  string `json:"signal_id,omitempty" jsonschema:"optional ULID signal_id (26-character Crockford base32) — adds a signals-show call for this one episode"`
	PilotHost string `json:"pilot_host,omitempty" jsonschema:"optional subject hostname — recorded for audit/correlation only; the engine CLI has no per-host filter, so cross-reference it against signals_list_json yourself"`
}

type diagnoseDetectionOutput struct {
	Host            string `json:"host"`
	ResolvedAddr    string `json:"resolved_addr,omitempty"`
	StatusJSON      string `json:"status_json,omitempty"`
	SignalsListJSON string `json:"signals_list_json,omitempty"`
	JournalTail     string `json:"journal_tail,omitempty"`
	SignalShowJSON  string `json:"signal_show_json,omitempty"`
	Unreachable     bool   `json:"unreachable,omitempty"`
	Error           string `json:"error,omitempty"`
	AuditDirectory  string `json:"audit_directory"`
}

// diagnoseDetectionHandler auto-resolves diagnose.DetectionEngineGroup's
// singleton host, same reasoning as diagnoseMetricsHandler.
func diagnoseDetectionHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseDetectionInput, diagnoseDetectionOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseDetectionInput) (*mcp.CallToolResult, diagnoseDetectionOutput, error) {
		signalID := strings.TrimSpace(in.SignalID)
		pilotHost := strings.TrimSpace(in.PilotHost)
		if signalID == "" && pilotHost == "" {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "at least one of signal_id or pilot_host is required"}), diagnoseDetectionOutput{}, nil
		}
		if signalID != "" && !diagnose.SignalIDPattern.MatchString(signalID) {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("signal_id %q is not a well-formed 26-character ULID", signalID)}), diagnoseDetectionOutput{}, nil
		}

		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseDetectionOutput{}, nil
		}
		host, err := diagnose.ResolveSingletonGroupHost(resolved, diagnose.DetectionEngineGroup)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseDetectionOutput{}, nil
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseDetectionOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "detection", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseDetectionOutput{}, nil
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		steps := diagnose.DetectionSteps(signalID)
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, host, steps, opts.StepTimeout)

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "detection", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: host,
			Params: map[string]string{"signal_id": signalID, "pilot_host": pilotHost},
			Start:  start, Finish: time.Now(), Steps: stepAuditList(results),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseDetectionOutput{Host: host, ResolvedAddr: resolved.HostAddr(host), AuditDirectory: auditDir}
		for _, sr := range results {
			switch {
			case sr.Result.RunErr != nil:
				if out.Error == "" {
					out.Error = fmt.Sprintf("%s: %v", sr.Step.ID, sr.Result.RunErr)
				}
			case sr.Result.Unreachable:
				out.Unreachable = true
			default:
				text := strings.TrimSpace(sr.Result.Stdout)
				switch sr.Step.ID {
				case "status":
					out.StatusJSON = text
				case "signals_list":
					out.SignalsListJSON = text
				case "journal":
					out.JournalTail = text
				case "signal_show":
					out.SignalShowJSON = text
				}
			}
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
	addRecoveredTool(server, &mcp.Tool{
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

		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
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
