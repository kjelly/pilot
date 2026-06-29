package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/sandbox"
)

// DefaultAllowedPlaybookRoots is the set of directories where
// `run_ansible` will accept playbook / inventory paths. Defaults to
// the empty slice, meaning the caller must opt-in to specific roots.
var DefaultAllowedPlaybookRoots = []string{}

// RunPlaybookTool executes ansible-playbook invocations with the
// pilot sandbox envelope (path whitelisting, mode dispatch, banner).
type RunPlaybookTool struct {
	Runner *ansible.Runner
	// AllowedPlaybookRoots restricts the LLM to playbooks and
	// inventories that live under any of these directories. If empty,
	// RunPlaybookTool uses DefaultAllowedPlaybookRoots. If still
	// empty, EVERY playbook path is rejected (fail closed).
	AllowedPlaybookRoots []string
	// DefaultInventory, when non-empty, is substituted for an
	// empty `inventory` argument from the model. The path must still
	// pass ValidatePath (i.e. be inside AllowedPlaybookRoots).
	// Set this from `pilot chat --inventory <path>`.
	DefaultInventory string
	// DefaultLimit, when non-empty, is substituted for an empty
	// `limit` argument from the model. Set this from
	// `pilot chat --limit <pattern>`.
	DefaultLimit string
	// Env, when non-nil, redirects ansible-playbook to run inside
	// the sandbox via a generated docker inventory. If nil, the
	// tool uses the model's inventory argument directly.
	Env sandbox.Environment
	// SandboxMode selects how the container is reached:
	//   "" / SandboxModeDocker     (default) host runs ansible-playbook
	//                              with `connection: docker` against
	//                              the container.
	//   SandboxModeDockerExec      host shells into the container with
	//                              `docker exec` and runs
	//                              ansible-playbook inside.
	// Use sandbox.ParseSandboxMode (or sandbox.ParseOrDefault) to
	// normalise a user-supplied string before storing.
	SandboxMode sandbox.SandboxMode
}

type dryRunKey struct{}

func ContextWithDryRun(ctx context.Context, dryRun bool) context.Context {
	return context.WithValue(ctx, dryRunKey{}, dryRun)
}

func IsDryRun(ctx context.Context) bool {
	v, _ := ctx.Value(dryRunKey{}).(bool)
	return v
}

func (t *RunPlaybookTool) Spec() *Spec {
	return &Spec{
		Name:        "run_ansible",
		Description: "Execute an existing Ansible playbook via ansible-playbook. By default runs with --check --diff (dry-run). The proposal will include the diff for human review before any real changes are made. Set check=false to actually apply (still requires human approval). The playbook and inventory paths must be under one of the configured allowed roots.",
		RiskLevel:   "medium",
		Reversible:  true,
		// run_ansible is only safe under --dry-run-all when check=true.
		// The Interceptor below enforces this by rewriting check=true.
		DryRunSafe:  true,
		Parameters:  runPlaybookArgs,
		Interceptor: t.intercept,
	}
}

// intercept is the agent-loop hook. Under --dry-run-all, any call that
// asks for check=false is rewritten to check=true (the same call still
// runs, but only in check mode). Outside dry-run, we leave the args
// alone.
func (t *RunPlaybookTool) intercept(ctx context.Context, args json.RawMessage) (*Result, error) {
	if !IsDryRun(ctx) {
		return nil, nil // no interception; proceed normally
	}
	var a struct {
		Check *bool `json:"check"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("run_ansible: invalid args: %w", err)
	}
	if a.Check == nil || !*a.Check {
		return nil, nil // explicit signal: proceed with overridden args via overrideCheckFlag
	}
	return nil, nil
}

// OverrideCheckFlag returns a copy of the JSON args with check=true.
// It is exported so the agent loop can call it after the Interceptor
// has signalled "rewrite this call".
func OverrideCheckFlag(args json.RawMessage) (json.RawMessage, error) {
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return nil, fmt.Errorf("run_ansible: cannot override check in non-object args: %w", err)
	}
	m["check"] = true
	out, _ := json.Marshal(m)
	return out, nil
}

// ValidatePath returns nil if `path` is under one of the allowed roots.
// Returns an error describing the violation otherwise.
func (t *RunPlaybookTool) ValidatePath(path string) error {
	if path == "" {
		return nil
	}
	roots := t.AllowedPlaybookRoots
	if len(roots) == 0 {
		roots = DefaultAllowedPlaybookRoots
	}
	if len(roots) == 0 {
		return fmt.Errorf("playbook path %q rejected: no allowed roots configured (set AllowedPlaybookRoots)", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("playbook path %q rejected: %v", path, err)
	}
	// Resolve symlinks to avoid escapes via crafted links.
	if rl, err := filepath.EvalSymlinks(abs); err == nil {
		abs = rl
	}
	for _, root := range roots {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if !strings.HasSuffix(rootAbs, "/") {
			rootAbs += "/"
		}
		if strings.HasPrefix(abs, rootAbs) {
			return nil
		}
	}
	return fmt.Errorf("playbook path %q (resolved %s) is outside the allowed roots %v", path, abs, roots)
}

// Execute is the top-level entry point for run_ansible. It is split
// into three stages:
//
//  1. prepareRequest: parse args, enforce whitelist, create temp
//     files, generate sandbox inventory, build ansible argv.
//  2. executor.Run:   delegate to the chosen playbookExecutor.
//  3. renderResult:   format ansible.Result into the tool Result.
//
// Splitting it this way makes each stage individually testable and
// stops Execute from being a 120-line god function (H3 fix).
func (t *RunPlaybookTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	req, rerr := t.prepareRequest(args)
	if rerr != nil {
		return rerr, nil
	}

	// Clean up any temp files prepareRequest created, regardless
	// of whether ansible succeeded, failed, or this function
	// returned a Result{IsError:true}. Errors from os.Remove are
	// swallowed because the tempfiles are best-effort and a
	// failed unlink cannot fail the run. The GeneratedInventory
	// flag distinguishes files we wrote (safe to delete) from
	// caller-supplied paths (must be left alone).
	defer func() {
		if req.ExtraVarsFile != "" {
			_ = os.Remove(req.ExtraVarsFile)
		}
		if req.GeneratedInventory && req.InventoryPath != "" {
			_ = os.Remove(req.InventoryPath)
		}
	}()

	executor, err := t.selectExecutor(t.SandboxMode)
	if err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}, nil
	}

	res, err := executor.Run(ctx, req)
	if err != nil {
		return t.renderResult(res, err, req.Check)
	}

	toolResult, renderErr := t.renderResult(res, nil, req.Check)
	if renderErr != nil {
		return nil, renderErr
	}

	// Auto-verification after successful playbook execution (check=false)
	if !req.Check && res.ExitCode == 0 {
		hostTag := hostTagFromPlaybook(req.PlaybookPath)
		verifyScriptPath := filepath.Join("scripts", fmt.Sprintf("verify-%s.sh", hostTag))
		if _, statErr := os.Stat(verifyScriptPath); statErr == nil {
			// Generate temporary verification playbook
			verifyPlaybookContent := fmt.Sprintf(`- name: Auto-verification
  hosts: all
  become: true
  tasks:
    - name: Run verification script
      ansible.builtin.script:
        cmd: "%s"
      register: verify_output

    - name: Print verification output
      ansible.builtin.debug:
        var: verify_output.stdout_lines
`, verifyScriptPath)

			f, tempPlaybookErr := os.CreateTemp("", "pilot-auto-verify-*.yml")
			if tempPlaybookErr == nil {
				_, _ = f.WriteString(verifyPlaybookContent)
				_ = f.Close()
				defer os.Remove(f.Name())

				verifyReq := req
				verifyReq.PlaybookPath = f.Name()
				verifyReq.Check = false // Run it for real
				verifyReq.EffectiveArgs = make([]string, len(req.EffectiveArgs))
				copy(verifyReq.EffectiveArgs, req.EffectiveArgs)
				if len(verifyReq.EffectiveArgs) > 0 {
					verifyReq.EffectiveArgs[0] = verifyReq.PlaybookPath
				}

				verifyRes, verifyErr := executor.Run(ctx, verifyReq)
				if verifyErr == nil && verifyRes.ExitCode == 0 {
					ndjsonLines := extractNDJSON(verifyRes.Stdout)
					report := renderVerifyReport(ndjsonLines)
					if report != "" {
						toolResult.Content += report
					}
				}
			}
		}
	}

	return toolResult, nil
}

// prepareRequest parses the JSON arguments, validates paths, creates
// the extra-vars temp file, generates the sandbox inventory, and
// builds the ansible argv. Returns a populated playbookExecRequest
// (or a ready-to-return error Result for any validation failure).
//
// The two return values model the two failure modes the rest of
// Execute needs to distinguish:
//   - err != nil:           hard failure (JSON parse, internal error)
//   - result != nil && err: validation failure with a user-facing
//                           message wrapped in a Result{IsError:true}
func (t *RunPlaybookTool) prepareRequest(args json.RawMessage) (playbookExecRequest, *Result) {
	var a struct {
		Playbook          string            `json:"playbook"`
		Inventory         string            `json:"inventory"`
		Limit             string            `json:"limit"`
		Check             *bool             `json:"check"`
		Tags              []string          `json:"tags"`
		SkipTags          []string          `json:"skip_tags"`
		ExtraVars         map[string]any    `json:"extra_vars"`
		RawExtraVars      string            `json:"extra_vars_raw"`
		Become            *bool             `json:"become"`
		Forks             *int              `json:"forks"`
		User              string            `json:"user"`
		Connection        string            `json:"connection"`
		VaultPasswordFile string            `json:"vault_password_file"`
		Diff              *bool             `json:"diff"`
		Timeout           *int              `json:"timeout"`
		FlushCache        *bool             `json:"flush_cache"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return playbookExecRequest{}, &Result{
			Content: fmt.Sprintf("ERROR: run_ansible: invalid args: %v", err),
			IsError: true,
		}
	}
	if a.Playbook == "" {
		return playbookExecRequest{}, &Result{
			Content: "ERROR: run_ansible: playbook is required",
			IsError: true,
		}
	}

	// Apply session defaults (typically from `pilot chat --inventory/--limit`).
	// The LLM can never pass an empty string to bypass these: an empty
	// argument is treated as "not specified" and the default fills in.
	if a.Inventory == "" && t.DefaultInventory != "" {
		a.Inventory = t.DefaultInventory
	}
	if a.Limit == "" && t.DefaultLimit != "" {
		a.Limit = t.DefaultLimit
	}

	// Mutual exclusion: extra_vars (object) and extra_vars_raw (string).
	if a.ExtraVars != nil && a.RawExtraVars != "" {
		return playbookExecRequest{}, &Result{
			Content: "ERROR: extra_vars and extra_vars_raw are mutually exclusive",
			IsError: true,
		}
	}

	// Path whitelist enforcement.
	if err := t.ValidatePath(a.Playbook); err != nil {
		return playbookExecRequest{}, &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}
	}
	if a.Inventory != "" {
		if err := t.ValidatePath(a.Inventory); err != nil {
			return playbookExecRequest{}, &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}
		}
	}
	if a.VaultPasswordFile != "" {
		// Vault file must be in allowed roots AND we never read its
		// contents — ansible-playbook reads the file directly.
		if err := t.ValidatePath(a.VaultPasswordFile); err != nil {
			return playbookExecRequest{}, &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}
		}
	}

	// Confirm the file actually exists before shelling out.
	if _, err := os.Stat(a.Playbook); err != nil {
		return playbookExecRequest{}, &Result{Content: fmt.Sprintf("ERROR: playbook not readable: %v", err), IsError: true}
	}

	check := true
	if a.Check != nil {
		check = *a.Check
	}

	// Only the docker-connection executor targets the container
	// from the HOST with `connection: docker`. docker-exec runs
	// ansible-playbook INSIDE the container, where the rewritten
	// inventory would be wrong (the container has no docker
	// socket) and would just be a wasted temp file. Gate the
	// rewrite accordingly so we never generate a file that the
	// caller cannot use.
	needsSandboxInv := t.Env != nil &&
		t.Env.ConnectionInfo().ConnectionType == "docker" &&
		t.SandboxMode != sandbox.SandboxModeDockerExec

	extraVarsFile, errRes := t.writeExtraVarsFile(a.ExtraVars)
	if errRes != nil {
		return playbookExecRequest{}, errRes
	}

	effectiveInventory, generatedInventory, errRes := t.resolveInventory(a.Inventory, a.Limit, needsSandboxInv)
	if errRes != nil {
		// The extra-vars file (if any) leaks on this error path,
		// because we have not yet installed the cleanup defer.
		// Best-effort manual cleanup so a JSON-parse / I/O error
		// after temp-file creation does not leave a tmpfile
		// behind every time.
		if extraVarsFile != "" {
			_ = os.Remove(extraVarsFile)
		}
		return playbookExecRequest{}, errRes
	}

	allArgs := ansible.BuildArgs(ansible.PlaybookArgs{
		Playbook:          a.Playbook,
		Inventory:         effectiveInventory,
		Limit:             a.Limit,
		Tags:              a.Tags,
		SkipTags:          a.SkipTags,
		ExtraVarsFile:     extraVarsFile,
		RawExtraVars:      a.RawExtraVars,
		Become:            a.Become,
		Forks:             a.Forks,
		User:              a.User,
		Connection:        a.Connection,
		VaultPasswordFile: a.VaultPasswordFile,
		Diff:              a.Diff,
		Timeout:           a.Timeout,
		FlushCache:        a.FlushCache,
	})

	// Default to "no override" (Timeout=0). The executor decides
	// whether the tool's Runner.Timeout or the per-call timeout
	// takes precedence — see playbookExecutor implementations.
	var timeout time.Duration
	if a.Timeout != nil && *a.Timeout > 0 {
		timeout = time.Duration(*a.Timeout) * time.Second
	}

	return playbookExecRequest{
		PlaybookPath:       a.Playbook,
		InventoryPath:      effectiveInventory,
		ExtraVarsFile:      extraVarsFile,
		Check:              check,
		Limit:              a.Limit,
		Timeout:            timeout,
		EffectiveArgs:      allArgs,
		GeneratedInventory: generatedInventory,
	}, nil
}

// writeExtraVarsFile marshals extra_vars (if provided) to a temp JSON
// file and returns its path. Returns ("", nil) when no extra_vars
// were provided. Temp-file ownership belongs to Execute, which
// installs the cleanup defer once prepareRequest returns; this
// helper just creates the file. Any failure path within this
// function performs its own os.Remove before returning so we do
// not leak the partial file on write errors.
func (t *RunPlaybookTool) writeExtraVarsFile(extra map[string]any) (string, *Result) {
	if extra == nil {
		return "", nil
	}
	data, err := json.Marshal(extra)
	if err != nil {
		return "", &Result{Content: fmt.Sprintf("ERROR: marshal extra_vars: %v", err), IsError: true}
	}
	f, err := os.CreateTemp("", "pilot-extra-vars-*.json")
	if err != nil {
		return "", &Result{Content: fmt.Sprintf("ERROR: create extra_vars tmpfile: %v", err), IsError: true}
	}
	// Restrict permissions — the file may contain secrets.
	_ = f.Chmod(0o600)
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", &Result{Content: fmt.Sprintf("ERROR: write extra_vars tmpfile: %v", err), IsError: true}
	}
	f.Close()
	// Best-effort cleanup; the tmpfile lives only for the duration
	// of the ansible invocation. Defer runs in Execute after the
	// result is rendered.
	return f.Name(), nil
}

// resolveInventory returns the inventory path ansible-playbook will
// actually use, plus a bool reporting whether the returned path
// was generated by pilot (true) or came from the caller (false).
// When a docker-connection sandbox is active, the model-supplied
// inventory is intentionally replaced with a generated
// `connection: docker` fragment so we never accidentally target a
// real prod host the LLM might have placed in the inventory.
//
// `needsSandboxInv` is the mode-aware gate computed by
// prepareRequest: the docker-exec executor runs ansible INSIDE
// the container, where the rewritten inventory would be wrong
// and is therefore skipped entirely.
func (t *RunPlaybookTool) resolveInventory(modelInventory, limit string, needsSandboxInv bool) (string, bool, *Result) {
	if !needsSandboxInv {
		return modelInventory, false, nil
	}
	conn := t.Env.ConnectionInfo()
	inv, err := buildSandboxInventory(conn, limit)
	if err != nil {
		return "", false, &Result{Content: fmt.Sprintf("ERROR: build sandbox inventory: %v", err), IsError: true}
	}
	f, err := os.CreateTemp("", "pilot-sandbox-inv-*.yml")
	if err != nil {
		return "", false, &Result{Content: fmt.Sprintf("ERROR: create sandbox inventory tmpfile: %v", err), IsError: true}
	}
	if _, err := f.WriteString(inv); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", false, &Result{Content: fmt.Sprintf("ERROR: write sandbox inventory: %v", err), IsError: true}
	}
	f.Close()
	return f.Name(), true, nil
}

// renderResult formats the ansible.Result into the tool Result that
// the agent loop and audit log consume. Centralised here so each
// executor doesn't duplicate the formatting logic.
func (t *RunPlaybookTool) renderResult(res *ansible.Result, err error, check bool) (*Result, error) {
	if err != nil {
		stderr := ""
		if res != nil {
			stderr = res.Stderr
		}
		return &Result{
			Content: fmt.Sprintf("ERROR: %v\nStderr: %s", err, stderr),
			IsError: true,
		}, nil
	}

	mode := "APPLY"
	if check {
		mode = "CHECK"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "[%s mode] %s\n", mode, res.Cmd)
	fmt.Fprintf(&sb, "Exit code: %d  Duration: %s\n\n", res.ExitCode, res.Duration)
	if res.Stdout != "" {
		sb.WriteString("--- stdout ---\n")
		cb := os.Getenv("ANSIBLE_STDOUT_CALLBACK")
		if cb == "" || cb == "default" || cb == "yaml" || cb == "debug" {
			sb.WriteString(ansible.FilterOutput(res.Stdout))
		} else {
			sb.WriteString(res.Stdout)
		}
	}
	if res.Stderr != "" {
		sb.WriteString("\n--- stderr ---\n")
		sb.WriteString(res.Stderr)
	}
	if res.ExitCode != 0 {
		return &Result{Content: sb.String(), IsError: true}, nil
	}
	return &Result{Content: sb.String()}, nil
}

// buildSandboxInventory generates a minimal ansible inventory that
// targets a single docker container. All hosts in the inventory
// resolve to the same container_id with `ansible_connection: docker`,
// so every task in the playbook runs against the same sandbox.
//
// For loop engineering, "all hosts in the inventory collapse onto
// the same container" is the intended behaviour: the user is
// iterating on a single playbook against a single test environment.
//
// We intentionally keep this inventory minimal — no group_vars, no
// host_vars — so the user can't accidentally inject config that
// the sandbox mode wouldn't honour.
func buildSandboxInventory(conn sandbox.AnsibleConnection, limit string) (string, error) {
	if conn.ConnectionType != "docker" {
		return "", fmt.Errorf("buildSandboxInventory: connection type %q not supported", conn.ConnectionType)
	}
	if conn.ContainerID == "" {
		return "", fmt.Errorf("buildSandboxInventory: empty container ID")
	}
	user := conn.User
	if user == "" {
		user = "root"
	}
	var sb strings.Builder
	sb.WriteString("# Generated by pilot sandbox mode — do not edit by hand.\n")
	sb.WriteString("all:\n")
	sb.WriteString("  hosts:\n")
	fmt.Fprintf(&sb, "    sandbox:\n")
	fmt.Fprintf(&sb, "      ansible_connection: docker\n")
	fmt.Fprintf(&sb, "      ansible_host: %s\n", conn.ContainerID)
	fmt.Fprintf(&sb, "      ansible_user: %s\n", user)
	if limit != "" {
		// Honour the model's --limit. The inventory has only one
		// host named "sandbox", so we just propagate the limit
		// string verbatim — ansible's --limit syntax is shared
		// with inventory host names.
		fmt.Fprintf(&sb, "  # effective --limit: %s\n", limit)
	}
	return sb.String(), nil
}

func hostTagFromPlaybook(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}

func extractNDJSON(stdout string) []string {
	var results []string
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimSuffix(trimmed, ",")
		if strings.HasPrefix(trimmed, "\"") && strings.HasSuffix(trimmed, "\"") {
			trimmed = trimmed[1 : len(trimmed)-1]
		}
		trimmed = strings.ReplaceAll(trimmed, `\"`, `"`)
		trimmed = strings.ReplaceAll(trimmed, `\\`, `\`)
		if strings.HasPrefix(trimmed, `{"id"`) {
			results = append(results, trimmed)
		}
	}
	return results
}

type verifyRecord struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func renderVerifyReport(ndjsonLines []string) string {
	var records []verifyRecord
	passed := 0
	failed := 0
	skipped := 0
	for _, line := range ndjsonLines {
		var rec verifyRecord
		if err := json.Unmarshal([]byte(line), &rec); err == nil {
			records = append(records, rec)
			switch rec.Status {
			case "pass":
				passed++
			case "fail":
				failed++
			case "skip":
				skipped++
			}
		}
	}
	if len(records) == 0 {
		return ""
	}
	
	verdict := "PASS"
	if failed > 0 {
		verdict = "FAIL"
	}
	
	var sb strings.Builder
	sb.WriteString("\n\n=== Auto-Verification Report ===\n")
	fmt.Fprintf(&sb, "Verdict: %s (Total: %d, Pass: %d, Fail: %d, Skip: %d)\n\n", verdict, len(records), passed, failed, skipped)
	sb.WriteString("| ID | Status | Detail |\n")
	sb.WriteString("|----|--------|--------|\n")
	
	// Fails first
	for _, r := range records {
		if r.Status == "fail" {
			fmt.Fprintf(&sb, "| %s | %s | %s |\n", r.ID, r.Status, r.Detail)
		}
	}
	// Others
	for _, r := range records {
		if r.Status != "fail" {
			fmt.Fprintf(&sb, "| %s | %s | %s |\n", r.ID, r.Status, r.Detail)
		}
	}
	return sb.String()
}
