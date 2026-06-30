package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/agent"
	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/app"
	"github.com/anomalyco/pilot/internal/store"
	"github.com/anomalyco/pilot/internal/sandbox"
)

var runCmd = &cobra.Command{
	Use:   "run [<playbook>] [goal]",
	Short: "Run pilot agent against one or more Ansible playbooks",
	Long: `Run the AI agent with a natural-language goal. The agent will use
its tools to inspect hosts, propose changes, and (with approval) apply them
via Ansible.

Use one of these to specify which playbook(s) to run:
  pilot run site.yml [goal]              single playbook (positional)
  ls *.yml | pilot run --from-stdin      read paths from stdin
  pilot run --discover 'playbooks/*.yml' glob pattern
  pilot run --discover playbooks/        scan directory`,
	Args: cobra.MaximumNArgs(2),
	RunE: runRun,
}

var (
	runInventory        string
	runLimit            string
	runMode             string
	runFromStdin        bool
	runDiscover         string
	runDryRunAll        bool
	runSkipSyntax       bool
	runSkipLint         bool
	runFailFast         bool
	runSandbox            bool
	runSandboxImage       string
	runSandboxHostname    string
	runSandboxNetwork     string
	runSandboxKeep        bool
	runSandboxPreferCached bool
	runSandboxDryRun      bool
	runSandboxTopology    string
	runSandboxMounts      []string
	// runTarget is the name of a docker target (managed by
	// `pilot docker-target`). When set, the LLM agent loop's
	// run_ansible tool calls get pointed at that target's
	// generated inventory. See app.ResolveDockerTarget.
	runTarget             string
	// runSandboxMode is declared in root.go as a shared global so
	// `pilot chat` can set it too. We don't redeclare it here.
)

func init() {
	runCmd.Flags().StringVarP(&runInventory, "inventory", "i", "", "Ansible inventory file")
	runCmd.Flags().StringVar(&runLimit, "limit", "", "limit execution to a host pattern")
	runCmd.Flags().StringVar(&runMode, "execution-mode", "serial", "execution mode: serial|parallel")


	// New flags
	runCmd.Flags().BoolVar(&runFromStdin, "from-stdin", false, "read playbook paths from stdin (one per line, or JSON Lines)")
	runCmd.Flags().StringVar(&runDiscover, "discover", "", "glob pattern or directory to discover playbooks")
	runCmd.Flags().BoolVar(&runDryRunAll, "dry-run-all", false, "execute the full agent loop but never mutate the system")
	runCmd.Flags().BoolVar(&runSkipSyntax, "skip-syntax-check", false, "skip ansible-playbook --syntax-check pre-flight")
	runCmd.Flags().BoolVar(&runSkipLint, "skip-lint", false, "skip ansible-lint pre-flight check")
	runCmd.Flags().BoolVar(&runFailFast, "fail-fast", false, "with --from-stdin/--discover, stop on first failure")
	runCmd.Flags().BoolVar(&runNoIndex, "no-index", false, "skip docs index freshness check (don't auto-rebuild)")
	runCmd.Flags().BoolVar(&runNoIndexOnStart, "no-index-on-start", false, "warn on stale index but don't rebuild")
	runCmd.Flags().BoolVar(&runStrictIndex, "strict-index", false, "error out if docs index is stale (don't auto-rebuild)")

	// Sandbox flags
	runCmd.Flags().BoolVar(&runSandbox, "sandbox", false, "run all tool calls inside a Docker container matching the target OS")
	runCmd.Flags().StringVar(&runSandboxImage, "sandbox-image", "", "override auto-detected docker image (e.g. 'ubuntu:22.04')")
	runCmd.Flags().StringVar(&runSandboxHostname, "sandbox-hostname", "", "inventory hostname for auto-detect via 'docker inspect <hostname>'")
	runCmd.Flags().StringVar(&runSandboxNetwork, "sandbox-network", "", "docker --network mode: host (default), bridge, none")
	runCmd.Flags().BoolVar(&runSandboxKeep, "sandbox-keep", false, "do not remove the sandbox container on Stop; reuse it on next run")
	runCmd.Flags().BoolVar(&runSandboxPreferCached, "sandbox-prefer-cached", false, "use --pull never when image is already cached locally")
	runCmd.Flags().BoolVar(&runSandboxDryRun, "sandbox-dry-run", false, "mount rootfs read-only with tmpfs /tmp; writes don't persist")
	runCmd.Flags().StringVar(&runSandboxTopology, "sandbox-topology", "", "multi-host topology: 'web01:webservers+frontend,db01:dbservers'")
	runCmd.Flags().StringSliceVar(&runSandboxMounts, "sandbox-mount", nil, "host:container[:ro] bind mount; may be repeated")
	// Sandbox execution mode. "" / "docker" (default) uses the
	// host's ansible-playbook with `connection: docker` (requires
	// host docker-py + community.docker). "docker-exec" runs
	// ansible-playbook inside the container via `docker exec`;
	// container must ship its own ansible.
	runCmd.Flags().StringVar(&runSandboxMode, "sandbox-mode", "",
		"sandbox execution mode: 'docker' (default; host ansible+docker connection) or 'docker-exec' (run ansible inside the container via `docker exec`)")
	runCmd.Flags().StringVar(&runTarget, "target", "",
		"docker target name (managed by `pilot docker-target`); routes the LLM agent's run_ansible tool calls to that container's generated inventory")
}

// playbookTarget is a single playbook to run, possibly with overrides.
// All optional fields are pointer-typed (or omitempty) so that JSON
// Lines that pre-date this struct keep working: an absent field
// decodes to the zero value and the corresponding ansible-playbook
// flag is simply not added.
type playbookTarget struct {
	Playbook string `json:"playbook"`

	// Host targeting
	Inventory string `json:"inventory,omitempty"`
	Limit     string `json:"limit,omitempty"`

	// Tag / var selection
	Tags       []string       `json:"tags,omitempty"`
	SkipTags   []string       `json:"skip_tags,omitempty"`
	ExtraVars  map[string]any `json:"extra_vars,omitempty"`
	RawExtraVars string       `json:"extra_vars_raw,omitempty"`

	// Privilege / connection
	Become     *bool  `json:"become,omitempty"`
	Forks      *int   `json:"forks,omitempty"`
	User       string `json:"user,omitempty"`
	Connection string `json:"connection,omitempty"`

	// Security / cache
	VaultPasswordFile string `json:"vault_password_file,omitempty"`
	Diff              *bool  `json:"diff,omitempty"`

	// Execution control
	Timeout    *int  `json:"timeout,omitempty"`
	FlushCache *bool `json:"flush_cache,omitempty"`
}

func runRun(cmd *cobra.Command, args []string) error {
	// ----- 1. Resolve target list --------------------------------------
	targets, err := resolveTargets(args)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no playbooks specified; pass a positional arg, --from-stdin, or --discover")
	}

	// ----- 2. Mode parsing ---------------------------------------------
	// mode is "serial" (default) or "parallel". When "parallel",
	// multiple playbooks run concurrently up to cfg.MaxConc
	// (default 5). Fail-fast cancels remaining work on first
	// failure and waits for in-flight goroutines to drain.
	mode := runMode

	// ----- 3. Setup stack ----------------------------------------------
	ctx := context.Background()
	// --dry-run-all forces the local environment even when --sandbox
	// is on. The whole point of dry-run is "I want to see what the
	// LLM would propose without any real execution", so spinning up
	// a Docker container that no tool will mutate is pure waste.
	appOpts := app.Options{
		NoTUI:  noTUI,
		Banner: true,
	}
	if runDryRunAll {
		appOpts.SkipSandbox = true
	}
	if runSandbox {
		appOpts.ForceSandbox = true
		appOpts.SandboxHostname = runSandboxHostname
		appOpts.SandboxKeep = runSandboxKeep
		appOpts.SandboxPreferCached = runSandboxPreferCached
		appOpts.SandboxDryRun = runSandboxDryRun
		appOpts.SandboxMode = runSandboxMode
		if runSandboxTopology != "" {
			topo, err := sandbox.ParseTopology(runSandboxTopology)
			if err != nil {
				return fmt.Errorf("--sandbox-topology: %w", err)
			}
			appOpts.SandboxTopology = &topo
		}
		for _, m := range runSandboxMounts {
			// host:container[:ro]
			parts := strings.SplitN(m, ":", 3)
			if len(parts) < 2 {
				return fmt.Errorf("--sandbox-mount %q: want host:container[:ro]", m)
			}
			mount := sandbox.SandboxMount{HostPath: parts[0], ContainerPath: parts[1]}
			if len(parts) == 3 && parts[2] == "ro" {
				mount.RO = true
			}
			appOpts.SandboxMounts = append(appOpts.SandboxMounts, mount)
		}
	}
	res, err := setupRunWithOpts(ctx, appOpts)
	if err != nil {
		return err
	}

	defer res.Store.Close()
	defer shutdownTUI(res.TUI)

	// ----- 3a. Ensure docs index is fresh ------------------------------
	if !runNoIndex {
		if _, err := ensureDocsIndex(ctx, res.Cfg.DataDir); err != nil {
			if res.TUI == nil {
				fmt.Fprintf(os.Stderr, "warning: ensureDocsIndex: %v\n", err)
			}
		}
	}

	// ----- 4. Banner for dry-run / batch -------------------------------
	if runDryRunAll {
		if res.TUI == nil {
			fmt.Fprintln(os.Stderr, "🔍 DRY-RUN MODE: no system changes will be made")
		} else {
			res.TUI.SendRunStart("dryrun-banner", "DRY-RUN MODE: no system changes will be made")
		}
	}

	// ----- 5. Batch loop -----------------------------------------------
	batchID := ""
	if len(targets) > 1 {
		batchID = newBatchID()
		if res.TUI == nil {
			fmt.Fprintf(os.Stderr, "▶ Batch %s — %d playbooks\n", shortIDOf(batchID), len(targets))
		}
	}

	results := make([]batchResult, len(targets))
	if mode == "parallel" {
		maxConc := res.Cfg.MaxConc
		if maxConc <= 0 {
			maxConc = 5
		}
		sem := make(chan struct{}, maxConc)
		type indexedResult struct {
			idx int
			br  batchResult
		}
		resChan := make(chan indexedResult, len(targets))
		// failFastCtx is cancelled the moment any worker reports
		// failure (when --fail-fast is set). runOneTarget checks
		// ctx.Err() between stages so an in-flight ansible run
		// still gets to finish its current call before yielding,
		// instead of leaving zombie subprocesses behind.
		failFastCtx, cancelFailFast := context.WithCancel(ctx)
		defer cancelFailFast()

		for i, tgt := range targets {
			go func(index int, target playbookTarget) {
				sem <- struct{}{}
				defer func() { <-sem }()
				prefix := fmt.Sprintf("[%d/%d] ", index+1, len(targets))
				br := runOneTarget(failFastCtx, res, batchID, prefix, target, mode)
				resChan <- indexedResult{idx: index, br: br}
			}(i, tgt)
		}

		for i := 0; i < len(targets); i++ {
			ir := <-resChan
			results[ir.idx] = ir.br

			// Print progress to non-TUI stderr
			if res.TUI == nil && !ir.br.failedAtSyntaxCheck {
				mark := "✓"
				if !ir.br.OK {
					mark = "✗"
				}
				prefix := fmt.Sprintf("[%d/%d] ", ir.idx+1, len(targets))
				fmt.Fprintf(os.Stderr, "  %s%s %s\n", prefix, mark, ir.br.Playbook)
			}

			if runFailFast && !ir.br.OK {
				if res.TUI == nil {
					fmt.Fprintln(os.Stderr, "  --fail-fast: cancelling remaining workers")
				}
				cancelFailFast()
			}
		}
	} else {
		// Serial execution
		for i, tgt := range targets {
			prefix := ""
			if len(targets) > 1 {
				prefix = fmt.Sprintf("[%d/%d] ", i+1, len(targets))
			}
			br := runOneTarget(ctx, res, batchID, prefix, tgt, mode)
			results[i] = br

			// Print progress to non-TUI stderr
			if res.TUI == nil && !br.failedAtSyntaxCheck {
				mark := "✓"
				if !br.OK {
					mark = "✗"
				}
				fmt.Fprintf(os.Stderr, "  %s%s %s\n", prefix, mark, tgt.Playbook)
			}

			// Fail-fast
			if runFailFast && !br.OK {
				if res.TUI == nil {
					fmt.Fprintln(os.Stderr, "  --fail-fast: stopping on first failure")
				}
				results = results[:i+1]
				break
			}
		}
	}

	// ----- 6. Summary --------------------------------------------------
	if len(targets) > 1 && res.TUI == nil {
		printBatchSummary(batchID, results)
	}

	if runDryRunAll {
		printDryRunWouldDo(results)
	}

	// If everything failed, return non-zero
	for _, r := range results {
		if !r.OK {
			return fmt.Errorf("%d/%d playbook runs failed", countFailures(results), len(results))
		}
	}
	return nil
}

// batchResult is a summary record used by the batch loop.
type batchResult struct {
	Playbook            string
	OK                  bool
	Err                 string
	ProposalCount       int
	Approved            int
	Rejected            int
	failedAtSyntaxCheck bool
	// Proposals is the full proposal list for this target. Only populated
	// when --dry-run-all is on (so we can print a useful WOULD-DO summary);
	// otherwise the audit log has the canonical copy.
	Proposals           []*agent.Proposal
}

func runOneTarget(ctx context.Context, res *setupResult, batchID, prefix string, tgt playbookTarget, mode string) batchResult {
	br := batchResult{Playbook: tgt.Playbook}

	// ----- a. Pre-flight syntax check ---------------------------------
	if !runSkipSyntax {
		// Use the shared BuildArgs so the syntax check sees the
		// same flag set that the real run will use (tags,
		// extra-vars, etc. — these don't affect YAML parseability
		// but matching keeps the pre-flight honest).
		// Extra-vars: the syntax check does not need actual values
		// but ansible-playbook does load them. We marshal if the
		// object form is present so the call is well-formed.
		var extraVarsFile string
		if len(tgt.ExtraVars) > 0 {
			data, err := json.Marshal(tgt.ExtraVars)
			if err == nil {
				f, ferr := os.CreateTemp("", "pilot-syntax-vars-*.json")
				if ferr == nil {
					_ = f.Chmod(0o600)
					if _, werr := f.Write(data); werr == nil {
						f.Close()
						extraVarsFile = f.Name()
						defer os.Remove(extraVarsFile)
					} else {
						f.Close()
						os.Remove(f.Name())
					}
				}
			}
		}
		syntaxArgs := []string{"--syntax-check"}
		syntaxArgs = append(syntaxArgs, ansible.BuildArgs(ansible.PlaybookArgs{
			Playbook:          tgt.Playbook,
			Inventory:         tgt.Inventory,
			Limit:             tgt.Limit,
			Tags:              tgt.Tags,
			SkipTags:          tgt.SkipTags,
			ExtraVarsFile:     extraVarsFile,
			RawExtraVars:      tgt.RawExtraVars,
			Become:            tgt.Become,
			Forks:             tgt.Forks,
			User:              tgt.User,
			Connection:        tgt.Connection,
			VaultPasswordFile: tgt.VaultPasswordFile,
			Diff:              tgt.Diff,
			Timeout:           tgt.Timeout,
			FlushCache:        tgt.FlushCache,
		})...)
		sres, err := res.Runner.Run(ctx, syntaxArgs...)
		if err != nil {
			br.Err = "syntax check error: " + err.Error()
			br.failedAtSyntaxCheck = true
			return br
		}
		if sres.ExitCode != 0 {
			br.Err = fmt.Sprintf("syntax check failed (exit=%d): %s", sres.ExitCode, trimForErr(sres.Stderr))
			br.failedAtSyntaxCheck = true
			if res.TUI == nil {
				fmt.Fprintf(os.Stderr, "  %s✗ %s\n", prefix, tgt.Playbook)
				fmt.Fprintf(os.Stderr, "    %s\n", trimForErr(sres.Stderr))
			}
			return br
		}
	}

	var lintIssues string
	if !runSkipLint {
		lintPath, err := exec.LookPath("ansible-lint")
		if err == nil {
			cmd := exec.CommandContext(ctx, lintPath, tgt.Playbook)
			out, _ := cmd.CombinedOutput()
			if len(out) > 0 && cmd.ProcessState != nil && !cmd.ProcessState.Success() {
				lintIssues = string(out)
				if res.TUI == nil {
					fmt.Fprintf(os.Stderr, "  ⚠️  ansible-lint found issues in %s:\n%s\n", tgt.Playbook, indentString(lintIssues, 4))
				}
			}
		} else {
			if res.TUI == nil {
				fmt.Fprintln(os.Stderr, "  ⚠️  ansible-lint not found in PATH; skipping pre-flight lint check.")
			}
		}
	}

	// ----- b. Create run record ---------------------------------------
	run := newRunRecord(res.Cfg, mode, tgt.Playbook, tgt.Inventory)
	run.BatchID = batchID
	run.DryRun = runDryRunAll
	if err := res.Store.CreateRun(run); err != nil {
		br.Err = "create run: " + err.Error()
		return br
	}

	// Clean up run status to "aborted" if process is interrupted
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		_ = res.Store.FinishRun(run.ID, "aborted")
		os.Exit(130)
	}()
	defer func() {
		signal.Stop(sigChan)
	}()

	// ----- c. Run the agent loop ---------------------------------------
	// Preflight: read the playbook file and inline its content into the
	// goal. This is the most reliable way to make sure the LLM sees the
	// playbook on turn 0 — every observed LLM hallucination of "the file
	// is empty / not at that path" goes away once the content is in the
	// initial user message. We keep this best-effort: if the read fails
	// for any reason (e.g. file unreadable, sandbox), we fall back to the
	// bare path-based goal and let the LLM figure it out.
	goal := buildGoal(tgt, lintIssues)
	if content, preflightErr := preflightReadPlaybook(tgt.Playbook); preflightErr == nil && content != "" {
		goal = goal + "\n\n--- playbook contents (preloaded; do NOT call read_file on the playbook again) ---\n" + content + "\n--- end of playbook contents ---"
	} else if preflightErr != nil {
		// Surface a clear early warning so the user knows the LLM will
		// have to read the file itself.
		fmt.Fprintf(os.Stderr, "⚠️  preflight read of playbook failed: %v\n", preflightErr)
	}
	if res.TUI != nil {
		res.TUI.SendRunStart(run.ID, goal)
	} else if prefix == "" {
		fmt.Fprintf(os.Stderr, "▶ Starting run %s\n", run.ID)
	}

	// Reuse the *App that setupRunWithOpts already built — do NOT call
	// app.New() again here. The previous 7-arg form rebuilt the entire
	// stack (bleve open, ollama Ping, registry default-walk) for every
	// playbook in a batch, which doubled the work for N=1 and made
	// hangs much more likely.
	// If --target is set, build the loop with the target's
	// generated inventory + limit as the run_ansible tool's defaults.
	// This means the LLM doesn't have to spell out "-i <file> -l <n>"
	// for every playbook it proposes.
	var loop *agent.Loop
	if inv := resolveTargetInventory(); inv != "" {
		// resolveTargetInventory stages the target's generated inventory
		// to a temp file and hands us ownership of the path. Remove it
		// when this run finishes — the file only needs to outlive
		// loop.Run below. (Previously this leaked one tmpfile per
		// `pilot run --target` invocation into $TMPDIR.)
		defer os.Remove(inv)
		loop = res.NewLoopWithDefaults(run.ID, os.Stderr, inv, runTarget)
	} else {
		loop = newAgentLoop(res, run.ID, os.Stderr)
	}
	// Inject dry-run flag
	loop.SetDryRun(runDryRunAll)

	if err := loop.Run(ctx, goal); err != nil {
		_ = res.Store.FinishRun(run.ID, "failed")
		_ = res.Store.SetRunError(run.ID, err.Error())
		br.Err = err.Error()
		if res.TUI != nil {
			res.TUI.SendError(err.Error())
		}
		return br
	}
	_ = res.Store.FinishRun(run.ID, "success")
	if res.TUI != nil {
		res.TUI.SendRunFinish(run.ID, "success")
	}

	// Tally proposals for the summary
	props, _ := res.Store.ListProposals(run.ID)
	br.ProposalCount = len(props)
	if runDryRunAll {
		// Capture for the WOULD-DO summary printed at batch end.
		br.Proposals = proposalsFromStore(props)
	}
	for _, p := range props {
		switch p.Status {
		case "approved", "applied":
			br.Approved++
		case "rejected":
			br.Rejected++
		}
	}
	br.OK = true
	return br
}

// preflightReadPlaybook returns the playbook's content so the agent loop
// can include it in the initial user message. The LLM otherwise spends
// its first 2-3 turns trying to read the file and either hallucinating
// "the file is empty" or proposing wrong paths ("/root/playbooks/...").
// Inlining the content on turn 0 is the most reliable fix.
//
// Errors are non-fatal: the caller logs them and continues with a
// path-only goal. We do NOT want preflight failure to abort the run
// — the LLM can still try read_file on its own.
func preflightReadPlaybook(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func buildGoal(tgt playbookTarget, lintIssues string) string {
	goal := "Run this Ansible playbook and fix any failures you encounter."
	lintSection := ""
	if lintIssues != "" {
		lintSection = fmt.Sprintf("\n\n⚠️  ansible-lint detected the following issues in the playbook. Please fix/refactor them before proposing to apply changes:\n%s", lintIssues)
	}

	// Resolve the playbook path to an absolute path so the LLM does not
	// have to guess where the user's CWD is. The previous wording
	// "Playbook: %s" left the path relative; some LLM models then
	// hallucinated an absolute path (e.g. /root/playbooks/...) that
	// did not exist, causing read_file to fail with "not in the allowed
	// paths" and the run to spiral.
	//
	// We also surface the user's CWD explicitly so any subsequent
	// read_file / run_command call uses the same root.
	playbookAbs := tgt.Playbook
	if abs, err := filepath.Abs(tgt.Playbook); err == nil {
		playbookAbs = abs
	}
	cwd, _ := os.Getwd()

	// When no inventory was supplied, say so explicitly. The model
	// otherwise fixates on the "No inventory was parsed" warning and
	// wastes turns hunting for an inventory file instead of just
	// running the playbook against the implicit localhost.
	invLine := tgt.Inventory
	if strings.TrimSpace(invLine) == "" {
		invLine = "(none — do NOT look for or pass an inventory file; run_ansible against the playbook's own hosts: line. For localhost playbooks Ansible's implicit local connection is used.)"
	}

	return fmt.Sprintf(`Playbook (absolute path): %s
Working directory: %s
Original (relative) spec: %s
Inventory: %s
Limit: %s

User goal: %s%s

IMPORTANT — this is a "run playbook" task; stay focused on running it:
- Your PRIMARY job is to RUN this playbook with the run_ansible tool. Under normal
  circumstances your VERY FIRST tool call must be run_ansible with "playbook" set to the
  absolute path above. Running the playbook IS how you observe the current state — do not
  "observe first".
- Do NOT explore the filesystem, hunt for inventory files, or run read-only probes
  (run_command / read_file / run_inspec) BEFORE you have run the playbook at least once.
- If Inventory above says "(none …)", do not pass an inventory at all — just call run_ansible
  with the playbook path.
- Use the other tools ONLY AFTER a run_ansible call actually FAILS, to diagnose and fix the
  failure, then re-run. When the PLAY RECAP shows failed=0 the task is COMPLETE: give a short
  summary and stop — do not call any more tools.

Every write operation goes through a tool call presented to the human for approval.
When calling read_file with the playbook, USE THE ABSOLUTE PATH above; do not invent a path.`,
		playbookAbs, cwd, tgt.Playbook, invLine, tgt.Limit, goal, lintSection)
}

func indentString(s string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

// resolveTargets returns the list of playbooks to run based on the
// (possibly mixed) combination of positional arg, --from-stdin, and
// --discover. Enforces mutual exclusion.
//
// Inventory resolution order (highest priority first):
//  1. explicit -i/--inventory CLI flag
//  2. ANSIBLE_INVENTORY env var (if CLI flag is empty)
//  3. per-line override in JSONL stdin (beats env, can also be empty)
//
// The resolved inv/lim is only applied to plain-path stdin and
// --discover; JSONL stdin honors per-line inventory/limit and leaves
// the global env-fallback aside (each line is independent).
func resolveTargets(args []string) ([]playbookTarget, error) {
	hasPositional := len(args) >= 1
	if runFromStdin && runDiscover != "" {
		return nil, fmt.Errorf("--from-stdin and --discover are mutually exclusive")
	}
	if hasPositional && (runFromStdin || runDiscover != "") {
		return nil, fmt.Errorf("positional playbook cannot be combined with --from-stdin or --discover")
	}
	if hasPositional && len(args) >= 2 {
		// we currently don't use the goal as a separate arg; the
		// default goal is used. We could parse args[1] as a goal in
		// the future.
	}

	// Fall back to ANSIBLE_INVENTORY when the CLI flag is empty.
	// Limit has no env-var convention; --limit is intentionally per-run.
	effectiveInventory := runInventory
	if effectiveInventory == "" {
		effectiveInventory = os.Getenv("ANSIBLE_INVENTORY")
	}
	effectiveLimit := runLimit

	switch {
	case hasPositional:
		return []playbookTarget{{
			Playbook:  args[0],
			Inventory: effectiveInventory,
			Limit:     effectiveLimit,
		}}, nil
	case runFromStdin:
		return readTargetsFromStdin(effectiveInventory, effectiveLimit)
	case runDiscover != "":
		return discoverTargets(runDiscover, effectiveInventory, effectiveLimit)
	default:
		return nil, fmt.Errorf("no playbook specified")
	}
}

// readTargetsFromStdin reads playbook paths from stdin. Auto-detects
// JSON Lines if the first non-empty line starts with '{'. Empty lines
// and lines starting with '#' are ignored.
//
// defaultInventory / defaultLimit are the env- or CLI-fallback values
// used for plain-path lines; JSON lines keep their per-line overrides
// and only inherit these when their inventory/limit is empty.
func readTargetsFromStdin(defaultInventory, defaultLimit string) ([]playbookTarget, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("no input on stdin")
	}

	// Auto-detect JSON vs plain paths
	if strings.HasPrefix(lines[0], "{") {
		return parseJSONLines(lines, defaultInventory, defaultLimit)
	}
	return parsePlainLines(lines, defaultInventory, defaultLimit)
}

func parsePlainLines(lines []string, defaultInventory, defaultLimit string) ([]playbookTarget, error) {
	var out []playbookTarget
	for _, line := range lines {
		// Expand globs
		matches, err := filepath.Glob(line)
		if err != nil {
			return nil, fmt.Errorf("bad glob %q: %w", line, err)
		}
		if len(matches) == 0 {
			// Not a glob and file doesn't exist; treat as literal
			matches = []string{line}
		}
		for _, m := range matches {
			out = append(out, playbookTarget{
				Playbook:  m,
				Inventory: defaultInventory,
				Limit:     defaultLimit,
			})
		}
	}
	return out, nil
}

func parseJSONLines(lines []string, defaultInventory, defaultLimit string) ([]playbookTarget, error) {
	var out []playbookTarget
	for _, line := range lines {
		var t playbookTarget
		if err := json.Unmarshal([]byte(line), &t); err != nil {
			return nil, fmt.Errorf("invalid JSON line %q: %w", line, err)
		}
		if t.Playbook == "" {
			return nil, fmt.Errorf("JSON line missing 'playbook': %q", line)
		}
		if t.Inventory == "" {
			t.Inventory = defaultInventory
		}
		if t.Limit == "" {
			t.Limit = defaultLimit
		}
		out = append(out, t)
	}
	return out, nil
}

// discoverTargets handles --discover. If the input looks like a glob
// (contains *, ?, [) it's expanded; otherwise if it's a directory,
// all *.yml and *.yaml files under it are listed; otherwise treated
// as a literal file path.
//
// defaultInventory / defaultLimit are applied to every discovered
// target (same semantics as positional mode).
func discoverTargets(pattern, defaultInventory, defaultLimit string) ([]playbookTarget, error) {
	if hasGlobMeta(pattern) {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("bad glob: %w", err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("glob %q matched no files", pattern)
		}
		return toTargets(matches, defaultInventory, defaultLimit), nil
	}
	// Directory or file
	info, err := os.Stat(pattern)
	if err != nil {
		return nil, fmt.Errorf("--discover %q: %w", pattern, err)
	}
	if info.IsDir() {
		entries, err := os.ReadDir(pattern)
		if err != nil {
			return nil, err
		}
		var matches []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext == ".yml" || ext == ".yaml" {
				matches = append(matches, filepath.Join(pattern, e.Name()))
			}
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no *.yml/*.yaml files found in %q", pattern)
		}
		return toTargets(matches, defaultInventory, defaultLimit), nil
	}
	// Single file
	return []playbookTarget{{Playbook: pattern, Inventory: runInventory, Limit: runLimit}}, nil
}

func hasGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

func toTargets(paths []string, defaultInventory, defaultLimit string) []playbookTarget {
	out := make([]playbookTarget, 0, len(paths))
	for _, p := range paths {
		out = append(out, playbookTarget{
			Playbook:  p,
			Inventory: defaultInventory,
			Limit:     defaultLimit,
		})
	}
	return out
}

// ----- Summary helpers ----------------------------------------------------

func printBatchSummary(batchID string, results []batchResult) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, strings.Repeat("─", 60))
	fmt.Fprintf(os.Stderr, "▶ Batch %s — summary\n", shortIDOf(batchID))
	for _, r := range results {
		mark := "✓"
		if !r.OK {
			mark = "✗"
		}
		fmt.Fprintf(os.Stderr, "  %s %s", mark, r.Playbook)
		if !r.OK {
			fmt.Fprintf(os.Stderr, "  (failed: %s)", truncForSummary(r.Err, 60))
		} else if r.ProposalCount > 0 {
			fmt.Fprintf(os.Stderr, "  (%d proposals, %d approved, %d rejected)", r.ProposalCount, r.Approved, r.Rejected)
		}
		fmt.Fprintln(os.Stderr)
	}
	succeeded, failed := countByOK(results)
	fmt.Fprintf(os.Stderr, "✓ Batch complete: %d/%d succeeded\n", succeeded, len(results))
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "  %d failed\n", failed)
	}
}

// printDryRunWouldDo summarises what the dry-run would have done.
// For each batch target that produced proposals, we list every proposal
// with its tool, risk level, and a one-line summary of the action
// the agent wanted to take.
func printDryRunWouldDo(results []batchResult) {
	total := 0
	for _, r := range results {
		total += len(r.Proposals)
	}
	if total == 0 {
		return
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, strings.Repeat("─", 60))
	fmt.Fprintf(os.Stderr, "🔍 DRY-RUN: WOULD-DO summary (%d proposals)\n", total)
	fmt.Fprintln(os.Stderr, strings.Repeat("─", 60))
	for _, r := range results {
		if len(r.Proposals) == 0 {
			continue
		}
		fmt.Fprintf(os.Stderr, "\n  %s — %d proposals:\n", r.Playbook, len(r.Proposals))
		for i, p := range r.Proposals {
			summary := proposalOneLineSummary(p)
			fmt.Fprintf(os.Stderr, "    [%d] %-7s %-22s %s\n",
				i+1, strings.ToUpper(p.RiskLevel), p.Tool, summary)
		}
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Run again WITHOUT --dry-run-all to actually apply.")
}

// proposalOneLineSummary returns a short human-readable summary of a
// proposal suitable for the WOULD-DO output. Falls back to "(no
// rationale)" if the agent didn't fill one in.
func proposalOneLineSummary(p *agent.Proposal) string {
	if p.Rationale != "" {
		return p.Rationale
	}
	// Try to extract the playbook / file path from Args.
	var args map[string]any
	if err := json.Unmarshal(p.Args, &args); err == nil {
		for _, k := range []string{"playbook", "path", "command"} {
			if v, ok := args[k].(string); ok && v != "" {
				return v
			}
		}
	}
	return "(no rationale)"
}

// proposalsFromStore converts a slice of *store.Proposal (which is what
// the store returns) into a slice of *agent.Proposal (which is what
// batchResult holds). Fields are copied lossily — only the ones the
// WOULD-DO summary needs.
func proposalsFromStore(src []*store.Proposal) []*agent.Proposal {
	out := make([]*agent.Proposal, 0, len(src))
	for _, p := range src {
		out = append(out, &agent.Proposal{
			ID:         p.ID,
			Tool:       p.Tool,
			Args:       p.Args,
			Rationale:  p.Rationale,
			RiskLevel:  p.RiskLevel,
			CISControl: p.CISControl,
			Status:     p.Status,
		})
	}
	return out
}

func countByOK(rs []batchResult) (succeeded, failed int) {
	for _, r := range rs {
		if r.OK {
			succeeded++
		} else {
			failed++
		}
	}
	return
}

func countFailures(rs []batchResult) int {
	_, f := countByOK(rs)
	return f
}

func trimForErr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		return s[:400] + "\n... [truncated]"
	}
	return s
}

func newBatchID() string {
	return uuid.NewString()
}

func shortIDOf(s string) string {
	if len(s) >= 8 {
		return s[:8]
	}
	return s
}

func truncForSummary(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// io.Discard import (kept for clarity in the helper chain)
var _ = io.Discard
