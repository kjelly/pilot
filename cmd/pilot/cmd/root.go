package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/agent"
	"github.com/anomalyco/pilot/internal/app"
	"github.com/anomalyco/pilot/internal/config"
	"github.com/anomalyco/pilot/internal/dockertarget"
	"github.com/anomalyco/pilot/internal/logx"
	"github.com/anomalyco/pilot/internal/store"
	"github.com/anomalyco/pilot/internal/ui/tui"
)

var (
	cfgFile   string
	ollamaURL string
	model     string
	stream    bool
	autoOK    string
	dataDir   string
	logLevel  string // --log-level (persistent); default from $PILOT_LOG_LEVEL or "warn"
	noTUI     bool   // deprecated
	useTUI    bool   // --tui (persistent flag, default false)

	// index management
	runNoIndex        bool
	runNoIndexOnStart bool
	runStrictIndex    bool
	// Sandbox mode (shared between `pilot run` and `pilot chat`).
	// Values: "" / "docker" (default) | "docker-exec".
	runSandboxMode string
)

var rootCmd = &cobra.Command{
	Use:   "pilot",
	Short: "AI-assisted Ubuntu security hardening via Ollama",
	Long: `pilot is an AI agent that helps harden Ubuntu hosts to CIS Benchmark.
It uses a local or cloud Ollama model to reason about failures, generate fixes,
and propose Ansible playbooks — but every write is gated by human approval.`,
	Version: "0.2.0",
	// PersistentPreRun installs the diagnostic logger before any command
	// runs, so every `slog.Warn/Debug/...` call is leveled and formatted
	// consistently. User-facing UX output is unaffected (it never goes
	// through slog). The default level is WARN, overridable via --log-level
	// or $PILOT_LOG_LEVEL; $PILOT_LOG_FORMAT=json switches to JSON output.
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		lvl := logLevel
		if lvl == "" {
			lvl = os.Getenv("PILOT_LOG_LEVEL")
		}
		logx.Init(lvl, os.Getenv("PILOT_LOG_FORMAT"), os.Stderr)
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default ~/.config/pilot/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&ollamaURL, "ollama", "", "Ollama server URL")
	rootCmd.PersistentFlags().StringVar(&model, "model", "", "Ollama model name")
	rootCmd.PersistentFlags().BoolVar(&stream, "stream", true, "stream LLM responses")
	rootCmd.PersistentFlags().StringVar(&autoOK, "auto-approve", "", "auto-approve proposals by risk: low|medium|never")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "data directory for proposals, db, generated playbooks")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "diagnostic log level: debug|info|warn|error (default warn; also $PILOT_LOG_LEVEL)")
	// TUI defaults to OFF. Use --tui to opt in. The flag respects TTY:
	//   --tui + TTY       → Bubbletea TUI
	//   --tui + no TTY    → falls back to promptui (with a one-line notice)
	//   (no --tui)        → promptui directly, no notice
	// --no-tui is kept as a deprecated alias for one release.
	rootCmd.PersistentFlags().BoolVar(&useTUI, "tui", false, "enable the interactive TUI (default: off; requires a TTY)")
	rootCmd.PersistentFlags().BoolVar(&noTUI, "no-tui", false, "DEPRECATED alias for omitting --tui (kept for backward compat)")
	if noTUI {
		// backward compat: --no-tui=true suppresses --tui.
		// We just leave useTUI=false so this branch is a no-op.
		_ = noTUI
	}

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(chatCmd)
	rootCmd.AddCommand(diagnoseCmd)
	rootCmd.AddCommand(modelsCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(indexDocsCmd)
	rootCmd.AddCommand(indexPlaybooksCmd)
	rootCmd.AddCommand(searchDocsCmd)
	rootCmd.AddCommand(listRunsCmd)
	rootCmd.AddCommand(showPlanCmd)
	rootCmd.AddCommand(doctorCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("pilot %s\n", rootCmd.Version)
	},
}

func loadConfig() *config.Config {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		slog.Warn("failed to load config; using defaults", "err", err)
		cfg = config.Default()
	}
	if ollamaURL != "" {
		cfg.OllamaURL = ollamaURL
	}
	if model != "" {
		cfg.Model = model
	}
	if autoOK != "" {
		cfg.AutoApprove = autoOK
	}
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	// Sandbox CLI flags (set on `pilot run` / `pilot chat` via
	// package-level vars in run.go / chat.go). loadConfig is the
	// central place to fold CLI flags into the config struct.
	if runSandbox {
		cfg.Sandbox.Enabled = true
	}
	if runSandboxImage != "" {
		cfg.Sandbox.Image = runSandboxImage
		cfg.Sandbox.Enabled = true
	}
	if runSandboxNetwork != "" {
		cfg.Sandbox.Network = runSandboxNetwork
	}
	if runSandboxMode != "" {
		cfg.Sandbox.Mode = runSandboxMode
	}
	return cfg
}

// setupResult is now a thin alias over *app.App. The fields and
// methods of *app.App match the previous setupResult surface; this
// keeps every existing call site working while centralising the
// stack construction in internal/app.
type setupResult = app.App

// setupRunWithOpts is setupRun plus the ability to pass additional
// app.Options (e.g. ForceSandbox from --sandbox CLI flag, or
// SkipSandbox from --dry-run-all). It is the hook for commands
// that need to override the default environment policy.
func setupRunWithOpts(ctx context.Context, opt app.Options) (*setupResult, error) {
	cfg := loadConfig()
	opt.NoTUI = !useTUI
	opt.Banner = true
	return app.New(ctx, cfg, opt)
}

// resolveTargetInventory returns a non-empty path to a generated
// inventory file when --target <name> was passed and the named
// docker target exists and is running. Returns "" otherwise.
//
// Called from `pilot run` and `pilot chat` so the LLM agent loop's
// run_ansible tool calls pick up the docker target's generated
// inventory automatically — no inventory-*.yaml file needed.
func resolveTargetInventory() string {
	if runTarget == "" {
		return ""
	}
	cfg := loadConfig()
	m, err := dockertarget.NewManager(cfg.DataDir)
	if err != nil {
		slog.Warn("--target: docker-target manager", "target", runTarget, "err", err)
		return ""
	}
	t, err := m.Get(context.Background(), runTarget)
	if err != nil {
		slog.Warn("--target: lookup", "target", runTarget, "err", err)
		return ""
	}
	if t.Status != dockertarget.StatusRunning {
		slog.Warn("--target not running; bring it up with `pilot docker-target up`",
			"target", runTarget, "status", t.Status)
		return ""
	}
	inv, err := t.RenderInventory()
	if err != nil {
		slog.Warn("--target: render inventory", "target", runTarget, "err", err)
		return ""
	}
	f, err := os.CreateTemp("", "pilot-run-target-*.yaml")
	if err != nil {
		return ""
	}
	defer f.Close()
	if _, err := f.WriteString(inv); err != nil {
		os.Remove(f.Name())
		return ""
	}
	return f.Name()
}

func newRunRecord(cfg *config.Config, mode, playbook, inventory string) *store.Run {
	r := &store.Run{
		ID:        uuid.NewString(),
		StartedAt: time.Now(),
		Mode:      mode,
		Playbook:  playbook,
		Inventory: inventory,
		Model:     cfg.Model,
		Status:    "running",
	}
	// Audit: record the docker image when sandbox mode is enabled.
	// LocalEnvironment reports "local" — we leave SandboxImage empty
	// in that case so the column reads as "no sandbox" on plain runs.
	if cfg.Sandbox.Enabled {
		switch cfg.Sandbox.Image {
		case "":
			// Auto-detect resolved at app.New; we don't have it
			// here. Leave empty and let the next migration fill it
			// in via a separate audit hook. For now, mark the run
			// as sandboxed by storing the auto-detect marker.
			r.SandboxImage = "<auto-detect>"
		default:
			r.SandboxImage = cfg.Sandbox.Image
		}
	}
	return r
}

// newAgentLoop assembles an agent.Loop from an already-constructed
// *App. It deliberately does NOT call app.New again — the caller
// (runOneTarget) was given the *App from setupRunWithOpts, and
// rebuilding the stack here would re-open the 100 MB bleve index,
// re-Ping Ollama, and re-walk every default. For batch runs that
// meant N+1 App constructions for N playbooks; for a single run it
// still cost a full duplicate start-up that could hang.
//
// Callers that hit the nil-res path get a failing Loop so the failure
// surfaces in the same place (the agent loop) rather than silently
// returning a working-but-stale Loop.
func newAgentLoop(
	res *setupResult,
	runID string,
	streamWriter io.Writer,
) *agent.Loop {
	if res == nil {
		return agent.NewLoop(agent.Config{RunID: runID, DataDir: ""})
	}
	if streamWriter == nil {
		streamWriter = os.Stderr
	}
	return res.NewLoop(runID, streamWriter)
}

// newAgentLoopWithDefaults wires chat-session defaults (from
// `pilot chat --inventory/--limit`) into both the run_ansible tool
// (deterministic fill-in) and the system prompt (visible hint to
// the LLM). See internal/tools/defaults.go for the tool-side logic.
func newAgentLoopWithDefaults(
	res *setupResult,
	systemPrompt string,
	streamWriter io.Writer,
	defaultInventory string,
	defaultLimit string,
) *agent.Loop {
	if res == nil {
		// Defensive fallback — same shape as newAgentLoop's error
		// path. This should not happen in practice.
		return agent.NewLoop(agent.Config{RunID: "", DataDir: ""})
	}
	if streamWriter == nil {
		streamWriter = os.Stderr
	}
	// System prompt override: App.NewLoop reads from Cfg.SystemPrompt
	// which we mutated via appendSessionDefaults in chat.go.
	return res.NewLoopWithDefaults("", streamWriter, defaultInventory, defaultLimit)
}

// shutdownTUI is a helper to call from main cleanup.
func shutdownTUI(tp *tui.Program) {
	if tp != nil {
		tp.Shutdown()
	}
}
