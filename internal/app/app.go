// Package app centralises pilot's runtime stack so every command
// (run, chat, diagnose) constructs the same set of collaborators
// and tears them down the same way. Before this package, the
// three commands each rebuilt Ollama / Store / Registry / Sanitizer
// in their own way, which led to drift (e.g. a dead registryWithTUITools
// stub that one path forgot to delete).
package app

import (
	"context"
	"strings"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/anomalyco/pilot/internal/agent"
	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/config"
	"github.com/anomalyco/pilot/internal/dockertarget"
	"github.com/anomalyco/pilot/internal/docs"
	"github.com/anomalyco/pilot/internal/ollama"
	"github.com/anomalyco/pilot/internal/sandbox"
	"github.com/anomalyco/pilot/internal/sanitizer"
	"github.com/anomalyco/pilot/internal/store"
	"github.com/anomalyco/pilot/internal/tools"
	"github.com/anomalyco/pilot/internal/ui"
	"github.com/anomalyco/pilot/internal/ui/tui"
)

// App holds the wired-up runtime stack. Methods are safe to call
// until Close is invoked.
type App struct {
	Cfg       *config.Config
	Ollama    *ollama.Client
	Tools     *tools.Registry
	Store     *store.Store
	Sanitizer *sanitizer.Redactor
	Approver  *ui.ConsoleApprover
	TUI       *tui.Program
	Runner    *ansible.Runner
	// Env is the execution environment tools target. Always set
	// (defaults to LocalEnvironment when sandbox is disabled).
	Env sandbox.Environment
	// ctx is the startup context; passed to ResolveDockerTarget so
	// the docker CLI invocation honours the same cancellation as
	// the rest of the app.
	ctx context.Context

}

// Options controls how App is built. The zero value is usable and
// means: build a stack with default Conservative registry wiring,
// start the TUI if a TTY is attached, and surface the stderr banner.
type Options struct {
	// NoTUI disables the TUI even on a TTY.
	NoTUI bool
	// Banner controls whether the "💡 TUI …" line is written to
	// stderr on startup.
	Banner bool
	// Registry, if non-nil, is used as the tool registry verbatim
	// instead of building one from cfg + AllowList defaults. This is
	// the right hook for tests and for callers that need a fully
	// custom tool set.
	Registry *tools.Registry
	// DefaultInventory, when non-empty, is substituted for an empty
	// inventory argument from the model in run_ansible tool calls.
	// Typical use: `pilot chat --inventory <path>`.
	DefaultInventory string
	// DefaultLimit, when non-empty, is substituted for an empty
	// limit argument from the model in run_ansible tool calls.
	// Typical use: `pilot chat --limit <pattern>`.
	DefaultLimit string
	// ForceSandbox bypasses cfg.Sandbox.Enabled when deciding
	// whether to bring up a Docker container. Set by the `--sandbox`
	// CLI flag.
	ForceSandbox bool
	// SandboxHostname, when non-empty, is passed to
	// `docker inspect` for auto-detect when cfg.Sandbox.Image is
	// empty. Typically the first inventory host's name.
	SandboxHostname string
	// SkipSandbox forces the local environment even if --sandbox
	// was passed. Used internally by --dry-run-all to avoid
	// spinning up a container that no tool will use.
	SkipSandbox bool
	// SandboxTopology describes multiple hosts to spin up, one
	// container per HostSpec. Empty = single anonymous sandbox host
	// (legacy behaviour).
	SandboxTopology *sandbox.Topology
	// SandboxKeep, when true, leaves the container alive after Stop()
	// so the next `pilot run --sandbox-keep` can `docker start` it
	// instead of `docker run`. Loop engineering speedup.
	SandboxKeep bool
	// SandboxPreferCached uses --pull never when the image is
	// already present locally. Saves 1-3s per loop iteration.
	SandboxPreferCached bool
	// SandboxDryRun makes the container rootfs read-only and uses
	// tmpfs for /tmp. The user can still issue write operations,
	// but they don't persist past Stop().
	SandboxDryRun bool
	// SandboxMounts are host->container bind mounts added to the
	// docker run for single-host sandboxes. Multi-host topology
	// sets its own per-host mounts.
	SandboxMounts []sandbox.SandboxMount
	// SandboxMode selects how run_ansible reaches the container.
	// "" or "docker" (default) keeps the legacy host-side
	// ansible + docker connection plugin path. "docker-exec"
	// routes the playbook through `docker exec` so the
	// container's own ansible is used and the host needs no
	// docker-py / community.docker.
	SandboxMode string
}

// New constructs an App and starts the TUI (if applicable).
// Close MUST be called when done.
func New(ctx context.Context, cfg *config.Config, opt Options) (*App, error) {
	if cfg == nil {
		return nil, errors.New("app.New: cfg is required")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	st, err := store.Open(filepath.Join(cfg.DataDir, "history.db"))
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	ollamaClient := ollama.NewClient(cfg.OllamaURL, cfg.Model)
	if err := ollamaClient.Ping(ctx); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("ollama not reachable at %s: %w", cfg.OllamaURL, err)
	}
	var extraRules []sanitizer.Rule
	for _, cr := range cfg.CustomRedactRules {
		re, err := regexp.Compile(cr.Pattern)
		if err == nil {
			extraRules = append(extraRules, sanitizer.Rule{
				Pattern:     re,
				Replace:     cr.Replace,
				Description: cr.Description,
			})
		} else {
			fmt.Fprintf(os.Stderr, "warning: invalid custom redact regex %q: %v\n", cr.Pattern, err)
		}
	}
	redactor := sanitizer.NewWith(extraRules...)
	runner := ansible.NewRunner()
	if opt.NoTUI {
		runner.StdoutWriter = os.Stdout
		runner.StderrWriter = os.Stderr
	}

	app := &App{
		Cfg:       cfg,
		Ollama:    ollamaClient,
		Store:     st,
		Sanitizer: redactor,
		Runner:    runner,
		ctx:       ctx,
	}

	// Build the execution environment. Default: LocalEnvironment.
	// With --sandbox or cfg.Sandbox.Enabled, build a Docker container.
	env, err := buildEnvironment(ctx, cfg, opt)
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("build environment: %w", err)
	}
	if err := env.Start(ctx); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("start environment %q: %w", env.Name(), err)
	}
	app.Env = env
	if opt.Banner && env.Name() != "local" {
		fmt.Fprintf(os.Stderr, "📦 sandbox active: %s\n", env.Name())
	}

	// TUI opt-in. --tui was not passed → NoTUI=true → skip the check entirely
	// (no notice, no fallback message). --tui + TTY → Bubbletea. --tui + no
	// TTY → fall back to promptui with the explanatory notice.
	if opt.NoTUI {
		// TUI explicitly disabled; stay silent.
	} else if tui.IsSupported(uintptr(os.Stderr.Fd())) {
		app.TUI = tui.New(st)
		app.TUI.Start()
		if opt.Banner {
			fmt.Fprintln(os.Stderr, "💡 TUI active (Ctrl-C to quit, ? for help)")
		}
	} else if opt.Banner {
		fmt.Fprintln(os.Stderr, "💡 TUI requested but no TTY available; using promptui")
	}

	app.Approver = ui.NewConsoleApprover(cfg.AutoApprove)
	if app.TUI != nil {
		app.Approver.WithTUI(app.TUI)
	}

	// Tool registry
	if opt.Registry != nil {
		app.Tools = opt.Registry
	} else {
		app.Tools = defaultRegistry(cfg, app.TUI, ollamaClient, runner, st, env)
	}
	return app, nil
}

// buildEnvironment constructs the Environment based on cfg.Sandbox
// and opt flags. opt.SkipSandbox always wins (used by --dry-run-all).
//
// Single-host (the legacy path) returns a single DockerEnvironment.
// Multi-host (opt.SandboxTopology non-empty) returns a MultiEnvironment
// wrapping one DockerEnvironment per HostSpec.
func buildEnvironment(ctx context.Context, cfg *config.Config, opt Options) (sandbox.Environment, error) {
	if opt.SkipSandbox {
		return sandbox.NewLocalEnvironment(), nil
	}
	if !cfg.Sandbox.Enabled && !opt.ForceSandbox {
		return sandbox.NewLocalEnvironment(), nil
	}
	img := cfg.Sandbox.Image
	if img == "" && cfg.Sandbox.AutoDetect != "none" {
		hostname := opt.SandboxHostname
		if hostname == "" {
			return nil, errors.New(
				"sandbox enabled but no image specified and no hostname for auto-detect; " +
					"set sandbox.image in config or pass --sandbox-image / --sandbox-hostname")
		}
		var derr error
		img, derr = sandbox.InspectExistingContainer(ctx, "", hostname)
		if derr != nil {
			return nil, fmt.Errorf("auto-detect image from container %q: %w", hostname, derr)
		}
	}
	if img == "" {
		return nil, errors.New("sandbox enabled but no image resolved")
	}

	if opt.SandboxTopology != nil && !opt.SandboxTopology.IsEmpty() {
		// M1 warning: multi-host currently collapses to the first host
		// for tool routing. Per-host exec/read/write isn't wired into
		// the run_ansible tool yet; until it is, the user's other hosts
		// are brought up but only the first one is reachable from
		// run_ansible. Surface this on stderr so the gap is visible.
		if len(opt.SandboxTopology.Hosts) > 1 {
			fmt.Fprintf(os.Stderr,
				"warning: multi-host sandbox: %d hosts requested, but only the first host (%q) is exposed to tools today. The other containers are running but unreachable via run_ansible until per-host routing ships.\n",
				len(opt.SandboxTopology.Hosts),
				opt.SandboxTopology.Hosts[0].Name)
		}
		first, _, err := buildMultiEnvironment(ctx, img, opt, cfg)
		if err != nil {
			return nil, err
		}
		if first == nil {
			return nil, errors.New("multi-host sandbox returned no host environment")
		}
		return first, nil
	}

	de := sandbox.NewDockerEnvironment(img)
	if cfg.Sandbox.ContainerName != "" {
		de.ContainerName = cfg.Sandbox.ContainerName
	}
	if cfg.Sandbox.Network != "" {
		de.Network = cfg.Sandbox.Network
	}
	if cfg.Sandbox.Pull != "" {
		de.Pull = cfg.Sandbox.Pull
	}
	de.Keep = opt.SandboxKeep
	de.PreferCached = opt.SandboxPreferCached
	de.Mounts = append(de.Mounts, opt.SandboxMounts...)
	if opt.SandboxDryRun {
		de.ReadOnlyRootfs = true
	}
	return de, nil
}

// buildMultiEnvironment brings up one DockerEnvironment per HostSpec
// and wraps them in a MultiEnvironment. If any container fails to
// start, the already-started ones are torn down before returning.
func buildMultiEnvironment(ctx context.Context, defaultImage string, opt Options, cfg *config.Config) (sandbox.Environment, sandbox.MultiEnvironment, error) {
	topo := opt.SandboxTopology
	hosts := make(map[string]sandbox.Environment, len(topo.Hosts))
	var started []sandbox.Environment
	for _, hs := range topo.Hosts {
		img := hs.Image
		if img == "" {
			img = defaultImage
		}
		de := sandbox.NewDockerEnvironment(img)
		de.ContainerName = "pilot-sandbox-" + hs.Name + "-" + sandbox.NewNanoID()
		if cfg.Sandbox.Network != "" {
			de.Network = cfg.Sandbox.Network
		}
		de.Keep = opt.SandboxKeep
		de.PreferCached = opt.SandboxPreferCached
		de.Mounts = append(de.Mounts, opt.SandboxMounts...)
		if opt.SandboxDryRun {
			de.ReadOnlyRootfs = true
		}
		if err := de.Start(ctx); err != nil {
			for _, s := range started {
				_ = s.Stop(ctx)
			}
			return nil, nil, fmt.Errorf("start sandbox host %q: %w", hs.Name, err)
		}
		started = append(started, de)
		hosts[hs.Name] = de
	}
	return nil, sandbox.NewMultiEnvironment(*topo, hosts), nil
}

// SandboxImage returns the docker image the active sandbox
// Environment was started with. Returns "" for LocalEnvironment
// or when the image name is unavailable, so callers can use the
// result to populate audit fields without a separate nil check.
//
// Uses TrimPrefix rather than slicing from a magic offset so that
// any future change to Environment.Name() (e.g. "docker-compose:..."
// or a podman-style prefix) won't cause an index-out-of-range panic.
func (a *App) SandboxImage() string {
	if a == nil || a.Env == nil {
		return ""
	}
	name := a.Env.Name()
	if name == "local" {
		return ""
	}
	const prefix = "docker:"
	if !strings.HasPrefix(name, prefix) {
		// Defensive: a non-docker Environment shouldn't reach here,
		// but if a future backend (podman, ssh, ...) is added and the
		// caller still wants an image string, return the full name.
		return name
	}
	return strings.TrimPrefix(name, prefix)
}

// Close releases owned resources (Env, Store, TUI). It is safe to
// call multiple times.

// ResolveDockerTarget looks up a docker target by name and returns a
// temp-file path containing its generated inventory. Returns
// ("", error) if the target doesn't exist or isn't running.
//
// This is the bridge that lets `pilot run --target <docker-target>`
// route the LLM agent loop's run_ansible tool calls to a docker
// container without the user having to write an inventory-*.yaml
// file.
func (a *App) ResolveDockerTarget(name, dataDir string) (string, error) {
	m, err := dockertarget.NewManager(dataDir)
	if err != nil {
		return "", err
	}
	t, err := m.Get(a.ctx, name)
	if err != nil {
		return "", err
	}
	if t.Status != dockertarget.StatusRunning {
		return "", fmt.Errorf("target %q is not running (status=%s); bring it up with `pilot docker-target up`", name, t.Status)
	}
	inv, err := t.RenderInventory()
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "pilot-run-target-*.yaml")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(inv); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func (a *App) Close() {
	if a == nil {
		return
	}
	if a.TUI != nil {
		a.TUI.Shutdown()
		a.TUI = nil
	}
	if a.Env != nil {
		_ = a.Env.Stop(context.Background())
		a.Env = nil
	}
	if a.Store != nil {
		_ = a.Store.Close()
		a.Store = nil
	}
}

func mapAllowedCommands(cmds []config.CmdSpec) []tools.CmdSpec {
	out := make([]tools.CmdSpec, len(cmds))
	for i, c := range cmds {
		args := make([]tools.ArgPattern, len(c.Args))
		for j, a := range c.Args {
			args[j] = tools.ArgPattern{
				Exact:  a.Exact,
				Prefix: a.Prefix,
			}
		}
		out[i] = tools.CmdSpec{
			Program: c.Program,
			Args:    args,
		}
	}
	return out
}

// NewLoop constructs an agent.Loop using the App's collaborators plus
// the given runID and stream writer. The TUI is wired through both the
// asker callback (RegistryConfig.Asker) and the TUIEmitter interface.
func (a *App) NewLoop(runID string, streamWriter io.Writer) *agent.Loop {
	return a.NewLoopWithDefaults(runID, streamWriter, "", "")
}

// NewLoopWithDefaults is NewLoop plus the ability to inject chat-
// session defaults (typically from `pilot chat --inventory/--limit`).
// These are wired into the tool registry so run_ansible will fill
// them in when the model omits the corresponding argument.
func (a *App) BuildRegistry(defaultInventory, defaultLimit string) *tools.Registry {
	cfgForTools := tools.RegistryConfig{
		DefaultInventory: defaultInventory,
		DefaultLimit:     defaultLimit,
		Env:              a.Env,
		SandboxMode:      sandbox.ParseOrDefault(a.Cfg.Sandbox.Mode),
	}
	if a.TUI != nil {
		cfgForTools.Asker = func(q string, opts []string) string {
			return a.TUI.AskUser(q, opts)
		}
	}
	if len(a.Cfg.AllowedReadPaths) > 0 {
		cfgForTools.AllowedReadPaths = a.Cfg.AllowedReadPaths
	} else {
		cfgForTools.AllowedReadPaths = append([]string{}, tools.AllowedCatPaths...)
		if cwd, err := os.Getwd(); err == nil {
			cfgForTools.AllowedReadPaths = append(cfgForTools.AllowedReadPaths, cwd+"/")
		}
		if _, err := os.Stat("./examples"); err == nil {
			cfgForTools.AllowedReadPaths = append(cfgForTools.AllowedReadPaths, "./examples/")
		}
	}
	if len(a.Cfg.AllowedPlaybookRoots) > 0 {
		cfgForTools.AllowedPlaybookRoots = a.Cfg.AllowedPlaybookRoots
	} else {
		cfgForTools.AllowedPlaybookRoots = []string{
			filepath.Join(a.Cfg.DataDir, "playbooks"),
			"./playbooks",
		}
		if cwd, err := os.Getwd(); err == nil {
			cfgForTools.AllowedPlaybookRoots = append(cfgForTools.AllowedPlaybookRoots, cwd)
		}
		if _, err := os.Stat("./examples"); err == nil {
			cfgForTools.AllowedPlaybookRoots = append(cfgForTools.AllowedPlaybookRoots, "./examples")
		}
	}
	cfgForTools.AllowedCommands = mapAllowedCommands(a.Cfg.AllowedCommands)

	var modIdx *docs.ModuleIndex
	blevePath := filepath.Join(a.Cfg.DataDir, "docs.bleve")
	if _, err := os.Stat(blevePath); err == nil {
		modIdx = docs.NewModuleIndex(blevePath)
		if err := modIdx.Open(); err != nil {
			modIdx = nil
		}
	}
	var pbIdx *docs.Index
	pbIndexPath := docs.PathFor(a.Cfg.DataDir, docs.SourcePlaybook)
	if _, err := os.Stat(pbIndexPath); err == nil {
		pbIdx = docs.NewIndex()
		_ = pbIdx.Load(pbIndexPath)
	}
	cachedEmb := NewCachedEmbedder(a.Ollama, a.Store)

	return tools.DefaultRegistryWithConfig(
		a.Ollama, a.Runner,
		filepath.Join(a.Cfg.DataDir, "generated-playbooks"),
		a.Cfg.SystemPrompt,
		modIdx, pbIdx, cachedEmb,
		cfgForTools,
	)
}

func (a *App) NewLoopWithDefaults(runID string, streamWriter io.Writer, defaultInventory, defaultLimit string) *agent.Loop {
	// Reuse the registry built in app.New whenever possible. The previous
	// behaviour called BuildRegistry on every NewLoop, which re-opens the
	// 100 MB bleve index from scratch — a 30+ second stall per call
	// that made `pilot run` feel like it was hanging between "Starting
	// run" and the first LLM proposal.
	//
	// We still rebuild the registry if the caller passed chat-session
	// defaults (inventory / limit) that differ from what the cached
	// registry was built with. For pilot run (no chat defaults), this
	// is a no-op and NewLoop is O(1).
	registry := a.Tools
	if defaultInventory != "" || defaultLimit != "" {
		registry = a.BuildRegistry(defaultInventory, defaultLimit)
	}

	var tuiEmitter agent.TUIEmitter
	if a.TUI != nil {
		tuiEmitter = a.TUI
	}
	if streamWriter == nil {
		streamWriter = os.Stderr
	}
	return agent.NewLoop(agent.Config{
		RunID:        runID,
		DataDir:      a.Cfg.DataDir,
		Ollama:       a.Ollama,
		Tools:        registry,
		Store:        a.Store,
		Sanitizer:    a.Sanitizer,
		Approver:     a.Approver,
		Stream:       true,
		MaxIter:      a.Cfg.MaxIter,
		SystemPrompt: a.Cfg.SystemPrompt,
		StreamWriter: streamWriter,
		TUI:          tuiEmitter,
		Runner:       a.Runner,
		Env:          a.Env,
		AllowDisposableApply: a.Cfg.AllowDisposableApply,
	})
}

// defaultRegistry builds the conservative-default registry used by
// the CLI. It mirrors what the previous setupRun/newAgentLoop pair
// built; tests that need different behaviour should pass opt.Registry.
func defaultRegistry(cfg *config.Config, tp *tui.Program, oc *ollama.Client, runner *ansible.Runner, st *store.Store, env sandbox.Environment) *tools.Registry {
	regCfg := tools.RegistryConfig{Store: st, Env: env, SandboxMode: sandbox.ParseOrDefault(cfg.Sandbox.Mode)}
	if len(cfg.AllowedReadPaths) > 0 {
		regCfg.AllowedReadPaths = cfg.AllowedReadPaths
	} else {
		regCfg.AllowedReadPaths = append([]string{}, tools.AllowedCatPaths...)
		if cwd, err := os.Getwd(); err == nil {
			regCfg.AllowedReadPaths = append(regCfg.AllowedReadPaths, cwd+"/")
		}
		if _, err := os.Stat("./examples"); err == nil {
			regCfg.AllowedReadPaths = append(regCfg.AllowedReadPaths, "./examples/")
		}
	}
	if len(cfg.AllowedPlaybookRoots) > 0 {
		regCfg.AllowedPlaybookRoots = cfg.AllowedPlaybookRoots
	} else {
		regCfg.AllowedPlaybookRoots = []string{
			filepath.Join(cfg.DataDir, "playbooks"),
			"./playbooks",
		}
		if cwd, err := os.Getwd(); err == nil {
			regCfg.AllowedPlaybookRoots = append(regCfg.AllowedPlaybookRoots, cwd)
		}
		if _, err := os.Stat("./examples"); err == nil {
			regCfg.AllowedPlaybookRoots = append(regCfg.AllowedPlaybookRoots, "./examples")
		}
	}
	regCfg.AllowedCommands = mapAllowedCommands(cfg.AllowedCommands)

	if tp != nil {
		regCfg.Asker = func(q string, opts []string) string {
			return tp.AskUser(q, opts)
		}
	}

	var modIdx *docs.ModuleIndex
	blevePath := filepath.Join(cfg.DataDir, "docs.bleve")
	if _, err := os.Stat(blevePath); err == nil {
		modIdx = docs.NewModuleIndex(blevePath)
		if err := modIdx.Open(); err != nil {
			modIdx = nil
		}
	}
	var pbIdx *docs.Index
	pbIndexPath := docs.PathFor(cfg.DataDir, docs.SourcePlaybook)
	if _, err := os.Stat(pbIndexPath); err == nil {
		pbIdx = docs.NewIndex()
		_ = pbIdx.Load(pbIndexPath)
	}
	cachedEmb := NewCachedEmbedder(oc, st)

	return tools.DefaultRegistryWithConfig(
		oc, runner,
		filepath.Join(cfg.DataDir, "generated-playbooks"),
		cfg.SystemPrompt,
		modIdx, pbIdx, cachedEmb,
		regCfg,
	)
}

