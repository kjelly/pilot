package tools

import (
	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/docs"
	"github.com/anomalyco/pilot/internal/ollama"
	"github.com/anomalyco/pilot/internal/sandbox"
	"github.com/anomalyco/pilot/internal/store"
)

// AllowedCatPaths is the default set of prefixes that `cat` is
// permitted to read inside run_command. It mirrors read_file's
// DefaultAllowedReadPrefixes so the two tools stay consistent.
var AllowedCatPaths = append([]string{}, DefaultAllowedReadPrefixes...)

// DefaultRegistry returns a registry pre-populated with the standard tool set.
// Pass nil for any dependency you don't want enabled — the corresponding tool
// will still register but will return an error when invoked.
func DefaultRegistry(ollamaClient *ollama.Client, runner *ansible.Runner, generatedDir, systemPrompt string) *Registry {
	return DefaultRegistryWithDocs(ollamaClient, runner, generatedDir, systemPrompt, nil, nil, nil)
}

// DefaultRegistryWithDocs is like DefaultRegistry but additionally
// registers a search_docs tool backed by the given module index,
// playbook index, and playbook embedder. Any may be nil; the tool will
// then return a helpful error for the side that wasn't built.
func DefaultRegistryWithDocs(
	ollamaClient *ollama.Client,
	runner *ansible.Runner,
	generatedDir, systemPrompt string,
	modIdx *docs.ModuleIndex,
	pbIdx *docs.Index,
	pbEmb docs.Embedder,
) *Registry {
	return DefaultRegistryWithConfig(ollamaClient, runner, generatedDir, systemPrompt, modIdx, pbIdx, pbEmb, RegistryConfig{})
}

// RegistryConfig allows callers to override default per-tool policies
// (e.g. tighten the read_file prefix list to a project directory or
// broaden the run_ansible allow-list of playbook roots).
type RegistryConfig struct {
	// ReadFile overrides the read_file tool's AllowedPrefixes / BaseDir.
	ReadFile *ReadFileTool
	// AllowedReadPaths restricts what `cat` may read inside run_command.
	// If empty, AllowedCatPaths is used.
	AllowedReadPaths []string
	// AllowedPlaybookRoots restricts run_ansible to playbooks/inventories
	// under these directories. If empty, the caller must opt in via the
	// setup sites; without any roots, run_ansible fails closed.
	AllowedPlaybookRoots []string
	// AllowedCommands is a list of dynamic commands whitelisted from the config.
	AllowedCommands []CmdSpec
	// Asker is the callback used by ask_user. If nil, the tool falls
	// back to reading from os.Stdin. Per-instance injection — there
	// is no process-global state.
	Asker Asker
	// Store is used by summarize_run to read the audit trail. If nil,
	// summarize_run reports an error when invoked.
	Store *store.Store
	// DefaultInventory, when non-empty, is used as the inventory
	// path for run_ansible calls when the model doesn't pass one
	// (typical for `pilot chat --inventory <path>`). The path still
	// must be inside AllowedPlaybookRoots.
	DefaultInventory string
	// DefaultLimit, when non-empty, is used as the --limit host
	// pattern for run_ansible calls when the model doesn't pass one
	// (typical for `pilot chat --limit <pattern>`).
	DefaultLimit string
	// Env is the execution environment tools target. When nil,
	// tools fall back to local exec / local file I/O. Set by
	// app.New from cfg.Sandbox + CLI flags.
	Env sandbox.Environment
	// SandboxMode mirrors cfg.Sandbox.Mode parsed via
	// sandbox.ParseSandboxMode. SandboxModeUnset and
	// SandboxModeDocker use the legacy host-side ansible + docker
	// connection plugin path. SandboxModeDockerExec routes
	// run_ansible through `docker exec` so the container runs
	// ansible-playbook itself; host needs no docker-py /
	// community.docker.
	SandboxMode sandbox.SandboxMode
}

// DefaultRegistryWithConfig is the most flexible constructor; it
// applies any RegistryConfig overrides the caller provides.
func DefaultRegistryWithConfig(
	ollamaClient *ollama.Client,
	runner *ansible.Runner,
	generatedDir, systemPrompt string,
	modIdx *docs.ModuleIndex,
	pbIdx *docs.Index,
	pbEmb docs.Embedder,
	cfg RegistryConfig,
) *Registry {
	r := NewRegistry()

	// read_file
	{
		t := cfg.ReadFile
		if t == nil {
			t = &ReadFileTool{}
		}
		if len(cfg.AllowedReadPaths) > 0 {
			t.AllowedPrefixes = cfg.AllowedReadPaths
		}
		t.Env = cfg.Env
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}

	// run_command
	{
		cats := cfg.AllowedReadPaths
		if len(cats) == 0 {
			cats = AllowedCatPaths
		}
		t := &RunCommandTool{
			AllowedReadPaths: cats,
			AllowedCommands:  cfg.AllowedCommands,
			Env:              cfg.Env,
		}
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}

	// run_ansible
	{
		t := &RunPlaybookTool{
			Runner:               runner,
			AllowedPlaybookRoots: cfg.AllowedPlaybookRoots,
			DefaultInventory:     cfg.DefaultInventory,
			DefaultLimit:         cfg.DefaultLimit,
			Env:                  cfg.Env,
			SandboxMode:          cfg.SandboxMode, // already sandbox.SandboxMode
		}
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}

	// gather_facts
	{
		t := &GatherFactsTool{
			Runner:               runner,
			AllowedPlaybookRoots: cfg.AllowedPlaybookRoots,
			DefaultInventory:     cfg.DefaultInventory,
			DefaultLimit:         cfg.DefaultLimit,
			Env:                  cfg.Env,
		}
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}

	// generate_playbook (requires ollama)
	if ollamaClient != nil {
		t := &GeneratePlaybookTool{
			Ollama:       ollamaClient,
			GeneratedDir: generatedDir,
			SystemPrompt: systemPrompt,
			ModuleIndex:  modIdx,
		}
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}
	// generate_rollback (requires ollama)
	if ollamaClient != nil {
		t2 := &GenerateRollbackTool{
			Ollama:       ollamaClient,
			GeneratedDir: generatedDir + "-rollback",
			SystemPrompt: systemPrompt,
			ModuleIndex:  modIdx,
		}
		spec := t2.Spec()
		spec.Execute = t2.Execute
		r.MustRegister(spec)
	}

	// vault_encrypt_string
	{
		t := &VaultEncryptStringTool{
			AllowedPlaybookRoots: cfg.AllowedPlaybookRoots,
			Asker:                cfg.Asker,
		}
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}

	// ask_user
	{
		t := &AskUserTool{Asker: cfg.Asker}
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}

	// run_inspec
	{
		t := &RunInSpecTool{Env: cfg.Env}
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}
	// plan_operations (requires store)
	{
		t3 := &PlanOperationsTool{Store: nil}
		spec := t3.Spec()
		spec.Execute = t3.Execute
		r.MustRegister(spec)
	}

	// search_docs
	{
		t := NewSearchDocsTool(modIdx, pbIdx, pbEmb)
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}

	// discover — first-turn guidance for vague user goals
	{
		t := &DiscoverTool{ModuleIndex: modIdx}
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}

	// summarize_run — structured end-of-run report
	{
		t := &SummarizeRunTool{Store: cfg.Store}
		spec := t.Spec()
		spec.Execute = t.Execute
		r.MustRegister(spec)
	}
	return r
}
