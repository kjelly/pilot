package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/app"
	"github.com/anomalyco/pilot/internal/spec"
	"github.com/anomalyco/pilot/internal/store"
)

var (
	specLintOnly    bool
	specGenerateOut string
	specApply       bool
	specInventory   string
	specLimit       string
	specRunIDFlag   string
	specHosts        string
	specConnection   string
	specToInv        string
	specFromSSH      bool
	specRoot         string
)

var specCmd = &cobra.Command{
	Use:   "spec <spec.md> [--lint | --generate | --apply | --status]",
	Short: "Compile and manage verification specs (docs/verification/*.md)",
	Long: `pilot spec is the entry point for the "write spec → generate playbook → apply → verify" loop.

A spec is a markdown checklist (see docs/verification-spec-template.md). Each row pairs
a requirement ID with a single-line shell command and an expected value.

Actions (selected by flag):

  --lint      Parse and lint the spec. Exit 1 on any error finding.
  --generate  Produce a hand-written-style Ansible playbook (one task per spec row, deduped)
              and write it to disk. Spec rows are recorded in spec_checkpoints as 'compiled'.
  --apply     Generate the playbook, then run it via ansible-playbook against --inventory/-i.
  --status    Print coverage: how many spec rows are compiled / applied / verified.

Traceability chain:
  spec row → spec.Generator (task + ParamHash) → run_ansible invocation →
  proposal (with .SpecID + .RowID) → spec_checkpoints row →
  verify_spec run → proposal_results (status pass/fail per check).
`,
	Args: cobra.ExactArgs(1),
	RunE: runSpec,
}

func init() {
	specCmd.Flags().BoolVar(&specLintOnly, "lint", false, "only lint the spec (do not generate)")
	specCmd.Flags().StringVar(&specGenerateOut, "generate", "", "generate a playbook to the given path")
	specCmd.Flags().BoolVar(&specApply, "apply", false, "after generating, run ansible-playbook against --inventory")
	specCmd.Flags().StringVarP(&specInventory, "inventory", "i", "", "inventory file (used with --apply)")
	specCmd.Flags().StringVarP(&specLimit, "limit", "l", "", "limit pattern (forwarded to ansible-playbook)")
	specCmd.Flags().StringVar(&specRunIDFlag, "run-id", "", "pilot run id to record against (default: derived from spec path)")
	specCmd.Flags().StringVar(&specHosts, "hosts", "", "override play hosts (default: localhost). Use with --apply/-i to target real hosts.")
	specCmd.Flags().StringVar(&specConnection, "connection", "", "override play connection (default: local). Use a real SSH-style value to disable local connection.")
	specCmd.Flags().StringVar(&specRoot, "root", "", "project root (where docs/ and playbooks/ live). Default: $PILOT_ROOT or current working directory. Lets specs and generated playbooks live outside this tool repo.")
	specCmd.Flags().StringVar(&specToInv, "to-inventory", "", "render a Targets table to an ansible inventory file at the given path")
	specCmd.Flags().BoolVar(&specFromSSH, "from-ssh-config", false, "use ~/.ssh/config to fill missing host fields before generating the inventory")
	rootCmd.AddCommand(specCmd)
}

func runSpec(cmd *cobra.Command, args []string) error {
	specPath := args[0]
	if !filepath.IsAbs(specPath) && specRoot != "" {
		specPath = filepath.Join(specRoot, specPath)
	}
	parsed, err := spec.Parse(specPath)
	if err != nil {
		return fmt.Errorf("parse spec: %w", err)
	}

	findings := spec.Lint(parsed)
	for _, f := range findings {
		fmt.Fprintln(os.Stderr, f.String())
	}
	if spec.HasErrors(findings) {
		return fmt.Errorf("spec has errors; fix them before --generate")
	}

	if specLintOnly {
		fmt.Printf("spec %s: %d rows, %d findings (%d errors)\n",
			parsed.Title, len(parsed.Rows), len(findings),
			countBySeverity(findings, spec.SeverityError))
		return nil
	}

	// Default action: short summary.
	action := "summary"
	if specToInv != "" {
		action = "to-inventory"
	}
	if specGenerateOut != "" {
		action = "generate"
	}
	if specApply {
		action = "apply"
	}

	switch action {
	case "to-inventory":
		return emitSpecInventory(cmd, parsed, specToInv, specFromSSH)
	case "summary":
		fmt.Printf("spec %s: %d rows\n", parsed.Title, len(parsed.Rows))
		fmt.Println("Use --lint / --generate / --apply to take action.")
		return nil
	}

	pb, err := spec.Generate(parsed, spec.GenerateOptions{
		IncludeRaw: true,
		Hosts:      specHosts,
		Connection: specConnection,
	})
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}

	outPath := specGenerateOut
	if outPath == "" {
		root, err := resolveSpecRoot()
		if err != nil {
			return err
		}
		outPath = filepath.Join(root, "playbooks", "generated", strings.TrimSuffix(filepath.Base(specPath), filepath.Ext(specPath))+".yml")
	}
	if !filepath.IsAbs(outPath) {
		root, err := resolveSpecRoot()
		if err != nil {
			return err
		}
		outPath = filepath.Join(root, outPath)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(outPath, []byte(pb.RenderYAML()), 0o644); err != nil {
		return fmt.Errorf("write playbook: %w", err)
	}
	fmt.Printf("✔ generated playbook: %s (%d tasks, %d rows → %d deduped)\n",
		outPath, len(pb.Tasks), len(parsed.Rows), len(parsed.Rows)-len(pb.Tasks))

	// Record compiled checkpoints.
	runID := specRunIDFlag
	if runID == "" {
		runID = "spec-" + strings.TrimSuffix(filepath.Base(specPath), filepath.Ext(specPath))
	}
	if st, openErr := openSpecStore(); openErr == nil {
		defer st.Close()
		for _, row := range parsed.Rows {
			for _, taskIdx := range pb.MapIDToTask[row.ID] {
				t := pb.Tasks[taskIdx]
				cp := &store.Checkpoint{
					SpecPath:  relOrAbs(specPath),
					RowID:     row.ID,
					RunID:     runID,
					TaskIndex: taskIdx,
					Module:    t.Module,
					ParamHash: paramHash(t),
					Status:    "compiled",
				}
				_ = st.UpsertCheckpoint(cp)
			}
		}
		fmt.Printf("✔ recorded %d checkpoints (run_id=%s)\n", len(parsed.Rows), runID)
	}

	if specApply {
		return runApplyGenerated(outPath, specInventory, specLimit)
	}
	return nil
}

func runApplyGenerated(playbook, inventory, limit string) error {
	if inventory == "" {
		return fmt.Errorf("--apply requires --inventory/-i")
	}
	ctx := context.Background()
	res, err := setupRunWithOpts(ctx, app.Options{NoTUI: true, Banner: false})
	if err != nil {
		return err
	}
	defer res.Store.Close()
	defer shutdownTUI(res.TUI)

	args := []string{playbook, "-i", inventory}
	if limit != "" {
		args = append(args, "-l", limit)
	}
	result, err := res.Runner.Run(ctx, args...)
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	fmt.Println(result.Stdout)
	if result.ExitCode != 0 {
		fmt.Fprintf(os.Stderr, "apply failed (exit=%d):\n%s\n", result.ExitCode, result.Stderr)
		return fmt.Errorf("apply exit=%d", result.ExitCode)
	}
	return nil
}

func openSpecStore() (*store.Store, error) {
	dataDir := os.Getenv("PILOT_DATA_DIR")
	if dataDir == "" {
		home, _ := os.UserHomeDir()
		dataDir = filepath.Join(home, ".local", "share", "pilot")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dataDir, "history.db"))
}

func countBySeverity(fs []spec.Finding, sev spec.Severity) int {
	n := 0
	for _, f := range fs {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func relOrAbs(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func paramHash(t spec.Task) string {
	h := sha256.Sum256([]byte(t.Module + "\x00" + t.Params))
	return hex.EncodeToString(h[:])
}

// pilot spec --status <spec.md>: print coverage
var specStatusCmd = &cobra.Command{
	Use:   "status <spec.md>",
	Short: "Print coverage of compiled/applied/verified rows for a spec",
	Args:  cobra.ExactArgs(1),
	RunE:  runSpecStatus,
}

func init() {
	specCmd.AddCommand(specStatusCmd)
}

func runSpecStatus(cmd *cobra.Command, args []string) error {
	specPath := args[0]
	if !filepath.IsAbs(specPath) && specRoot != "" {
		specPath = filepath.Join(specRoot, specPath)
	}
	st, err := openSpecStore()
	if err != nil {
		return err
	}
	defer st.Close()
	cps, err := st.ListCheckpoints(relOrAbs(specPath))
	if err != nil {
		return err
	}
	if len(cps) == 0 {
		fmt.Printf("spec %s: no checkpoints recorded yet — run `pilot spec %s --generate` first\n", specPath, specPath)
		return nil
	}
	cov := spec.CoverageFor(relOrAbs(specPath), toSpecCheckpoints(cps))
	fmt.Println(cov.String())

	// Per-row breakdown.
	fmt.Println()
	fmt.Println("| Row | Status | Module | Detail |")
	fmt.Println("|-----|--------|--------|--------|")
	for _, cp := range cps {
		fmt.Printf("| %s | %s | %s | %s |\n", cp.RowID, cp.Status, cp.Module, cp.VerifyDetail)
	}
	return nil
}

func toSpecCheckpoints(in []*store.Checkpoint) []spec.Checkpoint {
	out := make([]spec.Checkpoint, len(in))
	for i, cp := range in {
		out[i] = spec.Checkpoint{
			SpecPath:     cp.SpecPath,
			RowID:        cp.RowID,
			RunID:        cp.RunID,
			ProposalID:   cp.ProposalID,
			TaskIndex:    cp.TaskIndex,
			Module:       cp.Module,
			ParamHash:    cp.ParamHash,
			Status:       cp.Status,
			VerifyDetail: cp.VerifyDetail,
		}
	}
	return out
}

// emitSpecInventory renders a Spec's Targets table (or whatever
// InventoryFromSSHConfig fills in) to an ansible inventory YAML
// at `out`. It is the bridge between the spec — the human-edited
// source of truth — and the inventory — the runtime artifact the
// runner consumes.
//
// The function is also where `pilot spec --apply -i …` could
// eventually skip the user's `inventory.yaml` entirely: if a
// spec author wrote a Targets table, `--to-inventory` here
// replaces the manual `cat > inventory.yaml` ritual we used in
// the v1 pam-oidc-sshd run.
func emitSpecInventory(cmd *cobra.Command, parsed *spec.Spec, out string, fromSSH bool) error {
	if parsed == nil {
		return fmt.Errorf("spec: nil parsed")
	}
	if out == "" {
		return fmt.Errorf("--to-inventory requires an output path")
	}
	// If the spec has no Targets table AND fromSSH is set, we can
	// synthesize a single-host Hosts entry from the alias passed on
	// the CLI (via --inventory alias?). For now we just call out the
	// missing inputs — expanding this is left as a follow-up.
	if !parsed.HasTargets() && !fromSSH {
		return fmt.Errorf("spec %s has no Targets table; pass --from-ssh-config ALIAS "+
			"to synthesize from $HOME/.ssh/config",
			parsed.Title)
	}
	opts := spec.GenerateInventoryOptions{}
	// When fromSSH is set, augment any blank Address/User/IdentityFile
	// fields from the matching ~/.ssh/config block. The simplest MVP
	// applies the resolved-once config to every Host with a blank;
	// production-grade would let columns choose which alias to look up.
	if fromSSH {
		opts.SSHDefaults = map[string]string{}
		// We still let the spec's own values win — only fill blanks.
	}
	for i := range parsed.Hosts {
		if fromSSH {
			if h, _ := spec.InventoryFromSSHConfig(parsed.Hosts[i].Hostname); h != nil {
				if parsed.Hosts[i].Address == "" {
					parsed.Hosts[i].Address = h.Address
				}
				if parsed.Hosts[i].User == "" {
					parsed.Hosts[i].User = h.User
				}
				if parsed.Hosts[i].IdentityFile == "" {
					parsed.Hosts[i].IdentityFile = h.IdentityFile
				}
				if parsed.Hosts[i].Port == "" {
					parsed.Hosts[i].Port = h.Port
				}
			}
		}
	}
	rendered, err := parsed.GenerateInventory(opts)
	if err != nil {
		return err
	}
	if rendered == "" {
		return fmt.Errorf("spec %s has no inventory content to write", parsed.Title)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil && filepath.Dir(out) != "" {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(out), err)
	}
	if err := os.WriteFile(out, []byte(rendered), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Printf("✔ inventory written: %s (%d hosts from spec%s)\n",
		out, len(parsed.Hosts),
		ternary(fromSSH, " + ~/.ssh/config augmented", ""))
	return nil
}

func ternary(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

// resolveSpecRoot returns the absolute project root for spec/playbook
// paths. Resolution order:
//
//   1. --root flag (specRoot)
//   2. $PILOT_ROOT env var
//   3. current working directory
//
// Everything spec-relative (docs/verification/*.md sources,
// playbooks/generated/*.yml outputs) is laid out under this root so
// the tool repo can be a thin CLI sitting next to any number of
// sibling repos (or a single mono-repo layout).
func resolveSpecRoot() (string, error) {
	root := specRoot
	if root == "" {
		root = os.Getenv("PILOT_ROOT")
	}
	if root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve cwd: %w", err)
		}
		root = cwd
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolveSpecRoot: %w", err)
	}
	return abs, nil
}
