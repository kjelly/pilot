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
	rootCmd.AddCommand(specCmd)
}

func runSpec(cmd *cobra.Command, args []string) error {
	specPath := args[0]
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
	if specGenerateOut != "" {
		action = "generate"
	}
	if specApply {
		action = "apply"
	}

	switch action {
	case "summary":
		fmt.Printf("spec %s: %d rows\n", parsed.Title, len(parsed.Rows))
		fmt.Println("Use --lint / --generate / --apply to take action.")
		return nil
	}

	pb, err := spec.Generate(parsed, spec.GenerateOptions{IncludeRaw: true})
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}

	outPath := specGenerateOut
	if outPath == "" {
		outPath = filepath.Join("playbooks", "generated", strings.TrimSuffix(filepath.Base(specPath), filepath.Ext(specPath))+".yml")
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
