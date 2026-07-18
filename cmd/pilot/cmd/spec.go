package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/spec"
	"github.com/anomalyco/pilot/internal/store"
)

var (
	specLintOnly    bool
	specGenerateOut string
	specRunIDFlag   string
	specHosts       string
	specConnection  string
	specRoot        string
)

var specCmd = &cobra.Command{
	Use:   "spec <spec.md> [--lint | --generate | --status]",
	Short: "Compile and manage verification specs (docs/verification/*.md)",
	Long: `pilot spec is the entry point for the "write spec → apply → verify" loop.

A spec is a markdown checklist (see docs/verification-spec-template.md). Each row pairs
a requirement ID with a single-line shell command and an expected value.

Actions (selected by flag):

  --lint      Parse and lint the spec. Exit 1 on any error finding.
  --generate  Produce a hand-written-style Ansible playbook (one task per spec row, deduped)
              and write it to disk. Spec rows are recorded in spec_checkpoints as 'compiled'.
  --status    Print coverage: how many spec rows are compiled / applied / verified.

Deprecated 2026-07-17: --apply (running the generated playbook — apply goes through
the hand-written playbooks/apply/*.yml instead) and --to-inventory (superseded by
"pilot inventory generate").

Traceability chain:
  spec row → apply task (tagged with the row ID, playbooks/apply/*.yml) →
  "pilot verify" run → spec_checkpoints row (verified-pass / verified-fail)
  + .verification/ report.
`,
	Args: cobra.ExactArgs(1),
	RunE: runSpec,
}

func init() {
	specCmd.Flags().BoolVar(&specLintOnly, "lint", false, "only lint the spec (do not generate)")
	specCmd.Flags().StringVar(&specGenerateOut, "generate", "", "generate a playbook to the given path")
	specCmd.Flags().StringVar(&specRunIDFlag, "run-id", "", "pilot run id to record against (default: derived from spec path)")
	specCmd.Flags().StringVar(&specHosts, "hosts", "", "override play hosts (default: localhost)")
	specCmd.Flags().StringVar(&specConnection, "connection", "", "override play connection (default: local). Use a real SSH-style value to disable local connection.")
	specCmd.Flags().StringVar(&specRoot, "root", "", "project root (where docs/ and playbooks/ live). Default: $PILOT_ROOT or current working directory. Lets specs and generated playbooks live outside this tool repo.")
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

	if specGenerateOut == "" {
		fmt.Printf("spec %s: %d rows\n", parsed.Title, len(parsed.Rows))
		fmt.Println("Use --lint / --generate to take action.")
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
	if err := checkGenerateOutPath(outPath, specPath); err != nil {
		return err
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

	return nil
}

// checkGenerateOutPath rejects --generate targets inside playbooks/verify/.
// That directory is deprecated (2026-07-17): its committed artifacts never
// actually asserted the spec's Expected values while carrying the name of an
// acceptance artifact — see playbooks/verify/README.md. Acceptance runs
// `pilot verify <spec.md>`; ad-hoc generated playbooks belong in the
// gitignored playbooks/generated/ (the no-path default).
func checkGenerateOutPath(outPath, specPath string) error {
	p := filepath.ToSlash(outPath)
	if strings.Contains(p, "/playbooks/verify/") || strings.HasPrefix(p, "playbooks/verify/") {
		return fmt.Errorf("playbooks/verify/ is deprecated (2026-07-17, see playbooks/verify/README.md): run `pilot verify %s` for acceptance, or --generate into playbooks/generated/ (gitignored)", specPath)
	}
	return nil
}

func openSpecStore() (*store.Store, error) {
	dataDir := os.Getenv("PILOT_DATA_DIR")
	if dataDir == "" {
		home, _ := os.UserHomeDir()
		dataDir = filepath.Join(home, ".local", "share", "pilot")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "history.db")
	st, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = st.Close()
		return nil, err
	}
	return st, nil
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

// resolveSpecRoot returns the absolute project root for spec/playbook
// paths. Resolution order:
//
//  1. --root flag (specRoot)
//  2. $PILOT_ROOT env var
//  3. current working directory
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
