package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/spec"
	"github.com/anomalyco/pilot/internal/store"
	"github.com/anomalyco/pilot/internal/tools"
)

var (
	verifyInventory   string
	verifyLimit       string
	verifyHost        string
	verifyLocal       bool
	verifyProposalID  string
	verifyReportDir   string
	verifyTimeoutSec  int
)

var verifyCmd = &cobra.Command{
	Use:   "verify <spec.md>",
	Short: "Run each row of a verification spec against the inventory and emit a report",
	Long: `pilot verify closes the spec → apply loop.

It reads the spec markdown, executes every row's command (locally by default
or against the inventory via ansible ad-hoc), and writes:

  - .verification/<spec-stem>-<UTC-timestamp>.ndjson  raw NDJSON
  - .verification/<spec-stem>-<UTC-timestamp>.md      rendered PASS/FAIL report
  - spec_checkpoints                                  status flipped to verified-pass / verified-fail
  - proposal_results (when --proposal-id is set)      per-check row

Use --local for the smoke-test case where the spec tests the host pilot
itself is running on. Use --inventory + --limit for fleet verification.
`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVarP(&verifyInventory, "inventory", "i", "", "inventory file (run each row via ansible ad-hoc)")
	verifyCmd.Flags().StringVarP(&verifyLimit, "limit", "l", "", "limit pattern (forwarded to ansible)")
	verifyCmd.Flags().StringVar(&verifyHost, "host", "", "override target host (default: 'all')")
	// Default false: when an --inventory is supplied we run each row via
	// ansible ad-hoc against the fleet; with no inventory the tool falls
	// back to local automatically (see VerifySpecTool.runRow). Defaulting
	// to true silently ignored -i and made fleet verification unreachable.
	verifyCmd.Flags().BoolVar(&verifyLocal, "local", false, "force-run commands on the control node, even if --inventory is set")
	verifyCmd.Flags().StringVar(&verifyProposalID, "proposal-id", "", "record results against this proposal in proposal_results")
	verifyCmd.Flags().StringVar(&verifyReportDir, "report-dir", ".verification", "where to write NDJSON + markdown reports")
	verifyCmd.Flags().IntVar(&verifyTimeoutSec, "timeout", 15, "per-row command timeout (seconds)")
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	specPath := args[0]

	parsed, err := spec.Parse(specPath)
	if err != nil {
		return fmt.Errorf("parse spec: %w", err)
	}
	if findings := spec.Lint(parsed); spec.HasErrors(findings) {
		return fmt.Errorf("spec has errors; fix them before verify")
	}

	ctx := context.Background()
	tool := &tools.VerifySpecTool{
		Inventory:  verifyInventory,
		Limit:      verifyLimit,
		LocalOnly:  verifyLocal,
		Host:       verifyHost,
		ProposalID: verifyProposalID,
	}
	res, err := tool.Execute(ctx, mustJSONVerify(map[string]any{
		"spec_path":   specPath,
		"host":        verifyHost,
		"timeout_sec": verifyTimeoutSec,
	}))
	if err != nil {
		return err
	}
	if res.IsError {
		return fmt.Errorf("verify_spec: %s", res.Content)
	}
	rows, err := tools.ReadNDJSON(res.Content)
	if err != nil {
		return fmt.Errorf("read NDJSON: %w", err)
	}

	// Render the report and write to disk.
	ts := time.Now().UTC().Format("20060102-150405")
	stem := strings.TrimSuffix(filepath.Base(specPath), filepath.Ext(specPath))
	if err := os.MkdirAll(verifyReportDir, 0o755); err != nil {
		return fmt.Errorf("mkdir report-dir: %w", err)
	}
	ndPath := filepath.Join(verifyReportDir, fmt.Sprintf("%s-%s.ndjson", stem, ts))
	mdPath := filepath.Join(verifyReportDir, fmt.Sprintf("%s-%s.md", stem, ts))
	if err := os.WriteFile(ndPath, []byte(res.Content), 0o644); err != nil {
		return fmt.Errorf("write NDJSON: %w", err)
	}
	md := renderVerifyReport(parsed, rows)
	if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
		return fmt.Errorf("write markdown: %w", err)
	}
	fmt.Printf("✔ NDJSON:   %s\n✔ Report:   %s\n", ndPath, mdPath)

	// Flip spec_checkpoints and optionally insert proposal_results.
	if st, err := openSpecStore(); err == nil {
		defer st.Close()
		for _, vr := range rows {
			stMap := "verified-fail"
			if vr.Status == "pass" {
				stMap = "verified-pass"
			}
			if vr.Status == "skip" {
				continue
			}
			cp := &store.Checkpoint{
				SpecPath:     relOrAbs(specPath),
				RowID:        vr.ID,
				RunID:        "verify-" + ts,
				Status:       stMap,
				VerifyDetail: vr.Detail,
			}
			_ = st.UpsertCheckpoint(cp)
			if verifyProposalID != "" {
				_ = st.RecordProposalResult(&store.ProposalResult{
					ProposalID: verifyProposalID,
					CheckID:    vr.ID,
					Host:       vr.Host,
					Status:     vr.Status,
					Detail:     vr.Detail,
				})
			}
		}
	}

	// Verdict line.
	pass, fail, skip := 0, 0, 0
	for _, r := range rows {
		switch r.Status {
		case "pass":
			pass++
		case "fail":
			fail++
		case "skip":
			skip++
		}
	}
	verdict := "PASS"
	if fail > 0 {
		verdict = "FAIL"
	}
	fmt.Printf("\nverdict: **%s**  (pass=%d fail=%d skip=%d)\n", verdict, pass, fail, skip)
	if fail > 0 {
		return fmt.Errorf("verification failed: %d rows", fail)
	}
	return nil
}

// renderVerifyReport produces the markdown summary used for both
// human reading and `diff` against previous baselines. The format
// matches what scripts/render-report.py emits so existing diff
// tooling keeps working.
func renderVerifyReport(s *spec.Spec, rows []tools.VerifyRow) string {
	pass, fail, skip := 0, 0, 0
	for _, r := range rows {
		switch r.Status {
		case "pass":
			pass++
		case "fail":
			fail++
		case "skip":
			skip++
		}
	}
	verdict := "PASS"
	if fail > 0 {
		verdict = "FAIL"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Verification Report — %s\n\n", s.Title)
	fmt.Fprintf(&sb, "- generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&sb, "- spec:      %s\n", s.Path)
	fmt.Fprintf(&sb, "- total:     %d  pass: %d  fail: %d  skip: %d\n", len(rows), pass, fail, skip)
	fmt.Fprintf(&sb, "- verdict:   **%s**\n\n", verdict)
	fmt.Fprintf(&sb, "| ID | Status | Detail |\n|----|--------|--------|\n")
	// Failures first (matches render-report.py).
	var fails []tools.VerifyRow
	var rest []tools.VerifyRow
	for _, r := range rows {
		if r.Status == "fail" {
			fails = append(fails, r)
		} else {
			rest = append(rest, r)
		}
	}
	for _, r := range fails {
		fmt.Fprintf(&sb, "| %s | %s | %s |\n", r.ID, r.Status, r.Detail)
	}
	for _, r := range rest {
		fmt.Fprintf(&sb, "| %s | %s | %s |\n", r.ID, r.Status, r.Detail)
	}
	return sb.String()
}

// mustJSONVerify is a tiny local helper that JSON-encodes v. We use
// it because Execute() takes json.RawMessage and the verify loop is
// easier to read with a map literal than nested RawMessage calls.
func mustJSONVerify(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mustJSONVerify: %v", err))
	}
	return b
}
