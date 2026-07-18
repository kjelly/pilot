package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/spec"
	"github.com/anomalyco/pilot/internal/store"
	"github.com/anomalyco/pilot/internal/tools"
)

var (
	verifyInventory  string
	verifyLimit      string
	verifyHost       string
	verifyLocal      bool
	verifyReportDir  string
	verifyTimeoutSec int
	verifyRoot       string
	verifyDir        string
	verifyProbe      string
	verifyProbeExp   string
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

Use --local for the smoke-test case where the spec tests the host pilot
itself is running on. Use --inventory + --limit for fleet verification.
`,
	// Allow either: positional <spec.md> (single-spec mode), or no
	// positional with --dir=<path> (multi-spec mode).
	Args: cobra.ArbitraryArgs,
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
	verifyCmd.Flags().StringVar(&verifyReportDir, "report-dir", ".verification", "where to write NDJSON + markdown reports")
	verifyCmd.Flags().IntVar(&verifyTimeoutSec, "timeout", 15, "per-row command timeout (seconds)")
	verifyCmd.Flags().StringVar(&verifyRoot, "root", "", "project root for spec/playbook layout (default: $PILOT_ROOT or cwd). Lets verify reuse --root from `pilot spec`.")
	verifyCmd.Flags().StringVar(&verifyDir, "dir", "", "verify every *.md under this directory in one shot; prints a rollup table at the end. Mutually exclusive with positional spec.md.")
	verifyCmd.Flags().StringVar(&verifyProbe, "probe", "", "author aid: run a SINGLE command through the exact verify pipeline (same module/become/ad-hoc as a spec row) and print rc + raw stdout + cleaned stdout + matcher verdict. Writes no report/store. Combine with --probe-expected to test a match.")
	verifyCmd.Flags().StringVar(&verifyProbeExp, "probe-expected", "", "expected value to test the --probe command against (same grammar as a spec Expected cell: int=rc, ~=contains, ^=regex).")
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	hasPositional := len(args) >= 1
	if verifyProbe != "" {
		if hasPositional || verifyDir != "" {
			return fmt.Errorf("--probe is standalone; do not combine it with a spec.md or --dir")
		}
		return runVerifyProbe(cmd)
	}
	if hasPositional && verifyDir != "" {
		return fmt.Errorf("positional spec.md and --dir are mutually exclusive; pass either one, not both")
	}
	if verifyDir != "" || !hasPositional {
		// Multi-spec mode: walk --dir for *.md, run each, print rollup table.
		dir := verifyDir
		if dir == "" {
			// default fallback: docs/verification under --root or cwd.
			root := verifyRoot
			if root == "" {
				root = os.Getenv("PILOT_ROOT")
			}
			if root == "" {
				root, _ = os.Getwd()
			}
			dir = filepath.Join(root, "docs", "verification")
		}
		return runVerifyMulti(cmd, dir)
	}
	return runVerifyOne(cmd, args[0])
}

// runVerifyOne runs a single spec to completion (existing behavior).
// Errors from the verifier are surfaced, but spec-level failures (rows
// that fail) exit 0 — the report itself records the verdict.
func runVerifyOne(cmd *cobra.Command, specPathArg string) error {
	specPath := specPathArg
	if !filepath.IsAbs(specPath) {
		root := verifyRoot
		if root == "" {
			root = os.Getenv("PILOT_ROOT")
		}
		if root == "" {
			root, _ = os.Getwd()
		}
		specPath = filepath.Join(root, specPath)
	}
	parsed, err := spec.Parse(specPath)
	if err != nil {
		return fmt.Errorf("parse spec: %w", err)
	}
	if findings := spec.Lint(parsed); spec.HasErrors(findings) {
		return fmt.Errorf("spec has errors; fix them before verify")
	}

	ctx := context.Background()
	tool := &tools.VerifySpecTool{
		Inventory: verifyInventory,
		Limit:     verifyLimit,
		LocalOnly: verifyLocal,
		Host:      verifyHost,
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
	if !filepath.IsAbs(verifyReportDir) {
		// Anchor the report directory under --root so a spec that lives
		// outside this tool's repo can still produce its own .verification/
		// next to itself rather than spilling into cwd.
		root := verifyRoot
		if root == "" {
			root = os.Getenv("PILOT_ROOT")
		}
		if root == "" {
			root, _ = os.Getwd()
		}
		verifyReportDir = filepath.Join(root, verifyReportDir)
	}
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

	// Flip spec_checkpoints.
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

// runVerifyProbe runs one command through the verify pipeline and prints
// everything the matcher sees, so a spec author can pick the right Expected
// grammar without trial-and-error. It writes no report and touches no store.
func runVerifyProbe(cmd *cobra.Command) error {
	tool := &tools.VerifySpecTool{
		Inventory: verifyInventory,
		Limit:     verifyLimit,
		LocalOnly: verifyLocal,
		Host:      verifyHost,
	}
	pr := tool.Probe(context.Background(), verifyProbe, verifyProbeExp, verifyHost, verifyTimeoutSec)
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "command:  %s\n", pr.Command)
	fmt.Fprintf(w, "module:   %s  (become=%v)\n", pr.Module, pr.Become)
	fmt.Fprintf(w, "rc:       %d\n", pr.RC)
	fmt.Fprintf(w, "stdout:   %q\n", pr.Raw)
	fmt.Fprintf(w, "clean:    %q  ← what ~contains / ^regex / string-equality match against\n", pr.Clean)
	if strings.TrimSpace(verifyProbeExp) == "" {
		fmt.Fprintf(w, "\nNo --probe-expected given (raw result only). Pick an Expected from:\n"+
			"  0            → rc must equal 0        (rc=%d here)\n"+
			"  ~<substr>    → clean must contain it\n"+
			"  ^<regex>     → regex must match clean (NOT the raw ansible wrapper)\n", pr.RC)
		return nil
	}
	fmt.Fprintf(w, "expected: %s\n", pr.Expected)
	fmt.Fprintf(w, "verdict:  %s — %s\n", ternaryStr(pr.Pass, "PASS", "FAIL"), pr.Verdict)
	return nil
}

// renderVerifyReport produces the markdown summary used for both
// human reading and `diff` against previous baselines. The format
// matches what the (removed 2026-07-17) scripts/render-report.py
// emitted, so reports stay diffable against old baselines.
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
	// Failures first (matches the historical render-report.py layout).
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

// ternary is a tiny shorthand kept local to verify.go; spec.go has its own
// (per-package) copy because Go forbids free functions across files.
func ternaryStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

// runVerifyMulti walks dir for *.md, runs each through runVerifyOne,
// and prints a rollup table at the end:
//
//	pilot verify --dir docs/verification
//	  ✔  core-infra           8 rows  pass=4 fail=4 verdict=FAIL
//	  ✔  core-infra-provider 9 rows  pass=3 fail=6 verdict=FAIL
//	  ✔  pam-oidc-sshd       7 rows  pass=2 fail=5 verdict=FAIL
//	  ── 1 of 3 specs PASS; aggregate: FAIL ──
//
// Silent on specs with no rows. Skips the spec template file if present.
//
// We deliberately swallow the per-spec non-zero exit codes by inspecting the
// captured rows ourselves; one flaky spec must not block the rollup.
func runVerifyMulti(cmd *cobra.Command, dir string) error {
	matched, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return fmt.Errorf("glob %s: %w", dir, err)
	}
	if len(matched) == 0 {
		return fmt.Errorf("no specs (*.md) under %s; check --dir", dir)
	}
	// Stable order: alphabetic.
	sort.Strings(matched)
	fmt.Printf("verifying %d spec(s) under %s\n", len(matched), dir)
	type rollup struct {
		stem string
		rows int
		pass int
		fail int
		ok   bool
	}
	var rows []rollup
	overallOK := true
	for _, p := range matched {
		stem := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
		// Suppress per-spec verbose output during rollup; the per-spec
		// report still lands in --report-dir.
		// (runVerifyOne prints nd/md paths unconditionally; we don't need
		// to redirect — the rollup table at the end is the operator-facing
		// summary.)
		// Run the per-spec verify. Non-nil err means at least one
		// row failed; we still want a rollup entry (the verdict)
		// derived from the rendered report below.
		_ = runVerifyOne(cmd, p)
		// Parse the last .verification/<stem>-*.md to get verdict.
		pass, fail, total, ok := readLastReport(p)
		if !ok {
			fmt.Printf("\n  ✗ %s: no report produced\n", stem)
			overallOK = false
		}
		if fail > 0 {
			overallOK = false
		}
		rows = append(rows, rollup{stem: stem, rows: total, pass: pass, fail: fail, ok: ok})
		if !ok {
			continue
		}
		fmt.Printf("\n  %s — %d rows  pass=%d fail=%d  verdict=%s\n",
			stem, total, pass, fail, ternaryStr(fail == 0, "PASS", "FAIL"))
	}
	fmt.Println()
	if len(rows) == 0 {
		return fmt.Errorf("no specs verified; abort")
	}
	passed := 0
	for _, r := range rows {
		if r.fail == 0 && r.ok {
			passed++
		}
	}
	if overallOK && passed == len(rows) {
		fmt.Printf("── rollup: %d/%d specs PASS; aggregate: PASS ──\n", passed, len(rows))
	} else {
		fmt.Printf("── rollup: %d/%d specs PASS; aggregate: FAIL ──\n", passed, len(rows))
	}
	if !overallOK || passed < len(rows) {
		return fmt.Errorf("rollup: not every spec passed")
	}
	return nil
}

// readLastReport scans --report-dir for the most recent <stem>-*.md
// and returns pass/fail/total from the front-matter summary line. Cheaper
// and more reliable than re-parsing the per-row table.
func readLastReport(specPath string) (pass, fail, total int, ok bool) {
	stem := strings.TrimSuffix(filepath.Base(specPath), filepath.Ext(specPath))
	reportDir := verifyReportDir
	if reportDir == "" {
		reportDir = ".verification"
	}
	if !filepath.IsAbs(reportDir) {
		root := verifyRoot
		if root == "" {
			root = os.Getenv("PILOT_ROOT")
		}
		if root == "" {
			root, _ = os.Getwd()
		}
		reportDir = filepath.Join(root, reportDir)
	}
	// Anchor the glob to "<stem>-<UTC-timestamp>.md" (15 chars after the
	// stem dash); without this anchor, a glob for "core-infra-*.md" catches
	// "core-infra-provider-*.md" as well.
	matches, err := filepath.Glob(filepath.Join(reportDir, stem+"-????????-??????.md"))
	if err != nil || len(matches) == 0 {
		return 0, 0, 0, false
	}
	sort.Strings(matches)
	latest := matches[len(matches)-1]
	raw, err := os.ReadFile(latest)
	if err != nil {
		return 0, 0, 0, false
	}
	// Parse "- total:     9  pass: 3  fail: 6  skip: 0" from the front-matter.
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "- total:") {
			continue
		}
		// Use a regex-ish token scan since the line format is fixed.
		tokens := strings.Fields(line)
		for i := 0; i < len(tokens)-1; i++ {
			switch strings.TrimSuffix(tokens[i], ":") {
			case "total":
				total, _ = strconv.Atoi(strings.TrimSuffix(tokens[i+1], ":"))
			case "pass":
				pass, _ = strconv.Atoi(strings.TrimSuffix(tokens[i+1], ":"))
			case "fail":
				fail, _ = strconv.Atoi(strings.TrimSuffix(tokens[i+1], ":"))
			}
		}
		if total > 0 || pass > 0 || fail > 0 {
			return pass, fail, total, true
		}
	}
	return 0, 0, 0, false
}
