package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/gateledger"
)

// golangGateExemptions are the returns of the Go preview's functions that no
// row makes fire, each with the reason. A reason is not a license: when a row
// reaches the gate, the exemption must go (the ledger fails on a stale one).
var golangGateExemptions = map[string]string{
	// The Ansible engine's own checks, which the Go preview shares only a
	// function with (spec §2.1 refuses the Go engine's combinations earlier,
	// in validateReconcileEngineFlags).
	"ansible-force-and-preview-only": "Ansible engine; the Go engine refuses --force earlier (engine-preview-only). Row: TestReconcileRejectsFlagMisuse 'force and preview-only'",
	"ansible-actions-with-limit":     "Ansible engine --actions path; the Go engine refuses --actions earlier (engine-actions). Not part of the Go preview and without a row before this change",
	"ansible-actions-with-flags":     "Ansible engine --actions path. Row: TestReconcileRejectsFlagMisuse 'actions with component'",
	"ansible-actions-dispatch":       "delegates to the Ansible engine's scenario runner; the Go engine refuses --actions earlier",
	"ansible-needs-component":        "Ansible engine; the Go engine needs exactly one --component earlier (engine-component). Row: TestReconcileRejectsFlagMisuse 'preview-only without component'",
	"ansible-interactive-dispatch":   "delegates to the Ansible engine's wizard. Row: TestReconcileNonInteractiveRunsWithoutTTY",

	// Defense in depth: a failure that cannot be produced from a test
	// without breaking the process or the machine.
	"plan-out-abs":        "filepath.Abs fails only when the working directory no longer exists",
	"hosts-abs-dir":       "filepath.Abs fails only when the working directory no longer exists",
	"hosts-abs-inventory": "filepath.Abs fails only when the working directory no longer exists",
	"hosts-read-inventory": "inventory.yml vanishing between validateFileExists (gate inventory-missing) and this read; a race, " +
		"not something a test can order",
	"completeness-error": "validateDeploymentCompletenessSnapshot fails only in validateInventorySecretStorage, which " +
		"loadDeployInventorySnapshot runs first and refuses with gate ansible-inventory (row: a plaintext secret in group_vars)",
	"roster-file-unset": "validateDeploymentCompletenessSnapshot refuses a host without freeipa_roster_file first " +
		"(gate completeness; row 'no freeipa_roster_file: completeness refuses first' documents the order)",
	"plan-marshal":     "json.MarshalIndent of the plan document, plain data, cannot fail",
	"plan-write-bytes": "a write error on a file created a moment ago: needs a full disk",
	"plan-close":       "a close error on a file just written: needs a full disk",
}

// AGENTS.md §5.10 and §5.12 for the Go preview: every return that refuses
// (anything but nil) in the functions that hold its gates is named with a
// `// gate: <id>` comment, ids are unique, and each id has a test row that
// makes it fire or an exemption with a reason. So deleting a gate, or adding
// one nobody tested, fails here instead of passing every test (the class
// that cost two review rounds). The rows name their gates in a gate field.
func TestReconcileGolangEveryGateHasARow(t *testing.T) {
	holders := map[string][]string{
		"reconcile.go": {"runReconcile"},
		"reconcile_golang.go": {
			"validateReconcileEngineFlags", "runReconcileGolangPreview", "golangPreview", "inventoryCurrentWithHosts",
			"golangPreviewStage", "rosterServer", "sshTargetFromHostVars", "sshOptionArgs", "splitShellWords", "writeGolangPlan",
		},
	}
	var res gateledger.Result
	for file, funcs := range holders {
		one, err := gateledger.Scan(file, nil, funcs...)
		if err != nil {
			t.Fatal(err)
		}
		res.Returns = append(res.Returns, one.Returns...)
		res.Stray = append(res.Stray, one.Stray...)
	}
	if len(res.Returns) < 60 {
		t.Fatalf("found %d gates, want at least the 60+ the preview had: a holder lost its returns", len(res.Returns))
	}
	rowFiles, err := filepath.Glob("reconcile_golang*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	// This file's own tables carry no rows, only exemptions.
	rowFiles = slices.DeleteFunc(rowFiles, func(f string) bool { return f == "reconcile_golang_ledger_test.go" })
	rows, err := gateledger.RowGates(rowFiles...)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range gateledger.Check(res, rows, golangGateExemptions) {
		t.Error(p)
	}
}

// The ledger would be vacuous if the checks above could not fail; this proves
// they can on the real source: the scanner finds the real gates, and a copy
// of the real function with a gate comment removed, or with an un-annotated
// refusal added, is reported.
func TestReconcileGolangGateLedgerFiresOnTheRealSource(t *testing.T) {
	src, err := os.ReadFile("reconcile_golang.go")
	if err != nil {
		t.Fatal(err)
	}
	scan := func(source string) []string {
		res, err := gateledger.Scan("reconcile_golang.go", []byte(source), "golangPreview", "writeGolangPlan")
		if err != nil {
			t.Fatal(err)
		}
		rows := map[string]int{}
		for _, r := range res.Returns {
			rows[r.Gate] = 1
		}
		// Every gate that exists has a row here, so only the mutation shows.
		delete(rows, "")
		return gateledger.Check(res, rows, nil)
	}
	if p := scan(string(src)); len(p) != 0 {
		t.Fatalf("the unmodified source is not clean under its own rows: %v", p)
	}
	t.Run("a removed gate comment", func(t *testing.T) {
		mutated := strings.Replace(string(src), " // gate: login\n", "\n", 1)
		if mutated == string(src) {
			t.Fatal("the login gate comment is gone from the source")
		}
		if p := scan(mutated); !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, "without a `// gate: <id>` comment") }) {
			t.Fatalf("problems = %v, want the un-annotated return", p)
		}
	})
	t.Run("an added refusal nobody named", func(t *testing.T) {
		const anchor = "\tobservedAt := time.Now()\n"
		if !strings.Contains(string(src), anchor) {
			t.Fatal("the anchor line moved")
		}
		mutated := strings.Replace(string(src), anchor, "\tif host == \"\" {\n\t\treturn fmt.Errorf(\"new refusal\")\n\t}\n"+anchor, 1)
		if p := scan(mutated); !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, "new refusal") }) {
			t.Fatalf("problems = %v, want the added return named", p)
		}
	})
}
