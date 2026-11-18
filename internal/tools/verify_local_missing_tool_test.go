package tools

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/spec"
)

// Issue #332: a v1 row of the `cmd && echo 0 || echo 1` shape run on the
// control node passed when cmd's tool was missing. The shell printed
// "sh: 1: <tool>: not found" on stderr, the local runner matched stdout and
// stderr together, the merged text was no lone integer, so the echoed 1 was
// never read and the verdict fell back to the process rc — 0 for that idiom.
// The inventory path reads the echo from ansible's "(stdout)" segment only
// and failed the row correctly. These tests run real `sh -c` commands, so
// the stderr text is whatever the local shell really prints.

const missingToolPath = "/nonexistent/pilot-issue-332/tool"

func missingToolRow() string {
	return "sh -c '" + missingToolPath + " check >/dev/null && echo 0 || echo 1'"
}

// TestVerifyLocal_RcEchoReadFromStdoutOnly drives `pilot verify --local`'s
// real entry (VerifySpecTool.Execute on a spec file) with rows whose stderr
// is not empty.
func TestVerifyLocal_RcEchoReadFromStdoutOnly(t *testing.T) {
	if _, err := os.Stat(missingToolPath); err == nil {
		t.Fatalf("%s exists; the missing-tool case needs it absent", missingToolPath)
	}
	specPath := filepath.Join(t.TempDir(), "x.md")
	body := `# Verification Spec — issue-332

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | functional | missing tool | 0 | ` + missingToolRow() + ` |
| C2 | functional | tool present | 0 | sh -c 'true >/dev/null && echo 0 || echo 1' |
| C3 | functional | warning on stderr, echo 0 | 0 | sh -c 'echo warning >&2; echo 0' |
| C4 | functional | warning on stderr, echo 1 | 1 | sh -c 'echo warning >&2; echo 1' |
| C5 | functional | missing tool, expect 1 | 1 | ` + missingToolRow() + ` |
`
	if err := writeFile(specPath, body); err != nil {
		t.Fatal(err)
	}
	tool := &VerifySpecTool{LocalOnly: true}
	res, err := tool.Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": specPath}))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ReadNDJSON(res.Content)
	if err != nil {
		t.Fatalf("ReadNDJSON: %v\ncontent=%s", err, res.Content)
	}
	want := map[string]string{"C1": "fail", "C2": "pass", "C3": "pass", "C4": "pass", "C5": "pass"}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %s", len(rows), len(want), res.Content)
	}
	for _, row := range rows {
		if row.Status != want[row.ID] {
			t.Errorf("%s: status=%q want %q (detail=%q)", row.ID, row.Status, want[row.ID], row.Detail)
		}
	}
	for _, row := range rows {
		if row.ID == "C1" && !strings.Contains(row.Detail, "rc-from-stdout=1") {
			t.Errorf("C1 must fail on the echoed 1, not on the process rc: detail=%q", row.Detail)
		}
	}
}

// TestProbeLocal_MissingToolFails covers `pilot verify --local --probe`,
// the path the #332 capture came from.
func TestProbeLocal_MissingToolFails(t *testing.T) {
	tool := &VerifySpecTool{LocalOnly: true}
	ctx := context.Background()

	pr := tool.Probe(ctx, missingToolRow(), "0", "", 10)
	if pr.Pass {
		t.Fatalf("missing tool passed: rc=%d raw=%q verdict=%q", pr.RC, pr.Raw, pr.Verdict)
	}
	if !strings.Contains(pr.Verdict, "rc-from-stdout=1") || !strings.Contains(pr.Raw, "not found") {
		t.Errorf("verdict=%q raw=%q; want the echoed 1 read past the shell's not-found error", pr.Verdict, pr.Raw)
	}

	pr = tool.Probe(ctx, "sh -c 'true >/dev/null && echo 0 || echo 1'", "0", "", 10)
	if !pr.Pass {
		t.Errorf("present tool failed: raw=%q verdict=%q", pr.Raw, pr.Verdict)
	}
}

// TestVerifyLocal_AgreesWithInventoryOnRcEcho locks the invariant the fix
// restores: for one command result, a numeric Expected gets the same verdict
// on the local path as on the inventory path. The inventory text has the
// shape of the #332 capture from `ansible --one-line` (ansible-core 2.20.1):
// "<host> | CHANGED | rc=0 | (stdout) 1 (stderr) sh: 1: <tool>: not found".
func TestVerifyLocal_AgreesWithInventoryOnRcEcho(t *testing.T) {
	cases := []struct {
		name, stdout, stderr string
		rc                   int
	}{
		{"missing tool", "1\n", "sh: 1: /usr/local/sbin/pilot-wazuh-transaction: not found\n", 0},
		{"clean 0", "0\n", "", 0},
		{"clean 1", "1\n", "", 0},
		{"warning then 0", "0\n", "warning: deprecated\n", 0},
		{"no echo, rc 0", "", "", 0},
		{"no echo, rc 2", "", "boom\n", 2},
	}
	for _, c := range cases {
		local := "(rc=" + strconv.Itoa(c.rc) + ") " + localV1Output(c.stdout, c.stderr)
		adhoc := "host | CHANGED | rc=" + strconv.Itoa(c.rc) + " |"
		if out := strings.TrimSpace(c.stdout); out != "" {
			adhoc += " (stdout) " + out
		}
		if errText := strings.TrimSpace(c.stderr); errText != "" {
			adhoc += " (stderr) " + errText
		}
		inventory := "(rc=" + strconv.Itoa(c.rc) + ") " + adhoc
		for _, expected := range []string{"0", "1"} {
			lp, lv := evaluateV1LocalExpected(expected, c.stdout, local, c.rc)
			ip, iv := evaluateV1Expected(expected, inventory, c.rc)
			if lp != ip {
				t.Errorf("%s, expected %s: local pass=%v (%s), inventory pass=%v (%s)", c.name, expected, lp, lv, ip, iv)
			}
		}
	}
}

// TestVerifyLocal_IssueRowsFailWithoutTheirTools runs the rows #332 named
// (wazuh-manager C11/C12, wazuh-fim C10, wazuh-alert-delivery C1) from the
// real specs through the local runner on this machine, which has none of
// the pilot wazuh tools.
func TestVerifyLocal_IssueRowsFailWithoutTheirTools(t *testing.T) {
	for _, tool := range []string{"/usr/local/libexec/pilot-wazuh-delivery", "/usr/local/sbin/pilot-wazuh-transaction"} {
		if _, err := os.Stat(tool); err == nil {
			t.Skipf("%s is installed here; this test needs it absent", tool)
		}
	}
	targets := map[string][]string{
		"wazuh-manager.md":        {"C11", "C12"},
		"wazuh-fim.md":            {"C10"},
		"wazuh-alert-delivery.md": {"C1"},
	}
	runner := &VerifySpecTool{LocalOnly: true}
	for file, ids := range targets {
		parsed, err := spec.Parse(filepath.Join("..", "..", "docs", "verification", file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, id := range ids {
			var row *spec.Row
			for i := range parsed.Rows {
				if parsed.Rows[i].ID == id {
					row = &parsed.Rows[i]
				}
			}
			if row == nil {
				t.Errorf("%s %s: row not found", file, id)
				continue
			}
			got := runner.runLocal(context.Background(), *row, 10, parsed.SchemaVersion, nil)
			if got.Status != "fail" {
				t.Errorf("%s %s passed without its tool: detail=%q", file, id, got.Detail)
			}
		}
	}
}
