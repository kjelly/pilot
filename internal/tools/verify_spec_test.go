package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/store"
)

func TestVerifySpec_LocalMode(t *testing.T) {
	tmp := t.TempDir()
	specPath := filepath.Join(tmp, "x.md")
	body := `# Verification Spec — verify-test

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | a | present | ` + "`test -f /etc/os-release`" + ` |
| C2 | file | b | present | ` + "`test -f /nonexistent/path/file`" + ` |
| C3 | file | c | present | ` + "`test -d /tmp`" + ` |
`
	if err := writeFile(specPath, body); err != nil {
		t.Fatal(err)
	}

	tool := &VerifySpecTool{LocalOnly: true}
	res, err := tool.Execute(context.Background(), mustJSON(t, map[string]any{
		"spec_path": specPath,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("result.IsError=true content=%q", res.Content)
	}
	rows, err := ReadNDJSON(res.Content)
	if err != nil {
		t.Fatalf("ReadNDJSON: %v\ncontent=%s", err, res.Content)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows want=3", len(rows))
	}
	// /etc/os-release exists in any sane CI; /nonexistent never exists.
	if rows[0].Status != "pass" {
		t.Errorf("C1 status=%q detail=%q", rows[0].Status, rows[0].Detail)
	}
	if rows[1].Status != "fail" {
		t.Errorf("C2 (nonexistent) should fail, got %q", rows[1].Status)
	}
	if rows[2].Status != "pass" {
		t.Errorf("C3 (/tmp) should pass, got %q", rows[2].Status)
	}
}

func TestVerifySpec_PersistsHostRowEvidence(t *testing.T) {
	tmp := t.TempDir()
	specPath := filepath.Join(tmp, "x.md")
	if err := writeFile(specPath, `# Verification Spec — evidence

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | tmp exists | present | `+"`test -d /tmp`"+` |
`); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(tmp, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w, err := store.StartRun(context.Background(), s, store.RunStarted{RunID: "verify-evidence"})
	if err != nil {
		t.Fatal(err)
	}
	tool := &VerifySpecTool{LocalOnly: true, EvidenceWriter: w}
	res, err := tool.Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": specPath}))
	if err != nil || res.IsError {
		t.Fatalf("Execute err=%v result=%+v", err, res)
	}
	if err := w.Finish(context.Background(), store.RunFinished{Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	if count, err := s.EvidenceCount(w.RunID()); err != nil || count != 1 {
		t.Fatalf("evidence count=%d err=%v", count, err)
	}
}

func TestAdHocModule(t *testing.T) {
	cases := map[string]string{
		"test -f /etc/ipa/default.conf": "command",
		"systemctl is-active sssd":      "command",
		"sudo -l -U pilotuser":          "command",
		"ss -tlnH | grep -q ':389 '":    "shell",
		"grep -q IPA /etc/krb5.conf":    "command",
		"echo $HOME":                    "shell",
		"a && b":                        "shell",
		"cat f > /tmp/x":                "shell",
	}
	for cmd, want := range cases {
		if got := adHocModule(cmd); got != want {
			t.Errorf("adHocModule(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// TestProbe_LocalMode exercises the --probe path in local mode (no VM): it
// must expose rc, raw, clean and the matcher verdict for each Expected
// grammar, matching what a real spec row would decide.
func TestProbe_LocalMode(t *testing.T) {
	tool := &VerifySpecTool{LocalOnly: true}
	ctx := context.Background()

	// rc-based expected.
	pr := tool.Probe(ctx, "test -f /etc/os-release", "0", "", 10)
	if pr.Module != "local" || pr.RC != 0 || !pr.Pass {
		t.Errorf("rc-probe: module=%q rc=%d pass=%v verdict=%q", pr.Module, pr.RC, pr.Pass, pr.Verdict)
	}

	// ~contains against real stdout.
	pr = tool.Probe(ctx, "echo hello-world", "~hello", "", 10)
	if !pr.Pass || pr.Clean != "hello-world" {
		t.Errorf("contains-probe: clean=%q pass=%v verdict=%q", pr.Clean, pr.Pass, pr.Verdict)
	}

	// A failing match still returns cleanly with Pass=false so the author
	// sees exactly why. `echo active` never contains "inactive".
	pr = tool.Probe(ctx, "echo active", "~inactive", "", 10)
	if pr.Pass {
		t.Errorf("expected FAIL for `echo active` vs ~inactive (clean=%q), got pass; verdict=%q", pr.Clean, pr.Verdict)
	}

	// Empty expected → default rc==0 rule, no crash.
	pr = tool.Probe(ctx, "true", "", "", 10)
	if !pr.Pass {
		t.Errorf("empty-expected probe on `true` should default-pass; verdict=%q", pr.Verdict)
	}
}

func TestVerifySpec_SpecPathRequired(t *testing.T) {
	tool := &VerifySpecTool{}
	res, err := tool.Execute(context.Background(), json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error")
	}
	if res != nil {
		t.Errorf("res should be nil on hard error")
	}
}

func TestReadNDJSON(t *testing.T) {
	content := `{"id":"C1","status":"pass","detail":"ok"}
{"id":"C2","status":"fail","detail":"nope"}
`
	rows, err := ReadNDJSON(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].ID != "C1" || rows[1].Status != "fail" {
		t.Errorf("rows=%+v", rows)
	}
	// Malformed line should surface an error.
	if _, err := ReadNDJSON(`{"id":"C1"`); err == nil {
		t.Error("expected error on malformed JSON")
	}
}

// helpers
func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLooksLikePermissionError(t *testing.T) {
	positives := []string{
		`docker: Got permission denied while trying to connect to the Docker daemon socket`,
		`dial unix /var/run/docker.sock: connect: permission denied`,
		`pg_isready: could not open file "/var/run/postgresql": Permission denied`,
		`mount: only root can do that (Operation not permitted)`,
		`This command has to be run as root`,
	}
	for _, s := range positives {
		if !looksLikePermissionError(s) {
			t.Errorf("expected permission error for %q", s)
		}
	}
	negatives := []string{
		`connection refused`,
		`no such file or directory`,
		`could not resolve host`,
		``,
	}
	for _, s := range negatives {
		if looksLikePermissionError(s) {
			t.Errorf("did not expect permission error for %q", s)
		}
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
