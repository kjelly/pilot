package tools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
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
