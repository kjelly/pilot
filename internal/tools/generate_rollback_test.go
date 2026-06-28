package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/ollama"
)

func TestGenerateRollbackRequiresProposalID(t *testing.T) {
	tc := &GenerateRollbackTool{Ollama: nil}
	_, err := tc.Execute(context.Background(), json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error for missing proposal_id")
	}
}

func TestGenerateRollbackRequiresOllamaClient(t *testing.T) {
	tc := &GenerateRollbackTool{Ollama: nil}
	res, err := tc.Execute(context.Background(), json.RawMessage(`{"proposal_id":"p1"}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error result, got: %s", res.Content)
	}
	if !strings.Contains(res.Content, "ollama") {
		t.Errorf("error should mention ollama: %s", res.Content)
	}
}

func TestGenerateRollbackWritesYAML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"message":{"role":"assistant","content":"`+"```yaml"+`\n- name: Rollback PermitRootLogin\n  ansible.builtin.lineinfile:\n    path: /etc/ssh/sshd_config\n    regexp: '^PermitRootLogin'\n    line: 'PermitRootLogin yes'\n    state: present\n  become: true\n`+"```"+`"},"done":true}`)
	}))
	defer srv.Close()

	oc := ollama.NewClient(srv.URL, "test-model")
	tmp := t.TempDir()
	tc := &GenerateRollbackTool{
		Ollama:       oc,
		GeneratedDir: tmp,
	}
	res, err := tc.Execute(context.Background(), json.RawMessage(`{"proposal_id":"abc-123","description":"Disable root SSH","original_tool":"run_ansible","original_args":"{}"}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", res.Content)
	}
	if !strings.Contains(res.Content, "Rollback playbook written to") {
		t.Errorf("missing written-to message: %s", res.Content)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no file was written")
	}
	body, err := os.ReadFile(tmp + "/" + entries[0].Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "PermitRootLogin") {
		t.Errorf("rollback YAML missing key content: %s", body)
	}
	if !strings.Contains(string(body), "Rollback for proposal abc-123") {
		t.Errorf("rollback file missing header: %s", body)
	}
}

func TestGenerateRollbackRejectsNonYAML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"message":{"role":"assistant","content":"I cannot help with that."},"done":true}`)
	}))
	defer srv.Close()
	oc := ollama.NewClient(srv.URL, "test-model")
	tc := &GenerateRollbackTool{Ollama: oc, GeneratedDir: t.TempDir()}
	res, _ := tc.Execute(context.Background(), json.RawMessage(`{"proposal_id":"p"}`))
	if !res.IsError {
		t.Errorf("expected error for non-YAML response, got: %s", res.Content)
	}
}
