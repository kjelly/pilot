package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/vmtarget"
)

func TestParseAnsibleJSONResult_Basic(t *testing.T) {
	raw := `{"stats":{"host1":{"ok":5,"changed":2,"failures":0,"unreachable":0,"skipped":1,"rescued":0,"ignored":0}}}`
	res, err := parseAnsibleJSONResult(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, ok := res.Stats["host1"]
	if !ok {
		t.Fatalf("expected stats entry for host1, got: %+v", res.Stats)
	}
	want := AnsibleHostStats{Ok: 5, Changed: 2, Skipped: 1}
	if got != want {
		t.Errorf("stats mismatch: got %+v, want %+v", got, want)
	}
}

func TestParseAnsibleJSONResult_SkipsLeadingNoise(t *testing.T) {
	raw := "[DEPRECATION WARNING]: something unrelated\n" +
		`{"stats":{"host1":{"ok":1,"changed":0,"failures":0,"unreachable":0,"skipped":0,"rescued":0,"ignored":0}}}`
	res, err := parseAnsibleJSONResult(raw)
	if err != nil {
		t.Fatalf("expected leading warning text to be skipped, got error: %v", err)
	}
	if res.Stats["host1"].Ok != 1 {
		t.Errorf("expected host1.ok=1, got %+v", res.Stats["host1"])
	}
}

func TestParseAnsibleJSONResult_NoJSON(t *testing.T) {
	_, err := parseAnsibleJSONResult("ERROR! playbook not found\n")
	if err == nil {
		t.Fatal("expected an error when no JSON object is present")
	}
}

func TestSummarizeAnsibleJSONResult_SortedAndFormatted(t *testing.T) {
	res := &ansibleJSONResult{Stats: map[string]AnsibleHostStats{
		"zebra": {Ok: 1},
		"alpha": {Ok: 2, Changed: 1, Failures: 1},
	}}
	out := summarizeAnsibleJSONResult(res)
	alphaIdx := strings.Index(out, "alpha")
	zebraIdx := strings.Index(out, "zebra")
	if alphaIdx < 0 || zebraIdx < 0 || alphaIdx > zebraIdx {
		t.Fatalf("expected hosts sorted alphabetically (alpha before zebra), got:\n%s", out)
	}
	if !strings.Contains(out, "changed=1") || !strings.Contains(out, "failed=1") {
		t.Errorf("expected changed/failed counts in output, got:\n%s", out)
	}
}

func TestExecAnsiblePlaybookCaptured_RealBinaryProducesParsableJSON(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	root := t.TempDir()
	pbPath := filepath.Join(root, "site.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: localhost\n  gather_facts: false\n  connection: local\n  tasks:\n    - name: noop\n      command: /bin/true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	raw, runErr := execAnsiblePlaybookCaptured(context.Background(), nil, []string{"ANSIBLE_STDOUT_CALLBACK=json"}, pbPath)
	if runErr != nil {
		t.Fatalf("expected playbook to succeed, got: %v\noutput: %s", runErr, raw)
	}
	res, err := parseAnsibleJSONResult(raw)
	if err != nil {
		t.Fatalf("expected parsable json output, got error: %v\noutput: %s", err, raw)
	}
	if len(res.Stats) == 0 {
		t.Errorf("expected at least one host in stats, got none\noutput: %s", raw)
	}
}

func TestVtRunLogPath_CreatesDirAndReturnsTimestampedPath(t *testing.T) {
	root := t.TempDir()
	tgt := &vmtarget.Target{Name: "core", Dir: root}

	path, err := vtRunLogPath(tgt, "playbooks/apply/foo-apply.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dir := filepath.Dir(path)
	if dir != filepath.Join(root, "runs") {
		t.Errorf("expected log dir %s, got %s", filepath.Join(root, "runs"), dir)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("expected runs dir to exist: %v", err)
	}
	if !strings.HasSuffix(path, "-foo-apply.log") {
		t.Errorf("expected path to end with -foo-apply.log, got %s", path)
	}
}
