package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
)

// This is a bounded syscall fault harness. The original helper and query
// emitter run unchanged; sitecustomize injects EIO only for the opened journal
// directory. It does not replace FreeIPA, SSSD, query results or receipt bytes.
func TestFreeIPAProvider_RealRetirementDurabilityFailurePersistsUntilSynced(t *testing.T) {
	playbook, _ := retirementQueryHarness(t, "pending")
	journal := filepath.Join(filepath.Dir(playbook), "journal.json")
	dir := t.TempDir()
	flag := filepath.Join(dir, "directory-fsync-error")
	events := filepath.Join(dir, "fsync-events")
	shim := `import errno,os,stat
real_fsync=os.fsync
journal=os.environ.get('I226_FSYNC_JOURNAL','')
flag=os.environ.get('I226_FSYNC_FAULT','')
events=os.environ.get('I226_FSYNC_EVENTS','')
def audited_fsync(fd):
 path=os.readlink('/proc/self/fd/%d'%fd)
 if path in (journal,os.path.dirname(journal)):
  kind='directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file'
  with open(events,'a') as stream: stream.write(kind+'\n')
  if kind=='directory' and os.path.exists(flag):
   raise OSError(errno.EIO,'injected journal directory fsync EIO')
 return real_fsync(fd)
os.fsync=audited_fsync
`
	if err := os.WriteFile(filepath.Join(dir, "sitecustomize.py"), []byte(shim), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flag, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pythonPath := dir
	if previous := os.Getenv("PYTHONPATH"); previous != "" {
		pythonPath += string(os.PathListSeparator) + previous
	}
	t.Setenv("PYTHONPATH", pythonPath)
	t.Setenv("PYTHONDONTWRITEBYTECODE", "1")
	t.Setenv("I226_FSYNC_JOURNAL", journal)
	t.Setenv("I226_FSYNC_FAULT", flag)
	t.Setenv("I226_FSYNC_EVENTS", events)
	helper, err := filepath.Abs("../../../playbooks/apply/files/freeipa-ssh-key-cache.py")
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]any{"domain": "ipa.pilot.internal", "stage": "sandbox", "retirements": []map[string]string{{
		"alias": retirementTestAlias, "fqdn": retirementTestFQDN, "stage": "sandbox", "reason": "approved synthetic retirement", "origin": "durability-harness"}}})
	if err != nil {
		t.Fatal(err)
	}
	runRetirement := func(wantError bool) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "python3", helper, "retire", journal)
		command.Stdin = bytes.NewReader(input)
		out, err := command.CombinedOutput()
		if (err != nil) != wantError {
			t.Fatalf("retirement retry durability result: error=%v wantError=%v\n%s", err, wantError, out)
		}
		if wantError && !strings.Contains(string(out), "injected journal directory fsync EIO") {
			t.Fatalf("retirement failed outside its durability barrier: %s", out)
		}
		return out
	}
	runRetirement(true) // Replace commits a visible receipt; directory fsync fails.
	visible, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Retired map[string]struct {
			Discharged int `json:"discharged"`
		} `json:"retired"`
	}
	if err := json.Unmarshal(visible, &state); err != nil {
		t.Fatal(err)
	}
	if state.Retired[retirementTestAlias].Discharged != 1 {
		t.Fatal("first directory error did not leave the intended visible receipt")
	}
	runRetirement(true) // Same bytes, same still-active fault: must not report success.
	real := &retirementAnsibleExecutor{}
	provider := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{ServerInventory: "localhost,", IdentityApplyPlaybook: playbook})
	provider.cfg.Executor = &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		if queryKind(args) == "ssh_retirement" {
			return real.Run(context.Background(), args...)
		}
		body := "host not found"
		if queryKind(args) == "host_dns" {
			body = dnsShowNotFound
		}
		return &ansible.Result{Stdout: "HOST_INSPECT[" + retirementTestFQDN + "]: " + body}, nil
	}}
	step, err := provider.ExecutorForStep(Step{Action: ActionFreeIPAIdentityApplyConverge, TargetIdentity: retirementTestFQDN,
		Params: map[string]string{"inventory_alias": retirementTestAlias}})
	if err != nil {
		t.Fatal(err)
	}
	if done, err := step.Inspect(context.Background()); err == nil || done || !strings.Contains(real.stdout, "injected journal directory fsync EIO") {
		t.Fatalf("provider Inspect accepted visible unflushed receipt: done=%v err=%v\n%s", done, err, real.stdout)
	}
	if _, err := provider.Verify(context.Background(), VerifyInput{FQDN: retirementTestFQDN, InventoryAlias: retirementTestAlias}); err == nil ||
		!strings.Contains(err.Error(), "SSH retirement") || !strings.Contains(real.stdout, "injected journal directory fsync EIO") {
		t.Fatalf("provider Verify did not reject at the actual durability failure: %v\n%s", err, real.stdout)
	}
	if current, err := os.ReadFile(journal); err != nil || !bytes.Equal(visible, current) {
		t.Fatal("retry/status altered visible receipt, epochs or pending state")
	}
	if err := os.Remove(flag); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(events, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Changed bool `json:"changed"`
	}
	if err := json.Unmarshal(runRetirement(false), &result); err != nil || result.Changed {
		t.Fatalf("recovered no-op changed receipt: %+v %v", result, err)
	}
	if done, err := step.Inspect(context.Background()); err != nil || !done {
		t.Fatalf("durable recovered Inspect=%v,%v", done, err)
	}
	rows, err := provider.Verify(context.Background(), VerifyInput{FQDN: retirementTestFQDN, InventoryAlias: retirementTestAlias})
	if err != nil {
		t.Fatal(err)
	}
	if row := findVerification(t, rows, "ssh_cache_retirement"); row.Active || row.Status != "pass" {
		t.Fatalf("recovered Verify did not confirm retirement: %+v", row)
	}
	barriers, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if string(barriers) != strings.Repeat("file\ndirectory\n", 3) {
		t.Fatalf("success outlets did not each sync journal file and directory: %q", barriers)
	}
	if current, err := os.ReadFile(journal); err != nil || !bytes.Equal(visible, current) {
		t.Fatal("successful durability confirmation rewrote semantic state")
	}
}
