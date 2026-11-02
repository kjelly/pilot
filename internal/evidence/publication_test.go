package evidence

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func publicationRecord(id, outcome string) *Record {
	return &Record{Schema: Schema, Feature: "publication", RunID: id, Outcome: outcome, Candidate: Candidate{Commit: strings.Repeat(id, 40)}}
}
func assertPublished(t *testing.T, path, id, outcome string, pointer bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseMachineBlock(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.RunID != id || r.Outcome != outcome {
		t.Fatalf("disk record = %s/%s, want %s/%s", r.RunID, r.Outcome, id, outcome)
	}
	latest, err := os.ReadFile(filepath.Join(filepath.Dir(path), "LATEST.md"))
	if !pointer {
		if !os.IsNotExist(err) {
			t.Fatalf("failed/replaced record retains advertised success pointer: err=%v latest=%s", err, latest)
		}
		return
	}
	if err != nil || !bytes.Contains(latest, []byte(r.Candidate.Commit)) {
		t.Fatalf("success pointer does not identify durable record: %s (%v)", latest, err)
	}
}
func TestEvidencePublicationSamePathCycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issue.md")
	for _, arm := range []struct {
		id, outcome string
		pointer     bool
	}{{"a", "success", true}, {"b", "rolled_back", false}, {"c", "success", true}} {
		if err := publicationRecord(arm.id, arm.outcome).Publish(path); err != nil {
			t.Fatal(err)
		}
		assertPublished(t, path, arm.id, arm.outcome, arm.pointer)
	}
}
func TestEvidencePublicationDifferentFailurePreservesPointer(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.md")
	b := filepath.Join(dir, "b.md")
	if err := publicationRecord("a", "success").Publish(a); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "LATEST.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := publicationRecord("b", "failed").Publish(b); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "LATEST.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("different-path failure modified unrelated success pointer")
	}
}
func TestEvidencePublicationFaults(t *testing.T) {
	for _, fault := range []string{"record-write", "pointer-write", "invalidation-sync"} {
		t.Run(fault, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "issue.md")
			a := publicationRecord("a", "success")
			if err := a.Publish(path); err != nil {
				t.Fatal(err)
			}
			ops := defaultPublicationOps()
			write := ops.atomicWrite
			syncDir := ops.syncDirectory
			ops.atomicWrite = func(p string, b []byte) error {
				if (fault == "record-write" && p == path) || (fault == "pointer-write" && filepath.Base(p) == "LATEST.md") {
					return errors.New("injected publication write failure")
				}
				return write(p, b)
			}
			ops.syncDirectory = func(d *os.File) error {
				if fault == "invalidation-sync" {
					return errors.New("injected invalidation sync failure")
				}
				return syncDir(d)
			}
			err := publicationRecord("b", "success").publish(path, ops)
			if err == nil {
				t.Fatal("injected publication fault unexpectedly succeeded")
			}
			id := "a"
			if fault == "pointer-write" {
				id = "b"
			}
			assertPublished(t, path, id, "success", false)
		})
	}
}
func TestEvidencePublicationRejectsStaleCompatibilityUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "issue.md")
	old := publicationRecord("a", "success")
	if err := old.Publish(path); err != nil {
		t.Fatal(err)
	}
	if err := publicationRecord("b", "failed").Publish(path); err != nil {
		t.Fatal(err)
	}
	if err := UpdateLatest(dir, old, path); err == nil || !strings.Contains(err.Error(), "refusing stale") {
		t.Fatalf("obsolete caller resurrected pointer: %v", err)
	}
	assertPublished(t, path, "b", "failed", false)
}

// A real child holds the directory lock across record replacement and pointer
// publication. Pausing precisely at that boundary makes the lock/crash oracle
// deterministic, rather than relying on concurrent scheduling to expose a race.
func TestEvidencePublicationProcessHelper(t *testing.T) {
	path := os.Getenv("PILOT_PUBLICATION_HELPER")
	if path == "" {
		return
	}
	ops := defaultPublicationOps()
	write := ops.atomicWrite
	if os.Getenv("PILOT_PUBLICATION_PAUSE") == "1" {
		ops.atomicWrite = func(p string, b []byte) error {
			if err := write(p, b); err != nil {
				return err
			}
			if p == path {
				fmt.Println("record-replaced")
				_, err := bufio.NewReader(os.Stdin).ReadString('\n')
				return err
			}
			return nil
		}
	}
	if err := publicationRecord(os.Getenv("PILOT_PUBLICATION_ID"), os.Getenv("PILOT_PUBLICATION_OUTCOME")).publish(path, ops); err != nil {
		t.Fatal(err)
	}
}
func TestEvidencePublicationProcessLockAndCrash(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(fmt.Sprint("crash=", crash), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "issue.md")
			if err := publicationRecord("a", "success").Publish(path); err != nil {
				t.Fatal(err)
			}
			child := func(id, outcome string, pause bool) *exec.Cmd {
				cmd := exec.Command(os.Args[0], "-test.run=^TestEvidencePublicationProcessHelper$")
				cmd.Env = append(os.Environ(), "PILOT_PUBLICATION_HELPER="+path, "PILOT_PUBLICATION_ID="+id, "PILOT_PUBLICATION_OUTCOME="+outcome, fmt.Sprintf("PILOT_PUBLICATION_PAUSE=%d", map[bool]int{false: 0, true: 1}[pause]))
				return cmd
			}
			a := child("b", "success", true)
			stdout, err := a.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := a.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			a.Stderr = os.Stderr
			if err := a.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Process.Kill() })
			line, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil || line != "record-replaced\n" {
				t.Fatalf("helper boundary: %q %v", line, err)
			}
			dir, err := os.Open(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			err = syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if !errors.Is(err, syscall.EWOULDBLOCK) {
				t.Fatalf("publication directory is not process-locked at record/pointer boundary: %v", err)
			}
			assertPublished(t, path, "b", "success", false)
			if crash {
				if err := a.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				_ = a.Wait()
				assertPublished(t, path, "b", "success", false)
				return
			}
			b := child("c", "failed", false)
			var bOutput bytes.Buffer
			b.Stdout = &bOutput
			b.Stderr = &bOutput
			if err := b.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.Process.Kill() })
			if _, err := fmt.Fprintln(stdin, "continue"); err != nil {
				t.Fatal(err)
			}
			if err := a.Wait(); err != nil {
				t.Fatal(err)
			}
			if err := b.Wait(); err != nil {
				t.Fatalf("second publisher: %v %s", err, bOutput.String())
			}
			assertPublished(t, path, "c", "failed", false)
		})
	}
}

func TestEvidencePublicationDifferentPointerWriteFaultPreservesSuccess(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.md")
	b := filepath.Join(dir, "b.md")
	if err := publicationRecord("a", "success").Publish(a); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "LATEST.md"))
	if err != nil {
		t.Fatal(err)
	}
	ops := defaultPublicationOps()
	write := ops.atomicWrite
	ops.atomicWrite = func(path string, data []byte) error {
		if filepath.Base(path) == "LATEST.md" {
			return errors.New("injected pointer replacement failure")
		}
		return write(path, data)
	}
	if err := publicationRecord("b", "success").publish(b, ops); err == nil {
		t.Fatal("pointer write fault unexpectedly passed")
	}
	after, err := os.ReadFile(filepath.Join(dir, "LATEST.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("different-path pointer write failure damaged unrelated success")
	}
}
