//go:build linux || darwin || freebsd

package cmd

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigSecretStorage_PTYRejectsBeforeRendering(t *testing.T) {
	dir := t.TempDir()
	const value = "ISSUE130_DUMMY_PASSWORD"
	writeTestFile(t, filepath.Join(dir, "host_vars", "example.yml"), "ansible_password: "+value+"\n")
	proc := startEditPTYWithEnv(t, dir, 24, 100, "PILOT_ROOT="+repoRootForTest(t))
	if rc := proc.waitExit(t, 5*time.Second); rc == 0 {
		t.Fatal("unsafe workspace exited successfully")
	}
	out := waitForPTYOutput(t, proc.out, time.Second, "forbidden secret storage")
	if strings.Contains(out, value) {
		t.Fatal("credential leaked to real terminal")
	}
}
