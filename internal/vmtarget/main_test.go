package vmtarget

import (
	"fmt"
	"os"
	"testing"
)

// TestMain points networkLockDir at a per-run directory, so the tests'
// network locks never touch the host's real /tmp lock files, which a live
// `pilot vm-target up` may hold.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pilot-vmtarget-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create network lock dir:", err)
		os.Exit(1)
	}
	networkLockDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
