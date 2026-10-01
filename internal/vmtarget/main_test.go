package vmtarget

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/kjelly/pilot/internal/sshcontrol"
)

// TestMain points networkLockDir at a per-run directory, so the tests'
// network locks never touch the host's real /tmp lock files, which a live
// `pilot vm-target up` may hold. It also keeps the SSH control directories
// RenderInventory creates out of the real /tmp, and stops managers from
// cleaning the fact cache of the machine running the tests (tests that
// assert the fact cache calls set Manager.dropFacts themselves).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pilot-vmtarget-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create network lock dir:", err)
		os.Exit(1)
	}
	networkLockDir = dir
	controlBase, err := os.MkdirTemp("/tmp", "pilot-vmt-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create SSH control base:", err)
		os.Exit(1)
	}
	if err := os.Setenv(sshcontrol.BaseEnv, controlBase); err != nil {
		fmt.Fprintln(os.Stderr, "set", sshcontrol.BaseEnv+":", err)
		os.Exit(1)
	}
	defaultDropFacts = func(context.Context, []string) error { return nil }
	code := m.Run()
	_ = os.RemoveAll(dir)
	_ = os.RemoveAll(controlBase)
	os.Exit(code)
}
