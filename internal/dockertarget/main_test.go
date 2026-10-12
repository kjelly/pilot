package dockertarget

import (
	"context"
	"os"
	"testing"
)

// TestMain stops managers from cleaning the fact cache of the machine
// running the tests; tests that assert the fact cache calls set
// Manager.dropFacts themselves.
func TestMain(m *testing.M) {
	defaultDropFacts = func(context.Context, []string) error { return nil }
	os.Exit(m.Run())
}
