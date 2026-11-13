package dockertarget

import (
	"context"
	"os"
	"testing"
)

// productionDropFacts is defaultDropFacts as NewManager has it outside the
// tests, saved before TestMain stubs it out (useProductionDropFacts).
var productionDropFacts func(stateDir string) func(context.Context, []string) error

// TestMain stops managers from cleaning the fact cache of the machine
// running the tests; tests that assert the fact cache calls set
// Manager.dropFacts themselves, or restore productionDropFacts, the wiring
// NewManager has outside the tests.
func TestMain(m *testing.M) {
	productionDropFacts = defaultDropFacts
	defaultDropFacts = func(string) func(context.Context, []string) error {
		return func(context.Context, []string) error { return nil }
	}
	os.Exit(m.Run())
}
