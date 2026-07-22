package cmd

import (
	"github.com/kjelly/pilot/internal/spec"
)

// parseSpecForTest / generateSpecPlaybookForTest are thin wrappers
// around the spec package; they exist so the cmd-level test file
// doesn't import spec directly and they make the assertions read
// like integration steps.
func parseSpecForTest(path string) (*spec.Spec, error) {
	return spec.Parse(path)
}

func generateSpecPlaybookForTest(s *spec.Spec) (*spec.Playbook, error) {
	return spec.Generate(s, spec.GenerateOptions{IncludeRaw: true})
}
