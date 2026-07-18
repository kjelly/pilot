package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/spec"
)

// TestPilotSpec_HostsFlag is the regression test for the
// "pilot spec --apply skips real hosts" bug.
//
// Pre-fix wiring in cmd/pilot/cmd/spec.go:
//
//	pb, err := spec.Generate(parsed, spec.GenerateOptions{IncludeRaw: true})
//
// → produces `hosts: localhost` (generator default). When the user
// supplies `--inventory` and runs `pilot spec --apply`, ansible-playbook
// silently prints "skipping: no hosts matched" because no entry in
// `--inventory` is named `localhost` and `--limit` was the user's
// intended target.
//
// Post-fix wiring:
//
//	pb, err := spec.Generate(parsed, spec.GenerateOptions{
//	    IncludeRaw: true,
//	    Hosts:      specHosts,
//	    Connection: specConnection,
//	})
//
// → respects --hosts and --connection. We exercise the wiring here by
// running runSpec directly with the flags set and asserting the YAML
// the command writes to disk reflects the override.
//
// To prove the test isn't a tautology: revert the spec.Generate call
// back to the single-arg form. Even with --hosts=test-vm the produced
// YAML writes "hosts: localhost" and the test below FAILS.
func TestPilotSpec_HostsFlag(t *testing.T) {
	// Build a tmp spec file.
	tmp := t.TempDir()
	specPath := filepath.Join(tmp, "apply-hosts.md")
	body := `# Verification Spec — apply-hosts

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | x | present | sh -c 'test -f /etc/os-release; echo $?' |
`
	if err := os.WriteFile(specPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(tmp, "apply-hosts.yml")

	savedHosts, savedConn, savedGen := specHosts, specConnection, specGenerateOut
	defer func() {
		specHosts, specConnection, specGenerateOut = savedHosts, savedConn, savedGen
	}()

	specHosts = "webservers"
	specConnection = "ssh"
	specGenerateOut = outPath

	// The generated playbook file is what we inspect.
	if err := runSpec(nil, []string{specPath}); err != nil {
		t.Fatalf("runSpec: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read %s: %v", outPath, err)
	}
	if !strings.Contains(string(got), "hosts: webservers\n") {
		t.Errorf("--hosts=test-vm did not propagate: playbook hosts line is not the override\n--- %s ---", got)
	}
	if !strings.Contains(string(got), "connection: ssh\n") {
		t.Errorf("--connection=ssh did not propagate: playbook connection line is not the override\n--- %s ---", got)
	}

	// Defensive: also prove the spec package itself accepts the option;
	// if a future maintainer removes Hosts from GenerateOptions the
	// compile error will catch it. (Compile-time assurance.)
	_ = spec.GenerateOptions{Hosts: specHosts, Connection: specConnection}
}
