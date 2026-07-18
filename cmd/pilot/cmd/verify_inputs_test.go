package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anomalyco/pilot/internal/spec"
)

func TestResolveVerifyInputsPrecedenceAndSecretBoundary(t *testing.T) {
	tmp := t.TempDir()
	specPath := filepath.Join(tmp, "v2.md")
	body := `---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent: {summary: inputs, source: test, maintainer: sre}
targets: {roles: [test]}
inputs:
  - {name: endpoint, required: true}
  - {name: token, required: true, secretRef: {provider: ansibleVar, name: token}}
traceability: {components: [test]}
defaults: {become: false, action: {mode: readOnly}}
---
# Verification Spec — inputs
## Checks
` + "```yaml" + `
- {id: C1, category: x, check: x, probe: 'true', expect: {exitCode: 0}}
` + "```" + `
`
	if err := os.WriteFile(specPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := spec.Parse(specPath)
	if err != nil {
		t.Fatal(err)
	}
	inputFile := filepath.Join(tmp, "inputs.yaml")
	if err := os.WriteFile(inputFile, []byte("endpoint: file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	savedInputs, savedFile, savedComponents, savedStage := verifyInputs, verifyInputsFile, verifyComponents, verifyStage
	defer func() {
		verifyInputs, verifyInputsFile, verifyComponents, verifyStage = savedInputs, savedFile, savedComponents, savedStage
	}()
	verifyInputsFile = inputFile
	verifyInputs = []string{"endpoint=cli"}
	t.Setenv("PILOT_INPUT_ENDPOINT", "env")
	values, err := resolveVerifyInputs(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if values.Overrides["endpoint"] != "cli" || values.Environment["endpoint"] != "env" {
		t.Fatalf("values=%v", values)
	}
	verifyInputs = []string{"token=plaintext"}
	if _, err := resolveVerifyInputs(parsed); err == nil {
		t.Fatal("secret CLI input unexpectedly accepted")
	}
	verifyComponents = []string{"test"}
	components, err := resolveVerifyComponents(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !components["test"] {
		t.Fatalf("components=%v", components)
	}
}
