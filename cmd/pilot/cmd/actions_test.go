package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSemanticActionCatalogIsStable(t *testing.T) {
	want := []string{"create_host", "set_host_field", "enable_role", "save_hosts", "deploy", "reconcile"}
	specs := semanticActionSpecs()
	if len(specs) != len(want) {
		t.Fatalf("spec count = %d, want %d", len(specs), len(want))
	}
	for i, spec := range specs {
		if spec.Name != want[i] {
			t.Fatalf("spec %d name = %q, want %q", i, spec.Name, want[i])
		}
		if spec.Description == "" {
			t.Fatalf("spec %q has no description", spec.Name)
		}
	}
}

func TestWriteActionsSchemaIsMachineReadable(t *testing.T) {
	var out bytes.Buffer
	if err := writeActionsSchema(&out); err != nil {
		t.Fatalf("writeActionsSchema() error = %v", err)
	}
	var schema struct {
		Version int `json:"version"`
		Actions []struct {
			Name     string   `json:"name"`
			Required []string `json:"required"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(out.Bytes(), &schema); err != nil {
		t.Fatalf("schema is not JSON: %v\n%s", err, out.String())
	}
	if schema.Version != 1 || len(schema.Actions) != 6 {
		t.Fatalf("schema metadata = version %d, actions %d", schema.Version, len(schema.Actions))
	}
	if !strings.Contains(out.String(), `"name": "deploy"`) || !strings.Contains(out.String(), `"answers"`) {
		t.Fatalf("schema omitted deploy answer contract:\n%s", out.String())
	}
}

func TestActionsListIncludesEverySemanticAction(t *testing.T) {
	var out bytes.Buffer
	if err := writeActionsList(&out); err != nil {
		t.Fatalf("writeActionsList() error = %v", err)
	}
	for _, name := range []string{"create_host", "set_host_field", "enable_role", "save_hosts", "deploy", "reconcile"} {
		if !strings.Contains(out.String(), name) {
			t.Fatalf("actions list omitted %q:\n%s", name, out.String())
		}
	}
}
