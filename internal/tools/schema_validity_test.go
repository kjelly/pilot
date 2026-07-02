package tools

import (
	"encoding/json"
	"testing"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/ollama"
)

// jsonSchemaTypes are the type keywords a tool parameter may declare.
var jsonSchemaTypes = map[string]bool{
	"object": true, "array": true, "string": true,
	"integer": true, "number": true, "boolean": true, "null": true,
}

// TestToolSchemasAreStructurallyValid guards every registered tool's
// hand-written JSON-Schema parameter block. The schemas are literal strings
// in schemas.go kept in manual sync with each handler's unpack struct; there
// is no codegen, so the highest-frequency mistakes are (a) a `required` entry
// that names a property that does not exist (a typo — the LLM is then told a
// field is mandatory that the handler never reads), and (b) a malformed
// property definition. This test is the cheap backstop for both: it walks the
// DEFAULT registry (the real tool set the agent and MCP server expose) and
// asserts each schema is a well-formed object schema.
func TestToolSchemasAreStructurallyValid(t *testing.T) {
	runner := ansible.NewRunner()
	oc := ollama.NewClient("http://localhost:11434", "test")
	r := DefaultRegistry(oc, runner, t.TempDir(), "you are a test")

	for _, name := range r.List() {
		spec, ok := r.Get(name)
		if !ok {
			t.Fatalf("List() reported %q but Get() missed it", name)
		}
		t.Run(name, func(t *testing.T) {
			var schema struct {
				Type       string                     `json:"type"`
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			}
			if err := json.Unmarshal(spec.Parameters, &schema); err != nil {
				t.Fatalf("Parameters is not valid JSON: %v\n%s", err, spec.Parameters)
			}
			if schema.Type != "object" {
				t.Errorf(`schema "type" = %q, want "object"`, schema.Type)
			}
			if schema.Properties == nil {
				t.Fatalf("schema has no \"properties\" object")
			}

			// Every property must declare a known JSON-Schema type.
			for prop, raw := range schema.Properties {
				var def struct {
					Type string `json:"type"`
				}
				if err := json.Unmarshal(raw, &def); err != nil {
					t.Errorf("property %q is malformed: %v", prop, err)
					continue
				}
				if def.Type == "" {
					t.Errorf("property %q has no \"type\"", prop)
					continue
				}
				if !jsonSchemaTypes[def.Type] {
					t.Errorf("property %q has unknown type %q", prop, def.Type)
				}
			}

			// Every `required` name MUST be a declared property. A mismatch
			// here means the LLM is told a field is mandatory that the schema
			// never defines — almost always a typo in the property name.
			for _, req := range schema.Required {
				if _, defined := schema.Properties[req]; !defined {
					t.Errorf("required field %q is not defined in properties %v", req, keysOf(schema.Properties))
				}
			}
		})
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
