package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func nativeAnsiblePython(t *testing.T) (string, []string) {
	t.Helper()
	bin, err := exec.LookPath("ansible-playbook")
	if err != nil {
		if os.Getenv("PILOT_REQUIRE_ANSIBLE_EVIDENCE_TESTS") == "1" {
			t.Fatal(err)
		}
		t.Skip("ansible-playbook unavailable")
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	shebang, _, _ := strings.Cut(string(raw), "\n")
	parts := strings.Fields(strings.TrimPrefix(shebang, "#!"))
	if !strings.HasPrefix(shebang, "#!") || len(parts) == 0 {
		t.Fatal("cannot locate native Ansible interpreter")
	}
	return parts[0], parts[1:]
}

// Compare the production Go parser, not a test imitation of its grammar, with
// the installed native API in one bounded batch. Invalid/excluded native forms
// may still execute, but must never be admitted as a complete Go parse.
func TestEvidenceNativeInlineGrammarDifferential(t *testing.T) {
	python, prefix := nativeAnsiblePython(t)
	nativeInlineGrammarDifferential(t, func(program string, raw []byte) []byte {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, python, append(prefix, "-c", program)...)
		cmd.Stdin = bytes.NewReader(raw)
		cmd.Dir = t.TempDir()
		cmd.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+cmd.Dir+"/ansible-tmp")
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("native parser batch failed: %v", err)
		}
		return output
	})
}

func nativeInlineGrammarDifferential(t *testing.T, run func(string, []byte) []byte) {
	t.Helper()
	alphabet := []byte{'a', ' ', '=', '\'', '"'}
	var suffixes []string
	var enumerate func(string, int)
	enumerate = func(s string, remaining int) {
		suffixes = append(suffixes, s)
		if remaining > 0 {
			for _, ch := range alphabet {
				enumerate(s+string(ch), remaining-1)
			}
		}
	}
	enumerate("", 6)
	var payloads []string
	for _, key := range []string{"api_token=", "'api_token'=", "\"api_token\"=", "\"api_token="} {
		for _, suffix := range suffixes {
			payloads = append(payloads, key+suffix)
		}
	}
	generated := len(payloads)
	payloads = append(payloads,
		`api_token=abc"def"`, `api_token=abc'def'`, `api_token="abc"def`, `api_token='abc'def`,
		`api_token="a'b=c d"`, `api_token='a"b=c d'`, `api_token=abc=def`,
		`api_token= other_key=literal`, `_token1=literal target_group=all`,
		`"api_token=literal"`, `'api_token=literal'`, `api_token =literal`, `api_token= literal`,
		"api_token=a\tb", "api_token=a\rb", "api_token=a\nb", "api_token=\"a\tb\"", "api_token=\"a\rb\"", "api_token=\"a\nb\"",
		`api_token=Sentinel\Password225`, `api_token="Sentinel\nPassword225"`,
		`api_token=Sent{#abc#}inel`, `api_token='{{ "Sentinel" }}'`, `api_token='{% if true %}Sentinel{% endif %}'`,
	)
	raw, err := json.Marshal(payloads)
	if err != nil {
		t.Fatal(err)
	}
	program := `import json, sys
from ansible.parsing.splitter import parse_kv
results=[]
for raw in json.load(sys.stdin):
    try:
        results.append(parse_kv(raw))
    except Exception:
        results.append(None)
json.dump(results, sys.stdout)`
	output := run(program, raw)
	var native []map[string]string
	if err := json.Unmarshal(output, &native); err != nil {
		t.Fatal(err)
	}
	if len(native) != len(payloads) {
		t.Fatalf("native batch returned %d of %d inputs", len(native), len(payloads))
	}
	admitted := 0
	generatedAdmitted := 0
	for i, payload := range payloads {
		fields, ok := splitInlineVars(payload)
		if !ok {
			continue
		}
		admitted++
		if i < generated {
			generatedAdmitted++
		}
		actual := map[string]string{}
		for _, field := range fields {
			key, value, _ := strings.Cut(field, "=")
			actual[key] = value
		}
		if !reflect.DeepEqual(actual, native[i]) {
			t.Fatalf("Go admitted native grammar discrepancy for %q: Go=%q native=%q", payload, actual, native[i])
		}
	}
	if generated != 78124 || generatedAdmitted != 1334 {
		t.Fatalf("bounded grammar corpus changed: generated=%d admitted=%d (want 78124/1334)", generated, generatedAdmitted)
	}
	t.Logf("actual Go/native parse_kv: generated=%d admitted=%d; extra cases=%d total admitted=%d discrepancies=0", generated, generatedAdmitted, len(payloads)-generated, admitted)
}
