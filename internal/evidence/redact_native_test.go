package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise actual Ansible binding, callback output, scan completeness, persisted
// metadata sanitization and closure refusal together. A parser-only test cannot
// prove that the runtime value is the one the scanner knows.
func TestEvidenceNativeAnsibleSecretGrammar(t *testing.T) {
	bin, err := exec.LookPath("ansible-playbook")
	if err != nil {
		if os.Getenv("PILOT_REQUIRE_ANSIBLE_EVIDENCE_TESTS") == "1" {
			t.Fatal(err)
		}
		t.Skip("ansible-playbook unavailable")
	}
	type arm struct {
		name, payload, want string
		unsupported         bool
		yamlUnsupported     bool
		scalarUnsupported   bool
		file                bool
	}
	var arms []arm
	for _, v := range []struct{ name, raw, want string }{
		{"unknown", `Sentinel\Password225`, `Sentinel\Password225`},
		{"double-slash", `Sentinel\\Password225`, `Sentinel\Password225`},
		{"newline", `Sentinel\nPassword225`, "Sentinel\nPassword225"},
		{"tab", `Sentinel\tPassword225`, "Sentinel\tPassword225"},
	} {
		for _, q := range []struct{ name, quote string }{{"bare", ""}, {"single", "'"}, {"double", "\""}} {
			arms = append(arms, arm{name: v.name + "/" + q.name, payload: "api_token=" + q.quote + v.raw + q.quote, want: v.want, unsupported: true})
		}
		raw, err := json.Marshal(map[string]string{"api_token": v.want})
		if err != nil {
			t.Fatal(err)
		}
		arms = append(arms, arm{name: v.name + "/json", payload: string(raw), want: v.want})
	}
	for _, v := range []struct{ raw, want string }{{"yes", "true"}, {"Yes", "true"}, {"YES", "true"}, {"on", "true"}, {"On", "true"}, {"ON", "true"}, {"no", "false"}, {"No", "false"}, {"NO", "false"}, {"off", "false"}, {"Off", "false"}, {"OFF", "false"}, {"'YES'", "YES"}, {"\"off\"", "off"}, {"!!str YES", "YES"}} {
		arms = append(arms, arm{name: "yaml/" + v.raw, payload: "api_token: " + v.raw + "\n", want: v.want, file: true})
	}
	for _, v := range []struct{ raw, want string }{{"1:20", "80"}, {"1:20:30", "4830"}, {"1:20.5", "80.5"}} {
		arms = append(arms, arm{name: "yaml-sexagesimal/" + v.raw, payload: "api_token: " + v.raw + "\n", want: v.want, file: true, yamlUnsupported: true})
	}
	for _, v := range []struct {
		raw, want   string
		unsupported bool
	}{
		{"y", "y", false}, {"Y", "Y", false}, {"n", "n", false}, {"N", "N", false},
		{"0123", "83", false}, {"0o123", "0o123", false}, {"0x11", "17", false}, {"1_000", "1000", false},
		{"1e3", "1e3", true}, {"1.0e+3", "1000.0", true}, {"1.0e3", "1.0e3", true},
		{"null", "null", true}, {"~", "null", true},
		{".inf", "Infinity", true}, {".nan", "NaN", true}, {"2026-11-01", "2026-11-01", true}, {"2026-11-01T12:00:00Z", "2026-11-01T12:00:00+00:00", true},
	} {
		arms = append(arms, arm{name: "yaml-types/" + v.raw, payload: "api_token: " + v.raw + "\n", want: v.want, file: true, scalarUnsupported: v.unsupported})
	}
	for _, a := range arms {
		t.Run(a.name, func(t *testing.T) {
			root := t.TempDir()
			pb := filepath.Join(root, "apply.yml")
			oracle := filepath.Join(root, "bound.txt")
			playbook := "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug:\n        msg: '{{ api_token }}'\n    - ansible.builtin.copy:\n        content: '{{ api_token | to_json }}'\n        dest: '{{ oracle_path }}'\n        mode: '0600'\n"
			if err := os.WriteFile(pb, []byte(playbook), 0600); err != nil {
				t.Fatal(err)
			}
			payload := a.payload
			if a.file {
				payload = "@vars.yml"
				if err := os.WriteFile(filepath.Join(root, "vars.yml"), []byte(a.payload), 0600); err != nil {
					t.Fatal(err)
				}
			}
			extra := []string{"-e", payload, "-e", "oracle_path=" + oracle}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			argv := append([]string{"-i", "localhost,", "-c", "local", pb}, extra...)
			cmd := exec.CommandContext(ctx, bin, argv...)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+filepath.Join(root, "ansible-tmp"), "ANSIBLE_REMOTE_TEMP="+filepath.Join(root, "remote-tmp"), "ANSIBLE_NOCOLOR=1", "ANSIBLE_FORCE_COLOR=0")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("native Ansible failed: %v\n%s", err, output)
			}
			bound, err := os.ReadFile(oracle)
			if err != nil {
				t.Fatal(err)
			}
			var effective any
			if err := json.Unmarshal(bound, &effective); err != nil {
				if !a.scalarUnsupported || (string(bound) != "Infinity" && string(bound) != "NaN") {
					t.Fatalf("native oracle is not JSON: %q: %v", bound, err)
				}
			}
			value, ok := effective.(string)
			if !ok {
				value = string(bound)
			}
			if value != a.want {
				t.Fatalf("native binding = %q, want %q\n%s", bound, a.want, output)
			}
			t.Logf("native rc=0; effective value=%q; callback=%s", bound, output)
			sources, skipped := SecretSources(root, extra)
			red := Redact(map[string]string{"native": string(output)}, sources, skipped)
			record := publicationRecord("a", "success")
			record.Redaction = red
			record.Command = RedactCommandLine(extra)
			if a.unsupported {
				if len(sources) != 0 || len(skipped) != 1 || skipped[0] != "inline extra-vars (backslash escape syntax not scanned)" {
					t.Fatalf("unsupported native escape grammar falsely scanned as complete: sources=%d skipped=%v", len(sources), skipped)
				}
				closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"apply.yml"}, ExtraArgs: extra})
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, ref := range closure.Unresolved {
					if ref.From == "extra-vars" && ref.Ref == "inline extra-vars expression" {
						found = true
					}
				}
				if !found {
					t.Fatal("unsupported native escape grammar missing explicit inline closure refusal")
				}
				encoded, err := json.Marshal(closure)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), "Sentinel") {
					t.Fatal("closure refusal disclosed unsupported payload")
				}
				rendered, err := record.Markdown(nil)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(rendered), "**INCOMPLETE**") || strings.Contains(string(rendered), "Sentinel") {
					t.Fatalf("human/machine summary hides skipped native grammar or leaks payload: %s", rendered)
				}
			} else if a.scalarUnsupported {
				if len(skipped) == 0 {
					t.Fatal("unproved YAML native scalar falsely complete")
				}
				rendered, err := record.Markdown(nil)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(rendered), "**INCOMPLETE**") {
					t.Fatal("unproved YAML scalar missing completeness warning")
				}
			} else if a.yamlUnsupported {
				if len(skipped) != 1 || skipped[0] != "YAML 1.1 sexagesimal secret scalar (runtime value not scanned)" {
					t.Fatalf("unsupported YAML effective secret falsely complete: %v", skipped)
				}
				rendered, err := record.Markdown(nil)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(rendered), "**INCOMPLETE**") {
					t.Fatal("YAML native scalar refusal missing human completeness warning")
				}
			} else {
				if len(skipped) != 0 || len(red.Hits) == 0 {
					t.Fatalf("native callback disclosure falsely clean: sources=%d skipped=%v hits=%v\n%s", len(sources), skipped, red.Hits, output)
				}
				record.Error = "native value: " + a.want
				record.Operator = a.want
				record.Steps = []Step{{Note: a.want}}
				if err := SanitizeRecord(record, sources); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(record.Error, a.want) || strings.Contains(record.Operator, a.want) || strings.Contains(record.Steps[0].Note, a.want) {
					t.Fatal("native effective secret survived persisted metadata sanitization")
				}
			}
			if !strings.Contains(string(output), "PLAY RECAP") {
				t.Fatal("native callback did not complete")
			}
		})
	}
}

func TestEvidenceNativeYAMLBooleanForms(t *testing.T) {
	// Fast discriminating control for the YAML 1.1 boundary, including inherited
	// container secrecy and the quoted/explicit-string positive controls.
	root := t.TempDir()
	content := "credentials:\n  value: YES\npassword:\n  - value: off\nquoted_token: 'YES'\nexplicit_token: !!str off\n"
	if err := os.WriteFile(filepath.Join(root, "vars.yml"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	sources, skipped := SecretSources(root, []string{"-e", "@vars.yml"})
	if len(skipped) != 0 {
		t.Fatal(skipped)
	}
	for _, value := range []string{"true", "True", "false", "False", "YES", "off"} {
		if len(Scan(map[string]string{"native": fmt.Sprint(value)}, sources)) == 0 {
			t.Fatalf("YAML 1.1 effective secret %q falsely clean", value)
		}
	}
}
