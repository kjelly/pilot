package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A test-only aggregate callback repeats the native effective debug value to
// stderr. This checks both real output channels using exactly the values Ansible
// bound, rather than manufacturing expected stream text inside the Go oracle.
const grammarStderrCallback = `from ansible.plugins.callback import CallbackBase
import sys
class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'grammar_stderr'
    CALLBACK_NEEDS_ENABLED = True
    def v2_runner_on_ok(self, result):
        if result._task.action in ('debug', 'ansible.builtin.debug'):
            sys.stderr.write('native-secret-stderr:' + str(result._result.get('msg', '')) + '\n')
            sys.stderr.flush()
`

func TestEvidenceNativeQuoteAndTemplateCallbacks(t *testing.T) {
	bin, err := exec.LookPath("ansible-playbook")
	if err != nil {
		if os.Getenv("PILOT_REQUIRE_ANSIBLE_EVIDENCE_TESTS") == "1" {
			t.Fatal(err)
		}
		t.Skip("ansible-playbook unavailable")
	}
	type arm struct {
		name, payload, want    string
		unsupported, templated bool
		file                   bool
	}
	arms := []arm{
		{"embedded double", `api_token=Sent"inel"`, `Sent"inel"`, true, false, false},
		{"embedded single", `api_token=Sent'inel'`, `Sent'inel'`, true, false, false},
		{"leading double pair", `api_token="Sent"inel`, `"Sent"inel`, true, false, false},
		{"leading single pair", `api_token='Sent'inel`, `'Sent'inel`, true, false, false},
		{"middle double pair", `api_token=Se"nti"nel`, `Se"nti"nel`, true, false, false},
		{"middle single pair", `api_token=Se'nti'nel`, `Se'nti'nel`, true, false, false},
		{"mixed concatenation", `api_token='Sent'"inel"`, `'Sent'"inel"`, true, false, false},
		{"whole double opposite quote", `api_token="Sent'inel=with spaces"`, `Sent'inel=with spaces`, false, false, false},
		{"whole single opposite quote", `api_token='Sent"inel=with spaces'`, `Sent"inel=with spaces`, false, false, false},
		{"unquoted equals", `api_token=Sent=inel`, `Sent=inel`, false, false, false},
		{"raw tab", "api_token=Sent\tinel", "Sent\tinel", true, false, false},
		{"raw carriage return", "api_token=Sent\rinel", "Sent\rinel", true, false, false},
		{"raw newline", "api_token=Sent\ninel", "Sent", true, false, false},
		{"quoted key double", `"api_token"=Sentinel`, `missing`, true, false, false},
		{"quoted key single", `'api_token'=Sentinel`, `missing`, true, false, false},
		{"whole assignment double", `"api_token=Sentinel"`, `missing`, true, false, false},
		{"whole assignment single", `'api_token=Sentinel'`, `missing`, true, false, false},
		{"space before equals", `api_token =Sentinel`, `missing`, true, false, false},
	}
	for _, expr := range []struct{ name, value string }{
		{"comment", `Sent{#abc#}inel`}, {"interpolation", `{{ 'Sentinel' }}`}, {"statement", `{% if true %}Sentinel{% endif %}`},
	} {
		arms = append(arms, arm{name: expr.name + " inline", payload: `api_token="` + expr.value + `"`, want: "Sentinel", templated: true})
		encoded, err := json.Marshal(map[string]string{"api_token": expr.value})
		if err != nil {
			t.Fatal(err)
		}
		arms = append(arms, arm{name: expr.name + " json", payload: string(encoded), want: "Sentinel", templated: true})
		arms = append(arms, arm{name: expr.name + " escaped json", payload: "{" + strings.ReplaceAll(string(encoded)[1:], "{", `\u007b`), want: "Sentinel", templated: true})
		raw, _ := json.Marshal(expr.value)
		arms = append(arms, arm{name: expr.name + " yaml", payload: "api_token: " + string(raw) + "\n", want: "Sentinel", templated: true, file: true})
	}
	for _, a := range arms {
		t.Run(a.name, func(t *testing.T) {
			root := t.TempDir()
			pb := filepath.Join(root, "apply.yml")
			oracle := filepath.Join(root, "effective.json")
			if err := os.MkdirAll(filepath.Join(root, "callback_plugins"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "callback_plugins/grammar_stderr.py"), []byte(grammarStderrCallback), 0600); err != nil {
				t.Fatal(err)
			}
			playbook := "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug:\n        msg: \"{{ api_token | default('missing') }}\"\n    - ansible.builtin.copy:\n        content: \"{{ api_token | default('missing') | to_json }}\"\n        dest: '{{ oracle_path }}'\n        mode: '0600'\n"
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
			args := []string{"-e", payload, "-e", "oracle_path=" + oracle}
			argv := append([]string{"-i", "localhost,", "-c", "local", pb}, args...)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, argv...)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+filepath.Join(root, "local-tmp"), "ANSIBLE_REMOTE_TEMP="+filepath.Join(root, "remote-tmp"), "ANSIBLE_CALLBACK_PLUGINS="+filepath.Join(root, "callback_plugins"), "ANSIBLE_CALLBACKS_ENABLED=grammar_stderr", "ANSIBLE_NOCOLOR=1", "ANSIBLE_FORCE_COLOR=0")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("native callback run failed: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
			}
			raw, err := os.ReadFile(oracle)
			if err != nil {
				t.Fatal(err)
			}
			var bound string
			if err := json.Unmarshal(raw, &bound); err != nil {
				t.Fatal(err)
			}
			if bound != a.want {
				t.Fatalf("native effective=%q want=%q", bound, a.want)
			}
			if !strings.Contains(stdout.String(), "PLAY RECAP") || !strings.Contains(stderr.String(), "native-secret-stderr:"+bound) {
				t.Fatalf("native stream oracle missing callback: stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
			t.Logf("native rc=0 bound=%q stdout=%s stderr=%s", bound, stdout.String(), stderr.String())
			sources, skipped := SecretSources(root, args)
			rec := publicationRecord("a", "success")
			rec.Command = RedactCommandLine(args)
			rec.Redaction = Redact(map[string]string{"stdout": stdout.String(), "stderr": stderr.String()}, sources, skipped)
			if a.unsupported || a.templated {
				expected := "inline extra-vars (unsupported quoting or assignments)"
				if a.templated {
					expected = "templated secret value (runtime result not scanned)"
				}
				if len(skipped) != 1 || skipped[0] != expected {
					t.Fatalf("unproved native quote/template grammar falsely complete: sources=%d skipped=%v", len(sources), skipped)
				}
				closure, err := ComputeClosure(ClosureInput{Root: root, ExtraArgs: args})
				if err != nil {
					t.Fatal(err)
				}
				if !a.file {
					assertInlineGrammarRefusal(t, closure)
				} else {
					found := false
					for _, ref := range closure.Unresolved {
						if ref.From == "vars.yml" && ref.Ref == "unsupported expression" {
							found = true
						}
					}
					if !found {
						t.Fatal("native YAML template opener missing closure refusal")
					}
				}
				doc, err := rec.Markdown(nil)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(doc), "**INCOMPLETE**") {
					t.Fatal("unproved native quote/template callback falsely summarized complete")
				}
				if strings.Contains(rec.Command, "Sent") {
					t.Fatal("inline secret payload survived command redaction")
				}
			} else {
				if len(skipped) != 0 {
					t.Fatalf("native-proved whole quotes skipped: %v", skipped)
				}
				hits := map[string]bool{}
				for _, hit := range rec.Redaction.Hits {
					hits[hit.Step] = true
				}
				if !hits["stdout"] || !hits["stderr"] {
					t.Fatalf("native known value missed in output channel: %v", rec.Redaction.Hits)
				}
				rec.Error = bound
				rec.Operator = bound
				rec.Steps = []Step{{Note: bound}}
				rec.Tooling = map[string]string{bound: bound}
				if err := SanitizeRecord(rec, sources); err != nil {
					t.Fatal(err)
				}
				doc, err := rec.Markdown(nil)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(doc), "Sent") {
					t.Fatalf("native known effective secret survived persisted metadata sanitization: %s", doc)
				}
			}
		})
	}
}
