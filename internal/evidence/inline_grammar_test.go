package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInlineGrammarWholeValuesAndExplicitRefusals(t *testing.T) {
	cases := []struct {
		payload string
		fields  []string
	}{
		{`api_token=abc=def`, []string{`api_token=abc=def`}},
		{` api_token="a'b=c d" target_group=all `, []string{`api_token=a'b=c d`, `target_group=all`}},
		{`api_token='a"b=c d'`, []string{`api_token=a"b=c d`}},
		{`_api_token1= key2='literal'`, []string{`_api_token1=`, `key2=literal`}},
		{`api_token=''`, []string{`api_token=`}},
		{`api_token=""`, []string{`api_token=`}},
		{`api_token=abc"def"`, nil}, {`api_token=abc'def'`, nil},
		{`api_token="abc"def`, nil}, {`api_token='abc'def`, nil},
		{`api_token="abc"'def'`, nil}, {`api_token='abc'"def"`, nil},
		{`api_token=a"b"c`, nil}, {`api_token=a'b'c`, nil},
		{`'api_token'=literal`, nil}, {`"api_token"=literal`, nil},
		{`'api_token=literal'`, nil}, {`"api_token=literal"`, nil},
		{`api_token =literal`, nil}, {`api_token= literal`, nil}, {`api_token = literal`, nil},
		{`api_token='unterminated`, nil}, {`api_token="unterminated`, nil},
		{"api_token=a\tb", nil}, {"api_token=a\rb", nil}, {"api_token=a\nb", nil},
		{"api_token='a\tb'", nil}, {"api_token='a\rb'", nil}, {"api_token='a\nb'", nil},
		{`api_token=a\b`, nil}, {`api_token='a\b'`, nil}, {`api_token="a\b"`, nil},
		{`1api_token=value`, nil}, {`api-token=value`, nil}, {`api.token=value`, nil},
	}
	root := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			fields, ok := splitInlineVars(tc.payload)
			if ok != (tc.fields != nil) || !reflect.DeepEqual(fields, tc.fields) {
				t.Fatalf("bounded quote grammar parsed %q as %q/%v; want %q", tc.payload, fields, ok, tc.fields)
			}
			forms := [][]string{{"-e", tc.payload}, {"--extra-vars", tc.payload}, {"-e" + tc.payload}, {"-e=" + tc.payload}, {"--extra-vars=" + tc.payload}}
			for _, args := range forms {
				sources, skipped := SecretSources(root, args)
				if tc.fields != nil {
					if len(skipped) != 0 {
						t.Fatalf("proved whole-value grammar was skipped: %v", skipped)
					}
					continue
				}
				if len(sources) != 0 || len(skipped) != 1 {
					t.Fatalf("unsupported quote grammar falsely complete: sources=%d skipped=%v", len(sources), skipped)
				}
				for _, note := range skipped {
					if strings.Contains(note, "api_token") || strings.Contains(note, "literal") {
						t.Fatalf("refusal contains payload: %s", note)
					}
				}
				c, err := ComputeClosure(ClosureInput{Root: root, ExtraArgs: args})
				if err != nil {
					t.Fatal(err)
				}
				assertInlineGrammarRefusal(t, c)
				rec := publicationRecord("a", "success")
				rec.Redaction = Redact(nil, sources, skipped)
				doc, err := rec.Markdown(nil)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(doc), "**INCOMPLETE**") {
					t.Fatal("unsupported quoting has no human completeness warning")
				}
			}
		})
	}
}

func assertInlineGrammarRefusal(t *testing.T, c *Closure) {
	t.Helper()
	for _, ref := range c.Unresolved {
		if ref.From == "extra-vars" && ref.Ref == "inline extra-vars expression" {
			return
		}
	}
	t.Fatal("inline grammar/expression refusal missing; ambient marker does not prove this boundary")
}

func TestAllJinjaOpenersAreRuntimeUncertainty(t *testing.T) {
	for _, value := range []string{`Sent{#abc#}inel`, `{{ 'Sentinel' }}`, `{% if true %}Sentinel{% endif %}`} {
		root := t.TempDir()
		yamlRaw, _ := json.Marshal(value) // JSON quoted scalar is valid YAML too.
		if err := os.WriteFile(filepath.Join(root, "vars.yml"), []byte("api_token: "+string(yamlRaw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(map[string]string{"api_token": value})
		escaped := "{" + strings.ReplaceAll(string(encoded)[1:], "{", `\u007b`)
		for _, payload := range []string{"api_token=\"" + strings.ReplaceAll(value, `"`, `\"`) + "\"", string(encoded), escaped, "@vars.yml"} {
			sources, skipped := SecretSources(root, []string{"-e", payload})
			if len(skipped) == 0 || !strings.Contains(strings.Join(skipped, " "), "runtime result not scanned") {
				t.Fatalf("Jinja opener omitted from secret runtime uncertainty: %q sources=%d skipped=%v", value, len(sources), skipped)
			}
			c, err := ComputeClosure(ClosureInput{Root: root, ExtraArgs: []string{"-e", payload}})
			if err != nil {
				t.Fatal(err)
			}
			if payload != "@vars.yml" {
				assertInlineGrammarRefusal(t, c)
			} else {
				found := false
				for _, ref := range c.Unresolved {
					if ref.From == "vars.yml" && ref.Ref == "unsupported expression" {
						found = true
					}
				}
				if !found {
					t.Fatal("loaded YAML Jinja opener silently omitted from closure expressions")
				}
			}
		}
		// Every YAML literal context and template text uses the same opener boundary.
		writeClosureFile(t, root, "play.yml", "- hosts: all\n  gather_facts: false\n  tasks:\n    - debug:\n        msg: "+string(yamlRaw)+"\n")
		c, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ref := range c.Unresolved {
			if ref.From == "play.yml" && ref.Ref == "unsupported expression" {
				found = true
			}
		}
		if !found {
			t.Fatal("playbook Jinja opener silently omitted")
		}
	}
}
