package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureClosure(t *testing.T) *Closure {
	t.Helper()
	c, err := ComputeClosure(ClosureInput{
		Root:      filepath.Join("testdata", "closure"),
		Playbooks: []string{"playbooks/site.yml"},
		Specs:     []string{"docs/verification/demo.md"},
		ExtraArgs: []string{"-e", "@vaultdir/sandbox.yaml", "-e", "@/outside/the/repo/vault.yaml", "-e", "target_group=all"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func closurePaths(c *Closure) map[string]File {
	out := map[string]File{}
	for _, f := range c.Files {
		out[f.Path] = f
	}
	return out
}

func TestComputeClosureFollowsEveryStaticReference(t *testing.T) {
	files := closurePaths(fixtureClosure(t))
	for _, want := range []string{
		"playbooks/site.yml",
		"playbooks/apply/demo-apply.yml",            // import_playbook
		"playbooks/test/fixtures/demo-fixtures.yml", // second import_playbook
		"playbooks/apply/vars/demo.yml",             // vars_files
		"playbooks/apply/tasks/helpers.yml",         // include_tasks with file: + apply:
		"playbooks/apply/tasks/helpers-inner.yml",   // include inside an included file, relative to it
		"playbooks/apply/templates/demo.conf.j2",    // template src via templates/
		"playbooks/apply/files/rules/a.conf",        // copy src: directory
		"playbooks/apply/files/rules/b.conf",        //
		"playbooks/apply/files/helper.sh",           // script free-form first word
		"playbooks/apply/files/banner.txt",          // lookup('file', ...)
		"playbooks/apply/tasks/nested.yml",          // import_tasks inside a block
		"playbooks/apply/files/rescue.sh",           // script cmd: inside rescue
		"docs/verification/demo.md",                 // the spec
		"vaultdir/sandbox.yaml",                     // -e @file inside the repo
		"contracts/demo.yaml",                       // contract named like the spec
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("closure lacks %s", want)
		}
	}
	if _, ok := files["playbooks/apply/files/unused.sh"]; ok {
		t.Error("an unreferenced file must not be in the closure")
	}
	if f := files["playbooks/apply/files/helper.sh"]; f.Mode != "100755" {
		t.Errorf("executable helper mode = %s", f.Mode)
	}
	if f := files["playbooks/apply/tasks/nested.yml"]; f.Mode != "100644" || f.Blob != GitBlobOID([]byte("- name: nested\n")) || f.Size != 15 {
		t.Errorf("nested.yml = %+v", f)
	}
}

func TestComputeClosureTemplatedIncludesBecomeGlobs(t *testing.T) {
	c := fixtureClosure(t)
	files := closurePaths(c)
	for _, want := range []string{"playbooks/apply/tasks/distro-debian.yml", "playbooks/apply/tasks/distro-redhat.yml"} {
		f, ok := files[want]
		if !ok || !f.Dynamic {
			t.Errorf("%s should be listed as a dynamic match: %+v", want, f)
		}
	}
	var missing, variable bool
	for _, u := range c.Unresolved {
		if u.Ref == "tasks/does-not-exist.yml" && u.From == "playbooks/apply/demo-apply.yml" {
			missing = true
		}
		if u.Ref == "{{ demo_roster_file }}" && strings.Contains(u.Reason, "variable") {
			variable = true
		}
	}
	if !missing {
		t.Errorf("the missing include must be reported as unresolved: %+v", c.Unresolved)
	}
	if !variable {
		t.Errorf("a wildcard-only reference must be reported, not matched as a whole directory: %+v", c.Unresolved)
	}
	if _, ok := files["playbooks/apply/files/unused.sh"]; ok {
		t.Error("the variable reference must not pull the directory in")
	}
	if n := len(files); n > 20 {
		t.Errorf("closure has %d files; a wildcard-only reference was expanded", n)
	}
	if len(c.External) != 1 || !strings.HasSuffix(c.External[0], "/outside/the/repo/vault.yaml") {
		t.Errorf("external = %v", c.External)
	}
}

func TestComputeClosureIsSortedAndDeduplicated(t *testing.T) {
	c := fixtureClosure(t)
	seen := map[string]bool{}
	for i, f := range c.Files {
		if seen[f.Path] {
			t.Fatalf("duplicate %s", f.Path)
		}
		seen[f.Path] = true
		if i > 0 && c.Files[i-1].Path > f.Path {
			t.Fatalf("not sorted at %s", f.Path)
		}
	}
}

func TestClosureRecordsSearchMembershipIncludingMisses(t *testing.T) {
	c := fixtureClosure(t)
	patterns := map[string]bool{}
	for _, p := range c.Patterns {
		patterns[p] = true
	}
	for _, want := range []string{
		"playbooks/apply/tasks/distro-*.yml",
		"playbooks/apply/files/rules/**",
		"playbooks/apply/tasks/does-not-exist.yml",
		"contracts/demo.yaml", "ansible.cfg", "requirements.yml",
	} {
		if !patterns[want] {
			t.Errorf("missing searched pattern %s: %v", want, c.Patterns)
		}
	}
}

func TestComputeClosureRejectsAMissingPlaybook(t *testing.T) {
	if _, err := ComputeClosure(ClosureInput{Root: filepath.Join("testdata", "closure"), Playbooks: []string{"playbooks/nope.yml"}}); err == nil {
		t.Fatal("expected an error for a missing playbook")
	}
}

func TestExtraVarsFiles(t *testing.T) {
	got := extraVarsFiles([]string{"-e", "@a.yml", "-e=@b.yml", "--extra-vars", "@c.yml", "--extra-vars=@d.yml", "-e", "k=v", "-e@e.yml", "-i", "inv"})
	want := []string{"a.yml", "b.yml", "c.yml", "d.yml", "e.yml"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v", got)
	}
}

func TestClosureFileExpressionsNeverDisappear(t *testing.T) {
	cases := []struct {
		name, expression string
		unresolved       bool
	}{
		{"lookup variable", "{{ lookup('file', input_path) }}", true},
		{"query variable", "{{ query('file', input_path) }}", true},
		{"query literal", "{{ query('file', 'input.txt') }}", false},
		{"lookup play vars", "{{ lookup('file', 'input.txt') }}", false},
		{"lookup multiple terms", "{{ lookup('file', 'input.txt', 'other.txt') }}", true},
		{"lookup transformed path", "{{ lookup('file', 'input.txt' ~ suffix) }}", true},
		{"dynamic plugin", "{{ lookup(plugin_name, 'input.txt') }}", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, raw := range map[string]string{
				"play.yml":        "- hosts: all\n  vars:\n    value: \"" + tc.expression + "\"\n  tasks: []\n",
				"files/input.txt": "original input\n", "files/other.txt": "second\n",
			} {
				writeClosureFile(t, root, name, raw)
			}
			c, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.unresolved {
				if len(c.Unresolved) == 0 {
					t.Fatalf("unsupported reading expression was silently omitted: %+v", c)
				}
			} else if _, ok := closurePaths(c)["files/input.txt"]; !ok || len(c.Unresolved) != 0 {
				t.Fatalf("literal input was not captured: %+v", c)
			}
		})
	}
}

func writeClosureFile(t *testing.T, root, name, raw string) {
	t.Helper()
	abs := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestClosureLoadedInputsAndImplicitVars(t *testing.T) {
	root := t.TempDir()
	for name, raw := range map[string]string{
		"play.yml":           "- hosts: all\n  vars_files: [vars/settings.yml]\n  tasks:\n    - template: {src: outer.j2, dest: /tmp/out}\n",
		"vars/settings.yml":  `value: "{{ lookup('file', input_path) }}"`,
		"templates/outer.j2": `{{ query('file', nested_input) }}`,
		"group_vars/all":     "feature: enabled\n",
		"host_vars/host.yml": "mode: test\n",
		"topology.yaml":      "nodes: []\n",
	} {
		writeClosureFile(t, root, name, raw)
	}
	c, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}, Inputs: []string{"topology.yaml"}})
	if err != nil {
		t.Fatal(err)
	}
	paths := closurePaths(c)
	for _, path := range []string{"vars/settings.yml", "templates/outer.j2", "group_vars/all", "host_vars/host.yml", "topology.yaml"} {
		if _, ok := paths[path]; !ok {
			t.Errorf("missing execution input %s", path)
		}
	}
	unresolved := map[string]bool{}
	for _, ref := range c.Unresolved {
		unresolved[ref.From] = true
	}
	for _, path := range []string{"vars/settings.yml", "templates/outer.j2"} {
		if !unresolved[path] {
			t.Errorf("file-reading expression in %s was silently omitted: %+v", path, c)
		}
	}
	for _, want := range []string{"group_vars/**", "host_vars/**"} {
		if !strings.Contains(strings.Join(c.Patterns, "\n"), want) {
			t.Errorf("missing implicit membership %s", want)
		}
	}
}

func TestClosureReadsImplicitWhenExpressions(t *testing.T) {
	root := t.TempDir()
	writeClosureFile(t, root, "play.yml", "- hosts: all\n  tasks:\n    - debug: {msg: hello}\n      when: lookup('file', input_path) == 'enabled'\n")
	c, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Unresolved) == 0 {
		t.Fatalf("implicit Ansible expression silently omitted: %+v", c)
	}
}

func TestClosureConfigurationAndSymlinksFailClosed(t *testing.T) {
	root := t.TempDir()
	writeClosureFile(t, root, "play.yml", "- hosts: all\n  tasks:\n    - copy: {src: linked.txt, dest: /tmp/out}\n")
	writeClosureFile(t, root, "ansible.cfg", "[defaults]\nlookup_plugins=/outside/plugins\n")
	writeClosureFile(t, root, "input.txt", "input\n")
	if err := os.Symlink("input.txt", filepath.Join(root, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	c, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}})
	if err != nil {
		t.Fatal(err)
	}
	unresolved := map[string]bool{}
	for _, ref := range c.Unresolved {
		unresolved[ref.Ref] = true
	}
	if !unresolved["ansible.cfg"] || !unresolved["linked.txt"] {
		t.Fatalf("unsupported configuration/symlink claims complete resolution: %+v", c)
	}
}

func TestClosureInlineExpressionsCannotClaimCompleteResolution(t *testing.T) {
	root := t.TempDir()
	writeClosureFile(t, root, "play.yml", "- hosts: all\n  tasks: []\n")
	const sentinel = "InlineClosureSentinel225"
	payloads := []string{
		`value="{{ lookup('file', 'input.txt') }}" api_token=` + sentinel,
		`value="{{ query('file', 'input.txt') }}" api_token=` + sentinel,
		`value="{{ q('file', input_path) }}" api_token=` + sentinel,
		`{"value":"{{ lookup('file', 'input.txt') }}","api_token":"` + sentinel + `"}`,
		`value="{% include 'input.txt' %}" api_token=` + sentinel,
		`{"value":"\u007b\u007b \u006cookup('file', 'input.txt') }}","api_token":"` + sentinel + `"}`,
	}
	forms := []func(string) []string{
		func(v string) []string { return []string{"-e", v} },
		func(v string) []string { return []string{"-e" + v} },
		func(v string) []string { return []string{"-e=" + v} },
		func(v string) []string { return []string{"--extra-vars", v} },
		func(v string) []string { return []string{"--extra-vars=" + v} },
	}
	for i, payload := range payloads {
		for j, form := range forms {
			t.Run(fmt.Sprintf("payload%d-form%d", i, j), func(t *testing.T) {
				closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}, ExtraArgs: form(payload)})
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
					t.Fatalf("inline runtime input silently omitted: %+v", closure)
				}
				raw, _ := json.Marshal(closure)
				if strings.Contains(string(raw), sentinel) || strings.Contains(string(raw), "input.txt") {
					t.Fatalf("inline payload leaked to closure metadata: %s", raw)
				}
			})
		}
	}
	closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}, ExtraArgs: []string{"-e", "target_group=all api_token=" + sentinel}})
	if err != nil {
		t.Fatal(err)
	}
	if len(closure.Unresolved) != 0 {
		t.Fatalf("plain literal inline vars unnecessarily unresolved: %+v", closure)
	}
}
