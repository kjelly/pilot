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
		{"query literal", "{{ query('file', 'input.txt') }}", true},
		{"lookup play vars", "{{ lookup('file', 'input.txt') }}", true},
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
			if tc.name == "query literal" || tc.name == "lookup play vars" {
				if _, ok := closurePaths(c)["files/input.txt"]; !ok {
					t.Fatal("known literal dependency must still be hashed even when expressions prevent reuse")
				}
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

func TestClosureDispatchHasAnExplicitSafeSubset(t *testing.T) {
	cases := []struct {
		name, play string
		wantInput  bool
		unresolved bool
	}{
		{"direct copy", "- hosts: all\n  tasks:\n    - copy: {src: payload.txt, dest: /tmp/out}\n", true, false},
		{"direct template", "- hosts: all\n  tasks:\n    - ansible.builtin.template: {src: payload.txt, dest: /tmp/out}\n", true, false},
		{"action scalar", "- hosts: all\n  tasks:\n    - action: copy src=payload.txt dest=/tmp/out api_token=DispatchSecretSentinel225\n", false, true},
		{"action mapping", "- hosts: all\n  tasks:\n    - action: {module: copy, src: payload.txt, dest: /tmp/out}\n", false, true},
		{"local action scalar", "- hosts: all\n  tasks:\n    - local_action: copy src=payload.txt dest=/tmp/out\n", false, true},
		{"local action mapping", "- hosts: all\n  tasks:\n    - local_action: {module: copy, src: payload.txt, dest: /tmp/out}\n", false, true},
		{"args augmentation", "- hosts: all\n  tasks:\n    - copy:\n      args: {src: payload.txt, dest: /tmp/out}\n", false, true},
		{"non scalar source", "- hosts: all\n  tasks:\n    - copy: {src: [payload.txt], dest: /tmp/out}\n", false, true},
		{"null source", "- hosts: all\n  tasks:\n    - copy: {src: null, dest: /tmp/out}\n", false, true},
		{"free form copy", "- hosts: all\n  tasks:\n    - copy: src=payload.txt dest=/tmp/out\n", true, true},
		{"legacy copy", "- hosts: all\n  tasks:\n    - ansible.legacy.copy: {src: payload.txt, dest: /tmp/out}\n", false, true},
		{"custom module", "- hosts: all\n  tasks:\n    - custom_reader: {source: payload.txt}\n", false, true},
		{"other collection module", "- hosts: all\n  tasks:\n    - example.reader.read: {source: payload.txt}\n", false, true},
		{"builtin file reader outside subset", "- hosts: all\n  tasks:\n    - ansible.builtin.synchronize: {src: payload.txt, dest: /tmp/out}\n", false, true},
		{"controller shell inherited context", "- hosts: all\n  connection: local\n  tasks:\n    - shell: cat payload.txt\n", false, true},
		{"command", "- hosts: all\n  tasks:\n    - command: cat payload.txt\n", false, true},
		{"raw", "- hosts: all\n  tasks:\n    - raw: cat payload.txt\n", false, true},
		{"unknown with reader", "- hosts: all\n  tasks:\n    - debug: {msg: test}\n      with_filetree: payload.txt\n", false, true},
		{"module defaults", "- hosts: all\n  module_defaults: {copy: {src: payload.txt}}\n  tasks:\n    - copy: {content: literal, dest: /tmp/out}\n", false, true},
		{"collections", "- hosts: all\n  collections: [example.reader]\n  tasks:\n    - copy: {content: literal, dest: /tmp/out}\n", false, true},
		{"validation executable", "- hosts: all\n  tasks:\n    - copy: {src: payload.txt, dest: /tmp/out, validate: 'cat omitted.txt %s'}\n", true, true},
		{"delegated script", "- hosts: all\n  tasks:\n    - script: payload.txt\n      delegate_to: localhost\n", true, true},
		{"script arbitrary sibling input", "- hosts: all\n  tasks:\n    - script: payload.txt\n", true, true},
		{"aliased source mapping", "- hosts: all\n  vars:\n    copy_args: &copy_args {src: payload.txt, dest: /tmp/out}\n  tasks:\n    - copy: *copy_args\n", false, true},
		{"merged source mapping", "- hosts: all\n  vars:\n    copy_args: &copy_args {src: payload.txt}\n  tasks:\n    - copy:\n        <<: *copy_args\n        dest: /tmp/out\n", false, true},
		{"aliased vars files", "- hosts: all\n  vars: {files: &files [payload.txt]}\n  vars_files: *files\n  tasks: []\n", false, true},
		{"import mapping layout", "- import_playbook: {file: payload.txt}\n", false, true},
		{"aliased import", "- vars: {import: &import payload.txt}\n  import_playbook: *import\n", false, true},
		{"nested vars files alternatives", "- hosts: all\n  vars_files: [[payload.txt, missing.txt]]\n  tasks: []\n", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeClosureFile(t, root, "play.yml", tc.play)
			writeClosureFile(t, root, "payload.txt", "#!/bin/sh\ncat omitted.txt\n")
			writeClosureFile(t, root, "omitted.txt", "opaque input\n")
			closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantInput {
				if _, ok := closurePaths(closure)["payload.txt"]; !ok {
					t.Fatalf("supported reader source omitted: %+v", closure)
				}
			}
			if tc.unresolved != (len(closure.Unresolved) > 0) {
				t.Fatalf("unsupported dispatch omitted input without refusal: %+v", closure)
			}
			raw, _ := json.Marshal(closure)
			if strings.Contains(string(raw), "DispatchSecretSentinel225") {
				t.Fatalf("dispatch payload leaked: %s", raw)
			}
		})
	}
}

func TestClosureCustomCodeAndForwardedDispatchOptionsRefuseReuse(t *testing.T) {
	t.Run("custom action code may read another input", func(t *testing.T) {
		root := t.TempDir()
		writeClosureFile(t, root, "play.yml", "- hosts: all\n  tasks: [{debug: {msg: hello}}]\n")
		writeClosureFile(t, root, "action_plugins/reader.py", "value = open('omitted.txt').read()\n")
		writeClosureFile(t, root, "omitted.txt", "custom input\n")
		closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := closurePaths(closure)["action_plugins/reader.py"]; !ok {
			t.Fatal("custom code hash omitted")
		}
		if len(closure.Unresolved) == 0 {
			t.Fatalf("custom code omitted dependency claims complete closure: %+v", closure)
		}
	})
	for _, args := range [][]string{{"-M", "modules"}, {"--module-path=modules"}, {"-i", "inventory.yaml"}, {"--vault-password-file", "password-helper"}, {"--tags", "C1"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := t.TempDir()
			writeClosureFile(t, root, "play.yml", "- hosts: all\n  tasks: []\n")
			closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}, ExtraArgs: args})
			if err != nil {
				t.Fatal(err)
			}
			if len(closure.Unresolved) != 1 || closure.Unresolved[0].Ref != "forwarded Ansible options" {
				t.Fatalf("forwarded dispatch path omitted: %+v", closure)
			}
		})
	}
}

func TestClosureIncludedExecutionRequiresFullSearchContext(t *testing.T) {
	root := t.TempDir()
	for name, raw := range map[string]string{
		"play.yml":              "- hosts: all\n  tasks:\n    - import_tasks: sub/parent.yml\n",
		"sub/parent.yml":        "- include_tasks: inner/child.yml\n",
		"sub/inner/child.yml":   "- copy: {src: payload.txt, dest: /tmp/out}\n",
		"sub/files/payload.txt": "intermediate include input\n",
		"files/payload.txt":     "top-level fallback\n",
	} {
		writeClosureFile(t, root, name, raw)
	}
	closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"play.yml", "sub/parent.yml", "sub/inner/child.yml"} {
		if _, ok := closurePaths(closure)[name]; !ok {
			t.Errorf("included source hash omitted: %s", name)
		}
	}
	found := false
	for _, ref := range closure.Unresolved {
		if ref.Ref == "unsupported task dispatch" && strings.Contains(ref.Reason, "full runtime Ansible search context") {
			found = true
		}
	}
	if !found {
		t.Fatalf("two-directory fallback cannot prove full include search context: %+v", closure)
	}
}

func TestClosureNonliteralExpressionsCannotClaimFileIndependence(t *testing.T) {
	for _, condition := range []string{"when: \"'payload.txt' is file\"", "until: result.stdout == 'ready'", "changed_when: result.rc == 1", "failed_when: result.rc != 0"} {
		t.Run(condition, func(t *testing.T) {
			root := t.TempDir()
			writeClosureFile(t, root, "play.yml", "- hosts: all\n  tasks:\n    - debug: {msg: hello}\n      "+condition+"\n")
			closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, ref := range closure.Unresolved {
				if ref.Ref == "unsupported expression" {
					found = true
				}
			}
			if !found {
				t.Fatalf("nonliteral condition is not proven file independent: %+v", closure)
			}
		})
	}
	root := t.TempDir()
	writeClosureFile(t, root, "play.yml", "- hosts: all\n  tasks:\n    - assert: {that: [true]}\n      when: true\n")
	closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(closure.Unresolved) != 0 {
		t.Fatalf("literal booleans should remain supported: %+v", closure)
	}
	writeClosureFile(t, root, "play.yml", "- hosts: all\n  tasks:\n    - assert: {that: [\"'payload.txt' is file\"]}\n")
	closure, err = ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(closure.Unresolved) == 0 {
		t.Fatal("assert expression was silently ignored")
	}
}

func TestClosureInlineDispatchVariablesRefuseReuse(t *testing.T) {
	root := t.TempDir()
	writeClosureFile(t, root, "play.yml", "- hosts: all\n  tasks: [{debug: {msg: literal}}]\n")
	for _, args := range [][]string{{"-e", "ansible_connection=local"}, {"--extra-vars", `{"ansible_python_interpreter":"ContextSecretSentinel225"}`}} {
		closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"play.yml"}, ExtraArgs: args})
		if err != nil {
			t.Fatal(err)
		}
		if len(closure.Unresolved) == 0 {
			t.Fatalf("inline context variables were assumed file independent: %+v", closure)
		}
		raw, _ := json.Marshal(closure)
		if strings.Contains(string(raw), "ContextSecretSentinel225") {
			t.Fatalf("dispatch variable payload leaked: %s", raw)
		}
	}
}
