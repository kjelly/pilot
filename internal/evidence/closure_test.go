package evidence

import (
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
