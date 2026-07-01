package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractTargetFlag(t *testing.T) {
	cases := []struct {
		name     string
		in       []string
		wantVal  string
		wantRest []string
	}{
		{"separate --target", []string{"--target", "core", "ls"}, "core", []string{"ls"}},
		{"joined --target=", []string{"--target=core", "ls"}, "core", []string{"ls"}},
		{"separate --name", []string{"--name", "core", "ls"}, "core", []string{"ls"}},
		{"joined --name=", []string{"--name=core", "ls"}, "core", []string{"ls"}},
		{"not present", []string{"ls", "-l"}, "", []string{"ls", "-l"}},
		{"empty", []string{}, "", []string{}},
		{"--target with no value", []string{"--target"}, "", []string{"--target"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := append([]string(nil), tc.in...)
			gotVal, gotRest := extractTargetFlag(tc.in)
			if gotVal != tc.wantVal {
				t.Errorf("val=%q want %q", gotVal, tc.wantVal)
			}
			if !equalStrings(gotRest, tc.wantRest) {
				t.Errorf("rest=%v want %v", gotRest, tc.wantRest)
			}
			if !equalStrings(tc.in, orig) {
				t.Errorf("extractTargetFlag mutated caller's args: in=%v orig=%v", tc.in, orig)
			}
		})
	}
}

func TestKindFromStateFile(t *testing.T) {
	tmp := t.TempDir()
	state := func(name, key string) string {
		return `{"version":1,"targets":[{"` + key + `":"` + name + `","status":"running"}]}`
	}
	dtPath := filepath.Join(tmp, "docker-targets.json")
	vmPath := filepath.Join(tmp, "vm-targets.json")
	if err := os.WriteFile(dtPath, []byte(state("alpha", "hostname")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vmPath, []byte(state("alpha", "name")), 0o644); err != nil {
		t.Fatal(err)
	}
	dockerKind, err := kindFromStateFile(dtPath, "alpha", "hostname")
	if err != nil || dockerKind != "docker" {
		t.Errorf("docker lookup: kind=%q err=%v", dockerKind, err)
	}
	vmKind, err := kindFromStateFile(vmPath, "alpha", "name")
	if err != nil || vmKind != "vm" {
		t.Errorf("vm lookup: kind=%q err=%v", vmKind, err)
	}
	missingKind, err := kindFromStateFile(filepath.Join(tmp, "nope.json"), "alpha", "name")
	if err != nil || missingKind != "" {
		t.Errorf("missing state: kind=%q err=%v", missingKind, err)
	}
	wrongKind, err := kindFromStateFile(vmPath, "not-alpha", "name")
	if err != nil || wrongKind != "" {
		t.Errorf("wrong name: kind=%q err=%v", wrongKind, err)
	}
	badPath := filepath.Join(tmp, "bad.json")
	if err := os.WriteFile(badPath, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	badKind, err := kindFromStateFile(badPath, "alpha", "name")
	if err != nil || badKind != "" {
		t.Errorf("bad json: kind=%q err=%v", badKind, err)
	}
}

func TestSplitWrapperArgs_RealisticVerify(t *testing.T) {
	p, extra, err := splitWrapperArgs([]string{
		"--target", "core",
		"--spec", "docs/verification/core-infra-provider.md",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.target != "core" {
		t.Errorf("target=%q want core", p.target)
	}
	if p.spec != "docs/verification/core-infra-provider.md" {
		t.Errorf("spec=%q", p.spec)
	}
	if len(extra) != 0 {
		t.Errorf("extra=%v want []", extra)
	}
}

func TestSplitWrapperArgs_RealisticRun(t *testing.T) {
	p, extra, err := splitWrapperArgs([]string{
		"--target", "core",
		"--playbook", "playbooks/apply/x.yml",
		"--role", "dns",
		"--", "-e", "foo=bar", "--check",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.target != "core" || p.playbook != "playbooks/apply/x.yml" || p.role != "dns" {
		t.Errorf("parsed=%+v", p)
	}
	if !equalStrings(extra, []string{"-e", "foo=bar", "--check"}) {
		t.Errorf("extra=%v", extra)
	}
}

func TestSplitWrapperArgs_PositionalPlaybook(t *testing.T) {
	p, _, err := splitWrapperArgs([]string{
		"--target", "core",
		"playbooks/apply/x.yml",
		"--role", "dns",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.playbook != "playbooks/apply/x.yml" {
		t.Errorf("playbook=%q", p.playbook)
	}
	if p.role != "dns" {
		t.Errorf("role=%q", p.role)
	}
}

func TestBackendTakesName(t *testing.T) {
	with := []string{"up", "down", "run", "verify", "exec", "ssh", "shell", "snapshot", "rollback"}
	without := []string{"list", "show-inventory"}
	for _, s := range with {
		if !backendTakesName(s) {
			t.Errorf("backendTakesName(%q) = false, want true", s)
		}
	}
	for _, s := range without {
		if backendTakesName(s) {
			t.Errorf("backendTakesName(%q) = true, want false", s)
		}
	}
}

func TestTargetCmdRegistered(t *testing.T) {
	var found bool
	for _, c := range rootCmd.Commands() {
		if c.Name() == "target" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("target subcommand not registered on rootCmd")
	}
}

func TestTargetSubCommandsAllRegistered(t *testing.T) {
	want := []string{"up", "down", "list", "run", "verify", "exec", "ssh", "shell", "snapshot", "rollback"}
	var have []string
	for _, c := range targetCmd.Commands() {
		have = append(have, c.Name())
	}
	for _, w := range want {
		ok := false
		for _, h := range have {
			if h == w {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("subcommand %q missing; have %v", w, have)
		}
	}
}

func TestSplitWrapperArgs_KeyValueFlag(t *testing.T) {
	_, extra, err := splitWrapperArgs([]string{"--target", "core", "--foo", "bar", "-x"})
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(extra, []string{"--foo", "bar", "-x"}) {
		t.Errorf("extra=%v", extra)
	}
}

func TestSplitWrapperArgs_JoinedFlag(t *testing.T) {
	_, extra, err := splitWrapperArgs([]string{"--target", "core", "--foo=bar"})
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(extra, []string{"--foo=bar"}) {
		t.Errorf("extra=%v", extra)
	}
}

func TestSplitWrapperArgs_TargetOnlyAfterSpec(t *testing.T) {
	p, _, err := splitWrapperArgs([]string{
		"--spec", "docs/...md",
		"--target", "core",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.target != "core" || p.spec != "docs/...md" {
		t.Errorf("parsed=%+v", p)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
