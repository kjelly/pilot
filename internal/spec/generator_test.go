package spec

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestGenerate_RenderYAML_MultiLineModulesAreValid is a regression test
// for the double-indentation bug: sysctl/systemd/apt tasks have
// multi-key params, and the generator used to pre-indent the
// continuation lines which RenderYAML then indented again, producing
// unparseable YAML. The whole playbook must round-trip through a YAML
// parser, and the nested keys must land at the right depth.
func TestGenerate_RenderYAML_MultiLineModulesAreValid(t *testing.T) {
	body := `# Verification Spec — multiline

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | sysctl | ip_forward | "0" | ` + "`sysctl -n net.ipv4.ip_forward`" + ` |
| C2 | service | sshd | active | ` + "`systemctl is-active sshd`" + ` |
| C3 | package | fail2ban | present | ` + "`dpkg -s fail2ban`" + ` |
`
	s, err := ParseReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	pb, err := Generate(s, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := pb.RenderYAML()

	// 1. The whole document must parse.
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(out), &plays); err != nil {
		t.Fatalf("generated YAML does not parse: %v\n--- output ---\n%s", err, out)
	}
	if len(plays) != 1 {
		t.Fatalf("want 1 play, got %d", len(plays))
	}

	// 2. The sysctl task's params must be a nested mapping with both keys.
	tasks, _ := plays[0]["tasks"].([]any)
	if len(tasks) != 3 {
		t.Fatalf("want 3 tasks, got %d", len(tasks))
	}
	sysctl, _ := tasks[0].(map[string]any)
	params, ok := sysctl["ansible.posix.sysctl"].(map[string]any)
	if !ok {
		t.Fatalf("sysctl params did not parse as a mapping: %#v", sysctl["ansible.posix.sysctl"])
	}
	// 3. The expected quotes must have been stripped: value is 0, not "0".
	if got := params["value"]; got != "0" {
		t.Errorf("sysctl value = %#v, want %q (surrounding quotes should be stripped)", got, "0")
	}
	if got := params["name"]; got != "net.ipv4.ip_forward" {
		t.Errorf("sysctl name = %#v", got)
	}
}

func TestGenerate_Dedup(t *testing.T) {
	// Three rows with the same dedup key (all "test -f /tmp/a").
	body := `# Verification Spec — dedup

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | a | present | ` + "`test -f /tmp/a`" + ` |
| C2 | file | b | present | ` + "`test -f /tmp/a`" + ` |
| C3 | file | c | present | ` + "`test -f /tmp/a`" + ` |
`
	s, err := ParseReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	pb, err := Generate(s, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pb.Tasks) != 1 {
		t.Fatalf("dedup failed: got %d tasks want=1", len(pb.Tasks))
	}
	if got, want := strings.Join(pb.Tasks[0].SourceIDs, ","), "C1,C2,C3"; got != want {
		t.Errorf("sourceIDs=%q want=%q", got, want)
	}
	// All three IDs map back to task 0.
	for _, id := range []string{"C1", "C2", "C3"} {
		if got := pb.MapIDToTask[id]; len(got) != 1 || got[0] != 0 {
			t.Errorf("MapIDToTask[%q]=%v want=[0]", id, got)
		}
	}
}

func TestGenerate_ModuleSelection(t *testing.T) {
	body := `# Verification Spec — mods

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | sshd | present | ` + "`test -f /etc/ssh/sshd_config`" + ` |
| C2 | sysctl | ip_forward | "0" | ` + "`sysctl -n net.ipv4.ip_forward`" + ` |
| C3 | service | sshd | active | ` + "`systemctl is-active sshd`" + ` |
| C4 | package | fail2ban | present | ` + "`dpkg -s fail2ban`" + ` |
| C5 | file | grep | present | ` + "`grep -E 'foo' /etc/bar`" + ` |
`
	s, _ := ParseReader(strings.NewReader(body))
	pb, _ := Generate(s, GenerateOptions{})
	if len(pb.Tasks) != 5 {
		t.Fatalf("tasks=%d want=5", len(pb.Tasks))
	}
	wants := []string{
		"ansible.builtin.stat",
		"ansible.posix.sysctl",
		"ansible.builtin.systemd",
		"ansible.builtin.apt",
		"ansible.builtin.debug", // grep → debug placeholder (no clean module match)
	}
	for i, want := range wants {
		if pb.Tasks[i].Module != want {
			t.Errorf("task[%d] module=%q want=%q", i, pb.Tasks[i].Module, want)
		}
	}
}

func TestGenerate_BecomeInference(t *testing.T) {
	body := `# Verification Spec — become

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | sshd | present | ` + "`test -f /etc/ssh/sshd_config`" + ` |
| C2 | file | homedir | present | ` + "`test -f /home/user/x`" + ` |
`
	s, _ := ParseReader(strings.NewReader(body))
	pb, _ := Generate(s, GenerateOptions{})
	if !pb.Tasks[0].Become {
		t.Error("C1 should infer become: true (path under /etc/)")
	}
	if pb.Tasks[1].Become {
		t.Error("C2 should NOT infer become: true")
	}
}

func TestGenerate_RenderYAML(t *testing.T) {
	body := `# Verification Spec — render

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | sshd | present | ` + "`test -f /etc/ssh/sshd_config`" + ` |
`
	s, _ := ParseReader(strings.NewReader(body))
	pb, _ := Generate(s, GenerateOptions{})
	out := pb.RenderYAML()
	// Spot-check the YAML: play header, gather_facts default (false), task name carries ID.
	for _, want := range []string{
		"---\n- name:",
		"hosts: localhost",
		"connection: local",
		"gather_facts: false",
		"ansible.builtin.stat:",
		"path: \"/etc/ssh/sshd_config\"",
		"become: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered YAML missing %q\n--- output ---\n%s", want, out)
		}
	}
}

func TestGenerate_IncludeRaw(t *testing.T) {
	body := `# Verification Spec — raw

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | mycheck | OK | ` + "`echo hello`" + ` |
`
	s, _ := ParseReader(strings.NewReader(body))
	pb, _ := Generate(s, GenerateOptions{IncludeRaw: true})
	if pb.Tasks[0].Module != "ansible.builtin.command" {
		t.Errorf("IncludeRaw=true should yield ansible.builtin.command, got %q", pb.Tasks[0].Module)
	}
	if pb.Tasks[0].RawCommand != "echo hello" {
		t.Errorf("RawCommand=%q", pb.Tasks[0].RawCommand)
	}
}
