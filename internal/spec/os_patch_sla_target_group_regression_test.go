package spec

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #177: os-patch-sla-apply.yml declared `target_group: sandbox` in its
// play `vars:`, and play vars outrank `-e`-less defaults, so
//
//	hosts: "{{ target_group | default(patch_stage) }}"
//
// never fell back to patch_stage. `-e patch_stage=staging|prod` (all that
// `pilot deploy` and site.yml pass) still selected the `sandbox` group: the
// play silently skipped the staging/prod fleet, or failed the group_names
// gate. Only an explicit `-e target_group=` worked. These tests lock the
// selection through real `ansible-playbook --list-hosts`, and a repo-wide
// lint keeps the same shadow from coming back in any other play.

const osPatchSlaTargetInventory = `all:
  vars:
    ansible_connection: local
  children:
    prod:
      hosts: {prod1: {}}
    staging:
      hosts: {stg1: {}}
    sandbox:
      hosts: {sbx1: {}}
`

const osPatchSlaPlayName = "OS patch SLA apply"

// listPlayHosts runs `ansible-playbook --list-hosts` and returns, for the
// first play whose header contains playName, its host pattern and hosts.
// Only stdout is parsed: stderr carries host-pattern warnings.
func listPlayHosts(t *testing.T, playbook, playName string, extra ...string) (pattern string, hosts []string) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	abs, err := filepath.Abs(playbook)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	inv := filepath.Join(dir, "inv.yml")
	if err := os.WriteFile(inv, []byte(osPatchSlaTargetInventory), 0o644); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-i", inv, abs, "--list-hosts"}, extra...)
	cmd := exec.Command("ansible-playbook", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ansible-playbook %v: %v\n%s", args, err, out)
	}
	in := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "play #"):
			if in {
				return pattern, hosts
			}
			in = strings.Contains(trimmed, playName)
		case !in:
		case strings.HasPrefix(trimmed, "pattern:"):
			pattern = strings.TrimSpace(strings.TrimPrefix(trimmed, "pattern:"))
		case strings.HasPrefix(trimmed, "hosts ("):
		case trimmed != "":
			hosts = append(hosts, trimmed)
		}
	}
	if !in {
		t.Fatalf("no play containing %q in --list-hosts output of %s:\n%s", playName, playbook, out)
	}
	return pattern, hosts
}

func requireOsPatchSlaHosts(t *testing.T, pattern string, hosts []string, wantPattern string, wantHosts ...string) {
	t.Helper()
	if pattern != fmt.Sprintf("['%s']", wantPattern) {
		t.Errorf("host pattern=%s want ['%s']", pattern, wantPattern)
	}
	if strings.Join(hosts, ",") != strings.Join(wantHosts, ",") {
		t.Errorf("hosts=%v want %v", hosts, wantHosts)
	}
}

var osPatchSlaStageHost = map[string]string{"sandbox": "sbx1", "staging": "stg1", "prod": "prod1"}

// TestOsPatchSla_PatchStageSelectsItsOwnGroup is the "should pass" half:
// each patch_stage selects the same-named inventory group, and with no -e at
// all the default stage (sandbox) applies.
func TestOsPatchSla_PatchStageSelectsItsOwnGroup(t *testing.T) {
	for _, stage := range []string{"sandbox", "staging", "prod"} {
		t.Run(stage, func(t *testing.T) {
			pattern, hosts := listPlayHosts(t, osPatchSlaApplyPath, osPatchSlaPlayName, "-e", "patch_stage="+stage)
			requireOsPatchSlaHosts(t, pattern, hosts, stage, osPatchSlaStageHost[stage])
		})
	}
	t.Run("no -e defaults to sandbox", func(t *testing.T) {
		pattern, hosts := listPlayHosts(t, osPatchSlaApplyPath, osPatchSlaPlayName)
		requireOsPatchSlaHosts(t, pattern, hosts, "sandbox", "sbx1")
	})
}

// TestOsPatchSla_ExplicitTargetGroupStillOverrides keeps the documented
// escape hatch: `-e target_group=` wins for every stage.
func TestOsPatchSla_ExplicitTargetGroupStillOverrides(t *testing.T) {
	for _, stage := range []string{"sandbox", "staging", "prod"} {
		t.Run(stage+"/prod", func(t *testing.T) {
			pattern, hosts := listPlayHosts(t, osPatchSlaApplyPath, osPatchSlaPlayName,
				"-e", "patch_stage="+stage, "-e", "target_group=prod")
			requireOsPatchSlaHosts(t, pattern, hosts, "prod", "prod1")
		})
		t.Run(stage+"/all", func(t *testing.T) {
			pattern, hosts := listPlayHosts(t, osPatchSlaApplyPath, osPatchSlaPlayName,
				"-e", "patch_stage="+stage, "-e", "target_group=all")
			if pattern != "['all']" {
				t.Errorf("pattern=%s want ['all']", pattern)
			}
			sort.Strings(hosts)
			if got := strings.Join(hosts, ","); got != "prod1,sbx1,stg1" {
				t.Errorf("hosts=%s want prod1,sbx1,stg1", got)
			}
		})
	}
}

// TestOsPatchSla_UnknownStageSelectsNoHosts is the "should trigger" case: a
// patch_stage that is not a group must not silently fall back to sandbox (the
// pre-fix behaviour for every stage). The play's own assert still rejects it
// at run time; here the point is that nothing in the sandbox group is chosen.
func TestOsPatchSla_UnknownStageSelectsNoHosts(t *testing.T) {
	pattern, hosts := listPlayHosts(t, osPatchSlaApplyPath, osPatchSlaPlayName, "-e", "patch_stage=bogus")
	requireOsPatchSlaHosts(t, pattern, hosts, "bogus")
}

// TestOsPatchSla_SiteStyleEntryPassesOnlyPatchStage reproduces how site.yml
// and `pilot deploy` reach this playbook: the entry play asserts
// target_group is undefined (site.yml's safety valve), then imports the
// playbook with only patch_stage supplied.
func TestOsPatchSla_SiteStyleEntryPassesOnlyPatchStage(t *testing.T) {
	abs, err := filepath.Abs(osPatchSlaApplyPath)
	if err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(t.TempDir(), "site-like.yml")
	body := "- name: valve\n  hosts: localhost\n  gather_facts: false\n  tasks:\n" +
		"    - ansible.builtin.assert:\n        that: [target_group is not defined]\n" +
		"- import_playbook: " + abs + "\n"
	if err := os.WriteFile(wrapper, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	pattern, hosts := listPlayHosts(t, wrapper, osPatchSlaPlayName, "-e", "patch_stage=prod")
	requireOsPatchSlaHosts(t, pattern, hosts, "prod", "prod1")
}

// TestOsPatchSla_RealSiteYmlSelectsTheStageGroup runs the real site.yml entry
// point (`pilot deploy`'s path) with patch_stage=prod.
func TestOsPatchSla_RealSiteYmlSelectsTheStageGroup(t *testing.T) {
	pattern, hosts := listPlayHosts(t, "../../playbooks/site.yml", osPatchSlaPlayName,
		"--tags", "patch", "-e", "patch_stage=prod")
	requireOsPatchSlaHosts(t, pattern, hosts, "prod", "prod1")
}

// hostsDefaultShadowViolations returns one message per play whose
// `hosts: "{{ V | default(D) ... }}"` has V declared in the same play's
// `vars:` with a value that is not D. Play vars outrank everything but -e,
// so such a declaration makes the default dead: the play can only be
// retargeted with `-e V=`, and any other input that D was meant to follow
// (a stage variable, infra_role) is ignored. A declared value is accepted
// when it is D itself, or the template that evaluates to D.
func hostsDefaultShadowViolations(doc any) []string {
	plays, _ := doc.([]any)
	var out []string
	for i, p := range plays {
		play, _ := p.(map[string]any)
		hosts, _ := play["hosts"].(string)
		m := hostsDefaultRe.FindStringSubmatch(hosts)
		if m == nil {
			continue
		}
		name, def := m[1], strings.TrimSpace(m[2])
		vars, _ := play["vars"].(map[string]any)
		raw, declared := vars[name]
		if !declared {
			continue
		}
		got := strings.TrimSpace(fmt.Sprint(raw))
		if tpl := regexp.MustCompile(`^\{\{\s*(.*?)\s*\}\}$`).FindStringSubmatch(got); tpl != nil {
			got = tpl[1]
		}
		if got == def || strings.Trim(def, `'"`) == got {
			continue
		}
		reason := "its value differs from the default, so the default is dead"
		if stageLikeLiteral[got] {
			reason = "a stage literal pins every stage to one group"
		}
		label := fmt.Sprint(play["name"])
		out = append(out, fmt.Sprintf("play #%d %q: vars declares %s: %v but hosts defaults to %s: %s; delete the play var so `-e %s=` is the only override",
			i+1, label, name, raw, def, reason, name))
	}
	return out
}

var (
	hostsDefaultRe   = regexp.MustCompile(`^\{\{\s*(\w+)\s*\|\s*default\(([^()]*)\)`)
	stageLikeLiteral = map[string]bool{"sandbox": true, "staging": true, "prod": true}
)

// TestRegression_HostsDefaultIsNotShadowedByPlayVars is a repo-wide lint over
// playbooks/**/*.yml. It generalises #177 (os-patch-sla) to every play. There
// is no allowlist: the other plays that declare their `hosts:` variable
// declare exactly its default.
func TestRegression_HostsDefaultIsNotShadowedByPlayVars(t *testing.T) {
	var files []string
	err := filepath.WalkDir("../../playbooks", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	checked := 0
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: parse: %v", path, err)
		}
		if plays, _ := doc.([]any); len(plays) > 0 {
			for _, p := range plays {
				if play, _ := p.(map[string]any); play != nil {
					if h, _ := play["hosts"].(string); hostsDefaultRe.MatchString(h) {
						checked++
					}
				}
			}
		}
		for _, v := range hostsDefaultShadowViolations(doc) {
			t.Errorf("%s: %s", path, v)
		}
	}
	if checked < 25 {
		t.Errorf("lint examined only %d plays with a `hosts: {{ v | default(...) }}` pattern; the walk or regex is broken", checked)
	}
}

// TestHostsDefaultShadowViolations is the lint's self-test: it must trigger on
// the pre-fix os-patch-sla shape and pass on the benign shapes in the repo.
func TestHostsDefaultShadowViolations(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"os-patch-sla before #177", `
- name: shadowing
  hosts: "{{ target_group | default(patch_stage) }}"
  vars:
    patch_stage: sandbox
    target_group: sandbox
`, 1},
		{"stage literal over a literal default", `
- name: shadowing literal
  hosts: "{{ target_group | default('keycloak') }}"
  vars:
    target_group: prod
`, 1},
		{"declared equals literal default", `
- name: benign
  hosts: "{{ target_group | default('docker') }}"
  vars:
    target_group: docker
`, 0},
		{"declared template equals variable default", `
- name: benign chain
  hosts: "{{ target_group | default(infra_role) | default('ntp') }}"
  vars:
    target_group: "{{ infra_role }}"
`, 0},
		{"not declared", `
- name: benign undeclared
  hosts: "{{ target_group | default(patch_stage) }}"
  vars:
    patch_stage: sandbox
`, 0},
		{"static hosts", `
- name: static
  hosts: localhost
  vars:
    target_group: sandbox
`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(c.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			if got := hostsDefaultShadowViolations(doc); len(got) != c.want {
				t.Errorf("violations=%d want %d: %v", len(got), c.want, got)
			}
		})
	}
}
