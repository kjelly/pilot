package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// These are real Ansible task executions with fake native executables. The
// separate VM evidence covers the native package manager and service.
func runOsPatchTasks(t *testing.T, tasks []map[string]any, vars map[string]any, env []string) (int, string) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook unavailable: %v", err)
	}
	dir := t.TempDir()
	play := []map[string]any{{"hosts": "localhost", "gather_facts": false, "vars": vars, "tasks": tasks}}
	raw, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "play.yml")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(dir, "inventory.yml")
	groups, _ := vars["group_names"].([]string)
	body := "all:\n  hosts:\n    localhost:\n      ansible_connection: local\n"
	if len(groups) > 0 {
		body += "  children:\n"
		for _, group := range groups {
			body += fmt.Sprintf("    %s:\n      hosts:\n        localhost: {}\n", group)
		}
	}
	if err := os.WriteFile(inv, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", inv, p)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=default", "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCAL_TEMP="+dir, "ANSIBLE_REMOTE_TEMP="+dir)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	if e, ok := err.(*exec.ExitError); ok {
		return e.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

func TestOsPatchSla_NativeFailureAndPackageChange(t *testing.T) {
	for _, mode := range []string{"failure", "change", "nochange", "swallowed-negative-control"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			state := filepath.Join(dir, "version")
			if err := os.WriteFile(state, []byte("1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			scripts := map[string]string{
				"dpkg-query":         "#!/bin/sh\nprintf 'example\\tinstalled\\t'; cat \"$PATCH_VERSION\"\n",
				"unattended-upgrade": "#!/bin/sh\n[ \"$*\" = '--debug' ] || exit 2\n[ \"$DEBIAN_FRONTEND\" = noninteractive ] || exit 3\ncase \"$PATCH_MODE\" in failure|swallowed-negative-control) echo native-failure-42 >&2; exit 42;; change) printf '2\\n' > \"$PATCH_VERSION\";; esac\n# Deliberately print no recognizable changed/no-change debug text.\necho opaque-native-success\n",
			}
			for name, body := range scripts {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			native := osPatchSlaTask(t, "Step 3: Run unattended-upgrades")
			if mode == "swallowed-negative-control" {
				native["failed_when"] = false
			}
			tasks := []map[string]any{
				osPatchSlaTask(t, "Step 2: Capture pre-upgrade"), native,
				osPatchSlaTask(t, "Step 3c:"),
				{"name": "sentinel reached", "ansible.builtin.debug": map[string]any{"msg": "after-native"}},
			}
			rc, out := runOsPatchTasks(t, tasks, map[string]any{"unattended_upgrades_usable": true}, []string{
				"PATH=" + dir + ":" + os.Getenv("PATH"), "PATCH_VERSION=" + state, "PATCH_MODE=" + mode,
			})
			if mode == "failure" {
				if rc == 0 || !strings.Contains(out, "native-failure-42") || strings.Contains(out, "after-native") {
					t.Fatalf("native rc42 must stop subsequent work, rc=%d\n%s", rc, out)
				}
				return
			}
			if rc != 0 || !strings.Contains(out, "after-native") {
				t.Fatalf("expected sentinel, rc=%d\n%s", rc, out)
			}
			want := "changed=0"
			if mode == "change" {
				want = "changed=1"
			}
			if !strings.Contains(out, want) {
				t.Fatalf("package state must determine %s\n%s", want, out)
			}
			// With the previous error-swallowing behavior restored, the same
			// fault reaches the sentinel: the failure oracle above rejects it.
		})
	}
}

func TestOsPatchSla_StageGates(t *testing.T) {
	_, byName, _ := osPatchSlaTasks(t)
	var gates []map[string]any
	for _, prefix := range []string{"Gate: patch_stage must be", "Gate: staging/prod", "Gate: patch_stage must match", "Gate: prod requires"} {
		for name, task := range byName {
			if strings.HasPrefix(name, prefix) {
				gates = append(gates, task)
			}
		}
	}
	if len(gates) != 4 {
		t.Fatalf("stage gates=%d want4", len(gates))
	}
	for _, tc := range []struct {
		name, stage, group, confirm string
		age                         int
		failure                     string
	}{
		{"sandbox", "sandbox", "sandbox", "", 168, ""},
		{"staging confirmed", "staging", "staging", "confirm_staging", 168, ""},
		{"prod confirmed boundary", "prod", "prod", "confirm_prod", 168, ""},
		{"staging unconfirmed", "staging", "staging", "", 168, "confirm flag is false"},
		{"prod unconfirmed", "prod", "prod", "", 168, "confirm flag is false"},
		{"stale attestation", "prod", "prod", "confirm_prod", 169, "no staging attestation"},
		{"negative attestation", "prod", "prod", "confirm_prod", -1, "no staging attestation"},
		{"wrong inventory", "sandbox", "prod", "", 168, "group 不一致"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars := map[string]any{"patch_stage": tc.stage, "group_names": []string{tc.group}, "confirm_staging": false, "confirm_prod": false, "staging_attested_within_hours": tc.age}
			if tc.confirm != "" {
				vars[tc.confirm] = true
			}
			rc, out := runOsPatchTasks(t, gates, vars, nil)
			if tc.failure == "" && rc != 0 || tc.failure != "" && (rc == 0 || !strings.Contains(out, tc.failure)) {
				t.Fatalf("rc=%d want failure %q\n%s", rc, tc.failure, out)
			}
		})
	}
}

func TestOsPatchSla_CountQueries(t *testing.T) {
	s, err := Parse("../../docs/verification/os-patch-sla.md")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// Native python-apt-shaped fixtures; security version2 can exist below
	// a general-update candidate3. C2 must still see version2.
	module := `import os
class Origin:
    def __init__(self, archive): self.archive=archive
class Version:
    def __init__(self, version, archive): self.version=version; self.origins=[Origin(archive)]
class Package:
    is_installed=True
    is_upgradable=True
    installed=Version('1','noble')
    versions=[Version('3','noble-updates'),Version('2','noble-security' if os.environ['PATCH_CASE']=='security' else 'noble-updates')]
def Cache():
    if os.environ['PATCH_CASE']=='error': raise RuntimeError('metadata-query-error')
    return [Package(),Package()]
`
	if err := os.WriteFile(filepath.Join(dir, "apt.py"), []byte(module), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "apt_pkg.py"), []byte("def version_compare(a,b): return int(a)-int(b)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []string{"general", "security", "error"} {
		for _, row := range s.Rows[:2] {
			t.Run(tc+row.ID, func(t *testing.T) {
				cmd := exec.Command("sh", "-c", row.Command)
				cmd.Env = append(os.Environ(), "PYTHONPATH="+dir, "PATCH_CASE="+tc)
				out, err := cmd.CombinedOutput()
				wantFail := tc == "error" || tc == "security" && row.ID == "C2"
				if (err != nil) != wantFail {
					t.Fatalf("err=%v wantFail=%v\n%s", err, wantFail, out)
				}
				if tc != "error" {
					want := "general-updates=2"
					if row.ID == "C2" {
						want = "0"
						if tc == "security" {
							want = "2"
						}
					}
					if strings.TrimSpace(string(out)) != want {
						t.Fatalf("actual=%q want=%q", out, want)
					}
				}
			})
		}
	}
}

func TestRegression_OsPatchSlaPolicyOrdering(t *testing.T) {
	names, _, _ := osPatchSlaTasks(t)
	index := func(prefix string) int {
		for i, n := range names {
			if strings.HasPrefix(n, prefix) {
				return i
			}
		}
		t.Fatalf("missing task %q", prefix)
		return -1
	}
	if index("Step 2d:") >= index("Step 5:") || index("Step 5:") >= index("Step 2e:") || index("Step 2e:") >= index("Step 3:") {
		t.Fatal("snapshot -> policy -> native validation -> upgrade ordering violated")
	}
	args, _ := osPatchSlaTask(t, "Step 3:")["ansible.builtin.command"].(map[string]any)
	got, _ := json.Marshal(args["argv"])
	if string(got) != `["unattended-upgrade","--debug"]` {
		t.Errorf("unsupported native argv: %s", got)
	}
	for _, prefix := range []string{"Step 2e:", "Step 3d:"} {
		if task := osPatchSlaTask(t, prefix); task["failed_when"] != nil || task["ignore_errors"] != nil {
			t.Errorf("%s probe errors must fail: %v", prefix, task)
		}
	}
}

func TestOsPatchSla_NativeOriginMetadata(t *testing.T) {
	s, err := Parse("../../docs/verification/os-patch-sla.md")
	if err != nil {
		t.Fatal(err)
	}
	var effective string
	for _, row := range s.Rows {
		if row.ID == "C6" {
			effective = row.Command
		}
	}
	probe := osPatchSlaTask(t, "Step 2a:")["ansible.builtin.command"].(map[string]any)["argv"].([]any)
	dir := t.TempDir()
	modules := map[string]string{
		"apt.py": `import json,os
from types import SimpleNamespace as N
def Cache():
    origins=[N(**x) for x in json.loads(os.environ['PATCH_METADATA'])]
    if os.environ.get('PATCH_UNTRUSTED'):
        for o in origins: o.trusted=False
    return [N(versions=[N(origins=origins)])]
`,
		"platform.py": `import json,os
def freedesktop_os_release(): return json.loads(os.environ['PATCH_RELEASE'])
`,
		"apt_pkg.py": `import json,os
class Config:
    def value_list(self,key): return json.loads(os.environ['PATCH_CONFIG']).get(key,[])
config=Config()
`,
	}
	for name, content := range modules {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ fixture, distro, release, want string }{
		{"ubuntu24", "ubuntu", "noble", "Ubuntu:noble-security"},
		{"debian12", "debian", "bookworm", "Debian:oldstable-security"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			metadata, err := os.ReadFile(filepath.Join("testdata/os-patch-sla", tc.fixture+"-origins.json"))
			if err != nil {
				t.Fatal(err)
			}
			release, _ := json.Marshal(map[string]string{"ID": tc.distro, "VERSION_CODENAME": tc.release})
			env := append(os.Environ(), "PYTHONPATH="+dir, "PATCH_METADATA="+string(metadata), "PATCH_RELEASE="+string(release))
			cmd := exec.Command("/usr/bin/python3", "-c", fmt.Sprint(probe[2]))
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			var origins []string
			if err != nil || json.Unmarshal(out, &origins) != nil || len(origins) != 1 || origins[0] != tc.want {
				t.Fatalf("native metadata must select %q: err=%v output=%s", tc.want, err, out)
			}
			for _, variant := range []string{"security", "general", "inherited-pattern", "untrusted"} {
				config := map[string][]string{"Unattended-Upgrade::Allowed-Origins": {tc.want}}
				if variant == "general" {
					config["Unattended-Upgrade::Allowed-Origins"] = []string{strings.Replace(tc.want, "-security", "-updates", 1)}
				}
				if variant == "inherited-pattern" {
					config["Unattended-Upgrade::Origins-Pattern"] = []string{"origin=*"}
				}
				configJSON, _ := json.Marshal(config)
				cmd := exec.Command("sh", "-c", effective)
				cmd.Env = append(env, "PATCH_CONFIG="+string(configJSON))
				if variant == "untrusted" {
					cmd.Env = append(cmd.Env, "PATCH_UNTRUSTED=1")
				}
				out, err := cmd.CombinedOutput()
				if (err == nil) != (variant == "security") {
					t.Fatalf("%s effective policy err=%v output=%s", variant, err, out)
				}
			}
		})
	}
}
