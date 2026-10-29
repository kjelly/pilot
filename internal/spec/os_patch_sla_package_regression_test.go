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

// Issue #167: os-patch-sla-apply.yml never installed `unattended-upgrades`.
// Step 4 (systemd start+enable) failed on any host without the package, in a
// real run and in --check (apt install is only simulated there, so the unit
// never exists), and Step 3's `failed_when: false` hid the missing command.
// These tests lock the fix: C8 in the spec, the install through the shared
// apt framework (strict, skipped under --check), and the check-mode gates.

const osPatchSlaApplyPath = "../../playbooks/apply/os-patch-sla-apply.yml"

// osPatchSlaTasks returns the play's tasks, by name.
func osPatchSlaTasks(t *testing.T) (names []string, byName map[string]map[string]any, handlers []map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(osPatchSlaApplyPath)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatalf("parse %s: %v", osPatchSlaApplyPath, err)
	}
	if len(plays) != 1 {
		t.Fatalf("plays=%d want 1", len(plays))
	}
	byName = map[string]map[string]any{}
	for _, key := range []string{"tasks", "post_tasks"} {
		list, _ := plays[0][key].([]any)
		for _, item := range list {
			task, _ := item.(map[string]any)
			name, _ := task["name"].(string)
			if name == "" {
				continue
			}
			names = append(names, name)
			byName[name] = task
		}
	}
	hs, _ := plays[0]["handlers"].([]any)
	for _, item := range hs {
		h, _ := item.(map[string]any)
		handlers = append(handlers, h)
	}
	return names, byName, handlers
}

// osPatchSlaTask returns the one task whose name starts with prefix.
func osPatchSlaTask(t *testing.T, prefix string) map[string]any {
	t.Helper()
	names, byName, _ := osPatchSlaTasks(t)
	var found []string
	for _, n := range names {
		if strings.HasPrefix(n, prefix) {
			found = append(found, n)
		}
	}
	if len(found) != 1 {
		t.Fatalf("tasks starting with %q: %v, want exactly one", prefix, found)
	}
	return byName[found[0]]
}

func whenText(task map[string]any) string { return fmt.Sprint(task["when"]) }

// TestRegression_OsPatchSlaInstallsThePackageThroughTheAptFramework locks the
// shape of the fix in the playbook.
func TestRegression_OsPatchSlaInstallsThePackageThroughTheAptFramework(t *testing.T) {
	raw, err := os.ReadFile(osPatchSlaApplyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Step 1 keeps its own strict update_cache (apt-repository-fault-
	// tolerance spec section 17; aptUpdateCacheAllowlist in cmd/pilot/cmd).
	step1 := osPatchSlaTask(t, "Step 1: Refresh apt cache")
	aptArgs, _ := step1["ansible.builtin.apt"].(map[string]any)
	if aptArgs == nil || fmt.Sprint(aptArgs["update_cache"]) != "true" {
		t.Errorf("Step 1 must keep `update_cache: true`, got %v", step1)
	}

	// The install is the shared include, strict, never a plain apt task.
	install := osPatchSlaTask(t, "Step 1c:")
	inc, _ := install["ansible.builtin.include_tasks"].(map[string]any)
	if inc == nil || inc["file"] != "tasks/apt-package-install.yml" {
		t.Fatalf("Step 1c must include_tasks file: tasks/apt-package-install.yml, got %v", install)
	}
	vars, _ := install["vars"].(map[string]any)
	if vars["pilot_apt_policy"] != "strict" {
		t.Errorf("pilot_apt_policy=%v want strict (apt-repository-fault-tolerance spec section 17)", vars["pilot_apt_policy"])
	}
	if got := fmt.Sprint(vars["pilot_apt_packages"]); got != "[unattended-upgrades]" {
		t.Errorf("pilot_apt_packages=%s want [unattended-upgrades]", got)
	}
	if vars["pilot_apt_component"] != "os-patch-sla" {
		t.Errorf("pilot_apt_component=%v want os-patch-sla", vars["pilot_apt_component"])
	}
	// The shared include runs real apt-get update / download-only probes even
	// under --check, so it must not run there, and it must not run when the
	// package is already installed.
	when := whenText(install)
	for _, want := range []string{"not ansible_check_mode", "not (unattended_upgrades_present | bool)"} {
		if !strings.Contains(when, want) {
			t.Errorf("Step 1c when=%s, missing %q", when, want)
		}
	}
	// The playbook's only apt-module task is Step 1: no second install path.
	if n := strings.Count(string(raw), "ansible.builtin.apt:"); n != 1 {
		t.Errorf("ansible.builtin.apt tasks=%d want 1 (Step 1 only); install via tasks/apt-package-install.yml", n)
	}

	// The presence probe reads for real even under --check.
	probe := osPatchSlaTask(t, "Step 1b: Read whether")
	if probe["check_mode"] != false {
		t.Errorf("Step 1b probe must set check_mode: false (a command is skipped under --check), got %v", probe["check_mode"])
	}

	// After the install the presence is read again and a real run fails closed.
	assertTask := osPatchSlaTask(t, "Step 1e:")
	if _, ok := assertTask["ansible.builtin.assert"]; !ok {
		t.Errorf("Step 1e must be an assert, got %v", assertTask)
	}
	if got := whenText(assertTask); got != "not ansible_check_mode" {
		t.Errorf("Step 1e when=%q want %q (check mode cannot have installed anything)", got, "not ansible_check_mode")
	}
	after := osPatchSlaTask(t, "Step 1d: Re-read")
	if got := whenText(after); got != "not ansible_check_mode" {
		t.Errorf("Step 1d re-read when=%q want %q", got, "not ansible_check_mode")
	}

	// The gate fact is defined under --check (set_fact is not skipped) and is
	// "present, or a real run".
	usable := osPatchSlaTask(t, "Step 1d: unattended-upgrades is usable")
	sf, _ := usable["ansible.builtin.set_fact"].(map[string]any)
	got := fmt.Sprint(sf["unattended_upgrades_usable"])
	if !strings.Contains(got, "unattended_upgrades_present") || !strings.Contains(got, "not ansible_check_mode") {
		t.Errorf("unattended_upgrades_usable=%q must be `present or not ansible_check_mode`", got)
	}
	if _, has := usable["when"]; has {
		t.Errorf("the gate fact must be set unconditionally so --check defines it: %v", usable["when"])
	}

	// Steps 3, 4 and the handler read the gate.
	const gate = "unattended_upgrades_usable | bool"
	for _, prefix := range []string{"Step 3: Run unattended-upgrades", "Step 4: Ensure unattended-upgrades"} {
		if w := whenText(osPatchSlaTask(t, prefix)); !strings.Contains(w, gate) {
			t.Errorf("%s... when=%q must contain %q", prefix, w, gate)
		}
	}
	_, _, handlers := osPatchSlaTasks(t)
	if len(handlers) != 1 {
		t.Fatalf("handlers=%d want 1", len(handlers))
	}
	if w := whenText(handlers[0]); !strings.Contains(w, gate) {
		t.Errorf("restart handler when=%q must contain %q: under --check Step 5 notifies it on a host without the unit", w, gate)
	}

	// Check mode on a host without the package says what apply will do.
	msg := osPatchSlaTask(t, "Step 4 (check mode):")
	dbg, _ := msg["ansible.builtin.debug"].(map[string]any)
	if dbg == nil || !strings.Contains(fmt.Sprint(dbg["msg"]), "apply will install") {
		t.Errorf("check-mode message must say apply will install the package, got %v", msg)
	}

	// Step 3's failed_when: false stays (unattended-upgrade's own non-zero
	// exits are verify's business), but is no longer silent.
	step3 := osPatchSlaTask(t, "Step 3: Run unattended-upgrades")
	if step3["failed_when"] != false {
		t.Errorf("Step 3 failed_when=%v want false", step3["failed_when"])
	}
	report := osPatchSlaTask(t, "Step 3b:")
	if !strings.Contains(whenText(report), "uu_run.rc") {
		t.Errorf("Step 3b must report a non-zero unattended-upgrade rc, got when=%s", whenText(report))
	}

	// AGENTS.md section 4.5 point 1: a block's `when:` is re-evaluated per
	// task; the fix uses no block, so nothing here can flip under itself.
	if strings.Contains(string(raw), "\n      block:") {
		t.Errorf("no block expected in os-patch-sla-apply.yml; if one is added, its when must read only facts nothing inside it sets")
	}
}

const osPatchSlaLocalInventory = `all:
  hosts:
    localhost:
      ansible_connection: local
      ansible_python_interpreter: "{{ ansible_playbook_python }}"
`

type osPatchSlaTaskResult struct {
	skipped bool
	failed  bool
	msg     string
}

// runOsPatchSlaCheck runs the real playbook on localhost (extra: --check, ...) with
// a fake dpkg-query first in PATH: it prints `installed` when present is
// true, and behaves like real dpkg-query for an unknown package (rc 1, message
// on stderr, no stdout) otherwise. It needs no root and no apt: become is off,
// and under --check the install include is not reached.
func runOsPatchSlaCheck(t *testing.T, present bool, extra ...string) (rc int, tasks map[string]osPatchSlaTaskResult, raw string) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	abs, err := filepath.Abs(osPatchSlaApplyPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	inv := filepath.Join(dir, "inv.yml")
	if err := os.WriteFile(inv, []byte(osPatchSlaLocalInventory), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho 'dpkg-query: no packages found matching unattended-upgrades' >&2\nexit 1\n"
	if present {
		script = "#!/bin/sh\nprintf installed\n"
	}
	if err := os.WriteFile(filepath.Join(bin, "dpkg-query"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	args := []string{"-i", inv, abs,
		"-e", "ansible_become=false", "-e", "target_group=all",
		// A config no real host has, so Step 5 reports changed and notifies
		// the restart handler deterministically.
		"-e", `{"unattended_origins": ["issue167:fake-origin"]}`}
	cmd := exec.Command("ansible-playbook", append(args, extra...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"),
		"ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1")
	out, runErr := cmd.Output()
	raw = string(out)
	if ee, ok := runErr.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Skipped bool `json:"skipped"`
					Failed  bool `json:"failed"`
					Msg     any  `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse JSON callback output: %v\n%s", err, out)
	}
	tasks = map[string]osPatchSlaTaskResult{}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			if h, ok := task.Hosts["localhost"]; ok {
				tasks[task.Task.Name] = osPatchSlaTaskResult{skipped: h.Skipped, failed: h.Failed, msg: fmt.Sprint(h.Msg)}
			}
		}
	}
	return rc, tasks, raw
}

func osPatchSlaResult(t *testing.T, tasks map[string]osPatchSlaTaskResult, prefix, raw string) osPatchSlaTaskResult {
	t.Helper()
	for name, r := range tasks {
		if strings.HasPrefix(name, prefix) {
			return r
		}
	}
	t.Fatalf("no task starting with %q ran\n%s", prefix, raw)
	return osPatchSlaTaskResult{}
}

// TestOsPatchSla_CheckModeWithoutThePackageSkipsTheServiceSteps is the gate
// that must trigger: --check on a host without unattended-upgrades does not
// fail on Step 4, says apply will install the package, does not run the
// install include, and the notified restart handler is skipped too. Before
// the fix Step 4 failed here and the play exited 2.
func TestOsPatchSla_CheckModeWithoutThePackageSkipsTheServiceSteps(t *testing.T) {
	rc, tasks, raw := runOsPatchSlaCheck(t, false, "--check")
	if rc != 0 {
		t.Fatalf("rc=%d want 0 (check mode on a host without the package must not fail)\n%s", rc, raw)
	}
	if r := osPatchSlaResult(t, tasks, "Step 1b: Record", raw); r.skipped || r.failed {
		t.Errorf("presence fact not recorded: %+v", r)
	}
	if r := osPatchSlaResult(t, tasks, "Step 1c:", raw); !r.skipped {
		t.Errorf("Step 1c ran its real-apt install include under --check: %+v", r)
	}
	if r := osPatchSlaResult(t, tasks, "Step 1e:", raw); !r.skipped {
		t.Errorf("Step 1e asserted package presence under --check, where nothing is installed: %+v", r)
	}
	msg := osPatchSlaResult(t, tasks, "Step 4 (check mode):", raw)
	if msg.skipped || !strings.Contains(msg.msg, "apply will install") {
		t.Errorf("check-mode message: skipped=%v msg=%q", msg.skipped, msg.msg)
	}
	for _, prefix := range []string{"Step 3: Run unattended-upgrades", "Step 4: Ensure unattended-upgrades", "Step 3b:"} {
		if r := osPatchSlaResult(t, tasks, prefix, raw); !r.skipped {
			t.Errorf("%s... ran although the package is absent in a preview: %+v", prefix, r)
		}
	}
	// Step 5 itself still previews the config change.
	if r := osPatchSlaResult(t, tasks, "Step 5:", raw); r.skipped || r.failed {
		t.Errorf("Step 5 should still preview: %+v", r)
	}
	if r, ok := tasks["restart unattended-upgrades"]; !ok {
		t.Errorf("the restart handler never ran, so its gate was not exercised (Step 5 should have notified it)\n%s", raw)
	} else if !r.skipped {
		t.Errorf("restart handler ran against a host without the unit: %+v", r)
	}
}

// TestOsPatchSla_CheckModeWithThePackageStillRunsTheServiceSteps is the
// matching "should pass" case: with the package present the gates open, the
// check-mode message is not printed, and Step 4 and the handler are not
// skipped. Whether they then pass depends on this machine's real unit, so
// only "ran" is asserted.
func TestOsPatchSla_CheckModeWithThePackageStillRunsTheServiceSteps(t *testing.T) {
	_, tasks, raw := runOsPatchSlaCheck(t, true, "--check")
	if r := osPatchSlaResult(t, tasks, "Step 4 (check mode):", raw); !r.skipped {
		t.Errorf("check-mode message printed although the package is present: %+v", r)
	}
	if r := osPatchSlaResult(t, tasks, "Step 1c:", raw); !r.skipped {
		t.Errorf("Step 1c must not run when the package is present (and never under --check): %+v", r)
	}
	if r := osPatchSlaResult(t, tasks, "Step 4: Ensure unattended-upgrades", raw); r.skipped {
		t.Errorf("Step 4 skipped although the package is present: %+v", r)
	}
}

// TestOsPatchSla_RealRunFailsClosedWhenThePackageIsStillMissing is the real-run
// gate that must trigger. A real run cannot be hermetic from the top (Step 1 is
// a root-only apt update and Step 1c a real install), so it starts at Step 1d,
// i.e. right after the install: with dpkg still reporting the package absent,
// Step 1e fails with the package named in its message, and Steps 3-5 never
// run. Before the fix nothing checked, Step 3 failed silently
// (`failed_when: false`) and Step 4 failed on the missing unit.
func TestOsPatchSla_RealRunFailsClosedWhenThePackageIsStillMissing(t *testing.T) {
	rc, tasks, raw := runOsPatchSlaCheck(t, false, "--start-at-task", "Step 1d: Re-read unattended-upgrades presence after the install")
	if rc == 0 {
		t.Fatalf("a real run without the package exited 0\n%s", raw)
	}
	gate := osPatchSlaResult(t, tasks, "Step 1e:", raw)
	if !gate.failed || !strings.Contains(gate.msg, "unattended-upgrades is not installed on") {
		t.Errorf("Step 1e: failed=%v msg=%q, want a failure naming the missing package", gate.failed, gate.msg)
	}
	for name := range tasks {
		for _, later := range []string{"Step 3", "Step 4", "Step 5"} {
			if strings.HasPrefix(name, later) {
				t.Errorf("%s ran after the fail-closed gate", name)
			}
		}
	}
}
