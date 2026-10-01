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

// tasks/freeipa-ca-trust.yml is shared by freeipa-ca-trust-apply.yml (C2)
// and internal-endpoint-apply.yml's baseline play (C10, followed by the C9
// resolver baseline). On a fresh chain's check-mode run the FreeIPA server
// install is only simulated, so /etc/ipa/ca.crt does not exist yet; the
// include must then stop its own preview with a message instead of failing
// every host, while a real run without the CA keeps failing closed
// (AGENTS.md §4.5 point 4). Found 2026-10-01 by the dns tier's fresh
// topology test (docs/evidence/dns/2026-10-01-3f781fb.md).

const (
	freeipaCaTrustTasksPath   = "../../playbooks/apply/tasks/freeipa-ca-trust.yml"
	freeipaCaTrustApplyPath   = "../../playbooks/apply/freeipa-ca-trust-apply.yml"
	freeipaCaTrustStatVar     = "freeipa_ca_trust_ca_stat"
	freeipaCaTrustGateMsg     = "FreeIPA CA is not the configured root trust anchor: /etc/ipa/ca.crt does not exist on localhost"
	freeipaCaTrustPreviewMsg  = "Check mode: /etc/ipa/ca.crt does not exist on localhost yet"
	freeipaCaTrustGuardWhen   = "not (ansible_check_mode and not freeipa_ca_trust_ca_stat.stat.exists)"
	freeipaCaTrustLocalSource = `all:
  children:
    freeipa-server:
      hosts:
        localhost:
          ansible_connection: local
          ansible_python_interpreter: "{{ ansible_playbook_python }}"
`
)

// TestRegression_FreeipaCaTrustFreshCheckModeStructure locks the shape of
// the fix: the CA stat, then a check-mode-only message, then one block that
// holds the gate and every task after it, skipped only when check mode
// meets a missing CA. No meta: end_host/end_play, because ending the host
// would also end internal-endpoint's C9 resolver preview.
func TestRegression_FreeipaCaTrustFreshCheckModeStructure(t *testing.T) {
	raw, err := os.ReadFile(freeipaCaTrustTasksPath)
	if err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(raw, &tasks); err != nil {
		t.Fatalf("parse %s: %v", freeipaCaTrustTasksPath, err)
	}
	var walk func(v any)
	walk = func(v any) {
		switch n := v.(type) {
		case map[string]any:
			for k, c := range n {
				if k == "meta" || k == "ansible.builtin.meta" {
					t.Errorf("shared include must not use meta: %v (internal-endpoint's baseline play previews C9 after it)", c)
				}
				walk(c)
			}
		case []any:
			for _, c := range n {
				walk(c)
			}
		}
	}
	for _, task := range tasks {
		walk(task)
	}
	if len(tasks) != 3 {
		t.Fatalf("top-level tasks=%d want 3 (CA stat, check-mode message, guarded block)", len(tasks))
	}

	stat, preview, guarded := tasks[0], tasks[1], tasks[2]
	if stat["register"] != freeipaCaTrustStatVar {
		t.Errorf("first task registers %v, want %s", stat["register"], freeipaCaTrustStatVar)
	}

	debug, ok := preview["ansible.builtin.debug"].(map[string]any)
	if !ok || !strings.Contains(fmt.Sprint(debug["msg"]), "Check mode: /etc/ipa/ca.crt does not exist on") {
		t.Errorf("second task must be a debug explaining the stopped preview, got %v", preview)
	}
	gotWhen := fmt.Sprint(preview["when"])
	for _, want := range []string{"ansible_check_mode", "not " + freeipaCaTrustStatVar + ".stat.exists"} {
		if !strings.Contains(gotWhen, want) {
			t.Errorf("check-mode message when=%s, missing %q", gotWhen, want)
		}
	}

	if got := fmt.Sprint(guarded["when"]); got != freeipaCaTrustGuardWhen {
		t.Errorf("guarded block when=%q want %q", got, freeipaCaTrustGuardWhen)
	}
	block, ok := guarded["block"].([]any)
	if !ok || len(block) == 0 {
		t.Fatalf("third task must be a block, got %v", guarded)
	}
	gate, _ := block[0].(map[string]any)
	assert, _ := gate["ansible.builtin.assert"].(map[string]any)
	if assert == nil || !strings.Contains(fmt.Sprint(assert["that"]), freeipaCaTrustStatVar+".stat.exists") ||
		!strings.Contains(fmt.Sprint(assert["fail_msg"]), "does not exist on") {
		t.Errorf("first task in the block must be the fail-closed CA gate, got %v", gate)
	}
	// AGENTS.md §4.5 point 1: the block's when is re-evaluated per task, so
	// it may only read facts nothing inside the block sets.
	for _, item := range block {
		task, _ := item.(map[string]any)
		names := []string{fmt.Sprint(task["register"])}
		if sf, ok := task["ansible.builtin.set_fact"].(map[string]any); ok {
			for k := range sf {
				names = append(names, k)
			}
		}
		for _, n := range names {
			if n != "<nil>" && strings.Contains(freeipaCaTrustGuardWhen, n) {
				t.Errorf("block task %v sets %s, which the block's when reads", task["name"], n)
			}
		}
	}
}

type freeipaCaTrustTaskResult struct {
	name    string
	skipped bool
	failed  bool
	msg     string
}

type freeipaCaTrustRun struct {
	rc    int
	tasks []freeipaCaTrustTaskResult
	raw   string
}

// find returns the localhost result of the first task whose name contains
// fragment.
func (r freeipaCaTrustRun) find(t *testing.T, fragment string) freeipaCaTrustTaskResult {
	t.Helper()
	for _, task := range r.tasks {
		if strings.Contains(task.name, fragment) {
			return task
		}
	}
	t.Fatalf("no task named *%s* ran\n%s", fragment, r.raw)
	return freeipaCaTrustTaskResult{}
}

// runFreeipaCaTrust runs playbook against localhost as the freeipa-server
// CA source. It skips when ansible-playbook is missing, or when this machine
// has a FreeIPA CA: then a real run would get past the gate and try to
// install it.
func runFreeipaCaTrust(t *testing.T, playbook string, args ...string) freeipaCaTrustRun {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	if _, err := os.Stat("/etc/ipa/ca.crt"); err == nil {
		t.Skip("/etc/ipa/ca.crt exists on this machine; the missing-CA cases cannot run here")
	}
	abs, err := filepath.Abs(playbook)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	inv := filepath.Join(dir, "inv.yml")
	if err := os.WriteFile(inv, []byte(freeipaCaTrustLocalSource), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", append([]string{"-i", inv, abs, "-e", "ansible_become=false"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1")
	out, runErr := cmd.Output()
	res := freeipaCaTrustRun{raw: string(out)}
	if ee, ok := runErr.(*exec.ExitError); ok {
		res.rc = ee.ExitCode()
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
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			if h, ok := task.Hosts["localhost"]; ok {
				res.tasks = append(res.tasks, freeipaCaTrustTaskResult{
					name: task.Task.Name, skipped: h.Skipped, failed: h.Failed, msg: fmt.Sprint(h.Msg),
				})
			}
		}
	}
	return res
}

// TestFreeipaCaTrust_CheckModeWithoutCAStopsPreview: check mode against a
// source without /etc/ipa/ca.crt prints why the preview stops and exits 0,
// both for a full run and for the tag-scoped --tags C2 run. Before the fix
// this failed at the gate (rc 2).
func TestFreeipaCaTrust_CheckModeWithoutCAStopsPreview(t *testing.T) {
	for _, tags := range []string{"", "C2"} {
		t.Run("tags="+tags, func(t *testing.T) {
			args := []string{"--check", "--diff"}
			if tags != "" {
				args = append(args, "--tags", tags)
			}
			r := runFreeipaCaTrust(t, freeipaCaTrustApplyPath, args...)
			if r.rc != 0 {
				t.Fatalf("rc=%d want 0\n%s", r.rc, r.raw)
			}
			if got := r.find(t, "stop this preview"); got.skipped || !strings.Contains(got.msg, freeipaCaTrustPreviewMsg) {
				t.Errorf("preview message: skipped=%v msg=%q", got.skipped, got.msg)
			}
			for _, name := range []string{"Gate: /etc/ipa/ca.crt exists on", "install the CA bundle"} {
				if got := r.find(t, name); !got.skipped {
					t.Errorf("task *%s* ran in a stopped preview: %+v", name, got)
				}
			}
		})
	}
}

// TestFreeipaCaTrust_RealRunWithoutCAFailsClosed: the same source in a real
// run still fails at the gate with the spec's message, and installs nothing.
func TestFreeipaCaTrust_RealRunWithoutCAFailsClosed(t *testing.T) {
	r := runFreeipaCaTrust(t, freeipaCaTrustApplyPath)
	if r.rc == 0 {
		t.Fatalf("real run without a CA exited 0\n%s", r.raw)
	}
	if got := r.find(t, "stop this preview"); !got.skipped {
		t.Errorf("check-mode message printed in a real run: %+v", got)
	}
	gate := r.find(t, "Gate: /etc/ipa/ca.crt exists on")
	if !gate.failed || !strings.Contains(gate.msg, freeipaCaTrustGateMsg) {
		t.Errorf("gate: failed=%v msg=%q, want failure with %q", gate.failed, gate.msg, freeipaCaTrustGateMsg)
	}
	for _, task := range r.tasks {
		if strings.Contains(task.name, "install the CA bundle") {
			t.Errorf("install task reached after the gate failed: %+v", task)
		}
	}
}

// TestFreeipaCaTrust_CheckModeWithCAStillValidates: when the source has a CA
// the guard does not skip anything in check mode. The CA stat is forced to
// "exists" with an extra var (which outranks register), so the gate passes
// and the validation reads the real, absent file and fails: proof that the
// validation path still runs.
func TestFreeipaCaTrust_CheckModeWithCAStillValidates(t *testing.T) {
	r := runFreeipaCaTrust(t, freeipaCaTrustApplyPath, "--check",
		"-e", `{"`+freeipaCaTrustStatVar+`": {"stat": {"exists": true}}}`)
	if got := r.find(t, "stop this preview"); !got.skipped {
		t.Errorf("check-mode message printed although the CA exists: %+v", got)
	}
	if gate := r.find(t, "Gate: /etc/ipa/ca.crt exists on"); gate.skipped || gate.failed {
		t.Errorf("gate should run and pass: %+v", gate)
	}
	if info := r.find(t, "read the integrated CA's issuer"); info.skipped {
		t.Errorf("CA validation skipped although the CA exists: %+v", info)
	}
}

// TestFreeipaCaTrust_StoppedPreviewKeepsThePlayGoing mirrors
// internal-endpoint-apply.yml's baseline play: the shared include under
// apply tags, then another task. Check mode without a CA must still reach
// the task after the include.
func TestFreeipaCaTrust_StoppedPreviewKeepsThePlayGoing(t *testing.T) {
	include, err := filepath.Abs(freeipaCaTrustTasksPath)
	if err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(t.TempDir(), "baseline.yml")
	body := `- hosts: all
  gather_facts: false
  vars:
    freeipa_ca_trust_source_host: localhost
  tasks:
    - name: CA trust baseline
      tags: [C10]
      ansible.builtin.include_tasks:
        file: ` + include + `
        apply:
          tags: [C10]
    - name: resolver baseline marker
      tags: [C9]
      ansible.builtin.debug:
        msg: resolver baseline reached
`
	if err := os.WriteFile(wrapper, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	r := runFreeipaCaTrust(t, wrapper, "--check", "--tags", "C9,C10")
	if r.rc != 0 {
		t.Fatalf("rc=%d want 0\n%s", r.rc, r.raw)
	}
	if got := r.find(t, "stop this preview"); got.skipped {
		t.Errorf("preview message skipped: %+v", got)
	}
	if got := r.find(t, "resolver baseline marker"); got.skipped || !strings.Contains(got.msg, "resolver baseline reached") {
		t.Errorf("task after the include did not run: %+v", got)
	}
}
