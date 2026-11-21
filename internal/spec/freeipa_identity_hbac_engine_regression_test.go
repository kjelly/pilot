package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The HBAC engine variable of the mixed run (docs/superpowers/specs/
// 2026-11-19-freeipa-go-reconcile-phase3-hbac-spec.md §3.3 and §7.1).
// `pilot reconcile --engine golang --scope full` runs a Go stage for the roster's
// HBAC after this playbook, and hands the playbook `-e pilot_identity_hbac_engine=go`
// so that the roster's HBAC services, rules and allow_all lockdown are not handed to the
// tasks that would write them, and `-e pilot_identity_cache_settle=defer` so that the
// first run of the playbook does not refresh the clients' caches before the Go HBAC stage
// has written (the second run, `--tags client-cache`, does). Locked here:
//
//   - static: exactly the four tasks that refresh the caches or acknowledge the obligation
//     carry the defer condition, and exactly the two rule-normalization tasks carry the
//     engine condition, so a task added later is not left outside either;
//   - the variables are `-e` variables of pilot's mixed run, never inventory inputs;
//   - runtime, with real Ansible: the gate lets the combinations of the mixed run through
//     and refuses the others, and with the engine set to go the normalized HBAC lists
//     keep what `pilot access` compiles and drop what the roster declares, while with it
//     unset they are what they were.

const (
	hbacEngineVar   = "pilot_identity_hbac_engine"
	settleVar       = "pilot_identity_cache_settle"
	hbacEngineGuard = "pilot_identity_hbac_engine | default('ansible') != 'go'"
	settleGuard     = "pilot_identity_cache_settle | default('now') != 'defer'"
	hbacEngineGate  = "Gate: the HBAC engine is ansible or go, and go comes with the users/groups engine; settle is now or defer"
)

var (
	// The four tasks that refresh the clients' authorization caches or say the obligation is settled.
	settleGuarded = []string{
		"Resolve the enrolled clients for the sudo full refresh",
		"Refresh SSSD caches on enrolled FreeIPA clients",
		"Gate: every enrolled client finished a sudo full refresh",
		"Acknowledge legacy authorization cache recovery",
	}
	// The two tasks that hand the roster's HBAC rules to the tasks that write them.
	hbacEngineGuarded = []string{
		"Normalize canonical HBAC rules for the compatibility reconciler",
		"Normalize absent static HBAC rules for deletion (spec 2026-09-07 §6.1)",
	}
)

// allIdentityTasks is every task of the first play, pre_tasks first, then the private-cache block.
func allIdentityTasks(t *testing.T) []map[string]any {
	t.Helper()
	plays := identityPlays(t, identityApplyPath)
	var out []map[string]any
	pre, _ := plays[0]["pre_tasks"].([]any)
	for _, raw := range pre {
		if task, ok := raw.(map[string]any); ok {
			out = append(out, task)
		}
	}
	block, err := identityReconcileBlock(plays)
	if err != nil {
		t.Fatal(err)
	}
	return append(out, block...)
}

func hbacEngineProblems(tasks []map[string]any) []string {
	var problems []string
	has := func(task map[string]any, cond string) bool {
		return slices.ContainsFunc(whenList(task), func(c string) bool { return strings.TrimSpace(c) == cond })
	}
	mentions := func(task map[string]any, v string) bool {
		return slices.ContainsFunc(whenList(task), func(c string) bool { return strings.Contains(c, v) })
	}
	byName := map[string]bool{}
	for _, task := range tasks {
		name := taskName(task)
		byName[name] = true
		if slices.Contains(settleGuarded, name) != has(task, settleGuard) {
			if slices.Contains(settleGuarded, name) {
				problems = append(problems, fmt.Sprintf("%q does not carry %q", name, settleGuard))
			} else {
				problems = append(problems, fmt.Sprintf("%q carries %q but is not one of the cache refresh tasks", name, settleGuard))
			}
		}
		if mentions(task, settleVar) && !has(task, settleGuard) {
			problems = append(problems, fmt.Sprintf("%q names %s in a way other than the defer condition", name, settleVar))
		}
		if slices.Contains(hbacEngineGuarded, name) != has(task, hbacEngineGuard) {
			if slices.Contains(hbacEngineGuarded, name) {
				problems = append(problems, fmt.Sprintf("%q does not carry %q", name, hbacEngineGuard))
			} else {
				problems = append(problems, fmt.Sprintf("%q carries %q but is not a rule normalization task", name, hbacEngineGuard))
			}
		}
		if mentions(task, hbacEngineVar) && !has(task, hbacEngineGuard) {
			problems = append(problems, fmt.Sprintf("%q names %s in a way other than the engine condition", name, hbacEngineVar))
		}
	}
	for _, name := range append(slices.Clone(settleGuarded), hbacEngineGuarded...) {
		if !byName[name] {
			problems = append(problems, fmt.Sprintf("no task called %q", name))
		}
	}
	return problems
}

func TestRegression_IdentityHBACEngineGuard(t *testing.T) {
	if problems := hbacEngineProblems(allIdentityTasks(t)); len(problems) != 0 {
		t.Fatalf("the HBAC engine guard is wrong:\n%s", strings.Join(problems, "\n"))
	}
}

// The lint fires: each of these playbooks has one defect and is reported.
func TestHBACEngineGuardLintFires(t *testing.T) {
	good := allIdentityTasks(t)
	clone := func() []map[string]any {
		out := make([]map[string]any, len(good))
		for i, task := range good {
			c := map[string]any{}
			for k, v := range task {
				c[k] = v
			}
			out[i] = c
		}
		return out
	}
	find := func(tasks []map[string]any, name string) map[string]any {
		for _, task := range tasks {
			if taskName(task) == name {
				return task
			}
		}
		t.Fatalf("no task %q", name)
		return nil
	}
	for name, mutate := range map[string]func([]map[string]any){
		"a refresh task loses the defer condition":   func(ts []map[string]any) { delete(find(ts, settleGuarded[1]), "when") },
		"the acknowledgement loses it":               func(ts []map[string]any) { delete(find(ts, settleGuarded[3]), "when") },
		"a rule normalization loses the engine one":  func(ts []map[string]any) { delete(find(ts, hbacEngineGuarded[0]), "when") },
		"the absent-rule normalization loses it":     func(ts []map[string]any) { delete(find(ts, hbacEngineGuarded[1]), "when") },
		"another task takes the engine condition":    func(ts []map[string]any) { find(ts, "Kinit admin")["when"] = hbacEngineGuard },
		"another task takes the defer condition":     func(ts []map[string]any) { find(ts, "Kinit admin")["when"] = settleGuard },
		"a task reads the variable some other way":   func(ts []map[string]any) { find(ts, "Kinit admin")["when"] = "pilot_identity_hbac_engine == 'go'" },
		"a guarded task is renamed and so goes away": func(ts []map[string]any) { find(ts, settleGuarded[0])["name"] = "renamed" },
	} {
		ts := clone()
		mutate(ts)
		if len(hbacEngineProblems(ts)) == 0 {
			t.Errorf("%s: the lint does not see it", name)
		}
	}
	if problems := hbacEngineProblems(clone()); len(problems) != 0 {
		t.Fatalf("the unmodified playbook is reported: %v", problems)
	}
}

func TestRegression_IdentityHBACEngineIsNotAnInventoryInput(t *testing.T) {
	var hits []string
	roots := []string{"../../contracts", "../../group_vars", "../../playbooks/apply/tasks", "../../playbooks/check", "../../playbooks/decommission", "../../playbooks/site.yml"}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr == nil && (strings.Contains(string(data), hbacEngineVar) || strings.Contains(string(data), settleVar)) {
				hits = append(hits, path)
			}
			return nil
		})
	}
	if len(hits) != 0 {
		t.Fatalf("%s or %s is named in %v: they are `-e` variables of pilot's mixed run only, and the other playbooks must not read them (or an inventory file set them)", hbacEngineVar, settleVar, hits)
	}
}

// runMini runs the given tasks on localhost with real Ansible and returns the debug output of the
// task called report.
func runMini(t *testing.T, vars map[string]any, tasks []any, report string) (rc int, out map[string]any, failed map[string]string) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	body, err := yaml.Marshal([]map[string]any{{
		"name": "mini", "hosts": "localhost", "connection": "local", "gather_facts": false, "vars": vars, "tasks": tasks,
	}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pb := filepath.Join(dir, "mini.yml")
	if err := os.WriteFile(pb, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", pb)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False",
		"ANSIBLE_INVENTORY_UNPARSED_WARNING=False", "ANSIBLE_PYTHON_INTERPRETER=/usr/bin/python3")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, runErr := cmd.Output()
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
					Failed bool           `json:"failed"`
					Msg    any            `json:"msg"`
					Result map[string]any `json:"-"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(raw, &cb); err != nil {
		t.Fatalf("parse the JSON callback output: %v\n%s%s", err, raw, stderr.String())
	}
	failed = map[string]string{}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			for _, h := range task.Hosts {
				if h.Failed {
					failed[task.Task.Name], _ = h.Msg.(string)
				}
				if task.Task.Name == report {
					if m, ok := h.Msg.(map[string]any); ok {
						out = m
					}
				}
			}
		}
	}
	return rc, out, failed
}

func TestRegression_IdentityHBACEngineGateRuntime(t *testing.T) {
	const outVar = "pilot_identity_auth_cache_output"
	var gate map[string]any
	for _, task := range allIdentityTasks(t) {
		if taskName(task) == hbacEngineGate {
			gate = task
		}
	}
	if gate == nil {
		t.Fatalf("no %q", hbacEngineGate)
	}
	if tags, _ := gate["tags"].([]any); !slices.Contains(tags, any("always")) {
		t.Fatalf("the gate is not tagged always: %v", gate["tags"])
	}
	file := "/tmp/pilot-observation.json"
	for _, tc := range []struct {
		name   string
		vars   map[string]any
		refuse bool
	}{
		{"unset", nil, false},
		{"ansible", map[string]any{hbacEngineVar: "ansible"}, false},
		{"the mixed run, first playbook run", map[string]any{hbacEngineVar: "go", engineVar: "go", outVar: file, settleVar: "defer"}, false},
		{"the mixed run, second playbook run", map[string]any{hbacEngineVar: "go", engineVar: "go", outVar: file}, false},
		{"settle now, spelled out", map[string]any{settleVar: "now"}, false},
		{"go without the users/groups engine", map[string]any{hbacEngineVar: "go", outVar: file}, true},
		{"go with the users/groups engine on ansible", map[string]any{hbacEngineVar: "go", engineVar: "ansible", outVar: file}, true},
		// Without the observation file the users/groups gate refuses the run; this gate
		// does not name the file, so it lets the combination through.
		{"go and users/groups go, no file (the other gate's refusal)", map[string]any{hbacEngineVar: "go", engineVar: "go"}, false},
		{"neither word", map[string]any{hbacEngineVar: "rust", engineVar: "go", outVar: file}, true},
		{"the other case", map[string]any{hbacEngineVar: "Go", engineVar: "go", outVar: file}, true},
		{"defer on a plain run", map[string]any{settleVar: "defer"}, true},
		{"defer with the engine on ansible", map[string]any{settleVar: "defer", hbacEngineVar: "ansible"}, true},
		{"settle is neither word", map[string]any{settleVar: "later"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, _, failed := runMini(t, tc.vars, []any{gate}, "")
			msg, gateFailed := failed[hbacEngineGate]
			if tc.refuse {
				if rc == 0 || !gateFailed {
					t.Fatalf("the gate let it through: rc=%d failed=%v", rc, failed)
				}
				if !strings.Contains(msg, hbacEngineVar) {
					t.Errorf("the refusal does not say what to fix: %q", msg)
				}
				return
			}
			if rc != 0 || gateFailed {
				t.Fatalf("the gate refused a run it must allow: rc=%d msg=%q", rc, msg)
			}
		})
	}
}

// The normalized HBAC lists, with real Ansible: the engine variable keeps the rules `pilot access`
// compiles and drops the roster's, and without it nothing changes.
func TestRegression_IdentityHBACEngineNormalization(t *testing.T) {
	names := []string{
		"Normalize canonical FreeIPA settings",
		hbacEngineGuarded[0], hbacEngineGuarded[1],
		"Append v3.0 compiled grant HBAC rules (spec.md §9)",
	}
	var tasks []any
	for _, want := range names {
		found := false
		for _, task := range allIdentityTasks(t) {
			if taskName(task) == want {
				// The mini play has no no_log noise to hide.
				c := map[string]any{}
				for k, v := range task {
					if k != "no_log" {
						c[k] = v
					}
				}
				tasks = append(tasks, c)
				found = true
			}
		}
		if !found {
			t.Fatalf("no task %q", want)
		}
	}
	const report = "report"
	tasks = append(tasks, map[string]any{"name": report, "ansible.builtin.debug": map[string]any{"msg": map[string]any{
		"rules":    "{{ ipa_hbac_rules | map(attribute='name') | list }}",
		"absent":   "{{ ipa_hbac_rules_absent }}",
		"services": "{{ ipa_hbac_services | map(attribute='name') | list }}",
		"lockdown": "{{ ipa_hbac_disable_allow_all | bool }}",
	}}})
	roster := map[string]any{
		"schema_version": 3,
		"hbac": map[string]any{
			"disable_allow_all": true,
			"services":          []any{map[string]any{"name": "custom-svc"}},
			"rules": []any{
				map[string]any{"name": "login-team", "subjects": map[string]any{"users": []any{"alice"}}, "targets": map[string]any{"hostcat": "all"}, "services": []any{"sshd"}},
				map[string]any{"name": "break-glass", "subjects": map[string]any{"users": []any{"admin"}}, "targets": map[string]any{"hostcat": "all"}, "services": []any{"sshd"}},
				map[string]any{"name": "old-rule", "state": "absent", "subjects": map[string]any{"users": []any{"alice"}}, "targets": map[string]any{"hostcat": "all"}, "services": []any{"sshd"}},
			},
		},
	}
	grant := []any{map[string]any{"name": "pilot-grant-login-x", "users": []any{"bob"}, "services": []any{"sshd"}, "hostcat": "all", "enabled": true}}
	run := func(extra map[string]any) map[string]any {
		// The play's own vars (ipa_domain and the lists the normalization appends to), then ours.
		vars := map[string]any{}
		playVars, _ := identityPlays(t, identityApplyPath)[0]["vars"].(map[string]any)
		for k, v := range playVars {
			vars[k] = v
		}
		vars["freeipa_roster"], vars["pilot_compiled_grant_hbac_rules"], vars["ipa_admin_password"] = roster, grant, "lab-password-1"
		for k, v := range extra {
			vars[k] = v
		}
		rc, out, failed := runMini(t, vars, tasks, report)
		if rc != 0 || out == nil {
			t.Fatalf("the normalization did not run: rc=%d failed=%v out=%v", rc, failed, out)
		}
		return out
	}
	list := func(v any) []string {
		var out []string
		for _, x := range v.([]any) {
			out = append(out, fmt.Sprint(x))
		}
		return out
	}
	def := run(nil)
	if got := list(def["rules"]); !slices.Equal(got, []string{"login-team", "break-glass", "pilot-grant-login-x"}) {
		t.Errorf("default: rules %v", got)
	}
	if got := list(def["absent"]); !slices.Equal(got, []string{"old-rule"}) {
		t.Errorf("default: absent %v", got)
	}
	if got := list(def["services"]); !slices.Equal(got, []string{"custom-svc"}) || def["lockdown"] != true {
		t.Errorf("default: services %v lockdown %v", got, def["lockdown"])
	}
	for _, extra := range []map[string]any{{hbacEngineVar: "ansible"}} {
		if got := run(extra); fmt.Sprint(got) != fmt.Sprint(def) {
			t.Errorf("%v changes the default: %v vs %v", extra, got, def)
		}
	}
	goRun := run(map[string]any{hbacEngineVar: "go"})
	if got := list(goRun["rules"]); !slices.Equal(got, []string{"pilot-grant-login-x"}) {
		t.Errorf("go: rules %v, want only the compiled grant rule", got)
	}
	if got := list(goRun["absent"]); len(got) != 0 {
		t.Errorf("go: absent %v", got)
	}
	if got := list(goRun["services"]); len(got) != 0 || goRun["lockdown"] != false {
		t.Errorf("go: services %v lockdown %v, want none and false", got, goRun["lockdown"])
	}
}
