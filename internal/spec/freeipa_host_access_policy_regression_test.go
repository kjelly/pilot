package spec

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const hostAccessPolicyTaskPath = "../../playbooks/apply/tasks/freeipa-host-access-policy.yml"

// loadHostAccessPolicyTasks returns the task file's raw text and every task
// mapping in it, flattened through block/rescue/always.
func loadHostAccessPolicyTasks(t *testing.T) (string, []map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(hostAccessPolicyTaskPath)
	if err != nil {
		t.Fatalf("read %s: %v", hostAccessPolicyTaskPath, err)
	}
	var top []map[string]any
	if err := yaml.Unmarshal(raw, &top); err != nil {
		t.Fatalf("parse %s: %v", hostAccessPolicyTaskPath, err)
	}
	var flat []map[string]any
	var walk func([]map[string]any)
	walk = func(tasks []map[string]any) {
		for _, task := range tasks {
			flat = append(flat, task)
			for _, key := range []string{"block", "rescue", "always"} {
				nested, ok := task[key].([]any)
				if !ok {
					continue
				}
				var children []map[string]any
				for _, n := range nested {
					if m, ok := n.(map[string]any); ok {
						children = append(children, m)
					}
				}
				walk(children)
			}
		}
	}
	walk(top)
	return string(raw), flat
}

func taskArgv(task map[string]any) []string {
	cmd, ok := task["ansible.builtin.command"].(map[string]any)
	if !ok {
		return nil
	}
	list, ok := cmd["argv"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		out = append(out, strings.TrimSpace(toString(v)))
	}
	return out
}

func toString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	default:
		b, _ := json.Marshal(s)
		return string(b)
	}
}

func taskWhen(task map[string]any) string {
	switch w := task["when"].(type) {
	case string:
		return w
	case []any:
		parts := make([]string, 0, len(w))
		for _, p := range w {
			parts = append(parts, toString(p))
		}
		return strings.Join(parts, " and ")
	default:
		return ""
	}
}

// TestRegression_FreeipaHostAccessPolicyTask_StaticSafetyInvariants locks
// the static invariants of per-host recording spec §34.10 items 1–14
// against the task file itself.
func TestRegression_FreeipaHostAccessPolicyTask_StaticSafetyInvariants(t *testing.T) {
	text, tasks := loadHostAccessPolicyTasks(t)

	// 1. Exact dedicated namespace, matched case-insensitively.
	if !strings.Contains(text, "PREFIX = 'pilot.policy.ssh-recording='") {
		t.Error("plan script must use the exact pilot.policy.ssh-recording= namespace")
	}
	if !strings.Contains(text, `re.compile(r'^pilot\.policy\.ssh-recording=', re.IGNORECASE)`) {
		t.Error("managed-value detection must be case-insensitive (userClass equality is case-insensitive in LDAP)")
	}

	// 2. Never manages annotation values.
	if strings.Contains(text, "pilot.annotation.") {
		t.Error("access policy reconcile must not reference pilot.annotation.* — those belong to freeipa-host-annotations.yml")
	}

	// 3. Never full-replaces userClass (checked on real argv, not comments).
	for _, task := range tasks {
		for _, arg := range taskArgv(task) {
			if strings.HasPrefix(arg, "--setattr") {
				t.Errorf("task %q uses %s; a full userClass replacement drops foreign values", toString(task["name"]), arg)
			}
		}
	}
	if !strings.Contains(text, "--addattr=userclass=") || !strings.Contains(text, "--delattr=userclass=") {
		t.Error("mutations must be scoped --addattr/--delattr on userclass")
	}

	// 4. Foreign values are carried through and asserted after apply.
	if !strings.Contains(text, "preserve_foreign") || !strings.Contains(text, "Gate: foreign userClass values (including annotations) are unchanged after apply") {
		t.Error("expected foreign-value preservation plus a post-apply foreign-unchanged gate")
	}

	// 5/6. Conflict codes are produced before the first mutation.
	firstMutation := strings.Index(text, "--delattr=userclass=")
	if add := strings.Index(text, "--addattr=userclass="); add >= 0 && (firstMutation < 0 || add < firstMutation) {
		firstMutation = add
	}
	for _, code := range []string{"CONFLICT_DUPLICATE_SSH_RECORDING_POLICY", "CONFLICT_MALFORMED_SSH_RECORDING_POLICY", "CONFLICT_UNKNOWN_SSH_RECORDING_POLICY"} {
		idx := strings.Index(text, code)
		if idx < 0 {
			t.Errorf("missing conflict code %s", code)
			continue
		}
		if firstMutation >= 0 && idx > firstMutation {
			t.Errorf("%s must be detected before any userClass mutation", code)
		}
	}
	gate := strings.Index(text, "Gate: access policy reconcile plan must have no conflicts before any mutation")
	if gate < 0 || gate > firstMutation {
		t.Error("the conflict gate assert must precede the first mutation task")
	}

	var ipaCalls, mutations, hostShows int
	for _, task := range tasks {
		name := toString(task["name"])
		argv := taskArgv(task)

		// 11/12. Every ipa call is argv form with the admin endpoint override.
		if len(argv) > 0 && argv[0] == "ipa" {
			ipaCalls++
			if len(argv) < 3 || argv[1] != "-e" || !strings.HasPrefix(argv[2], "xmlrpc_uri=https://") {
				t.Errorf("task %q: ipa call must pass -e xmlrpc_uri=https://<admin endpoint>/ipa/xml, got %v", name, argv)
			}
			switch {
			case len(argv) > 3 && argv[3] == "host-mod":
				mutations++
				// 7. Check mode never mutates.
				if !strings.Contains(taskWhen(task), "not ansible_check_mode") {
					t.Errorf("mutation task %q must be gated on `not ansible_check_mode`", name)
				}
			case len(argv) > 3 && argv[3] == "host-show":
				hostShows++
			case len(argv) > 3 && argv[3] == "host-add":
				// 11. No host-add fallback.
				t.Errorf("task %q: must never create a host object (host-add)", name)
			}
		}

		// 12. No shell anywhere.
		if _, ok := task["ansible.builtin.shell"]; ok {
			t.Errorf("task %q uses ansible.builtin.shell; use command argv", name)
		}
		if _, ok := task["shell"]; ok {
			t.Errorf("task %q uses shell; use command argv", name)
		}

		// 10/13. kinit (the only task handling the admin password) is no_log.
		if len(argv) > 0 && argv[0] == "kinit" {
			if task["no_log"] != true {
				t.Errorf("kinit task %q must be no_log: true", name)
			}
		}

		// Variable prefix: every set_fact key and register name is ipa_host_policy_*.
		if facts, ok := task["ansible.builtin.set_fact"].(map[string]any); ok {
			for k := range facts {
				if !strings.HasPrefix(k, "ipa_host_policy_") {
					t.Errorf("task %q sets fact %q; all facts must use the ipa_host_policy_ prefix", name, k)
				}
			}
		}
		if reg, ok := task["register"].(string); ok && !strings.HasPrefix(reg, "ipa_host_policy_") {
			t.Errorf("task %q registers %q; all registers must use the ipa_host_policy_ prefix", name, reg)
		}
	}
	if ipaCalls == 0 || mutations != 2 {
		t.Errorf("expected ipa calls with exactly two host-mod mutation tasks (delattr, addattr), got calls=%d mutations=%d", ipaCalls, mutations)
	}
	// 8. A post-write re-read exists (the initial read plus the verify read).
	if hostShows < 2 || !strings.Contains(text, "(Phase F) — re-read live state for verification") {
		t.Errorf("expected a live read and a post-write verification re-read, got %d host-show calls", hostShows)
	}
	if !strings.Contains(text, "Gate: post-apply managed policy value exactly matches desired") {
		t.Error("expected an exact-match post-apply gate on the managed value")
	}

	// 14. Host absence and FreeIPA unreachability are classified separately.
	if !strings.Contains(text, "HOST_ABSENT") || !strings.Contains(text, "FREEIPA_UNREACHABLE") {
		t.Error("host-show failures must be classified as HOST_ABSENT or FREEIPA_UNREACHABLE, not conflated")
	}
	if strings.Contains(text, "command: ipa ") || strings.Contains(text, "cmd: ipa ") {
		t.Error("ipa must be invoked in argv form, never a command string")
	}
}

// TestRegression_FreeipaClientApplyPlaybook_AccessPolicyIncludeOrderAndTags
// locks per-host recording spec §8.1 / §34.10 item 13.
func TestRegression_FreeipaClientApplyPlaybook_AccessPolicyIncludeOrderAndTags(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-client-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)
	annotationsIdx := strings.Index(playbook, "file: tasks/freeipa-host-annotations.yml")
	policyIdx := strings.Index(playbook, "file: tasks/freeipa-host-access-policy.yml")
	if annotationsIdx < 0 || policyIdx < 0 {
		t.Fatal("both includes must use the `file:` + `apply:` form")
	}
	if policyIdx < annotationsIdx {
		t.Error("the access policy include must come after the annotations include")
	}
	for _, include := range []struct{ file, tag string }{
		{"tasks/freeipa-host-annotations.yml", "host-annotations"},
		{"tasks/freeipa-host-access-policy.yml", "host-access-policy"},
	} {
		idx := strings.Index(playbook, "file: "+include.file)
		window := playbook[idx:]
		if end := strings.Index(window, "\n\n"); end > 0 {
			window = window[:end]
		}
		if !strings.Contains(window, "apply:\n") || !strings.Contains(window, "tags: [freeipa-client, "+include.tag+"]") {
			t.Errorf("include of %s must propagate tags via `apply: tags: [freeipa-client, %s]`:\n%s", include.file, include.tag, window)
		}
	}
}

// TestRegression_FreeipaHostAccessPolicyPlanScript_ReconcileMatrix runs the
// task file's own embedded plan script against every row of per-host
// recording spec §8.3.
func TestRegression_FreeipaHostAccessPolicyPlanScript_ReconcileMatrix(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	_, tasks := loadHostAccessPolicyTasks(t)
	var script string
	for _, task := range tasks {
		if facts, ok := task["ansible.builtin.set_fact"].(map[string]any); ok {
			if s, ok := facts["ipa_host_policy_plan_script"].(string); ok {
				script = s
			}
		}
	}
	if script == "" {
		t.Fatal("ipa_host_policy_plan_script not found")
	}

	const (
		off = "pilot.policy.ssh-recording=off"
		out = "pilot.policy.ssh-recording=terminal_output"
	)
	foreign := []string{"external-provisioning", "pilot.annotation.location=DC1"}
	cases := []struct {
		name      string
		desired   string
		live      []string
		wantOK    bool
		wantCode  string
		wantAdd   []string
		wantDel   []string
		wantNoop  bool
		wantKeepF []string
	}{
		{name: "inherit+absent", desired: "", live: foreign, wantOK: true, wantNoop: true, wantKeepF: foreign},
		{name: "inherit+valid deletes", desired: "", live: append([]string{out}, foreign...), wantOK: true, wantDel: []string{out}, wantKeepF: foreign},
		{name: "off+absent adds", desired: "off", live: nil, wantOK: true, wantAdd: []string{off}},
		{name: "off+off noop", desired: "off", live: []string{off}, wantOK: true, wantNoop: true},
		{name: "off+other replaces", desired: "off", live: []string{out}, wantOK: true, wantDel: []string{out}, wantAdd: []string{off}},
		{name: "output+absent adds", desired: "terminal_output", live: foreign, wantOK: true, wantAdd: []string{out}, wantKeepF: foreign},
		{name: "output+same noop", desired: "terminal_output", live: []string{out}, wantOK: true, wantNoop: true},
		{name: "output+off replaces", desired: "terminal_output", live: []string{off}, wantOK: true, wantDel: []string{off}, wantAdd: []string{out}},
		{name: "duplicate fails", desired: "off", live: []string{off, out}, wantCode: "CONFLICT_DUPLICATE_SSH_RECORDING_POLICY"},
		{name: "empty value malformed", desired: "", live: []string{"pilot.policy.ssh-recording="}, wantCode: "CONFLICT_MALFORMED_SSH_RECORDING_POLICY"},
		{name: "case variant malformed", desired: "terminal_output", live: []string{"Pilot.Policy.SSH-Recording=terminal_output"}, wantCode: "CONFLICT_MALFORMED_SSH_RECORDING_POLICY"},
		{name: "unknown value", desired: "off", live: []string{"pilot.policy.ssh-recording=banana"}, wantCode: "CONFLICT_UNKNOWN_SSH_RECORDING_POLICY"},
		{name: "reserved terminal_io is unknown", desired: "", live: []string{"pilot.policy.ssh-recording=terminal_io"}, wantCode: "CONFLICT_UNKNOWN_SSH_RECORDING_POLICY"},
		{name: "other pilot.policy namespace is foreign", desired: "", live: []string{"pilot.policy.userclass-canary=1"}, wantOK: true, wantNoop: true, wantKeepF: []string{"pilot.policy.userclass-canary=1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			live := c.live
			if live == nil {
				live = []string{}
			}
			input, _ := json.Marshal(map[string]any{"desired": c.desired, "live_userclass": live})
			outRaw, _ := exec.Command(python, "-c", script, string(input)).Output()
			var got struct {
				OK              bool     `json:"ok"`
				Errors          []string `json:"errors"`
				Add             []string `json:"add"`
				Delete          []string `json:"delete"`
				Noop            bool     `json:"noop"`
				PreserveForeign []string `json:"preserve_foreign"`
				ExpectedManaged []string `json:"expected_managed"`
			}
			if err := json.Unmarshal(outRaw, &got); err != nil {
				t.Fatalf("plan script output %q: %v", outRaw, err)
			}
			if c.wantCode != "" {
				if got.OK || len(got.Errors) != 1 || !strings.HasPrefix(got.Errors[0], c.wantCode) {
					t.Fatalf("want failure %s, got ok=%v errors=%v", c.wantCode, got.OK, got.Errors)
				}
				return
			}
			if !got.OK {
				t.Fatalf("unexpected failure: %v", got.Errors)
			}
			norm := func(s []string) []string {
				if len(s) == 0 {
					return nil
				}
				return s
			}
			if !reflect.DeepEqual(norm(got.Add), norm(c.wantAdd)) || !reflect.DeepEqual(norm(got.Delete), norm(c.wantDel)) || got.Noop != c.wantNoop {
				t.Fatalf("plan add=%v delete=%v noop=%v, want add=%v delete=%v noop=%v", got.Add, got.Delete, got.Noop, c.wantAdd, c.wantDel, c.wantNoop)
			}
			if !reflect.DeepEqual(norm(got.PreserveForeign), norm(c.wantKeepF)) {
				t.Fatalf("preserve_foreign=%v, want %v", got.PreserveForeign, c.wantKeepF)
			}
			wantManaged := []string(nil)
			if c.desired != "" {
				wantManaged = []string{"pilot.policy.ssh-recording=" + c.desired}
			}
			if !reflect.DeepEqual(norm(got.ExpectedManaged), wantManaged) {
				t.Fatalf("expected_managed=%v, want %v", got.ExpectedManaged, wantManaged)
			}
		})
	}
}

// hostAccessPolicyUserclassRe is the playbook's own userclass extraction
// regex, in the dialect both Python and Go RE2 accept.
var hostAccessPolicyUserclassRe = regexp.MustCompile(`(?im)^[ \t]*userclass: (.+)$`)

// hostShowCapture is one Phase 0 real capture fixture split into its parts.
type hostShowCapture struct {
	rc             string
	stdout, stderr string
}

func loadHostShowCapture(t *testing.T, name string) hostShowCapture {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var c hostShowCapture
	section := ""
	var out, errOut []string
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "# rc="):
			c.rc = strings.TrimPrefix(line, "# rc=")
		case line == "# --- stdout ---":
			section = "stdout"
		case line == "# --- stderr ---":
			section = "stderr"
		case strings.HasPrefix(line, "#") && section == "":
			// file header comment
		case section == "stdout":
			out = append(out, line)
		case section == "stderr":
			errOut = append(errOut, line)
		}
	}
	c.stdout = strings.Join(out, "\n")
	c.stderr = strings.TrimSpace(strings.Join(errOut, "\n"))
	return c
}

func runHostAccessPolicyPlan(t *testing.T, desired string, live []string) map[string]any {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	_, tasks := loadHostAccessPolicyTasks(t)
	var script string
	for _, task := range tasks {
		if facts, ok := task["ansible.builtin.set_fact"].(map[string]any); ok {
			if s, ok := facts["ipa_host_policy_plan_script"].(string); ok {
				script = s
			}
		}
	}
	if live == nil {
		live = []string{}
	}
	input, _ := json.Marshal(map[string]any{"desired": desired, "live_userclass": live})
	out, _ := exec.Command(python, "-c", script, string(input)).Output()
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("plan script output %q: %v", out, err)
	}
	return got
}

// TestRegression_FreeipaHostAccessPolicy_RealUserclassFixtures locks
// per-host recording spec §34.10 item 15: the playbook's own userclass
// regex, applied to real `ipa host-show --all --raw` captures, yields the
// exact values, and the plan script classifies each real state correctly.
func TestRegression_FreeipaHostAccessPolicy_RealUserclassFixtures(t *testing.T) {
	text, _ := loadHostAccessPolicyTasks(t)
	if !strings.Contains(text, `regex_findall('(?im)^[ \t]*userclass: (.+)$')`) {
		t.Fatal("the task file's userclass extraction regex changed; update hostAccessPolicyUserclassRe to match")
	}
	extract := func(stdout string) []string {
		var vals []string
		for _, m := range hostAccessPolicyUserclassRe.FindAllStringSubmatch(stdout, -1) {
			vals = append(vals, m[1])
		}
		return vals
	}

	valid := loadHostShowCapture(t, "freeipa-host-show-raw-userclass-valid.txt")
	if valid.rc != "0" {
		t.Fatalf("valid fixture rc=%s", valid.rc)
	}
	wantValid := []string{"external-provisioning", "pilot.annotation.location=DC1", "pilot.policy.ssh-recording=terminal_output"}
	if got := extract(valid.stdout); !reflect.DeepEqual(got, wantValid) {
		t.Fatalf("valid fixture userclass = %q, want %q", got, wantValid)
	}
	if plan := runHostAccessPolicyPlan(t, "terminal_output", wantValid); plan["ok"] != true || plan["noop"] != true {
		t.Errorf("valid fixture with matching desired should be NOOP, got %v", plan)
	}
	if plan := runHostAccessPolicyPlan(t, "", wantValid); plan["ok"] != true || !reflect.DeepEqual(plan["delete"], []any{"pilot.policy.ssh-recording=terminal_output"}) {
		t.Errorf("valid fixture with inherit should delete only the marker, got %v", plan)
	}

	dup := loadHostShowCapture(t, "freeipa-host-show-raw-userclass-duplicate.txt")
	dupVals := extract(dup.stdout)
	if len(dupVals) != 4 {
		t.Fatalf("duplicate fixture userclass = %q, want 4 values", dupVals)
	}
	if plan := runHostAccessPolicyPlan(t, "off", dupVals); plan["ok"] != false || !strings.HasPrefix(toString(plan["errors"].([]any)[0]), "CONFLICT_DUPLICATE_SSH_RECORDING_POLICY") {
		t.Errorf("duplicate fixture must fail with CONFLICT_DUPLICATE, got %v", plan)
	}

	cv := loadHostShowCapture(t, "freeipa-host-show-raw-userclass-casevariant.txt")
	cvVals := extract(cv.stdout)
	if !reflect.DeepEqual(cvVals, []string{"external-provisioning", "pilot.annotation.location=DC1", "Pilot.Policy.SSH-Recording=terminal_output"}) {
		t.Fatalf("case-variant fixture userclass = %q", cvVals)
	}
	if plan := runHostAccessPolicyPlan(t, "terminal_output", cvVals); plan["ok"] != false || !strings.HasPrefix(toString(plan["errors"].([]any)[0]), "CONFLICT_MALFORMED_SSH_RECORDING_POLICY") {
		t.Errorf("case-variant fixture must fail with CONFLICT_MALFORMED, got %v", plan)
	}
}

// TestRegression_FreeipaHostAccessPolicy_HostAbsentClassification locks
// per-host recording spec §34.10 item 16: the not-found pattern the task
// file uses matches FreeIPA's real not-found stderr and not the real
// unreachable-endpoint stderr.
func TestRegression_FreeipaHostAccessPolicy_HostAbsentClassification(t *testing.T) {
	_, tasks := loadHostAccessPolicyTasks(t)
	var pattern string
	for _, task := range tasks {
		if vars, ok := task["vars"].(map[string]any); ok {
			if p, ok := vars["ipa_host_policy_not_found_re"].(string); ok {
				pattern = p
			}
		}
	}
	if pattern == "" {
		t.Fatal("ipa_host_policy_not_found_re not found in the task file")
	}
	re := regexp.MustCompile(pattern)

	notFound := loadHostShowCapture(t, "freeipa-host-show-not-found.txt")
	if notFound.rc == "0" || !re.MatchString(notFound.stderr) {
		t.Errorf("not-found fixture (rc=%s stderr=%q) must be classified HOST_ABSENT by %q", notFound.rc, notFound.stderr, pattern)
	}
	unreachable := loadHostShowCapture(t, "freeipa-host-show-unreachable.txt")
	if unreachable.rc == "0" || re.MatchString(unreachable.stderr) {
		t.Errorf("unreachable fixture (rc=%s stderr=%q) must NOT be classified HOST_ABSENT by %q", unreachable.rc, unreachable.stderr, pattern)
	}
}
