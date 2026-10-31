package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// Issue #214: a FreeIPA sudo rule that newly applies to a user or host
// reached the enrolled clients only through SSSD's smart/full refresh
// (15 min / 6 h) or a restart, because `sss_cache -E` only expires rules the
// client already holds. Live captures on Ubuntu 24.04 (SSSD 2.9.4) and
// AlmaLinux 9.8 (SSSD 2.9.8), 2026-10-31:
//
//	new rule, user added to an existing rule, host added to a hostgroup:
//	  `sss_cache -E` does not make `sudo -l -U` allow it; a restart does,
//	  after sudoLastFullRefreshTime advanced about 10 s later
//	group member added, command added to a command group, any revocation:
//	  `sss_cache -E` alone is enough
//
// The helper therefore restarts SSSD and only reports success once the
// client's own sudoLastFullRefreshTime is a value that was not there before
// and is later than the second the restart finished. "Not older than the
// restart" would accept the stopping SSSD instance's own write in the restart's
// second (or an older marker after a clock step back) as the start-up refresh;
// the fakes therefore publish the start-up refresh only after a delay, like the
// real one, and model those two writers explicitly.

// runSudoRefreshHelper runs the production helper as Ansible does
// (`python3 -c <program>` with JSON on stdin) against the fake sss tools.
func runSudoRefreshHelper(t *testing.T, program, host string, input string) (stdout, stderr string, rc int) {
	t.Helper()
	cmd := exec.Command("python3", "-c", program)
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = append(os.Environ(), "CACHE_TEST_HOST="+host)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("python3 did not run: %v", err)
		}
		return out.String(), errb.String(), ee.ExitCode()
	}
	return out.String(), errb.String(), 0
}

// unfinishedClients returns the gate's failure entry from a run's failures.
func unfinishedClients(failures []string) string {
	for _, f := range failures {
		if strings.HasPrefix(f, sudoRefreshGate+":") {
			return f
		}
	}
	return ""
}

func readSudoRefreshProgram(t *testing.T) string {
	t.Helper()
	program, err := os.ReadFile(sudoRefreshProgram)
	if err != nil {
		t.Fatal(err)
	}
	return string(program)
}

// restartsOf returns the hosts whose SSSD the fake systemctl restarted.
func restartsOf(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "restarts"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(raw))
	slices.Sort(got)
	return got
}

func TestRegression_IdentitySSHCacheSudoRefreshHelper(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("python3 not installed: %v", err)
	}
	const input = `{"domain": "ipa.pilot.internal", "timeout": 3, "interval": 0.2}`
	program := readSudoRefreshProgram(t)
	setup := func(t *testing.T) (string, func(name, value string)) {
		dir := t.TempDir()
		write := installSSHCacheFakes(t, dir)
		write("calls", "")
		return dir, write
	}

	// Both captured ldbsearch layouts (Ubuntu 2.9.4, AlmaLinux 2.9.8) converge.
	for _, mode := range []string{"ldbsearch-marker-ubuntu-2.9.4", "ldbsearch-marker-el9-2.9.8"} {
		t.Run("converges/"+mode, func(t *testing.T) {
			dir, write := setup(t)
			write("ldb-mode-h", mode)
			stdout, stderr, rc := runSudoRefreshHelper(t, program, "h", input)
			if rc != 0 || !strings.Contains(stdout, `"converged": true`) {
				t.Fatalf("rc=%d stdout=%q stderr=%q", rc, stdout, stderr)
			}
			if got := readSSHCacheCalls(t, dir); !slices.Equal(got, []string{"h/*"}) {
				t.Fatalf("sss_cache calls = %v; want one global expiry", got)
			}
			if got := restartsOf(t, dir); !slices.Equal(got, []string{"h"}) {
				t.Fatalf("restarts = %v", got)
			}
		})
	}

	future := strconv.FormatInt(time.Now().Unix()+3600, 10)
	// The counterexamples. Each one fails on the invariant (no new full
	// refresh finished after the restart), not on a missing call.
	failures := []struct {
		name   string
		setup  func(write func(name, value string))
		want   string
		expire bool // sss_cache and the restart are still attempted
	}{
		{"offline: the restart does not advance the marker", func(w func(string, string)) { w("no-refresh-h", "") },
			"did not complete within 3s (sudoLastFullRefreshTime before=1, restarted at", true},
		{"no full refresh ever completed: container has no marker", func(w func(string, string)) { w("ldb-mode-h", "ldbsearch-no-container") },
			"now=None", true},
		{"restart fails", func(w func(string, string)) { w("fail-restart-h", "") }, "systemctl failed (rc=5)", true},
		{"cache expiry fails", func(w func(string, string)) { w("fail-global-h", "") }, "sss_cache failed (rc=9)", false},
		// The race behind the review of #222: the stopping instance records a
		// refresh in the restart's second and the new one never refreshes.
		// "Not older than the restart" read that as the start-up refresh.
		{"the stopping instance's write in the restart's second is not the start-up refresh",
			func(w func(string, string)) { w("stale-refresh-h", ""); w("no-refresh-h", "") },
			"did not complete within 3s (sudoLastFullRefreshTime before=1, restarted at", true},
		// A marker from the future (clock stepped back since the last refresh)
		// is newer than the restart without being a refresh the restart caused.
		{"a marker newer than the restart that the restart did not change",
			func(w func(string, string)) { w("marker-h", future); w("no-refresh-h", "") },
			"before=" + future + ", restarted at", true},
		{"cache database unreadable: nothing is touched", func(w func(string, string)) { w("ldb-mode-h", "ldbsearch-no-db") },
			"cannot read the SSSD sudo cache (ldbsearch rc=1)", false},
	}
	for _, tc := range failures {
		t.Run("fails/"+tc.name, func(t *testing.T) {
			dir, write := setup(t)
			tc.setup(write)
			stdout, stderr, rc := runSudoRefreshHelper(t, program, "h", input)
			if rc == 0 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("rc=%d stdout=%q stderr=%q; want failure containing %q", rc, stdout, stderr, tc.want)
			}
			if strings.Contains(stdout, "converged") {
				t.Fatalf("failure reported convergence: %q", stdout)
			}
			if !tc.expire && len(restartsOf(t, dir)) != 0 {
				t.Fatalf("SSSD was restarted although the precondition failed: %v", restartsOf(t, dir))
			}
		})
	}

	// The controls for the counterexamples above: the same writers, followed
	// by the start-up refresh, converge. A fake that never refreshes would
	// pass every failure case, so these show the helper keeps waiting for the
	// refresh it needs instead of failing on the stale value.
	converging := []struct {
		name  string
		setup func(write func(name, value string))
	}{
		{"the stopping instance writes first, then the start-up refresh lands",
			func(w func(string, string)) { w("stale-refresh-h", "") }},
		{"a marker from the future (clock stepped back), then the start-up refresh lands",
			func(w func(string, string)) { w("marker-h", future) }},
		{"no marker before (never refreshed): the start-up refresh creates it",
			func(w func(string, string)) { w("absent-until-refresh-h", "") }},
	}
	for _, tc := range converging {
		t.Run("converges/"+tc.name, func(t *testing.T) {
			dir, write := setup(t)
			tc.setup(write)
			stdout, stderr, rc := runSudoRefreshHelper(t, program, "h", input)
			if rc != 0 || !strings.Contains(stdout, `"converged": true`) {
				t.Fatalf("rc=%d stdout=%q stderr=%q", rc, stdout, stderr)
			}
			if got := restartsOf(t, dir); !slices.Equal(got, []string{"h"}) {
				t.Fatalf("restarts = %v", got)
			}
		})
	}

	// Mutation: the pre-#214 behaviour (expire only, no restart) must be
	// rejected by the helper's own check, because the marker never moves.
	t.Run("mutation: expire without restart is not convergence", func(t *testing.T) {
		dir, _ := setup(t)
		mutated := strings.Replace(program, `, ["systemctl", "restart", "sssd"])`, `,)`, 1)
		if mutated == program {
			t.Fatal("mutation did not apply: helper no longer lists the restart command")
		}
		_, stderr, rc := runSudoRefreshHelper(t, mutated, "h", input)
		if rc == 0 || !strings.Contains(stderr, "did not complete within 3s") {
			t.Fatalf("expire-only helper rc=%d stderr=%q; want the convergence check to fail", rc, stderr)
		}
		if len(restartsOf(t, dir)) != 0 {
			t.Fatal("mutation still restarted SSSD")
		}
	})

	t.Run("rejects an invalid domain before touching anything", func(t *testing.T) {
		dir, _ := setup(t)
		_, stderr, rc := runSudoRefreshHelper(t, program, "h", `{"domain": "x;rm -rf /"}`)
		if rc == 0 || !strings.Contains(stderr, "invalid domain") {
			t.Fatalf("rc=%d stderr=%q", rc, stderr)
		}
		if got := readSSHCacheCalls(t, dir); len(got) != 0 || len(restartsOf(t, dir)) != 0 {
			t.Fatalf("calls=%v restarts=%v", got, restartsOf(t, dir))
		}
	})
}

// A client enrolled before ldb-tools joined freeipa-client-apply.yml has no
// ldbsearch. The helper must fail before touching SSSD, with the instruction
// that fixes it, not a Python traceback (the main upgrade path).
func TestRegression_IdentitySSHCacheSudoRefreshWithoutLdbTools(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 not installed: %v", err)
	}
	dir := t.TempDir()
	write := installSSHCacheFakes(t, dir)
	write("calls", "")
	// A PATH that holds only the fake sss_cache and systemctl: no ldbsearch,
	// whatever the machine running the test has installed.
	bin := t.TempDir()
	for _, name := range []string{"sss_cache", "systemctl"} {
		if err := os.Symlink(filepath.Join(dir, name), filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(python, "-c", readSudoRefreshProgram(t))
	cmd.Stdin = strings.NewReader(`{"domain": "ipa.pilot.internal", "timeout": 3}`)
	cmd.Env = append(os.Environ(), "PATH="+bin, "CACHE_TEST_HOST=old-client")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err = cmd.Run()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 1 {
		t.Fatalf("want exit 1, got %v; stderr=%q", err, stderr.String())
	}
	for _, want := range []string{"ldbsearch not found", "freeipa-client-apply.yml"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr %q lacks %q", stderr.String(), want)
		}
	}
	if strings.Contains(stderr.String(), "Traceback") {
		t.Fatalf("a Python traceback instead of the instruction: %q", stderr.String())
	}
	if got := readSSHCacheCalls(t, dir); len(got) != 0 || len(restartsOf(t, dir)) != 0 {
		t.Fatalf("SSSD was touched although the marker could not be read: calls=%v restarts=%v", got, restartsOf(t, dir))
	}
}

// The helper reads the marker with ldbsearch, so freeipa-client-apply.yml must
// install ldb-tools on both OS families, under the tags of the SSSD tools
// install. Dropping the package passes every runtime test above and fails every
// client's identity apply (AGENTS.md 5.7: a pair that must change together).
func TestRegression_IdentitySSHCacheSudoRefreshToolIsInstalledByClientApply(t *testing.T) {
	if !strings.Contains(readSudoRefreshProgram(t), `"ldbsearch"`) {
		t.Fatal("the helper no longer calls ldbsearch: update this pairing")
	}
	raw, err := os.ReadFile("../../playbooks/apply/freeipa-client-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var debian, redhat bool
	var walk func([]any)
	walk = func(all []any) {
		for _, value := range all {
			task, _ := value.(map[string]any)
			if task == nil {
				continue
			}
			tags := fmt.Sprint(task["tags"])
			if strings.Contains(fmt.Sprint(task["name"]), "install SSSD cache tools") {
				if !strings.Contains(tags, "C8") {
					t.Errorf("task %q lost its C8 tag: %s", task["name"], tags)
				}
				if vars, ok := task["vars"].(map[string]any); ok {
					debian = debian || strings.Contains(fmt.Sprint(vars["pilot_apt_packages"]), "ldb-tools")
				}
				if dnf, ok := task["ansible.builtin.dnf"].(map[string]any); ok {
					redhat = redhat || strings.Contains(fmt.Sprint(dnf["name"]), "ldb-tools")
				}
			}
			if inner, ok := task["block"].([]any); ok {
				walk(inner)
			}
		}
	}
	for _, play := range plays {
		for _, key := range []string{"pre_tasks", "tasks", "post_tasks"} {
			if tasks, ok := play[key].([]any); ok {
				walk(tasks)
			}
		}
	}
	if !debian || !redhat {
		t.Fatalf("freeipa-client-apply.yml must install ldb-tools on Debian (apt framework vars) and RedHat (dnf): debian=%v redhat=%v", debian, redhat)
	}
}

// The refresh task's own settings, parsed (substring checks would be satisfied
// by the SSH-key refresh task's identical lines): bounded connect and task time
// (a suspended client otherwise hangs the apply), errors collected for the gate,
// a gate that derives the clients it expects from the loop's inputs (one
// resolved list, shared), and a timeout that an inventory value can still change.
func TestRegression_IdentitySSHCacheSudoRefreshTaskShape(t *testing.T) {
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	if _, shadowed := plays[0]["vars"].(map[string]any)["ipa_identity_sudo_refresh_timeout"]; shadowed {
		t.Error("ipa_identity_sudo_refresh_timeout is a play var: it would shadow an inventory value (AGENTS.md 4.5 item 3)")
	}
	var resolve, refresh, gate map[string]any
	var walk func([]any)
	walk = func(all []any) {
		for _, value := range all {
			task, _ := value.(map[string]any)
			switch task["name"] {
			case sudoRefreshResolve:
				resolve = task
			case "Refresh SSSD caches on enrolled FreeIPA clients":
				refresh = task
			case sudoRefreshGate:
				gate = task
			}
			if inner, ok := task["block"].([]any); ok {
				walk(inner)
			}
		}
	}
	walk(plays[0]["tasks"].([]any))
	if refresh == nil || gate == nil {
		t.Fatalf("refresh task=%v gate=%v", refresh != nil, gate != nil)
	}
	taskVars, _ := refresh["vars"].(map[string]any)
	if fmt.Sprint(taskVars["ansible_connect_timeout"]) != "5" || fmt.Sprint(taskVars["ansible_ssh_timeout"]) != "5" {
		t.Errorf("refresh connect timeouts = %v", taskVars)
	}
	if !strings.Contains(fmt.Sprint(refresh["timeout"]), "ipa_identity_sudo_refresh_timeout | default(60)") {
		t.Errorf("refresh task timeout must derive from the per-client bound, got %v", refresh["timeout"])
	}
	if refresh["ignore_errors"] != true || refresh["ignore_unreachable"] != true {
		t.Errorf("refresh must collect failures for the gate: ignore_errors=%v ignore_unreachable=%v", refresh["ignore_errors"], refresh["ignore_unreachable"])
	}
	// The clients to refresh are resolved once and the loop and the gate both
	// read that result: two copies of the expression drifted apart before
	// (a substring test on the deferred hosts hid client-1 behind client-10 in
	// both). The resolving task is a setter for tasks carrying the same tags
	// and conditions, so it runs whenever they do (AGENTS.md 4.4).
	if got := strings.TrimSpace(fmt.Sprint(refresh["loop"])); got != "{{ ipa_sudo_refresh_clients }}" {
		t.Errorf("refresh loop must read the resolved client list, got %q", got)
	}
	gateVars, _ := gate["vars"].(map[string]any)
	if got := strings.TrimSpace(fmt.Sprint(gateVars["ipa_sudo_refresh_expected"])); got != "{{ ipa_sudo_refresh_clients }}" {
		t.Errorf("gate must expect exactly the clients the loop was given, got %q", got)
	}
	if resolve == nil {
		t.Fatal("the task resolving the clients to refresh is missing")
	}
	setFact, _ := resolve["ansible.builtin.set_fact"].(map[string]any)
	resolveVars, _ := resolve["vars"].(map[string]any)
	resolved := fmt.Sprint(setFact["ipa_sudo_refresh_clients"])
	deferred := fmt.Sprint(resolveVars["ipa_sudo_deferred_hosts"])
	for _, want := range []string{"groups.get('freeipa-client'", "reject('in', ipa_sudo_deferred_hosts)"} {
		if !strings.Contains(resolved, want) {
			t.Errorf("resolved clients must derive from the inventory group minus the deferred hosts (missing %q): %s", want, resolved)
		}
	}
	for _, want := range []string{"pilot_deferred_hosts", "from_json", " is string"} {
		if !strings.Contains(deferred, want) {
			t.Errorf("deferred hosts passed as a string must be parsed as JSON (missing %q): %s", want, deferred)
		}
	}
	for _, key := range []string{"tags", "when"} {
		if fmt.Sprint(resolve[key]) != fmt.Sprint(refresh[key]) || fmt.Sprint(resolve[key]) != fmt.Sprint(gate[key]) {
			t.Errorf("resolve, refresh and gate must share %s: %v / %v / %v", key, resolve[key], refresh[key], gate[key])
		}
	}
	if !strings.Contains(fmt.Sprint(gateVars["ipa_sudo_refresh_unfinished"]), "difference(") {
		t.Errorf("gate must subtract the converged clients from the expected ones: %v", gateVars["ipa_sudo_refresh_unfinished"])
	}
}

// sudoRefreshProductionTasks returns the production tasks of the given names
// from the identity playbook, in playbook order, adapted to run unprivileged
// against the fakes in dir: no become, and the refresh task gets the fake
// host's environment.
func sudoRefreshProductionTasks(t *testing.T, dir string, names ...string) []any {
	t.Helper()
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var tasks []any
	var collect func([]any)
	collect = func(all []any) {
		for _, value := range all {
			task := value.(map[string]any)
			if name, _ := task["name"].(string); slices.Contains(names, name) {
				delete(task, "become") // test runs unprivileged; production uses root
				if name == "Refresh SSSD caches on enrolled FreeIPA clients" {
					task["environment"] = map[string]any{"CACHE_TEST_HOST": "{{ item }}", "CACHE_TEST_DIR": dir}
				}
				tasks = append(tasks, task)
			}
			if inner, ok := task["block"].([]any); ok {
				collect(inner)
			}
		}
	}
	collect(plays[0]["tasks"].([]any))
	if len(tasks) != len(names) {
		t.Fatalf("production tasks %q found: %d", names, len(tasks))
	}
	return tasks
}

// localSudoRefreshClients declares test clients on a local connection, and a
// stand-in for the settlement the refresh task reads (sudo_test_dirty).
func localSudoRefreshClients(hosts ...string) []any {
	var tasks []any
	for _, host := range hosts {
		tasks = append(tasks, map[string]any{"name": "test inventory " + host, "tags": []string{"always"},
			"ansible.builtin.add_host": map[string]any{"name": host, "groups": "freeipa-client", "ansible_connection": "local"}})
	}
	return append(tasks, map[string]any{"name": "settlement", "tags": []string{"always"},
		"ansible.builtin.set_fact": map[string]any{"ipa_auth_cache_settle": map[string]any{"stdout": "{{ {'dirty': sudo_test_dirty} | to_json }}"}}})
}

// TestRegression_IdentitySSHCacheSudoRefreshPlaybook runs the production
// refresh task and gate through real Ansible: only sss_cache, ldbsearch and
// systemctl are fakes (built from real captures). It checks which clients are
// contacted, that one failing client neither blocks nor hides the others, and
// that the apply fails (PARTIAL) while any client has no completed refresh.
func TestRegression_IdentitySSHCacheSudoRefreshPlaybook(t *testing.T) {
	dir := t.TempDir()
	write := installSSHCacheFakes(t, dir)
	tasks := []any{}
	// client-b can be made unreachable: an unreachable loop item registers no
	// rc, which the gate must report instead of raising on.
	for _, host := range []string{"client-a", "client-b"} {
		connection, address := "local", "127.0.0.3"
		if host == "client-b" {
			connection = "{{ 'ssh' if sudo_test_unreachable | default(false) else 'local' }}"
			address = "127.0.0.2"
		}
		tasks = append(tasks, map[string]any{"name": "test inventory " + host, "tags": []string{"always"},
			"ansible.builtin.add_host": map[string]any{"name": host, "groups": "freeipa-client",
				"ansible_connection": connection, "ansible_host": address, "ansible_port": 1}})
	}
	tasks = append(tasks, map[string]any{"name": "settlement", "tags": []string{"always"},
		"ansible.builtin.set_fact": map[string]any{"ipa_auth_cache_settle": map[string]any{"stdout": "{{ {'dirty': sudo_test_dirty} | to_json }}"}}})
	inventory := slices.Clone(tasks)
	production := sudoRefreshProductionTasks(t, dir, sudoRefreshResolve, "Refresh SSSD caches on enrolled FreeIPA clients", sudoRefreshGate)
	tasks = append(tasks, production...)
	vars := withSudoRefresh(t, map[string]any{"ipa_domain": "ipa.pilot.internal", "stage": "sandbox",
		"ipa_identity_refresh_sssd_cache": true, "sudo_test_dirty": true})
	// The fake's start-up refresh lands about 1.5 s after the restart and the
	// helper polls once a second: leave room for the third poll.
	vars["ipa_identity_sudo_refresh_timeout"] = 5

	reset := func() {
		t.Helper()
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if n := e.Name(); n == "restarts" || strings.HasPrefix(n, "marker-") || strings.HasPrefix(n, "no-refresh-") ||
				strings.HasPrefix(n, "fail-restart-") || strings.HasPrefix(n, "ldb-mode-") || strings.HasPrefix(n, "refresh-due-") ||
				strings.HasPrefix(n, "stale-refresh-") || strings.HasPrefix(n, "absent-until-refresh-") {
				_ = os.Remove(filepath.Join(dir, n))
			}
		}
		write("calls", "")
	}
	run := func(extra map[string]any, args ...string) ag82Run {
		t.Helper()
		reset()
		return runGatewayTasks(t, dir, tasks, vars, extra, args...)
	}
	expect := func(label string, result ag82Run, success bool, restarted ...string) {
		t.Helper()
		if (result.rc == 0) != success {
			t.Fatalf("%s: rc=%d failures=%v\n%s", label, result.rc, result.failures, result.raw)
		}
		if got := restartsOf(t, dir); !slices.Equal(got, restarted) {
			t.Fatalf("%s: restarted %v; want %v\n%s", label, got, restarted, result.raw)
		}
	}

	expect("every client converges", run(nil), true, "client-a", "client-b")
	for _, host := range []string{"client-a", "client-b"} {
		raw, err := os.ReadFile(filepath.Join(dir, "marker-"+host))
		if err != nil {
			t.Fatalf("%s: marker not advanced: %v", host, err)
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err != nil || time.Since(time.Unix(n, 0)) > time.Minute {
			t.Fatalf("%s: marker %q is not a fresh epoch", host, raw)
		}
	}

	// A client whose SSSD cannot reach FreeIPA never completes the refresh:
	// the apply fails PARTIAL naming only that client, and the other client
	// was still refreshed.
	reset()
	write("no-refresh-client-b", "")
	partial := runGatewayTasks(t, dir, tasks, vars, nil)
	if partial.rc == 0 {
		t.Fatalf("a client without a completed refresh must fail the apply\n%s", partial.raw)
	}
	if got := restartsOf(t, dir); !slices.Equal(got, []string{"client-a", "client-b"}) {
		t.Fatalf("restarted %v; want both (the failing client must not block the other)", got)
	}
	// The callback JSON-escapes the quotes of the host list.
	gateMessage := unfinishedClients(partial.failures)
	if !strings.Contains(gateMessage, `[\"client-b\"]`) || !strings.Contains(gateMessage, "PARTIAL") {
		t.Fatalf("gate message does not name only the unfinished client: %v", partial.failures)
	}

	expect("the next apply repeats the refresh once the client recovers", run(nil), true, "client-a", "client-b")

	// The stopping SSSD instance records a refresh in the restart's second and
	// the new instance never refreshes (the race the review of #222 found).
	// That is not a completed refresh: PARTIAL naming only that client. The
	// same writer followed by the real start-up refresh converges.
	reset()
	write("stale-refresh-client-b", "")
	write("no-refresh-client-b", "")
	stale := runGatewayTasks(t, dir, tasks, vars, nil)
	if stale.rc == 0 {
		t.Fatalf("a marker written by the stopping instance must not count as the refresh\n%s", stale.raw)
	}
	if got := unfinishedClients(stale.failures); !strings.Contains(got, `[\"client-b\"]`) || !strings.Contains(got, "PARTIAL") {
		t.Fatalf("stale marker: gate did not report PARTIAL naming client-b: %v", stale.failures)
	}
	expect("the stopping instance writes, then the start-up refresh lands", func() ag82Run {
		reset()
		write("stale-refresh-client-b", "")
		return runGatewayTasks(t, dir, tasks, vars, nil)
	}(), true, "client-a", "client-b")

	// An unreachable client registers no rc. Real SSH to a closed port, as in
	// the live run where a suspended client produced this failure.
	reset()
	unreachable := runGatewayTasks(t, dir, tasks, vars, map[string]any{"sudo_test_unreachable": true})
	if unreachable.rc == 0 {
		t.Fatalf("an unreachable client must fail the apply\n%s", unreachable.raw)
	}
	if got := unfinishedClients(unreachable.failures); !strings.Contains(got, `[\"client-b\"]`) || !strings.Contains(got, "PARTIAL") {
		t.Fatalf("unreachable client: gate did not report PARTIAL naming client-b: %v", unreachable.failures)
	}
	if got := restartsOf(t, dir); !slices.Equal(got, []string{"client-a"}) {
		t.Fatalf("restarted %v; want only the reachable client-a", got)
	}

	// A deferred-hosts value that cannot be read must fail the apply before
	// any client is touched, never be read as "nothing deferred".
	reset()
	broken := runGatewayTasks(t, dir, tasks, vars, map[string]any{"pilot_deferred_hosts": 5})
	if broken.rc == 0 {
		t.Fatalf("an unreadable pilot_deferred_hosts must fail the apply\n%s", broken.raw)
	}
	if got := restartsOf(t, dir); len(got) != 0 {
		t.Fatalf("restarted %v although the client list could not be resolved", got)
	}

	// The refresh task itself failing before it registers any item (here the
	// resolving task did not run, so its loop has no list) registers no
	// results. The gate must fail the apply, not read that as nothing to do.
	reset()
	withoutResolve := append(slices.Clone(inventory), production[1:]...)
	starved := runGatewayTasks(t, dir, withoutResolve, vars, nil)
	if starved.rc == 0 {
		t.Fatalf("a refresh that could not even start must fail the apply\n%s", starved.raw)
	}
	if got := restartsOf(t, dir); len(got) != 0 {
		t.Fatalf("restarted %v although the refresh could not start", got)
	}

	// A failing restart is the same PARTIAL outcome.
	reset()
	write("fail-restart-client-a", "")
	if r := runGatewayTasks(t, dir, tasks, vars, nil); r.rc == 0 || !strings.Contains(unfinishedClients(r.failures), `[\"client-a\"]`) {
		t.Fatalf("restart failure: rc=%d failures=%v", r.rc, r.failures)
	}
	_ = os.Remove(filepath.Join(dir, "fail-restart-client-a"))

	// No contact when nothing changed, in --check, with the option off, or
	// for a client pilot deferred; a deferred client does not fail the gate.
	expect("nothing changed", run(map[string]any{"sudo_test_dirty": false}), true)
	expect("check mode", run(nil, "--check"), true)
	expect("option off", run(map[string]any{"ipa_identity_refresh_sssd_cache": false}), true)
	expect("deferred client", run(map[string]any{"pilot_deferred_hosts": []string{"client-b"}}), true, "client-a")
}

// pilot passes the deferred hosts as one `-e pilot_deferred_hosts=["a","b"]`
// (cmd/pilot/cmd/deploy_availability.go deferredHostsExtraVar, passed through
// by ansibleExtraVarArgs unchanged; locked by
// TestDeferredHostsReachAnsibleAsAKeyValueExtraVar). Ansible 2.19 types that
// value as a string, so `reject('in', pilot_deferred_hosts)` was a substring
// test: with client-10 deferred, client-1 was silently left out of the refresh
// and out of the gate that checks it. The production resolving task, refresh
// task and gate run through real Ansible with colliding host names and that
// exact argv form; the refresh helper itself is a stand-in here (it is covered
// by TestRegression_IdentitySSHCacheSudoRefreshHelper and the playbook test),
// so a run costs milliseconds, not seconds per client.
func TestRegression_IdentitySSHCacheSudoRefreshDeferredHosts(t *testing.T) {
	dir := t.TempDir()
	write := installSSHCacheFakes(t, dir)
	hosts := []string{"client-1", "client-10", "client-2"}
	tasks := localSudoRefreshClients(hosts...)
	tasks = append(tasks, sudoRefreshProductionTasks(t, dir, sudoRefreshResolve, "Refresh SSSD caches on enrolled FreeIPA clients", sudoRefreshGate)...)
	vars := withSudoRefresh(t, map[string]any{"ipa_domain": "ipa.pilot.internal", "stage": "sandbox",
		"ipa_identity_refresh_sssd_cache": true, "sudo_test_dirty": true})
	// A refresh that records the host it ran on and fails when no-refresh-<host>
	// exists, standing in for the helper (same stdin, same exit contract).
	vars["ipa_sudo_refresh_program"] = `import json, os, sys
json.load(sys.stdin)
host, d = os.environ['CACHE_TEST_HOST'], os.environ['CACHE_TEST_DIR']
with open(d + '/restarts', 'a') as f:
    f.write(host + '\n')
sys.exit(1 if os.path.exists(d + '/no-refresh-' + host) else 0)
`
	run := func(args ...string) ag82Run {
		t.Helper()
		_ = os.Remove(filepath.Join(dir, "restarts"))
		return runGatewayTasks(t, dir, tasks, vars, nil, args...)
	}
	// pilotForm is pilot's argv for a deferred set: sorted, compact JSON, one
	// key=value extra var.
	pilotForm := func(deferred ...string) []string {
		encoded, err := json.Marshal(deferred)
		if err != nil {
			t.Fatal(err)
		}
		return []string{"-e", "pilot_deferred_hosts=" + string(encoded)}
	}
	listForm := func(deferred ...string) []string {
		encoded, err := json.Marshal(map[string]any{"pilot_deferred_hosts": deferred})
		if err != nil {
			t.Fatal(err)
		}
		return []string{"-e", string(encoded)}
	}
	contacted := func(label string, result ag82Run, success bool, want ...string) {
		t.Helper()
		if (result.rc == 0) != success {
			t.Fatalf("%s: rc=%d failures=%v\n%s", label, result.rc, result.failures, result.raw)
		}
		if got := restartsOf(t, dir); !slices.Equal(got, want) {
			t.Fatalf("%s: refreshed %v; want %v (failures=%v)", label, got, want, result.failures)
		}
	}

	// Each prefix collision, in pilot's form and as a real list: only the named
	// hosts are skipped, everything else is refreshed.
	for _, tc := range []struct {
		deferred []string
		want     []string
	}{
		{nil, []string{"client-1", "client-10", "client-2"}},
		{[]string{"client-10"}, []string{"client-1", "client-2"}},
		{[]string{"client-1"}, []string{"client-10", "client-2"}},
		{[]string{"client-1", "client-2"}, []string{"client-10"}},
		{[]string{"client-1", "client-10", "client-2"}, nil},
	} {
		label := fmt.Sprintf("deferred %v", tc.deferred)
		deferred := tc.deferred
		if deferred == nil {
			deferred = []string{}
		}
		contacted(label+" (pilot's key=value form)", run(pilotForm(deferred...)...), true, tc.want...)
		contacted(label+" (list)", run(listForm(deferred...)...), true, tc.want...)
	}
	contacted("pilot_deferred_hosts not given", run(), true, "client-1", "client-10", "client-2")

	// The gate expects exactly the clients the loop was given: client-1 fails
	// its refresh while client-10 is deferred. It was silently dropped by the
	// loop and the gate alike, so the apply reported success.
	write("no-refresh-client-1", "")
	failed := run(pilotForm("client-10")...)
	if failed.rc == 0 {
		t.Fatalf("client-1 did not refresh and is not deferred, yet the apply succeeded\n%s", failed.raw)
	}
	if got := restartsOf(t, dir); !slices.Equal(got, []string{"client-1", "client-2"}) {
		t.Fatalf("refreshed %v; want client-1 and client-2", got)
	}
	got := unfinishedClients(failed.failures)
	if !strings.Contains(got, `[\"client-1\"]`) || strings.Contains(got, "client-10") || !strings.Contains(got, "PARTIAL") {
		t.Fatalf("gate must name exactly client-1: %v", failed.failures)
	}
	if err := os.Remove(filepath.Join(dir, "no-refresh-client-1")); err != nil {
		t.Fatal(err)
	}

	// A value that cannot be read as a host list fails before any client is
	// touched; it is not silently treated as "nothing deferred".
	for label, args := range map[string][]string{
		"a bare host name":    {"-e", "pilot_deferred_hosts=client-1"},
		"an empty value":      {"-e", "pilot_deferred_hosts="},
		"a number":            {"-e", `{"pilot_deferred_hosts": 5}`},
		"a null":              {"-e", `{"pilot_deferred_hosts": null}`},
		"truncated JSON text": {"-e", `pilot_deferred_hosts=["client-1"`},
	} {
		bad := run(args...)
		if bad.rc == 0 {
			t.Fatalf("%s: an unreadable pilot_deferred_hosts must fail the apply\n%s", label, bad.raw)
		}
		if got := restartsOf(t, dir); len(got) != 0 {
			t.Fatalf("%s: refreshed %v before failing", label, got)
		}
	}
}
